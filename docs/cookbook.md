# Cookbook

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · Cookbook · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · [Security model](security-model.md)

Task-oriented recipes. Each is self-contained — copy one without reading the rest. Throughout, `Crypto`
is an `ICryptoProvider` and `Pkix` an `IPkixProvider` (`TDefaultCryptoProvider.Create as ICryptoProvider`
and `TDefaultPkixProvider.Create as IPkixProvider`, units `TlpDefaultCryptoProvider` /
`TlpDefaultPkixProvider`), and `LoadFile` is the small helper from
[Getting started §3](getting-started.md#3-your-first-client-fully-verified). New to the library?
Read [Getting started](getting-started.md) first.

**Recipes**

- [Connect a client](#connect-a-client)
- [Stand up a server](#stand-up-a-server)
- [Serve several host names (SNI)](#serve-several-host-names-sni)
- [Choose a security posture](#choose-a-security-posture)
- [Force post-quantum-hybrid only](#force-post-quantum-hybrid-only)
- [Trust a private CA, the OS store, or a pinned key](#trust-a-private-ca-the-os-store-or-a-pinned-key)
- [Integrate with your networking stack](#integrate-with-your-networking-stack)
- [Drive TLS over your own transport (`TTlsStream`)](#drive-tls-over-your-own-transport)
- [Drive the raw sans-IO engine (async frameworks)](#drive-the-raw-sans-io-engine)
- [Export keying material and rekey](#export-keying-material-and-rekey)
- [Mutual TLS (client certificates)](#mutual-tls-client-certificates)
- [Negotiate ALPN](#negotiate-alpn)
- [Inspect the connection](#inspect-the-connection)
- [Resume sessions](#resume-sessions)
- [0-RTT early data](#0-rtt-early-data)
- [Set a revocation posture](#set-a-revocation-posture)
- [Certificate compression](#certificate-compression)
- [Hide the SNI with Encrypted Client Hello](#hide-the-sni-with-encrypted-client-hello)
- [Connect without sending SNI (still verified)](#connect-without-sending-sni-still-verified)
- [External (out-of-band) PSKs](#external-out-of-band-psks)
- [TLS 1.2 pre-shared keys](#tls-12-pre-shared-keys-rfc-4279--rfc-5489)
- [Require Extended Master Secret (TLS 1.2)](#require-extended-master-secret-tls-12)
- [Cap the inbound record size](#cap-the-inbound-record-size)
- [Turn off GREASE](#turn-off-grease)
- [Use the OS-native crypto overlay](#use-the-os-native-crypto-overlay)
- [The dangerous surface (dev only)](#the-dangerous-surface-dev-only)

---

## Connect a client

Fully verified against a CA bundle you supply. The facade wires the **Compatible** preset for you:

```pascal
uses TlpTlsLib, TlpITlsConfig;

LConfig := TTlsLib.NewClientConfig(LoadFile('my-ca.pem'));   // PEM bundle or a single DER cert
```

Need more control (ALPN, a posture other than Compatible, pinning, …)? Build it explicitly — every
recipe below uses this shape:

```pascal
uses TlpTlsPresets, TlpITlsConfigBuilder, TlpITlsConfig, TlpCertificateVerifierSource;

LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LoadFile('my-ca.pem')).Build)
  .Build;
```

Then turn the config into a connection with a [`TTlsStream`](#drive-tls-over-your-own-transport) or a
[stack adapter](#integrate-with-your-networking-stack).

## Stand up a server

A server needs a **credential** (chain + private key). Three ways to supply it:

```pascal
uses TlpTlsPresets, TlpITlsConfigBuilder, TlpITlsConfig, TlpTlsCredential;

// TTlsCredential.Load takes the crypto + pkix providers explicitly; LoadPkcs12 takes the crypto provider only
// (a) separate PEM/DER files — leaf-first chain + unencrypted key
LCred := TTlsCredential.Load(Crypto, Pkix,
  LoadFile('server-chain.pem'), LoadFile('server-key.pem'));
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(LCred).Build;

// (b) an encrypted private key
LCred := TTlsCredential.Load(Crypto, Pkix,
  LoadFile('chain.pem'), LoadFile('key.pem'), 'key-password');
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(LCred).Build;

// (c) a PKCS#12 / .pfx bundle (chain + key in one blob)
LCred := TTlsCredential.LoadPkcs12(Crypto, LoadFile('identity.pfx'), 'pfx-password');
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(LCred).Build;
```

Then, per accepted socket, `TTlsEngineFactory.CreateServerEngine(LConfig)` and wrap it in a stream or
hand it to your adapter. The PKCS#12 importer fails closed on a bad password or a malformed blob
(typed exception), wipes the password and key bytes, and expects a single private key.
The leaf is the certificate that pairs the key (the linked one if it does, else the lowest DER),
and the chain follows it by issuer name. Where the OS-native overlay can, the OS unwraps the
file; a store it cannot unwrap goes to the portable importer.

To staple OCSP for the leaf, set the credential's `OcspStaple` (DER) or `OcspStapleCallback` (it
refreshes an expiring staple and takes precedence; it must not do network I/O). The staple is sent
only to a client that offered `status_request`.

## Serve several host names (SNI)

Map a credential to each SNI host name. A host is an exact name or a single left-most-label
wildcard (`*.example.org`); a `WithCredential` beside them is the default for a client that sent no
SNI or an unknown one:

```pascal
uses TlpTlsPresets, TlpITlsConfig, TlpTlsCredential;

LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithSniCredential('api.example.com', TTlsCredential.Load(Crypto, Pkix,
    LoadFile('api-chain.pem'), LoadFile('api-key.pem')))
  .WithSniCredential('*.example.org', TTlsCredential.Load(Crypto, Pkix,
    LoadFile('org-chain.pem'), LoadFile('org-key.pem')))
  .WithCredential(LDefaultCred)     // optional
  .Build;
```

`Build` raises `EInvalidOperationTlsLibException` when a leaf's dNSName SANs do not cover its host
(a wildcard entry needs the same wildcard SAN), when a host is mapped twice, or for a wildcard such
as `*.com`. Without a default credential, an unmatched host is refused with `unrecognized_name` (`handshake_failure` when the client sent no SNI).

For selection by anything else (the client's signature schemes, ALPN, groups), implement
`ITlsServerCredentialResolver` (unit `TlpITlsCredentialResolver`) and install it with
`WithCredentialResolver`, which replaces `WithCredential` / `WithSniCredential` (combining them is
refused at `Build`):

```pascal
uses SysUtils, TlpITlsCredentialResolver, TlpTlsCredential;

type
  TMyResolver = class(TInterfacedObject, ITlsServerCredentialResolver)
  private
    FApiCred, FDefaultCred: TTlsCredential;
  public
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
  end;

function TMyResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  Result := True;
  if SameText(AClientHello.ServerName, 'api.example.com') then
    ACredential := FApiCred
  else if AClientHello.ServerName = '' then
    ACredential := FDefaultCred
  else
    Result := False;   // refused as unrecognized_name
end;

// ...
  .WithCredentialResolver(LResolver as ITlsServerCredentialResolver)
```

`TryResolve` runs once per ClientHello on the certificate path (twice after a HelloRetryRequest,
never on a resumed or PSK handshake), concurrently across connections that share the config, so it
must be thread-safe and must not do network I/O.

A chain with a certificate (other than a self-issued one) signed with MD5, or with SHA-1 the client
did not advertise, is refused with `handshake_failure` (RFC 9846 4.5.1.2; MD5 inferred from 4.5.1.3), independent of
`AllowedDeprecatedHashes`; a SHA-256 chain is still sent. `AClientHello.CertificateSignatureSchemes`
lists what the client advertised, so a resolver can pick another chain. A client credential in that
state is not sent: the client answers without a certificate.

## Choose a security posture

Presets are safe **starting points**, not locked profiles — override before `Build`:

```pascal
LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client     // TLS 1.3 only, PQ-hybrid preferred
  .WithServerVerification(TServerVerification.WebPki(caPem).Build)
  .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11))
  .Build;
```

| Preset | Versions | Groups | Notes |
|---|---|---|---|
| `Compatible` | 1.3 + hardened 1.2 | X25519, X25519MLKEM768, SecP256r1MLKEM768, P-256/384/521 | The default; widest interop. |
| `Hardened` | 1.3 only | X25519MLKEM768 (first), SecP256r1MLKEM768, X25519, P-256 | Modern peers; PQ preferred. |
| `Strict` | 1.3 only | X25519MLKEM768, X25519, secp256r1 | Fixed group allowlist, tight cert limits, resumption off. |

Re-enabling a safe posture setting on `Strict` (e.g. `WithResumption(True)`) is allowed with no
guard — `psk_dhe_ke` resumption is forward-secret. Only genuine downgrades live behind the
[dangerous surface](#the-dangerous-surface-dev-only).

To narrow or reorder the cipher suites, list their wire codes (the `TCipherSuites13` /
`TCipherSuites12` constants). The list can only **narrow and reorder** the set the preset already
holds — a suite outside it is refused at `Build` — and applies per protocol: a protocol the list names keeps exactly the listed suites, in that
order; one it does not name keeps its own.

```pascal
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(LCred)
  .WithCipherSuiteList(TArray<UInt16>.Create(
    TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256, TCipherSuites12.EcdheEcdsaAes128GcmSha256))
  .Build;     // TLS 1.2 prefers ChaCha20, then AES-128-GCM; TLS 1.3 is unchanged
```

If your suites arrive as names (a config file, a host's cipher-list string), `TCipherSuiteCatalog.TryCode`
(unit `TlpCipherSuiteCatalog`) maps an IANA or OpenSSL name (case-insensitive) to its code; the framework adapters do this for their host's
cipher-list property. The suite order in the configured registry is
the single preference authority: the default registries put AES-GCM first only when the CPU has
AES hardware, and a registry you supply through `WithCipherSuites` is used in the order you gave it.

A server imposes that order by default (`TServerCipherPreference.ServerOrder`). To pick the client's
most-preferred mutually supported suite instead, for TLS 1.3 and 1.2 alike:

```pascal
uses TlpNegotiationTypes;   // TServerCipherPreference

LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(LCred)
  .WithCipherSuitePreference(TServerCipherPreference.ClientOrder)
  .Build;
```

The registries behind those lists are replaceable as a whole: `WithNamedGroups` (the groups the
config can use), `WithSignatureSchemes` and `WithCipherSuites` take a registry, while
`WithPreferredGroups` orders the groups (a code the registry lacks is skipped; an empty list, or
a list with no registered group, is refused at `Build`; a repeated group is refused by `WithPreferredGroups`). A server
acknowledges a client's `server_name` with an empty extension by default; `WithServerNameAcknowledgement(False)`
omits it. `WithIntermediateCertificates` on a verification builder supplies the intermediates a
leaf-only peer leaves out.

## Force post-quantum-hybrid only

Every preset already *offers* X25519MLKEM768. To offer **nothing but** the hybrid (a client that
refuses classical-only key exchange), restrict the preferred groups:

```pascal
uses TlpNegotiationTypes;   // TNamedGroupCatalog

LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem).Build)
  .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768))
  .Build;
```

A note on interop: because TlsLib4Pascal sends a **single** key_share (for its most-preferred group),
a Compatible-preset client talking to a PQ-preferring server completes via one HelloRetryRequest —
normal and automatic. X25519MLKEM768 is interop-verified against OpenSSL 3.5+ and BoringSSL.

## Trust a private CA, the OS store, or a pinned key

The short version — the full treatment is in
[certificate-verification.md](certificate-verification.md) and [system-trust.md](system-trust.md):

```pascal
// a private / self-signed CA (still fully validated against it)
.WithServerVerification(TServerVerification.WebPki(LoadFile('my-ca.pem')).Build)

// several anchor sources union together
.WithServerVerification(TServerVerification.WebPki(
  TArray<ITrustAnchorStore>.Create(storeA, storeB),
  TArray<TBytes>.Create(caPemA, caPemB)).Build)

// the OS root store (needs the TlsLib.Trust.System package)
//   uses TlpSystemTrustFacade;
//   .WithServerVerification(TSystemTrust.ServerVerification(Pkix).Build)

// the OS root store plus my private CA (a chain the OS rejects only for lack of a root is
// judged against my CA; any other OS failure stays final)
//   uses TlpSystemTrustFacade, TlpOSSystemTrust, TlpTrustAnchorStore, TlpITrustAnchorStore;   // TSystemTrustMode, TTrustAnchorStore, ITrustAnchorStore
//   .WithServerVerification(TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default,
//     TTrustAnchorStore.Create(Pkix.Certificates.LoadChain(LoadFile('my-ca.pem'))) as ITrustAnchorStore).Build)

// a fixed offline root bundle (needs TlsLib.Trust.Bundle)
//   uses TlpBundleTrust;
.WithServerVerification(TServerVerification.WebPki(TBundleTrust.FromPemFile(Pkix, 'roots.pem')).Build)

// pin an SPKI-SHA256 on top of normal validation (augments, never replaces)
.WithCertificatePinning(TArray<TBytes>.Create(spkiSha256))
```

Anchors **union** inside one `WebPki` policy; a `TServerVerification.Custom` verifier **replaces** the
pipeline and takes no anchors at all. Pinning and the host-name check are covered in
[the verification guide](certificate-verification.md).

## Integrate with your networking stack

If you already use one of these stacks, you don't touch `ITlsTransport` — the adapter swaps TlsLib4Pascal
in through that stack's own SSL seam. One line, no app rewrite. Add the matching `TlsLib.Adapter.*`
package (singular `Adapter`), then:

**mORMot** — swap the global TLS factory (process-wide), then use mORMot exactly as before:

```pascal
uses TlsLibMormotTls;
RegisterTlsLib4PascalTls;        // every mORMot TCrtSocket now uses TlsLib4Pascal
```

**Indy** — drop in the IO handler:

```pascal
uses TlsLibIndyTls;
LClient.IOHandler := TTlsLibIOHandlerSocket.Create(LClient);   // client
LServer.IOHandler := TTlsLibServerIOHandler.Create(LServer);   // server
```

**Synapse** — the plugin registers itself on `uses`; create sockets normally:

```pascal
uses blcksock, TlsLibSynapseTls;   // registers SSLImplementation := TSSLTlsLib
LSock := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
```

(Link exactly one SSL plugin — don't also link `ssl_openssl`.)

**fcl-net** — a little different from the others: you configure through fcl-net's own
`CertificateData` (file names), and `uses TlsLibFclNetTls` registers `TTlsLibSocketHandler` as
fcl-net's default SSL handler class. Client side, construct a handler, point it at your trust root,
and hand it to the socket:

```pascal
uses ssockets, TlsLibFclNetTls;

LHandler := TTlsLibSocketHandler.Create;
LHandler.CertificateData.CertCA.FileName := 'root.pem';         // trust anchor (VerifyPeerCert defaults True)
LSock := TInetSocket.Create('example.com', 443, LHandler);      // then LSock.Connect
```

Server side, fcl-net's `TInetServer` asks *you* for a handler per accepted connection via its own
`OnCreateClientSocketHandler` event — so you write that callback (here `MakeHandler`) and return a
configured `TTlsLibSocketHandler`:

```pascal
// the callback — signature required by fcl-net's TInetServer.OnCreateClientSocketHandler:
procedure TMyServer.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var LH: TTlsLibSocketHandler;
begin
  LH := TTlsLibSocketHandler.Create;
  LH.CertificateData.Certificate.FileName := 'server-chain.pem';
  LH.CertificateData.PrivateKey.FileName  := 'server-key.pem';
  AHandler := LH;
end;

// wiring:
LServer := TInetServer.Create('0.0.0.0', 443);
LServer.OnCreateClientSocketHandler := MakeHandler;   // @MakeHandler under FPC {$mode objfpc}; TInetServer's event (fcl-net's own), not the adapter's
```

Each adapter maps its host's trust/verify options onto the library (ALPN on fcl-net only), and each exposes a
handshake-read timeout (`HandshakeTimeoutMs`, `SSLOptions.HandshakeTimeoutMs` on Indy, or
`SetTlsLibMormotHandshakeTimeout` for mORMot; `0` = 30 s default; fcl-net falls back to
`Socket.IOTimeout` first) so a stalled peer can't pin the connecting thread.
Each also honours its host's cipher-list property (`CipherList` on mORMot, `SSLOptions.CipherList` on Indy, `Ciphers` on
Synapse, `CertificateData.CipherList` on fcl-net): IANA or OpenSSL suite names (case-insensitive), in preference
order, narrowing the hardened set exactly as `WithCipherSuiteList` does. Cipher-string expressions
like `HIGH` or `!aNULL` are refused rather than guessed at. See the package READMEs:
[mORMot](../TlsLib.Adapters/mORMot/README.md) · [Indy](../TlsLib.Adapters/Indy/README.md) ·
[Synapse](../TlsLib.Adapters/Synapse/README.md) · [fcl-net](../TlsLib.Adapters/FclNet/README.md).

## Drive TLS over your own transport

When you own the socket, implement the two-method `ITlsTransport` and let `TTlsStream` — a real
`TStream` — do the TLS:

```pascal
uses SysUtils, TlpTlsEngineFactory, TlpTlsStream, TlpITlsTransport, TlpITlsEngine,
  TlpTlsLibExceptions;

type
  TMySocketTransport = class(TInterfacedObject, ITlsTransport)
  public
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;  // 0 = orderly EOF
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

var LStream: TTlsStream;
begin
  LStream := TTlsStream.Create(
    TMySocketTransport.Create as ITlsTransport,
    TTlsEngineFactory.CreateClientEngine(LConfig, 'example.com'),
    {IsClient=}True, 'example.com');
  try
    LStream.Handshake;
    LStream.Write(Req[0], Length(Req));
    try
      LCount := LStream.Read(Buf[0], Length(Buf));
    except
      on ETlsTransportTruncated do
        raise Exception.Create('peer closed without close_notify (possible truncation)');
    end;
    LStream.CloseNotify;
  finally
    LStream.Free;
  end;
end;
```

`Read` returns 0 when the peer closes cleanly with `close_notify`. A transport close without
`close_notify` makes `Read` raise `ETlsTransportTruncated` (unit `TlpTlsLibExceptions`);
`TransportTruncated` stays True afterwards.

`TTlsStream` arms no timeout, so a silent peer blocks `Handshake` and `Read`. For bounded reads, run
the connection as a `TTlsConnection` over an `ITlsTimedTransport` (see
[Getting started §4](getting-started.md#4-turn-a-config-into-a-connection)).

Once the write side is closed — you called `CloseNotify` or (under TLS 1.2
only) the peer sent an inbound `close_notify` — a further `Write` raises
`EInvalidOperationTlsLibException` rather than silently discarding the bytes. Under TLS 1.3 an
inbound `close_notify` closes only the read side (RFC 9846 6.1), so you may keep writing until you
close your own side; `ITlsEngine.WriteClosed` tells you which case you are in. The engine never reports data as
sent that it did not send, so a write on a closed stream is always surfaced, never a phantom success.

If your transport's `Write` raises, the stream is finished: later writes, and reads once the data
already received is returned, raise `ETlsStreamError` with no alert (`HasAlert` False), and
`CloseNotify` does nothing. Reconnect; resumption still works.

## Drive the raw sans-IO engine

For non-blocking / event-loop frameworks, drive `ITlsEngine` directly — it owns no sockets, threads,
or timers. You pump bytes; it transduces. The contract (unit `TlpITlsEngine`):

- feed ciphertext in with `ProcessInput(wire, offset, len)`
- drain ciphertext to send with `TakeOutgoing(dest, destOffset)`; it copies at most
  `Length(dest) - destOffset` bytes (0 when that is not positive), so size `dest` first and loop
  while `WantsWrite`
- call `StartHandshake` once; a second call raises (it does nothing on an engine that already failed)
- push/pull application data with `Write(...)` / `ReadAppData(...)`
- check `WantsWrite` / `IsHandshaking`, and service `NextEvent` every cycle — application data is
  not an event (poll `PendingAppData` / `ReadAppData`); past 64 undrained events the informational
  kinds are dropped, while `PeerAlert`, `Closed` and `CertificateReceived` never are

```pascal
uses TlpTlsEngineFactory, TlpITlsEngine;

LEngine := TTlsEngineFactory.CreateClientEngine(LConfig, 'example.com');
SetLength(LOut, 16 * 1024 + 256);
LEngine.StartHandshake;
repeat
  // 1. flush anything the engine wants to send
  while LEngine.WantsWrite do
  begin
    LN := LEngine.TakeOutgoing(LOut, 0);
    MySocketSend(LOut, LN);
  end;
  // 2. feed whatever arrived
  LN := MySocketRecv(LIn);
  if LN > 0 then LEngine.ProcessInput(LIn, 0, LN);
until not LEngine.IsHandshaking;
// the last ProcessInput can finish the handshake with the client Finished or an alert still queued
while LEngine.WantsWrite do
begin
  LN := LEngine.TakeOutgoing(LOut, 0);
  MySocketSend(LOut, LN);
end;
// then LEngine.Write / LEngine.ReadAppData for application data
```

`Write` refuses application data until the application write epoch is in force, so it is never sealed
in the clear, under the handshake keys, or as replayable 0-RTT: a TLS 1.3 server may write from its
own Finished onward (half-RTT), while a TLS 1.3 client and any TLS 1.2 endpoint must wait for the
handshake to complete (there is no False-Start; 0-RTT goes through `WriteEarlyData`). A zero-length
`Write` once a write epoch exists is a no-op.

This is the same engine the stream and every adapter run — it is also the seam where a native/OS TLS
engine could be substituted wholesale. Most apps should prefer the stream or an adapter.

## Export keying material and rekey

Both are `ITlsEngine` methods; `TTlsStream` and `TTlsConnection` do not wrap them. With a stream,
keep the engine you passed to `TTlsStream.Create`.

**Exported keying material** (RFC 5705 / RFC 9846 7.5) binds an application secret to this
connection:

```pascal
LKey := LEngine.ExportKeyingMaterial('EXPORTER-my-app', 32);                // no context
LKey := LEngine.ExportKeyingMaterial('EXPORTER-my-app', LContext, 32);      // with a context
```

A supplied context, even an empty one, gives a different value from no context. The result is empty
until the exporter secret is derived. A TLS 1.3 server has it from its own Finished on, before
client authentication completes under mutual TLS. TLS 1.2 has it only once the handshake completes,
and only when the session used Extended Master Secret (`ConnectionInfo.ExtendedMasterSecret`). It
is also empty on a failed connection. `ExportEarlyKeyingMaterial` is the TLS 1.3 0-RTT variant.

**KeyUpdate** (TLS 1.3, RFC 9846 4.7.3) rekeys the write direction; `UpdateRequested` also asks the
peer to rekey and answer with its own KeyUpdate:

```pascal
uses TlpHandshakeMessages;   // TKeyUpdateRequest

LEngine.RequestKeyUpdate(TKeyUpdateRequest.UpdateRequested);
// the KeyUpdate is queued outbound: drain it with TakeOutgoing like any other record
```

It is a no-op before the handshake completes, on TLS 1.2, on a failed engine, after your own
`close_notify` and once 2^48-1 KeyUpdates have been sent. If an earlier `UpdateRequested` has not
yet been answered by a KeyUpdate from the peer, a new one is sent as `UpdateNotRequested`; the write
keys are still updated (RFC 9846 4.7.3). A peer's KeyUpdate is handled automatically and reported as a
`KeyUpdateReceived` event.

## Mutual TLS (client certificates)

Server side — require a client certificate and name the CA(s) you'll accept it from:

```pascal
uses TlpTlsCredential;   // TClientAuthMode

LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(TTlsCredential.Load(Crypto, Pkix,
    LoadFile('server-chain.pem'), LoadFile('server-key.pem')))
  .WithPeerAuth(TClientAuthMode.Required)                         // None | Requested | Required
  .WithClientVerification(TClientVerification.WebPki(LoadFile('client-ca.pem')).Build)  // the CA you accept clients from
  .Build;
```

`WithClientVerification` is what actually **trusts** the client certificate — a client-auth server
with none is refused at `Build`. `WithClientCertificateAuthorities(...)` is a
separate, optional knob that only *advertises* the acceptable CA names to the client (the
CertificateRequest); it does not establish trust. To validate client certificates with the **OS chain
engine** against this private CA instead of the built-in pipeline, see
[OS-engine client-certificate validation](system-trust.md#os-engine-client-certificate-validation-mtls).

Client side — present your credential:

```pascal
LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LoadFile('server-ca.pem')).Build)
  .WithCredential(TTlsCredential.Load(Crypto, Pkix,
    LoadFile('client-chain.pem'), LoadFile('client-key.pem')))  // or TTlsCredential.LoadPkcs12
  .Build;
```

`Required` fails the handshake closed if the client presents nothing. To revoke client certificates,
see [revocation](#set-a-revocation-posture) — note a client can't staple, so `Hard` client-cert
revocation needs a live resolver.

## Negotiate ALPN

Offer protocols in preference order (client) or advertise what you support (server). A protocol name
is 1..255 opaque octets (RFC 7301), so the builder takes bytes; `TAlpnProtocols` supplies `H2` and
`Http11` and turns ASCII text into octets:

```pascal
uses TlpAlpnProtocols;

.WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11))
// or, from ASCII text:
.WithAlpnProtocols(TAlpnProtocols.FromText(TArray<string>.Create('h2', 'http/1.1')))
```

Read the result off the connection afterwards (`ConnectionInfo.AlpnProtocol`, bytes; compare with
`TArrayUtilities.AreEqual` or turn an ASCII name back with `TAlpnProtocols.TryToText`). A server
already rejects an offer that shares no protocol with it; `.WithAlpnRejection(True)` rejects every
ALPN offer.

## Inspect the connection

After `Handshake`, `ConnectionInfo` is a stable read-only snapshot:

```pascal
uses TlpTlsConnectionInfo;

var LInfo: TTlsConnectionInfo;
begin
  LInfo := LStream.ConnectionInfo;
  // LInfo.NegotiatedVersion.WireValue   $0304 = TLS 1.3, $0303 = TLS 1.2
  // LInfo.CipherSuite                    e.g. $1301 = TLS_AES_128_GCM_SHA256
  // LInfo.NamedGroup                     e.g. $001D = X25519 (default); $11EC = X25519MLKEM768 hybrid
  // LInfo.AlpnProtocol                   negotiated ALPN name (bytes), or empty
  // LInfo.ServerName                     SNI the peer sent (server side)
  // LInfo.Resumed                        True if this was a resumption (an external PSK is not one)
  // LInfo.PeerCertificates               peer chain as presented, leaf first (on a resume: the chain stored with the session)
  // LInfo.ValidatedPath                  path PKIX validated on this connection, leaf..anchor; empty on a resume unless re-verified
  // LInfo.PeerOcspStaple                 the stapled OCSP response, if any
  // LInfo.RequestedCertificateAuthorities  CA names the peer's CertificateRequest listed (DER)
  // LInfo.PskIdentity                    the PSK identity that authenticated it (TLS 1.2 PSK, or the TLS 1.3 external identity as configured), or empty
  // LInfo.ExtendedMasterSecret           RFC 7627 in use (always True on TLS 1.3)
  // LInfo.EchStatus                      NotOffered / Greased / Accepted / Rejected / Backend
  // LInfo.EchRetryConfigs, EchIsRetryAttempt, EchRejectAborted   the client-side ECH reject details
  // LInfo.PeerSignatureScheme            IANA code of the scheme that verified the peer's signature; 0 if none (a resume: the original's)
  // LInfo.HelloRetryRequest              a HelloRetryRequest was used (client: received; server: sent)
  // LInfo.EarlyDataReason                why 0-RTT was or was not used (TEarlyDataReason)
  // LInfo.EarlyDataAccepted              0-RTT was accepted (client: the server took it; server: it opened the early-data window)
  // LInfo.TicketAgeSkew                  server, TLS 1.3 resumption: client-reported ticket age less the server's own, in seconds
  // LInfo.RequestedSignatureSchemes      the signature_algorithms the peer's CertificateRequest listed
end;
```

## Resume sessions

Resumption is `psk_dhe_ke` (forward-secret). The client cache hands each ticket out once. Give the
**client** a session cache; the **server** resumes out of the box via stateless tickets, which are
only single-use once you upgrade it to a stateful store. A `Hard`-revocation client using
`WithResumeVerification(Reverify)` needs `WithLiveRevocationVerdict` (a resume carries no staple), and
`Build` refuses it without one; see [certificate-verification.md](certificate-verification.md).

```pascal
uses TlpInMemorySessionCache, TlpInMemorySessionStore, TlpSessionTicketKeys, TlpISession;

// CLIENT: reuse this config across connections and its cached tickets come with it. Don't share one
// cache across configs with different trust — a stricter config could resume a looser one and skip its check.
LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem).Build)
  .WithResumption(True)
  .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
  .Build;

// SERVER: stateless STEK tickets (rotating key), the default resumption path. WithResumption(True)
// alone mints a rotating default key manager.
LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(TTlsCredential.Load(Crypto, Pkix, chainPem, keyPem))
  .WithResumption(True)
  // supply your own manager (WithSessionTicketKeys) only to share keys across servers
  // (TFleetTicketKeyManager + InstallKey); TStekTicketKeyManager.Create(ARandom) rotates only when you call Rotate
  .Build;

// SERVER (stronger): add a stateful store to get true single-use tickets + 0-RTT anti-replay
  .WithSessionStore(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore)
```

Both default in-memory implementations are bounded and safe to share across connections/threads.
A ticket links the connections that use it, so do not share a cache across connections that must
stay unlinkable (RFC 9846 C.4).

A client cache is scoped to the config that stored the session: a cache shared by two configs
resumes neither's sessions in the other. Two client knobs change that:

```pascal
uses TlpTlsCredential;   // TResumeVerification

// configs that trust identically and should share one cache: give them the same scope
  .WithSessionCache(LSharedCache)
  .WithResumptionScope(TEncoding.UTF8.GetBytes('api-pool'))   // at most 32 bytes; needs a cache

// re-run certificate verification against the stored chain on every resume
  .WithResumeVerification(TResumeVerification.Reverify)
```

`WithResumptionScope` is an assertion that the configs trust identically. A scope longer than 32
bytes raises `EArgumentTlsLibException`; `Build` refuses a scope or `Reverify` on a config with no
session cache or with resumption off. `ReuseOriginal` (the default) trusts the
original handshake's verification; `Reverify` checks the stored chain against the current trust
before the session is offered, at the cost of a verification per resume, and fills
`ConnectionInfo.ValidatedPath`. A session whose chain fails is not offered: no ticket, binder or
early data is sent and the client runs a full handshake that verifies the fresh chain
(`Resumed = False`). A server takes `WithResumptionScope` too, to partition configs sharing a
ticket-key manager or session store; a server that requests client certificates and supplies either
must set one. The two roles default differently when the scope is empty: a client isolates (a fresh scope per config), a server
shares.

On the server, `WithTicketLifetime(Seconds)` sets the lifetime advertised for issued tickets (default
7200 s; at most seven days, a larger value is refused; 0 is refused while resumption is on). A client
clamps any advertised lifetime to seven days, and a resumption chain ends seven days after the full
handshake whatever the lifetime. The default ticket key rotates on that lifetime, and is minted
only when resumption is on and no ticket keys or session store are set. `WithDefaultSessionTicketKeys`
asks for that default explicitly (also beside a session store), and `Tls13.WithTicketCount` sets how
many TLS 1.3 tickets each handshake issues; on a TLS 1.3-only server `WithTicketCount(0)` refuses
default ticket keys and a non-default lifetime, as no tickets would be issued.

## 0-RTT early data

0-RTT is **off by default** and is a deliberate opt-in, because early data is replayable — only send
*idempotent* requests as early data. Enable it on both ends, and give the server an anti-replay
strategy:

```pascal
uses TlpAntiReplay, TlpISession, TlpInMemorySessionStore, TlpInMemorySessionCache;

// SERVER: authorize an early-data budget + register replays (needs resumption; a default
// anti-replay register is supplied unless you pass your own)
LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(TTlsCredential.Load(Crypto, Pkix, chainPem, keyPem))
  .WithResumption(True)
  .WithSessionStore(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore)
  .Tls13
    .WithEarlyData({MaxBytes=}16384)
    .WithAntiReplay(TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy)
  .Build;

// CLIENT: allow offering early data on a resumed connection
LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem).Build)
  .WithResumption(True)
  .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
  .Tls13.WithEarlyData(True)
  .Build;
```

Sending the early bytes themselves is a sans-IO engine intent (`WriteEarlyData`, which returns how
many bytes it accepted as 0-RTT), and acceptance is reported as an event. Bytes beyond the ticket's
`max_early_data`, and any early data the server rejects, are **not** re-sent for you — resend them as
1-RTT after the handshake completes if you need to. Treat 0-RTT as an advanced optimisation — leave it
off unless you need it and your early request is idempotent.

Under `WithResumeVerification(Reverify)` the stored chain is checked before the ClientHello is built,
so early data is sent only for a session that passes current trust. `Build` refuses `WithEarlyData(True)`
together with `Reverify` and an async verdict (`WithAsyncCertificateVerdict` or
`WithLiveRevocationVerdict`): that verdict resolves after the server flight, so no early data could
precede it. A `Hard`-revocation client using `Reverify` always carries a live verdict, so it cannot
use 0-RTT.

On the server, accepted early data is **never** returned by `ReadAppData` or a stream `Read`: it is
replayable, so it is kept apart and read with `ReadEarlyData` (`PendingEarlyData` says how much is
waiting). It precedes all 1-RTT data and stays readable after the handshake completes. Read both
queues, and act on early data only when the request is safe to replay.

`TTlsStream` and `TTlsConnection` expose the same queue as `ReadEarlyData`, which returns 0 once none
is left. Call it after the handshake and before `Read`: `Read` raises
`EInvalidOperationTlsLibException` while early bytes are unread, so they are never skipped or
reordered. The framework adapters cannot hand early data to the application, so they refuse a
`ServerConfig` built with `WithEarlyData`; serve 0-RTT through `TTlsConnection` or the sans-IO engine.

## Set a revocation posture

The posture governs how an **unknown/indeterminate** status is treated; a definitive, authenticated
**Revoked** always aborts with `certificate_revoked` under every posture:

```pascal
uses TlpTrustPolicy, TlpCertificateVerifierSource;   // TRevocationPosture, TServerVerification

// on the verification policy (TClientVerification.WebPki has the same method for mTLS):
TServerVerification.WebPki(caPem).WithRevocation(TRevocationPosture.Soft).Build   // default: accept missing/indeterminate status
TServerVerification.WebPki(caPem).WithRevocation(TRevocationPosture.Hard).Build   // reject missing/indeterminate status
TServerVerification.WebPki(caPem).WithRevocation(TRevocationPosture.Off).Build    // don't require status (and perform no live fetch)
```

`Hard` needs a way to obtain status, or `Build` refuses it. A client needs a stapling request
(Hardened and Strict request one; on Compatible add `.WithOcspStaplingRequest(True)`) or
`WithLiveRevocationVerdict(deadlineMs)`. A server checking client certificates needs
`WithLiveRevocationVerdict(deadlineMs)`, since a client cannot staple.

```pascal
uses TlpTrustPolicy, TlpCertificateVerifierSource;

// a Compatible client that asks the server for a stapled OCSP response (status_request, RFC 6066)
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem)
    .WithRevocation(TRevocationPosture.Hard).Build)
  .WithOcspStaplingRequest(True)
  .Build;
```

A client that does not request a staple rejects an unsolicited one, and a must-staple leaf
(RFC 7633) is enforced only when the client requested one.

Stapled OCSP is validated in the handshake pipeline. **Live** OCSP/CRL is opt-in, never in the
sans-IO core: you attach a resolver to the `TTlsStream` backed by the reference socket fetcher
`TSocketHttpFetcher` (unit `TlpSocketHttpFetcher`, in the `TlsLib.Net` package, `TlsLib.Net/src/`). The full wiring — including `must-staple`, the
posture/live-channel interaction, and server-side client-cert revocation — is in
[certificate-verification.md → Live OCSP/CRL](certificate-verification.md#live-ocspcrl-revocation-opt-in).

The fetcher speaks a strict HTTP/1.1 subset over the library's own sockets, and https over its own
TLS client, on every compiler and OS. Configure it with a `TSocketHttpFetcherSettings` value
(`Defaults`, then set what you need):

- `TlsConfig` — the client config for https responders; without one an https responder fails closed.
  It must not arm a certificate-verdict park (`WithAsyncCertificateVerdict` or
  `WithLiveRevocationVerdict`; there is no resolver here, and a live one would call the fetcher
  itself), which the constructor refuses. OCSP and CRL responders are almost always plain http.
- `Resolver` — the `IHostResolver` for the host the fetcher dials: the responder, or the proxy when
  one is set. It can refuse loopback or private addresses for what it resolves; under a proxy the
  proxy resolves the responder, so address checks on the responder are the proxy's job. Name
  resolution is outside the fetch timeout.
- `DestinationPolicy` — an `IFetchDestinationPolicy` asked `Admits(Url)` with the parsed responder
  URL before every connect, direct or proxied; nil admits every URL. It may be called from several
  threads at once. Live revocation does not block private or loopback responders unless you set
  one. Ports on the standard blocked-port list (SMTP, IRC, LDAP and the like) are always refused.
- `ProxyHost` / `ProxyPort` — an explicit forward proxy: http requests are sent in absolute form,
  https through a `CONNECT` tunnel. No system proxy is discovered.

```pascal
LSettings := TSocketHttpFetcherSettings.Defaults;
LSettings.TlsConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TSystemTrust.ServerVerification(Pkix).Build).Build;
LFetcher := TSocketHttpFetcher.Create(LSettings);
```

## Certificate compression

RFC 8879 certificate compression is **on by default** (zlib) for TLS 1.3 — most valuable for large
chains, notably PQ certificates. Nothing to configure to benefit in either role: an endpoint
decompresses the peer's `Certificate` automatically and compresses its own when the peer advertised
a matching algorithm (a server compresses its certificate for a client; with mutual TLS a client
compresses its certificate for a server that advertises it). An empty array turns a direction off.

To make a busy endpoint deflate its stable certificate **once** instead of every handshake, add the
cross-connection cache (either role, opt-in, bounded, thread-safe):

```pascal
uses TlpInMemoryCertificateCompressionCache, TlpICertificateCompressionCache;

LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(TTlsCredential.Load(Crypto, Pkix, chainPem, keyPem))
  .Tls13.WithCertificateCompressionCache(
    TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache)
  .Build;
```

Full detail — algorithms, the bomb-defense on decompression, why the cache can never change the wire
output — in [certificate-compression.md](certificate-compression.md).

## Hide the SNI with Encrypted Client Hello

ECH (RFC 9849) encrypts the true SNI. As a **client**, fetch the operator's `ECHConfigList` (the `ech`
SvcParam of the HTTPS record for the name you connect to) and offer it — the leaf is verified against the true name, and a
reject never falls back to plaintext:

```pascal
uses TlpEchClient, TlpTlsVersion, TlpTlsEngineFactory;   // TEchClientModes, TlsWireVersionTls13, TTlsEngineFactory

LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem).Build)
  .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));   // a real ECH offer is TLS 1.3-only
LClient.Tls13.WithEch(TEchClientModes.Enable(EchConfigList)); // bytes from DNS
LEngine := TTlsEngineFactory.CreateClientEngine(LClient.Build, 'secret.example');
// a completed handshake reports ConnectionInfo.EchStatus = Accepted; over a TTlsStream or an
// adapter a reject raises EEchRejectedTlsLibException carrying RetryConfigs (the raw engine
// records EchStatus = Rejected instead)
```

As a **server**, hold the config + private key (an RFC 9934 PEM from `EchKeyGen` or `openssl ech`) and
trial-decrypt:

```pascal
LStore := TInMemoryEchKeyStore.FromPem(EchPem, Crypto);
LServer := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(TTlsCredential.Load(Crypto, Pkix, chainPem, keyPem));
LServer.Tls13.WithEchKeyStore(LStore, True);
```

ECH is TLS 1.3 only. Full detail — GREASE, rejection/`retry_configs`, key generation, and DNS — in
[ech.md](ech.md).

## Connect without sending SNI (still verified)

A client can leave the `server_name` extension out while still verifying the certificate against the
host you connect to (RFC 9525):

```pascal
LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LoadFile('my-ca.pem')).Build)
  .WithServerNameIndication(TServerNameIndication.Omit);
LEngine := TTlsEngineFactory.CreateClientEngine(LClient.Build, 'host.example');
```

A server that picks its certificate by SNI may refuse the hello (`missing_extension`) or serve a default
certificate that then fails the name check; the client never retries with the name.

## External (out-of-band) PSKs

For external pre-shared keys (a key both endpoints already share out of band, not from a prior
handshake). The PSK is imported per RFC 9258, so both peers must implement the import; a peer that
does not import the PSK as RFC 9258 describes will not interoperate (a raw PSK from another tool's
`-psk` option, for example):

```pascal
uses TlpSession, TlpSecretBuffer, TlpCryptoDomainTypes;   // TExternalPsk, TSecretBuffer, THashAlgorithm

var LPsk: TExternalPsk;
begin
  LPsk.Identity := IdentityBytes;                 // agreed identity label
  LPsk.Secret   := TSecretBuffer.From(KeyBytes);  // the shared key material
  LPsk.Context  := nil;                            // optional RFC 9258 ImportedIdentity context
  LPsk.Hash     := THashAlgorithm.SHA_256;         // the PSK's bound hash

  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(caPem).Build)
    .Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(LPsk))
    // .WithExternalPskRequired(False)  // let the client fall back to certificate authentication
    .Build;
end;
```

External PSKs are TLS 1.3 only, so they are set on the `Tls13` facet (as is the
server's `WithTicketCount`); a config that does not offer TLS 1.3 refuses a non-default value of them
at `Build`. Both ends configure the same identity + key. A client requires the PSK by default; use
`Tls13.WithExternalPskRequired(False)` to let it fall back to certificate authentication.

`WithExternalPreSharedKeys` refuses a malformed PSK up front: an empty or over-65535-byte identity, an
empty secret, an identity plus context whose imported identity exceeds 65535 bytes, and two PSKs that
share an identity and context. A client's `Build` also refuses a set that, sent once per KDF hash
(SHA-256 and SHA-384), would not fit the 65535-byte ClientHello extensions block beside fixed
allowances: the other extensions, the ALPN list as configured, a cached ticket when a session cache
is set (a client caches no ticket over 16428 bytes, whoever issued it), and a doubled hello plus ECH
overhead when ECH is on. A set that passes encodes (about 538 two-byte-identity PSKs with none of
those, 246 with ECH); a server may hold any number. A connection an
external PSK authenticated reports `Resumed = False` and the configured identity in `PskIdentity`;
only a later ticket resumption of it is a resumption.

## TLS 1.2 pre-shared keys (RFC 4279 / RFC 5489)

A pre-shared key for a TLS 1.2 endpoint is a different thing from the TLS 1.3 external PSK above: it
rides the ECDHE_PSK cipher suites, the identity travels in the ClientKeyExchange, and the secret is
used raw (no RFC 9258 import). It has its own type, `TTls12Psk`, and its own setters on the `Tls12`
facet. Use a secret of its own: do not feed one key to both a `TTls12Psk` and a `TExternalPsk`.

```pascal
uses TlpSession, TlpSecretBuffer, TlpTlsVersion;   // TTls12Psk, TSecretBuffer, TlsWireVersionTls12

var LPsk: TTls12Psk;
begin
  LPsk.Identity := IdentityBytes;                 // 1 to 65535 bytes, sent in the clear
  LPsk.Secret   := TSecretBuffer.From(KeyBytes);  // 1 to 65535 bytes

  // client: no trust source needed, TLS 1.2 only
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .Tls12.WithPreSharedKey(LPsk)
    // .WithPreSharedKeyRequired(False)  // also offer the certificate suites (needs a trust source)
    .Build;

  // server: one or more keys, looked up by identity
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .Tls12.WithPreSharedKeys(TArray<TTls12Psk>.Create(LPsk))
    .Build;
end;
```

Configuring a key brings in the ECDHE_PSK suites (ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM); they are
in no preset. The key exchange is ephemeral ECDH, so a recorded session stays forward secret. Notes:

* A server prefers a configured PSK over its certificate. A client that requires its PSK (the default)
  offers no TLS 1.2 certificate suite.
* A server with no certificate, or a client with no trust source, must offer only the versions it holds
  a PSK for (here `WithSupportedVersions([TLS 1.2])`); `Build` refuses any other version.
* The server sends no certificate and, when client authentication is required, a known identity stands in
  for it. `ConnectionInfo.PskIdentity` names the key that authenticated a connection.
* An identity the server does not know proceeds on a stand-in secret, so the handshake ends as it does for a
  wrong secret and a probe learns nothing about which identities exist.
* A PSK session resumes while its identity is still configured with the same secret; removing the key
  or rotating its secret ends the sessions it made.
* Give a text identity as UTF-8 (RFC 4279 5.1). The config shares your secret buffer rather than
  copying it, so keep the buffer alive for the life of the config.
* The server sends no identity hint unless `Tls12.WithPreSharedKeyIdentityHint` sets one (RFC 4279 5.2); a
  client ignores any hint.
* A low-entropy secret falls to an offline dictionary attack on a recorded handshake (RFC 4279 7.2); use
  a random key of at least 128 bits. The identity is not private (RFC 4279 7.3).

## Require Extended Master Secret (TLS 1.2)

Both endpoints always offer and use `extended_master_secret` (RFC 7627) when the peer supports it.
To refuse a TLS 1.2 peer that does not, require it on the `Tls12` facet (TLS 1.3 is unaffected):

```pascal
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(LCred)
  .Tls12.WithExtendedMasterSecret(True)
  .Build;
```

A server that still accepts non-EMS clients chooses how it treats a resumption of a non-EMS session
offered without EMS (RFC 7627 5.3) with `Tls12.WithNonEmsResumption` (`TNonEmsResumption`, unit
`TlpTlsCredential`): `Decline` (the default) runs a full handshake, `Abort` ends it with
`handshake_failure`, and `Resume` performs the legacy abbreviated handshake. `Decline` and `Abort`
also stop issuing resumable sessions from a non-EMS handshake. `Abort` or `Resume` together with
`WithExtendedMasterSecret(True)` is refused at `Build`. The `Tls12` facet needs TLS 1.2 among the
offered versions, so it does not apply to the Hardened or Strict preset.

## Cap the inbound record size

`WithRecordSizeLimit` offers `record_size_limit` (RFC 8449): the largest record this endpoint
accepts, counted as TLSInnerPlaintext under TLS 1.3. It suits memory-constrained peers. `0`, the
default, offers nothing; any other value must be 64..16384, or the setter raises
`EArgumentTlsLibException`.

```pascal
uses TlpCertificateVerifierSource;

LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem).Build)
  .WithRecordSizeLimit(4096)
  .Build;
```

## Turn off GREASE

A client sends GREASE values (RFC 8701) in its ClientHello by default, whatever versions it offers,
so peers that choke on unknown values are found early. To stop sending them:

```pascal
  .WithGrease(False)   // client builder
```

## Use the OS-native crypto overlay

The optional `TlsLib.Crypto.System` package overlays the platform's native primitives (randomness,
key agreement, AEAD, hashes, HMAC, KDFs and handshake signing) onto a base provider. Where the
platform has no native backend, `Compose` returns the base unchanged. Trust, path validation and
revocation stay with the base.

```pascal
uses TlpOSCryptoProvider, TlpSystemCryptoStrictness, TlpDefaultCryptoProvider, TlpICryptoProvider,
  TlpNegotiationTypes;   // TNamedGroupCatalog

Crypto := TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider);
// optional: fail at startup when a group the app depends on would fall back to the portable code
TSystemCryptoStrictness.RequireNamedGroups(Crypto, [TNamedGroupCatalog.X25519]);
```

Where a native backend exists, the composed provider also implements `ICryptoBackendReport` (unit
`TlpICryptoBackendReport`), which says per primitive whether the OS or the portable code serves it.
`TSystemCryptoStrictness` can narrow a registry to the natively served
entries (`NativeNamedGroups`, `NativeCipherSuites`, `NativeSignatureSchemes`) or require them
(`RequireNamedGroups`, `RequireCipherSuites`, `RequireSignatureSchemes` raise
`ESystemCryptoRequirementTlsLibException` listing what is missing). A narrowed signature registry
governs what the endpoint advertises and accepts; a server's own signatures follow its credential
key, so a server accepts a narrowed registry only together with `WithPeerAuth`.

## The dangerous surface (dev only)

Everything that weakens authentication lives behind one loudly-named surface, and even then the
builder makes you type more than one thing. **Never ship these.**

```pascal
// accept ANY chain — no PKIX, no revocation, no host-name. Tests / pinned dev peers only.
// skip-verify is the explicit trust decision, so Build needs no trust store; an empty store is
// refused whenever verification is on.
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.DangerousSkip)
  .Build;

// relax ONLY the host-name check (chain still fully validated; an ECH reject still proves public_name)
.WithDangerousDisableServerNameCheck

// log every connection secret so Wireshark can decrypt a capture (SSLKEYLOGFILE, RFC 9850).
// Debugging only — this writes your keys to disk. Keyed by the ClientHello.random: the inner one when ECH was accepted, otherwise the outer one (RFC 9850 2.1).
uses TlpKeyLog, TlpIKeyLog;
procedure TMyApp.OnKeyLog(const ALabel: string; const AClientRandom, ASecret: TBytes);
begin
  FKeyLogFile.WriteLine(TNssKeyLogFormat.Line(ALabel, AClientRandom, ASecret));
end;
// ...
.WithDangerousKeyLog(TCallbackKeyLog.Create(Self.OnKeyLog) as IKeyLog)   // @Self.OnKeyLog under FPC {$mode objfpc}
```

Point Wireshark at the file via *Preferences → Protocols → TLS → (Pre)-Master-Secret log filename*.

When ECH is accepted the secrets are keyed by the *inner* ClientHello.random, but the log does not
emit the `ECH_SECRET`/`ECH_CONFIG` lines (keyed by the outer random) a decryptor would need to recover
that inner random, so an ECH-accepted capture is not decryptable from this log alone.

An *augment-only* verify callback (`WithCertificateVerifyCallback`) can add extra rejections on top
of normal validation but can never accept a chain the pipeline rejected — that, and how this differs
from the .NET/rustls "replace validation" model, is in
[certificate-verification.md → the dangerous escape hatches](certificate-verification.md#4-the-dangerous-escape-hatches).

---

*Didn't find your task? The [verification](certificate-verification.md),
[system-trust](system-trust.md), and [compression](certificate-compression.md) guides go deeper, and
each adapter's README covers its stack's specifics.*
