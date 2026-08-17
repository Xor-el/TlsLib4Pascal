# Cookbook

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · Cookbook · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [Security model](security-model.md)

Task-oriented recipes. Each is self-contained — copy one without reading the rest. Throughout, `P`
is an `ICryptoProvider` (`TDefaultCryptoProvider.Create as ICryptoProvider`, unit
`TlpDefaultCryptoProvider`), and `LoadFile` is the small helper from
[Getting started §3](getting-started.md#3-your-first-client-fully-verified). New to the library?
Read [Getting started](getting-started.md) first.

**Recipes**

- [Connect a client](#connect-a-client)
- [Stand up a server](#stand-up-a-server)
- [Choose a security posture](#choose-a-security-posture)
- [Force post-quantum-hybrid only](#force-post-quantum-hybrid-only)
- [Trust a private CA, the OS store, or a pinned key](#trust-a-private-ca-the-os-store-or-a-pinned-key)
- [Integrate with your networking stack](#integrate-with-your-networking-stack)
- [Drive TLS over your own transport (`TTlsStream`)](#drive-tls-over-your-own-transport)
- [Drive the raw sans-IO engine (async frameworks)](#drive-the-raw-sans-io-engine)
- [Mutual TLS (client certificates)](#mutual-tls-client-certificates)
- [Negotiate ALPN](#negotiate-alpn)
- [Inspect the connection](#inspect-the-connection)
- [Resume sessions](#resume-sessions)
- [0-RTT early data](#0-rtt-early-data)
- [Set a revocation posture](#set-a-revocation-posture)
- [Certificate compression](#certificate-compression)
- [External (out-of-band) PSKs](#external-out-of-band-psks)
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
uses TlpTlsPresets, TlpITlsConfigBuilder, TlpITlsConfig;

LConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(LoadFile('my-ca.pem'))
  .Build;
```

Then turn the config into a connection with a [`TTlsStream`](#drive-tls-over-your-own-transport) or a
[stack adapter](#integrate-with-your-networking-stack).

## Stand up a server

A server needs a **credential** (chain + private key). Three ways to supply it:

```pascal
uses TlpTlsPresets, TlpITlsConfigBuilder, TlpITlsConfig;

// (a) separate PEM/DER files — leaf-first chain + unencrypted key
LConfig := TTlsPresets.Compatible(P).Server
  .WithCredential(LoadFile('server-chain.pem'), LoadFile('server-key.pem'))
  .Build;

// (b) an encrypted private key
LConfig := TTlsPresets.Compatible(P).Server
  .WithCredential(LoadFile('chain.pem'), LoadFile('key.pem'), 'key-password')
  .Build;

// (c) a PKCS#12 / .pfx bundle (chain + key in one blob)
LConfig := TTlsPresets.Compatible(P).Server
  .WithCredentialPkcs12(LoadFile('identity.pfx'), 'pfx-password')
  .Build;
```

Then, per accepted socket, `TTlsEngineFactory.CreateServerEngine(LConfig)` and wrap it in a stream or
hand it to your adapter. The PKCS#12 importer fails closed on a bad password or a malformed blob
(typed exception), wipes the password and key bytes, and requires exactly one private-key entry.

## Choose a security posture

Presets are safe **starting points**, not locked profiles — override before `Build`:

```pascal
LConfig := TTlsPresets.Hardened(P).Client     // TLS 1.3 only, PQ-hybrid preferred
  .WithTrustAnchors(caPem)
  .WithAlpnProtocols(TArray<string>.Create('h2', 'http/1.1'))
  .Build;
```

| Preset | Versions | Groups | Notes |
|---|---|---|---|
| `Compatible` | 1.3 + hardened 1.2 | X25519, X25519MLKEM768, P-256/384/521 | The default; widest interop. |
| `Hardened` | 1.3 only | X25519MLKEM768 (first), X25519, P-256 | Modern peers; PQ preferred. |
| `Strict` | 1.3 only | X25519MLKEM768, X25519 | Constant-time group allowlist, tight cert limits, resumption off. |

Re-enabling a safe posture setting on `Strict` (e.g. `WithResumption(True)`) is allowed with no
guard — `psk_dhe_ke` resumption is forward-secret. Only genuine downgrades live behind the
[dangerous surface](#the-dangerous-surface-dev-only).

## Force post-quantum-hybrid only

Every preset already *offers* X25519MLKEM768. To offer **nothing but** the hybrid (a client that
refuses classical-only key exchange), restrict the preferred groups:

```pascal
uses TlpNegotiationTypes;   // TNamedGroupCatalog

LConfig := TTlsPresets.Hardened(P).Client
  .WithTrustAnchors(caPem)
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
.WithTrustAnchors(LoadFile('my-ca.pem'))

// several anchor sources union together
.WithTrustAnchors(caPemA).WithTrustAnchors(caPemB)

// the OS root store (needs the TlsLib.Trust.System package)
//   uses TlpSystemTrustFacade;
//   TSystemTrust.WithSystemTrust(TTlsPresets.Compatible(P).Client, P) ...

// a fixed offline root bundle (needs TlsLib.Trust.Bundle)
//   uses TlpBundleTrust;
.WithTrustStore(TBundleTrust.FromPemFile(P, 'roots.pem'))

// pin an SPKI-SHA256 on top of normal validation (augments, never replaces)
.WithCertificatePinning(TArray<TBytes>.Create(spkiSha256))
```

Anchor sources **union**; a whole `WithCertificateVerifier` **replaces** the pipeline and is
exclusive. Pinning and the host-name check are covered in
[the verification guide](certificate-verification.md).

## Integrate with your networking stack

If you already use one of these stacks, you don't touch `ITlsTransport` — the adapter swaps TlsLib4Pascal
in through that stack's own SSL seam. One line, no app rewrite. Add the matching `TlsLib.Adapter.*`
package (singular `Adapter`), then:

**mORMot** — swap the global TLS factory (process-wide), then use mORMot exactly as before:

```pascal
uses TlpMormotTls;
RegisterTlsLib4PascalTls;        // every mORMot TCrtSocket now uses TlsLib4Pascal
```

**Indy** — drop in the IO handler:

```pascal
uses TlpIndyTls;
LClient.IOHandler := TTlsLibIOHandlerSocket.Create(LClient);   // client
LServer.IOHandler := TTlsLibServerIOHandler.Create(LServer);   // server
```

**Synapse** — the plugin registers itself on `uses`; create sockets normally:

```pascal
uses TlpSynapseTls;           // registers SSLImplementation := TSSLTlsLib
LSock := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
```

(Link exactly one SSL plugin — don't also link `ssl_openssl`.)

**fcl-net** — a little different from the others: you configure through fcl-net's own
`CertificateData` (file names), and `uses TlpFclNetTls` registers `TTlsLibSocketHandler` as
fcl-net's default SSL handler class. Client side, construct a handler, point it at your trust root,
and hand it to the socket:

```pascal
uses ssockets, TlpFclNetTls;

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
LServer.OnCreateClientSocketHandler := MakeHandler;   // TInetServer's event (fcl-net's own), not the adapter's
```

Each adapter maps its host's trust/verify/ALPN options onto the library. See the package READMEs:
[mORMot](../TlsLib.Adapters/mORMot/README.md) · [Indy](../TlsLib.Adapters/Indy/README.md) ·
[Synapse](../TlsLib.Adapters/Synapse/README.md) · [fcl-net](../TlsLib.Adapters/FclNet/README.md).

## Drive TLS over your own transport

When you own the socket, implement the two-method `ITlsTransport` and let `TTlsStream` — a real
`TStream` — do the TLS:

```pascal
uses TlpTlsEngineFactory, TlpTlsStream, TlpITlsTransport, TlpITlsEngine;

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
    LCount := LStream.Read(Buf[0], Length(Buf));
    LStream.CloseNotify;
    // distinguish a clean shutdown from a truncation attack:
    if LStream.TransportTruncated then
      raise Exception.Create('peer closed without close_notify (possible truncation)');
  finally
    LStream.Free;
  end;
end;
```

`Read` returns 0 on an orderly close; `TransportTruncated` tells you whether that close was preceded
by a proper `close_notify`.

Once the connection is closed — either you called `CloseNotify`, or the peer half-closed with an
inbound `close_notify` — a further `Write` raises `EInvalidOperationTlsLibException` rather than
silently discarding the bytes. The engine never reports data as sent that it did not send, so a
write on a closed stream is always surfaced, never a phantom success.

## Drive the raw sans-IO engine

For non-blocking / event-loop frameworks, drive `ITlsEngine` directly — it owns no sockets, threads,
or timers. You pump bytes; it transduces. The contract (unit `TlpITlsEngine`):

- feed ciphertext in with `ProcessInput(wire, offset, len)`
- drain ciphertext to send with `TakeOutgoing(dest, destOffset)`
- push/pull application data with `Write(...)` / `ReadAppData(...)`
- check `WantsWrite` / `IsHandshaking`, and service `NextEvent`

```pascal
uses TlpTlsEngineFactory, TlpITlsEngine;

LEngine := TTlsEngineFactory.CreateClientEngine(LConfig, 'example.com');
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
// then LEngine.Write / LEngine.ReadAppData for application data
```

This is the same engine the stream and every adapter run — it is also the seam where a native/OS TLS
engine could be substituted wholesale. Most apps should prefer the stream or an adapter.

## Mutual TLS (client certificates)

Server side — require a client certificate and name the CA(s) you'll accept it from:

```pascal
uses TlpTlsCredential;   // TClientAuthMode

LServerConfig := TTlsPresets.Compatible(P).Server
  .WithCredential(LoadFile('server-chain.pem'), LoadFile('server-key.pem'))
  .WithPeerAuth(TClientAuthMode.Required)                         // None | Requested | Required
  .WithClientCertificateAuthorities(TArray<TBytes>.Create(LoadFile('client-ca.der')))
  .Build;
```

Client side — present your credential:

```pascal
LClientConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(LoadFile('server-ca.pem'))
  .WithCredential(LoadFile('client-chain.pem'), LoadFile('client-key.pem'))  // or WithCredentialPkcs12
  .Build;
```

`Required` fails the handshake closed if the client presents nothing. To revoke client certificates,
see [revocation](#set-a-revocation-posture) — note a client can't staple, so `Hard` client-cert
revocation needs a live resolver.

## Negotiate ALPN

Offer protocols in preference order (client) or advertise what you support (server):

```pascal
.WithAlpnProtocols(TArray<string>.Create('h2', 'http/1.1'))
```

Read the result off the connection afterwards (`ConnectionInfo.AlpnProtocol`, below). A server can
also hard-reject a client that offers no protocol it supports with `.WithAlpnRejection(True)`.

## Inspect the connection

After `Handshake`, `ConnectionInfo` is a stable read-only snapshot:

```pascal
uses TlpTlsConnectionInfo;

var LInfo: TTlsConnectionInfo;
begin
  LInfo := LStream.ConnectionInfo;
  // LInfo.NegotiatedVersion.WireValue   $0304 = TLS 1.3, $0303 = TLS 1.2
  // LInfo.CipherSuite                    e.g. $1301 = TLS_AES_128_GCM_SHA256
  // LInfo.NamedGroup                     $11EC = X25519MLKEM768
  // LInfo.AlpnProtocol                   negotiated ALPN, or ''
  // LInfo.ServerName                     SNI the peer sent (server side)
  // LInfo.Resumed                        True if this was a resumption
  // LInfo.PeerCertificates               validated peer chain, leaf first (TArray<TBytes>)
  // LInfo.PeerOcspStaple                 the stapled OCSP response, if any
end;
```

## Resume sessions

Resumption is `psk_dhe_ke` (forward-secret) and single-use by default. Give the **client** a session
cache; the **server** resumes out of the box via stateless tickets, or upgrade it to a stateful,
truly-single-use store.

```pascal
uses TlpInMemorySessionCache, TlpInMemorySessionStore, TlpSessionTicketKeys, TlpISession;

// CLIENT: keep tickets across connections in one cache (share it across your client configs)
LClientConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(caPem)
  .WithResumption(True)
  .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
  .Build;

// SERVER: stateless STEK tickets (rotating key), the default resumption path
LServerConfig := TTlsPresets.Compatible(P).Server
  .WithCredential(chainPem, keyPem)
  .WithResumption(True)
  .WithSessionTicketKeys(TStekTicketKeyManager.Create(P.GetRandom) as ISessionTicketKeyManager)
  .Build;

// SERVER (stronger): add a stateful store to get true single-use tickets + 0-RTT anti-replay
  .WithSessionStore(TInMemorySessionStore.Create(P.GetRandom) as ISessionStore)
```

Both default in-memory implementations are bounded and safe to share across connections/threads.

## 0-RTT early data

0-RTT is **off by default** and is a deliberate opt-in, because early data is replayable — only send
*idempotent* requests as early data. Enable it on both ends, and give the server an anti-replay
strategy:

```pascal
uses TlpAntiReplay, TlpISession;

// SERVER: authorize an early-data budget + register replays (needs resumption + a store)
LServerConfig := TTlsPresets.Compatible(P).Server
  .WithCredential(chainPem, keyPem)
  .WithResumption(True)
  .WithSessionStore(TInMemorySessionStore.Create(P.GetRandom) as ISessionStore)
  .Tls13
    .WithEarlyData({MaxBytes=}16384)
    .WithAntiReplay(TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy)
  .Build;

// CLIENT: allow offering early data on a resumed connection
LClientConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(caPem)
  .WithResumption(True)
  .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
  .Tls13.WithEarlyData(True)
  .Build;
```

Sending the early bytes themselves is a sans-IO engine intent (`WriteEarlyData`), and acceptance is
reported as an event; if the server rejects 0-RTT the data is transparently re-sent 1-RTT. Treat
0-RTT as an advanced optimisation — leave it off unless you need it and your early request is
idempotent.

## Set a revocation posture

The posture governs how an **unknown/indeterminate** status is treated; a definitive, authenticated
**Revoked** always aborts with `certificate_revoked` under every posture:

```pascal
uses TlpTrustPolicy;   // TRevocationPosture

.WithRevocation(TRevocationPosture.Soft)   // default: accept missing/indeterminate status
.WithRevocation(TRevocationPosture.Hard)   // reject missing/indeterminate status
.WithRevocation(TRevocationPosture.Off)    // don't require status (and perform no live fetch)
```

Stapled OCSP is validated in the handshake pipeline. **Live** OCSP/CRL is opt-in, never in the
sans-IO core: you attach a resolver to the `TTlsStream` backed by the reference socket fetcher
`TSocketHttpFetcher` (unit `TlpSocketHttpFetcher`, in `TlsLib.Net/` — a loose unit, not a package). The full wiring — including `must-staple`, the
posture/live-channel interaction, and server-side client-cert revocation — is in
[certificate-verification.md → Live OCSP/CRL](certificate-verification.md#live-ocspcrl-revocation-opt-in).

## Certificate compression

RFC 8879 certificate compression is **on by default** (zlib) for TLS 1.3 — most valuable for large
chains, notably PQ certificates. Nothing to configure to benefit as a client (you decompress inbound
automatically) or a server (you compress when the client offers a matching algorithm and it shrinks
the message).

To make a busy server deflate its stable certificate **once** instead of every handshake, add the
cross-connection cache (server, opt-in, bounded, thread-safe):

```pascal
uses TlpInMemoryCertificateCompressionCache, TlpICertificateCompressionCache;

LServerConfig := TTlsPresets.Compatible(P).Server
  .WithCredential(chainPem, keyPem)
  .Tls13.WithCertificateCompressionCache(
    TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache)
  .Build;
```

Full detail — algorithms, the bomb-defense on decompression, why the cache can never change the wire
output — in [certificate-compression.md](certificate-compression.md).

## External (out-of-band) PSKs

For RFC 9258 external pre-shared keys (a key both endpoints already share out of band, not from a
prior handshake):

```pascal
uses TlpSession, TlpSecretBuffer, TlpCryptoAlgorithms;   // TExternalPsk, TSecretBuffer, THashAlgorithm

var LPsk: TExternalPsk;
begin
  LPsk.Identity := IdentityBytes;                 // agreed identity label
  LPsk.Secret   := TSecretBuffer.From(KeyBytes);  // the shared key material
  LPsk.Context  := nil;                            // optional binder context
  LPsk.Hash     := THashAlgorithm.SHA_256;         // the PSK's bound hash

  LConfig := TTlsPresets.Compatible(P).Client
    .WithTrustAnchors(caPem)
    .WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(LPsk))
    // .WithExternalPskRequired(True)   // refuse to proceed without one
    .Build;
end;
```

Both ends configure the same identity + key. Use `WithExternalPskRequired(True)` when the deployment
must not fall back to certificate authentication.

## The dangerous surface (dev only)

Everything that weakens authentication lives behind one loudly-named surface, and even then the
builder makes you type more than one thing. **Never ship these.**

```pascal
// accept ANY chain — no PKIX, no revocation, no host-name. Tests / pinned dev peers only.
uses TlpICertificateTrust, TlpCertificateVerifier;
LConfig := TTlsPresets.Compatible(P).Client
  .WithDangerousInsecureSkipVerify(True)
  .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)  // still required; never consulted
  .Build;

// relax ONLY the host-name check (chain still fully validated)
.WithNameCheck(False)
```

An *augment-only* verify callback (`WithCertificateVerifyCallback`) can add extra rejections on top
of normal validation but can never accept a chain the pipeline rejected — that, and how this differs
from the .NET/rustls "replace validation" model, is in
[certificate-verification.md → the dangerous escape hatches](certificate-verification.md#4-the-dangerous-escape-hatches).

---

*Didn't find your task? The [verification](certificate-verification.md),
[system-trust](system-trust.md), and [compression](certificate-compression.md) guides go deeper, and
each adapter's README covers its stack's specifics.*
