# TlsLib4Pascal — Synapse adapter

Drops TlsLib4Pascal's managed TLS engine into an existing **Ararat Synapse** app
through Synapse's `TCustomSSL` "swap-your-SSL" seam — no OpenSSL.

## How to swap it in

Synapse is a **compile-time** plugin model: `uses` the plugin unit and its `initialization`
block registers it as the process-wide `SSLImplementation`. **Exactly one SSL plugin unit may be
linked per project** — do *not* also link `ssl_openssl`.

```pascal
uses blcksock, TlpSynapseTls;   // registers SSLImplementation := TSSLTlsLib

// client
sock := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
sock.SSL.CertCAFile := 'ca-bundle.pem';
sock.SSL.VerifyCert := True;
sock.SSL.SNIHost := 'example.com';   // SNI + the name we verify the certificate for
sock.Connect('example.com', '443');
sock.SSLDoConnect;                    // handshake

// server (per accepted connection)
peer := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
peer.Socket := listener.Accept;
peer.SSL.CertificateFile := 'server-cert.pem';
peer.SSL.PrivateKeyFile  := 'server-key.pem';
peer.SSLAcceptConnection;             // handshake
```

> The plugin registers itself in its `initialization` block (`SSLImplementation := TSSLTlsLib`).
> Synapse selects the backend by that class reference, not by unit name.

## What maps onto what (`TCustomSSL` properties → our config)

| Synapse `TCustomSSL` property                        | TlsLib4Pascal                            |
|------------------------------------------------------|------------------------------------------|
| `CertCAFile`                                         | `WithTrustAnchors` (client trust)        |
| `CertificateFile` + `PrivateKeyFile` + `KeyPassword` | `WithCredential` (server cert/key)       |
| `SNIHost`                                            | SNI + the verified host name             |
| `VerifyCert` (default **True** here)                 | verify on/off; **False** → **`dangerous` `WithDangerousInsecureSkipVerify`** |
| `OnVerifyCert` (native hook)                         | augment-only bridge (see below)          |
| `SSLType`                                            | accepted and ignored (we are TLS 1.2+)   |

**Certificate chain**: `CertificateFile` is the chain the server *presents* — put your leaf **followed
by any intermediates** in one PEM file so clients build a complete chain. `CertCAFile` is a **trust
source** (used to verify the *peer*), never part of what you send; putting intermediates only there
leaves the presented chain incomplete, forcing clients to fetch the missing CA.

**PKCS#12 (`.pfx`)**: Synapse also exposes `PFX`/`PFXfile`. To use a `.pfx`, build the credential
with the provider's `WithCredentialPkcs12(pfxBytes, password)` and drive `TTlsConfigBuilder`
directly; the `CertificateFile`/`PrivateKeyFile` path here covers PEM/DER pairs.

## Trust is ours (`dangerous` mapping)

**Verification is on by default — safer than stock Synapse.** Synapse's own `TCustomSSL` defaults
`VerifyCert` to `False`; this plugin's constructor flips it to **`True`**, so a dropped-in socket
verifies (name a `CertCAFile` + `SNIHost`, or `UseSystemTrust`). Setting `VerifyCert := False` is
the loud, deliberate bypass — a full bypass of PKIX/OCSP/host/pinning for tests and pinned dev
peers, **never** production. With `VerifyCert := True` and no trust source named, the build fails
closed (system trust is never implicit).

**Native `OnVerifyCert` hook (bridged).** Set `sock.SSL.OnVerifyCert := yourHandler` before the
handshake. After our built-in pipeline accepts the server chain, the plugin calls your handler,
which inspects the peer through the standard `TCustomSSL` accessors — `GetPeerSubject`,
`GetPeerIssuer`, `GetPeerName`, `GetPeerFingerprint` (SHA-256 of the leaf, lowercase hex),
`GetPeerSerialNo` — and returns `False` to reject (fail-closed with `bad_certificate`). It is
**augment-only**: it can add a reject rule on top of our verdict, never rescue a chain the
pipeline already rejected. (Unlike Indy's and mORMot's native hooks, `OnVerifyCert`'s signature —
`function(Sender: TObject): Boolean` — carries no OpenSSL type, so bridging it forces no coupling.)

**Neutral hooks (no drop to Tier-2).** For an app's own augment rule, or an out-of-band verdict
such as live OCSP/CRL, set the process-wide hooks the plugin threads into every client handshake:

```pascal
SetTlsLibSynapseVerifyCallback(cb);                      // augment-only  chain+host -> Boolean
SetTlsLibSynapseVerdictResolver(resolver, deadlineMs);   // parks the handshake for a verdict
```

Wire `TLiveRevocationChecker.ResolveVerdict` (from `TlpLiveRevocation`, over an injected
`IHttpFetcher`) as the resolver to get live revocation.

For the full trust picture — trusting a private CA, public-key pinning, host-name-only
relaxation, the `dangerous` escape hatches, and an ASP.NET Core mapping — see
[docs/certificate-verification.md](../../docs/certificate-verification.md).

## Notes

- The transport reads/writes the raw socket handle via `synsock`, bypassing `TTCPBlockSocket`'s
  own SSL-aware buffered methods (which would otherwise recurse once `SSLEnabled` is set).
- `WaitingData` reports our buffered plaintext count (the `SSL_pending` analogue).

## Proven

`Examples/` — the loopback (shared logic in `src/SynapseLoopbackExample.pas`) builds as a Lazarus
project (`Lazarus/SynapseLoopback.lpi`) or a Delphi project (`Delphi/SynapseLoopback.dproj`): two
`TTCPBlockSocket`s built with our plugin on `127.0.0.1`, full TLS 1.3 handshake + application echo.
Verified building + running under both FPC/Lazarus and Delphi.

`Examples/` also carries a **real-world** demo (`src/SynapseRealWorldExample.pas`,
`Lazarus/SynapseRealWorld.lpi` / `Delphi/SynapseRealWorld.dproj`): a single unmodified `THTTPSend`
does a live HTTPS `GET` and `POST` to `postman-echo.com` with its TLS handled entirely by
TlsLib4Pascal — a real handshake against a real internet server, real certificate verification
against a **pinned** root (`data/isrg-roots.pem`, the self-signed ISRG roots; **not** `VerifyCert
:= False`), and real HTTP over our records, with zero OpenSSL. It is a **network-gated demo, not a
test gate**: it needs outbound HTTPS and exits 0 (PASS) / 2 (SKIP, offline) / 1 (FAIL). `THTTPSend`
keeps the socket alive, so both verbs run over **one reused TLS connection** — exercising the
adapter's connection-reuse path end to end.

`Examples/` also carries an **advanced-config** demo (`src/SynapseAdvancedConfigExample.pas`,
`Lazarus/SynapseAdvancedConfig.lpi` / `Delphi/SynapseAdvancedConfig.dproj`): instead of the
`TCustomSSL` cert/CA properties, it hands each socket a fully-built config through
`(Sock.SSL as TSSLTlsLib).ServerConfig` / `ClientConfig` — an ordered, bound cipher-suite
preference pinned to TLS 1.2, so the negotiated 1.2 (the preset would pick 1.3) proves the injected
config replaced the built-in build. This is the escape hatch to the whole builder API (cipher
order, groups, resumption, ALPN, …).
