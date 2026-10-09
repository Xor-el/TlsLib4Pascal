# TlsLib4Pascal — Synapse adapter

Drops TlsLib4Pascal's managed TLS engine into an existing **Ararat Synapse** app
through Synapse's `TCustomSSL` "swap-your-SSL" seam — no OpenSSL.

## How to swap it in

Synapse is a **compile-time** plugin model: `uses` the plugin unit and its `initialization`
block registers it as the process-wide `SSLImplementation`. **Exactly one SSL plugin unit may be
linked per project** — do *not* also link `ssl_openssl`.

```pascal
uses blcksock, TlsLibSynapseTls;   // registers SSLImplementation := TSSLTlsLib

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
| `CertCAFile`                                         | `WithTrustAnchors` (client trust, or a server's client-auth CA) |
| `CertificateFile` + `PrivateKeyFile` + `KeyPassword` | `WithCredential` (server cert/key)       |
| `SNIHost`                                            | SNI + the verified host name             |
| `VerifyCert` (default **True** here)                 | verify on/off; **False** → **`dangerous` `WithDangerousInsecureSkipVerify`** |
| `ClientAuth` (extension, **server**) | `WithPeerAuth(None / Requested / Required)`; default `None` never requests a client certificate. Any other mode needs `VerifyCert` on and a private client-CA (`CertCAFile`), else the build fails closed. `UseSystemTrust` is a server-cert source, never a client-CA |
| `OnVerifyCert` (native hook)                         | augment-only bridge (see below)          |
| `SSLType`                                            | `LT_all` offers TLS 1.3 and 1.2; `LT_TLSv1_2` / `LT_TLSv1_3` offer that version alone; any other value fails the handshake |
| `HandshakeTimeoutMs`                                 | bounds the handshake read (ms); `0` = 30 s default |
| `ReadTimeoutMs` (extension)                          | bounds one `RecvBuffer` call (ms), including records with no application data; `0` (default) blocks, as Synapse's other TLS plugins do. Synapse's own timeouts only wait for the first byte, so set this on each accepted socket of a server that reads from untrusted peers, not on a client waiting on a slow server. A timeout surfaces as `WSASYSNOTREADY`, is retryable, and loses no data |

A server never requests a client certificate unless you set `ClientAuth` (cast `Sock.SSL` to
`TSSLTlsLib`); `CertCAFile` is the private client-CA a presented chain is verified against.
(Synapse's own OpenSSL plugin makes `VerifyCert` alone request one on a server; here that is this
explicit knob.) `UseSystemTrust` is a server-certificate source (a client verifying a server) and is
**not** a valid client-CA: a mode whose only source is it fails the build.

**Certificate chain**: `CertificateFile` is the chain the server *presents* — put your leaf **followed
by any intermediates** in one PEM file so clients build a complete chain. `CertCAFile` is a **trust
source** (used to verify the *peer*), never part of what you send; putting intermediates only there
leaves the presented chain incomplete, forcing clients to fetch the missing CA.

**PKCS#12 (`.pfx`)**: Synapse also exposes `PFX`/`PFXfile`. To use a `.pfx`, build the credential
with `TTlsCredential.LoadPkcs12(crypto, pfxBytes, password)` and pass it to `WithCredential` on a config
builder you drive directly (`TTlsPresets.…(crypto, pkix).Server`); the `CertificateFile`/`PrivateKeyFile`
path here covers PEM/DER pairs.

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
pipeline already rejected. The hook also runs on a resumed connection now (against the leaf stored
with the session), so an `OnVerifyCert` with side effects will see it fire on resumes too. (Unlike Indy's and mORMot's native hooks, `OnVerifyCert`'s signature —
`function(Sender: TObject): Boolean` — carries no OpenSSL type, so bridging it forces no coupling.)

**Neutral hooks (no drop to Tier-2).** For an app's own augment rule, or an out-of-band verdict
such as live OCSP/CRL, set the process-wide hooks the plugin threads into each handshake, by role:

```pascal
SetTlsLibSynapseVerifyCallback(cb);                            // augment-only  chain+host -> Boolean
SetTlsLibSynapseVerdictResolver(resolver, deadlineMs);         // client role: decides the server's chain
SetTlsLibSynapseServerVerdictResolver(resolver, deadlineMs);   // server role: decides an mTLS client's chain
```

Being process-wide, set these before opening any connection; changing a hook while connections are
in flight is not supported. A resolver beside a supplied config must be paired with a config that
itself defers the verdict (`WithLiveRevocationVerdict`), else the connection is refused.

Wire `TLiveRevocationChecker.ResolveVerdict` (from `TlpLiveRevocation`, over an injected
`IHttpFetcher`) as the resolver to get live revocation. The resolver is role-specific — the client
hook evaluates the server's chain (server-auth EKU), the server hook an mTLS client's chain
(client-auth EKU) — so pair each with the matching `TOSSystemTrust.LiveRevocationResolver` overload
(client vs server config).

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
order, groups, resumption, ALPN, …). A built config supplied alongside cert/trust options (or a
pinned `SSLType`, a verify callback or a crypto/PKIX provider) is refused, not silently dropped.

Synapse's `Ciphers` property names the suites to use: exact IANA or OpenSSL suite names, separated
by `:`, `,` or spaces, in preference order. It narrows and reorders TlsLib's own hardened set and
never widens it. A list that names no TLS 1.3 suite leaves TLS 1.3 on with its default suites (an
OpenSSL cipher list never governed 1.3); a list that names TLS 1.3 suites narrows 1.3 too, and a
list naming only TLS 1.3 suites turns TLS 1.2 off. Cipher-string expressions such as `HIGH` or
`!aNULL`, and suites TlsLib does not implement, fail the handshake rather than being skipped; empty
or `DEFAULT` keeps the preset, and a list beside a supplied `ClientConfig` / `ServerConfig` is
refused.
