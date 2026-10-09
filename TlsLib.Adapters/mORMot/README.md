# TlsLib4Pascal — mORMot adapter

Drops TlsLib4Pascal's managed TLS engine into an existing **mORMot 2** app through
mORMot's own `INetTls` "swap-your-SSL" seam — no fork, no recompile of mORMot.

## How to swap it in

Add `TlsLibMormotTls` to your uses clause and point mORMot's global factory at ours **once**,
at startup (before any `TCrtSocket` is created):

```pascal
uses mormot.net.sock, TlsLibMormotTls;
begin
  RegisterTlsLib4PascalTls;          // NewNetTls := NewTlsLib4PascalTls
  // ... every TCrtSocket opened with TLS now uses TlsLib4Pascal
end;
```

That is the whole integration. `RegisterTlsLib4PascalTls` mirrors how `mormot.lib.openssl11`
assigns `NewNetTls`; if you prefer, assign it yourself: `NewNetTls := NewTlsLib4PascalTls;`.

## What maps onto what (`TNetTlsContext` → our config)

| mORMot `TNetTlsContext` field            | TlsLib4Pascal                                             |
|------------------------------------------|----------------------------------------------------------|
| `CACertificatesFile`                     | `WithTrustAnchors` (PEM/DER bundle)                       |
| `CertificateFile` + `PrivateKeyFile` + `PrivatePassword` | `WithCredential` (server cert/key, or client mTLS) |
| `ClientCertificateAuthentication`        | `WithPeerAuth(Required)` + client-chain trust; `False` (default) never requests a client certificate. The client-CA is `CACertificatesFile` (`CASystemStores` is a server-cert source, ignored on a server). `Requested` (ask, tolerate absence) is available through `SetTlsLibMormotServerConfig` with a builder-driven config |
| `IgnoreCertificateErrors`                | **`dangerous` `WithDangerousInsecureSkipVerify`** (see below) |
| `DisableTls13`                           | offers TLS 1.2 alone (`SupportedVersions`)                |
| `CipherName` (out)                       | filled with the negotiated suite and version (`TLS_AES_128_GCM_SHA256 TLSv1.3`) |

**Certificate chain**: `CertificateFile` is the chain the server *presents* — put your leaf **followed
by any intermediates** in one PEM file so clients build a complete chain. `CACertificatesFile` is a
**trust source** (used to verify the *peer*), never part of what you send; putting intermediates only
there leaves the presented chain incomplete, forcing clients to fetch the missing CA.

Accepted **and ignored** (documented no-ops — we are TLS 1.2+ and never renegotiate; they never
silently weaken the connection): `AllowDeprecatedTls`, `ClientAllowUnsafeRenegotation`,
`ClientVerifyOnce`, `ReleaseBuffers`, `WithPeerInfo` and
`OnPrivatePassword` (set `PrivatePassword`; an encrypted key without it fails loudly at load).
Of the output fields only `CipherName` (and a server's `LastError`) are filled; `PeerIssuer`,
`PeerSubject`, `PeerInfo` and `PeerCert` stay empty.

**Trust precedence** follows mORMot's OpenSSL backend: a client uses `CACertificatesFile`
exclusively when it is set, and the `CASystemStores` OS roots only when it is not.

**PKCS#12 (`.pfx`)**: mORMot passes cert/key as separate files, so map those to `WithCredential`.
To load a `.pfx` blob instead, build the credential yourself with
`TTlsCredential.LoadPkcs12(crypto, pfxBytes, password)` and pass it to `WithCredential` on a config
builder you drive directly (`TTlsPresets.…(crypto, pkix).Server`).

## Trust is ours (`dangerous` mapping)

`IgnoreCertificateErrors` reaches **only** our loud `InsecureSkipVerify` — a full, deliberate
bypass of PKIX/OCSP/host/pinning for tests and pinned dev peers, **never** production. With it
off (the default), an untrusted chain fails through our pipeline. `CASystemStores` is the OS
server-certificate store: a client verifies a server against it, but a server never authenticates
clients against it — a server's client-CA is `CACertificatesFile`.

mORMot's native peer-verify callbacks (`OnPeerValidate` / `OnEachPeerVerify` /
`OnAfterPeerValidate`) are **not** bridged, by design: their signatures hand the app an OpenSSL
`PSSL` / `PX509` pointer to dereference, so honouring them would re-couple the adapter to OpenSSL —
the dependency it exists to avoid. Because silently ignoring one would drop a rule the app relies
on (for example a client-certificate allow-list), a context that sets any of them — or
`HostNamesCsv`, `OnAcceptServerName`, or an in-memory `CertificateBin` / `CertificateRaw` /
`PrivateKeyRaw` / `CACertificatesRaw` — **fails loudly**: a client at connect, a server at bind.

`CipherList` is honoured: exact IANA or OpenSSL suite names, separated by `:`, `,` or spaces, in
preference order. It narrows and reorders TlsLib's own hardened set and never widens it. A list that
names no TLS 1.3 suite leaves TLS 1.3 on with its default suites (an OpenSSL cipher list never
governed 1.3); a list that names TLS 1.3 suites narrows 1.3 too, and a list naming only TLS 1.3
suites turns TLS 1.2 off. Cipher-string expressions such as `HIGH` or `!aNULL`, and suites TlsLib
does not implement, fail loudly rather than being skipped; empty or `DEFAULT` keeps the preset, and a
list beside a config supplied with `SetTlsLibMormotClientConfig` / `SetTlsLibMormotServerConfig` is
refused.

Instead, the neutral hooks are process-wide setters (mORMot builds an `INetTls` per connection
through the global factory, so its hooks are set the same way):

```pascal
SetTlsLibMormotVerifyCallback(cb);                            // augment-only  chain+host -> Boolean
SetTlsLibMormotVerdictResolver(resolver, deadlineMs);         // client role: decides the server's chain
SetTlsLibMormotServerVerdictResolver(resolver, deadlineMs);   // server role: decides an mTLS client's chain
SetTlsLibMormotHandshakeTimeout(ms);                          // bounds the handshake read; 0 = 30 s default
```

`VerifyCallback` runs after our pipeline accepts the chain and can only additionally reject.
The resolvers decide a parked verdict out-of-band — wire `TLiveRevocationChecker.ResolveVerdict`
(from `TlpLiveRevocation`, over an injected `IHttpFetcher`) to them for live OCSP/CRL. The verdict
resolver is role-specific: the client hook evaluates the server's chain (server-auth EKU), the
server hook an mTLS client's chain (client-auth EKU), so they are separate — pair each with the
matching `TOSSystemTrust.LiveRevocationResolver` overload (client vs server config). Both are
fail-closed and never loosen our verdict. Beside a config you supply yourself, that config must
itself defer the verdict (`WithLiveRevocationVerdict`), else the connection is refused.

For the full trust picture — trusting a private CA, public-key pinning, host-name-only
relaxation, the `dangerous` escape hatches, and an ASP.NET Core mapping — see
[docs/certificate-verification.md](../../docs/certificate-verification.md).

## Notes

- `GetRawTls` returns `nil`: TlsLib4Pascal is a managed engine with no `PSSL`/OpenSSL handle to
  hand back. `GetRawCert` returns the peer leaf DER (for mORMot's cert pinning / peer info), but
  not the signature-hash name, so TLS channel binding that needs it stays inert. On a resumed
  connection it returns the leaf stored with the session (previously it was empty on a resume).
- Application reads honour the socket's own `ReceiveTimeout`: an idle peer surfaces from `Receive`
  as `nrRetry` with the connection intact (never a fatal error or a truncation), exactly as mORMot's
  plain sockets report it. A send that stays blocked because the peer stopped reading is bounded
  (30 s) and then fails rather than retrying forever.
- Blocking seam only (the standard mORMot `TCrtSocket` path). Async frameworks
  (`mormot.net.async`) drive the raw Tier-0 engine off `WantsRead`/`WantsWrite` instead.

## Proven

`Examples/` — the loopback (shared logic in `src/MormotLoopbackExample.pas`) builds as a Lazarus
project (`Lazarus/MormotLoopback.lpi`) or a Delphi project (`Delphi/MormotLoopback.dproj`), each
driving our `INetTls` on both ends over mORMot's socket layer on `127.0.0.1`: full TLS 1.3
handshake + application echo, negotiated version asserted.

`Examples/` also carries a **real-world** demo (`src/MormotRealWorldExample.pas`,
`Lazarus/MormotRealWorld.lpi` / `Delphi/MormotRealWorld.dproj`): a single unmodified
`THttpClientSocket` does a live HTTPS `GET` and `POST` to `postman-echo.com` with its TLS handled
entirely by TlsLib4Pascal — a real handshake against a real internet server, real certificate
verification against a **pinned** root (`data/isrg-roots.pem`, the self-signed ISRG roots; **not**
`IgnoreCertificateErrors`), and real HTTP over our records, with zero OpenSSL. It calls
`RegisterTlsLib4PascalTls` to point mORMot's `NewNetTls` factory at our `INetTls`, sets trust via
`Client.TLS.CACertificatesFile`, and drives both verbs with a keep-alive `Get`/`Post` over **one
reused TLS connection**. It is a **network-gated demo, not a test gate**: it needs outbound HTTPS
and exits 0 (PASS) / 2 (SKIP, offline) / 1 (FAIL).

`Examples/` also carries an **advanced-config** demo (`src/MormotAdvancedConfigExample.pas`,
`Lazarus/MormotAdvancedConfig.lpi` / `Delphi/MormotAdvancedConfig.dproj`): instead of the
`TNetTlsContext` cert/trust fields, it installs fully-built configs process-wide via
`SetTlsLibMormotServerConfig` / `SetTlsLibMormotClientConfig` — an ordered, bound cipher-suite
preference pinned to TLS 1.2, so the negotiated 1.2 (the preset would pick 1.3) proves the injected
config replaced the built-in build. This is the escape hatch to the whole builder API (cipher
order, groups, resumption, ALPN, …). A built config supplied alongside cert/trust options (or
`DisableTls13`, a verify callback or a crypto/PKIX provider) is refused, not silently dropped.
