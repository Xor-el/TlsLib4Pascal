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
| `ClientCertificateAuthentication`        | `WithPeerAuth(Required)` + client-chain trust            |
| `IgnoreCertificateErrors`                | **`dangerous` `WithDangerousInsecureSkipVerify`** (see below) |
| `CipherName` (out)                       | filled with the negotiated version (`TLSv1.3`/`TLSv1.2`) |

Accepted **and ignored** (documented no-ops — we are TLS 1.2+ and never renegotiate; they never
silently weaken the connection): `DisableTls13`, `AllowDeprecatedTls`, `ClientAllowUnsafeRenegotation`.

**PKCS#12 (`.pfx`)**: mORMot passes cert/key as separate files, so map those to `WithCredential`.
To load a `.pfx` blob instead, build the credential yourself with the provider's
`WithCredentialPkcs12(pfxBytes, password)` and drive `TTlsConfigBuilder` directly.

## Trust is ours (`dangerous` mapping)

`IgnoreCertificateErrors` reaches **only** our loud `InsecureSkipVerify` — a full, deliberate
bypass of PKIX/OCSP/host/pinning for tests and pinned dev peers, **never** production. With it
off (the default), an untrusted chain fails through our pipeline. System certificate stores
(`CASystemStores`) are not consulted — supply `CACertificatesFile`.

mORMot's native peer-verify callbacks (`OnPeerValidate` / `OnEachPeerVerify`) are **not**
bridged, by design: their signatures hand the app an OpenSSL `PSSL` / `PX509` pointer to
dereference, so honouring them would re-couple the adapter to OpenSSL — the dependency it
exists to avoid.

Instead, the neutral hooks are process-wide setters (mORMot builds an `INetTls` per connection
through the global factory, so its hooks are set the same way):

```pascal
SetTlsLibMormotVerifyCallback(cb);                      // augment-only  chain+host -> Boolean
SetTlsLibMormotVerdictResolver(resolver, deadlineMs);   // out-of-band verdict; parks the handshake
```

`VerifyCallback` runs after our pipeline accepts the chain and can only additionally reject.
The resolver decides a parked verdict out-of-band — wire `TLiveRevocationChecker.ResolveVerdict`
(from `TlpLiveRevocation`, over an injected `IHttpFetcher`) to it for live OCSP/CRL. Both are
fail-closed and never loosen our verdict.

For the full trust picture — trusting a private CA, public-key pinning, host-name-only
relaxation, the `dangerous` escape hatches, and an ASP.NET Core mapping — see
[docs/certificate-verification.md](../../docs/certificate-verification.md).

## Notes

- `GetRawTls` returns `nil`: TlsLib4Pascal is a managed engine with no `PSSL`/OpenSSL handle to
  hand back. `GetRawCert` returns the peer leaf DER (for mORMot's cert pinning / peer info), but
  not the signature-hash name, so TLS channel binding that needs it stays inert.
- Blocking seam only (the standard mORMot `TCrtSocket` path). Async frameworks
  (`mormot.net.async`) drive the raw Tier-1 engine off `WantsRead`/`WantsWrite` instead.

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
order, groups, resumption, ALPN, …).
