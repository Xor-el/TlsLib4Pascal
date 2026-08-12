# TlsLib4Pascal — Indy adapter

Drops TlsLib4Pascal's managed TLS engine into an existing **Indy** app through Indy's
own `TIdSSLIOHandlerSocketBase` / `TIdServerIOHandlerSSLBase` "swap-your-SSL" seam — no OpenSSL.

## How to swap it in

Replace your OpenSSL IOHandler with ours — it is a drop-in `TIdIOHandler`.

**Client** (`TIdTCPClient`, or any Indy client component):

```pascal
uses TlsLibIndyTls;
...
IO := TTlsLibIOHandlerSocket.Create(Client);
IO.SSLOptions.RootCertFile := 'ca-bundle.pem';   // trust
Client.IOHandler := IO;
Client.Host := 'example.com';                     // used for SNI + verification
Client.Connect;                                   // handshake runs here
```

**Server** (`TIdTCPServer`):

```pascal
SrvIO := TTlsLibServerIOHandler.Create(Server);
SrvIO.SSLOptions.CertFile := 'server-cert.pem';
SrvIO.SSLOptions.KeyFile  := 'server-key.pem';
Server.IOHandler := SrvIO;                         // each accepted peer handshakes on accept
```

## STARTTLS / `PassThrough`

`PassThrough` is honoured. Start plaintext by setting `IO.PassThrough := True` before connecting;
when the protocol says "go secure", set `IO.PassThrough := False` and the handshake runs then
(the classic STARTTLS upgrade).

## What maps onto what (`SSLOptions` → our config)

| `TTlsLibSSLOptions`                | TlsLib4Pascal                                              |
|-----------------------------------|-----------------------------------------------------------|
| `RootCertFile`                    | `WithTrustAnchors` (client trust / server client-auth CA) |
| `CertFile` + `KeyFile` + `KeyPassword` | `WithCredential` (server cert/key, or client mTLS)   |
| `VerifyPeer` (server)             | `WithPeerAuth(Required)` when a `RootCertFile` is set      |
| `VerifyPeer = False` / `InsecureSkipVerify` | **`dangerous` `WithDangerousInsecureSkipVerify`** |
| `VerifyCallback`                  | neutral augment-only hook (`WithCertificateVerifyCallback`) |
| `VerdictResolver` + `VerdictDeadlineMs` | out-of-band async verdict, e.g. live OCSP/CRL      |

**PKCS#12 (`.pfx`)**: map a `.pfx` by building the credential with the provider's
`WithCredentialPkcs12(pfxBytes, password)` and driving `TTlsConfigBuilder` directly (the
file-based `SSLOptions` cover PEM/DER cert+key pairs).

## Trust is ours (`dangerous` mapping)

An empty verify posture / `InsecureSkipVerify` reaches **only** our loud `InsecureSkipVerify`
(a full, deliberate bypass — tests and pinned dev peers only, never production). With it off
(the default), an untrusted chain fails through our pipeline.

Indy's native `OnVerifyPeer` is **not** bridged, by design: its signature hands the app a
`TIdX509`, which is constructed from an OpenSSL `PX509` (`TIdX509.Create(aX509: PX509)`), so
honouring it would re-couple the adapter to OpenSSL — the dependency it exists to avoid.

Instead, the neutral hooks are on `SSLOptions` directly (no drop to Tier-2):

```pascal
IO.SSLOptions.VerifyCallback  := cb;         // augment-only  chain+host -> Boolean (reject further)
IO.SSLOptions.VerdictResolver := resolver;   // out-of-band verdict; parks the handshake
IO.SSLOptions.VerdictDeadlineMs := 5000;     // advisory deadline for the resolver
```

`VerifyCallback` runs after our pipeline accepts the chain and can only additionally reject.
`VerdictResolver` decides a parked verdict out-of-band — wire `TLiveRevocationChecker.ResolveVerdict`
(from `TlpLiveRevocation`, over an injected `IHttpFetcher`) to it for live OCSP/CRL. Both are
fail-closed and never loosen our verdict.

For the full trust picture — trusting a private CA, public-key pinning, host-name-only
relaxation, the `dangerous` escape hatches, and an ASP.NET Core mapping — see
[docs/certificate-verification.md](../../docs/certificate-verification.md).

## Notes

- Blocking seam only (the standard Indy IOHandler path).
- `Clone` is implemented, so the handler works with Indy's server IOHandler pooling.

## Proven

`Examples/` — the loopback (shared logic in `src/IndyLoopbackExample.pas`) builds as a Lazarus
project (`Lazarus/IndyLoopback.lpi`) or a Delphi project (`Delphi/IndyLoopback.dproj`): a
`TIdTCPServer` and `TIdTCPClient` on `127.0.0.1`, each using our IOHandlers — full TLS 1.3
handshake + application echo, negotiated version asserted.

`Examples/` also carries a **real-world** demo (`src/IndyRealWorldExample.pas`,
`Lazarus/IndyRealWorld.lpi` / `Delphi/IndyRealWorld.dproj`): a single unmodified `TIdHTTP` does a
live HTTPS `GET` and `POST` to `postman-echo.com` with its TLS handled entirely by TlsLib4Pascal — a
real handshake against a real internet server, real certificate verification against a **pinned**
root (`data/isrg-roots.pem`, the self-signed ISRG roots; **not** `InsecureSkipVerify`), and real
HTTP over our records, with zero OpenSSL. It is a **network-gated demo, not a test gate**: it needs
outbound HTTPS and exits 0 (PASS) / 2 (SKIP, offline) / 1 (FAIL). One `TIdHTTP` drives both verbs:
the adapter handshakes each connection Indy opens, so the second request works whether Indy keeps
the socket alive or reconnects (`ConnectClient` discards the prior TLS session so a reconnect
re-handshakes rather than reusing the closed session's keys).

`Examples/` also carries an **advanced-config** demo (`src/IndyAdvancedConfigExample.pas`,
`Lazarus/IndyAdvancedConfig.lpi` / `Delphi/IndyAdvancedConfig.dproj`): it hands the IOHandlers
fully-built configs through `SSLOptions.ServerConfig` / `SSLOptions.ClientConfig` — the escape
hatch to the whole builder API (cipher order, groups, resumption, ALPN, …) — and drives the
server's `WithCipherSuitePreference` both ways: `ServerOrder` (default) imposes the server's own
order, `ClientOrder` honors the client's. It reads the result back through the adapter's
`NegotiatedCipherSuite` accessor and asserts that under `ClientOrder` the client's most-preferred
suite always wins (flip the client's order, flip the result), while under `ServerOrder` the
negotiated suite is stable regardless of the client's order — proving, through the real handshake,
that only the server guides selection and can defer to the client when it chooses to.
