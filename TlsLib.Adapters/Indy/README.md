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
Client.Host := 'example.com';                     // used for SNI + verification (URIToCheck's host wins, so TIdHTTP via a proxy verifies the origin)
Client.Connect;                                   // handshake runs here
```

**Server** (`TIdTCPServer`):

```pascal
SrvIO := TTlsLibServerIOHandler.Create(Server);
SrvIO.SSLOptions.CertFile := 'server-cert.pem';
SrvIO.SSLOptions.KeyFile  := 'server-key.pem';
Server.IOHandler := SrvIO;                         // each peer handshakes on its first I/O, on its own worker thread
```

## STARTTLS / `PassThrough`

`PassThrough` is honoured and defaults to `False` (Indy's own base defaults it to `True`), so a
plain connect handshakes. Start plaintext by setting `IO.PassThrough := True` before connecting;
when the protocol says "go secure", set `IO.PassThrough := False` and the handshake runs then
(the classic STARTTLS upgrade).

## What maps onto what (`SSLOptions` → our config)

| `TTlsLibSSLOptions`                | TlsLib4Pascal                                              |
|-----------------------------------|-----------------------------------------------------------|
| `RootCertFile`                    | `WebPki` anchors (client trust; on a server the client-auth CA, consulted only when `ClientAuth <> None`) |
| `CertFile` + `KeyFile` + `KeyPassword` | `WithCredential` (server cert/key, or client mTLS); a `.pfx` / `.p12` `CertFile` is a PKCS#12 |
| `ClientAuth` (server)             | `WithPeerAuth(None / Requested / Required)`; the default `None` never requests a client certificate. Any other mode needs a private client-CA (`RootCertFile` or a `CustomTrustStore`/custom verifier) and `VerifyPeer` on, else the build fails closed. `UseSystemTrust` is a server-cert source, never a client-CA |
| `VerifyPeer = False` / `InsecureSkipVerify` | **`dangerous` `DangerousSkip`** |
| `UseSystemTrust`                  | OS roots plus `RootCertFile` and `CustomTrustStore` (server-cert trust only); the OS engine on Windows, macOS, iOS and Android, harvested roots on Unix ([rule](../../docs/system-trust.md#os-and-host-roots)); on Android, `RootCertFile` and `CustomTrustStore` roots do not apply to hosts a network-security-config `<domain-config>` names |
| `CustomTrustStore`                | an injected `ITrustAnchorStore`, unioned with the other anchor sources |
| `CustomServerCertificateVerifier` / `CustomClientCertificateVerifier` | `TServerVerification.Custom` / `TClientVerification.Custom` (replaces the pipeline; excludes every anchor source) |
| `SessionResumption`               | `WithResumption` (default `True`; 0-RTT is never enabled) |
| `Crypto` / `Pkix`                 | the providers the options-driven build uses (nil = the shared defaults) |
| `ClientConfig` / `ServerConfig`   | a fully built config that replaces the options-driven build |
| `VerifyCallback`                  | neutral augment-only hook (`WithCertificateVerifyCallback`) |
| `VerdictResolver` + `VerdictDeadlineMs` | client-role out-of-band verdict (server's chain), e.g. live OCSP/CRL |
| `ServerVerdictResolver` + `ServerVerdictDeadlineMs` | server-role out-of-band verdict (mTLS client's chain); beside a supplied `ClientConfig` / `ServerConfig` that config must itself defer the verdict, else the connection is refused; beside a server config that requests no client certificate the resolver is refused outright |
| `HandshakeTimeoutMs`              | bounds the handshake read (ms); `0` = 30 s default        |

**Certificate chain**: `CertFile` is the chain the server *presents* — put your leaf **followed by any
intermediates** in one PEM file (a concatenation) so clients build a complete chain. `RootCertFile` is
a **trust source** (used to verify the *peer*), never part of what you send; putting intermediates only
there leaves the presented chain incomplete, forcing clients to fetch the missing CA (slow, and it fails
where fetching is blocked).

**PKCS#12 (`.pfx`)**: a `CertFile` ending in `.pfx` or `.p12` is read as a PKCS#12 identity opened
with `KeyPassword`, as in Indy's own handler; `KeyFile` must then be empty or the same file. Its CA
bag is sent as part of the chain and never trusted. A `.pfx` on `KeyFile` beside a PEM `CertFile`
**fails loudly**.

**Mutual TLS (client certificates)**: a server requests client certificates only when you set
`SSLOptions.ClientAuth` — `Requested` (ask, tolerate a client that sends none) or `Required` (ask,
abort when none is presented); the default `None` never asks. Setting a `RootCertFile` alone does not
request client certificates — it is only the CA a presented client chain is verified against.
`UseSystemTrust` is a server-certificate source (a client verifying a server) and is **not** a valid
client-CA: a mode whose only trust source is it fails the build. Name a private `RootCertFile` (or a
`CustomTrustStore`) for the client-CA instead.

## Trust is ours (`dangerous` mapping)

`VerifyPeer := False` or `InsecureSkipVerify := True` reaches **only** our loud `DangerousSkip`
(a full, deliberate bypass — tests and pinned dev peers only, never production). With it off
(the default), an untrusted chain fails through our pipeline.

Indy's native `OnVerifyPeer` is **not** bridged, by design: its signature hands the app a
`TIdX509`, which is constructed from an OpenSSL `PX509` (`TIdX509.Create(aX509: PX509)`), so
honouring it would re-couple the adapter to OpenSSL — the dependency it exists to avoid.

Instead, the neutral hooks are on `SSLOptions` directly (no drop to Tier-2):

```pascal
IO.SSLOptions.VerifyCallback  := cb;               // augment-only, runs last: presented, validated, host -> Boolean
IO.SSLOptions.VerdictResolver := resolver;         // client role: decides the server's chain
IO.SSLOptions.VerdictDeadlineMs := 5000;           // client resolver's fetch budget (ms)
IO.SSLOptions.ServerVerdictResolver := resolver;   // server role: decides an mTLS client's chain
IO.SSLOptions.ServerVerdictDeadlineMs := 5000;     // server resolver's fetch budget (ms)
```

`VerifyCallback` runs last, after our pipeline and any pinning accept the chain, and can only
additionally reject. It receives the chain the peer presented and the path that was validated (`nil`
when verification was skipped).
The verdict resolvers decide a parked verdict out-of-band — wire `TLiveRevocationChecker.ResolveVerdict`
(from `TlpLiveRevocation`, over an injected `IHttpFetcher`) to them for live OCSP/CRL. The resolver is
role-specific: the client hook evaluates the server's chain (server-auth EKU), the server hook an mTLS
client's chain (client-auth EKU), so pair each with the matching `TOSSystemTrust.LiveRevocationResolver`
overload (client vs server config). All are fail-closed and never loosen our verdict.

These hooks are per handler, so the server-role ones are refused at build when `ClientAuth` is `None`
(`VerifyCallback` too: a server reaches it only through a requested client chain).

For the full trust picture — trusting a private CA, public-key pinning, host-name-only
relaxation, the `dangerous` escape hatches, and an ASP.NET Core mapping — see
[docs/certificate-verification.md](../../docs/certificate-verification.md).

## Notes

- Blocking seam only (the standard Indy IOHandler path).
- A connection is not thread-safe once the handshake is done: do not read and write it from two
  threads at once (a broadcaster writing while a worker reads must serialize), because a read can
  flush queued outbound records.
- `Clone` is implemented, so the handler works with Indy's server IOHandler pooling. The FTP data
  channels (`MakeFTPSvrPort` / `MakeFTPSvrPasv`) get a handler built from the same options.
- `KeyPassword` is not streamed (`stored False`), so a password never lands in a `.dfm`.
- `Close` sends a best-effort `close_notify` before the socket is torn down.
- A read that ends without the peer's `close_notify` raises `ETlsTransportTruncated`, and raises it
  again on every later read. Indy's `Connected` reads the socket too, so after such a truncation it
  raises the same error instead of returning `False`; `Disconnect` swallows it.
- A read that outlives Indy's `ReadTimeout` surfaces as `Id_WSAETIMEDOUT`; `HandshakeTimeoutMs`
  bounds the handshake separately.
- After the handshake the client handler reports `NegotiatedVersion`, `NegotiatedCipherSuite`,
  `NegotiatedGroup`, `PeerServerName`, `EchStatus`, `Resumed` and `NegotiatedAlpn` (text; empty when
  none was agreed).
- Built configs are cached and reused. After rotating a certificate or key, call
  `TTlsLibIOHandlerSocket.FlushConfigCache` (client, process-wide) or the listener's
  `TTlsLibServerIOHandler.FlushConfigCache` so the next connection rebuilds and the retired key is
  released.

## Proven

`Examples/` — the loopback (shared logic in `src/IndyLoopbackExample.pas`) builds as a Lazarus
project (`Lazarus/IndyLoopback.lpi`) or a Delphi project (`Delphi/IndyLoopback.dpr`): a
`TIdTCPServer` and `TIdTCPClient` on `127.0.0.1`, each using our IOHandlers — full TLS 1.3
handshake + application echo, negotiated version asserted.

`Examples/` also carries a **real-world** demo (`src/IndyRealWorldExample.pas`,
`Lazarus/IndyRealWorld.lpi` / `Delphi/IndyRealWorld.dpr`): a single unmodified `TIdHTTP` does a
live HTTPS `GET` and `POST` to `postman-echo.com` with its TLS handled entirely by TlsLib4Pascal — a
real handshake against a real internet server, real certificate verification, and real HTTP over
our records, with zero OpenSSL. It runs twice: leg A verifies against the pinned root
(`data/isrg-roots.pem`), leg B against the OS trust store (`UseSystemTrust`). Neither skips
verification. It is a **network-gated demo, not a test gate**: it needs outbound HTTPS and exits
0 (both legs PASS) / 2 (SKIP, offline) / 1 (FAIL). One `TIdHTTP` drives both verbs:
the adapter handshakes each connection Indy opens, so the second request works whether Indy keeps
the socket alive or reconnects (`ConnectClient` discards the prior TLS session so a reconnect
re-handshakes rather than reusing the closed session's keys).

`Examples/` also carries an **advanced-config** demo (`src/IndyAdvancedConfigExample.pas`,
`Lazarus/IndyAdvancedConfig.lpi` / `Delphi/IndyAdvancedConfig.dpr`): it hands the IOHandlers
fully-built configs through `SSLOptions.ServerConfig` / `SSLOptions.ClientConfig` — the escape
hatch to the whole builder API (cipher order, groups, resumption, ALPN, …) — and drives the
server's `WithCipherSuitePreference` both ways: `ServerOrder` (default) imposes the server's own
order, `ClientOrder` honors the client's. It reads the result back through the adapter's
`NegotiatedCipherSuite` accessor and asserts that under `ClientOrder` the client's most-preferred
suite always wins (flip the client's order, flip the result), while under `ServerOrder` the
negotiated suite is stable regardless of the client's order — proving, through the real handshake,
that only the server guides selection and can defer to the client when it chooses to.

`Examples/` further holds `IndyEchLoopback`, `IndyResumptionScope`, `IndyWedgeDemo` and
`IndyCustomization`, each as a Lazarus `.lpi` and a Delphi `.dpr`.

A built config (`SSLOptions.ServerConfig` / `SSLOptions.ClientConfig`) supplied alongside cert/trust
options (or a verify callback or a crypto/PKIX provider) is refused, not silently dropped; so are
resumption turned off, a non-default `ClientAuth`, verification switched off, and a cipher list.

`SSLOptions.CipherList` (the name Indy's own OpenSSL options use) names the suites to use: exact IANA
or OpenSSL suite names, separated by `:`, `,`, `;`, spaces or tabs, matched without regard to case
and de-duplicated, in preference order. It narrows and reorders
TlsLib's own hardened set and never widens it. A list that names no TLS 1.3 suite leaves TLS 1.3 on
with its default suites (an OpenSSL cipher list never governed 1.3); a list that names TLS 1.3 suites
narrows 1.3 too, and a list naming only TLS 1.3 suites turns TLS 1.2 off. Cipher-string expressions
such as `HIGH` or `!aNULL`, and suites TlsLib does not implement, are refused rather than skipped;
empty or `DEFAULT` keeps the preset, and a list beside a supplied config is refused.
