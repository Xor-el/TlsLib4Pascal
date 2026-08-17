# TlsLib4Pascal — fcl-net adapter (FclNet)

Drops TlsLib4Pascal's managed TLS engine into **Free Pascal's own networking** through
fcl-net's `TSSLSocketHandler` "swap-your-SSL" seam — so a stock `TFPHTTPClient` HTTPS
request (or any `TInetSocket`) speaks our managed TLS instead of OpenSSL.

**Free Pascal only.** This adapter ships no Delphi package or examples.

## How to swap it in

fcl-net picks its SSL backend by a **default handler class** registered at unit
`initialization`. `uses` the adapter unit and `TTlsLibSocketHandler` becomes that default —
`TFPHTTPClient`, `TInetSocket`, and friends now handshake through TlsLib4Pascal. Do *not*
also link `opensslsockets` (its `initialization` would register the OpenSSL handler and
whichever unit initialises last wins).

```pascal
uses fphttpclient, TlpFclNetTls;   // registers TTlsLibSocketHandler as fcl-net's default
```

Because fcl-net **auto-creates** the handler and `TFPHTTPClient` gives you no handler to pass or
set (the socket owns and frees it per connection), you have two ways in.

**Just trust the OS store (zero hooks).** One explicit opt-in at startup, then a plain
`TFPHTTPClient` verifies against the system-trust store with nothing else:

```pascal
uses fphttpclient, TlpFclNetTls;

TlsLibFclNetTrustDefaults.UseSystemTrust := True;      // once, at startup (off by default)
body := TFPHTTPClient.SimpleGet('https://example.com'); // just works, verified against OS trust
```

It stays explicit (system trust is never implicit), and a per-connection handler still overrides
it. Use this for the common "trust the OS like curl does" case.

**Per-connection trust (`OnGetSocketHandler`).** When trust varies per request (pin a CA here, the
OS store there), supply a configured `TTlsLibSocketHandler`:

```pascal
procedure TMyForm.GetHandler(Sender: TObject; const UseSSL: Boolean; out AHandler: TSocketHandler);
var H: TTlsLibSocketHandler;
begin
  AHandler := nil;
  if not UseSSL then Exit;              // a plain http:// request keeps the default plaintext handler
  H := TTlsLibSocketHandler.Create;
  H.UseSystemTrust := True;             // (or pin a CA: H.CertificateData.CertCA.FileName := ...)
  AHandler := H;                        // verification is on by default; nothing else to set
end;
client.OnGetSocketHandler := GetHandler;
```

A handler you return fully configured covers every trust and credential case below.

> There is a second hook, `AfterSocketHandlerCreate`, that tweaks the handler fcl-net created
> for you rather than supplying one. It is rarely needed (returning a ready handler from
> `OnGetSocketHandler` does everything it can), and some fcl-net releases leave it `protected` on
> `TFPCustomHTTPClient` — only `OnGetSocketHandler` is re-published on `TFPHTTPClient`. If you
> want it, surface it with a one-line `class(TFPHTTPClient) published property
> AfterSocketHandlerCreate; end;` — the real-world example uses this to demonstrate both hooks.

Driving a `TInetSocket` directly (passing a handler suppresses auto-connect — call `Connect`):

```pascal
h := TTlsLibSocketHandler.Create;
h.CertificateData.CertCA.FileName := 'ca-bundle.pem';   // pinned trust anchor (verification is on by default)
sock := TInetSocket.Create('example.com', 443, h);      // handler set => no auto-connect
sock.Connect;                                           // TCP + our TLS handshake
sock.Write(reqBytes[0], Length(reqBytes));
n := sock.Read(buf[0], Length(buf));
sock.Free;                                              // flushes close_notify, closes the socket
```

The host passed to `TInetSocket.Create` is both the SNI name and the name the certificate is
verified against.

## Configuring trust

Peer/credential material comes from fcl-net's **native `CertificateData` slots** — each a
`TSSLData` holding *either* inline `.Value: TBytes` *or* a `.FileName` — so a fcl-net user sets
trust the familiar way. Only what fcl-net lacks is added as extension properties on
`TTlsLibSocketHandler`.

| Source                                                | Maps to                                            |
|-------------------------------------------------------|----------------------------------------------------|
| `CertificateData.CertCA` / `.TrustedCertificate`      | `WithTrustAnchors` — pinned anchors (unioned)      |
| `CertificateData.Certificate` + `.PrivateKey` + `KeyPassword` | `WithCredential` — own cert (server, or mTLS client) |
| `UseSystemTrust: Boolean`                             | OS system-trust store (crypt32 / SecTrust / Unix)  |
| `CustomTrustStore: ITrustAnchorStore`                 | `WithTrustStore` (unions with the above)           |
| `CustomVerifier: ICertificateVerifier`                | `WithCertificateVerifier` — **replaces** the pipeline |
| `CheckHostName: Boolean` (default True)               | `WithNameCheck`                                     |
| `AlpnProtocols: TArray<string>`                       | `WithAlpnProtocols`                                |
| `VerifyPeerCert` (fcl-net native, default **True** here) | verify on/off; **False** → `dangerous` `WithDangerousInsecureSkipVerify` |
| `VerifyCallback` / `VerdictResolver` + `VerdictDeadlineMs` | augment-only hook / out-of-band verdict (live OCSP/CRL) |
| `OnVerifyCertificate` (fcl-net native)                | augment-only reject after our pipeline             |

**Certificate chain**: `CertificateData.Certificate` is the chain the server *presents* — put your leaf
**followed by any intermediates** (a concatenated PEM, or a multi-cert byte slot) so clients build a
complete chain. `CertCA` / `TrustedCertificate` are **trust sources** (used to verify the *peer*), never
part of what you send; putting intermediates only there leaves the presented chain incomplete, forcing
clients to fetch the missing CA.

**Verification is on by default — safer than fcl-net.** fcl-net's own OpenSSL handler leaves
`VerifyPeerCert` at `False` (so stock `TFPHTTPClient` does **not** verify — a well-known footgun);
this adapter's constructor defaults it to **`True`**. Trust is therefore **fail-closed**: a client
that names **no** trust source (`CertCA`/`TrustedCertificate`, `UseSystemTrust`, `CustomTrustStore`,
`CustomVerifier`) **refuses to connect** — system trust is never implicit. Anchor sources UNION; a
`CustomVerifier` is exclusive. A server requires `CertificateData.Certificate`/`.PrivateKey`; it
requests + verifies client certificates only when a client-trust source is named (mTLS is opt-in).

Setting `VerifyPeerCert := False` is the loud, deliberate bypass (no PKIX/host/pinning checks) —
for tests and pinned dev peers, never production.

> This matches the other TlsLib adapters: each honours its host's native verify switch (Indy's
> `VerifyPeer`, mORMot's `IgnoreCertificateErrors`, Synapse's `VerifyCert`) — `False` wires straight
> to the dangerous bypass — and each defaults that switch to the **secure** position in its own
> constructor, regardless of the host library's own (often insecure) default.

For the full trust picture — trusting a private CA, public-key pinning, host-name-only
relaxation, the `dangerous` escape hatches, and an ASP.NET Core mapping — see
[docs/certificate-verification.md](../../docs/certificate-verification.md); for the OS
system-trust model see [docs/system-trust.md](../../docs/system-trust.md).

## Notes

- The transport reads/writes the raw socket handle via the `Sockets` unit's `fpRecv`/`fpSend`,
  bypassing the SSL-aware handler methods (which carry decrypted application data).
- `BytesAvailable` reports our buffered plaintext count (the `SSL_pending` analogue).
- `TSocketStream` owns and frees the handler it was given; the adapter frees its inner
  `TTlsStream` in `Destroy`.

## Proven

`Examples/` — the **loopback** (shared logic in `src/FclNetLoopbackExample.pas`, program
`Lazarus/FclNetLoopback.lpi`): a fcl-net `TInetServer` (accepted connections carrying our
handler) and a `TInetSocket` client on `127.0.0.1`, full TLS 1.3 handshake + application echo.
No external dependencies — this is the compile-and-run proof.

`Examples/` also carries a **real-world** demo (`src/FclNetRealWorldExample.pas`,
`Lazarus/FclNetRealWorld.lpi`): a single `TFPHTTPClient` does a live HTTPS `GET` and `POST` to
`postman-echo.com` with its TLS handled entirely by TlsLib4Pascal — real handshake, real
certificate verification, real HTTP over our records, zero OpenSSL. It runs twice, exercising
**both** config hooks: leg A pins the bundled root (`data/isrg-roots.pem`) via
`AfterSocketHandlerCreate`, leg B uses the OS system-trust store via `OnGetSocketHandler`.
`KeepConnection` reuses **one** TLS connection for both verbs. It is a **network-gated demo,
not a test gate**: it needs outbound HTTPS and exits 0 (PASS) / 2 (SKIP, offline) / 1 (FAIL).

`Examples/` also carries an **advanced-config** demo (`src/FclNetAdvancedConfigExample.pas`,
`Lazarus/FclNetAdvancedConfig.lpi`): instead of the `CertificateData` cert/trust slots, it hands
each handler a fully-built config through `ServerConfig` / `ClientConfig` — an ordered, bound
cipher-suite preference pinned to TLS 1.2, so the negotiated 1.2 (the preset would pick 1.3) proves
the injected config replaced the built-in build. This is the escape hatch to the whole builder API
(cipher order, groups, resumption, ALPN, …).
