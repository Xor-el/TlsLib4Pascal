# Certificate verification & trust

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · Verification · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · [Security model](security-model.md)

TlsLib4Pascal is **fail-closed** by default: a client will not complete a handshake unless it
can verify the server's certificate chain, and the config builder refuses to build a client
without a trust source (there is no silent-insecure mode — you have to *ask* for it, loudly).

This guide covers, from safest to most dangerous:

1. [Trusting a private / self-signed CA](#1-trust-a-private-or-self-signed-ca) — still fully verified
2. [Public-key pinning](#2-pin-a-public-key) — augments verification
3. [Relaxing only the host-name check](#3-relax-only-the-host-name-check-dangerous)
4. [The `dangerous` escape hatches](#4-the-dangerous-escape-hatches) — bypass verification
5. [Coming from ASP.NET Core / .NET](#5-coming-from-aspnet-core--net)
6. [Through the integration adapters](#6-through-the-integration-adapters)
7. [Other knobs](#7-other-knobs) — chain limits, key-strength floors, stapling

> To verify against the **OS system trust store** (the way a browser does) instead of your own
> anchors, see [system-trust.md](system-trust.md).

Throughout, `Crypto` is an `ICryptoProvider` and `Pkix` an `IPkixProvider` (e.g.
`TDefaultCryptoProvider.Create as ICryptoProvider` and `TDefaultPkixProvider.Create as IPkixProvider`).
`TTlsPresets.Compatible(Crypto, Pkix)` returns an `ITlsConfigBuilder`; `.Client` / `.Server` pick the
endpoint. A built `ITlsClientConfig` becomes an engine via
`TTlsEngineFactory.CreateClientEngine(cfg, host)`, which you wrap in a Tier-2 `TTlsStream`.

---

## 1. Trust a private or self-signed CA

The **right** way to talk to a server whose certificate a public CA didn't issue: trust *its*
CA (or the self-signed cert itself). The chain is still fully validated — PKIX, expiry,
extendedKeyUsage, host-name, revocation — just against your anchor instead of the public roots.

> **End-entity certificate.** The certificate a peer presents must not be a CA (basicConstraints
> `cA=TRUE`): a sub-CA certificate cannot be served as a server or client identity (`bad_certificate`).
> The one exception is the self-signed certificate you trust directly — a leaf that is itself the
> configured anchor, which is how `openssl req -x509` certificates (they carry `CA:TRUE`) are pinned.
> The built-in verifier and the OS-native delegates apply the same rule.

> **extendedKeyUsage (RFC 5280 4.2.1.12).** A server certificate must carry `serverAuth`, a
> client certificate `clientAuth`, enforced over the leaf and every intermediate (never the trust
> anchor). It is *required-if-present*: a certificate with no EKU extension is unrestricted, but one
> that has an EKU lacking the role's purpose is rejected with `unsupported_certificate`. `anyExtendedKeyUsage`
> is not accepted as a substitute.

```pascal
uses SysUtils, Classes, TlpITlsConfig, TlpITlsConfigBuilder, TlpTlsPresets,
  TlpCertificateVerifierSource;

function LoadFile(const APath: string): TBytes;
var LS: TFileStream;
begin
  LS := TFileStream.Create(APath, fmOpenRead or fmShareDenyWrite);
  try SetLength(Result, LS.Size); if LS.Size > 0 then LS.ReadBuffer(Result[0], LS.Size);
  finally LS.Free; end;
end;

// TServerVerification.WebPki accepts a PEM block/bundle OR a single DER certificate
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LoadFile('my-ca.pem')).Build)
  .Build;
```

There is also a batteries-included facade for exactly this case:

```pascal
uses TlpTlsLib;
LConfig := TTlsLib.NewClientConfig(LoadFile('my-ca.pem'));   // Compatible preset + this trust
```

---

## 2. Pin a public key

Require that some certificate on the **validated path** carries a known public key (SPKI-SHA256).
Pinning **augments** PKIX — it never replaces it, so the chain must *also* validate normally.
(Pins match against the chain the verifier validated — the leaf, any intermediate, and the trust
anchor, including an issuer recovered from a configured intermediate — per RFC 7469. An attacker
therefore cannot satisfy a pin by appending the genuine certificate to a chain that validated by a
different path. Under `TServerVerification.DangerousSkip`, where no path is built, only the leaf is
pinnable.) After the handshake this same validated path is readable as
`ConnectionInfo.ValidatedPath` (empty under `DangerousSkip`, though a pin still matches the leaf),
alongside the chain the peer actually presented in `ConnectionInfo.PeerCertificates`.

```pascal
uses TlpCryptoDomainTypes, TlpICryptoProvider, TlpIPkixProvider;

function SpkiSha256(const ACrypto: ICryptoProvider; const APkix: IPkixProvider;
  const ACertDer: TBytes): TBytes;
var LHash: IHash; LSpki: TBytes;
begin
  LSpki := APkix.Certificates.PublicKeyInfo(ACertDer);
  LHash := ACrypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LSpki, 0, System.Length(LSpki));
  Result := LHash.DoFinal;
end;

LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LoadFile('my-ca.pem')).Build)
  .WithCertificatePinning( TArray<TBytes>.Create(SpkiSha256(Crypto, Pkix, LoadFile('leaf.der'))) )
  .Build;
```

---

## 3. Relax only the host-name check (dangerous)

If the *only* thing you want to ignore is a host-name mismatch (the certificate is trusted, but
its SAN doesn't match the address you connected to), turn off just that check — PKIX, expiry,
revocation and extendedKeyUsage all still apply. This is **dangerous**: with the match off, *any*
trusted certificate is accepted regardless of the host it was issued for (a man-in-the-middle
risk), so it lives under the `dangerous` name and is a pin-only trust posture. It governs the
connected host only: with Encrypted Client Hello, a reject is still verified against the config's
`public_name` (see [ech.md](ech.md)).

```pascal
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LoadFile('my-ca.pem')).Build)
  .WithDangerousDisableServerNameCheck   // RFC 9525 identity check off; chain still validated
  .Build;
```

Name checking is **on by default**. A client with name checking on but no host to verify against
is refused when the engine is created (fail-closed) rather than silently skipping RFC 9525 — pass
the connection host, or opt out with `WithDangerousDisableServerNameCheck`.

Sending no SNI is a separate choice and keeps this check. `WithServerNameIndication(TServerNameIndication.Omit)`
leaves the `server_name` extension out of the ClientHello while the certificate is still verified
against the connection host (RFC 9525). A server that routes by SNI may refuse such a hello or present a
default certificate that then fails the name check; the client never falls back to sending the name.

---

## 4. The `dangerous` escape hatches

The deliberately-loud "dangerous" naming covers `TServerVerification.DangerousSkip` /
`TClientVerification.DangerousSkip` (below), `WithDangerousDisableServerNameCheck` (§3) and
`WithDangerousKeyLog`. **Never ship any of them in production.** The verify callback of §4b is not
one of them: it can only tighten.

### 4a. `DangerousSkip` — accept *any* chain

Bypasses the built-in pipeline entirely: PKIX, revocation, host-name, the per-certificate and
count chain caps, the algorithm and key-strength policy, and distrust. Any configured public-key
**pinning still applies**, matched against the leaf only (it composes over the verifier, not inside
the pipeline), and so does the verify callback — so
`DangerousSkip` together with `WithCertificatePinning` is pin-only trust: no CA validation,
but the peer must still present a pinned key. For tests and pinned development peers only. A
real Encrypted Client Hello offer is refused at `Build` under it, since nothing would authenticate
an ECH reject (RFC 9849 6.1.7).

```pascal
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  // skip-verify is itself the explicit trust decision, so Build() needs no trust source; a store
  // with no roots is refused whenever verification is on (no silent-insecure).
  .WithServerVerification(TServerVerification.DangerousSkip)
  .Build;
```

### 4b. The augment verify callback — *tighten-only*

```pascal
TTlsCertificateVerifyCallback =
  function(const APresented, AValidated: TArray<TBytes>;
    const AHostName: string): Boolean of object;
```

Set with `WithCertificateVerifyCallback(cb)`. It runs **last** — after the built-in pipeline (or the
OS delegate) and after SPKI pinning — and can **only additionally reject**: returning `True` never
rescues a chain that was already rejected; returning `False` rejects one that passed. This is
deliberately stricter than rustls/.NET, whose custom validators *replace* verification wholesale.
On an Encrypted Client Hello reject, `AHostName` is the config's `public_name` (and an async verdict
resolver's host decision sees it too), not the host you connected to.

`APresented` is every certificate the peer sent (leaf first), including extras that played no part in
validation. `AValidated` is the leaf-first path the verifier reported as validated (a built-in or OS
verifier ends it at the trust anchor), and is `nil` when nothing was validated (under
`DangerousSkip`) — as Go's `VerifyPeerCertificate` passes `rawCerts` and `verifiedChains`. A rule
about *who issued* the peer belongs on `AValidated` (an appended copy of a CA you trust in
`APresented` proves nothing); a caller that skipped validation and vets the peer itself reads
`APresented`.

```pascal
type
  TMyRules = class
    function Check(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
  end;

// tighten a normally-verified connection with an extra rule of your own; LMyRules is a
// TMyRules instance, a plain object (not reference counted) that must outlive the config
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LoadFile('my-ca.pem')).Build)
  .WithCertificateVerifyCallback(LMyRules.Check)   // @LMyRules.Check under FPC {$mode objfpc}
  .Build;
```

To **replace** validation wholesale (your logic is the sole gate — the rustls/.NET model), implement
the role interface for the peer you verify and install it with `TServerVerification.Custom` (a client)
or `TClientVerification.Custom` (a server). A client verifies the *server* certificate, so it
implements `IServerCertificateVerifier`; a server verifying a *client* certificate (mTLS) implements
`IClientCertificateVerifier`. It is a first-class, fail-closed seam: it replaces the built-in
pipeline, and because a `Custom` policy takes no anchors, intermediates or skip-verify, nothing it
would ignore can be set beside it. (The server name arrives typed as `TServerName`, a DNS name or IP
literal.)

```pascal
uses SysUtils, TlpICertificateTrust, TlpServerName, TlpTrustTypes, TlpTlsAlert,
  TlpTlsPresets, TlpCertificateVerifierSource;

type
  TMyServerVerifier = class(TInterfacedObject, IServerCertificateVerifier)
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.Custom(
    TMyServerVerifier.Create as IServerCertificateVerifier))  // sole gate
  .Build;
```

On a positive verdict set `AVerified.Path` to the leaf-first path you actually validated (including
the trust anchor where you can name it); a key-pinning decorator matches its pins against that path,
not the certificates the peer presented. Leave `AVerified.Outcome` at its default `Trusted` unless
you reached a definitive, authenticated revocation verdict inline (a current Good staple), in which
case set `RevocationSettledInline` and a configured live-revocation park is skipped. On rejection
return `Default(TVerifiedChain)`.

Implement the verifier (and any custom trust store) on `TInterfacedObject` or another
reference-counted base: the config holds it by interface for its lifetime, so a non-refcounted
object could be freed while still in use.

---

## 5. Coming from ASP.NET Core / .NET

| ASP.NET Core / `HttpClientHandler` | TlsLib4Pascal |
|---|---|
| `DangerousAcceptAnyServerCertificateValidator` | `TServerVerification.DangerousSkip` |
| `ServerCertificateCustomValidationCallback = (_,_,_,_) => true` (accept-all) | `TServerVerification.DangerousSkip` |
| `ServerCertificateCustomValidationCallback` with real logic (replace validation) | `TServerVerification.Custom(myVerifier)` |
| A callback that only *tightens* (extra rejections on top of normal validation) | `WithCertificateVerifyCallback(rule)` alone |
| Trusting a specific CA instead of the system store | `TServerVerification.WebPki(caPemOrDer).Build` |
| Ignoring only `SslPolicyErrors.RemoteCertificateNameMismatch` | `WithDangerousDisableServerNameCheck` |

The one semantic to internalise: **`ServerCertificateCustomValidationCallback = (...) => true`
maps to `DangerousSkip`, not to our verify callback** — because ours can only reject
further, never accept-all. (See §4b.)

---

## 6. Through the integration adapters

The [mORMot / Indy / Synapse / fcl-net adapters](../TlsLib.Adapters) map their host's "ignore certificate
errors" flag onto `DangerousSkip` for you, so the accept-any case is a one-liner:

```pascal
// mORMot   (TNetTlsContext)
Context.IgnoreCertificateErrors := True;

// Indy     (our TTlsLibSSLOptions)
IO.SSLOptions.InsecureSkipVerify := True;        // or SSLOptions.VerifyPeer := False

// Synapse  (TCustomSSL) — NOTE: with our TSSLTlsLib plugin VerifyCert defaults to TRUE (secure) — the
//           plugin flips Synapse's insecure base default. Set it False for the accept-any bypass
sock.SSL.VerifyCert := False;

// fcl-net  (TTlsLibSocketHandler)
Handler.VerifyPeerCert := False;
```

A host framework's *own* verify callback is bridged only when its signature carries no OpenSSL
type. Indy `OnVerifyPeer` and mORMot `OnEachPeerVerify` hand you an OpenSSL cert (`TIdX509` /
`PX509`), so they are **not** bridged (it would re-couple the adapter to OpenSSL). Synapse's
`OnVerifyCert` (`function(Sender): Boolean`, no OpenSSL type) **is** bridged: set it and inspect
the peer through `GetPeerSubject` / `GetPeerIssuer` / `GetPeerFingerprint`. So is fcl-net's
`OnVerifyCertificate`, augment-only as well.

For the neutral, framework-agnostic path, each adapter surfaces the augment-only
`WithCertificateVerifyCallback` on its own options (Indy `SSLOptions.VerifyCallback`; fcl-net
`VerifyCallback` on the handler; Synapse / mORMot `SetTlsLib…VerifyCallback`) — no drop to Tier-2 required. The same surfaces expose an
out-of-band **verdict resolver** that parks the handshake for a decision; wire
`TLiveRevocationChecker.ResolveVerdict` (live OCSP/CRL over an injected `IHttpFetcher`) to it. All
of these are augment-only and fail-closed. See each adapter's README for details.

The verdict resolver is **role-specific**: the *client* hook decides the server's chain (a
server-auth trust engine), the *server* hook decides an mTLS client's chain (a client-auth engine).
The two evaluate different EKUs, so each adapter exposes them separately — a client hook
(`VerdictResolver` on Indy and fcl-net / `SetTlsLib…VerdictResolver`) and a server hook (`ServerVerdictResolver` /
`SetTlsLib…ServerVerdictResolver`). Pair each with the matching `TOSSystemTrust.LiveRevocationResolver`
overload (a client config for the client hook, a server config for the server hook). An OS-native
resolver handed a chain of the wrong role refuses it with `internal_error` (a local
misconfiguration) rather than a misleading trust failure.

A resolver only runs when the handshake parks for a verdict. Beside an adapter's own built config
that is automatic; beside a config you supply yourself (`ClientConfig` / `ServerConfig`) the
config must already defer the verdict (`WithLiveRevocationVerdict` or `WithAsyncCertificateVerdict`),
otherwise the resolver would never fire and live revocation would silently be off, so the
connection is refused instead. A server only parks under a client-authentication mode, so only a
server config with one needs to defer.

### Live OCSP/CRL revocation (opt-in)

Live revocation is **off by default** and never happens inside the sans-IO core: the config
builder takes no `IHttpFetcher`, by design, so the engine stays network-free. You opt in on the
`TTlsStream` (the convenience blocking stream) by attaching a checker to the parked verdict:

```pascal
// 1. enable the live-revocation verdict on the config, so the engine defers an indeterminate
//    stapled outcome and parks for the live check: a policy built with
//    .WithRevocation(TRevocationPosture.Hard), then .WithLiveRevocationVerdict(deadlineMs)
//    on the builder  <-- without this the resolver never fires
// 2. attach the live checker to the stream (the clock dates the responses, the monotonic
//    clock times the fetch budget; the fetcher owns every socket):
checker := TLiveRevocationChecker.Create(Pkix, clock, config.MonotonicClock, fetcher,
  TRevocationPosture.Hard, TLiveRevocationMethod.OcspThenCrl, budgetMs);
try
  stream.SetCertificateVerdictResolver(checker.ResolveVerdict);   // @checker.ResolveVerdict under FPC {$mode objfpc}
  stream.Handshake;
  // ... use the stream
finally
  checker.Free;
end;
```

The checker is a plain object: you own it, keep it alive for as long as the stream can park, and
free it after the stream is done.

The checker tries the responders a certificate lists in order — every OCSP responder URL, then every
CRL distribution point — and stops at the first definitive answer (a current **Good** or a
**Revoked**); an unreachable, malformed or stale answer moves on to the next. URLs that name the same
responder are tried once, judged on a canonical form: the scheme and host are compared without
regard to case, a default port (`:80` for http, `:443` for https) or a bare `:` is the same as no port, an empty
path is the same as `/`, percent-encoding hex case is normalised, and the fragment is dropped; path
and query are otherwise compared exactly. The fetcher is handed that canonical text, not the
original spelling. A URL carrying userinfo, or one the strict parser refuses (a scheme other than http or https, such as an `ldap://` CRL point, a bad port, a
last label that starts with a digit, a trailing dot, a zone identifier, brackets in the path or query), is skipped without
using up the cap. A URL that parses is fetched wherever it points: a private or loopback responder
is not blocked unless the fetcher has a destination policy. By
default at most three OCSP responders and three CRL points are tried. `budgetMs` is the **total**
time one check may spend fetching across all of those attempts, measured on the injected clock: each
attempt gets a fair share of what remains (never less than 250 ms by default, or the whole budget
when that is smaller), so one dead responder cannot starve the next, and a spent budget ends the
check indeterminate, which the posture then decides. `0` leaves each fetch's timeout to the fetcher
with no shared deadline, so give a real budget, no larger than the config's async-verdict deadline.
Each responder tried learns which certificate is being checked; extra ones are asked only after an
indeterminate answer, and posture `Off` asks none. The portable checker checks the **leaf only**,
against its issuer; an intermediate's own revocation is not fetched (the OS-native path below
checks the whole chain).

The limits are tunable through `TLiveRevocationOptions` (declare one, which already holds the
defaults, and set what you need), passed as the last constructor argument: `MaxOcspResponders` and
`MaxCrlDistributionPoints` (1 to 8, default 3), `MinAttemptMs` (1 to 60000, default 250; never 0,
which would leave a fetch unbounded), `MaxCrlBytes` (4 KiB to 256 MiB, default 32 MiB) and
`MaxCachedResponses` (0 to 1024, default 64; 0 turns the response cache off). `IssuerCandidates` is a
list of local issuer certificates for a leaf-only chain (default none; no range).
A value outside its range, or a nil `Pkix` provider, clock, monotonic clock or fetcher, is refused when the checker is
created.

The checker keeps the OCSP responses and CRLs it fetched that carry a `nextUpdate`, so a later check
of the same certificate (keyed by its OCSP CertID, or by the canonical CRL URL) does not fetch again.
A cached answer is re-authenticated and re-judged against the injected clock on every use, is never
used at or past its `nextUpdate`, is kept for at most a day, never outlives the byte budget of
`MaxCrlBytes`, and an indeterminate result is never cached.

The park happens **after the peer has proved it holds the leaf key** — after the client's
`CertificateVerify` (server side), the server's `CertificateVerify` (TLS 1.3) or signed
`ServerKeyExchange` (TLS 1.2) — so a replayed certificate without its key cannot make the endpoint
fetch anything. Path, name and inline revocation checks still run first.

A parked verdict is decided at the **stricter of the checker's posture and the configuration's**
(`Hard` over `Soft` over `Off`): a `Hard` configuration is not relaxed by a checker built `Soft`, and
an `Off` checker still checks when the configuration asks for more. A response's `thisUpdate` may run
up to five minutes ahead of the local clock (a responder's clock may be ahead); `nextUpdate` is exact.

A **stapled** OCSP response (validated in the handshake pipeline, before the park) is preferred;
the live fetch is the fallback for a leaf that carries no staple. When the staple already settles
revocation with a current, authenticated **Good** that carries a `nextUpdate` and is inside its window, the live park is **skipped** (the fetch would only
re-answer what the staple already did); a Good staple without a `nextUpdate` is accepted inline but
still parks. So a `WithLiveRevocationVerdict` resolver is invoked only for
peers whose status is still undecided. A host that must observe *every* accepted peer (an audit hook,
extra policy) uses the host-decision park (`WithAsyncCertificateVerdict`), which always parks. The
posture governs the
*indeterminate* outcome — `Hard` rejects an unreachable/malformed/stale result, `Soft` accepts it
— while a definitive, issuer-authenticated **Revoked** always aborts with `certificate_revoked`.
Posture **`Off` performs no live fetch at all** (its network and privacy cost is suppressed); a
stapled Revoked is still honoured by the pipeline. CRL responses are only trusted inside their
`thisUpdate`/`nextUpdate` window, so a replayed stale CRL is treated as indeterminate, never a Good.

The verification policy's **`WithRevocation` posture and the live channel are one policy**: with
`WithLiveRevocationVerdict`, an indeterminate/no-staple leaf is *deferred* to the resolver rather
than decided inline, so `WithRevocation(Hard)` + `WithLiveRevocationVerdict` rejects only a
genuinely revoked (or unreachable, under Hard) peer — it does not blanket-reject an unstapled one.
A `WithAsyncCertificateVerdict` (host-decision) park is augment-only: it does **not** defer the
revocation gate, so under it `Hard` still rejects a missing staple inline. Without any live
deferral, `Hard` decides inline (a missing staple is rejected); a `must-staple` leaf (RFC 7633)
requires a current Good staple, and is enforced only for an initial-handshake server certificate
the client requested a staple for (`WithOcspStaplingRequest`) — never deferred. A Hard posture with a live checker
uses `WithLiveRevocationVerdict`, not `WithAsyncCertificateVerdict` (Build refuses a Hard client that has neither a
staple request nor live-revocation deferral, and a Hard `TServerVerification.Custom` always needs
`WithLiveRevocationVerdict` because an injected verifier does not apply the posture; Hardened and Strict request a staple, Compatible needs
`WithOcspStaplingRequest(True)`, and a Hard client-authenticating server always needs
`WithLiveRevocationVerdict`). On resumption this is decisive: a `Hard` client with
`WithResumeVerification(Reverify)` but no `WithLiveRevocationVerdict` can never obtain revocation
status for a resumed server (a resume carries no staple), so `Build` refuses the pair; add
`WithLiveRevocationVerdict` or keep the default `ReuseOriginal`. A chain that fails `Reverify` is
not offered and the client runs a full handshake; see
[Resume sessions](cookbook.md#resume-sessions).
On a resumption that does abbreviate, `ConnectionInfo.ValidatedPath` is populated only when the
client re-verified the stored chain (`WithResumeVerification(Reverify)`); under `ReuseOriginal` it is
empty, since no path was built on this connection, while `ConnectionInfo.PeerCertificates` still
carries the chain stored with the session.

### OS-native live revocation (opt-in, Windows + Apple)

When you verify the server certificate through the **OS trust delegate**, you can have the OS engine
(Windows crypt32 / Apple SecTrust, macOS + iOS) do the live revocation fetch itself — still off the
sans-IO engine thread, in the same async-verdict park. It is **off by default** (the delegate is
cache-only): the inline pass stays socket-free and, when live is armed, *defers* an indeterminate
revocation so the handshake parks; the OS then re-evaluates with network fetch enabled on the host
thread and the verdict resolves the park.

```pascal
// 1. arm the OS delegate in live mode: this uses the delegate, defers inline, and enables the
//    async park. The deadline must be non-zero (0 raises) so the Windows resolver can bound its
//    fetch (Apple has no per-evaluation timeout). It replaces any earlier WithServerVerification.
//    Windows + Apple only; other platforms raise.
client := TSystemTrust.WithLiveSystemTrust(client, TRevocationPosture.Hard, deadlineMs);
// 2. wire the OS-native resolver, built from the frozen config, to the stream/adapter:
resolver := TOSSystemTrust.LiveRevocationResolver(clientConfig);   // caller owns + frees it
stream.SetCertificateVerdictResolver(resolver.ResolveVerdict);   // @resolver.ResolveVerdict under FPC {$mode objfpc}
```

The OS engine returns a tri-state: a definitive **Revoked** aborts with `certificate_revoked`; a
**Good** accepts; an **indeterminate** (the OS could not fetch or decide) follows the posture —
`Soft`/`Off` accept, `Hard` rejects with `bad_certificate_status_response`. A handshake staple is
attached to the live evaluation, so a server that already stapled a current Good is not re-fetched.
Pass an optional fallback resolver to `LiveRevocationResolver(config, fallback)` (typically a
`TLiveRevocationChecker.ResolveVerdict`) to run the **portable** OCSP/CRL over your `IHttpFetcher`
on an indeterminate OS outcome before the posture decides.

**Android and Linux/BSD have no OS-native live revocation** (Android's platform TrustManager owns
revocation with no network knob; Unix has no OS delegate). Compose the **portable**
`TLiveRevocationChecker` there instead. `TSystemTrustFetch.Live` on those platforms raises a typed
`ESystemTrustUnsupportedTlsLibException`, as does arming Live without `WithLiveRevocationVerdict`
(raised when the engine is created, before any I/O, not at `Build`); a
host-decision `WithAsyncCertificateVerdict` does not satisfy it.

**Server-side (mutual-TLS client certificates).** The same posture applies to the client
certificate a server verifies — set it with `TClientVerification`'s `WithRevocation`. A client cannot be asked
to staple, so `Hard` client-certificate revocation is satisfiable **only** by a live resolver
(there is no stapled fallback); `Build` rejects a `Hard`, client-authenticating server that does not
call `WithLiveRevocationVerdict`. Attach the resolver on the server's stream exactly as above; a revoked client certificate
then aborts the handshake with `certificate_revoked`. This works with both the **portable**
`TLiveRevocationChecker` (give it the configured client-CA anchors as `TLiveRevocationOptions.IssuerCandidates`, so it can
recover the issuer of a leaf-only client credential) and the **OS-native** delegate on Windows/Apple
(`TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.Live)` +
`TOSSystemTrust.LiveRevocationResolver(serverConfig)` + `WithLiveRevocationVerdict(deadlineMs)` on the
server builder, since no server facade arms it — see the OS-native subsection above and
[system-trust.md](system-trust.md)).

### Time source: one injected clock

Every time-based certificate decision reads from a single injected `ITlsClock` — the chain
`notBefore`/`notAfter` window, the PKIX path-validation date, the OCSP delegated-responder validity,
and the stapled/live `thisUpdate`/`nextUpdate` freshness windows. There is no hidden system-clock
fallback anywhere in the trust path, so the *whole* trust decision is deterministic and
mock-clock testable — inject a fixed clock with `WithClock` to test acceptance of a not-yet-valid
or just-expired leaf, or to validate against a trusted time on a device with no reliable RTC:

```pascal
config := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caDer).Build)
  .WithClock(myFixedClock)   // drives cert validity, PKIX, and revocation freshness
  .Build;
```

The default is the real system clock (`TSystemClock`), so this only matters when you override it.

Deadlines are a separate concern and use a separate clock. The handshake read cap and the
live-revocation budget measure *elapsed* time on an `ITlsMonotonicClock` (default
`TSystemMonotonicClock`), which a wall-clock step can neither stretch nor shorten. Override the
handshake cap's clock with `WithMonotonicClock`; the `TLiveRevocationChecker` constructor takes its
clock explicitly, like its other inputs (pass `Config.MonotonicClock` to share the connection's).
Neither affects certificate, OCSP or ticket time, which stay on `ITlsClock`.

### The live-check budget over `TTlsStream`

`TTlsStream` does not pass the config's `WithLiveRevocationVerdict(deadlineMs)` to the resolver.
The OS-native resolver reads that deadline from the config it was built from. A portable
`TLiveRevocationChecker` spends its own constructor `budgetMs`; to bound either further per stream,
use `SetCertificateVerdictResolver(resolver, deadlineMs)`, and the smaller non-zero value
applies to the portable checker and the OS resolver alike (on Windows; Apple has no per-evaluation
fetch timeout).

---

## 7. Other knobs

### Certificate-chain limits

`WithCertificateChainLimits` (client and server builders) caps the peer's chain before any PKIX work.
It is a resource budget, not a trust input. The fields of `TCertificateChainLimits` (unit
`TlpCertificateLimits`):

| Field | Default | `Strict` preset |
|---|---|---|
| `MaxCertificateLength` (one certificate) | 64 KiB | 16 KiB |
| `MaxTotalChainLength` (the whole Certificate message) | 64 KiB | 32 KiB |
| `MaxChainCertificates` | 16 | 8 |

`MaxTotalChainLength` is also the handshake reassembly ceiling and the certificate-decompression
ceiling. Start from `Defaults`; the setter raises `EArgumentTlsLibException` for a non-positive cap,
a per-certificate cap above the total, a total above 16 MiB - 1, or a count outside 1..255. The caps
apply in the built-in and OS verifiers; a `Custom` verifier owns only the per-certificate and count caps
(`MaxTotalChainLength` still bounds reassembly and decompression for every verifier). On a server,
`WithCertificateChainLimits` bounds a requested client certificate only; without `WithPeerAuth` any
value other than the preset's is refused at `Build`.

```pascal
uses TlpCertificateLimits, TlpCertificateVerifierSource;

LLimits := TCertificateChainLimits.Defaults;
LLimits.MaxCertificateLength := 1 shl 17;   // a large post-quantum chain
LLimits.MaxTotalChainLength := 1 shl 18;
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem).Build)
  .WithCertificateChainLimits(LLimits)
  .Build;
```

### Key-strength floors

`WithMinimumStrength` on a `WebPki` or `VerifierSource` policy (server or client verification) sets
the floors the leaf and intermediates must meet; a configured trust anchor is exempt. The fields of
`TCertificateStrengthPolicy` (unit `TlpCertificateStrengthPolicy`) and their `Defaults`, used by
every preset:

- `MinRsaModulusBits` 2048, `MaxRsaModulusBits` 8192 (0 = no cap, a verify-cost defence).
- `AllowedEcCurves` P-256, P-384, P-521 (empty = any curve the provider recognises).
- `AllowEdDsa` True.
- `AllowedDeprecatedHashes` empty: name `TCertSignatureHash.Sha1` (unit `TlpPkixDomainTypes`) to
  admit SHA-1-signed certificates from a private PKI that has not been re-issued.

```pascal
uses TlpCertificateStrengthPolicy, TlpCertificateVerifierSource;

LStrength := TCertificateStrengthPolicy.Defaults;
LStrength.MinRsaModulusBits := 3072;
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(caPem)
    .WithMinimumStrength(LStrength).Build)
  .Build;
```

### The chain-algorithm policy (always on)

Over the validated path (the anchor exempt), the built-in pipeline and the OS delegates always check:

- every leaf and intermediate is signed with a signature scheme this endpoint advertised, else
  `unsupported_certificate`;
- each key meets the floors above, else `unsupported_certificate`;
- an MD5-signed certificate is refused under any policy, and a SHA-1-signed one unless
  `AllowedDeprecatedHashes` admits it (RFC 9846 4.5.1.3), with `bad_certificate`.

A `Custom` verifier replaces the pipeline and is not checked.

### OCSP stapling and must-staple

A client requests a staple (`status_request`, RFC 6066) only with `WithOcspStaplingRequest(True)`.
`Hardened` and `Strict` turn it on; `Compatible` leaves it off. A client that did not request a
staple rejects an unsolicited one. A must-staple leaf (RFC 7633) is enforced only for a server
certificate on the initial handshake of a client that requested a staple. Without a current, valid
Good staple it fails with `bad_certificate_status_response` under every posture, even with a live
resolver configured.

### More behaviour worth knowing

- **Anchors.** `WebPki` also takes a single `ITrustAnchorStore`, or a union of stores and root blobs
  (`WebPki(TArray<ITrustAnchorStore>, TArray<TBytes>)`); a malformed anchor is refused at `Build`. `Custom(verifier, posture)` adds a
  revocation posture for a live verdict over the verifier's path (the plain `Custom` is `Soft`).
- **Identity.** Names match the certificate's SANs, with a single wildcard
  only as the whole leftmost label and only when at least two labels remain below it (so never
  `*.com`; there is no public-suffix list); an IP-literal host matches only an
  iPAddress SAN.
- **Pinning.** Server-side `WithCertificatePinning` (mTLS) pins the client certificate; a pin is exactly
  32 bytes (SPKI-SHA256).
- **Verify callback.** A callback that returns `False` aborts with `certificate_unknown`.
- **Strength floors.** `WithMinimumStrength` raises `EArgumentTlsLibException` for a non-positive
  minimum RSA modulus or a maximum below it.
- **Live revocation.** `TLiveRevocationMethod` is `Ocsp`, `Crl` or `OcspThenCrl`; an OCSP response is
  capped at 64 KiB. `WithAsyncCertificateVerdict(0)` and `WithLiveRevocationVerdict(0)` impose no
  deadline on the resolver (0 = unbounded), and calling the other of the two after one is set raises
  `EInvalidOperationTlsLibException` (they share one verdict slot).
- **The fetcher.** `TSocketHttpFetcher` (package `TlsLib.Net`, see [the cookbook](cookbook.md#set-a-revocation-posture))
  takes `TSocketHttpFetcherSettings` (a runnable use is `TlsLib.Net/Examples/README.md`'s
  RealPeerRevocationProbe); a timeout of 0 means 60 s, the response head is capped at 64 KiB,
  and it follows no redirect, treats a 101 or 204 as a failure and cannot reach an IPv6 responder.
- **Server-side mTLS.** A server requests client certificates with `WithPeerAuth` and verifies them with
  `WithClientVerification(TClientVerification.WebPki(...).Build)`. Without `WithPeerAuth`, the
  client-verification, pinning, callback, verdict, chain-limit and changed signature-scheme registry settings are refused at `Build`, and a
  server that shares a session store or ticket keys must also set `WithResumptionScope`.

---

## Rule of thumb

Reach for §1–§3 (trust a CA, pin, or relax just the host-name) before ever reaching for §4.
`DangerousSkip` disables authentication entirely — it makes the connection encrypted but
**not** authenticated, which defeats most of the point of TLS. Keep it to tests.
