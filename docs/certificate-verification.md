# Certificate verification & trust

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · Verification · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · [Security model](security-model.md)

TlsLib4Pascal is **fail-closed** by default: a client will not complete a handshake unless it
can verify the server's certificate chain, and the config builder refuses to build a client
without a trust source (there is no silent-insecure mode — you have to *ask* for it, loudly).

This guide covers, from safest to most dangerous:

1. [Trusting a private / self-signed CA](#1-trust-a-private-or-self-signed-ca) — still fully verified
2. [Public-key pinning](#2-pin-a-public-key) — augments verification
3. [Relaxing only the host-name check](#3-relax-only-the-host-name-check)
4. [The `dangerous` escape hatches](#4-the-dangerous-escape-hatches) — bypass verification
5. [Coming from ASP.NET Core / .NET](#5-coming-from-aspnet-core--net)
6. [Through the integration adapters](#6-through-the-integration-adapters)

> To verify against the **OS system trust store** (the way a browser does) instead of your own
> anchors, see [system-trust.md](system-trust.md).

Throughout, `P` is an `ICryptoProvider` (e.g. `TDefaultCryptoProvider.Create as ICryptoProvider`).
`TTlsPresets.Compatible(P)` returns an `ITlsConfigBuilder`; `.Client` / `.Server` pick the
endpoint. A built `ITlsClientConfig` becomes an engine via
`TTlsEngineFactory.CreateClientEngine(cfg, host)`, which you wrap in a Tier-2 `TTlsStream`.

---

## 1. Trust a private or self-signed CA

The **right** way to talk to a server whose certificate a public CA didn't issue: trust *its*
CA (or the self-signed cert itself). The chain is still fully validated — PKIX, expiry,
host-name, revocation — just against your anchor instead of the public roots.

```pascal
uses SysUtils, Classes, TlpITlsConfig, TlpITlsConfigBuilder, TlpTlsPresets;

function LoadFile(const APath: string): TBytes;
var LS: TFileStream;
begin
  LS := TFileStream.Create(APath, fmOpenRead or fmShareDenyWrite);
  try SetLength(Result, LS.Size); if LS.Size > 0 then LS.ReadBuffer(Result[0], LS.Size);
  finally LS.Free; end;
end;

// WithTrustAnchors accepts a PEM block/bundle OR a single DER certificate
LConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(LoadFile('my-ca.pem'))
  .Build;
```

There is also a batteries-included facade for exactly this case:

```pascal
uses TlpTlsLib;
LConfig := TTlsLib.NewClientConfig(LoadFile('my-ca.pem'));   // Compatible preset + this trust
```

---

## 2. Pin a public key

Require that some certificate in the chain presents a known public key (SPKI-SHA256). Pinning
**augments** PKIX — it never replaces it, so the chain must *also* validate normally.

```pascal
uses TlpCryptoAlgorithms, TlpICryptoProvider;

function SpkiSha256(const AProvider: ICryptoProvider; const ACertDer: TBytes): TBytes;
var LHash: IHash; LSpki: TBytes;
begin
  LSpki := AProvider.CertificatePublicKeyInfo(ACertDer);
  LHash := AProvider.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LSpki, 0, System.Length(LSpki));
  Result := LHash.DoFinal;
end;

LConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(LoadFile('my-ca.pem'))
  .WithCertificatePinning( TArray<TBytes>.Create(SpkiSha256(P, LoadFile('leaf.der'))) )
  .Build;
```

---

## 3. Relax only the host-name check

If the *only* thing you want to ignore is a host-name mismatch (the certificate is trusted, but
its SAN doesn't match the address you connected to), turn off just that check — PKIX, expiry and
revocation all still apply.

```pascal
LConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(LoadFile('my-ca.pem'))
  .WithNameCheck(False)          // RFC 6125 identity check off; chain still validated
  .Build;
```

---

## 4. The `dangerous` escape hatches

Two knobs live under the deliberately-loud "dangerous" naming. **Never ship either in
production.**

### 4a. `InsecureSkipVerify` — accept *any* chain

Bypasses the entire pipeline: PKIX, revocation, host-name, and pinning. For tests and pinned
development peers only.

```pascal
uses TlpICertificateTrust, TlpCertificateVerifier;   // TTrustAnchorStore

LConfig := TTlsPresets.Compatible(P).Client
  .WithDangerousInsecureSkipVerify(True)
  // Build() still REQUIRES a trust source (no silent-insecure). Pass an empty store — it is
  // never consulted because verification is skipped. You had to type two things to do this.
  .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
  .Build;
```

### 4b. The augment verify callback — *tighten-only*

```pascal
TTlsCertificateVerifyCallback =
  function(const AChain: TArray<TBytes>; const AHostName: string): Boolean of object;
```

Set with `WithCertificateVerifyCallback(cb)`. It runs **after** the built-in pipeline and can
**only additionally reject** — returning `True` never rescues a chain the pipeline already
failed; returning `False` rejects one it passed. This is deliberately stricter than
rustls/.NET, whose custom validators *replace* verification wholesale.

```pascal
type
  TMyRules = class
    function Check(const AChain: TArray<TBytes>; const AHostName: string): Boolean;
  end;

// tighten a normally-verified connection with an extra rule of your own
LConfig := TTlsPresets.Compatible(P).Client
  .WithTrustAnchors(LoadFile('my-ca.pem'))
  .WithCertificateVerifyCallback(LMyRules.Check)
  .Build;
```

To **replace** validation wholesale (your logic is the sole gate — the rustls/.NET model), implement
`ICertificateVerifier` and install it with `WithCertificateVerifier`. It is a first-class,
fail-closed seam: it replaces the built-in pipeline and is **exclusive** — it cannot be combined with
any anchor source.

```pascal
type
  TMyVerifier = class(TInterfacedObject, ICertificateVerifier)
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
  end;

LConfig := TTlsPresets.Compatible(P).Client
  .WithCertificateVerifier(TMyVerifier.Create as ICertificateVerifier)  // your rule is the only gate
  .Build;
```

---

## 5. Coming from ASP.NET Core / .NET

| ASP.NET Core / `HttpClientHandler` | TlsLib4Pascal |
|---|---|
| `DangerousAcceptAnyServerCertificateValidator` | `WithDangerousInsecureSkipVerify(True)` |
| `ServerCertificateCustomValidationCallback = (_,_,_,_) => true` (accept-all) | `WithDangerousInsecureSkipVerify(True)` |
| `ServerCertificateCustomValidationCallback` with real logic (replace validation) | `WithCertificateVerifier(myVerifier)` |
| A callback that only *tightens* (extra rejections on top of normal validation) | `WithCertificateVerifyCallback(rule)` alone |
| Trusting a specific CA instead of the system store | `WithTrustAnchors(caPemOrDer)` |
| Ignoring only `SslPolicyErrors.RemoteCertificateNameMismatch` | `WithNameCheck(False)` |

The one semantic to internalise: **`ServerCertificateCustomValidationCallback = (...) => true`
maps to `InsecureSkipVerify`, not to our verify callback** — because ours can only reject
further, never accept-all. (See §4b.)

---

## 6. Through the integration adapters

The [mORMot / Indy / Synapse adapters](../TlsLib.Adapters) map their host's "ignore certificate
errors" flag onto `InsecureSkipVerify` for you (and supply the required empty trust store
internally), so the accept-any case is a one-liner:

```pascal
// mORMot   (TNetTlsContext)
Context.IgnoreCertificateErrors := True;

// Indy     (our TTlsLibSSLOptions)
IO.SSLOptions.InsecureSkipVerify := True;        // or SSLOptions.VerifyPeer := False

// Synapse  (TCustomSSL) — NOTE: with our TSSLTlsLib plugin VerifyCert defaults to TRUE (secure) — the
//           plugin flips Synapse's insecure base default. Set it False for the accept-any bypass
sock.SSL.VerifyCert := False;
```

A host framework's *own* verify callback is bridged only when its signature carries no OpenSSL
type. Indy `OnVerifyPeer` and mORMot `OnEachPeerVerify` hand you an OpenSSL cert (`TIdX509` /
`PX509`), so they are **not** bridged (it would re-couple the adapter to OpenSSL). Synapse's
`OnVerifyCert` (`function(Sender): Boolean`, no OpenSSL type) **is** bridged: set it and inspect
the peer through `GetPeerSubject` / `GetPeerIssuer` / `GetPeerFingerprint`.

For the neutral, framework-agnostic path, each adapter surfaces the augment-only
`WithCertificateVerifyCallback` on its own options (Indy `SSLOptions.VerifyCallback`; Synapse /
mORMot `SetTlsLib…VerifyCallback`) — no drop to Tier-2 required. The same surfaces expose an
out-of-band **verdict resolver** that parks the handshake for a decision; wire
`TLiveRevocationChecker.ResolveVerdict` (live OCSP/CRL over an injected `IHttpFetcher`) to it. All
of these are augment-only and fail-closed. See each adapter's README for details.

### Live OCSP/CRL revocation (opt-in)

Live revocation is **off by default** and never happens inside the sans-IO core: the config
builder takes no `IHttpFetcher`, by design, so the engine stays network-free. You opt in on the
`TTlsStream` (the convenience blocking stream) by attaching a checker to the parked verdict:

```pascal
// 1. enable async verdicts on the config, so the engine parks for an out-of-band
//    decision instead of deciding inline: ...WithRevocation(TRevocationPosture.Hard)
//    .WithAsyncCertificateVerdict(True, deadlineMs)  <-- without this the resolver never fires
// 2. attach the live checker to the stream (the clock drives the deadline; the
//    fetcher owns every socket):
checker := TLiveRevocationChecker.Create(provider, clock, fetcher, TRevocationPosture.Hard,
  TLiveRevocationMethod.OcspThenCrl, timeoutMs);
stream.SetCertificateVerdictResolver(checker.ResolveVerdict);
```

A **stapled** OCSP response (validated in the handshake pipeline, before the park) is preferred;
the live fetch is the fallback for a leaf that carries no staple. The posture governs the
*indeterminate* outcome — `Hard` rejects an unreachable/malformed/stale result, `Soft` accepts it
— while a definitive, issuer-authenticated **Revoked** always aborts with `certificate_revoked`.
Posture **`Off` performs no live fetch at all** (its network and privacy cost is suppressed); a
stapled Revoked is still honoured by the pipeline. CRL responses are only trusted inside their
`thisUpdate`/`nextUpdate` window, so a replayed stale CRL is treated as indeterminate, never a Good.

The config **`WithRevocation` posture and the live channel are one policy**: when a verdict
resolver is attached, an indeterminate/no-staple leaf is *deferred* to it rather than decided
inline, so `WithRevocation(Hard)` + a resolver rejects only a genuinely revoked (or unreachable,
under Hard) peer — it does not blanket-reject an unstapled one. Without a resolver, `Hard` decides
inline as before (a missing staple is rejected); a `must-staple` leaf (RFC 7633) always requires a
current Good staple and is never deferred.

**Server-side (mutual-TLS client certificates).** The same posture applies to the client
certificate a server verifies — set it with the server `WithRevocation`. A client cannot be asked
to staple, so `Hard` client-certificate revocation is satisfiable **only** by a live resolver
(there is no stapled fallback); `Build` rejects a `Hard`, client-authenticating server that has no
resolver. Attach the resolver on the server's stream exactly as above; a revoked client certificate
then aborts the handshake with `certificate_revoked`.

### Time source: one injected clock

Every time-based certificate decision reads from a single injected `ITlsClock` — the chain
`notBefore`/`notAfter` window, the PKIX path-validation date, the OCSP delegated-responder validity,
and the stapled/live `thisUpdate`/`nextUpdate` freshness windows. There is no hidden system-clock
fallback anywhere in the trust path, so the *whole* trust decision is deterministic and
mock-clock testable — inject a fixed clock with `WithClock` to test acceptance of a not-yet-valid
or just-expired leaf, or to validate against a trusted time on a device with no reliable RTC:

```pascal
config := TTlsConfigBuilder.CreateClient
  .WithTrustedCertificate(caDer)
  .WithClock(myFixedClock)   // drives cert validity, PKIX, and revocation freshness
  .BuildClient;
```

The default is the real system clock (`TSystemClock`), so this only matters when you override it.

---

## Rule of thumb

Reach for §1–§3 (trust a CA, pin, or relax just the host-name) before ever reaching for §4.
`InsecureSkipVerify` disables authentication entirely — it makes the connection encrypted but
**not** authenticated, which defeats most of the point of TLS. Keep it to tests.
