# OS system trust

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · System trust · [Compression](certificate-compression.md) · [ECH](ech.md) · [Security model](security-model.md)

By default TlsLib4Pascal verifies against **the trust anchors you give it** — a private CA, a
pinned root bundle, whatever you pass to `WithTrustAnchors` (see
[certificate-verification.md](certificate-verification.md)). This guide is about the other common
case: verifying against **the operating system's own trust store**, the way a browser or `curl`
does, without shipping your own CA bundle.

That capability is **opt-in and lives in a separate package** — the core library never depends on
any OS trust API, so a build that doesn't want it pays nothing (no `crypt32`, no `Security.framework`,
no filesystem probing linked in). You add the `TlsLib.Trust.System` package only when you want it.

Throughout, `P` is an `ICryptoProvider` (`TDefaultCryptoProvider.Create as ICryptoProvider`).

---

## How it works

By default TlsLib4Pascal does its **own** chain validation (PKIX, expiry, host-name, revocation) with
CryptoLib4Pascal. "System trust" in **Anchors** mode therefore means *harvest the OS's trusted root
set and feed those roots into our own validator* — the chain decision stays in the library. On every
platform that can enumerate its store, that is the default:

| Platform | Source | How |
|---|---|---|
| **Windows** | `ROOT` + `CA` system stores, minus `Disallowed` | `crypt32` enumeration → our validator |
| **macOS** | System + admin + user trust settings | `Security.framework` → our validator |
| **Unix/Linux** | `/etc/ssl/certs` (and distro variants; honours `SSL_CERT_FILE` / `SSL_CERT_DIR`) | filesystem harvest → our validator |
| **iOS** | *(no enumeration API)* | delegates the verdict to `SecTrust` |
| **Android** | *(harvest banned — stale/partial)* | delegates the verdict to the platform `X509TrustManager` (Delphi: zero-config; FPC: one `TlsLibAndroidInitTrust` call) |

iOS and Android are the two exceptions — both **delegate-only**. Apple exposes no API to *list* the
trusted roots, so there we delegate the whole verdict to `SecTrust`. On Android the on-disk root set is
stale/partial (Android 7+ splits system vs user CAs; Android 14+ moves system roots to the immutable
`com.android.conscrypt` APEX) and only the Java `X509TrustManager` applies the full policy —
network-security-config (per-domain trust, user-CA opt-in, pinning) — so harvesting is banned and we
hand the peer chain to the platform verifier via JNI. The platform manager does not itself consult a
stapled OCSP response, so the delegate decides the staple with the library's own revocation verdict
(cache-only, no network) after the platform chain check — see the posture note below.

The delegate needs the running JavaVM to attach handshake threads. **On Delphi this is automatic** — the
unit captures `System.JavaMachine` in its `initialization` (the RTL has set it by then, in
`ANativeActivity_onCreate`), so a NativeActivity app has nothing to call. **On FPC it must be supplied
once** — FPC has no such global, and its `JNI_OnLoad` is the natural place to pass it:

```pascal
// Delphi: nothing to do - UseSystemTrust just works on Android.

// FPC: call once with the JavaVM, from your JNI_OnLoad (where the runtime hands it to you):
uses TlpAndroidSystemTrust;

function JNI_OnLoad(vm: pointer; reserved: pointer): longint; cdecl; [public, alias: 'FPC_JNI_ON_LOAD'];
begin
  TlsLibAndroidInitTrust(vm);
  Result := JNI_VERSION_1_6;
end;
```

If the JavaVM cannot be resolved (only reachable on FPC when the call is omitted), every `Verify` fails
closed (rejects, `internal_error`) and logs guidance to logcat. The OS engine validates the chain, but
Android's `X509TrustManager` does **not** verify the host (that is `HostnameVerifier`'s job), so the
delegate enforces RFC 6125 hostname identity with the library's own matcher after the OS trust check —
a valid-chain certificate for the wrong host is rejected. As with iOS, an empty host name skips both the
hostname check and the per-domain NSC/pin lookup (the OS falls back to plain
`X509TrustManager.checkServerTrusted`), and that same host-less path is what the client-certificate
(mutual-TLS) case uses — both limitations are shared with iOS by design.

Two optional packages support this:

- **`TlsLib.Trust.System`** — the OS harvest + delegate above.
- **`TlsLib.Trust.Bundle`** — a baked-in PEM root set (e.g. the Mozilla/NSS roots), for when you want
  a *fixed, offline* public-root set instead of whatever the host happens to trust. See
  [Bundled roots](#bundled-roots) below.

---

## Using it directly

The `TSystemTrust` facade adds the OS anchors to a config builder and returns it for chaining:

```pascal
uses TlpTlsPresets, TlpICryptoProvider, TlpDefaultCryptoProvider, TlpSystemTrustFacade;

var P: ICryptoProvider;
begin
  P := TDefaultCryptoProvider.Create as ICryptoProvider;
  LConfig := TSystemTrust.WithSystemTrust(TTlsPresets.Compatible(P).Client, P).Build;
  // LConfig now verifies against the OS trust store
end;
```

There are `ITlsClientConfigBuilder` and `ITlsServerConfigBuilder` overloads (the server one supplies
the OS anchors used to verify **client** certificates in mutual TLS). An optional third argument,
`TSystemTrustMode` (`Default` / `Anchors` / `Delegate`), forces harvest-vs-delegate; `Default`
picks the best available for the platform and is what you want.

> **`WithSystemTrust` on a server harvests OS roots (Anchors mode) only.** Its `Delegate` mode means
> "verify the peer against the OS's *own* trusted roots", which is the public web PKI — never what you
> want for authenticating *clients* (any publicly-issued certificate would be accepted). So the server
> overload supports **Anchors** mode and raises on `Delegate`. To validate client certificates with the
> **OS chain engine** against *your* private CA instead, see
> [OS-engine client-certificate validation](#os-engine-client-certificate-validation-mtls) below — that
> path treats your configured client-CA anchors as an *exclusive* trust root, so the OS/public roots are
> never consulted.

Because system anchors are just another anchor source, they **union** with anything else you add —
so "trust the public web PKI **and** my private CA" is simply:

```pascal
LConfig := TSystemTrust.WithSystemTrust(TTlsPresets.Compatible(P).Client, P)
  .WithTrustAnchors(LoadFile('my-private-ca.pem'))   // unions with the OS roots
  .Build;
```

---

## Delegate mode: verifying through the OS chain engine

Everything above is **Anchors** mode — harvest the OS roots, then run *our* validator. **Delegate**
mode is the other option: hand the whole verdict to the platform's chain engine. It is the default
(and only) mode where roots cannot be enumerated (iOS, Android), and can be forced elsewhere with
`TSystemTrustMode.Delegate`.

On **Windows** the server delegate runs crypt32's SSL server policy with URL retrieval forced
**cache-only** (no socket — it never blocks the handshake), and it honours the same connection
settings the built-in verifier does:

- **Revocation posture** — `WithRevocation(Soft|Hard|Off)` governs an *indeterminate* outcome
  (no cached CRL/OCSP reachable): `Soft` accepts, `Hard` rejects, `Off` skips the check. A definitive
  *revoked* always rejects.
- **The stapled OCSP response** from the handshake is fed to the engine as cached revocation data.
- **The injected clock** (`WithClock`) supplies the validation time.

Because it is cache-only, the delegate is synchronous — the asynchronous live-OCSP/CRL resolver
(`WithAsyncCertificateVerdict`) is **not** engaged in Delegate mode. That is by design, not a
regression.

The **macOS, iOS and Android** delegates honour the same three settings — Apple through a
`SecPolicyCreateRevocation` policy plus `SecTrustSetVerifyDate` and the stapled response, Android
through a library-side staple check after the platform chain verdict. The one difference is that
Android has no verify-date seam, so its *chain* validity is judged at the platform's own time (the
clock still drives the staple-freshness window). The platform specifics are in the policy-difference
notes below.

### OS-engine client-certificate validation (mTLS)

An mTLS **server** authenticates the *client's* certificate, and it must do so against **your**
client-CA — never the public web PKI. So this is deliberately *not* `WithSystemTrust`'s job (its
`Delegate` would mean the OS roots). Instead, install the OS client delegate explicitly; it builds an
**exclusive-root** chain engine over the client-CA anchors you configure, so nothing else can root a
client path:

```pascal
uses TlpOSSystemTrust;   // TOSSystemTrust

LConfig := TTlsPresets.Compatible(P).Server
  .WithCredential(LoadFile('server-chain.pem'), LoadFile('server-key.pem'))
  .WithPeerAuth(TClientAuthMode.Required)                       // request + require a client cert
  .WithTrustAnchors(LoadFile('client-ca.pem'))                  // YOUR private client CA
  .WithCertificateVerifierSource(TOSSystemTrust.ClientVerifierSource(P))
  .Build;
```

The delegate uses the `clientAuth` EKU + the OS client-auth policy (a client certificate is never
stapled). It is available on **Windows, macOS, iOS and Android**: Windows and Apple apply the same
posture/clock/cache-only revocation as the server delegate; the Android client delegate is an
anchors-only KeyStore chain check (no posture/clock — see the Android note below). Note it **consumes**
the configured anchors (they are its exclusive root), so — unlike a whole verifier — it *composes* with
`WithTrustAnchors` rather than being exclusive of it.

### Policy differences vs. the built-in verifier

The OS chain engine is not a byte-for-byte replacement for the built-in PKIX pipeline — choosing a
delegate is choosing the OS's behaviour, which differs in a few security-relevant ways. The table
below is the **Windows** delegate, verified against crypt32 (that is the delegate this library's tests
exercise). The rows are a mix of Windows-specific mechanisms and generic delegate traits — the rows
marked *(any delegate)* apply to any OS delegate; the rest are crypt32 specifics.

| Area | Built-in verifier | Windows delegate (crypt32) |
|---|---|---|
| **Revocation fetch** | live OCSP/CRL via the async resolver (at the park) | **cache-only** + the handshake staple; no network, async resolver not engaged |
| **Uncached root** | validates against the roots you gave it | cache-only disables AuthRoot auto-download, so a valid-but-uncached root can surface as `unknown_ca` |
| **Alert specificity** | maps each failure to its specific alert | a catch-all of engine error codes collapses to `bad_certificate` (posture/expiry/revocation/EKU are still specific) |
| **OS distrust inputs** | unaware of them | honours the OS **Disallowed** store and CTLs |
| **Chain-algorithm/strength policy** *(any delegate)* | over the assembled path, configured roots exempt | over the **OS-built path**, the OS anchor exempt (a whole-verifier instance source is not policy-checked) |
| **Name matching** *(any delegate)* | our RFC 6125 matcher | the OS host-name logic (may differ on wildcards / IP literals) |
| **Path building & name constraints** *(any delegate)* | CryptoLib `PkixCertPathBuilder` | the OS engine's own path building |

The macOS, iOS and Android delegates diverge from the built-in pipeline in *analogous* ways, but along
their own platform's lines — their own distrust inputs (SecTrust settings, the Android store) and their
own alert mapping. Like the Windows delegate they are **cache-only** (no network revocation during the
handshake): the Apple delegate disables SecTrust network fetch and applies the posture as a
`SecPolicyCreateRevocation` policy; the Android delegate applies the posture through the library's own
staple verdict. A few specifics worth stating:

- **Revocation posture is honoured on every delegate**, cache-only. **Hard** therefore needs a fresh
  stapled (or, on Windows/Apple, cached) *Good* response: because the staple covers only the leaf and
  the intermediate has no cached response over a cold cache, Hard can reject a first, cold-cache
  handshake — the same on Windows and Apple. On the client (mTLS) path a certificate is never stapled,
  so Hard mTLS through any OS delegate likewise needs a warm cache.
- **Off is slightly stricter than the built-in / Windows Off on Apple and Android**: a definitive
  *Revoked* in a stapled/cached response still rejects (it is never softened), whereas Windows Off
  skips revocation entirely.
- **Injected clock:** honoured for chain validity on Windows and Apple. On **Android** the platform
  `X509TrustManager` exposes no verify-date seam, so the chain is validated at the platform's own time;
  the clock *is* honoured for the staple-freshness window (the library decides that). This is the one
  documented Android limitation.
- **Android needs the peer to send its issuer for Hard**: the staple post-check authenticates the
  staple against `chain[1]`, so a leaf-only chain is indeterminate and Hard rejects it (Windows
  discovers the issuer itself).
- **must-staple (RFC 7633) is enforced by the built-in verifier only** — no OS delegate, Windows
  included, honours it.
- **Chain-algorithm/strength policy runs on every delegate, over the path the OS built** (the OS
  anchor exempt), so the advertised-scheme filter, the MD5/SHA-1 refusal and the key-strength floors
  apply under Delegate mode too — not just the portable pipeline. One ordering nuance follows from
  *where* each platform checks revocation: Windows/Apple fold revocation into the OS chain verdict
  (before our policy), so a certificate that is both weak and revoked reports `certificate_revoked`;
  Android decides the staple in a post-check *after* our policy, so the same certificate reports
  `unsupported_certificate`. A whole-verifier instance you inject as the trust source is not
  policy-checked (you replaced the trust decision wholesale).

None of these differences weaken the trust decision relative to a correctly-configured OS; they are
behavioural *differences* to be aware of when you pick Delegate over the portable pipeline.

---

## Composition: union vs. exclusive

The builder distinguishes two kinds of trust contribution:

- **Anchor sources** — `WithTrustAnchors`, `WithTrustStore`, and `TSystemTrust.WithSystemTrust`.
  These are additive: supply several and they **union** into one root set.
- **A whole verifier** — `WithCertificateVerifier` (below). This **replaces** the built-in pipeline
  and is **exclusive**: combining it with any anchor source, or setting two verifiers, is a typed
  error (`EInvalidOperationTlsLibException`) at `Build`.

The rule that decides exclusivity is: *a trust source that brings its **own** roots is exclusive of
your anchors; one that **consumes** your anchors composes with them.* A whole verifier and the OS
**server** delegate (OS roots) bring their own → exclusive. The OS **client** delegate uses your
configured client-CA anchors as its exclusive root → it composes with `WithTrustAnchors` (that is why
the mTLS example above sets both).

## System trust is never implicit

Consistent with the library's fail-closed stance, **you must ask for system trust** — it is never a
silent default. A client builder with verification on but no trust source named (no anchors, no
system trust, no verifier) is **refused at `Build`**, not quietly pointed at the OS store. This is
deliberate: an implicit trust source is exactly the kind of thing that weakens security by accident.

---

## Replacing verification wholesale: `WithCertificateVerifier`

Sometimes you want to substitute the entire verification decision with a ready-made verifier instance,
or plug in bespoke logic. That is what `WithCertificateVerifier` is for: the client builder takes an
`IServerCertificateVerifier`, the server builder an `IClientCertificateVerifier`. It **replaces** the
built-in PKIX pipeline for that config:

```pascal
LConfig := TTlsPresets.Compatible(P).Client
  .WithCertificateVerifier(MyVerifier)   // exclusive: no WithTrustAnchors alongside it
  .Build;
```

A pre-built instance cannot see a connection's clock or revocation posture. When a verifier needs
those — as the OS delegates do — install a **source** with `WithCertificateVerifierSource` instead;
the engine builds the verifier per connection from the trust context. `TSystemTrust.WithSystemTrust`
and `TOSSystemTrust.ClientVerifierSource` (above) use this path for you.

---

## Through the adapters

Each adapter exposes system trust through *its host library's* idiom, and all three obey the
never-implicit / fail-closed rule.

### Indy

The IO-handler's `SSLOptions` carry a `UseSystemTrust` flag. It unions with a `RootCertFile` bundle
and any `CustomTrustStore`; a custom verifier replaces the pipeline. Verifying with no source named
fails closed.

```pascal
LIO := TTlsLibIOHandlerSocket.Create(LHttp);
LIO.SSLOptions.UseSystemTrust := True;          // OS roots
// LIO.SSLOptions.RootCertFile := 'private.pem'; // (optional) unions a private CA
LHttp.IOHandler := LIO;
```

### mORMot

Map mORMot's native `TNetTlsContext.CASystemStores`: naming an **anchor-bearing** store
(`scsRoot` and/or `scsCA`) turns on the OS harvest, unioning with `CACertificatesFile`.
`scsMY`/`scsSpc` are *not* server-auth anchors and do not trigger it.

```pascal
LClient.TLS.CASystemStores := [scsRoot];         // OS roots (unions with CACertificatesFile)
```

Two caveats:

- **`CACertificatesRaw` is not supported.** It carries live OpenSSL `PX509` handles; TlsLib4Pascal is
  OpenSSL-free, so a context that sets it is rejected with a clear error — pass a PEM/DER file via
  `CACertificatesFile`, or use `CASystemStores`.
- **On a server doing mTLS**, `CASystemStores` validates *client* certificates against the public
  web-PKI roots — a very broad surface that is rarely what you want. Prefer a private
  `CACertificatesFile` for client-certificate authentication.

### Synapse

Synapse's `TCustomSSL` base has no system-trust concept, so the adapter exposes it as a property on
its own plugin — the same way Synapse's own plugins expose extras (`TSSLSChannel.DataTimeout`,
`TSSLCryptLib.PrivateKeyLabel`): cast `Sock.SSL` to the plugin type.

```pascal
uses TlsLibSynapseTls;    // registers the plugin

(LHttp.Sock.SSL as TSSLTlsLib).UseSystemTrust := True;   // OS roots
LHttp.Sock.SSL.VerifyCert := True;                        // real verification
// LHttp.Sock.SSL.CertCAFile := 'private.pem';            // (optional) unions a private CA
```

`VerifyCert := True` with a `CertCAFile` pins to that bundle; with `UseSystemTrust` it uses the OS
store; with both it unions them; with neither it fails closed. `VerifyCert := False` is the loud
`InsecureSkipVerify` bypass.

---

## Bundled roots

When you want a **fixed, offline** public-root set — reproducible across machines, independent of
whatever the host trusts — use `TlsLib.Trust.Bundle` instead of (or alongside) the OS harvest:

```pascal
uses TlpBundleTrust;
LConfig := TTlsPresets.Compatible(P).Client
  .WithTrustStore(TBundleTrust.FromPemFile(P, 'roots.pem'))
  .Build;
```

---

## Packaging

The core `TlsLib4PascalPackage` requires **none** of this — verify it never lists a trust package in
its `requires` / `RequiredPkgs`. To use OS trust, add the optional package to your project:

- **FPC (Lazarus):** add `TlsLib.Trust.System` (and/or `TlsLib.Trust.Bundle`) as a required package.
- **Delphi:** add the corresponding `.dpk`/`.dproj`.

The adapters that support system trust already declare the dependency, so if you use an adapter you
get it transitively.
