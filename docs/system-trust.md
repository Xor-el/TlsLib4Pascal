# OS system trust

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · System trust · [Compression](certificate-compression.md) · [ECH](ech.md) · [Security model](security-model.md)

By default TlsLib4Pascal verifies against **the trust anchors you give it** — a private CA, a
pinned root bundle, whatever you pass to `TServerVerification.WebPki` (see
[certificate-verification.md](certificate-verification.md)). This guide is about the other common
case: verifying against **the operating system's own trust store**, the way a browser or `curl`
does, without shipping your own CA bundle.

That capability is **opt-in and lives in a separate package** — the core library never depends on
any OS trust API, so a build that doesn't want it pays nothing (no `crypt32`, no `Security.framework`,
no filesystem probing linked in). You add the `TlsLib.Trust.System` package only when you want it.

Throughout, `Crypto` is an `ICryptoProvider` and `Pkix` an `IPkixProvider`
(`TDefaultCryptoProvider.Create as ICryptoProvider` and `TDefaultPkixProvider.Create as IPkixProvider`).

---

## How it works

There are two ways to use the OS trust store, chosen with `TSystemTrustMode`:

- **Delegate**: the OS chain engine builds and judges the path with its own roots and full policy
  (crypt32 on Windows, `SecTrust` on Apple, the Java `X509TrustManager` on Android).
- **Anchors**: harvest the OS's trusted root set and feed those roots into our own validator (PKIX,
  expiry, host-name, revocation with CryptoLib4Pascal). The chain decision stays in the library.

`Default` uses the OS engine wherever the OS has one and harvests where it has none:

| Platform | `Default` | `Anchors` | `Delegate` |
|---|---|---|---|
| **Windows** | Delegate (crypt32) | harvest of the `ROOT` store (server-auth-capable roots only), minus `Disallowed`; every `Disallowed` certificate is also refused anywhere on a path | yes |
| **macOS** | Delegate (`SecTrust`) | harvest of System + admin + user trust settings (SSL-scoped; a user "Never Trust" in any domain excludes); a Deny on any certificate, root or intermediate, is refused anywhere on a path | yes |
| **iOS** | Delegate (`SecTrust`) | raises (no enumeration API) | yes |
| **Android** | Delegate (`X509TrustManager`; Delphi: zero-config, FPC: one `TlsLibAndroidInitTrust` call) | raises (harvest banned, the on-disk set is stale/partial) | yes |
| **Linux, BSD, Solaris** | Anchors | `/etc/ssl/certs` (and distro variants; honours `SSL_CERT_FILE` / `SSL_CERT_DIR`, ignored under elevated privilege) | raises (no OS verifier) |

> **Breaking change.** `Default` used to be Anchors on Windows and macOS. It is now Delegate there.
> Anchors stays an explicit opt-in on both: pass `TSystemTrustMode.Anchors` to get the old behaviour
> (see [Delegate vs. Anchors](#delegate-vs-anchors-what-differs)).

The Unix `SSL_CERT_FILE` / `SSL_CERT_DIR` overrides are dropped when the process runs with elevated
privileges (setuid/setgid, or the kernel's secure-execution flag), falling back to the built-in CA
table — an attacker who controls a privileged process's environment cannot redirect trust to their
own CA.

iOS and Android are **delegate-only**. Apple exposes no API to *list* the
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
uses jni, TlpAndroidSystemTrust;

function JNI_OnLoad(vm: pointer; reserved: pointer): longint; cdecl; [public, alias: 'FPC_JNI_ON_LOAD'];
begin
  TlsLibAndroidInitTrust(vm);
  Result := JNI_VERSION_1_6;
end;
```

If the JavaVM cannot be resolved (only reachable on FPC when the call is omitted), every `Verify` fails
closed (rejects, `internal_error`) and logs guidance to logcat. The OS engine validates the chain, but
Android's `X509TrustManager` does **not** verify the host (that is `HostnameVerifier`'s job), so the
delegate enforces RFC 9525 hostname identity with the library's own matcher after the OS trust check —
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

The `TSystemTrust` facade makes the OS trust the server-certificate verification policy of a client:

```pascal
uses TlpTlsPresets, TlpICryptoProvider, TlpIPkixProvider, TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider, TlpSystemTrustFacade;

var
  Crypto: ICryptoProvider;
  Pkix: IPkixProvider;
begin
  Crypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  Pkix := TDefaultPkixProvider.Create as IPkixProvider;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TSystemTrust.ServerVerification(Pkix).Build)
    .Build;
  // LConfig now verifies against the OS trust store
end;
```

`TSystemTrust.ServerVerification` returns a **client** policy only — system trust is a
*server-certificate* trust source (a client verifying a server). An optional argument,
`TSystemTrustMode` (`Default` / `Anchors` / `Delegate`), forces harvest-vs-delegate; `Default` picks
the engine as in the table above and is what you want. A forced mode the platform cannot honour
raises `ESystemTrustUnsupportedTlsLibException`.

> **An mTLS server's client-CA is never the OS store.** The OS roots are the public web PKI (harvested
> for *server* authentication), so rooting *client*-certificate trust there would accept any
> publicly-issued certificate as a valid client. There is no server form of `ServerVerification`.
> Supply the server's client-CA explicitly with `TClientVerification.WebPki`. To validate client
> certificates with the **OS chain engine** against *your* private CA, use
> [OS-engine client-certificate validation](#os-engine-client-certificate-validation-mtls) below — it
> treats your configured client-CA anchors as an *exclusive* trust root, so the OS/public roots are
> never consulted. If you deliberately want the machine store as the client-CA, write it out —
> `TClientVerification.WebPki(TOSSystemTrust.AnchorStore(Pkix))` — and know it authenticates clients
> against the public PKI.

### Host roots beside the OS roots

Host anchors go in as an argument. The rule is the same on every OS engine: *my CA plus the OS
roots.* "Trust the public web PKI **and** my private CA" is simply:

```pascal
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default,
    TTrustAnchorStore.Create(Pkix.Certificates.LoadChain(LoadFile('my-private-ca.pem')))
    as ITrustAnchorStore).Build)   // the private CA beside the OS roots
  .Build;
```

What happens:

- The OS judges the chain with its own roots and full policy.
- If it fails **only** for lack of a trusted root, the same OS engine judges the chain against the
  host roots alone. Any other failure (revoked, expired, distrusted, wrong usage, name, pin) is final
  and the host roots never rescue it.
- Apple does this natively in one evaluation: `SecTrust` takes the host roots as extra anchors beside
  the system roots. Windows and Android do two passes: the OS roots first, then the host roots as the
  exclusive root.
- When both passes fail, the alert of the pass that reached a root is reported, else the first
  pass's.
- In Anchors mode the host roots join the harvested OS roots in our own validator and any anchor ends
  a path.
- Host roots are judged as private PKI. Rules that exist only for system roots (Apple CT and validity
  caps, Android CT) do not apply to a chain that ends at one.
- OS distrust (Windows `Disallowed`, macOS trust-settings Deny) also refuses a path that ended at a
  host root. iOS and Android expose no readable distrust list, so there is nothing to apply.

**Android.** The host roots apply app-wide, like a certificate in `<base-config>` that every domain
inherits. They override a `network_security_config.xml` domain entry that restricts roots, because
Android has no API to read it. NSC pin-set failures, expiry and revocation stay final, and
user-installed CAs are not newly trusted. If you need per-domain roots, put them in
`network_security_config.xml` and pass no host roots.

### OS distrust in Anchors mode

An OS-distrusted certificate is refused by the built-in verifier wherever it appears on the path,
not only as a root:

- **What counts:** the certificates the platform lets us read as distrusted — Windows `Disallowed`
  and macOS trust settings with a Deny result. They travel with the anchor snapshot.
- **Exact certificate only:** the match is on the whole certificate. A re-issued certificate with
  the same key or name is a different certificate and is not caught; a Disallowed entry known only
  by hash (no certificate in the store) and the OS's built-in blocklists are not visible. Use
  **Delegate** mode where the full OS policy matters.
- **Verdict:** a distrusted leaf, or a path that can only run through a distrusted intermediate,
  fails with `bad_certificate`. If the peer also sent a valid alternative path that avoids the
  distrusted certificate, that path verifies. A distrusted root is never an anchor: if the peer
  does not send it, the chain simply has no anchor and fails with `unknown_ca`.
- **Distrust wins across sources:** the union above applies to distrust too, so a root that the OS
  distrusts is not re-admitted by supplying it again as a host anchor.
- **Immutable stores:** an `ITrustAnchorStore` is a snapshot, and the union of several is built once
  at `Build`. Verification caches work by store identity, so a custom store must never change after
  it is handed to a config — build a new store (and a new config) to change trust.
- **No distrust input:** Unix. **Not applicable:** Android and iOS, which are delegate-only (the
  platform already applies its own distrust).
- **macOS Deny scope:** a Deny whose scope cannot be read is treated as a Deny, so it can also
  block a certificate that was only denied for another purpose.

---

## Delegate mode: verifying through the OS chain engine

The distrust notes above are about **Anchors** mode — harvest the OS roots, then run *our* validator.
**Delegate** mode hands the whole verdict to the platform's chain engine. It is the default on
Windows, macOS, iOS and Android, and the only mode on iOS and Android. Linux, BSD and Solaris have no
OS verifier, so `TSystemTrustMode.Delegate` raises there.

On **Windows** the server delegate runs crypt32's SSL server policy with URL retrieval forced
**cache-only** (no socket — it never blocks the handshake), and it honours the same connection
settings the built-in verifier does:

- **Revocation posture** — `WithRevocation(Soft|Hard|Off)` governs an *indeterminate* outcome
  (no cached CRL/OCSP reachable): `Soft` accepts, `Hard` rejects, `Off` skips the check. A definitive
  *revoked* always rejects.
- **The stapled OCSP response** from the handshake is fed to the engine as cached revocation data.
- **The injected clock** (`WithClock`) supplies the validation time.

Because it is cache-only, the delegate is synchronous and never touches the network on the engine
thread. The asynchronous live-OCSP/CRL resolver (`WithLiveRevocationVerdict`) is engaged only when you
arm it: an indeterminate cache-only outcome then defers to the park, including under `Hard`.

The **macOS, iOS and Android** delegates honour the same three settings — Apple through a
`SecPolicyCreateRevocation` policy plus `SecTrustSetVerifyDate` and the stapled response, Android
through a library-side staple check after the platform chain verdict. The one difference is that
Android has no verify-date seam, so its *chain* validity is judged at the platform's own time (the
clock still drives the staple-freshness window). The platform specifics are in the policy-difference
notes below.

### Delegate vs. Anchors: what differs

Both modes accept the same chains in the normal case. These are the differences you can observe:

| | Delegate (Default on Windows, macOS, iOS, Android) | Anchors (Default on Linux, BSD, Solaris) |
|---|---|---|
| OS distrust | the OS applies it natively to a path that ended at an OS root; for a path that ended at a host root the library applies an exact-match post-check over the readable list (Windows `Disallowed`, macOS Deny), with the same caveats as Anchors mode (hash-only entries and built-in blocklists are invisible), and none on iOS and Android | exact-certificate match only (Windows `Disallowed`, macOS Deny), on every path |
| Root-store properties (Windows EKU override, disabled and partially distrusted roots; enterprise policy) | honoured | not honoured: a harvest keeps the certificates only |
| Windows roots not installed yet | not downloaded inline (cache-only retrieval) | not seen: the harvest lists installed roots |
| Missing intermediates | no fetch inline; the OS may use its cache | configured intermediates only |
| Revocation source | OS cache plus the staple; on Windows and Apple `Hard` is decided inline from the staple or an OS-cached good status, and needs the live-revocation verdict only when neither exists (Android has no cached revocation, so `Hard` is refused without it) | staple plus the portable live checker |
| System-root-only rules (Apple CT and validity caps, Android CT) | apply to the OS roots, not to host roots | none |
| Error alerts | the OS's mapping | ours |

To get Anchors behaviour on Windows or macOS, pass `TSystemTrustMode.Anchors`: it is deterministic,
runs our own pipeline and has portable revocation. iOS and Android have no Anchors mode.

### OS-engine client-certificate validation (mTLS)

An mTLS **server** authenticates the *client's* certificate, and it must do so against **your**
client-CA — never the public web PKI. So this is deliberately *not* `TSystemTrust`'s job
(it has no server form at all). Instead, install the OS client delegate explicitly; it builds an
**exclusive-root** chain engine over the client-CA anchors you configure, so nothing else can root a
client path:

```pascal
uses TlpSystemTrustBase, TlpOSSystemTrust;   // TSystemTrustFetch, TOSSystemTrust

LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(TTlsCredential.Load(Crypto, Pkix,
    LoadFile('server-chain.pem'), LoadFile('server-key.pem')))
  .WithPeerAuth(TClientAuthMode.Required)                       // request + require a client cert
  .WithClientVerification(TClientVerification.VerifierSource(   // YOUR private client CA as its root
    TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.CacheOnly),
    TTrustAnchorStore.Create(Pkix.Certificates.LoadChain(LoadFile('client-ca.pem')))
    as ITrustAnchorStore).Build)
  .Build;
```

The delegate uses the `clientAuth` EKU + the OS client-auth policy (a client certificate is never
stapled). It is available on **Windows, macOS, iOS and Android**: Windows and Apple apply the same
posture/clock revocation as the server delegate; the Android client delegate is an
anchors-only KeyStore chain check with no OS revocation and no verify-date seam: revocation is
decided by the posture alone, and the chain is validated at the platform's own time. Note it **consumes**
the anchors you pass to `TClientVerification.VerifierSource` (they are its exclusive root); `Build`
refuses it when those anchors yield no root (it would trust nothing). The `AFetch` argument selects cache-only
(no socket) or live revocation — see the next section.

#### Live client-certificate revocation (Windows + Apple, opt-in)

By default the client delegate is **cache-only** (the inline pass never opens a socket). To have the OS
engine fetch client-certificate revocation over the network — off the sans-IO engine thread, in the
async-verdict park, exactly like the server-cert live path — arm the delegate `Live` and wire the
OS-native resolver built from the **server** config:

```pascal
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
  .WithCredential(TTlsCredential.Load(Crypto, Pkix,
    LoadFile('server-chain.pem'), LoadFile('server-key.pem')))
  .WithPeerAuth(TClientAuthMode.Required)
  .WithClientVerification(TClientVerification.VerifierSource(
    TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.Live),
    TTrustAnchorStore.Create(Pkix.Certificates.LoadChain(LoadFile('client-ca.pem')))
    as ITrustAnchorStore).WithRevocation(TRevocationPosture.Hard).Build)
  .WithLiveRevocationVerdict(deadlineMs)             // the park the live check runs in (non-zero)
  .Build;
resolver := TOSSystemTrust.LiveRevocationResolver(LConfig);   // reads the client-CA anchors + posture
serverStream.SetCertificateVerdictResolver(resolver.ResolveVerdict);  // caller owns + frees it
```

The inline pass stays socket-free and *defers* an indeterminate revocation (effective-Soft) so the
handshake parks; the OS engine then re-evaluates with network fetch enabled and resolves the park —
a definitive **Revoked** aborts `certificate_revoked`, a **Good** accepts, an **indeterminate** follows
the posture (`Soft`/`Off` accept, `Hard` rejects `bad_certificate_status_response`). Because the client
path roots against an **in-memory exclusive client-CA store** (never the machine store), this needs no
store install and is exercisable locally. `Live` requires `WithLiveRevocationVerdict` (the park is
where it runs) — a server built `Live` without it raises before any IO. Pass an optional portable
fallback to `LiveRevocationResolver(config, fallback)` to run `TLiveRevocationChecker` over your
`IHttpFetcher` on an indeterminate OS outcome. **Windows and Apple only** — Android/Unix `Live` raises
`ESystemTrustUnsupportedTlsLibException` (compose the portable checker there instead).

### Policy differences vs. the built-in verifier

The OS chain engine is not a byte-for-byte replacement for the built-in PKIX pipeline — choosing a
delegate is choosing the OS's behaviour, which differs in a few security-relevant ways. Every delegate
runs **one shared pipeline over a per-OS chain engine**: the OS builds and trusts the path and reports
a revocation outcome, then the same chain-strength policy, revocation-posture decision, stapled-OCSP
check and endpoint-identity match run over it. So the library-side post-checks below are identical on
every platform; only the chain build/trust, the OS's own distrust inputs and its alert codes differ.

**Shared by every delegate** — the same code on Windows, Apple and Android (and, unlike the built-in
verifier, all **cache-only**: no network revocation during the handshake; the async resolver runs only
when `WithLiveRevocationVerdict` is armed, and Windows and Apple can opt into `Live`, which fetches in
the async park instead):

- **Chain-strength policy** runs over the OS-built path (the OS anchor exempt): the advertised-scheme
  filter, the MD5 refusal, the default SHA-1 refusal and the key-strength floors apply under Delegate
  mode too. A
  private PKI that still has SHA-1 certificates can name `TCertSignatureHash.Sha1` in the policy's
  `AllowedDeprecatedHashes`; that only stops this library refusing it, so a platform engine that
  rejects SHA-1 itself still does. A whole-verifier instance you inject as the trust source is
  *not* policy-checked (you replaced the trust decision wholesale).
- **RFC 9525 identity** is matched in-library on every delegate, SAN-only: the library checks the leaf's
  dNSName / iPAddress SANs itself rather than trust an engine's own host match, so no platform's
  deprecated subject-CN fallback is honoured. The host is still handed to a host-matching engine (for OS
  name-constraint checks) when the name check is on.
- **Revocation posture** (`Soft`/`Hard`/`Off`) is honoured cache-only. **Hard** needs a fresh *Good*
  (a stapled leaf response, or a cached one on Windows/Apple) — a cold cache, or the intermediate that
  a staple never covers, can make Hard reject a first handshake unless `WithLiveRevocationVerdict` is
  armed, which defers that indeterminate outcome to the park. A client certificate is never stapled,
  so **Hard mTLS** needs `WithLiveRevocationVerdict` on every platform (`Build` refuses a Hard,
  client-authenticating server without it).
- **A definitive stapled *Revoked* rejects under every posture, `Off` included** — a library post-check
  honours the staple even where the OS skipped revocation — aborting `certificate_revoked`.
- **must-staple (RFC 7633)** is enforced by every delegate, as the built-in verifier does: the TLS
  Feature well-formedness is a hard `bad_certificate` invariant for either role, and a must-staple server
  leaf the client asked to staple on the initial handshake demands a current *Good* staple
  (`bad_certificate_status_response`) even under `Soft`/`Off`.

**Per-platform specifics:**

| | Windows (crypt32) | Apple (SecTrust) | Android (`X509TrustManager`) |
|---|---|---|---|
| **Revocation mechanism** | chain revocation flags + cache-only URL retrieval, plus the staple | `SecPolicyCreateRevocation`, network fetch disabled | none of its own — the library's staple verdict |
| **OS distrust inputs** | the **Disallowed** store + CTLs (Anchors mode reads the Disallowed certificates only) | SecTrust settings (Anchors mode reads the Deny results only) | the platform trust store |
| **Alert mapping** | crypt32 codes → a specific alert, else `bad_certificate` | `OSStatus` → a specific alert, else `bad_certificate` | mapped from the `X509TrustManager` exception |
| **Injected clock** | chain validity + staple freshness | chain validity + staple freshness | staple freshness only — no verify-date seam, so the chain validates at the platform's own time (the one documented Android limitation) |
| **Host handed to the OS** | the DNS host (an IP literal is stripped) | the DNS host (IP stripped) | the connected host as-is — the network-security-config domain key, not a name check |
| **Issuer discovery for Hard** | discovers the issuer itself | discovers it itself | needs the peer to send its issuer (a leaf-only chain is indeterminate → Hard rejects, unless `WithLiveRevocationVerdict` defers it to the park) |
| **A weak *and* revoked leaf** | `certificate_revoked` (revocation is folded into the OS verdict, before our policy) | `certificate_revoked` | `unsupported_certificate` (the staple is a post-check *after* our strength policy) |
| **An uncached valid root** | may surface as `unknown_ca` (cache-only disables AuthRoot auto-download) | n/a — the OS ships its root store | n/a — the OS ships its root store |

On Android the **client-certificate** path is a special case: `checkClientTrusted` reports no validated
path, so the delegate takes the presented leaf alone as the validated path (the rest of the presented
chain has no guaranteed order). Live-revocation issuer discovery therefore uses the configured client-CA
candidates rather than a peer-sent intermediate, and only a leaf-key SPKI pin can match on this path.
The chain-algorithm and key-strength floor is applied to the leaf only: a client-certificate chain's
intermediates are validated by the platform but not held to that floor, so on this path the floor is
lower than on the server path and in the portable pipeline. If a deployment needs it on the whole
chain, use `TClientVerification.WebPki` over the client-CA anchors instead of the OS source, which
selects the portable pipeline for client certificates.

Apart from that leaf-only floor, none of these differences weaken the trust decision relative to a
correctly-configured OS; they are behavioural *differences* to weigh when you pick Delegate over the
portable pipeline.

---

## Composition: union vs. exclusive

A verification policy is one choice, and the anchors are arguments of the factory that makes it:

- **`WebPki`** — the built-in pipeline over the anchors you give it (stores and PEM/DER blobs
  **union** into one root set). System trust in Anchors mode joins this as a `WebPki` over the
  harvested OS roots plus yours (`TSystemTrust.ServerVerification`, client only: system trust is
  server-cert trust, never a server's client-CA).
- **`VerifierSource`** — a source that owns its roots (the OS delegate: the `Delegate` mode, the
  default on Windows, macOS, iOS and Android). The pipeline knobs (revocation, intermediates, minimum
  strength) still apply. Host roots reach it as a factory argument and are applied as described in
  [Host roots beside the OS roots](#host-roots-beside-the-os-roots).
- **`Custom`** — a whole verifier instance (below). It **replaces** the built-in pipeline, so it
  takes no anchors, intermediates or skip-verify: nothing it would ignore can be set beside it.
- **`DangerousSkip`** — no verification.

Who supplies the roots:

- A whole verifier brings its own roots and takes none of yours.
- The OS **server** delegate brings the OS roots and takes your host roots beside them.
- The OS **client** delegate uses the client-CA anchors you pass to
  `TClientVerification.VerifierSource` as its exclusive root. Because it has nothing to consume
  otherwise, `Build` refuses a client delegate whose anchors yield no root certificate (rather than
  deferring to an `unknown_ca` at handshake).

## System trust is never implicit

Consistent with the library's fail-closed stance, **you must ask for system trust** — it is never a
silent default. A client builder with verification on but no trust source named (no anchors, no
system trust, no verifier) is **refused at `Build`**, not quietly pointed at the OS store. This is
deliberate: an implicit trust source is exactly the kind of thing that weakens security by accident.

---

## Replacing verification wholesale: `Custom`

Sometimes you want to substitute the entire verification decision with a ready-made verifier instance,
or plug in bespoke logic. That is what `TServerVerification.Custom` is for: a client takes an
`IServerCertificateVerifier`, and `TClientVerification.Custom` takes an `IClientCertificateVerifier`
for a server. It **replaces** the built-in PKIX pipeline for that config:

```pascal
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.Custom(MyVerifier))   // takes no anchors
  .Build;
```

Because the instance replaces the pipeline, the settings that would be silently ignored beside it
(intermediate certificates, skip-verify) cannot be set on it at all, and a Hard revocation posture
needs a live revocation verdict (`Build` refuses it otherwise). The adapters refuse a custom verifier
beside switched-off peer verification the same way.

A pre-built instance cannot see a connection's clock or revocation posture. When a verifier needs
those — as the OS delegates do — use `VerifierSource` instead; the engine builds the verifier per
connection from the trust context. `TSystemTrust.ServerVerification` and
`TOSSystemTrust.ClientVerifierSource` (above) use this path for you.

---

## Through the adapters

Each adapter exposes system trust through *its host library's* idiom, and all four obey the
never-implicit / fail-closed rule.

### Indy

The IO-handler's `SSLOptions` carry a `UseSystemTrust` flag. It unions with a `RootCertFile` bundle
and any `CustomTrustStore` (the union rule is [Host roots beside the OS roots](#host-roots-beside-the-os-roots));
a custom verifier replaces the pipeline. Verifying with no source named fails closed. The flag uses
the `Default` mode.

```pascal
LIO := TTlsLibIOHandlerSocket.Create(LHttp);
LIO.SSLOptions.UseSystemTrust := True;          // OS roots
// LIO.SSLOptions.RootCertFile := 'private.pem'; // (optional) unions a private CA
LHttp.IOHandler := LIO;
```

### mORMot

Map mORMot's native `TNetTlsContext.CASystemStores`: naming an **anchor-bearing** store
(`scsRoot` and/or `scsCA`) turns on the OS harvest, but only when `CACertificatesFile` is empty: a
CA file replaces system trust, as it does in mORMot's own OpenSSL backend.
`scsMY`/`scsSpc` are *not* server-auth anchors and do not trigger it. (On Windows the harvest
itself reads the `ROOT` store only — the `CA` store holds cached intermediates, not anchors — so
`scsCA` and `scsRoot` both enable the same ROOT-only harvest.)

```pascal
LClient.TLS.CASystemStores := [scsRoot];         // OS roots (only when CACertificatesFile is empty)
```

Two caveats:

- **`CACertificatesRaw` is not supported.** It carries live OpenSSL `PX509` handles; TlsLib4Pascal is
  OpenSSL-free, so a context that sets it is rejected with a clear error — pass a PEM/DER file via
  `CACertificatesFile`, or use `CASystemStores`.
- **On a server doing mTLS**, `CASystemStores` is **ignored** — system trust verifies server
  certificates and is never a server's client-CA. The client-CA is `CACertificatesFile` (or a
  builder-driven config via `SetTlsLibMormotServerConfig`); a server with client auth on and only
  `CASystemStores` fails the build.

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

### fcl-net

fcl-net's `TSSLData` slots have no system-trust concept either, so the handler adds
`UseSystemTrust` as an extension property beside the native `CertificateData` trust slots. It is off
by default; `TlsLibFclNetTrustDefaults.UseSystemTrust` turns it on for every new handler, so a plain
`TFPHTTPClient` picks it up.

```pascal
uses TlsLibFclNetTls;

TlsLibFclNetTrustDefaults.UseSystemTrust := True;        // once, at startup: OS roots for every handler
// or per handler, inside OnCreateClientSocketHandler:
H.UseSystemTrust := True;                                // OS roots
// H.CertificateData.CertCA.FileName := 'private.pem';   // (optional) unions a private CA
```

`VerifyPeerCert` defaults to **True** here (stock fcl-net defaults it to `False`). With
`UseSystemTrust` it uses the OS store; with `CertCA` / `TrustedCertificate` it pins to those
anchors; with both it unions them; with neither it fails closed. `VerifyPeerCert := False` is the
loud `InsecureSkipVerify` bypass.

### Writing your own adapter

The core library reaches system trust only through `ISystemTrustInstaller` (unit
`TlpISystemTrustInstaller`), so a host-neutral adapter can offer a `UseSystemTrust` switch without
the core depending on this package. `TSystemTrustInstaller.Shared` (unit `TlpSystemTrustFacade`) is
the implementation the four adapters use: a stateless, process-wide instance.

- `ServerVerification(Pkix, ExtraAnchors)` returns the OS server-certificate policy, the same as
  `TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default, ExtraAnchors).Build`.
  `ExtraAnchors` (nil for none) are the host's own roots, trusted beside the OS ones on every
  platform (see [Host roots beside the OS roots](#host-roots-beside-the-os-roots)).
- `Identity` names the trust it installs (`'os-system-trust'` for the shared instance). Adapter
  config caches key on it (`TTlsConfigComposer.ClientSignature`), so an installer that installs
  different roots needs a different identity. The signature refuses an empty one.

Set it on the client-role options the composer builds from; a server never reads it, since system
trust is never a client-CA:

```pascal
uses TlpTlsConnection, TlpITlsConfig, TlpSystemTrustFacade;

LOptions := TTlsOptions.Default;
LOptions.SystemTrust := TSystemTrustInstaller.Shared;
LConfig := TTlsConfigComposer.BuildClientConfig(LOptions);
```

### Writing your own platform engine

An OS delegate is a generic verifier over an `IPlatformChainEngine` (unit `TlpIPlatformChainEngine`).
The engine builds and trusts a path with the OS; the delegate adds posture, strength policy, staple,
identity and the host-roots rule. The contract:

- `EvaluateServer` judges against the OS roots, or against `Anchors` as the exclusive root when that
  is non-empty. A rejection fills `AResult.Failure` with `NoTrustAnchor` when the only fault is that no
  trusted root was reached, and `Other` for anything else. An engine that does not classify leaves
  `None`, which counts as `Other` (host roots are then never tried).
- An engine that can trust host roots beside its own roots in one evaluation declares
  `NativeAnchorUnion` and reads `ExtraAnchors`.
- Any other engine must honour `Anchors` as the exclusive root on the server path and declare
  `ExclusiveServerAnchors`. The delegate then retries a `NoTrustAnchor` failure with the host roots as
  the exclusive root. This is required for host roots to work; there is no fallback to our own
  validator.
- A path that relied on the host roots is refused when it holds a certificate in the OS distrust set
  the source read. Under a native union every accepted path is checked, since which root ended it
  is not known.

---

## Bundled roots

When you want a **fixed, offline** public-root set — reproducible across machines, independent of
whatever the host trusts — use `TlsLib.Trust.Bundle` instead of (or alongside) the OS harvest:

```pascal
uses TlpBundleTrust;
LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(
    TBundleTrust.FromPemFile(Pkix, 'roots.pem')).Build)
  .Build;
```

---

## Packaging

The core `TlsLib4PascalPackage` requires **none** of this — verify it never lists a trust package in
its `requires` / `RequiredPkgs`. To use OS trust, add the optional package to your project:

- **FPC (Lazarus):** add `TlsLib.Trust.System` (and/or `TlsLib.Trust.Bundle`) as a required package.
- **Delphi:** add `TlsLib.Trust.System.dpk` (and/or `TlsLib.Trust.Bundle.dpk`) to your requires.

The adapters that support system trust already declare the dependency, so if you use an adapter you
get it transitively.
