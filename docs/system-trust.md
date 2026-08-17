# OS system trust

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · System trust · [Compression](certificate-compression.md) · [Security model](security-model.md)

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

TlsLib4Pascal does its **own** chain validation (PKIX, expiry, host-name, revocation) with
CryptoLib4Pascal — it does not hand verification off to the OS. "System trust" therefore means
*harvest the OS's trusted root set and feed those roots into our own validator*. On every platform
that can enumerate its store, that is what happens:

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
network-security-config (per-domain trust, user-CA opt-in, pinning) and platform revocation — so
harvesting is banned and we hand the peer chain to the platform verifier via JNI.

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
the anchors used to verify **client** certificates in mutual TLS). An optional third argument,
`TSystemTrustMode` (`Default` / `Anchors` / `Delegate`), forces harvest-vs-delegate; `Default`
picks the best available for the platform and is what you want.

Because system anchors are just another anchor source, they **union** with anything else you add —
so "trust the public web PKI **and** my private CA" is simply:

```pascal
LConfig := TSystemTrust.WithSystemTrust(TTlsPresets.Compatible(P).Client, P)
  .WithTrustAnchors(LoadFile('my-private-ca.pem'))   // unions with the OS roots
  .Build;
```

---

## Composition: union vs. exclusive

The builder distinguishes two kinds of trust contribution:

- **Anchor sources** — `WithTrustAnchors`, `WithTrustStore`, and `TSystemTrust.WithSystemTrust`.
  These are additive: supply several and they **union** into one root set.
- **A whole verifier** — `WithCertificateVerifier` (below). This **replaces** the built-in pipeline
  and is **exclusive**: combining it with any anchor source, or setting two verifiers, is a typed
  error (`EInvalidOperationTlsLibException`) at `Build`.

## System trust is never implicit

Consistent with the library's fail-closed stance, **you must ask for system trust** — it is never a
silent default. A client builder with verification on but no trust source named (no anchors, no
system trust, no verifier) is **refused at `Build`**, not quietly pointed at the OS store. This is
deliberate: an implicit trust source is exactly the kind of thing that weakens security by accident.

---

## Replacing verification wholesale: `WithCertificateVerifier`

Sometimes you want to substitute the entire verification decision — e.g. hand it to an OS verifier
(the iOS/Android delegate), or plug in bespoke logic. That is what `WithCertificateVerifier(ICertificateVerifier)`
is for. It **replaces** the built-in PKIX pipeline for that config:

```pascal
LConfig := TTlsPresets.Compatible(P).Client
  .WithCertificateVerifier(MyVerifier)   // exclusive: no WithTrustAnchors alongside it
  .Build;
```

---

## Through the adapters

Each adapter exposes system trust through *its host library's* idiom, and all three obey the
never-implicit / fail-closed rule.

### Indy

The IO-handler's `SSLOptions` carry a `UseSystemTrust` flag. It unions with a `RootCertFile` bundle
and any `CustomTrustStore`; a `CustomVerifier` replaces the pipeline. Verifying with no source named
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
uses TlpSynapseTls;    // registers the plugin

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
