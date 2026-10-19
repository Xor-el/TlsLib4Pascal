# System-trust demo (FMX)

A minimal FMX app that verifies a live HTTPS server chain against the **host OS trust store**
with no manual trust config: an unmodified Indy `TIdHTTP` does a GET with
`SSLOptions.UseSystemTrust := True` (no pinned root, no anchors) and the OS renders the verdict.

The form is platform-neutral, so it doubles as the seed of a single cross-platform system-trust
demo. The project is enabled for Android64, iOS, macOS and Win32; Android64 is the primary target,
where the verdict comes from the Java `X509TrustManager` (roots, revocation, and the app's
network-security-config) reached over JNI.

## Zero-config trust

There is nothing to call. On Android under Delphi the delegate captures the JavaVM itself, so
`UseSystemTrust` just works. The one exception is **Android under FPC**: there you call
`TlsLibAndroidInitTrust(AJavaVM)` once at startup, passing the running JavaVM. This Delphi/FMX project does not need it, which is why the form carries
no platform-specific trust code.

## Files here

| File | Role |
|---|---|
| `SystemTrustDemo.dpr` | Program. Compiles the core, `TlsLib.Trust.System` and the Indy adapter from source via the search path. |
| `SystemTrustDemoFormUnit.pas` / `.fmx` | The form: a URL box, a button and a log. It runs the demo off the UI thread and shows the lines it returns. No platform-specific trust code. |
| `SystemTrustDemoRunner.pas` | Everything the demo does: the OS-verified GET, then the offline OS-delegate checks below; also the OS-and-host-roots cells. |

## Building it (RAD Studio, author side)

This is a **live-device, network-gated demo** - it is deliberately not wired into any automated
gate, and the Android build needs your configured SDK/NDK, so it is built from the IDE, not the
headless build scripts.

1. Open `SystemTrustDemo.dpr` in RAD Studio (10.4 Sydney or later) and add it to a
   project group, or drop the four files into a new **Multi-Device Application -> Blank**.
   The tracked `.dproj` carries no machine-specific SDK/NDK paths; the IDE adds your Android
   SDK/NDK, manifest and deployment config to it locally, and those edits must not be committed.
2. Target platform **Android64**.
3. Add to the project search path (locally, not committed): every subfolder of `TlsLib/src`,
   `TlsLib.Trust.System/src`, `TlsLib.Adapters/Indy/Adapter` (Indy itself ships with Delphi) and the
   source folders of the library's dependencies.
4. In the Android manifest, grant the `INTERNET` permission (Project -> Options -> Uses
   Permissions -> **Internet**). No other permission is required - trust roots are read
   through the framework, never from the filesystem.
5. Deploy to a device/emulator and tap **Verify via OS system trust**.

## What to look for

- Default `https://postman-echo.com/get` -> **PASS**: the public chain verified against the
  device's system roots with zero manual trust config. With no network the GET reports
  `SKIP: network unreachable` instead.
- After the GET, three offline **OS-delegate checks** run, each a `PASS:` line (`FAIL:` is a
  defect): an intermediate supplied only through the trust context completes a leaf-only chain
  over the platform engine (and the same leaf is refused without it, with `unknown_ca` on
  Android); an empty presented chain
  is refused with `bad_certificate` on both roles by the delegate's own guard; and a
  live-revocation source is refused up front where the engine has no network-revocation setting,
  so a live deadline is never silently dropped. The last line reports `INFO:` where the engine
  does fetch live revocation (Windows, Apple); on **Android** it must be `PASS:`, and accepting
  the live source there is a `FAIL:`.
- To prove **network-security-config delegation** (not just static roots), install a private
  CA on the device (Settings -> Security -> user certificate, or an MDM push) and point the
  URL at a host whose leaf chains to it - it is honored because the OS `X509TrustManager`,
  not a bundled root list, renders the verdict.
- Point the URL at a host with an untrusted or self-signed chain -> the verification **fails
  closed** (rejects with `unknown_ca`/`certificate_expired`); rejection reasons are written to
  logcat under the `TlsLib` tag.

## OS and host roots cells

Tap **OS and host roots** to run the OS-and-host-roots cells. Each cell fetches a live site
with the demo's own root passed with the OS roots (the rule is in `docs/system-trust.md`,
"OS and host roots") and prints `PASS:`, `FAIL:` or `SKIP:` (offline) against what
the cell expects. The log heading names the mode that ran: `Default = Delegate (OS engine)`, and
on Windows and macOS also `Anchors`. Android and iOS have only the Delegate mode.

| Cell | Host root | Expected |
|---|---|---|
| the URL box (default `postman-echo.com`), a public site | an unrelated test root | connects through the OS roots |
| `untrusted-root.badssl.com` | its own root (embedded PEM) | connects |
| `untrusted-root.badssl.com` | none | refused |
| `expired.badssl.com` | the badssl root | refused (expiry is final) |
| `wrong.host.badssl.com` | the badssl root | refused (name is final) |
| `self-signed.badssl.com` | an unrelated test root | refused (on Android with the network-security-config wired, refused by domain scope before the host roots run) |
| `letsencrypt.org` (Android only, wrong network-security-config pin) | ISRG Root X1, the OS root it chains to | refused |
| `self-signed.badssl.com` (Android only, listed in the network-security-config) | its own certificate | refused (host roots do not apply to a host a `<domain-config>` names) |

On a phone, a `FAIL:` on the second cell means the host root was not trusted with the OS roots;
a `FAIL:` on any refused cell means a final failure (expiry, name, untrusted, pin, or a domain-configured host) was rescued.
The `letsencrypt.org` cell passes the same root the site already chains to, so the host root would
accept it if the pin failure were not final. Both network-security-config cells print `SKIP:` off
Android. To check that the `self-signed.badssl.com` host-root cell discriminates, run it once with the
network-security-config removed (`-Remove` below): it should then connect.

### Wiring the network-security-config cells (Android, local project files)

`res/xml/network_security_config.xml` pins `letsencrypt.org` to a key that matches nothing and lists
`self-signed.badssl.com` with no pins or anchors; it names no other domain and has no base config.
Wire it in locally with the script (the `.deployproj` and the manifest template are not committed):

```
powershell -File scripts\maintenance\sync-trust-demo-nsc.ps1
```

It writes `SystemTrustDemo.NetworkSecurity.deployproj` (imported by `SystemTrustDemo.dproj`) and adds
`android:networkSecurityConfig` to `AndroidManifest.template.xml`. If the template is absent, build the
demo for Android once so the IDE creates it, then re-run. Re-run after the IDE regenerates the
template. `-Remove` undoes it.

### Android CT refuses host roots (Android 16+)

To reproduce, add `<base-config><certificateTransparency enabled="true"/></base-config>` to
`res/xml/network_security_config.xml`, rebuild, and run the OS and host roots cells: the
`untrusted-root.badssl.com` cell with its own root is refused (alert 48) because the private-root chain
carries no SCTs. Remove the element again afterwards.

### User-installed CA is not trusted

On Android the cells end with a `MANUAL:` procedure. Install the `untrusted-root.badssl.com` root
(Settings -> Security -> Encryption & credentials -> Install a certificate -> CA certificate; a screen
lock is required), then run the cells again: the `no host root` cell must still be refused, because
apps targeting API 24 and later do not trust user CAs without a network-security-config opt-in.
The root is `badssl-untrusted-root.crt` in this folder (sha256
`43194b56f17cd0b72be548b35ae93adb1664e4023d1d7d0957f5bab66a31fe3d`); copy it to the phone. To fetch
it yourself, run `openssl s_client -connect untrusted-root.badssl.com:443 -showcerts` on a PC and
take the last certificate.

## Caveats (shared with the iOS delegate, by design)

- An empty host name skips per-domain NSC/pin lookup (the OS falls back to plain
  `X509TrustManager.checkServerTrusted`); the same host-less path serves the mutual-TLS
  peer-certificate case. See `docs/system-trust.md`.
