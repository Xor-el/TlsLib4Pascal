# System-trust demo (FMX)

A minimal FMX app that verifies a live HTTPS server chain against the **host OS trust store**
with no manual trust config: an unmodified Indy `TIdHTTP` does a GET with
`SSLOptions.UseSystemTrust := True` (no pinned root, no anchors) and the OS renders the verdict.

The form is platform-neutral, so it doubles as the seed of a single cross-platform system-trust
demo. The project is enabled for Android64, iOS, macOS and Win32; Android64 is the primary target,
where the verdict comes from the Java `X509TrustManager` (roots, revocation, and the app's
network-security-config) reached over JNI.

## Zero-config trust

There is nothing to call. On Android the delegate captures the JavaVM itself from
`System.JavaMachine` when its unit initializes, so `UseSystemTrust` just works. The one exception is **Android under FPC**, which has
no `System.JavaMachine` to auto-resolve - there you call `TlsLibAndroidInitTrust(AJavaVM)` once at
startup, passing the running JavaVM. This Delphi/FMX project does not need it, which is why the form
carries no platform-specific trust code.

## Files here

| File | Role |
|---|---|
| `SystemTrustDemo.dpr` | Program. Compiles the core, `TlsLib.Trust.System` and the Indy adapter from source via the search path. |
| `SystemTrustDemoFormUnit.pas` / `.fmx` | The form: a URL box, a button and a log. It runs the demo off the UI thread and shows the lines it returns. No platform-specific trust code. |
| `SystemTrustDemoRunner.pas` | Everything the demo does: the OS-verified GET, then the offline OS-delegate checks below; also the host-roots cells. |

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
   `TlsLib.Trust.System/src`, and `TlsLib.Adapters/Indy/Adapter` (Indy itself ships with Delphi).
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

## Host roots cells

Tap **Host roots beside OS roots** to run the host-roots cells. Each cell fetches a live site
with the demo's own root passed beside the OS roots (the rule is in `docs/system-trust.md`,
"Host roots beside the OS roots") and prints `PASS:`, `FAIL:` or `SKIP:` (offline) against what
the cell expects. The log heading names the mode that ran: `Default = Delegate (OS engine)`, and
on Windows and macOS also `Anchors`. Android and iOS have only the Delegate mode.

| Cell | Host root | Expected |
|---|---|---|
| the URL box (default `postman-echo.com`), a public site | an unrelated test root | connects through the OS roots |
| `untrusted-root.badssl.com` | its own root (embedded PEM) | connects |
| `untrusted-root.badssl.com` | none | refused |
| `expired.badssl.com` | the badssl root | refused (expiry is final) |
| `wrong.host.badssl.com` | the badssl root | refused (name is final) |
| `self-signed.badssl.com` | an unrelated test root | refused |

On a phone, a `FAIL:` on the second cell means the host root was not trusted beside the OS roots;
a `FAIL:` on any refused cell means a final failure (expiry, name, untrusted) was rescued.

## Caveats (shared with the iOS delegate, by design)

- An empty host name skips per-domain NSC/pin lookup (the OS falls back to plain
  `X509TrustManager.checkServerTrusted`); the same host-less path serves the mutual-TLS
  peer-certificate case. See `docs/system-trust.md`.
