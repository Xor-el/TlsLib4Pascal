# System-trust demo (Free Pascal, console)

A minimal console app that verifies a live HTTPS server chain against the **host OS trust
store** with no manual trust config: an unmodified `TFPHTTPClient` does a GET with its TLS
carried by the **FclNet adapter**, and the peer is verified against the OS system-trust store: the
OS engine on Windows (crypt32) and macOS (SecTrust), the `/etc/ssl` bundle that TlsLib4Pascal
harvests and validates itself on Unix — no pinned root, no OpenSSL.

This is the **Free Pascal counterpart to the Delphi FMX/Indy trust demo** in
`../Delphi`. They are deliberately separate: the trust *system* is shared (the same
`TlsLib.Trust.System` package renders the anchors/verdict on every platform), only the
**transport/host differs per platform** — `TFPHTTPClient` over the FclNet adapter here, Indy
`TIdHTTP` on FMX/Android there.

## Zero-config trust

There is nothing to call on a desktop OS. The demo runs twice: once with the one-line
`TlsLibFclNetTrustDefaults.UseSystemTrust := True` opt-in, once with a per-connection
`OnGetSocketHandler` that sets `UseSystemTrust := True`; both must PASS. (A GUI
variant on **Android** would additionally need `TlsLibAndroidInitTrust(vm)` once at startup —
see `docs/system-trust.md` — but this console demo targets the desktop.)

## Files here

| File | Role |
|---|---|
| `src/SystemTrustExample.pas` | The neutral `class function Run: Integer` logic (0 PASS / 1 FAIL / 2 SKIP). |
| `SystemTrustDemo.lpr` / `.lpi` | The console program. |

## Building + running

```bash
lazbuild --add-package-link <CryptoLib4Pascal>/CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk
lazbuild --add-package-link TlsLib/src/Packages/FPC/TlsLib4PascalPackage.lpk
lazbuild --add-package-link TlsLib.Trust.System/Packages/FPC/TlsLib.Trust.System.lpk
lazbuild --add-package-link TlsLib.Net/Packages/FPC/TlsLib.Net.lpk
lazbuild --add-package-link TlsLib.Adapters/FclNet/Packages/FPC/TlsLib.Adapter.FclNet.lpk
lazbuild --cpu=x86_64 --os=win64 TlsLib.Trust.System/Examples/Lazarus/SystemTrustDemo.lpi   # use your own --cpu / --os
./TlsLib.Trust.System/Examples/Lazarus/bin/SystemTrustDemo
```

It is a **network-gated demo, not a test gate**: it needs outbound HTTPS and exits 0 (PASS) /
2 (SKIP, offline) / 1 (FAIL).

Pass `host-roots` to run the host-roots cells instead (`./SystemTrustDemo host-roots`); see below.

## What to look for

- `https://postman-echo.com/get` (the `GetUrl` / `Host` constants in `src/SystemTrustExample.pas`)
  → **PASS**: the public chain verified against the machine's system roots with zero manual trust
  config, entirely inside TlsLib4Pascal.
- Edit those constants to point at a host with an untrusted/self-signed chain → verification
  **fails closed** (system trust is never implicit).

## Host roots cells

`SystemTrustDemo host-roots` passes the demo's own root beside the OS roots (the rule is in
`docs/system-trust.md`, "Host roots beside the OS roots") and prints one `PASS:` / `FAIL:` /
`SKIP:` line per cell, per mode. The modes are `Default` and, where `Default` is the OS engine
(Windows, macOS), `Anchors`. Exit code 0 / 1 / 2 as above.

| Cell | Host root | Expected |
|---|---|---|
| `postman-echo.com`, a public site | an unrelated test root | connects through the OS roots |
| `untrusted-root.badssl.com` | its own root (embedded PEM) | connects |
| `untrusted-root.badssl.com` | none | refused |
| `expired.badssl.com` | the badssl root | refused (expiry is final) |
| `wrong.host.badssl.com` | the badssl root | refused (name is final) |
| `self-signed.badssl.com` | an unrelated test root | refused |
