# TlsLib4Pascal — documentation

**TlsLib4Pascal docs** · Home · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · [Security model](security-model.md)

TlsLib4Pascal is a fully managed, from-scratch **TLS 1.2 + TLS 1.3** stack for **Delphi** and
**FPC / Lazarus** — no OpenSSL, no platform TLS engine, no external runtime dependency beyond its
sibling Pascal libraries. **Post-quantum hybrid key exchange (X25519MLKEM768) is on by default.**
Certificate path validation, the cryptographic primitives, and the CSPRNG come from
CryptoLib4Pascal; TlsLib4Pascal owns the wire protocol, the handshake, and the trust policy.

This folder is the **usage** documentation. Start with *Getting started*, reach for the *Cookbook*
by task, and drop into a deep-dive guide when you need the detail.

## Reading map

| Read this | When |
|---|---|
| **[Getting started](getting-started.md)** | First time here — install, package setup, a working client and server. |
| **[Cookbook](cookbook.md)** | You know roughly what you want and need the recipe ("how do I do mTLS / resumption / ALPN / …"). |
| **[Certificate verification & trust](certificate-verification.md)** | The trust pipeline in depth: private CAs, pinning, live revocation, and the *dangerous* escape hatches. |
| **[OS system trust](system-trust.md)** | Verify against the operating system's own root store, the way a browser does. |
| **[Certificate compression](certificate-compression.md)** | RFC 8879 compression and the cross-connection compression cache. |
| **[Encrypted Client Hello](ech.md)** | RFC 9849 ECH: hide the SNI — offering it as a client, accepting it as a server, key generation, and DNS. |
| **[Security model](security-model.md)** | The invariants, the fail-closed guarantees, and how each is tested — the auditor's map. |
| **[SECURITY.md](../SECURITY.md)** | Reporting a vulnerability + the coordinated-disclosure policy. |
| **Adapter READMEs** (in each package) | Dropping TlsLib4Pascal into [mORMot](../TlsLib.Adapters/mORMot/README.md), [Indy](../TlsLib.Adapters/Indy/README.md), [Synapse](../TlsLib.Adapters/Synapse/README.md), or [fcl-net](../TlsLib.Adapters/FclNet/README.md). |

## Three ways to integrate

Pick the tier that matches how much of the I/O you want to own. All three run the *same* managed
engine — the difference is only who drives the socket.

| Tier | Use it when | Entry point |
|---|---|---|
| **1 — Batteries-included facade** | You just want a config or an engine with safe defaults, fast. | `TTlsLib.NewClientConfig` / `NewServerConfig` (unit `TlpTlsLib`) |
| **2 — `TTlsStream` over your transport** | You own the socket and want a `TStream` that speaks TLS over it. | `TTlsStream` (unit `TlpTlsStream`) over an `ITlsTransport` |
| **3 — Drop-in adapter** | You already use mORMot / Indy / Synapse / fcl-net and want to swap in TLS with one line. | the adapter unit for your stack |
| *(0 — raw sans-IO engine)* | *You drive an async/event framework and want no I/O assumptions at all.* | `ITlsEngine` via `TTlsEngineFactory` |

Most applications want Tier 1 or a Tier 3 adapter. Tier 2 is the clean seam for a custom socket;
Tier 0 is for non-blocking frameworks that pump bytes themselves.

## Choosing a security posture

Presets are **mutable starting points with safe defaults**, not locked profiles — pick the closest
one and override what you need before `Build`. Names describe *posture*, not an era, so their
contents track evolving best practice.

| Preset | Versions | Groups | For |
|---|---|---|---|
| **Compatible** *(default)* | TLS 1.3 + hardened TLS 1.2 | X25519, **X25519MLKEM768**, P-256/384/521 | The broad default. Interops widely; still PQ-hybrid capable and AEAD-only. |
| **Hardened** | TLS 1.3 only | **X25519MLKEM768** (preferred), X25519, P-256 | Modern peers only; post-quantum hybrid preferred. |
| **Strict** | TLS 1.3 only | **X25519MLKEM768**, X25519 only | Locked-down posture: constant-time group allowlist, tight certificate limits, resumption off. |

```pascal
uses TlpTlsPresets, TlpDefaultCryptoProvider, TlpICryptoProvider;

var P: ICryptoProvider;
begin
  P := TDefaultCryptoProvider.Create as ICryptoProvider;
  LConfig := TTlsPresets.Compatible(P).Client.WithTrustAnchors(caPem).Build;
end;
```

The one thing the library *won't* let you do by accident is ship an unauthenticated client: the
builder **refuses to `Build` a client with no trust source**. Turning verification off is possible,
but only through the loudly-named [`dangerous` surface](certificate-verification.md#4-the-dangerous-escape-hatches).

## What you depend on

The default distribution is **core + the CryptoLib4Pascal provider**. Its only direct dependency is
**CryptoLib4Pascal** (crypto primitives, PKIX path validation, CSPRNG).

Zero other runtime dependencies — literally. Everything else is an **optional package** you add only
if you use it:

| Package | Adds |
|---|---|
| `TlsLib4PascalPackage` | The core library + default provider. **Requires none of the below.** |
| `TlsLib.Trust.System` | OS system-trust harvest + delegate ([system-trust.md](system-trust.md)). |
| `TlsLib.Trust.Bundle` | A PEM/DER CA-bundle loader (`FromPem` / `FromPemFile`). |
| `TlpSocketHttpFetcher` *(unit in `TlsLib.Net/`)* | The reference socket `IHttpFetcher` for live OCSP/CRL — a loose unit, not a package. |
| `TlsLib.Adapter.*` | The mORMot / Indy / Synapse / fcl-net drop-in adapters (package name is singular — `TlsLib.Adapter.mORMot`, `…Indy`, `…Synapse`, `…FclNet`). |

See [Getting started](getting-started.md) for how to add these on Delphi and FPC/Lazarus.

---

*Compiler floor: Delphi 10.4 Sydney+ and FPC 3.2.2+. The library is single-threaded per connection;
config objects are immutable once built and freely shareable across threads.*
