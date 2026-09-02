# Security policy

TlsLib4Pascal is a TLS library — a security-critical component. We take vulnerability reports
seriously and are grateful to researchers who report them responsibly.

## Supported versions

`master` is the actively maintained branch and the source for all releases. Fixes land on `master`
first and ship in the next tagged release, so `master` may already contain a fix that hasn't been
released yet — please check against `master` before reporting an issue. Older tagged releases are not
backported to.

## Reporting a vulnerability

**Please report security vulnerabilities privately — do not open a public issue, pull request, or
discussion for a suspected vulnerability.**

Preferred channel: **GitHub private vulnerability reporting.** On this repository, go to the
**Security** tab → **Report a vulnerability**.

A good report includes:

- the affected component (e.g. record layer, handshake state machine, key schedule, trust pipeline,
  the default crypto provider's *usage*, or a specific adapter) and version or commit;
- a clear description of the issue and its security impact (what an attacker can achieve);
- a minimal reproduction — a test case, a packet capture, a shim/BoGo case, or a short program — and
  the affected toolchain (Delphi or FreePascal, version, OS, architecture) where relevant;
- any suggested remediation, if you have one.

You do not need a working exploit — a credible analysis of a broken invariant is enough.

## What to expect

This is a solo-maintained open-source project, so responses are best-effort rather than covered by a
formal SLA. In general you can expect:

- **Acknowledgement** of your report, typically within a few days.
- An initial **assessment** (is it a vulnerability, likely severity, affected versions) once it's
  been reviewed.
- **Coordinated disclosure.** We aim to develop and release a fix before public disclosure, and to
  coordinate timing with you. Our default embargo target is **90 days** from the initial report,
  shorter for issues under active exploitation and extendable by mutual agreement for complex fixes.
- **Credit** in the release notes, if you'd like it. Let us know if you'd prefer to remain anonymous.

## Scope

**In scope** — vulnerabilities in the managed TLS stack this repository ships:

- the sans-IO engine, record layer, and handshake state machines (all four graphs);
- the key schedule and record protection (nonce handling, key derivation, transcript);
- the certificate/trust pipeline (path validation orchestration, endpoint identity, revocation,
  pinning, the deferred-verdict seam) and the trust packages (`TlsLib.Trust.System` /
  `TlsLib.Trust.Bundle`);
- the default provider's **wiring and usage** of CryptoLib4Pascal (e.g. a nonce-reuse or
  parameter-validation mistake in how TlsLib4Pascal drives the primitives);
- the extension framework, negotiation policy, and the session/resumption/0-RTT machinery;
- the first-party integration adapters (mORMot, Indy, Synapse, fcl-net).

Examples of the kind of thing we most want to hear about: authentication bypass or a fail-open trust
path; a parser over-read or memory-safety issue; an AEAD nonce reuse or key-schedule error; a
downgrade that isn't detected; a timing/side-channel oracle on secret-dependent data; a DoS with an
unbounded resource; secret material surviving in freed memory.

**Out of scope / report elsewhere:**

- **Cryptographic primitive flaws** (the AEADs, hashes, KEMs, signature schemes, PKIX path building,
  the CSPRNG themselves) live in [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal) —
  please report those to that project. A *misuse* of a correct primitive by TlsLib4Pascal is in scope
  here.
- **Deliberately-insecure configuration** via the loudly-named *dangerous* surface
  (`WithDangerousInsecureSkipVerify`, disabling the name check, key logging) working as documented is
  not a vulnerability — that is opt-in, fail-loud behavior. A way to reach an insecure state *without*
  the dangerous surface is in scope.
- Third-party host frameworks themselves (mORMot / Indy / Synapse / the FCL) — report framework bugs
  upstream; report the *adapter's* handling of them here.
- Missing hardening that is a documented non-goal or roadmap item (e.g. `mlock`/swap resistance — see
  the secret-hygiene scope note in the security model).
- General bugs, incorrect documentation, or feature requests with no security impact — please use the
  normal [issue tracker](https://github.com/Xor-el/TlsLib4Pascal/issues) for those.

## Learn more

The [security model](docs/security-model.md) documents the invariants this library is built on, where
each is enforced, and how it is tested — useful context for a report, and the map an auditor would
start from.
