# Security model

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · Security model

This document is the map of what TlsLib4Pascal defends against, **where each defense is enforced, and
how it is tested.** It serves two audiences: users deciding how much to trust the library, and
security reviewers / auditors who want the invariant → enforcement → evidence chain without
reconstructing it from the source.

> See [SECURITY.md](../SECURITY.md) for how to report a vulnerability.

## Design philosophy

Three principles shape everything below.

1. **Invariant-driven, not incidental.** The classic TLS vulnerability classes — buffer over-read,
   timing oracles, decompression bombs, invalid-curve points, AEAD nonce reuse, resource exhaustion —
   are closed by **stated, tested invariants**, not left implicit. Each has a hard contract asserted
   by the test/fuzz suite.
2. **Fail-closed by default.** The insecure path is never the default and never silent. A client will
   not complete a handshake it cannot verify, and the config builder **refuses to build** a client
   with no trust source. Weakening authentication is possible only through one loudly-named
   *dangerous* surface.
3. **Measured, not asserted.** TlsLib4Pascal's own guarantees are backed by executable evidence, not
   claims — the RFC 8448 byte-exact key-schedule vectors, structure-aware fuzzing, and the BoGo
   conformance gate.

## Threat model

TlsLib4Pascal defends the confidentiality, integrity, and authenticity of a TLS 1.2 / 1.3 connection
against a **network attacker** (Dolev–Yao): one who can read, drop, inject, reorder, and replay
records, present forged or malicious certificates, and drive the handshake with hostile or
malformed input. It additionally hardens against **local side-channel** observation of the default
provider's secret-dependent computation (cache/timing).

Explicitly **out of the threat model** (documented non-goals): a hostile process with the same memory
(the secret-hygiene invariant targets the managed runtime, not `mlock`/swap/hibernation resistance);
a compromised or malicious swapped-in crypto provider (that provider owns its own side-channel and
correctness posture); and physical/fault attacks beyond the deterministic-hedged-nonce mitigation.

## The invariants

Each row is a hard contract. "Enforced" is where in the design it lives; "Tested by" names the
principal test units (the fuzz + BoGo + KAT suites cross-cover several).

| # | Invariant | Vulnerability class closed | Enforced by | Tested by |
|---|---|---|---|---|
| 1 | **Parser safety — no over-read.** One bounds-checked reader mediates all wire parsing; every length-prefixed field is validated against bytes-remaining *before* the read; sub-structures parse over a bounded sub-slice; trailing bytes are rejected (`decode_error`). No raw pointer indexing into borrowed buffers. | Heartbleed / GnuTLS-length buffer over-read | the single wire reader/codec | `WireCodecTests`, `RecordHeaderTests`, `ExtensionCodecTests`; **structure-aware fuzzing** (`TlsFuzzer`) asserts no crash / no over-read on truncated / oversized / reordered / duplicated / wrong-context input |
| 2 | **Constant-time secret comparison.** Finished `verify_data`, PSK binder, session-ticket MAC/decrypt, HRR-cookie MAC, and AEAD tags use a constant-time compare — never an early-exit `=` on secret-dependent data. | timing oracle / MAC forgery | CT compare helper used at every secret-equality site | key-schedule + handshake + resumption tests (`Tls13KeyScheduleTests`, `Tls12KeyScheduleTests`, `Tls13ResumptionTests`) |
| 3 | **Certificate decompression cap (RFC 8879).** Output is capped at the peer's `uncompressed_length`; output exceeding it or a length mismatch aborts `bad_certificate`; the same max message size applies as if uncompressed; memory is bounded during decompression. | decompression / zip bomb | centralized bomb defense in the compression policy layer (`MaxDecompressedLength = 2^18`, ratio guard `100`, exact-length match) | `CertificateCompressionCacheTests` + the compression policy tests |
| 4 | **Peer key-share / public-key validation.** Incoming key shares are validated before use: NIST-curve points are checked on-curve and non-identity; X25519/X448 are safe by construction; ML-KEM decapsulation uses constant-time implicit rejection; the hybrid combiner concatenates so no component failure leaks. | invalid-curve / small-subgroup | the KEM-shaped `INamedGroup` seam (`ValidatePeerShare`) | `NamedGroupTests` (incl. hybrid + short-ciphertext rejection) |
| 5 | **AEAD nonce non-reuse + usage limits.** Per-epoch nonces are monotonic and never repeat within a key; a proactive KeyUpdate rekeys before the AES-GCM record limit (~2^24.5); the sequence never wraps without a rekey. | catastrophic GCM nonce reuse | `IRecordProtection` (monotonic sequence → nonce) + the provider's `CheckNonceReuse` guard | `RecordProtectionTests`, `ProviderTests` |
| 6 | **DoS / resource limits.** Hard caps on handshake-reassembly size, floods of empty records / warning alerts / KeyUpdate requests, the stateful session store, and the 0-RTT strike register. All configurable; secure defaults. A handshake parked on an async verdict buffers inbound under these same caps. | memory exhaustion / infinite-work loops | the record layer + engine bounds; the stateless HRR cookie | record/handshake tests; `TStrikeRegisterAntiReplay` bounds (`Tls13ResumptionTests`) |
| 7 | **Secret hygiene.** All key material — schedule secrets, traffic keys, PSKs, resumption secrets, STEK/ticket keys, the HRR-cookie secret — lives in a heap-stable `ISecretBuffer`, deterministically wiped once at end-of-life through an anti-dead-store-elimination barrier. Provider intermediates (round keys, HKDF PRKs, scratch) are wiped too. | key material recovered from freed memory | `TSecretBuffer` (refcounted, single buffer, wiped on `_Release`) | `SecretTests`; the **heap-scan teardown test** asserts no key survives a closed connection |
| 8 | **Single-threaded per connection.** An engine/connection is single-threaded (caller serializes; no internal locks). Config objects are immutable once built and freely shareable across threads. | accidental data races on connection state | stated contract; frozen config objects | design invariant; config-freeze tests |
| 9 | **Fail-closed authentication.** A client with verification on but no trust source is refused at `Build` (`SNoTrustStore`). Anchor sources *union*; a whole verifier is *exclusive* (combining it with an anchor source is a typed error at `Build`). A parked certificate verdict that never resolves (or times out) fails the handshake — the only pass is an explicit positive verdict. A definitive, authenticated `Revoked` aborts under every revocation posture, including `Off`. | silent-insecure / fail-open trust | the config builder guards + the trust pipeline (augment-only) | `CertificateVerifierTests`, `TrustCompositionTests`, `CertificateCheckTests`, `LiveRevocationTests` |
| 10 | **Downgrade protection.** The ServerHello.random downgrade sentinel is set/checked and is *cryptographically bound* (via the 1.2 SKE signature and, both versions, the Finished MAC over the transcript); a 1.3-capable client aborts `illegal_parameter` on a spurious downgrade. Server-side `TLS_FALLBACK_SCSV` aborts `inappropriate_fallback`. | version-downgrade MITM | negotiation prologue + Finished MAC + SCSV | `NegotiationTests`, `Tls12DualVersionTests` |
| 11 | **CSPRNG hard-fail + fork safety.** A randomness failure aborts the operation with a fatal error — never a silent fallback to a weak or zero source. The default provider reseeds after a detected `fork()`. | weak / replayed randomness (post-fork nonce reuse) | the provider's RNG contract | provider RNG tests |

## Authentication & trust — the fail-closed core

The one behavior most worth internalizing: **you cannot ship an unauthenticated client by accident.**
The builder requires an explicit trust source, and turning verification off is gated behind a single,
loudly-named surface (`WithDangerousInsecureSkipVerify`, name-check off, key logging) that you have to
opt into deliberately. Custom verification **augments** — a `WithCertificateVerifyCallback` can only
*additionally reject*, never rescue a chain the built-in pipeline failed; only a whole
`WithCertificateVerifier` replaces the pipeline, and it is exclusive. The async deferred-verdict seam
rides the same augment-only rule and is fail-closed on timeout. See
[certificate-verification.md](certificate-verification.md) and [system-trust.md](system-trust.md).

## Cryptographic posture

- **AEAD-only, forward-secret.** No CBC-HMAC, RC4, 3DES, static-RSA/DH, or TLS-level compression —
  designing out BEAST / Lucky13 / POODLE / padding-oracle / CRIME by construction. TLS 1.2 is a
  hardened ECDHE + AEAD + EMS profile.
- **Post-quantum hybrid KEX on by default** (X25519MLKEM768), interop-verified against OpenSSL 3.5+
  and BoringSSL.
- **Forward-secret resumption.** `psk_dhe_ke` only by default; `psk_ke` (no forward secrecy) is
  reachable only through the dangerous surface. Single-use tickets. **0-RTT is off by default** and,
  when enabled, is bounded by an anti-replay strategy.
- **Path validation** is delegated to the crypto backend's PKIX engine (PKITS-verified in the
  default distribution), run under a constrained web-PKI profile by default, with the full RFC 5280
  machinery available on opt-in.
- **Side-channel / constant-time behavior is the crypto provider's responsibility, not
  TlsLib4Pascal's.** TlsLib4Pascal *selects* the primitives its default preferences and Strict preset
  use; the pluggable `ICryptoProvider` implements them and owns its own side-channel posture.

## Testing & assurance

The correctness/security story is enforced continuously, not once:

- **RFC 8448 byte-exact trace replay** + HKDF / traffic-key known-answer tests
  (`Tls13KeyScheduleTests`, `Tls12KeyScheduleTests`) — the handshake and key schedule match the RFC
  vectors bit for bit.
- **Structure-aware negative fuzzing** of the pure core (`TlsFuzzer`) — truncated / oversized /
  reordered / duplicated / wrong-context input must produce the exact alert and never crash; this is
  the executable form of the no-over-read invariant.
- **BoGo conformance as a required CI gate** — the BoringSSL external-stack test suite
  (`BoGoShim` + `bogo-classify.py`) runs full-suite-minus-explicit-disables at boundary 0: every test
  PASSes or is disabled-with-a-reason, and any unexpected / regressed / stale-disable result fails CI.
  Plus an always-on `openssl s_client`/`s_server` interop matrix (including a version-gated
  X25519MLKEM768 hybrid cell).
- **Regression suite** pinning immunity to the designed-out attacks (downgrade sentinel, no-CBC,
  decompression bomb, invalid-curve, timing).
- **Heap-scan teardown test** — after a connection closes, freed buffers are scanned to assert no key
  material survives.
- **Dual compiler.** The suite builds and runs on both Delphi and FPC.

## Deliberate design decisions an auditor should know

These are intentional and documented — flagging them up front so they aren't mistaken for defects:

- **Single `key_share` model.** The client offers one `key_share` (its most-preferred group), not a
  classical+PQ pair. The observable consequence is an extra HelloRetryRequest when the peer's selected
  group differs — verified to interop (direct and HRR) against OpenSSL 3.5+ / BoringSSL. This is *not*
  BoringSSL's multi-key_share prediction, and the corresponding BoGo cases are disabled by policy.
- **Augment-only custom verification** (vs the rustls/.NET "replace validation" model) — a callback can
  only tighten, never loosen.
- **No process-global mutable configuration.** All behavior lives in immutable, per-connection config
  objects; there is no `install_default()`-style ambient global (a footgun for a security library).
- **The managed engine is always ours.** Native OS/JVM TLS stacks are never the handshake/record
  engine (a deliberate one-behavior / one-test-corpus stance); OS *trust* is the only sanctioned OS
  touch, and it is opt-in.

## Reporting

Found something? See **[SECURITY.md](../SECURITY.md)** — report privately, never in a public issue.
