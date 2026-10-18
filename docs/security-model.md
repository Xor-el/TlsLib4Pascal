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
malformed input. Local side-channel observation (cache/timing) of secret-dependent computation is
the crypto provider's responsibility, not the library's (see Cryptographic posture); the library
itself compares secrets in constant time (invariant 2).

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
| 3 | **Certificate decompression cap (RFC 8879).** Output is capped at the peer's `uncompressed_length`; output exceeding it or a length mismatch aborts `bad_certificate`; the same max message size applies as if uncompressed; memory is bounded during decompression. | decompression / zip bomb | centralized bomb defense in the compression policy layer (declared length capped at the configured `MaxTotalChainLength`, ratio guard `100`, exact-length match) | `ResourceLimitTests` (bomb / decompression ceiling) + the compression policy tests |
| 4 | **Peer key-share / public-key validation.** Incoming key shares are validated before use: NIST-curve points are checked on-curve and non-identity; X25519 is safe by construction (the OS-native crypto overlay additionally reduces a non-canonical X25519 u per RFC 7748 5, and fails closed as a peer-input error on a u the OS module refuses); ML-KEM decapsulation uses constant-time implicit rejection; the hybrid combiner concatenates so no component failure leaks. | invalid-curve / small-subgroup | the KEM-shaped `INamedGroup` seam (`ValidatePeerShare`) | `NamedGroupTests` (incl. hybrid + short-ciphertext rejection) |
| 5 | **AEAD nonce non-reuse + usage limits.** Per-epoch nonces are monotonic and never repeat within a key; on TLS 1.3 a proactive KeyUpdate rekeys before the AES-GCM record limit (~2^24.5); TLS 1.2 has no rekey, so at the limit (23,726,566 records) the engine sends close_notify and raises `ERecordLimitTlsLibException`; the sequence never wraps without a rekey. | catastrophic GCM nonce reuse | `IRecordProtection` (monotonic sequence → nonce) + the AEAD backend's own nonce-reuse rejection (`SAeadSealRejected`; the OS-native crypto overlay checks too) | `RecordProtectionTests`, `ProviderTests` |
| 6 | **DoS / resource limits.** Hard caps on handshake-reassembly size, floods of empty records / warning alerts / KeyUpdate requests, the stateful session store, and the 0-RTT strike register. The reassembly and chain sizes, the session store and the strike register are configurable; the flood caps (consecutive empty records, change_cipher_spec, warning alerts, post-handshake messages) are fixed constants. Secure defaults throughout. A handshake parked on an async verdict buffers inbound under these same caps. | memory exhaustion / infinite-work loops | the record layer + engine bounds; the stateless HRR cookie | record/handshake tests; `TStrikeRegisterAntiReplay` bounds (`Tls13ResumptionTests`) |
| 7 | **Secret hygiene.** All key material — schedule secrets, traffic keys, PSKs, resumption secrets, STEK/ticket keys, the HRR-cookie secret — lives in a heap-stable `ISecretBuffer`, wiped once at end-of-life with a plain `FillChar` over the buffer (`TSecureMemory.Wipe`; there is no extra barrier against the compiler eliding the store). Provider intermediates (round keys, HKDF PRKs, scratch) are wiped too. | key material recovered from freed memory | `TSecretBuffer` (refcounted, single buffer, wiped in its destructor when the last reference is released) | `SecretTests` (`TestWipeOnLastRelease` asserts the buffer is zeroed when its last reference is released) |
| 8 | **Single-threaded per connection.** An engine/connection is single-threaded (caller serializes; no internal locks). Config objects are immutable once built and freely shareable across threads. | accidental data races on connection state | stated contract; frozen config objects | design invariant; config-freeze tests |
| 9 | **Fail-closed authentication.** A client with verification on but no trust source is refused at `Build` (`SNoTrustStore`), and a client with name checking on but no usable host is refused when the engine is created — never a silent RFC 9525 skip (disable it only via `WithDangerousDisableServerNameCheck`). A certificate whose `extendedKeyUsage` excludes the TLS role — `serverAuth` for a server, `clientAuth` for a client, over the leaf and every intermediate — is rejected as `unsupported_certificate` (required-if-present; `anyExtendedKeyUsage` is not a substitute). Anchors *union* inside one `WebPki` policy; a whole verifier (`Custom`) takes no anchors, intermediates or skip-verify, so nothing it would ignore can be set beside it. A parked verdict with no resolver, or whose resolver raises, fails the handshake — the only pass is an explicit positive verdict. The deadline is a budget handed to the resolver, which must honour it; the library runs no timer. A definitive, authenticated `Revoked` aborts under every revocation posture, including `Off`. Our own certificate chain is never sent when a certificate in it other than a self-issued one is signed with MD5, or with SHA-1 the peer did not advertise (RFC 9846 4.5.1.2; MD5 inferred from 4.5.1.3): a server aborts `handshake_failure`, a client answers without a certificate. | silent-insecure / fail-open trust / wrong-purpose certificate | the config builder guards + the engine factory + the trust pipeline (augment-only) | `CertificateVerifierTests`, `TrustCompositionTests`, `CertificateCheckTests`, `LiveRevocationTests`, `ServerSideLiveRevocationTests`, `ChainAlgorithmPolicyTests` |
| 10 | **Downgrade protection.** The ServerHello.random downgrade sentinel is set/checked and is *cryptographically bound* (via the 1.2 SKE signature and, both versions, the Finished MAC over the transcript); a 1.3-capable client aborts `illegal_parameter` on a spurious downgrade. Server-side `TLS_FALLBACK_SCSV` aborts `inappropriate_fallback`. A server aborts with `protocol_version` when a ClientHello has `supported_versions` and a `legacy_version` other than 0x0303; this includes the ClientHello after a HelloRetryRequest and the ECH outer ClientHello (RFC 9846 4.2.2). | version-downgrade MITM | negotiation prologue + Finished MAC + SCSV | `NegotiationTests`, `Tls12DualVersionTests`, `HelloRetryRequestTests`, `EchClientEngineTests` |
| 11 | **CSPRNG hard-fail.** A randomness failure aborts the operation with a fatal error — never a silent fallback to a weak or zero source. There is no fork detection: after `fork()` the child must not use the parent's provider or any connection it inherited; build a fresh provider in the child. | weak / replayed randomness | the provider's RNG contract | provider RNG tests |

## Authentication & trust — the fail-closed core

The one behavior most worth internalizing: **you cannot ship an unauthenticated client by accident.**
The builder requires an explicit trust source, and turning verification off is gated behind a single,
loudly-named surface (`TServerVerification.DangerousSkip`, name-check off, key logging) that you have to
opt into deliberately. Custom verification **augments** — a `WithCertificateVerifyCallback` can only
*additionally reject*, never rescue a chain the built-in pipeline failed. Two paths replace the
pipeline: a whole `TServerVerification.Custom`, which takes no other trust setting, and a
`TServerVerification.VerifierSource`, whose custom source receives the verify callback only through
its context and must apply it to keep the augment-only rule (the OS delegate does). The async deferred-verdict seam
rides the same augment-only rule and is fail-closed when unresolved. See
[certificate-verification.md](certificate-verification.md) and [system-trust.md](system-trust.md).

`WithDangerousKeyLog` is the one deliberate exception to invariant 7 (secret hygiene): it hands a
sink each connection secret in the SSLKEYLOGFILE format (RFC 9850) so a capture can be decrypted. The
core passes a transient copy it wipes on return; whatever the sink keeps is the host's exposure. It is
off by default, no preset enables it, and every line is keyed by the ClientHello.random (the inner
one when ECH was accepted). For debugging only — never production.

## Cryptographic posture

- **AEAD-only, forward-secret.** No CBC-HMAC, RC4, 3DES, static-RSA/DH, or TLS-level compression —
  designing out BEAST / Lucky13 / POODLE / padding-oracle / CRIME by construction. TLS 1.2 is a
  hardened ECDHE + AEAD profile that offers Extended Master Secret; a TLS 1.2 keying-material
  exporter is available only when the session used EMS (RFC 7627 5.4). A TLS 1.2 server does not
  resume a session established without EMS by default: it declines to a full handshake and issues
  no such session (RFC 7627 5.3). `Tls12.WithNonEmsResumption` can instead abort the handshake
  (the literal SHOULD) or resume it for legacy clients; `WithExtendedMasterSecret(True)` rejects
  every non-EMS client.
- **Opt-in TLS 1.2 pre-shared keys.** Configuring a `TTls12Psk` adds the ECDHE_PSK suites over an AEAD
  (RFC 5489, RFC 7905, RFC 8442); the exchange stays ephemeral, so the posture above holds. Plain PSK
  (no forward secrecy, RFC 4279 7.1), DHE_PSK and CBC variants are not implemented. An identity the
  server does not know proceeds on a stand-in secret and ends like a wrong secret (RFC 4279 2 permits
  this), so a probe cannot enumerate identities; the identity itself is sent in the clear (RFC 4279 7.3).
  A PSK session resumes only while its identity is configured with the same secret.
- **Post-quantum hybrid KEX** (X25519MLKEM768, and SecP256r1MLKEM768 in the Compatible and Hardened
  presets) offered by the presets and preferred under Hardened and Strict. X25519MLKEM768 is
  interop-verified against OpenSSL 3.5+ and BoringSSL; SecP256r1MLKEM768 against OpenSSL where the
  installed build supports it.
- **Resumption.** TLS 1.3 resumes with `psk_dhe_ke` only; `psk_ke` (no forward secrecy) is never
  negotiated. TLS 1.2 resumption (session ID / ticket) reuses the original master secret, so it is
  only as forward-secret as the session store / ticket-key lifetime. Client-cache tickets are single-use; server tickets are single-use with a session
  store. A resumption chain ends seven days after the full handshake that authenticated it, however
  often its tickets are renewed (RFC 9846 4.7.1): a renewal keeps the original authentication time
  and advertises only what is left. A connection ended by a fatal alert, sent or received, drops the
  sessions and stateful tickets it stored (RFC 5246 7.2.2, RFC 9846 6); a stateless ticket cannot
  be recalled. A transport failure (a reset socket) is not a fatal alert and leaves them resumable
  (RFC 5246 7.2.1). A server's ticket lifetime defaults to 7200 s and `WithTicketLifetime` accepts at
  most seven days (604800 s); a client clamps any advertised lifetime to seven days. With resumption
  on and no session store or ticket keys set, `Build` mints a default ticket key (STEK) that rotates on
  that lifetime. **0-RTT is off by default** and, when enabled, is bounded by an anti-replay strategy.
  A server `WithEarlyData` budget must be below 1 MiB and needs resumption; with explicit
  `WithSessionTicketKeys` and no session store it also needs `WithAntiReplay`, and `WithAntiReplay`
  needs a positive budget; with `Tls13.WithTicketCount(0)` it also needs a session store or ticket
  keys. A client `WithEarlyData(True)` needs resumption and a session cache.
- **Path validation** is delegated to the crypto backend's PKIX engine (PKITS-verified in the
  default distribution), run with a bounded path build (at most 4 non-self-issued intermediates,
  chain-size caps); other RFC 5280 behaviour needs a custom `ICertificatePathValidator` injected
  through `TPkixProviderBuilder`.
- **Side-channel / constant-time behavior is the crypto provider's responsibility, not
  TlsLib4Pascal's.** TlsLib4Pascal *selects* the primitives its default preferences and Strict preset
  use; the pluggable `ICryptoProvider` implements them and owns its own side-channel posture.

## Testing & assurance

The correctness/security story is enforced continuously, not once:

- **RFC 8448 byte-exact trace replay** + HKDF / traffic-key known-answer tests
  (`Tls13KeyScheduleTests`, `Tls12KeyScheduleTests`; the RFC 8448 replay traces are in
  `Tls13ClientReplayTests` and `Tls13ServerReplayTests`) — the handshake and key schedule match the RFC
  vectors bit for bit.
- **Structure-aware negative fuzzing** of the pure core (`TlsFuzzer`) — truncated / oversized /
  reordered / duplicated / wrong-context input must produce the exact alert and never crash; this is
  the executable form of the no-over-read invariant.
- **BoGo conformance as a required CI gate** — the BoringSSL external-stack test suite
  (`BoGoShim` + `bogo-classify.py`) runs full-suite-minus-explicit-disables at boundary 0: every test
  PASSes or is disabled-with-a-reason, and any unexpected / regressed / stale-disable result fails CI.
  Plus a capability-gated `openssl s_client`/`s_server` interop matrix, including a version-gated
  X25519MLKEM768 hybrid cell; a cell the installed OpenSSL cannot run is skipped.
- **Regression suite** pinning immunity to the designed-out attacks (downgrade sentinel, no-CBC,
  decompression bomb, invalid-curve, timing).
- **Secret-wipe test** — a secret buffer is asserted to be zeroed when its last reference is
  released.
- **Dual compiler.** The suite builds and runs on both Delphi and FPC.

## Deliberate design decisions an auditor should know

These are intentional and documented — flagging them up front so they aren't mistaken for defects:

- **Single `key_share` model.** The client offers one `key_share` (its most-preferred group), not a
  classical+PQ pair. The observable consequence is an extra HelloRetryRequest when the peer's selected
  group differs — verified to interop (direct and HRR) against OpenSSL 3.5+ / BoringSSL. This is *not*
  BoringSSL's multi-key_share prediction, and the corresponding BoGo cases are disabled by policy.
- **Augment-only custom verification** (vs the rustls/.NET "replace validation" model) — a callback can
  only tighten, never loosen.
- **A cipher list narrows, and a host's list is read by exact name only.** A cipher list
  (`WithCipherSuiteList`, which takes wire codes, or a framework adapter's `CipherList` / `Ciphers`
  property, which takes suite names) can reorder and drop suites from the hardened set but never add
  one. A host's string is read exactly: OpenSSL-style expressions (`HIGH`, `ALL`, `!aNULL`, `+RSA`)
  and unimplemented suites are refused rather than skipped, so a list never quietly means something
  other than what the host wrote. An OpenSSL cipher list never governed TLS 1.3, so a
  list naming no TLS 1.3 suite leaves 1.3 on with its default suites. A list naming only suites of
  a version the config does not offer is refused at `Build` as dead.
- **No process-global mutable configuration in the core.** All behavior lives in immutable,
  per-connection config objects; there is no ambient process-wide default to install (a footgun for
  a security library). The framework adapters expose a few process-wide setters (for example the
  mORMot handshake timeout).
- **Strict PKCS#1 DigestInfo.** Every RSASSA-PKCS1-v1_5 verification (certificate, CRL and OCSP
  signatures, and TLS 1.2 handshake signatures) re-encodes the DigestInfo with its NULL parameters and
  compares it exactly (RFC 8017 8.2.2, 9.2 and B.1). The optional OS-native crypto overlay,
  which only verifies handshake signatures, does the same: it names no hash OID and hands the OS the one
  DigestInfo of RFC 8017 9.2 Note 1, so a DigestInfo without the NULL does not verify there either. The
  portable path is always strict as well. One path is outside this: OS
  trust delegate mode (the Default mode of OS trust on Windows, macOS, iOS and Android), where the chain and any
  revocation data the OS fetches are judged by the platform.
- **One PKCS#12 credential policy.** One piece of code decides, for every backend, that a store
  holds exactly one private key, which certificate is its leaf and which follow it as the chain;
  the backends only read the store. The OS-native overlay has the OS unwrap the store where it
  can (password derivation, integrity check, decryption), so the private key never enters the
  portable backend's memory, and sends a store it cannot unwrap or serve to the portable backend,
  which owns the errors. An OS backend may read legacy encryption profiles (for example RC2 or
  3DES) that the portable backend rejects. Not every OS reports a second key that matches no
  certificate or separate key bags that hold the same key, so an OS backend can accept a store
  the portable backend rejects.
- **The managed engine is always ours.** Native OS/JVM TLS stacks are never the handshake/record
  engine (a deliberate one-behavior / one-test-corpus stance); OS *trust* (opt-in; its Default
  mode is the OS's own verifier on Windows, macOS, iOS and Android) and the opt-in OS-native crypto
  overlay (`TlsLib.Crypto.System`) are the only sanctioned OS touches.

## Reporting

Found something? See **[SECURITY.md](../SECURITY.md)** — report privately, never in a public issue.
