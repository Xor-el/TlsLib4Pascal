# FIPS and CNSA policy

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · Compliance · [Security model](security-model.md)

The optional `TlsLib.Compliance` package is a policy over the OS cryptographic module. It sends
every TLS crypto operation to that module and refuses anything else: an algorithm outside the rules,
an operation the module does not serve, a config that weakens the rules. It adds no cryptography of
its own and the core does not depend on it.

The samples build a crypto provider from `TDefaultCryptoProvider.Create as ICryptoProvider` and
a PKIX provider from `TDefaultPkixProvider.Create as IPkixProvider`.

---

## What is claimed

TlsLib is not a validated cryptographic module and claims no CMVP validation. On Windows 11 22H2
(build 22621) and Windows Server 2022 (build 20348), its primitives run in Microsoft's Cryptographic
Primitives Library (`bcryptprimitives.dll`), CMVP certificate #5410, FIPS 140-3 Level 1, validated
2026-08-31, sunset 2031-08-30. Other builds, including 23H2, 24H2, 25H2 and Server 2025, are not
covered; strict mode refuses them. A platform with no validated-module table is refused the same
way.

The TLS 1.2 and TLS 1.3 key derivations are composed outside the module; every HMAC runs in-module.
TLS 1.2 is allowed only with Extended Master Secret (RFC 7627).

The `Fips140_3` preset refuses every ML-KEM and PQ/T hybrid group (including
SecP256r1MLKEM768): the OS module (CMVP #5410) has no validated ML-KEM, and current CMVP
guidance (IG D.S Scenario 2) approves hybrids only when ML-KEM runs inside a validated module, so
hybrids will be added once such a module is available.

---

## Use it

```pascal
uses TlpDefaultCryptoProvider, TlpDefaultPkixProvider, TlpICryptoProvider, TlpIPkixProvider,
  TlpOSCryptoProvider, TlpTlsCredential, TlpITlsConfig, TlpComplianceTypes, TlpCompliancePresets,
  TlpICompliancePolicy, TlpCompliancePolicy, TlpOSModuleAttestation, TlpOSSystemTrust,
  TlpComplianceTls;

var
  Policy: ICompliancePolicy;
  Client: ITlsClientConfig;
  Server: ITlsServerConfig;
begin
  Policy := TCompliancePolicy.Create(TCompliancePresets.Cnsa1,
    TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider),
    TDefaultPkixProvider.Create as IPkixProvider, TOSModuleAttestation.Current,
    TComplianceEnforcement.Strict);          // raises on a build the table does not validate
  WriteLn(Policy.PlatformReport.Describe);
  Client := TComplianceTls.BuildClient(Policy,
    TComplianceTls.Client(Policy, TSystemTrustRoots.OsRoots));
  Server := TComplianceTls.BuildServer(Policy, TComplianceTls.Server(Policy,
    TTlsCredential.Load(Policy.Crypto, Policy.Pkix, ChainPem, KeyPem)));   // load through Policy
end;
```

`TComplianceTls` seeds a config builder with the policy's providers and allowlists, the OS
verifier, and the Extended Master Secret requirement. `BuildClient` and `BuildServer` freeze the
config and pass it to `Admit`. A config built any other way can still be checked with
`Policy.Evaluate` or `Policy.Admit`; one that skips both loses the non-crypto checks below.

- `Client(Policy, Roots)` verifies the server through the OS verifier and raises where the platform
  has none; `Roots` is a `TSystemTrustRoots`: `OsRoots`, `OsAndHostRoots(Store)` or
  `HostRoots(Store)`.
- `Client(Policy, Verification)` takes your own `IServerVerificationBuilder`; the strength floors of
  the rules are applied to it.
- `Client(Policy, Roots, Posture, DeadlineMs)` uses the OS verifier with live revocation; run it
  with the OS live-revocation resolver (see [system-trust.md](system-trust.md)).
- `Server(Policy, Credential)` narrows the credential key to the schemes of the rules. Session
  resumption stays on only where the rules allow AES-256-GCM, which seals the tickets, under the
  policy's scope and ticket keys ([Resumption state](#resumption-state)). For mutual
  TLS add `WithPeerAuth` and a client verification from the OS source, with
  `WithMinimumStrength(Policy.Rules.Strength)`.
- `Server(Policy, Resolver)` selects the credential per handshake through your
  `ITlsServerCredentialResolver`, wrapped by `Policy.CheckedCredentialResolver` (below).

### A private CA

A private CA does not need to be installed in the OS store. Pass it with the roots:

```pascal
Client := TComplianceTls.BuildClient(Policy, TComplianceTls.Client(Policy,
  TSystemTrustRoots.OsAndHostRoots(Store)));   // the OS roots and Store
Client := TComplianceTls.BuildClient(Policy, TComplianceTls.Client(Policy,
  TSystemTrustRoots.HostRoots(Store)));        // Store alone; the OS roots never vouch
```

`Store` is an `ITrustAnchorStore` holding the CA certificates. The chain is still verified by the
OS verifier, so strict mode accepts both.

### Checking credentials chosen at run time

```pascal
Server := TComplianceTls.BuildServer(Policy, TComplianceTls.Server(Policy, MyResolver));
```

`Policy.CheckedCredentialResolver(MyResolver)` returns a resolver that asks yours and then refuses
(`TryResolve` answers `False`, which aborts the handshake) any credential the policy does not
tolerate, narrowing the key it admits to the schemes of the rules. Strict mode refuses on any
finding, relaxed mode on a configuration finding. It reads the chosen credential's certificate on
every handshake. A refusal reaches the client as `unrecognized_name` (SNI) or `handshake_failure`
and the host gets no reason, so run `Policy.EvaluateCredential(Credential)` over your credentials at
startup. It judges the credential as given and never raises; the wrapper judges it after narrowing
the key, so a key with extra schemes is a finding in the report and admitted by the wrapper.

---

## Presets and rules

A policy runs a `TComplianceRules` record: versions, cipher suites, AEADs, named groups, signature
schemes, certificate strength floors, requirements, and the key-derivation rule.

| Preset | Versions | Suites | Groups | Certificates |
|---|---|---|---|---|
| `Fips140_3` | TLS 1.3, 1.2 | AES-GCM (128 and 256) with ECDSA or RSA | secp256r1, secp384r1, secp521r1 | RSA 2048, 3072 or 4096, ECDSA P-256/384/521, no EdDSA |
| `Cnsa1` | TLS 1.3, 1.2 | AES-256-GCM with SHA-384 | secp384r1 | RSA 3072 or 4096, ECDSA P-384 |

Both presets require extended master secret and refuse early data, Encrypted Client Hello, PSKs,
key logging and verification bypasses, and require chains to be verified by the OS verifier.
`Cnsa1` follows RFC 9151 without `rsa_pss_pss_sha384`, which the core does not model, and is a
subset of `Fips140_3`.

`TComplianceRules.Intersect(A, B)` only ever narrows: it keeps what both allow, takes the stricter
strength floors and the union of the requirements, and raises when no curve or RSA size is shared.
The exact RSA sizes (`RsaModulusBits`: 2048, 3072 and 4096 for `Fips140_3`; 3072 and 4096 for
`Cnsa1`, the sizes the module's validation covers) apply to the policy's own credentials. A peer
chain is held to the size range of `Strength` only, and the report says so.
A report is `Compliant` only when the rules are a subset of a named preset
(`TCompliancePresets.TryMatch`), the module is validated and nothing was found, so rules built by
hand that add an algorithm to a preset are never compliant.
Rules no config can run raise `EArgumentTlsLibException` in both modes.

---

## Strict and relaxed

| Finding category | Construction, strict | Construction, relaxed | Admit, strict | Admit, relaxed | Evaluate |
|---|---|---|---|---|---|
| Rules (outside every preset) | raises | reported | raises | reported | reported |
| Platform (module, backends, chain or credential outside the module) | raises | reported | raises | reported | reported |
| Configuration (allowlists, flags, provider identity) | not checked | not checked | raises | raises | reported |

- `Evaluate` never raises for a finding. `Admit` evaluates and then raises
  `EComplianceUnmetTlsLibException` carrying the findings.
- Relaxed is never silent: its report is `NotCompliant` while any finding stands. Relaxed passes
  platform facts through (a portable chain check, a portable key) and keeps every allowlist.
- A refusal inside a handshake ends it with a fatal `internal_error` (RFC 9846 6.2).

---

## What Admit checks

Provider identity, versions, cipher suites, named groups and preferred groups, signature schemes,
Extended Master Secret when TLS 1.2 is offered, early data, Encrypted Client Hello (GREASE counts),
external and TLS 1.2 PSKs, key logging, verification bypass, and the certificate strength floors
(clients, and servers that request a client certificate). A client's chain must be verified by the
OS verifier, and so must a server's client chain.

- **Verifier source.** Only a client that can end in a certificate, and a server that requests a
  client certificate, are examined. The source is judged by its class, not by a marker interface,
  which any host class can list. The OS verifier source is in the module and gives no finding. The
  built-in verifier is portable PKIX, a platform fact: `ChainVerifiedOutsideModule`. Anything else
  (an instance verifier, a host source, a host class that lists `ISystemVerifierSource`) is
  `CustomVerifierConfigured`, a configuration finding that Admit refuses in both modes; use the OS
  verifier source.

- **Named groups.** A group carries the key-agreement provider it was built over, so a code in the
  rules is not enough: every group in the config, and every preferred group the config resolves,
  must be an object of `Policy.NamedGroups`. Any other group is `ForeignNamedGroup`, even one built
  over the policy's crypto provider. The facade already uses them; to change the set, start from
  `Policy.NamedGroups.ToBuilder` and prune.
- **Cipher suites.** A suite must be the catalog definition of its code, so a hand-built record
  that reuses an allowed code with another hash, AEAD or key length is `CipherSuiteNotAllowed`.
- **Credentials.** For every server credential (the default and each server-name entry) and a
  client's own, Admit checks the key size and curve against the floors, that the key can sign with
  no scheme outside the rules, and that the module serves the key. A key that can sign with a
  scheme the rules do not allow is a finding that names the extras; credentials loaded through the
  policy's crypto provider are already narrowed.
- **Resolver.** Only the library's own SNI resolver (`TSniCredentialResolver`, immutable) is
  enumerated at build time. Any other resolver, even one that lists its credentials
  (`ITlsServerCredentialSet`) or claims to be checked (`IComplianceCredentialResolver`), cannot be
  inspected: `CredentialResolverUnchecked` is a configuration finding. Wrap it with
  `Policy.CheckedCredentialResolver`, or use `Server(Policy, Resolver)`; the wrapper's check at
  each handshake is the enforcement. A wrapper made by another policy instance is not trusted.
  When the wrapped resolver is the library's SNI resolver, Admit checks its entries too, so a weak
  static entry fails the build. Each finding names its credential by place and common name, such
  as `credential 2 (CN=host)`.
- **Markers.** `ISystemSigningKey` and `ISystemSignatureVerifier` are not trusted on their own: on
  Windows the backend report confirms the class of the key or verifier, so a host class that lists
  them is reported as portable.
- **Session tickets.** A server that issues tickets from ticket keys without AES-256-GCM among the
  allowed AEADs is `TicketAeadNotAllowed`; the facade turns resumption off for such rules. A server
  with a session store and no ticket keys seals nothing and a client never does, so neither gets
  the finding. Where the ticket keys and the resumption scope come from is judged separately: see
  [Resumption state](#resumption-state).
- **Server name.** A client with the server-name check disabled is `DangerousTrustConfigured` with
  the subject `ServerName`, unless every version it offers must end in a PSK (TLS 1.3 with a
  required external PSK, TLS 1.2 with a required TLS 1.2 PSK). Such a client verifies no chain, so
  the strength floors and revocation posture are not examined for it either.
- **Fleet ticket keys.** Keys installed by the host (`IFleetTicketKeyManager`) are disclosed even
  behind `CheckedTicketKeys`: the policy cannot see how they were generated.

A verification callback is allowed: it can only add rejections. GREASE is allowed: its values are
never negotiated (RFC 8701).

---

## Resumption state

A resumed session skips the handshake, so state minted by a config the policy never admitted must
not resume into one it did. Keys generated in the non-approved mode must not be used in the
approved mode (Security Policy #5410), and a shared store, cache or ticket key would otherwise
carry them across. The policy binds the state to itself:

- `Policy.SessionScope` returns a 32-byte scope: a 16-byte prefix, random per policy instance, then
  16 fresh bytes. A server seals its scope into every ticket and session and requires it on
  resumption; a client keys its cache by it. A store, cache or fleet key shared with a config that
  has another scope never resumes across the two: the engine runs a full handshake.
- `Policy.TicketKeys(Clock, LifetimeSeconds)` mints default ticket keys from the policy crypto
  provider's random generator, rotating on the ticket lifetime.
  `Policy.CheckedTicketKeys(Fleet)` marks a fleet whose keys you install as checked; it stays
  disclosed. Install only keys generated in the approved mode.
- A facade server whose rules allow AES-256-GCM carries both, so it is admitted. The facade client
  holds no cache; add one with the scope, as below.

```pascal
ServerBuilder.WithResumptionScope(Policy.SessionScope)
  .WithSessionTicketKeys(Policy.TicketKeys(TSystemClock.Create as ITlsClock, 7200));  // 7200 s
ClientBuilder.WithSessionCache(Cache).WithResumptionScope(Policy.SessionScope);
```

Findings, both configuration findings that Admit refuses in both modes:

- `ResumptionStateUnchecked`: resumption is on, a client holds a session cache or a server holds a
  session store or ticket keys, and the scope does not start with the policy prefix. Set
  `WithResumptionScope(Policy.SessionScope)` or turn resumption off. A hand-built client cache
  without a scope gets a fresh random one from the builder, which cannot be told from a scope you
  chose, so it is reported although nothing else shares it.
- `TicketKeysUnchecked`: the server ticket keys were not issued by this policy instance. Only the
  wrapper classes of `TicketKeys` and `CheckedTicketKeys` count, judged by class; the builder's
  default keys, a `TStekTicketKeyManager` you create, a marker-listing host class and the keys of
  another policy are all unchecked. Use `Policy.TicketKeys`, or `CheckedTicketKeys` for a fleet.

Keys that rotate on a lifetime other than the config's `TicketLifetimeSeconds` are disclosed. To
turn resumption off on a facade server, also clear what it set:
`WithResumption(False).WithSessionTicketKeys(nil).WithResumptionScope(nil)`; the builder refuses
ticket settings while resumption is off.

Residual: a host that copies a policy scope onto a config the policy never admitted, or reads it
from an admitted config, defeats the separation. That is forgery by code in the process.

---

## HPKE

Encrypted Client Hello is refused by both presets (`NoEch`), so HPKE matters only to rules that
allow it. A base provider whose HPKE is the default composition is rebuilt over the refusing
primitives, so it runs in the module like everything else. A foreign HPKE is wrapped: in relaxed
mode it keeps only the KEMs whose group the rules allow and the AEADs the rules allow (hashes are
not filtered), and in strict mode it refuses everything, because where it runs cannot be known. A
foreign HPKE also produces a platform finding when the rules allow ECH.

---

## Revocation

No OCSP staple is requested, because the OS verifier checks a staple's signature in portable code.
Check revocation through the OS: use `Client(Policy, Roots, Posture, DeadlineMs)` with the OS
live-revocation resolver, or leave the posture at Soft. A host-owned resolver cannot be seen in the
config, so the report discloses it. In strict mode a portable resolver fails closed under the Hard
posture, because the policy's revocation facet answers indeterminate; under Soft it passes. A
posture of Off is disclosed. A server reports these only when it requests client certificates.

---

## Limits

- Skipping `Admit` loses the non-crypto checks.
- Every honest misconfiguration through the public API is found. Deliberate forgery by code in the
  same process, such as fake config or registry objects or a stateful lying registry, is out of
  scope, as in comparable TLS libraries. A marker interface, a resolver that lists credentials or
  a verifier source that claims the OS is not taken at its word: the policy checks the class.
- Chains are verified by the OS verifier. A private CA does not need to be installed in the OS
  store: pass it as `TSystemTrustRoots.OsAndHostRoots(Store)` (trusted with the OS roots) or
  `TSystemTrustRoots.HostRoots(Store)` (trusted alone; the OS roots never vouch). Strict mode has
  no other chain verifier.
- A peer chain is held to the RSA size range, not to the exact sizes of the rules.
- PKCS#12 keys can fall back to portable code, which strict mode refuses; import PEM or DER keys.
- The module table is shipped data and needs an update per Windows release; the sunset date is
  reported, not enforced.
- The legacy FIPS policy flag is read and reported only.
- A base provider with its own HPKE composition is wrapped, not trusted: see HPKE above.
- Ticket keys a host installs and random generators a caller supplies are outside what the policy
  can inspect; a fleet is disclosed. Shared resumption state is kept apart by the policy scope, which
  a host can copy onto a config the policy never admitted.

---

## Reading the report

`Describe` prints the verdict, the matched preset, the module, then one line per finding and per
disclosure. Findings are facts that break the verdict; disclosures bound the claim without
breaking it. The sample is the report of `Evaluate` over a client config.

```
Verdict: NotCompliant (Relaxed)
Preset: Fips140_3
Module: Windows 10.0.19045.n Windows 10 22H2 bcryptprimitives.dll n.n.n.n, status NotValidated
Finding: ModuleNotValidated 10.0.19045.n: Windows 10.0.19045.n: the shipped table records no validated module for this build
Disclosure: the TLS key derivations are composed outside the module over its HMAC
Disclosure: a peer chain is held to the RSA size range, not to the exact sizes of the rules
```
