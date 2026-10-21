# FIPS and CNSA policy

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · Compliance · [Security model](security-model.md)

The optional `TlsLib.Compliance` package is a policy over the OS cryptographic module. In strict
mode it refuses a negotiated algorithm the module does not serve, and in both modes one the rules
do not allow. It checks a config against the rules at `Admit`. Hashes and HMACs are checked against
the module, not the rules, and a few internal SHA-256 uses are disclosed (see
[What Admit checks](#what-admit-checks)). It adds no cryptography of its own and the core does not
depend on it.

The samples build a crypto provider from `TDefaultCryptoProvider.Create as ICryptoProvider` and
a PKIX provider from `TDefaultPkixProvider.Create as IPkixProvider`.

---

## What is claimed

TlsLib is not a validated cryptographic module and claims no CMVP validation. Under a strict policy
on Windows 11 22H2 (build 22621) and Windows Server 2022 (build 20348), the primitives it admits run
in Microsoft's Cryptographic Primitives Library (`bcryptprimitives.dll`), CMVP certificate #5410,
FIPS 140-3 Level 1, validated 2026-08-31, sunset 2031-08-30. The certificate number and the dates
come from the CMVP listing; the builds and the module versions from the module's Security Policy.
Every other build is not covered; strict mode refuses it. A platform with no validated-module table
is refused the same way.

| Release | Build | Product type | Module version listed |
| --- | --- | --- | --- |
| Windows 11 22H2 | 22621 | workstation | 10.0.22621.30001 |
| Windows Server 2022 | 20348 | server or domain controller | 10.0.20348.30000 |

### The verdict

A report has one of three verdicts, printed by name in `Describe`:

- `NotCompliant`: a finding stands, the module is not `Validated`, or the rules fit no preset.
- `PrimitivesInModule`: the module is `Validated`, nothing was found, and every negotiated
  primitive (random generator, hash, HMAC, AEAD, key agreement, signatures) is a service of the
  module, but a key-schedule derivation the configuration can run is composed outside it.
- `Compliant`: additionally, every key-schedule derivation the configuration can run is a module
  service, with the GCM disclosure below attached, and the exporter disclosure when TLS 1.2 is
  offered.

A key-schedule derivation counts when an offered version runs it: TLS 1.3 derives with HKDF and
TLS 1.2 with its PRF. The Windows module serves the TLS 1.2 PRF. It lists an SP 800-56C HKDF
(shared-secret input) but no TLS 1.3 key-schedule KDF, so the library composes HKDF over the module
HMAC. A derivation that runs in portable code is outside the module too. So rules or a config that
offer TLS 1.2 alone can be `Compliant`, and any that offer TLS 1.3 reach `PrimitivesInModule` at
most. `IComplianceReport.KeyDerivationInModule` says whether any runs outside, and a disclosure names
each that does (the TLS 1.3 HKDF, the TLS 1.2 PRF). The rules'
`Kdf` field decides what a composed derivation does: `AllowComposed` (both presets) caps the
verdict, `RequireModule` makes it a `KdfOutsideModule` finding, which strict mode refuses. A report
of `Evaluate` or `Admit` is judged by the versions and cipher suites of that config;
`PlatformReport` by those of the rules.

A TLS 1.2 exporter derivation (RFC 5705) is not a key-schedule derivation. It is composed over the
module HMAC, so every report whose offered versions include TLS 1.2 carries a disclosure saying
that only the key-schedule derivations are module services. A strict policy whose `Kdf` is
`RequireModule` refuses an exporter label instead, and its report discloses the refusal; relaxed
mode and `AllowComposed` allow it.

### The GCM nonce

The Security Policy (section 2.7.1) states: "The counter portion of the IV must be set by the
module within its cryptographic boundary". The library builds the counter, not the module. For TLS
1.2 the explicit nonce is the record sequence number (RFC 5288), and for TLS 1.3 the write IV is
XORed with the sequence number (RFC 8446 section 5.3); the module receives the finished IV. It
offers no interface to generate or check the counter (IG C.H scenario 1(a)). Counter exhaustion
forces a key update or a close, and keys are ephemeral per session.

Every report whose rules list a GCM suite, which both presets do, carries a disclosure that says
this. It leaves the verdict alone: `Compliant` means every primitive and every key-schedule
derivation is a module service, with that disclosure attached.

### The module

The status is *Validated* only when all of these hold; any mismatch is *NotValidated* and the report
names the first one, and a fact the OS cannot supply makes it *Unknown*, which strict mode refuses:

- the OS is Windows NT 10.0 and its build is a row of the table, with that row's product type;
- the process is a native 64-bit x64 process: the tested environments are 64-bit only, and the
  policy treats the 32-bit module (the Security Policy names SysWOW64) as not covered, as it does an
  x64 process emulated on ARM64 and Windows on ARM;
- the firmware is UEFI, the only kind the Security Policy lists for x64 computers;
- the module in the process is the system copy, `bcryptprimitives.dll` under the system directory,
  and so are the `bcrypt.dll` and `ncrypt.dll` that call it;
- its file version is `10.0.<OS build>`.

When all hold and the date is after the certificate's sunset date (2031-08-30), the status is
*Historical*, and its reason names the certificate. Strict mode refuses it as it does any other
status but *Validated*; relaxed mode reports it. The date is read once, with the other facts, and a
policy keeps the status it was constructed with. The certificate number is kept and printed only
while the status is *Validated*.

The fourth component of the file version (the update revision) is reported but not gated. When it
differs from the version the certificate lists, the report carries a disclosure, not a finding.

The Security Policy names the editions in scope (Windows 11: Pro, Enterprise, IoT Enterprise,
Education, Home; Server 2022: Standard, Datacenter) and states that editions of one product share
the module, so the edition is reported in the identity and never gated. The policy knows them by
the edition ID the OS reports: `Core` (Home), `Professional`, `Enterprise`, `IoTEnterprise`,
`Education`, `ServerStandard` and `ServerDatacenter`. An edition outside that list for its release
(Windows 11 SE, Server 2022 Azure Edition, Azure Stack HCI) is covered only as a vendor-affirmed
relabel, and the report says so in a disclosure, as it does when the edition could not be read.
The same holds for hardware and virtual machines the Security Policy did not test: on any other
platform the module is vendor-affirmed, without assurance of the minimum strength of generated
keys, and every validated report carries a disclosure saying the hardware and any hypervisor are
not checked. These disclosures come from the attestation, so one a host supplies carries only what
it supplies.

The facts are read once when the attestation is created. They come from the OS version query, the
process, the firmware kind, the clock and the module file on disk, not from the image in memory.
Residuals: a compatibility layer can only make the build look older, which fails closed; code in
the process that alters what these queries return, or replaces the module in memory, is out of
scope; and a compatibility runtime such as Wine reports Windows facts it does not implement.

The attestation also says whether the crypto provider is the OS composition it describes. A
provider it does not cover is reported as `CryptoNotCovered` and counted as wholly outside the
module, so strict mode refuses it. An attestation the host supplies, rather than the library's own,
is disclosed as such. A host class that claims `Validated` and covers any provider is an explicit
act the policy cannot check.

TLS 1.2 is allowed only with Extended Master Secret (RFC 7627).

The `Fips140_3` preset refuses every ML-KEM and PQ/T hybrid group (including
SecP256r1MLKEM768): certificate #5410 covers no ML-KEM, and a hybrid is approved only when its
ML-KEM runs inside a validated module. `Fips140_3` is a policy for using the module, not a claim of
conformance to SP 800-52 Rev. 2.

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
`Policy.Evaluate` or `Policy.Admit`. Key agreement through the group objects and chain verification
through the verifier source are enforced only by `Admit`: they run inside the groups and the source,
not through `Policy.Crypto`, so a config from `Build` without `BuildClient`, `BuildServer` or
`Admit` is not policy-enforced for them.

- `Client(Policy, Roots)` verifies the server through the OS verifier and raises where the platform
  has none; `Roots` is a `TSystemTrustRoots`: `OsRoots`, `OsAndHostRoots(Store)` or
  `HostRoots(Store)`.
- `Client(Policy, Verification)` takes your own `IServerVerificationBuilder`; the strength floors of
  the rules, trust anchors included, are applied to it. The builder is changed, not copied, and a
  minimum strength set on it is replaced by the floors of the rules.
- `Client(Policy, Roots, Posture, DeadlineMs)` uses the OS verifier with live revocation; run it
  with the OS live-revocation resolver (see [system-trust.md](system-trust.md)).
- `Server(Policy, Credential)` narrows the credential key to the schemes of the rules. Session
  resumption stays on only where the rules allow AES-256-GCM, which seals the tickets, under the
  policy's scope and ticket keys ([Resumption state](#resumption-state)). For mutual TLS pass the
  server builder through one of the three `WithPeerAuth` overloads below.
- `Server(Policy, Resolver)` selects the credential per handshake through your
  `ITlsServerCredentialResolver`, wrapped by `Policy.CheckedCredentialResolver` (below).
- `WithPeerAuth(Policy, Builder, Mode, ClientCa)` requests a client certificate (`Requested` or
  `Required`) and verifies it through the OS verifier with `ClientCa` as its only root, using
  cached revocation data only. It raises where the platform has no OS client verifier.
- `WithPeerAuth(Policy, Builder, Mode, Verification)` takes your own `IClientVerificationBuilder`;
  the strength floors of the rules, trust anchors included, are applied to it. The builder is
  changed, not copied, and a minimum strength set on it is replaced by the floors of the rules.
- `WithPeerAuth(Policy, Builder, Mode, ClientCa, Posture, DeadlineMs)` is the `ClientCa` overload
  with live revocation; run it with the OS live-revocation resolver (see
  [Mutual TLS](#mutual-tls)).

### A private CA

A private CA does not need to be installed in the OS store. Pass it with the roots:

```pascal
Client := TComplianceTls.BuildClient(Policy, TComplianceTls.Client(Policy,
  TSystemTrustRoots.OsAndHostRoots(Store)));   // the OS roots and Store
Client := TComplianceTls.BuildClient(Policy, TComplianceTls.Client(Policy,
  TSystemTrustRoots.HostRoots(Store)));        // Store alone; the OS roots never vouch
```

`Store` is an `ITrustAnchorStore` holding the CA certificates. The chain is still verified by the
OS verifier, so strict mode accepts both. The keys of the CA certificates are held to the key
floors of the rules.

### Mutual TLS

```pascal
Builder := TComplianceTls.WithPeerAuth(Policy, TComplianceTls.Server(Policy, Credential),
  TClientAuthMode.Required, ClientCa);
Server := TComplianceTls.BuildServer(Policy, Builder);
```

`ClientCa` is an `ITrustAnchorStore` holding the client CA certificates, and it is the only root of
the client chain: the OS roots are never consulted. The strength floors come from the rules, and the
keys of the CA certificates are held to them, so building a server with a CA key below the floors
raises. A later `WithClientVerification` on the builder replaces the verification and drops the
floors, so call the overloads last.

For live revocation use the overload with `Posture` and `DeadlineMs`, then assign the OS resolver
from `TOSSystemTrust.LiveRevocationResolver(ServerConfig, nil)` to the verdict seam (see
[system-trust.md](system-trust.md)). A live-revocation resolver is host-owned and cannot be
inspected, so the report discloses it.

### Checking credentials chosen at run time

```pascal
Server := TComplianceTls.BuildServer(Policy, TComplianceTls.Server(Policy, MyResolver));
```

`Policy.CheckedCredentialResolver(MyResolver)` returns a resolver that asks yours and then refuses
(`TryResolve` answers `False`, which aborts the handshake) any credential the policy does not
tolerate, narrowing the key it admits to the schemes of the rules. Strict mode refuses on any
finding, relaxed mode on a configuration finding. It reads the chosen credential's certificates on
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
key logging and verification bypasses, require chains to be verified by the OS verifier, and hold
the key of a trust anchor to the key floors. `Cnsa1` is a subset of `Fips140_3`. It follows
RFC 9151 with these differences: `rsa_pss_pss_sha384` is not modeled by the core, DHE suites and
`ffdhe` groups are not in the library, and RSA is capped at 4096 bits where the RFC says 3072 or
larger.

Rules must lie within a named preset, in both modes: they may narrow a preset (fewer versions,
suites, groups or schemes, higher floors, `Kdf` of `RequireModule`) and must not widen one or drop
a requirement or the anchor flag. Anything else raises `EArgumentTlsLibException` at construction,
as do rules no config can run, and a suite or group listed twice. The report names the preset the
rules equal (`Cnsa1`) or the tightest one they fit (`within Fips140_3`).

`TComplianceRules.Intersect(A, B)` only ever narrows: it keeps what both allow, takes the stricter
strength floors and the union of the requirements, and raises when no curve or RSA size is shared.
The exact RSA sizes (`RsaModulusBits`: 2048, 3072 and 4096 for `Fips140_3`; 3072 and 4096 for
`Cnsa1`, the sizes the module's validation covers) apply to the policy's own credentials. A peer
chain is held to the size range of `Strength` only, and the report says so.

---

## Strict and relaxed

| Finding category | Construction, strict | Construction, relaxed | Admit, strict | Admit, relaxed | Evaluate |
|---|---|---|---|---|---|
| Platform (module, backends, derivation, chain or credential outside the module) | raises | reported | raises | reported | reported |
| Configuration (allowlists, flags, provider identity) | not checked | not checked | raises | raises | reported |

- `Evaluate` never raises for a finding. `Admit` evaluates and then raises
  `EComplianceUnmetTlsLibException` carrying the findings.
- Relaxed enforces the allowlists, the requirement flags and the configuration findings. The
  platform findings are facts about where the cryptography runs: `KdfOutsideModule` (from the `Kdf`
  field), `ChainVerifiedOutsideModule` and `StapleVerifiedOutsideModule` (from the
  `InModuleChainVerification` requirement), `CredentialKeyOutsideModule` and the others. Relaxed
  reports them and does not refuse portable code.
  Its report is `NotCompliant` while any finding stands, and every relaxed report carries a
  disclosure that relaxed mode does not refuse portable code and that per-connection fallbacks to
  portable code are not reflected in the verdict. Strict reports do not carry it. The rules must lie
  within a preset in both modes.
- A refusal inside a handshake ends it with a fatal `internal_error` (RFC 9846 6.2), except where
  the engine absorbs it (a session ticket that is not issued) and the resolver refusals described
  above, which reach the client as `unrecognized_name` or `handshake_failure`.

---

## What Admit checks

Provider identity, versions, cipher suites, named groups and preferred groups, signature schemes,
Extended Master Secret when TLS 1.2 is offered, early data, Encrypted Client Hello (GREASE counts),
external and TLS 1.2 PSKs, key logging, verification bypass, and the certificate strength floors
(clients, and servers that request a client certificate). A client's chain must be verified by the
OS verifier, and so must a server's client chain.

- **Verifier source.** Only a client that can end in a certificate, and a server that requests a
  client certificate, are examined. The source is judged by its class. The OS verifier source
  is in the module and gives no finding. The built-in verifier is portable PKIX, a platform fact:
  `ChainVerifiedOutsideModule`. Anything else (an instance verifier, a host source, one that
  decorates the OS source) is
  `CustomVerifierConfigured`, a configuration finding that Admit refuses in both modes whatever the
  rules say; use the OS verifier source.
- **Named groups.** A group carries the key-agreement provider it was built over, so a code in the
  rules is not enough: every preferred group the config registry holds, the groups the handshake
  can offer, must be an object of `Policy.NamedGroups`. Any other group with an allowed code is
  `ForeignNamedGroup`, even one built over the policy's crypto provider; a code the rules do not
  list is `NamedGroupNotAllowed`. A group the registry holds that no preferred code names, and a
  preferred code the registry lacks, are never offered and are not judged. The facade already uses
  them; to change the set, start from `Policy.NamedGroups.ToBuilder` and prune.
- **Cipher suites.** A code the rules do not list is `CipherSuiteNotAllowed`. A record that reuses
  a catalog code with a different definition is `CipherSuiteDiffersFromCatalog`; the core builder
  refuses it at Build, so the finding arises only for a config the builder did not produce, or
  whose registry changed after Build.
- **Encrypted Client Hello.** Both presets refuse it, keys and GREASE included: a config that holds
  an ECH client mode, a key store or a backend is `EchConfigured`.
- **Credentials.** For every server credential (the default and each server-name entry, a
  credential listed twice counting once) and a client's own, Admit checks every certificate of the
  chain: its key against the floors, the curves and the exact RSA sizes, and its signature (family
  and hash, RSA-PSS only with canonical parameters, EdDSA only where the rules list its scheme and
  admit EdDSA) against the schemes of the rules. A signature made under an RSASSA-PSS issuer key is
  refused, as no scheme of the rules covers it; the issuer is found in the chain whatever its
  position, and one whose key cannot be read is a finding. The last certificate's signature is not
  judged when it verifies under its own key; a self-issued link that does not, or one before the
  last, is judged. The self-signed test runs on the certificate inspector; one that cannot verify
  the root's self-signature makes the root be judged. It checks that the credential is one the
  config builder accepts (`TTlsCredential.Consistency`), that the key can sign with no scheme
  outside the rules, and that the module serves the key. A certificate chain
  with no key is `CredentialKeyMissing`, a key that is not the leaf's (compared by key value)
  `CredentialKeyMismatch`, and a leaf that forbids digitalSignature, an RSASSA-PSS leaf key or a key
  that cannot export its public half `CredentialKeyUnusable`. A key that can sign
  with a scheme the rules do not allow is a finding that names the extras; credentials loaded
  through the policy's crypto provider are already narrowed.
- **Resolver.** Only the library's own SNI resolver (`TSniCredentialResolver`, immutable) is
  enumerated at build time. Any other resolver, even one that lists its credentials
  (`ITlsServerCredentialSet`) or claims to be checked (`IComplianceCredentialResolver`), cannot be
  inspected: `CredentialResolverUnchecked` is a configuration finding. Wrap it with
  `Policy.CheckedCredentialResolver`, or use `Server(Policy, Resolver)`; the wrapper's check at
  each handshake is the enforcement, and it refuses a credential whose key is not its leaf's. A
  wrapper made by another policy instance is not trusted, even around the SNI resolver. When the
  wrapped resolver is the library's SNI resolver, Admit checks its entries too, so a weak static
  entry fails the build. Each finding names its credential by place and common name, such as
  `credential 2 (CN=host)`.
- **Markers.** `ISystemSigningKey` and `ISystemSignatureVerifier` are not trusted on their own: on
  Windows the backend report confirms the class of the key or verifier, so a host class that lists
  them is reported as portable. A report that does not check classes reports every key and
  verifier as portable.
- **Session tickets.** A server that issues tickets from ticket keys without AES-256-GCM among the
  allowed AEADs is `TicketAeadNotAllowed`; the facade turns resumption off for such rules. A server
  with a session store that offers TLS 1.3 only seals with the store alone, so the ticket keys
  beside it are idle and are not checked. TLS 1.2 always seals its tickets with the ticket keys,
  store or not, so a server that offers TLS 1.2 has its keys checked beside a store; a client never
  seals. Where the ticket keys and the resumption scope come from is judged separately: see
  [Resumption state](#resumption-state).
- **Server name.** A client with the server-name check disabled is `DangerousTrustConfigured` with
  the subject `ServerName`, unless every version it offers must end in a PSK (TLS 1.3 with a
  required external PSK, TLS 1.2 with a required TLS 1.2 PSK). Such a client verifies no chain, so
  the strength floors and revocation posture are not examined for it either.
- **Fleet ticket keys.** Keys installed by the host (`IFleetTicketKeyManager`) are disclosed even
  behind `CheckedTicketKeys`: the policy cannot see how they were generated. So is the fleet scope,
  which the host enters.
- **Internal SHA-256.** The engine hashes a few values nobody negotiates with SHA-256 (the
  HelloRetryRequest cookie, certificate pins, the certificate-compression cache, the config
  fingerprint). The module must serve SHA-256 and HMAC-SHA-256 whatever the rules list, and rules
  without SHA-256 (such as `Cnsa1`) carry a disclosure saying so.

A verification callback is allowed: it can only add rejections. GREASE is allowed: its values are
never negotiated (RFC 8701).

---

## Key derivation

Under a policy, HKDF is always assembled over the policy's own HMAC, so each HMAC it makes passes
the same checks as any other and the native HKDF-Expand of the OS provider never runs; that
shortcut stays available outside a policy. The TLS 1.2 PRF is the module's own where the backend
report says the module serves it and is otherwise assembled over the policy HMAC. In strict mode
either is refused when the HMAC is not the module's. The plain master secret derivation is refused
whenever the rules require Extended Master Secret. A TLS 1.2 label other than the key-schedule
labels (master secret, extended master secret, key expansion, client finished and server finished)
is an exporter derivation: it is composed over the module HMAC and disclosed, and a strict policy
whose `Kdf` is `RequireModule` refuses it and discloses the refusal instead.

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
  provider's random generator, rotating on the ticket lifetime, and returns them as
  `IRotatingTicketKeyManager`. It raises `EArgumentTlsLibException` for a nil clock, a zero
  lifetime, or rules without AES-256-GCM, which seals the tickets. The keys run on the clock you
  pass: a host that gives the builder a clock passes the same one here (the facade uses the system
  clock).
- `Policy.CheckedTicketKeys(Fleet, FleetScope)` marks a fleet whose keys you install as checked;
  it stays disclosed, and so does the scope, which you enter. Install only keys generated in the
  approved mode. Servers of one fleet resume across each other only under one scope, so you give
  the fleet its own (1 to 32 bytes, kept with the keys) and every server holding the wrapper must
  carry exactly that scope: Admit does not accept the policy prefix for them, except for a server
  whose fleet keys are idle beside a store, which accepts either. Rebuilding a fleet with another
  scope drops its outstanding tickets.
- A facade server whose rules allow AES-256-GCM carries a policy scope and policy ticket keys, so
  it is admitted. The facade client holds no cache; add one with the scope, as below.

```pascal
ServerBuilder.WithResumptionScope(Policy.SessionScope)
  .WithSessionTicketKeys(Policy.TicketKeys(TSystemClock.Create as ITlsClock, 7200));  // 7200 s
ClientBuilder.WithSessionCache(Cache).WithResumptionScope(Policy.SessionScope);
// servers sharing a fleet of keys you install: one scope for the fleet, on keys and servers alike
ServerBuilder.WithResumptionScope(FleetScope)
  .WithSessionTicketKeys(Policy.CheckedTicketKeys(Fleet, FleetScope));
```

Findings, both configuration findings that Admit refuses in both modes:

- `ResumptionStateUnchecked`: resumption is on, a client holds a session cache or a server holds a
  session store or ticket keys, and the scope does not start with the policy prefix (for keys
  behind `CheckedTicketKeys`: is not the fleet scope). Set
  `WithResumptionScope(Policy.SessionScope)` or turn resumption off. A hand-built client cache
  without a scope gets a fresh random one from the builder, which cannot be told from a scope you
  chose, so it is reported although nothing else shares it.
- `TicketKeysUnchecked`: the server ticket keys were not issued by this policy instance. Only the
  wrapper classes of `TicketKeys` and `CheckedTicketKeys` count, judged by class; the builder's
  default keys, a `TStekTicketKeyManager` you create, a marker-listing host class and the keys of
  another policy are all unchecked. Use `Policy.TicketKeys`, or `CheckedTicketKeys` for a fleet.
  A server that holds a session store and offers TLS 1.3 only seals with the store alone, so the
  keys beside it are not judged; one that offers TLS 1.2 seals with the keys, so they are.

Keys that rotate on a lifetime other than the config's `TicketLifetimeSeconds` are disclosed. To
turn resumption off on a facade server, use `TComplianceTls.WithoutResumption(ServerBuilder)`: it
clears the ticket keys and the scope the facade set and then switches resumption off. A bare
`WithResumption(False)` makes `Build` raise, because the builder refuses ticket settings while
resumption is off.

A fleet scope carries no policy prefix, so it does not tie the fleet to the policy. Never give a
fleet scope to a config the policy did not admit, and never share one between policies with
different rules: the tickets would resume across them. This is disclosed, not enforced. Likewise a
host that copies a policy scope onto a config the policy never admitted, or reads it from an
admitted config, defeats the separation.

---

## HPKE

Encrypted Client Hello is refused by both presets and rules outside them are not accepted, so a
policy-built config never uses HPKE. The policy provider still guards it. A base provider whose
HPKE is the default composition is rebuilt over the refusing primitives. A foreign HPKE is wrapped:
in relaxed mode it keeps only the KEMs whose group the rules allow and the AEADs the rules allow
(hashes are not filtered), and in strict mode it refuses everything, because where it runs cannot
be known.

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

- Only `Admit` holds a config to its groups and its verifier source. A key agreement runs inside a
  group object and a chain is verified by the verifier source, neither through the policy
  providers, so a config built without `BuildClient`, `BuildServer` or `Admit` is not
  policy-enforced for them.
- Admit finds misconfigurations made through the public API, except those listed here. Code in
  the same process that deliberately forges its way past a check is out of scope: fake config,
  registry or group objects, a chain engine of its own wrapped in the OS verifier source, a host
  attestation that claims `Validated` and covers any provider, a policy scope copied onto another
  config. A marker interface, a resolver that lists credentials or a verifier source that claims the
  OS is not taken at its word: the policy checks the class.
- Chains are verified by the OS verifier. A private CA does not need to be installed in the OS
  store: pass it as `TSystemTrustRoots.OsAndHostRoots(Store)` (trusted with the OS roots) or
  `TSystemTrustRoots.HostRoots(Store)` (trusted alone; the OS roots never vouch). Strict mode has
  no other chain verifier. The OS chain engine is not the validated module: it calls the module for
  the signature math, and the path building, name matching and revocation logic around it are the
  OS's.
- Trust anchors are held to the key floors, so an anchor key below them is refused: a server's
  client-CA anchors at `Build`, the root ending a server-certificate path at the handshake. An
  anchor's own signature and hash are not judged.
- A peer chain is held to the RSA size range, not to the exact sizes of the rules.
- The AES-GCM IV is built by the library and imported into the module, not generated inside it;
  see [The GCM nonce](#the-gcm-nonce). The Security Policy (section 2.7.1) accepts an imported IV
  only when it is constructed as IG C.H scenario 1(a) describes; that construction is the library's,
  outside the module.
- The Security Policy deprecates RSA of less than 128 bits of security strength, which includes
  2048-bit moduli, from 2031-01-01, before the certificate's sunset date, while `Fips140_3` allows
  2048-bit RSA. Legacy signature verification stays allowed under that transition.
- Relaxed mode reports platform facts and does not refuse portable code; the code a connection
  falls back to at run time is not reflected in the verdict.
- PKCS#12 keys can fall back to portable code, which strict mode refuses; import PEM or DER keys.
- The module table is shipped data and needs an update per Windows release.
- The legacy FIPS policy flag is read and reported only.
- The module is identified by the OS facts above, read once when the attestation is created, not
  by its signature or its self-test state; the OS exposes neither to a program.
- A base provider with its own HPKE composition is wrapped, not trusted: see HPKE above.
- Ticket keys a host installs are outside what the policy can inspect; a fleet is disclosed.
  Shared resumption state is kept apart by the policy scope, which a host can copy onto a config
  the policy never admitted. A fleet scope has no policy prefix and so ties nothing to the policy:
  keep it off configs the policy did not admit and off other policies.

---

## Reading the report

`Describe` prints the verdict, the matched preset, the module, then one line per finding and per
disclosure. Findings are facts that break the verdict; disclosures bound the claim without
breaking it. The sample is the report of `Evaluate` over a client config.

```
Verdict: NotCompliant (Relaxed)
Preset: Fips140_3
Module: Windows 10.0.19045.n Windows 10 22H2 edition Core product type 1 firmware UEFI
  bcryptprimitives.dll 10.0.19041.n C:\Windows\System32\bcryptprimitives.dll machine 0x8664
  legacy FIPS policy Disabled, status NotValidated
Finding: ModuleNotValidated 10.0.19045.n: Windows 10.0.19045.n: the shipped table records no
  validated module for this build
Disclosure: the GCM IV fixed field and counter (TLS 1.2 nonce_explicit = record sequence number;
  TLS 1.3 write_iv XOR sequence number) are built by the library outside the module boundary per
  RFC 5288 / RFC 8446 section 5.3 (IG C.H scenario 1(a), SP section 2.7.1); the module offers no
  interface to generate or check the counter; counter exhaustion forces a key update or close, and
  keys are ephemeral per session
Disclosure: relaxed mode reports platform facts but does not refuse portable code; per-connection
  fallbacks to portable code are not reflected in the verdict
Disclosure: a peer chain is held to the RSA size range, not to the exact sizes of the rules
Disclosure: the TLS 1.3 key schedule (HKDF) does not run as a module service
Disclosure: TLS 1.2 exporter derivations (RFC 5705) are composed over the module HMAC; only the
  key-schedule derivations are module services
```

A strict policy whose `Kdf` is `RequireModule` discloses the refusal in its place:

```
Disclosure: TLS 1.2 exporter derivations (RFC 5705) are refused: the rules require every key
  derivation to be a module service
```

The module line is one line, wrapped here. It gives the OS name and version, the product the table
lists for the build, the edition, product type, firmware, the module file name and version, the
listed version (validated releases only), the loaded path, the native machine (`0x8664` is x64; the
process machine follows when it is not native) and the legacy FIPS policy; it prints the
certificate number only while the status is Validated. The finding carries the reason the status
is not Validated, for example `the process is 32-bit; the policy covers the 64-bit module only, and
the tested environments are 64-bit`. On a validated release whose revision differs from the listed
one the report adds `Disclosure: the module file version 10.0.20348.2113 differs from the
10.0.20348.30000 the certificate lists; only the build is checked`. A validated report on Windows
also says the hardware and any hypervisor are not checked against the tested platforms, and, for an
edition outside the tested list, `edition X is outside the tested list; coverage is
vendor-affirmed`.
