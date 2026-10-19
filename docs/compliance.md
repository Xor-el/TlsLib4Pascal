# FIPS and CNSA policy

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · Compliance · [Security model](security-model.md)

The optional `TlsLib.Compliance` package is a policy over the OS cryptographic module. It sends
every TLS crypto operation to that module and refuses anything else: an algorithm outside the rules,
an operation the module does not serve, a config that weakens the rules. It adds no cryptography of
its own and the core does not depend on it.

Throughout, `Crypto` is an `ICryptoProvider` and `Pkix` an `IPkixProvider`
(`TDefaultCryptoProvider.Create as ICryptoProvider` and `TDefaultPkixProvider.Create as IPkixProvider`).

---

## What is claimed

TlsLib is not a validated cryptographic module and claims no CMVP validation. On Windows 11 22H2
(build 22621) and Windows Server 2022 (build 20348), its primitives run in Microsoft's Cryptographic
Primitives Library (`bcryptprimitives.dll`), CMVP certificate #5410, FIPS 140-3 Level 1, validated
2026-08-31, sunset 2031-08-30. Other builds, including 23H2, 24H2, 25H2 and Server 2025, are not
covered; strict mode refuses them. A platform with no validated-module table is refused the same way.

The TLS 1.2 and TLS 1.3 key derivations are composed outside the module; every HMAC runs in-module.
TLS 1.2 is allowed only with Extended Master Secret (RFC 7627).

The Fips140_3 profiles refuse every ML-KEM and PQ/T hybrid group (including SecP256r1MLKEM768): the OS module (CMVP #5410) has no validated ML-KEM, and current CMVP guidance (IG D.S Scenario 2) approves hybrids only when ML-KEM runs inside a validated module, so hybrids will be added once such a module is available.

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
  has none; `Roots` is a `TSystemTrustRoots`.
- `Client(Policy, Verification)` takes your own `IServerVerificationBuilder`; the strength floors of
  the rules are applied to it.
- `Client(Policy, Roots, Posture, DeadlineMs)` uses the OS verifier with live revocation; run it
  with the OS live-revocation resolver (see [system-trust.md](system-trust.md)).
- `Server(Policy, Credential)` narrows the credential key to the schemes of the rules. For mutual
  TLS add `WithPeerAuth` and a client verification from the OS source, with
  `WithMinimumStrength(Policy.Rules.Strength)`.

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
The exact RSA sizes apply to the policy's own credential; a peer chain is held to the size range.
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
(clients, and servers that request a client certificate). For an own credential it also checks the
key size and curve against the floors, the schemes the key can sign with, and whether the key is
served by the module. A client's chain must be verified by the OS verifier, and so must a server's
client chain.

A verification callback is allowed: it can only add rejections. GREASE is allowed: its values are
never negotiated (RFC 8701).

---

## Revocation

No OCSP staple is requested, because the OS verifier checks a staple's signature in portable code.
Check revocation through the OS: use `Client(Policy, Roots, Posture, DeadlineMs)` with the OS
live-revocation resolver, or leave the posture at Soft. A host-owned resolver cannot be seen in the
config, so the report discloses it; in strict mode a portable resolver still fails closed because
the policy's revocation facet answers indeterminate.

---

## Limits

- Skipping `Admit` loses the non-crypto checks.
- Chains are verified by the OS verifier against the OS certificate store, so a private CA must be
  installed there; strict mode has no other chain verifier.
- Credentials chosen by server name are not size-checked.
- PKCS#12 keys can fall back to portable code, which strict mode refuses; import PEM or DER keys.
- The module table is shipped data and needs an update per Windows release; the sunset date is
  reported, not enforced.
- The legacy FIPS policy flag is read and reported only.
- A base provider with its own HPKE composition keeps it; `Admit` refuses ECH either way.

---

## Reading the report

`Describe` prints the verdict, the matched preset, the module, then one line per finding and per
disclosure. Findings are facts that break the verdict; disclosures bound the claim without
breaking it.

```
Verdict: NotCompliant (Relaxed)
Preset: Fips140_3
Module: Windows 10.0.19045.n Windows 10 22H2 bcryptprimitives.dll n.n.n.n, status NotValidated
Finding: ModuleNotValidated 10.0.19045.n: Windows 10.0.19045.n: the shipped table records no validated module for this build
Disclosure: the TLS key derivations are composed outside the module over its HMAC
```
