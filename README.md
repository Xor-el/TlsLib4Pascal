<p align="center">
  <img src="assets/branding/logo.svg" width="160" alt="TlsLib4Pascal logo" />
  <h1 align="center">TlsLib4Pascal</h1>
  <p align="center">
    <strong>Opinionated yet Modular TLS for Modern Object Pascal</strong>
  </p>
  <p align="center">
    <a href="https://github.com/Xor-el/TlsLib4Pascal/actions/workflows/make.yml"><img src="https://github.com/Xor-el/TlsLib4Pascal/actions/workflows/make.yml/badge.svg" alt="Build Status"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://www.embarcadero.com/products/delphi"><img src="https://img.shields.io/badge/Delphi-Sydney%2B-red.svg" alt="Delphi Sydney+"></a>
    <a href="https://www.freepascal.org/"><img src="https://img.shields.io/badge/FreePascal-3.2.2%2B-blue.svg" alt="FreePascal 3.2.2+"></a>
  </p>
</p>

---

**TlsLib4Pascal** is a fully managed, from-scratch TLS 1.2 + TLS 1.3 stack for modern Object Pascal (Delphi and FreePascal), released under the permissive [MIT License](LICENSE).

## Table of Contents

- [Features](#features)
- [What's Inside](#whats-inside)
- [Getting Started](#getting-started)
- [Quick Examples](#quick-examples)
- [Documentation](#documentation)
- [Security](#security)
- [Running Tests](#running-tests)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [Tip Jar](#tip-jar)
- [License](#license)
- [Branding](assets/branding/README.md)

## Features

- **Fully managed, from-scratch** -- one pure Object Pascal TLS engine, identical on every platform
- **TLS 1.3 + hardened TLS 1.2** -- client and server, designed together; 1.2 is an ECDHE + AEAD + Extended-Master-Secret profile only
- **Post-quantum hybrid KEX by default** -- `X25519MLKEM768` in every preset
- **AEAD-only, forward-secret** -- no CBC-HMAC, RC4, 3DES, static-RSA/DH, or TLS-level compression; 0-RTT off by default
- **Secure by default, fail-closed** -- refuses to build an unauthenticated client, and every foot-gun lives behind one loudly-named `dangerous` surface
- **Complete trust pipeline** -- PKIX path validation, RFC 6125 endpoint identity, public-key pinning, stapled + live OCSP/CRL revocation, and opt-in OS system trust
- **Resumption, PSK & 0-RTT** -- 1.3 tickets with STEK rotation or a stateful store, 1.2 session IDs + RFC 5077, RFC 9258 external PSKs, anti-replay early data
- **Certificate compression** -- RFC 8879 with a centralized decompression-bomb defense and an optional cross-connection cache
- **Three ways to integrate** -- a batteries-included `TTlsLib` facade, a `TTlsStream` over a tiny transport interface, and drop-in adapters for mORMot, Indy, Synapse, and fcl-net (all over one sans-IO engine)
- **Conformance-tested** -- RFC 8448 byte-exact vectors, structure-aware fuzzing, and BoringSSL's BoGo suite as a required CI gate, alongside an OpenSSL interop matrix
- **Cross-platform, cross-compiler** -- Delphi and FreePascal / Lazarus

## What's Inside

<details>
<summary><strong>Protocol &amp; handshake</strong></summary>

- **TLS 1.3** ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) and **hardened TLS 1.2** ([RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) family) -- client + server.
- HelloRetryRequest with a stateless authenticated cookie; downgrade-sentinel protection + `TLS_FALLBACK_SCSV`.
- Middlebox-compatibility mode; post-handshake KeyUpdate; centralized alert + unexpected-message handling.
- A **sans-IO engine** core -- no sockets, threads, or timers; one contract for client/server and 1.2/1.3.

</details>

<details>
<summary><strong>Cipher suites, groups &amp; signatures</strong></summary>

#### AEAD cipher suites
`TLS_AES_128_GCM_SHA256` | `TLS_AES_256_GCM_SHA384` | `TLS_CHACHA20_POLY1305_SHA256` (+ the hardened ECDHE-ECDSA/RSA 1.2 AEAD suites)

#### Named groups
`X25519` | `X25519MLKEM768` (PQ hybrid) | `secp256r1` | `secp384r1` | `secp521r1`

#### Signature schemes
`ecdsa_secp256r1/384r1/521r1` | `rsa_pss_rsae_sha256/384/512` | `ed25519` | `ed448`

CPU-adaptive AEAD selection (ChaCha20-Poly1305 preferred where hardware AES is absent), server-preference backbone with an equal-preference AEAD group.

</details>

<details>
<summary><strong>Post-quantum</strong></summary>

- **PQ hybrid key exchange** -- `X25519MLKEM768` (code point `0x11EC`), native in the KEM-shaped group registry and offered by every preset.

</details>

<details>
<summary><strong>Trust &amp; certificates</strong></summary>

- **PKIX path validation** (PKITS-verified), constrained web-PKI profile by default with the full RFC 5280 machinery on opt-in.
- **Endpoint identity** -- RFC 6125 host-name / SAN matching (CN matching off by default).
- **Revocation** -- stapled OCSP, live OCSP/CRL over an injected fetcher, soft/hard/off posture, and RFC 7633 must-staple.
- **OS system trust** (opt-in) -- Windows / macOS / Linux anchor harvest, iOS / Android verifier delegates.
- **CA bundles** -- a PEM/DER bundle loader (`TlsLib.Trust.Bundle`).
- **Pinning**, **mutual TLS**, and **OCSP stapling** both directions.
- One composable, fail-closed pipeline; custom verification **augments** (can only reject further), and every bypass is behind the `dangerous` surface.

</details>

<details>
<summary><strong>Resumption, PSK &amp; 0-RTT</strong></summary>

- TLS 1.3 -- forward-secret `psk_dhe_ke`, single-use tickets, stateless STEK rotation auto-upgrading to a stateful store.
- TLS 1.2 -- session IDs + RFC 5077 tickets.
- **External PSKs** -- RFC 9258 out-of-band pre-shared keys.
- **0-RTT early data** -- off by default, bounded by a pluggable anti-replay strategy when enabled.

</details>

<details>
<summary><strong>Extensions</strong></summary>

`server_name` (SNI) | `application_layer_protocol_negotiation` (ALPN) | `supported_versions` | `supported_groups` | `key_share` | `signature_algorithms` (+ `_cert`) | `pre_shared_key` + `psk_key_exchange_modes` | `early_data` | `record_size_limit` | `status_request` (OCSP) | `compress_certificate` (RFC 8879) | `cookie` | `extended_master_secret` | `renegotiation_info` | GREASE

</details>

<details>
<summary><strong>Integration tiers</strong></summary>

- **Tier 1 -- batteries-included facade** (`TTlsLib`): a ready, safe config or engine in one call.
- **Tier 2 -- `TTlsStream`**: a `TStream` that speaks TLS over a two-method `ITlsTransport`.
- **Tier 3 -- drop-in adapters**: mORMot, Indy, Synapse, and fcl-net, each via that stack's own SSL seam.
- *Underneath, all three run on the raw sans-IO engine (`ITlsEngine`) — drive it directly only for async / event-loop frameworks that pump bytes themselves.*

</details>

<details>
<summary><strong>Security invariants</strong></summary>

Bounds-checked no-over-read parser · constant-time secret comparison · AEAD nonce non-reuse + usage limits · certificate decompression caps · peer key-share validation · full secret zeroization · DoS resource limits · single-threaded-per-connection model. Each is a stated, tested contract -- see the [security model](docs/security-model.md).

</details>

## Getting Started

### Prerequisites

| Compiler | Minimum Version |
|---|---|
| Delphi | Sydney (10.4) or later |
| FreePascal | 3.2.2 or later |

Install **[CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal)** first -- it is the only companion dependency (see [Dependencies](#dependencies)).

### Installation

**1. Clone the repository:**

```bash
git clone https://github.com/Xor-el/TlsLib4Pascal.git
```

**2a. Delphi**

- Install [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal).
- Open and install the core package: `TlsLib/src/Packages/Delphi/TlsLib4PascalPackage.dpk`
- Add the `TlsLib/src` subdirectories to your project's search path.

**2b. FreePascal / Lazarus**

- Install [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal).
- Open and install the core package: `TlsLib/src/Packages/FPC/TlsLib4PascalPackage.lpk`

### Optional packages

Add one only when you use its feature; the core references none of them:

| Package | Adds |
|---|---|
| `TlsLib.Trust.System` | OS system-trust harvest + verifier delegate |
| `TlsLib.Trust.Bundle` | A PEM/DER CA-bundle loader (`FromPem` / `FromPemFile`) |
| `TlsLib.Adapter.mORMot` / `.Indy` / `.Synapse` / `.FclNet` | Drop-in adapters for those networking stacks |

## Quick Examples

### A verified TLS client

```pascal
uses SysUtils, TlpTlsLib, TlpITlsConfig, TlpTlsEngineFactory, TlpTlsStream, TlpITlsEngine, TlpITlsTransport;

var
  LConfig: ITlsClientConfig;
  LEngine: ITlsEngine;
  LStream: TTlsStream;
  MyTransport: ITlsTransport;   // your socket, wrapped behind ITlsTransport
  Request, Response: TBytes;    // your request bytes, and a buffer for the reply
begin
  // Compatible preset (TLS 1.3 + hardened 1.2, PQ hybrid), verified against your CA bundle.
  LConfig := TTlsLib.NewClientConfig(LoadFile('my-ca.pem'));
  LEngine := TTlsEngineFactory.CreateClientEngine(LConfig, 'example.com');

  LStream := TTlsStream.Create(MyTransport, LEngine, {IsClient=} True, 'example.com');
  try
    LStream.Handshake;                        // completes or raises -- fail-closed
    LStream.Write(Request[0], Length(Request));
    SetLength(Response, 4096);
    LStream.Read(Response[0], Length(Response));
    LStream.CloseNotify;
  finally
    LStream.Free;
  end;
end;
```

### A TLS server

```pascal
uses TlpTlsLib, TlpITlsConfig, TlpTlsEngineFactory, TlpTlsStream, TlpITlsEngine, TlpITlsTransport;

var
  LConfig: ITlsServerConfig;
  LEngine: ITlsEngine;
  LStream: TTlsStream;
  AcceptedTransport: ITlsTransport;   // an accepted socket, wrapped behind ITlsTransport
begin
  // Compatible preset, from your certificate chain + private key (build the config once, reuse it):
  LConfig := TTlsLib.NewServerConfig(LoadFile('server-chain.pem'), LoadFile('server-key.pem'));

  // per accepted connection:
  LEngine := TTlsEngineFactory.CreateServerEngine(LConfig);
  LStream := TTlsStream.Create(AcceptedTransport, LEngine, {IsClient=} False, '');
  LStream.Handshake;
  // read / write / CloseNotify exactly as the client does
end;
```

### Already using mORMot / Indy / Synapse / fcl-net?

Swap in TlsLib4Pascal through that stack's own SSL seam -- often one line. For example, mORMot:

```pascal
uses TlpMormotTls;
RegisterTlsLib4PascalTls;   // every mORMot connection now uses TlsLib4Pascal
```

`MyTransport`, `LoadFile`, and the per-stack wiring are shown in [Getting Started](docs/getting-started.md) and the [Cookbook](docs/cookbook.md).

## Documentation

Full usage docs live in [`docs/`](docs/):

- **[Getting started](docs/getting-started.md)** -- install, first client and server, and how to verify it worked.
- **[Cookbook](docs/cookbook.md)** -- task recipes: mTLS, ALPN, resumption, 0-RTT, revocation, compression, the adapters, and the dangerous surface.
- **[Certificate verification & trust](docs/certificate-verification.md)** -- private CAs, pinning, live revocation, and the escape hatches.
- **[OS system trust](docs/system-trust.md)** -- verifying against the operating system's root store.
- **[Certificate compression](docs/certificate-compression.md)** -- RFC 8879 and the compression cache.
- **[Security model](docs/security-model.md)** -- the invariants, how each is enforced, and how it's tested.

## Security

TlsLib4Pascal is **secure by default and fail-closed**: it will not complete a handshake it cannot verify, the builder refuses a client with no trust source, and every way to weaken authentication is behind a single, loudly-named `dangerous` surface. The design closes the classic TLS vulnerability classes with stated, tested invariants -- see the **[security model](docs/security-model.md)**.

Found a vulnerability? Please report it **privately** -- see **[SECURITY.md](SECURITY.md)**.

## Running Tests

Tests use **DUnit** (Delphi) and **FPCUnit** (FreePascal); interop/conformance runs via a separate BoGo + OpenSSL harness.

**Delphi:** Open `TlsLib.Tests/Delphi.Tests/TlsLib.Tests.dpr` in the IDE and run.

**FreePascal / Lazarus:** Open `TlsLib.Tests/FreePascal.Tests/TlsLib.Tests.lpi` (or `TlsLibConsole.lpi`) and run.

## Dependencies

TlsLib4Pascal's only direct dependency is **CryptoLib4Pascal**.

| Dependency | Purpose |
|---|---|
| [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal) | Cryptographic primitives, PKIX path validation, X.509, CSPRNG |

## Contributing

Contributions are welcome. Please open an [issue](https://github.com/Xor-el/TlsLib4Pascal/issues) for bug reports or feature requests, and submit pull requests. For anything security-sensitive, use private reporting (see [SECURITY.md](SECURITY.md)) rather than a public issue.

## Tip Jar

If you find this library useful and would like to support its continued development, tips are greatly appreciated! 🙏

| Cryptocurrency | Wallet Address |
|---|---|
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/btc.png" width="20" alt="Bitcoin" /> **Bitcoin (BTC)** | `bc1quqhe342vw4ml909g334w9ygade64szqupqulmu` |
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/eth.png" width="20" alt="Ethereum" /> **Ethereum (ETH)** | `0x53651185b7467c27facab542da5868bfebe2bb69` |
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/sol.png" width="20" alt="Solana" /> **Solana (SOL)** | `BPZHjY1eYCdQjLecumvrTJRi5TXj3Yz1vAWcmyEB9Miu` |

## License

TlsLib4Pascal is released under the [MIT License](LICENSE).
