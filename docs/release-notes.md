# Release notes

**TlsLib4Pascal docs** · [Home](README.md) · Release notes

## Closing audit

A full re-audit of the library and its adapters, fixed in one series. Most of it is hardening that
needs no change on your side. The sections below start with what you have to act on.

### Requirements

- **CryptoLib4Pascal must include the strict-DigestInfo default** (CryptoLib pull request 210,
  commit `8fb514e`, or later). TlsLib4Pascal no longer sets that mode itself, so against an older
  CryptoLib an RSA signature whose DigestInfo leaves out the NULL parameters is accepted again,
  silently. CryptoLib is not pinned by version, so this is yours to check.

### Breaking changes

**Server ECH is one policy.** The three server-side ECH settings are now a single immutable
`IEchServerPolicy`, as the client already had.

| Before | Now |
|---|---|
| `Tls13.WithEchKeyStore(store)` then `Tls13.WithEchTrialDecrypt(True)` | `Tls13.WithEchKeyStore(store, True)` |
| `Tls13.WithEchSplitModeBackend` | `Tls13.WithEchBackend` |
| `ITlsServerConfig.EchKeyStore`, `.EchTrialDecrypt`, `.EchSplitModeBackend` | `ITlsServerConfig.EncryptedClientHello: IEchServerPolicy` (`nil` = ECH not served) |
| `TServerHandshakeParams.EchKeyStore`, `.EchTrialDecrypt`, `.EchSplitModeBackend` | `TServerHandshakeParams.EchPolicy` |

- `WithEchKeyStore(nil)` now raises. It used to clear ECH.
- A key store entry the crypto provider cannot serve (a key that does not belong to its config, or
  any advertised HPKE suite the provider cannot build) now raises `EArgumentTlsLibException` when
  the store is added, for any `IEchServerKeyStore`, not only the in-memory one. It used to be
  advertised and then decline ECH for every client that picked that suite.
- `WithEchKeyStore` and `WithEchBackend` are mutually exclusive: whichever is called second raises.
- Trial decryption can only be set together with a key store.

**`TTlsOptions.Tls12Only` is `TTlsOptions.SupportedVersions`.** A list of wire codes in preference
order replaces the boolean; empty keeps the default offer (TLS 1.3 and 1.2). Unknown or duplicate
codes raise. A supplied `ClientConfig`/`ServerConfig` alongside a non-empty list is refused, like
the other options a supplied config replaces.

**0-RTT data is read through `ReadEarlyData`.** Accepted early data is replayable, so the server now
keeps it apart from the 1-RTT stream. `ReadAppData`, `TTlsStream` and the adapters never return it.
A server that enabled 0-RTT and read only through those no longer receives the early bytes.
Read `PendingEarlyData` / `ReadEarlyData` to take them, knowing they can be replayed.

**Strict RSA PKCS#1 v1.5 DigestInfo.** Every RSASSA-PKCS1-v1_5 verification (certificate, CRL and
OCSP signatures, and TLS 1.2 handshake signatures) requires the DigestInfo with its NULL
parameters, as RFC 8017 does. A signer that omits them is now rejected. A host that must accept
them sets `TCryptoLibConfig.Pkcs1.StrictDigestInfo := False`, which applies to the whole process.
The optional Windows native (CNG) verifier, which only verifies handshake signatures, and OS trust
delegate mode are outside this setting.

### Behaviour changes

- **SHA-1 and MD5 on revocation answers.** OCSP responses, delegated responder certificates and CRLs
  are authenticated only when signed with something stronger than MD5 or SHA-1. A refused answer is
  indeterminate, so the posture decides: Hard rejects, Soft carries on. A private PKI that still
  signs with SHA-1 can admit it through `TCertificateStrengthPolicy.AllowedDeprecatedHashes`; MD5 is
  never admitted. The set is empty by default.
- **`WithIntermediateCertificates` reaches the OS trust delegates.** It was ignored on the server
  and client paths, so a leaf-only peer that the built-in verifier completes was refused with
  `unknown_ca`. Windows adds the intermediates to the untrusted intermediate store; Apple and
  Android append them behind the presented chain. They are never trust anchors. An empty peer chain
  is refused before the platform engine is called.
- **`certificate_expired` only for the leaf or its issuer line.** A stale extra certificate the peer
  happened to send is no longer the reason an untrusted chain is refused.
- **`server_name` outside printable ASCII is `illegal_parameter`.** It used to become a lossy
  string that reached the credential resolver, ticket check and logs.
- **ALPN lists are capped at 16 KiB** for both roles. The old cap of 65533 bytes could produce a
  list that the ClientHello could not always carry, so some accepted lists failed every handshake.
- **TLS 1.2 clients always offer `extended_master_secret`** per their configuration, including when
  resuming a session that did not use it.
- **A composed trust store keeps the stores it was built from**, so a reload cannot hand back a
  configuration frozen with roots an operator removed.
- **The host's `VerdictDeadlineMs` is honoured.** It was stored and never read; the live revocation
  checker and the OS live resolver now work within the tighter of it and their own budget.
- **PEM key import takes the first private key** in a file that holds several blocks.
- **Verifiers and pinning decorators raise on a nil PKIX provider, clock or inner verifier** at
  configuration, instead of failing at the first handshake.

### Fixes and hardening

- Fragmented handshake messages are reassembled without re-copying the buffer; feeding one large
  message a few bytes at a time was quadratic work.
- The plaintext fatal-alert allowance before the first protected record now works; a verdict
  arriving after a fatal abort no longer resumes the handshake; `StartHandshake` is a no-op on a
  terminal engine.
- The anti-replay strike register skips its full sweep while its queue is in expiry order.
- ECH: the retry `config_id` is checked against what the client sent; the owner-only key file is
  enforced on Windows (a protected access list for the owner alone, where it previously inherited
  the directory's); the inner ClientHello is no longer wiped in some places and not others, since it
  is privacy plaintext rather than key material and its server name is retained for the connection
  regardless.
- Random-source and ML-KEM inputs are bounds-checked, and an imported PKCS#12 key must equal the
  native key.
- Only a trailing `:80` is stripped when comparing responder URLs.
- Many RFC citations and stale comments corrected.

### Adapters

- **Indy:** a read that receives only bytes yielding no application data (session tickets, a key
  update) is bounded by the IOHandler's `ReadTimeout`; `ReadLn` returns an empty line with
  `ReadLnTimedOut` set instead of waiting forever.
- **Synapse:** `SSLType` is honoured: `LT_all` offers TLS 1.3 and 1.2, `LT_TLSv1_2` and `LT_TLSv1_3`
  offer that version alone, and any other value fails the handshake. A pinned `SSLType` alongside a
  supplied config is refused. The new `ReadTimeoutMs` property bounds one `RecvBuffer` call
  (default 0 = block, as Synapse's other TLS plugins do); set it on each accepted socket of a server
  that reads untrusted peers.
- **FclNet:** fcl-net's `SSLType` is honoured the same way (`stAny`, `stTLSv1_2`; any other value
  fails the handshake).
- **mORMot:** `DisableTls13` now offers TLS 1.2 alone, and `CipherList` is refused instead of
  silently ignored. A receive that wakes with nothing to read no longer outlives the handshake
  deadline.

### Known differences

- The optional Windows native (CNG) overlay accepts an RSA PKCS#1 v1.5 handshake signature whose
  DigestInfo has no NULL parameters. It is the one place the strict check does not reach.
- On Android the platform engine has no network revocation setting, so a live-revocation source is
  refused up front and a live deadline is never silently dropped.
