# Encrypted Client Hello (RFC 9849)

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · ECH · [Security model](security-model.md)

Encrypted Client Hello (ECH, RFC 9849) hides the parts of the TLS 1.3 `ClientHello` that leak the
site you are visiting — most importantly the Server Name Indication (SNI). The client sends a
**`ClientHelloInner`** (the real one, with the true SNI) encrypted under a public key the operator
publishes in DNS, wrapped inside a **`ClientHelloOuter`** that carries a public, non-sensitive name.
A network observer sees only the public name; the true destination stays encrypted.

ECH is **TLS 1.3 only** (RFC 9849 6.1: the ClientHelloInner must not offer TLS 1.2 or below). A
client offering a real ECH config is TLS 1.3-only — no TLS 1.2 fallback is offered, because a 1.2
handshake has no ECH and would defeat its purpose. GREASE alone does not constrain the version, and
an ECH server still serves TLS 1.2 to a client that offers no ECH.

ECH lives behind the **`.Tls13` facets**. Everything below is public, provider-neutral API; the HPKE
sealing/opening happens inside the crypto provider and no backend type escapes it.

---

## 1. Client — offering ECH

Fetch the operator's `ECHConfigList` (see [DNS](#4-dns--publishing-and-fetching-the-config)) and hand
it to the builder:

```pascal
uses TlpEchClient, TlpCertificateVerifierSource,   // TEchClientModes, TServerVerification
  TlpTlsPresets, TlpTlsVersion, TlpITlsConfigBuilder, TlpTlsEngineFactory, TlpITlsEngine;

LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
  .WithServerVerification(TServerVerification.WebPki(LCaPem).Build)
  .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));   // see below
LClient.Tls13.WithEch(TEchClientModes.Enable(LEchConfigList)); // the bytes from DNS
LEngine := TTlsEngineFactory.CreateClientEngine(LClient.Build, 'secret.example');
```

`WithEch` takes one exclusive mode: `Enable` offers the config list, `Retry` does so for the
reconnection driven by a reject's `retry_configs` (a second reject is not retried again), and `Grease`
only sends a decoy. `Enable` and `Retry` need a **TLS 1.3-only** client, because the inner ClientHello
never offers TLS 1.2 (RFC 9849 6.1): `Build` refuses a dual-version client with
`EInvalidOperationTlsLibException` rather than quietly narrowing it, so pin `WithSupportedVersions` first.

The client picks the first HPKE suite it supports from the config, builds the inner and outer, seals
the inner, and sends the outer. Once the server confirms acceptance the handshake continues on the
inner — the certificate is verified against the **true** name (`secret.example`), never the public
name. With `WithServerNameIndication(TServerNameIndication.Omit)` the inner ClientHello carries no SNI at
all, while the outer one still carries the config's public name (RFC 9849 6.1).

### What happens on rejection

If the server cannot decrypt ECH (a stale or wrong config), it completes the handshake to the
**public name** and returns fresh `retry_configs`. The library **never falls back to plaintext**: it
completes that handshake, then aborts with an `ech_required` alert and surfaces the outcome so the
application — not the library — decides whether to retry with the new configuration.

The reject handshake is authenticated against the config's **public name** (RFC 9849 6.1.7), and
the `retry_configs` are surfaced only after that succeeds. `WithDangerousDisableServerNameCheck`
turns off the match against your *origin* only; the public-name check stays on. A `Custom`
verifier receives the public name as the host on a reject and owns that check; the verify callback
and an async verdict resolver likewise see the public name as the host. A real ECH offer
under `TServerVerification.DangerousSkip` is refused at `Build`, since nothing would authenticate
the reject; `Grease` is unaffected.

Because the reject ends in a fatal alert, the stream surfaces it as a typed exception; catch it to
read the retry material:

```pascal
try
  LStream.Handshake; // or the adapter's connect
except
  on E: EEchRejectedTlsLibException do
    // E.RetryConfigs holds the server's retry_configs; E.IsRetryAttempt is True when this
    // handshake was already a retry (honor the one-retry cap). Reconnect with the new configs if
    // your policy allows, or surface the failure. If RetryConfigs is empty and IsRetryAttempt is
    // False, the server has securely disabled ECH (RFC 9849 6.1.6): retry WITHOUT an ECH policy
    // (or with GREASE), not with an empty config list, which TEchClientModes.Enable/Retry refuse.
end;
```

A sans-IO caller reads the same outcome off the engine instead: `LEngine.ConnectionInfo.EchStatus`
reports `NotOffered`, `Greased`, `Accepted`, `Rejected`, or `Backend`, and on a reject
`LEngine.ConnectionInfo.EchRetryConfigs` / `LEngine.ConnectionInfo.EchIsRetryAttempt` carry the
retry material — the engine records the reject rather than raising. `ConnectionInfo.EchRejectAborted`
is True when this endpoint aborted with `ech_required` over its own rejected offer (never on a server).

On rejection the client is talking to the *client-facing* server on the public name, not your
intended server, so it **declines client authentication** (sends an empty `Certificate`) rather than
expose your client certificate to the wrong party.

### GREASE

If you `Enable` an `ECHConfigList` but **none** of its configs is usable — an unsupported HPKE
suite, an invalid public key, or a mandatory unknown extension — the client **fails closed**: `Build`
raises `EArgumentTlsLibException` rather than silently sending the true SNI in the clear. An
**empty** config list is refused earlier, by `TEchClientModes.Enable` / `Retry` themselves, with the
same exception type. Connecting without ECH in that case is your explicit
choice: catch the error and build again with `Grease`.

To make ECH users indistinguishable from non-users, a client with no usable config can send a decoy
ECH extension (RFC 9849 6.2); `Grease` leaves the offered versions alone:

```pascal
LClient.Tls13.WithEch(TEchClientModes.Grease); // send a decoy ech, offer no real ECH
```

The decoy is random-but-plausible and is re-sent verbatim across a HelloRetryRequest; any ECH
response from the server is ignored once it passes a syntactic check (the HelloRetryRequest `ech`
and the EncryptedExtensions `retry_configs`; a malformed one is a decode_error). `EchStatus` reports `Greased` only when the handshake completes
as TLS 1.3: a dual-version client whose server picks TLS 1.2 reports `NotOffered`.

---

## 2. Server — accepting ECH

A server decrypts ECH with a key store that holds one or more configs and their private keys. Load
them from an RFC 9934 PEM (the format `EchKeyGen` and `openssl ech` emit):

```pascal
uses TlpInMemoryEchKeyStore, TlpTlsPresets;   // plus TlpIEch for IEchServerKeyStore

LStore := TInMemoryEchKeyStore.FromPem(LPemBytes, Crypto);
LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
LServer.Tls13.WithEchKeyStore(LStore, True);
```

`TInMemoryEchKeyStore.FromConfig(ConfigList, PrivateKey, Crypto)` builds the same store from an
`ECHConfigList` and its HPKE private key (an `ISecretBuffer`) instead of a PEM. The one-argument
`WithEchKeyStore(LStore)` leaves trial decryption off, so only the key whose `config_id` matches is
tried. You can supply your own `IEchServerKeyStore`: `Entries` lists the valid config and key pairs
in preference order, and `RetryConfigs` is the `ECHConfigList` advertised on a reject, which must be
non-empty and hold at least one config byte-equal to an entry's whenever `Entries` is non-empty.

The server trial-decrypts the outer against its keys; on success it reconstructs the inner and
serves the true name, on failure it serves the public name and advertises the store's `is_retry`
configs as `retry_configs`. The second argument, `True`, tries every key (not only the one whose
`config_id` matches), which tolerates a client that hides the id. `WithEchKeyStore` raises on a
nil store, on a store with no entries or with retry configs that are empty or not a valid list, and
on a key store entry whose key or advertised cipher suite the crypto provider cannot serve. A server
that only receives the inner ClientHello a split-mode client-facing server forwards (RFC 9849 7.2)
is configured with `WithEchBackend` instead; it holds no keys, so it cannot be combined with
`WithEchKeyStore`. A backend aborts an outer-type ech with `illegal_parameter` (RFC 9849 7), so use
it only behind the client-facing server, never on a directly reachable port. After
a HelloRetryRequest it also holds the second ClientHello to the first one's inner: the inner marker
must still be present and the random unchanged, else `illegal_parameter`.

Rotate keys by building a fresh store and swapping it in — the store is app-driven, not
clock-rotated, so it tracks exactly what you publish in DNS.

---

## 3. Generating keys — the `EchKeyGen` tool

`TlsLib.Tools/EchKeyGen` is a standalone CLI that produces everything an operator needs:

```
EchKeyGen -public_name public.example -origin secret.example -out ech.pem
          [-suite x25519,hkdf-sha256,aes-128-gcm] [-max_name_len 64] [-config_id N]
```

`-suite` is `kem,kdf,aead`: kem `x25519 | p256 | p384 | p521`, kdf `hkdf-sha256 | hkdf-sha384 |
hkdf-sha512`, aead `aes-128-gcm | aes-256-gcm | chacha20-poly1305`. Without `-config_id` (0 to 255)
a random id is chosen.

`-public_name` is the client-facing name carried inside the `ECHConfig` (the outer SNI);
`-origin` is the name clients actually connect to (the inner SNI) and is the owner of the HTTPS
record where the config is published (RFC 9460 2.3 and 9, RFC 9848 3, RFC 9849 4). It writes an RFC 9934 PEM (a
PKCS#8 `PRIVATE KEY` block the server store loads, plus an `ECHCONFIG` block) and prints the DNS
presentation line, owned by the origin. The `-out` file must not already exist: it is created
exclusively and is never overwritten or written through a symlink. On POSIX its mode is 0600; on
Windows it gets a protected, owner-only access list.

```
secret.example. HTTPS 1 . ech="AD7+DQA6BwAg..."
```

Set **`-max_name_len`** to the length of the longest backend name this config serves. The client
pads the encrypted inner up to that length (RFC 9849 6.1.3), so every name at or below it produces
the same ciphertext size and its length is hidden. The default is the longer of `64` and the
`-origin` length (at most `255`), so the origin is always fully padded. `0` is still accepted
explicitly: RFC 9849 defines it as the longest backend name being unknown, and the inner is then
only rounded to a 32-byte multiple, so a shorter name leaks its length within that bucket. Prefer a
value that covers all your names when you know them.

---

## 4. DNS — publishing and fetching the config

The `ECHConfigList` is published as the **`ech` SvcParam (key 5)** of an HTTPS/SVCB record
(RFC 9460) for the **origin** (the name clients connect to), not the `public_name`. Publish the
line `EchKeyGen` prints at that owner name. On the client side, once the application has
resolved the HTTPS record, extract the config with the out-of-core helper (no resolver is pulled
into the TLS core):

```pascal
uses TlpEchConfigFromSvcb;
if TEchConfigFromSvcb.TryFromServiceBinding(LHttpsRdata, LEchConfigList) then
  LClient.Tls13.WithEch(TEchClientModes.Enable(LEchConfigList));
```

---

## 5. Interop and testing

ECH is exercised end to end against BoringSSL's BoGo conformance suite (client, server, GREASE, and
the split-mode backend role) as part of the required CI gate, and its parsers (`ECHConfigList`, the
`encrypted_client_hello` extension, and `ech_outer_extensions`) are in the structure-aware fuzz
corpus.
