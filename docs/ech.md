# Encrypted Client Hello (RFC 9849)

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · ECH · [Security model](security-model.md)

Encrypted Client Hello (ECH, RFC 9849) hides the parts of the TLS 1.3 `ClientHello` that leak the
site you are visiting — most importantly the Server Name Indication (SNI). The client sends a
**`ClientHelloInner`** (the real one, with the true SNI) encrypted under a public key the operator
publishes in DNS, wrapped inside a **`ClientHelloOuter`** that carries a public, non-sensitive name.
A network observer sees only the public name; the true destination stays encrypted.

ECH is **TLS 1.3 only** (RFC 9849; the same stance as rustls and Go's `crypto/tls`, which refuse to
configure ECH below 1.3). When ECH is enabled the endpoint is 1.3-only — no TLS 1.2 fallback is
offered, because a 1.2 handshake has no ECH and would defeat its purpose.

ECH lives behind the **`.Tls13` facets**. Everything below is public, provider-neutral API; the HPKE
sealing/opening happens inside the crypto provider and no backend type escapes it.

---

## 1. Client — offering ECH

Fetch the operator's `ECHConfigList` (see [DNS](#4-dns--publishing-and-fetching-the-config)) and hand
it to the builder:

```pascal
LClient := TTlsPresets.Compatible(Provider).Client;
LClient.Tls13.WithEncryptedClientHello(LEchConfigList); // the bytes from DNS
LEngine := TTlsEngineFactory.CreateClientEngine(LClient.Build, 'secret.example');
```

The client picks the first HPKE suite it supports from the config, builds the inner and outer, seals
the inner, and sends the outer. Once the server confirms acceptance the handshake continues on the
inner — the certificate is verified against the **true** name (`secret.example`), never the public
name.

### What happens on rejection

If the server cannot decrypt ECH (a stale or wrong config), it completes the handshake to the
**public name** and returns fresh `retry_configs`. The library **never falls back to plaintext**: it
completes that handshake, then aborts with an `ech_required` alert and surfaces the outcome so the
application — not the library — decides whether to retry with the new configuration.

Because the reject ends in a fatal alert, the stream surfaces it as a typed exception; catch it to
read the retry material:

```pascal
try
  LStream.Handshake; // or the adapter's connect
except
  on E: EEchRejectedTlsLibException do
    // E.RetryConfigs holds the server's retry_configs (may be empty); E.IsRetryAttempt is True
    // when this handshake was already a retry (honor the one-retry cap). Reconnect with the new
    // configs if your policy allows, or surface the failure.
end;
```

A sans-IO caller reads the same outcome off the engine instead: `LEngine.EchStatus` reports
`NotOffered`, `Greased`, `Accepted`, `Rejected`, or `Backend`, and on a reject
`LEngine.EchRetryConfigs` / `LEngine.EchIsRetryAttempt` carry the retry material — the engine
records the reject rather than raising. `ConnectionInfo.EchStatus` mirrors the status for a
completed connection.

On rejection the client is talking to the *client-facing* server on the public name, not your
intended server, so it **declines client authentication** (sends an empty `Certificate`) rather than
expose your client certificate to the wrong party.

### GREASE

If you configure an `ECHConfigList` but **none** of its configs is usable — an unsupported HPKE
suite, an invalid public key, or a mandatory unknown extension — and GREASE is off, the client
**fails closed**: `CreateClientEngine` raises `EArgumentTlsLibException` rather than silently
sending the true SNI in the clear. Enable GREASE to opt into connecting without ECH in that case.

To make ECH users indistinguishable from non-users, a client with no usable config can send a decoy
ECH extension (RFC 9849 §6.2):

```pascal
LClient.Tls13.WithEchGrease(True); // send a decoy ech when no real config is usable
```

The decoy is random-but-plausible and is re-sent verbatim across a HelloRetryRequest; any ECH
response from the server is ignored.

---

## 2. Server — accepting ECH

A server decrypts ECH with a key store that holds one or more configs and their private keys. Load
them from an RFC 9934 PEM (the format `EchKeyGen` and `openssl ech` emit):

```pascal
LStore := TInMemoryEchKeyStore.FromPem(LPemBytes, Provider);
LServer := TTlsPresets.Compatible(Provider).Server;
LServer.Tls13.WithEchKeyStore(LStore).WithEchTrialDecrypt(True);
```

The server trial-decrypts the outer against its keys; on success it reconstructs the inner and
serves the true name, on failure it serves the public name and advertises the store's `is_retry`
configs as `retry_configs`. `WithEchTrialDecrypt(True)` tries every key (not only the one whose
`config_id` matches), which tolerates a client that hides the id.

Rotate keys by building a fresh store and swapping it in — the store is app-driven, not
clock-rotated, so it tracks exactly what you publish in DNS.

---

## 3. Generating keys — the `EchKeyGen` tool

`TlsLib.Tools/EchKeyGen` is a standalone CLI that produces everything an operator needs:

```
EchKeyGen -public_name public.example -out ech.pem [-suite x25519,hkdf-sha256,aes-128-gcm]
          [-max_name_len 64] [-config_id N]
```

It writes an RFC 9934 PEM (a PKCS#8 `PRIVATE KEY` block the server store loads, plus an `ECHCONFIG`
block) and prints the DNS presentation line:

```
public.example. HTTPS 1 . ech="AD7+DQA6BwAg..."
```

Set **`-max_name_len`** to the length of the longest backend name this config serves. The client
pads the encrypted inner up to that length (RFC 9849 §6.1.3), so every name at or below it produces
the same ciphertext size and its length is hidden. The default is `0`, which RFC 9849 defines as
"longest name not known": the inner is still rounded to a 32-byte multiple, but a shorter name then
leaks its length within that bucket. Prefer a value that covers your names when you know them.

---

## 4. DNS — publishing and fetching the config

The `ECHConfigList` is published as the **`ech` SvcParam (key 5)** of an HTTPS/SVCB record
(RFC 9460). Publish the line `EchKeyGen` prints. On the client side, once the application has
resolved the HTTPS record, extract the config with the out-of-core helper (no resolver is pulled
into the TLS core):

```pascal
uses TlpEchConfigFromSvcb;
if TEchConfigFromSvcb.TryFromServiceBinding(LHttpsRdata, LEchConfigList) then
  LClient.Tls13.WithEncryptedClientHello(LEchConfigList);
```

---

## 5. Interop and testing

ECH is exercised end to end against BoringSSL's BoGo conformance suite (client, server, GREASE, and
the split-mode backend role) as part of the required CI gate, and its parsers (`ECHConfigList`, the
`encrypted_client_hello` extension, and `ech_outer_extensions`) are in the structure-aware fuzz
corpus.
