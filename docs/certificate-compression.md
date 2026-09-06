# Certificate compression (RFC 8879)

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · Compression · [ECH](ech.md) · [Security model](security-model.md)

TlsLib4Pascal supports TLS 1.3 certificate compression (`compress_certificate`, RFC 8879): an
endpoint advertises the algorithms it can decompress, and a peer that holds a matching compressor
may send its `Certificate` message compressed. It is **on by default** with the built-in zlib
backend and is most valuable for large chains — notably post-quantum certificates, whose signatures
are big. TLS 1.2 never compresses (`compress_certificate` is a 1.3 extension).

Compression is negotiated and configured behind the `.Tls13` facets. The decompress direction is
security-sensitive and is bounded centrally (declared-length ceiling, ratio guard, exact-length
match) so a swapped-in algorithm inherits the same decompression-bomb defense; the compress
direction is not on the secret path.

```pascal
// advertise / send with a custom or extra backend (defaults to zlib)
Builder.Server.Tls13
  .WithCertificateCompressors(MyCompressors)
  .WithCertificateDecompressors(MyDecompressors);
```

---

## Cross-connection compression cache

Because a server's certificate is usually stable, deflating it on every handshake is wasted work.
The server memoizes that compression across connections: the cache is keyed by a `SHA-256` digest of
the exact uncompressed `Certificate` bytes, so a hit returns byte-for-byte what a fresh compress
would — the cache **never changes the bytes on the wire**, it only skips the recompute. A change that
alters the message (for example a refreshed leaf OCSP staple) changes the bytes, so the key changes
and the server simply recomputes; there is no stale-cache case.

The cache is **opt-in** — `nil` by default, the same posture as the session store, session cache,
and ticket keys, which you provision consciously. Enable it by handing the server config a cache:

```pascal
Builder.Server.Tls13.WithCertificateCompressionCache(
  TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache); // memoize across this config's connections
```

The shipped default (`TInMemoryCertificateCompressionCache`) is:

- **shared** across every connection built from that config (that sharing is the whole point);
- **bounded** (LRU-style, small fixed capacity) and **thread-safe** (internally locked), so one
  instance is safe to hand to many concurrent connections.

Leaving it `nil` compresses on every handshake (the default). You can also supply your own
`ICertificateCompressionCache` implementation (for example a store shared across several server
configs) via the same call.

Only the server's outbound `Certificate` compression is cached. Inbound **decompression is never
cached** — it is attacker-controlled, so caching it would add a cache-poisoning / bomb-amplification
surface for no benefit. There is no CRIME/BREACH-class concern here: RFC 8879 compresses only the
sender's own public certificate inside the encrypted handshake, with no attacker-chosen plaintext
mixed into the compressed stream.
