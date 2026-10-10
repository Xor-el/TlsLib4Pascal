# Certificate compression (RFC 8879)

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · Compression · [ECH](ech.md) · [Security model](security-model.md)

TlsLib4Pascal supports TLS 1.3 certificate compression (`compress_certificate`, RFC 8879) in both
directions of a handshake and in both roles. An endpoint advertises the algorithms it can
decompress, and a peer that holds a matching compressor may send its `Certificate` message
compressed. It is **on by default** with the built-in zlib backend and is most valuable for large
chains — notably post-quantum certificates, whose signatures are big. TLS 1.2 never compresses
(`compress_certificate` is a 1.3 extension, and a 1.2 peer ignores it).

## The four directions

| Who sends the compressed `Certificate` | Advertised by | Compressed with | Decompressed with |
|---|---|---|---|
| **Server** to a client | the client, in its ClientHello | the server's compressors | the client's decompressors |
| **Client** to a server (mutual TLS) | the server, in its CertificateRequest | the client's compressors | the server's decompressors |

Every endpoint therefore has two sets: the algorithms it can **decompress** (advertised) and the
ones it **compresses with** (used when the peer advertised a match). A server advertises only when
it asks for a client certificate. Both sets default to zlib in both roles, so a client certificate
is compressed by default to any server that advertises compression in its request.

Compression is configured behind the `Tls13` facet of either role builder:

```pascal
// replace the defaults with your own backends (an empty array turns that direction off)
Builder.Client.Tls13
  .WithCertificateCompressors(MyCompressors)       // my own Certificate, sent to a server
  .WithCertificateDecompressors(MyDecompressors);  // the server's Certificate, received
Builder.Server.Tls13
  .WithCertificateCompressors(MyCompressors)       // my Certificate, sent to a client
  .WithCertificateDecompressors(MyDecompressors);  // a client's Certificate (mutual TLS), received
```

A setter refuses a nil entry, the reserved codepoint 0, a codepoint listed twice, and more than 127
decompressors (all a `compress_certificate` extension can carry). To keep zlib beside your own,
include `TZlibCertificateCompression.DefaultCompressors` / `DefaultDecompressors` in the array. To
turn compression off entirely, pass an empty array in both directions.

A compressor is chosen in the **sender's** order: the first of its compressors that the peer
advertised. The message is then sent compressed whether or not it ended up smaller; RFC 8879 sets
no size rule. A `Certificate` with no entries (an endpoint declining client authentication) is
never compressed.

---

## Writing your own algorithm

Implement `ICertificateCompressor` and/or `ICertificateDecompressor` under any RFC 8879 codepoint
(the registry is open; `TCertificateCompressionAlgorithms` names zlib, brotli and zstd):

```pascal
ICertificateCompressor = interface(IInterface)
  function Algorithm: UInt16;
  function TryCompress(const AData: TBytes; out ACompressed: TBytes): Boolean;
end;

ICertificateDecompressor = interface(IInterface)
  function Algorithm: UInt16;
  function TryDecompress(const ACompressed: TBytes; AMaxLength: Int32;
    out ADecompressed: TBytes): Boolean;
end;
```

The two directions differ in how far the input can be trusted, so their contracts differ:

* **`TryCompress`** runs on your own `Certificate`. Return **False** to send it uncompressed (the
  algorithm declined it, or the backend failed in a way you caught); compression is a MAY, so that
  is always correct. Returning **True with an empty result** breaks the contract and fails the
  handshake with `internal_error`. An exception you let escape is **not** caught: it fails the
  handshake, so catch inside `TryCompress` and return False if you want to fall back on any backend
  error. A result over 2^24−1 bytes is sent uncompressed.
* **`TryDecompress`** runs on the peer's bytes. Return **False** when they cannot be decompressed:
  malformed, truncated, followed by trailing bytes, or longer than `AMaxLength` once inflated. Never
  allocate or produce more than `AMaxLength`. You need know nothing about TLS: a False **or** any
  exception becomes the `bad_certificate` alert RFC 8879 names. That includes an access violation
  in your own backend, so test it directly rather than through a handshake.

One instance is shared by every connection built from a config, so both methods must be safe to
call concurrently; a stateless implementation is.

---

## Resource safety

The decompress direction is security-sensitive and is bounded **centrally**, before and after your
backend runs, so a swapped-in algorithm inherits the same decompression-bomb defense:

| Check | Alert |
|---|---|
| Empty `compressed_certificate_message` (RFC 8879 `<1..2^24-1>`) | `decode_error` |
| Declared length outside `1..` the chain budget (`MaxTotalChainLength`) | `illegal_parameter` |
| Declared length over 100× the compressed size | `illegal_parameter` |
| An algorithm the endpoint did not advertise | `illegal_parameter` |
| A `CompressedCertificate` when none was advertised | `unexpected_message` |
| `TryDecompress` returns False or raises | `bad_certificate` |
| Result length differs from the declared length | `bad_certificate` |

The same chain budget bounds a compressed message on the wire as bounds an uncompressed one, in
both roles. The transcript always hashes the message exactly as sent or received (the compressed
form), never the decompressed body.

---

## Cross-connection compression cache

Because a certificate is usually stable, deflating it on every handshake is wasted work. Either
role can memoize that compression across connections: the cache is keyed by a `SHA-256` digest of
the algorithm code and the exact uncompressed `Certificate` bytes, so a hit returns byte-for-byte
what a fresh compress would — the cache **never changes the bytes on the wire**, it only skips the
recompute. A change that alters the message (for example a refreshed leaf OCSP staple) changes the
bytes, so the key changes and the endpoint simply recomputes; there is no stale-cache case.

The cache is **opt-in** — `nil` by default, the same posture as the session store and the session
cache, which you provision consciously (ticket keys differ: a server with resumption on mints a
default set at `Build`). Enable it by handing the config a cache:

```pascal
Builder.Server.Tls13.WithCertificateCompressionCache(
  TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache);
Builder.Client.Tls13.WithCertificateCompressionCache(  // a client presenting a stable certificate
  TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache);
```

The shipped default (`TInMemoryCertificateCompressionCache`) is:

- **shared** across every connection built from that config (that sharing is the whole point);
- **bounded** (LRU-style, small fixed capacity) and **thread-safe** (internally locked), so one
  instance is safe to hand to many concurrent connections.

Only **successful** compressions are cached. A compressor that declines (returns False) is asked
again next time, since a decline may be transient. You can also supply your own
`ICertificateCompressionCache` implementation (for example a store shared across several configs)
via the same call.

Only the endpoint's outbound `Certificate` compression is cached. Inbound **decompression is never
cached** — it is attacker-controlled, so caching it would add a cache-poisoning / bomb-amplification
surface for no benefit. There is no CRIME/BREACH-class concern here: RFC 8879 compresses only the
sender's own public certificate inside the encrypted handshake, with no attacker-chosen plaintext
mixed into the compressed stream.
