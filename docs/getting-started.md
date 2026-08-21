# Getting started

**TlsLib4Pascal docs** · [Home](README.md) · Getting started · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [Security model](security-model.md)

This gets you from an empty project to a working, fully-verified TLS connection — a client and a
server — in a few minutes, on either Delphi or FPC/Lazarus. Every snippet here compiles on **both**
compilers unless noted.

## 1. Install the packages

TlsLib4Pascal's only direct dependency is [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal).
Install it first, then add TlsLib4Pascal.

**FPC / Lazarus.** Open and install (or add as a project requirement) these package files:

```
CryptoLib4Pascal/CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk
TlsLib4Pascal/TlsLib/src/Packages/FPC/TlsLib4PascalPackage.lpk
```

**Delphi.** Add the matching `.dpk`/`.dproj` under each library's `Packages/Delphi/`, or just add the
libraries `src` roots to your project search path. The core package is
`TlsLib/src/Packages/Delphi/TlsLib4PascalPackage.dpk`.

Add an **optional** package only when you use its feature:

| Want… | Add package |
|---|---|
| Verify against the OS root store | `TlsLib.Trust.System` |
| An offline PEM CA bundle (loader) | `TlsLib.Trust.Bundle` |
| Live OCSP/CRL over real sockets | the `TlpSocketHttpFetcher` unit (in `TlsLib.Net/`) |
| A mORMot / Indy / Synapse / fcl-net drop-in | the matching `TlsLib.Adapter.*` |

The core references none of these — a build that doesn't use them links none of them.

## 2. The one object everything needs: the provider

Every entry point takes an `ICryptoProvider`. The default is a plain constructed instance — there is
no global singleton to install:

```pascal
uses TlpDefaultCryptoProvider, TlpICryptoProvider;

var P: ICryptoProvider;
begin
  P := TDefaultCryptoProvider.Create as ICryptoProvider;
  // reuse P across as many configs/connections as you like; it holds no per-connection state
end;
```

Construction is cheap (a CPU-feature probe plus vtable wiring; the CSPRNG seeds lazily). Build a
config once, then share it lock-free across many connections.

## 3. Your first client (fully verified)

The fastest path is the batteries-included facade. `NewClientConfig` gives you the **Compatible**
preset wired to the trust source you pass — here, a PEM/DER CA bundle read from disk:

```pascal
uses SysUtils, Classes, TlpTlsLib, TlpITlsConfig;

function LoadFile(const APath: string): TBytes;
var LS: TFileStream;
begin
  LS := TFileStream.Create(APath, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Result, LS.Size);
    if LS.Size > 0 then LS.ReadBuffer(Result[0], LS.Size);
  finally
    LS.Free;
  end;
end;

var LConfig: ITlsClientConfig;
begin
  LConfig := TTlsLib.NewClientConfig(LoadFile('my-ca.pem'));
  // LConfig now verifies every server chain against my-ca.pem — PKIX, expiry, host-name.
end;
```

To trust the **operating system's** roots instead (the browser/`curl` behaviour), add the
`TlsLib.Trust.System` package and see [system-trust.md](system-trust.md) — it is a one-line change.

## 4. Turn a config into a connection

A config is inert. You get an engine from it, then drive bytes. The simplest driver is the Tier-2
`TTlsStream`, which speaks TLS over anything that implements the tiny `ITlsTransport` interface (two
methods — `Read` and `Write`):

```pascal
uses SysUtils, TlpITlsConfig, TlpTlsEngineFactory, TlpTlsStream, TlpITlsTransport, TlpITlsEngine;

var
  LConfig: ITlsClientConfig;   // from step 3
  LEngine: ITlsEngine;
  LStream: TTlsStream;
  MyTransport: ITlsTransport;  // your socket, wrapped behind ITlsTransport
  Request, Buf: TBytes;        // your request bytes, and a read buffer
begin
  LEngine := TTlsEngineFactory.CreateClientEngine(LConfig, 'example.com');
  LStream := TTlsStream.Create(MyTransport, LEngine, {IsClient=}True, 'example.com');
  try
    LStream.Handshake;                       // completes or raises — fail-closed
    LStream.Write(Request[0], Length(Request));
    SetLength(Buf, 4096);
    LStream.Read(Buf[0], Length(Buf));
    LStream.CloseNotify;                      // clean TLS shutdown
  finally
    LStream.Free;
  end;
end;
```

`MyTransport` is your socket wrapped behind `ITlsTransport`:

```pascal
ITlsTransport = interface(IInterface)
  function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;   // 0 = orderly EOF
  procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
end;
```

Already using **mORMot, Indy, Synapse, or fcl-net**? Skip the transport entirely — the adapter for
your stack wires all of this into the socket type you already use. See the
[integration recipes](cookbook.md#integrate-with-your-networking-stack).

## 5. Your first server

A server needs a **credential** — a certificate chain plus its private key. The facade takes them as
raw PEM/DER bytes:

```pascal
uses TlpTlsLib, TlpITlsConfig, TlpTlsEngineFactory, TlpTlsStream, TlpITlsEngine, TlpITlsTransport;

var
  LConfig: ITlsServerConfig;
  LEngine: ITlsEngine;
  LStream: TTlsStream;
  AcceptedTransport: ITlsTransport;   // an accepted socket, wrapped behind ITlsTransport
begin
  LConfig := TTlsLib.NewServerConfig(LoadFile('server-chain.pem'), LoadFile('server-key.pem'));
  // then, per accepted socket:
  LEngine := TTlsEngineFactory.CreateServerEngine(LConfig);
  LStream := TTlsStream.Create(AcceptedTransport, LEngine, {IsClient=}False, '');
  LStream.Handshake;
  // read / write / CloseNotify exactly as the client does
end;
```

If your identity is a **PKCS#12 / `.pfx`** blob instead of separate files, see the
[server-from-PKCS#12 recipe](cookbook.md#stand-up-a-server).

## 6. Verify it actually worked

After the handshake, `ConnectionInfo` tells you what was negotiated — a good smoke test that TLS 1.3
and a modern key-exchange group really engaged:

```pascal
uses SysUtils, TlpTlsStream, TlpTlsConnectionInfo;

var
  LStream: TTlsStream;         // from step 4
  LInfo: TTlsConnectionInfo;
begin
  LInfo := LStream.ConnectionInfo;
  WriteLn('version : ', IntToHex(LInfo.NegotiatedVersion.WireValue, 4));  // $0304 = TLS 1.3
  WriteLn('group   : ', IntToHex(LInfo.NamedGroup, 4));                   // $001D X25519 (default); $11EC is the X25519MLKEM768 PQ hybrid
  WriteLn('alpn    : ', LInfo.AlpnProtocol);
  WriteLn('resumed : ', BoolToStr(LInfo.Resumed, True));
end;
```

## Where to go next

- **[Cookbook](cookbook.md)** — mutual TLS, ALPN, resumption, 0-RTT, revocation, compression, the
  dangerous surface, and the integration adapters, each as a self-contained recipe.
- **[Certificate verification & trust](certificate-verification.md)** — private CAs, pinning, live
  revocation, and how our *augment-only* verify callback differs from .NET/rustls.
- **[OS system trust](system-trust.md)** — the OS root store, per platform.

## A note on safety-by-default

Three defaults are worth internalising up front, because they shape everything else:

1. **Fail-closed.** A client won't finish a handshake it can't verify, and the builder won't produce
   a client with no trust source. There is no silent-insecure mode.
2. **PQ-hybrid on by default.** Every preset offers X25519MLKEM768; you don't opt in.
3. **AEAD-only, forward-secret.** No CBC, RC4, 3DES, static RSA, or TLS compression; resumption is
   `psk_dhe_ke` (forward-secret) and 0-RTT is off unless you explicitly enable it.
