# Handshake-only engine

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · [Compliance](compliance.md) · [Security model](security-model.md)

`ITlsHandshakeEngine` runs a TLS 1.3 handshake for a **host that owns record protection and the key
lifecycle**: a transport that frames, protects and numbers its own packets (the arrangement RFC 9001
describes) and wants TLS only for the handshake. The engine exchanges handshake messages per
encryption level and hands the host the traffic secrets. It holds no traffic keys, so it never seals
or opens a record.

The engine uses the same state machines, key schedule, extension codec, certificate pipeline, ECH,
resumption and crypto provider as `ITlsEngine`. A provider overlay or a compliance gate configured on
the config applies to every key operation here as it does there.

## What follows from the host owning records

- No `change_cipher_spec`, and an empty `legacy_session_id` (a server fails a ClientHello that carries
  one). Both exist to disguise the handshake as an earlier TLS version in a record stream.
- No `EndOfEarlyData`: the host delimits early data. A received one is `unexpected_message`.
- No `KeyUpdate`: the host rekeys. A received one is `unexpected_message`.
- No `record_size_limit`: a client does not offer it, a server ignores an offered one.
- No alerts on the wire. A failure is reported through `LastError`; for an alert a record engine would
  have sent, `Origin` is `Local` and the alert says which. For a failure TLS has no alert for (a
  ClientHello with a session id, a ticket whose early-data limit is not the host's) `Origin` is
  `LocalWithoutAlert` and the alert is a placeholder.
- TLS 1.3 only: per-level secrets are a TLS 1.3 idea. A config that offers TLS 1.2, or no TLS 1.3, is
  refused at creation.

## Creating one

```pascal
LClient := TTlsEngineFactory.CreateHandshakeClientEngine(LClientConfig, 'example.com',
  LHostExtensions, LTicketEarlyDataLimit);
LServer := TTlsEngineFactory.CreateHandshakeServerEngine(LServerConfig, LHostExtensions,
  LTicketEarlyDataLimit, LEarlyDataContext);
```

`LTicketEarlyDataLimit` is the early-data budget the host fixes for its tickets. A server that has
early data enabled in its config writes exactly this value into every NewSessionTicket (the config's
own budget is not used); a client fails the handshake, without an alert, on a ticket that advertises
any other non-zero value. A non-empty `LEarlyDataContext` replaces the config's early-data context.

Host extensions (`ITlsHostExtension`), the early-data context and session application data
(`ITlsSessionApplicationData`, client only) work as they do on `ITlsEngine`; the engine answers
`ITlsHostExtensionResults` for the peer's bodies.

## Driving it

Everything is pull. The host feeds the bytes of one level, then drains the outputs and the events.

```pascal
LClient.StartHandshake;
repeat
  while LClient.NextOutput(LOutput) do
    case LOutput.Kind of
      THandshakeOutputKind.HandshakeData:  Send(LOutput.Level, LOutput.Data);
      THandshakeOutputKind.ReadSecret:     InstallRead(LOutput.Level, LOutput.Secret);
      THandshakeOutputKind.WriteSecret:    InstallWrite(LOutput.Level, LOutput.Secret);
      THandshakeOutputKind.HandshakeComplete: ...
    end;
  // bytes arrive from the peer at ALevel
  LClient.ProvideHandshakeData(ALevel, ABytes, 0, Length(ABytes));
until LClient.IsTerminal or not LClient.IsHandshaking;
```

- Levels are `Plaintext`, `EarlyData`, `Handshake` and `Application`. `Plaintext` carries no secret.
- `ProvideHandshakeData` accepts bytes only at the level the engine reads now: `Plaintext` until the
  first read secret, then the level of the latest `Handshake` or `Application` read secret. Bytes at
  any other level, or a handshake message that straddles a change of read level, fail with
  `unexpected_message`. Keep data that arrives early for a later level and feed it when that level
  is reached.
- The outputs come in the order the handshake produced them. A secret belongs to the host from the
  moment it is taken (`ITrafficSecret`, wiped when released); the engine keeps no copy of an
  application secret.
- Client order: `ClientHello` at Plaintext, the early write secret when 0-RTT is offered, the
  handshake secrets at the ServerHello, then its Finished at Handshake, the application write and
  read secrets, and `HandshakeComplete`.
- Server order: the ServerHello at Plaintext, the handshake secrets (and the early read secret when
  it accepts 0-RTT), its flight at Handshake, the application write secret at its Finished. The
  application read secret is queued only after the client Finished verified.
- `HandshakeComplete` follows every other output of the step that completed the handshake.
- After a failure `NextOutput` returns nothing; read `LastError`.

## Checks between input and output

No host code runs inside a call, so the host can look at the state before it sends anything: after
`ProvideHandshakeData` returns, `ConnectionInfo` shows the selected ALPN protocol and
`ITlsHostExtensionResults` the peer's host extension bodies, before any output is taken. A host that
rejects the connection at that point stops there and reports the failure itself. Those values are
unauthenticated until the handshake completes.

## Tickets

A ticket minted by this engine carries its engine kind and resumes only on a handshake-only engine,
and a record engine's ticket is never offered to or accepted by this one, so a budget the host fixed
never becomes a record engine's early-data window. A client cache keeps the kinds under separate keys.

## Not provided

Post-handshake client authentication is not offered. A CertificateRequest after the handshake is
`unexpected_message`. TLS 1.2 and DTLS are out of scope.
