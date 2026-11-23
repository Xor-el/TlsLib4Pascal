# TLS 1.3 handshake-only engine

**TlsLib4Pascal docs** · [Home](README.md) · [Getting started](getting-started.md) · [Cookbook](cookbook.md) · [Verification](certificate-verification.md) · [System trust](system-trust.md) · [Compression](certificate-compression.md) · [ECH](ech.md) · [Compliance](compliance.md) · [Security model](security-model.md)

`ITls13HandshakeEngine` runs a TLS 1.3 handshake for a **host that owns record protection and the key
lifecycle**: a transport that frames and protects its own data (the arrangement RFC 9001 describes)
and wants TLS only for the handshake. The engine exchanges handshake messages per
encryption level and hands the host the traffic secrets. It holds no traffic keys, so it never seals
or opens a record.

`ITls13HandshakeEngine` inherits `ITlsCommonEngine`, as `ITlsEngine` does: starting the handshake, status,
the certificate verdict, events, connection facts and the exporters are the same calls on both.

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
LClient := TTlsEngineFactory.CreateTls13HandshakeClientEngine(LClientConfig, 'example.com',
  LHostExtensions, LTicketEarlyDataLimit);
LServer := TTlsEngineFactory.CreateTls13HandshakeServerEngine(LServerConfig, LHostExtensions,
  LTicketEarlyDataLimit, LEarlyDataContext);
```

Two overloads add what a service that shares one configuration needs: the client takes a trailing
resumption partition, the server a resumption scope and the ClientHello pause (see
[Resumption partition and scope](#resumption-partition-and-scope) and
[Pausing at the ClientHello](#pausing-at-the-clienthello)).

```pascal
LClient := TTlsEngineFactory.CreateTls13HandshakeClientEngine(LClientConfig, 'example.com',
  LHostExtensions, LTicketEarlyDataLimit, LPartition);
LServer := TTlsEngineFactory.CreateTls13HandshakeServerEngine(LServerConfig, LHostExtensions,
  LTicketEarlyDataLimit, LEarlyDataContext, LScope, {APauseAtClientHello=} True);
```

`LTicketEarlyDataLimit` is the early-data budget the host fixes for its tickets. A server that has
early data enabled in its config writes exactly this value into every NewSessionTicket (the config's
own budget is not used, though `WithEarlyData` must still be below 1 MiB); a limit of 0 turns the
server's 0-RTT off. Any client engine fails the
connection, without an alert, on a ticket that advertises any other value, an explicit 0
included; a client with no session cache otherwise ignores tickets. A limit of 0 leaves the
client's check off, so a host that offers 0-RTT passes the value its tickets must carry.
`LEarlyDataContext` is the early-data context the server's tickets carry and 0-RTT must match. It
is the only source: a config with its own early-data context (a record-engine setting) is refused,
and the context is sealed only while 0-RTT is on. It is at most 255 bytes.

Host extensions (`ITlsHostExtension`) and session application data (`ITlsSessionApplicationData`,
client only) work as they do on `ITlsEngine`; the engine answers `ITlsHostExtensionResults` for the
peer's bodies.

## Driving it

Everything is pull. The host feeds the bytes of one level, then drains the outputs and the events.
`ProvideHandshakeData` returns `Advanced` when it queued an output or an event, `NeedMoreInput` when
it needs more bytes, and `Fatal` once the engine failed.

```pascal
LClient.StartHandshake;
repeat
  // drain after every feed, so the step that completes the handshake is not left in the queue
  while LClient.NextOutput(LOutput) do
    case LOutput.Kind of
      TTls13HandshakeOutputKind.HandshakeData:  Send(LOutput.Level, LOutput.Data);
      TTls13HandshakeOutputKind.ReadSecret:     InstallRead(LOutput.Level, LOutput.Secret);
      TTls13HandshakeOutputKind.WriteSecret:    InstallWrite(LOutput.Level, LOutput.Secret);
      TTls13HandshakeOutputKind.HandshakeComplete: ...
    end;
  if LClient.IsTerminal then
    Break;
  // bytes arrive from the peer at ALevel
  LClient.ProvideHandshakeData(ALevel, ABytes, 0, Length(ABytes));
until False;
```

After `HandshakeComplete` the server's NewSessionTicket messages still arrive at the Application
level; feed them the same way.

- Levels are `Plaintext`, `EarlyData`, `Handshake` and `Application`. `Plaintext` carries no secret.
- `ReadLevel` is the level the next `ProvideHandshakeData` must use. It starts at `Plaintext` and
  moves when a `Handshake` or `Application` read secret is queued, before the host takes that
  secret from `NextOutput`; it is never `EarlyData`.
- `ProvideHandshakeData` accepts bytes only at the level the engine reads now (`ReadLevel`):
  `Plaintext` until the first read secret, then the level of the latest `Handshake` or `Application`
  read secret. Bytes at
  any other level, or a handshake message that straddles a change of read level, fail with
  `unexpected_message`. Keep data that arrives early for a later level and feed it when that level
  is reached. Handshake bytes at the `EarlyData` level fail the same way; a host whose transport
  forbids them there maps that failure or refuses the bytes before feeding them.
- The outputs come in the order the handshake produced them. A secret is a copy that belongs to the
  host from the moment it is taken (`ITrafficSecret`, wiped when released). The engine forgets its
  own application traffic secrets as it hands them out, since the host rekeys; the handshake
  secrets are released when the handshake completes.
- The host enforces the early-data budget (the engine neither bounds nor skips early data), and on
  an `EarlyDataRejected` event, also after a retry, it discards the early data and the early write
  key: nothing reverts a write level.
- A NewSessionTicket count restarts with each `ProvideHandshakeData` call, so a long-lived
  connection may receive tickets without limit.
- Client order: `ClientHello` at Plaintext, the early write secret when 0-RTT is offered, the
  handshake secrets at the ServerHello, then its Finished at Handshake, the application write and
  read secrets, and `HandshakeComplete`.
- Server order: the ServerHello at Plaintext, the handshake secrets (and the early read secret when
  it accepts 0-RTT), its flight at Handshake, the application write secret at its Finished. The
  application read secret is queued only after the client Finished verified.
- `HandshakeComplete` follows every other output of the step that completed the handshake.
- After a failure `LastError` says why. When the failure has an alert, everything queued up to the
  last handshake bytes stays pullable, plus every write secret queued after them; the rest is
  dropped. After any other failure `NextOutput` returns nothing.

## Error causes

`LastError.Cause` (`TTlsErrorCause`) tells apart failures that share an alert. Only this engine
reports one; a record engine always reports `Unspecified`.

| Cause | When | Alert |
|---|---|---|
| `Unspecified` | Every other failure, and every failure with no cause recorded. | any |
| `DataAfterReadLevelChange` | Handshake bytes follow the message that moved the read level, so they belong to the next level but arrived at the current one (RFC 9846 5.1). | `unexpected_message` |
| `UnrequestedPostHandshakeAuthentication` | A client receives a CertificateRequest after the handshake, which it never offered (RFC 9846 4.7.2). | `unexpected_message` |

## Resumption partition and scope

Services that share one configuration, and so one session cache or ticket key, keep their tickets
apart with a tag of their own.

- **Client partition.** The client factory overload takes a partition of at most 32 bytes. The
  ticket the engine offers is the one cached under that partition, and tickets it receives are
  cached under it. `ITlsResumptionPartition` (`Supports` on the engine) changes the partition tickets
  received from then on are stored under; the ticket offered stays the creation one. An empty
  partition is the unpartitioned key, which the overload without one uses. A longer one raises
  `EArgumentTlsLibException`.
- **Server scope.** The server factory overload takes a scope of at most 32 bytes, and
  `ContinueAfterClientHello` can replace it. A non-empty scope is combined with the configuration's
  scope, and the engine accepts and seals tickets only under the combination. The combination
  cannot equal any configuration scope, so an engine with a scope never resumes a ticket another
  configuration or an engine without one minted, and engines with different scopes never resume
  each other's tickets. An empty scope leaves the configuration's alone.

## Pausing at the ClientHello

A host that picks what to answer from what the client offered (a server name, an extension) creates
the server engine with `APauseAtClientHello`. Without it the engine answers a ClientHello as it
arrives, and `AwaitingClientHello` is always `False`, as on a client.

The engine parks once it decrypted an ECH ClientHello and validated the ClientHello, before it
selects a credential, a suite or a group, resumes a ticket, or decides on a HelloRetryRequest. The
`ProvideHandshakeData` call that parks returns `Advanced` with a `ClientHelloReceived` event. While
parked the engine queues no output; bytes fed meanwhile at `ReadLevel` are held, and nothing may
follow the ClientHello before the continue (a message held behind it fails the handshake when the
engine continues, as bytes after the ClientHello do without the pause). 0-RTT records that arrive
while parked are kept by the host until the continue queues the early read secret.

```pascal
if LServer.AwaitingClientHello then
begin
  LName := LServer.OfferedServerName;
  LServer.ContinueAfterClientHello(LReplies, LScope);
end;
```

- `OfferedServerName` is the server name the ClientHello offered, empty when it offered none. It and
  the offered extension bodies (`ITlsHostExtensionResults`) are unauthenticated. When ECH was
  rejected they come from the outer ClientHello.
- `ContinueAfterClientHello` takes one reply per registered server host extension the client
  offered that the host wants sent. The reply body replaces the body the extension was registered
  with, and is sent wherever the extension rides. An offered extension without a reply is not
  sent; with no pause the registered body is sent as before. A reply for an extension the client
  did not offer, two replies for one extension, a body over 65535 bytes or a scope over 32 bytes
  raises `EArgumentTlsLibException` and leaves the engine parked.
- The scope is the server scope above. Empty keeps the one the engine was created with.
- The continue then selects and answers. A selection failure is reported through `LastError` as
  any other, and the credential resolver runs inside the call. It is a no-op when the engine is not
  parked, is terminal, or is a client, and raises `EInvalidOperationTlsLibException` from inside a
  callback.
- A host that refuses the connection while parked calls `LatchTransportFailure`, which ends the
  engine; nothing was selected or minted.
- After a HelloRetryRequest the second ClientHello does not pause. On a pausing engine it must
  repeat the first one's offer of each registered host extension, body included, and the engine
  fails it with `illegal_parameter` otherwise (RFC 9846 4.2.2). An extension the HelloRetryRequest
  itself carried may change its body but not be dropped. After a retry the host-extension results
  show the second ClientHello's body, while the reply given at the pause stands.
- Ticket expiry, freshness and the 0-RTT replay check are judged when the engine continues: the
  pause counts toward the ticket age, so a long pause declines 0-RTT, and the resumption still goes ahead.

## Checks between input and output

No host extension callback runs inside a call. The callbacks the config names (a verify callback, a
credential resolver, a session cache, a key log) still do, a resolver on a server also inside
`ContinueAfterClientHello`. The host can look at the state before it sends anything: after
`ProvideHandshakeData` returns, `ConnectionInfo` shows the selected ALPN protocol and
`ITlsHostExtensionResults` the peer's host extension bodies, before any output is taken. A host that
rejects the connection at that point stops there and reports the failure itself. Those values are
unauthenticated until the handshake completes. The engine keeps the RFC 7301 rules, so it accepts a
handshake that selects no ALPN protocol; a host that requires one fails the connection with
`no_application_protocol` when `ConnectionInfo` reports none, on either side.

## Tickets

A ticket minted by this engine carries its engine kind and resumes only on a TLS 1.3 handshake-only engine,
and a record engine's ticket is never offered to or accepted by this one, so a budget the host fixed
never becomes a record engine's early-data window. A client cache keeps the kinds under separate keys.

## Not provided

Post-handshake client authentication is not offered. A CertificateRequest after the handshake is
`unexpected_message`. TLS 1.2 and DTLS are out of scope.
