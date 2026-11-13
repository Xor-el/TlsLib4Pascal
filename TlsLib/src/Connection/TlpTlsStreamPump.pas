{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsStreamPump;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  TlpTlsAlert,
  TlpTlsAlertProtocol,
  TlpTlsError,
  TlpTlsLibExceptions,
  TlpEchConfig,
  TlpTrustPolicy,
  TlpTlsConnectionInfo,
  TlpHandshakeMessages,
  TlpITlsEngine,
  TlpITlsEngineInbound,
  TlpITlsEngineOutbound,
  TlpITlsTransport;

type
  /// <summary>How a single application read cycle ended.</summary>
  TTlsReadStatus = (
    Data,        // plaintext was produced (the returned count is > 0)
    CleanEof,    // the peer sent close_notify: an orderly end of stream
    Truncated);  // the transport closed without close_notify: a possible truncation

  /// <summary>
  /// Drives one sans-IO engine over a blocking ITlsTransport, and is the only code that touches
  /// that engine while a connection is in use. It owns two locks, taken after the caller's
  /// handshake side (around DriveHandshake) or read side (around ReadApp), in the order W, then E:
  /// E guards every engine call, and so every seal, and is never held across transport I/O; W is
  /// held by whoever sends, so wire order is seal order; the reader, Close and Abort only try W
  /// and never wait for it, and every release of W is followed by a recheck for bytes another
  /// thread left owed. After the handshake the inbound calls never seal: a fatal alert that the
  /// input makes owed is sealed and sent by whoever next wins W, bounded by the close grace on a
  /// timed transport. A fatal outcome raises ETlsStreamError; a transport EOF mid-handshake raises
  /// ETlsTransportTruncated. ReadApp and DriveHandshake must each be called by one thread at a
  /// time, and ReadApp only once the handshake has completed; the other members may be called
  /// from any thread. ReadApp, ReadEarlyData, WriteApp, RequestKeyUpdate and CloseWriteSide raise
  /// EInvalidOperationTlsLibException when called by code that ReadApp is running (a callback).
  /// E is re-entrant: a callback inside an engine call takes it again, so it must stay a recursive
  /// lock.
  /// </summary>
  TTlsStreamPump = class sealed(TObject)
  public
  const
    // one TLS record's plaintext never exceeds 2^14; a 16 KiB transport read comfortably
    // holds a framed record and lets the record layer reassemble across reads
    TransportChunk = Int32(16384);
    // the most plaintext WriteApp seals before draining to the transport: four max-size
    // records, the record layer's retained outbound capacity, so a chunked bulk write never
    // regrows the outbound buffer and holds at most one slice of ciphertext at a time
    WriteChunk = Int32(4 * 16384);
  strict private
  type
    THandshakeState = (Idle, Running, Complete);
    // what a close or refusal asked for while the handshake was running
    TDeferredClose = (NotDeferred, DeferredNotify, DeferredAlert);
  var
    FInbound: ITlsEngineInbound;
    FOutbound: ITlsEngineOutbound;
    FTransport: ITlsTransport;
    FTimed: ITlsTimedTransport;
    FCloseGraceMs: Int32;
    // E guards every engine call, FWriteClosed, FDeferredClose and every write of FHandshakeState
    FEngineLock: TCriticalSection;
    // W guards FSendBuffer, FWriteChunk and the right to take bytes from the engine and send them
    FWriteLock: TCriticalSection;
    FHandshakeState: THandshakeState; // lock-free reads are hints; Complete is final
    // set under E for the length of a read's engine calls, so only the thread inside them sees True
    FInboundCall: Boolean;
    FWriteClosed: Boolean;
    FDeferredClose: TDeferredClose;
    FDeferredAlert: TTlsAlertDescription;
    FReadBuffer: TBytes; // the caller's read side
    FSendBuffer: TBytes;
    FWriteChunk: TBytes;
    /// <summary>Whether the engine is terminal, read under E.</summary>
    function EngineIsTerminal: Boolean;
    /// <summary>Sends every byte the engine owes; the caller holds W. A transport failure
    /// latches the engine (no alert, sessions kept), discards what it still owed, and raises
    /// unchanged. Nothing is ever sent after a partial send.</summary>
    procedure SendPending;
    /// <summary>As SendPending, bounded by the close grace on a timed transport; the deadline is
    /// armed only while W is held and cleared before the caller releases it.</summary>
    procedure SendPendingBounded;
    /// <summary>As SendPendingBounded, swallowing every failure: the caller is already
    /// surfacing its own error, or has data to return, that a transport error must not mask.
    /// The engine is latched on a failure.</summary>
    procedure SendPendingQuietly;
    /// <summary>Leaves W, then sends what another thread queued while this one held it: the
    /// recheck that keeps a record from being stranded. Quiet and bounded, since only control
    /// records can be owed once W is free.</summary>
    procedure ReleaseWrite;
    /// <summary>Sends what the engine owes if W is free, and returns at once if it is not (the
    /// holder sends it in its recheck).</summary>
    procedure FlushIfIdle(ARaise: Boolean);
    /// <summary>Sends what the engine queued; a transport failure raises while it is live and is
    /// swallowed once it is terminal. The caller holds W.</summary>
    procedure FlushPending;
    /// <summary>Flushes, then raises if the engine is terminal. The flush comes first so the
    /// fatal alert a failed ProcessInput/Write made owed reaches the peer before the error surfaces
    /// here (the peer then reads an alert, not a truncation); once terminal it is best-effort.</summary>
    procedure FlushThenRaiseIfFatal;
    /// <summary>Seals one slice of FWriteChunk; the caller holds W. Stops at a terminal or
    /// closed engine, sending what it owes first.</summary>
    procedure SealSlice(ALength: Int32);
    procedure RunHandshake(AIsClient: Boolean;
      const AResolveVerdict: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
    /// <summary>Raises the engine's terminal failure as the precise TLS error (its alert), or after
    /// a transport failure as an ETlsStreamError with no alert; a no-op while it is live.</summary>
    class procedure RaiseIfFatal(const AEngine: ITlsEngineInbound); static;
    /// <summary>Whether the engine ended because the peer sent close_notify before the handshake
    /// completed; that is a truncation for the caller, not a fatal alert.</summary>
    class function PeerClosedDuringHandshake(const AEngine: ITlsEngineInbound): Boolean; static;
    /// <summary>DrainEvents for the stream: a peer fatal alert raises ETlsStreamError with its
    /// description (internal_error for an unmapped code); reports a clean peer close via
    /// APeerClosed and captures a parked-certificate event, and returns True on a clean close.</summary>
    class function DrainEventsOrRaise(const AEngine: ITlsEngineInbound; out APeerClosed: Boolean;
      out ACertEvent: ICertificateReceivedEvent): Boolean; static;
    /// <summary>The verdict for a parked chain, decided without touching the engine, so no lock is
    /// held while a resolver runs.</summary>
    class procedure DecideVerdict(const ACertEvent: ICertificateReceivedEvent;
      const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole;
      ADeadlineMs: Cardinal; out AAccept: Boolean; out AAlert: TTlsAlertDescription); static;
  public
    /// <summary>Wraps a ready engine, which must expose both engine faces, and a transport.
    /// ACloseGraceMs bounds each terminal send (a fatal alert, close_notify) on a timed transport;
    /// zero or less leaves it unbounded.</summary>
    constructor Create(const AEngine: ITlsEngine; const ATransport: ITlsTransport;
      ACloseGraceMs: Int32);
    /// <summary>Releases the locks. No call may be running or follow.</summary>
    destructor Destroy; override;
    /// <summary>Sets the close grace (see Create). Only before the handshake has started: the
    /// sends that read it hold W, which is not taken here.</summary>
    procedure SetCloseGraceMs(AMs: Int32);
    /// <summary>Drains the engine's event queue: reports a peer fatal alert (APeerAlert, nil when
    /// none) and a peer close_notify (APeerClosed), and captures a parked-certificate event so a
    /// resolver can decide the verdict. Never raises; the caller maps a terminal event to its own
    /// signalling. Returns True when a terminal event was seen.</summary>
    class function DrainEvents(const AEngine: ITlsEngineInbound; out APeerAlert: IPeerAlertEvent;
      out APeerClosed: Boolean; out ACertEvent: ICertificateReceivedEvent): Boolean; static;
    /// <summary>Resolves a parked peer-certificate verdict through AResolveVerdict on the captured
    /// park event; fail-closed with certificate_unknown when there is no resolver or no captured
    /// chain (an unspecified acceptability problem, not a corrupt certificate). Sets the verdict on
    /// the engine only: the caller flushes the resumed flight, or the abort alert of a reject, and
    /// surfaces a terminal outcome its own way.</summary>
    class procedure ResolveVerdict(const AEngine: ITlsEngine;
      const ACertEvent: ICertificateReceivedEvent;
      const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole); overload; static;
    /// <summary>As above, handing the resolver ADeadlineMs as its time budget (0 = none set).</summary>
    class procedure ResolveVerdict(const AEngine: ITlsEngine;
      const ACertEvent: ICertificateReceivedEvent;
      const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole;
      ADeadlineMs: Cardinal); overload; static;
    /// <summary>Runs the handshake to completion, holding W throughout; a no-op once it has
    /// completed. A client sends its opening flight first (StartHandshake); a server waits for the
    /// ClientHello. Raises on failure. A close or refusal asked for meanwhile takes effect the
    /// moment the handshake completes (see Close and Abort). This overload has no resolver, so with
    /// async certificate verdicts enabled a parked verdict fails closed with certificate_unknown;
    /// use the resolver overload to decide it out-of-band.</summary>
    procedure DriveHandshake(AIsClient: Boolean); overload;
    /// <summary>Runs the handshake to completion, resolving any parked peer-certificate
    /// verdict through AResolveVerdict (a nil resolver fails such a park closed) with E released.
    /// With async verdicts disabled the handshake never parks and this behaves exactly like the
    /// plain overload.</summary>
    procedure DriveHandshake(AIsClient: Boolean;
      const AResolveVerdict: TCertificateVerdictResolver); overload;
    /// <summary>As above, handing the resolver ADeadlineMs as its time budget (0 = none set).</summary>
    procedure DriveHandshake(AIsClient: Boolean;
      const AResolveVerdict: TCertificateVerdictResolver; ADeadlineMs: Cardinal); overload;
    /// <summary>Raises when the calling thread is inside a read's engine calls, where a callback
    /// that wrote, rekeyed or closed could wait on a writer that waits for E; it holds E while it
    /// checks, so any other thread waits instead of seeing the flag.</summary>
    procedure RaiseIfInboundCall;
    /// <summary>One application read cycle: drains engine-buffered plaintext (which may have
    /// arrived coalesced with the final handshake flight) before blocking on the transport.
    /// Returns the count copied into ADest and, via AStatus, whether more may follow, the
    /// peer closed cleanly, or the transport was truncated. Never waits for W: when the input
    /// made the engine terminal it sends the owed alert only if W is free.</summary>
    function ReadApp(var ADest: TBytes; AMaxLength: Int32; out AStatus: TTlsReadStatus): Int32;
    /// <summary>The server's accepted 0-RTT bytes, copied into ADest; 0 when none remain.</summary>
    function ReadEarlyData(var ADest: TBytes; AMaxLength: Int32): Int32;
    /// <summary>Encrypts and sends ACount bytes, sealing and draining at most WriteChunk bytes per
    /// iteration so a bulk write never holds its whole ciphertext in memory. Holds W for the whole
    /// call, so concurrent writes are never interleaved. At the AEAD usage limit with no rekey
    /// available the engine's close_notify is still sent before ERecordLimitTlsLibException
    /// propagates. A transport failure ends the connection: its exception propagates and later
    /// calls raise the latched error.</summary>
    procedure WriteApp(const ABuffer; ACount: Int32); overload;
    /// <summary>As above, ending the call with ETlsWriteTimeout when it has not finished within
    /// AWriteTimeoutMs in total (zero or less = block). The deadline is armed once W is held and
    /// cleared before it is released, so it never bounds another sender; the transport must be an
    /// ITlsTimedTransport.</summary>
    procedure WriteApp(const ABuffer; ACount: Int32; AWriteTimeoutMs: Int32); overload;
    /// <summary>Sends a TLS 1.3 KeyUpdate and the reply owed to the peer's, waiting for W like a
    /// write; raises when the connection has failed or its write side is closed.</summary>
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    /// <summary>Seals close_notify and sends it if W is free; a busy writer sends it in its
    /// recheck, so it can still be unsent when this returns. A transport failure raises as for
    /// SendPending; a send past the close grace raises ETlsWriteTimeout. While the handshake is
    /// running it only records the request: the handshake thread sends close_notify as it
    /// completes, and a failure of that send latches the engine without raising there.</summary>
    procedure Close;
    /// <summary>Sends a fatal alert (the engine goes terminal), best effort and without waiting
    /// for W: used when the local host refuses a connection. While the handshake is running it
    /// only records the refusal: the handshake thread sends the alert as the handshake completes,
    /// so the connection never goes live.</summary>
    procedure Abort(ADescription: TTlsAlertDescription);
    /// <summary>Marks the write side closed; True when it was open on a running or completed
    /// handshake, so close_notify or an alert is owed. Before the handshake it only latches the
    /// flag, which a later write reports.</summary>
    function CloseWriteSide: Boolean;
    /// <summary>Whether CloseWriteSide has closed the write side.</summary>
    function WriteSideClosed: Boolean;
    /// <summary>Whether the handshake has completed, read without a lock: a hint that never
    /// blocks, which may lag a completion in progress.</summary>
    function IsHandshakeComplete: Boolean;
    /// <summary>Whether a handshake is running, read without a lock. Exact for a caller serialised
    /// with DriveHandshake: only the thread inside it sees True.</summary>
    function IsHandshakeRunning: Boolean;
    /// <summary>Whether the handshake has completed, confirmed under E when the lock-free read says
    /// no. A thread deciding whether it must wait for the handshake uses this one.</summary>
    function ConfirmHandshakeComplete: Boolean;
    /// <summary>Raises the engine's terminal failure as the precise TLS error, or after a
    /// transport failure as an ETlsStreamError with no alert, when it is in a fatal state; a no-op
    /// otherwise. Lets a caller re-surface a latched handshake failure with what the engine
    /// recorded.</summary>
    procedure RaiseFailure;
    /// <summary>The negotiated facts. Zero values at once while the handshake runs, so a thread
    /// polling during a slow certificate check is not stalled; the engine's own after it, even a
    /// failed one.</summary>
    function ConnectionInfo: TTlsConnectionInfo;
    /// <summary>Decrypted application bytes buffered and readable without the transport; 0 at once
    /// while the handshake runs.</summary>
    function PendingAppData: Int32;
    function ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
  end;

implementation

resourcestring
  SPeerFatalAlert = 'the peer sent a fatal alert';
  STruncatedHandshake = 'the transport closed during the handshake without close_notify ' +
    '(after %d handshake bytes from the peer)';
  SClosedDuringHandshake = 'the peer closed the connection during the handshake';
  SWriteAfterClose = 'a write was attempted after the connection was closed';
  SEarlyDataUnread = 'accepted 0-RTT data is waiting: read it with ReadEarlyData before Read';
  SInboundCallReentry = 'a callback a read runs cannot read, write, rekey, close or send an ' +
    'alert on the stream that is reading';
  SCloseGraceAfterHandshake = 'the close grace can only be set before the handshake starts';
  SPumpArguments = 'a pump needs a transport and an engine that exposes both engine faces ' +
    '(pass both, not nil)';

{ TTlsStreamPump }

constructor TTlsStreamPump.Create(const AEngine: ITlsEngine; const ATransport: ITlsTransport;
  ACloseGraceMs: Int32);
begin
  inherited Create;
  FEngineLock := TCriticalSection.Create;
  FWriteLock := TCriticalSection.Create;
  if (ATransport = nil) or not Supports(AEngine, ITlsEngineInbound, FInbound) or
    not Supports(AEngine, ITlsEngineOutbound, FOutbound) then
    raise EArgumentTlsLibException.CreateRes(@SPumpArguments);
  FTransport := ATransport;
  FCloseGraceMs := ACloseGraceMs;
  // a transport that cannot bound a send leaves terminal sends unbounded
  Supports(ATransport, ITlsTimedTransport, FTimed);
end;

destructor TTlsStreamPump.Destroy;
begin
  FWriteLock.Free;
  FEngineLock.Free;
  inherited Destroy;
end;

procedure TTlsStreamPump.SetCloseGraceMs(AMs: Int32);
begin
  FEngineLock.Enter;
  try
    if FHandshakeState <> THandshakeState.Idle then
      raise EInvalidOperationTlsLibException.CreateRes(@SCloseGraceAfterHandshake);
    FCloseGraceMs := AMs;
  finally
    FEngineLock.Leave;
  end;
end;

class procedure TTlsStreamPump.RaiseIfFatal(const AEngine: ITlsEngineInbound);
var
  LInfo: TTlsConnectionInfo;
begin
  if not AEngine.IsTerminal then
    Exit;
  if PeerClosedDuringHandshake(AEngine) then
    raise ETlsTransportTruncated.CreateRes(@SClosedDuringHandshake);
  // a client's ECH reject aborts with ech_required (RFC 9849 sec. 6.1.6); surface the
  // retry_configs and the retry flag through a typed exception so the application can decide to
  // reconnect. keyed on the abort itself, not EchStatus - a server reads Rejected after a benign
  // GREASE handshake that completed, so a later fatal there must surface as its true error
  LInfo := AEngine.ConnectionInfo;
  if LInfo.EchRejectAborted then
    raise EEchRejectedTlsLibException.Create(LInfo.EchRetryConfigs,
      LInfo.EchIsRetryAttempt);
  raise ETlsStreamError.Create(AEngine.LastError);
end;

procedure TTlsStreamPump.RaiseFailure;
begin
  FEngineLock.Enter;
  try
    RaiseIfFatal(FInbound);
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.EngineIsTerminal: Boolean;
begin
  FEngineLock.Enter;
  try
    Result := FOutbound.IsTerminal;
  finally
    FEngineLock.Leave;
  end;
end;

procedure TTlsStreamPump.RaiseIfInboundCall;
begin
  FEngineLock.Enter;
  try
    if FInboundCall then
      raise EInvalidOperationTlsLibException.CreateRes(@SInboundCallReentry);
  finally
    FEngineLock.Leave;
  end;
end;

procedure TTlsStreamPump.SendPending;
var
  LGot: Int32;
begin
  try
    repeat
      FEngineLock.Enter;
      try
        LGot := 0;
        if FOutbound.WantsWrite then
        begin
          if System.Length(FSendBuffer) < TransportChunk then
            SetLength(FSendBuffer, TransportChunk);
          LGot := FOutbound.TakeOutgoing(FSendBuffer, 0);
        end;
      finally
        FEngineLock.Leave;
      end;
      if LGot > 0 then
        FTransport.Write(FSendBuffer, 0, LGot);
    until LGot = 0;
  except
    // Write reports no progress on a raise: nothing queued can follow it intact
    on E: Exception do
    begin
      FEngineLock.Enter;
      try
        FOutbound.LatchTransportFailure(E.Message);
      finally
        FEngineLock.Leave;
      end;
      raise;
    end;
  end;
end;

procedure TTlsStreamPump.SendPendingBounded;
begin
  if (FTimed = nil) or (FCloseGraceMs <= 0) then
  begin
    SendPending;
    Exit;
  end;
  FTimed.SetWriteTimeout(FCloseGraceMs);
  try
    SendPending;
  finally
    FTimed.SetWriteTimeout(0);
  end;
end;

procedure TTlsStreamPump.SendPendingQuietly;
begin
  try
    SendPendingBounded;
  except
    // best effort: the caller's own error or data takes precedence
  end;
end;

procedure TTlsStreamPump.ReleaseWrite;
var
  LOwed: Boolean;
begin
  FWriteLock.Leave;
  repeat
    FEngineLock.Enter;
    try
      LOwed := FOutbound.WantsWrite;
    finally
      FEngineLock.Leave;
    end;
    // a holder that wins W instead rechecks after its own release
    if (not LOwed) or (not FWriteLock.TryEnter) then
      Exit;
    try
      SendPendingQuietly;
    finally
      FWriteLock.Leave;
    end;
  until False;
end;

procedure TTlsStreamPump.FlushIfIdle(ARaise: Boolean);
begin
  if not FWriteLock.TryEnter then
    Exit;
  try
    if ARaise then
      SendPendingBounded
    else
      SendPendingQuietly;
  finally
    ReleaseWrite;
  end;
end;

procedure TTlsStreamPump.FlushPending;
begin
  if EngineIsTerminal then
    SendPendingQuietly
  else
    SendPending;
end;

procedure TTlsStreamPump.FlushThenRaiseIfFatal;
begin
  FlushPending;
  RaiseFailure;
end;

class function TTlsStreamPump.DrainEvents(const AEngine: ITlsEngineInbound;
  out APeerAlert: IPeerAlertEvent; out APeerClosed: Boolean;
  out ACertEvent: ICertificateReceivedEvent): Boolean;
var
  LEvent: ITlsEvent;
  LAlertEvent: IPeerAlertEvent;
  LCertEvent: ICertificateReceivedEvent;
begin
  Result := False;
  APeerAlert := nil;
  APeerClosed := False;
  ACertEvent := nil;
  while AEngine.NextEvent(LEvent) do
    case LEvent.Kind of
      TTlsEventKind.PeerAlert:
        // first alert wins; no event is ever queued after a terminal one, so a full drain and a
        // stop-at-first-terminal dequeue the same set
        if (APeerAlert = nil) and Supports(LEvent, IPeerAlertEvent, LAlertEvent) then
        begin
          APeerAlert := LAlertEvent;
          Result := True;
        end;
      TTlsEventKind.Closed:
        begin
          APeerClosed := True;
          Result := True;
        end;
      TTlsEventKind.CertificateReceived:
        // capture the parked peer chain so a resolver can decide the verdict
        if Supports(LEvent, ICertificateReceivedEvent, LCertEvent) then
          ACertEvent := LCertEvent;
    end;
end;

class function TTlsStreamPump.PeerClosedDuringHandshake(
  const AEngine: ITlsEngineInbound): Boolean;
begin
  Result := AEngine.IsTerminal and (AEngine.LastError.Origin = TTlsErrorOrigin.Peer) and
    (AEngine.LastError.AlertByte = TTlsAlertDescription.CloseNotify.ToByte);
end;

class function TTlsStreamPump.DrainEventsOrRaise(const AEngine: ITlsEngineInbound;
  out APeerClosed: Boolean; out ACertEvent: ICertificateReceivedEvent): Boolean;
var
  LAlertEvent: IPeerAlertEvent;
begin
  DrainEvents(AEngine, LAlertEvent, APeerClosed, ACertEvent);
  if LAlertEvent <> nil then
  begin
    if LAlertEvent.Alert.HasKnownDescription then
      raise ETlsStreamError.CreateRes(LAlertEvent.Alert.Description, @SPeerFatalAlert)
    else
      raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError, @SPeerFatalAlert);
  end;
  Result := APeerClosed;
end;

class procedure TTlsStreamPump.DecideVerdict(const ACertEvent: ICertificateReceivedEvent;
  const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole;
  ADeadlineMs: Cardinal; out AAccept: Boolean; out AAlert: TTlsAlertDescription);
var
  LCtx: TCertificateVerdictContext;
begin
  // fail-closed: with no resolver (or no captured chain) the parked handshake is rejected
  // with certificate_unknown (an unspecified acceptability problem, not a corrupt certificate)
  AAccept := False;
  AAlert := TTlsAlertDescription.CertificateUnknown;
  if Assigned(AResolveVerdict) and (ACertEvent <> nil) then
  begin
    LCtx.PeerRole := APeerRole;
    LCtx.Chain := ACertEvent.Chain;
    LCtx.ValidatedPath := ACertEvent.ValidatedPath;
    LCtx.HostName := ACertEvent.HostName;
    LCtx.OcspStaple := ACertEvent.OcspStaple;
    LCtx.DeadlineMs := ADeadlineMs;
    LCtx.RevocationPosture := ACertEvent.RevocationPosture;
    // a resolver that raises must not leave the handshake parked with no verdict: the peer gets an
    // internal_error and the engine is terminal, so the caller surfaces the failure
    try
      AAccept := AResolveVerdict(LCtx, AAlert);
    except
      on Exception do
      begin
        AAccept := False;
        AAlert := TTlsAlertDescription.InternalError;
      end;
    end;
  end;
end;

class procedure TTlsStreamPump.ResolveVerdict(const AEngine: ITlsEngine;
  const ACertEvent: ICertificateReceivedEvent;
  const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole);
begin
  ResolveVerdict(AEngine, ACertEvent, AResolveVerdict, APeerRole, 0);
end;

class procedure TTlsStreamPump.ResolveVerdict(const AEngine: ITlsEngine;
  const ACertEvent: ICertificateReceivedEvent;
  const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole;
  ADeadlineMs: Cardinal);
var
  LAccept: Boolean;
  LAlert: TTlsAlertDescription;
begin
  DecideVerdict(ACertEvent, AResolveVerdict, APeerRole, ADeadlineMs, LAccept, LAlert);
  AEngine.SetCertificateVerdict(LAccept, LAlert);
end;

procedure TTlsStreamPump.DriveHandshake(AIsClient: Boolean);
begin
  // no resolver: with async verdicts disabled (the default) the handshake never parks, so
  // this is exactly the inline (non-async) path; if async was enabled without a resolver,
  // a park fails closed
  DriveHandshake(AIsClient, nil);
end;

procedure TTlsStreamPump.DriveHandshake(AIsClient: Boolean;
  const AResolveVerdict: TCertificateVerdictResolver);
begin
  DriveHandshake(AIsClient, AResolveVerdict, 0);
end;

procedure TTlsStreamPump.DriveHandshake(AIsClient: Boolean;
  const AResolveVerdict: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
var
  LRun: Boolean;
begin
  FWriteLock.Enter;
  try
    FEngineLock.Enter;
    try
      LRun := FHandshakeState <> THandshakeState.Complete;
      if LRun then
        FHandshakeState := THandshakeState.Running;
    finally
      FEngineLock.Leave;
    end;
    if not LRun then
      Exit;
    try
      RunHandshake(AIsClient, AResolveVerdict, ADeadlineMs);
      // sealed here, sent by the release of W below
      FEngineLock.Enter;
      try
        case FDeferredClose of
          TDeferredClose.DeferredNotify:
            FOutbound.SendClose;
          TDeferredClose.DeferredAlert:
            FOutbound.SendAlert(FDeferredAlert);
        end;
      finally
        FEngineLock.Leave;
      end;
    finally
      FEngineLock.Enter;
      try
        FDeferredClose := TDeferredClose.NotDeferred;
        if FHandshakeState = THandshakeState.Running then
          FHandshakeState := THandshakeState.Idle;
      finally
        FEngineLock.Leave;
      end;
    end;
  finally
    ReleaseWrite;
  end;
end;

procedure TTlsStreamPump.RunHandshake(AIsClient: Boolean;
  const AResolveVerdict: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
var
  LGot: Int32;
  LTotal: Int64;
  LPeerClosed, LHandshaking, LParked, LAccept: Boolean;
  LCertEvent: ICertificateReceivedEvent;
  LPeerRole: TPeerRole;
  LAlert: TTlsAlertDescription;
begin
  // our role fixes whose certificate a park concerns: a client verifies the server's chain,
  // a server the mTLS client's
  if AIsClient then
    LPeerRole := TPeerRole.Server
  else
    LPeerRole := TPeerRole.Client;
  // the client emits its opening flight now; a server has nothing to send until it
  // reads the ClientHello
  if AIsClient then
  begin
    FEngineLock.Enter;
    try
      FOutbound.StartHandshake;
    finally
      FEngineLock.Leave;
    end;
  end;
  LTotal := 0;
  if System.Length(FReadBuffer) < TransportChunk then
    SetLength(FReadBuffer, TransportChunk);
  LCertEvent := nil;
  FlushPending;
  repeat
    FEngineLock.Enter;
    try
      LHandshaking := FInbound.IsHandshaking;
      LParked := LHandshaking and FInbound.AwaitingCertificateVerdict;
    finally
      FEngineLock.Leave;
    end;
    if not LHandshaking then
      Break;
    // a parked verdict makes no progress on the wire; resolve it before blocking on a read
    // that would never return (the peer already sent the rest of its flight)
    if LParked then
    begin
      DecideVerdict(LCertEvent, AResolveVerdict, LPeerRole, ADeadlineMs, LAccept, LAlert);
      FEngineLock.Enter;
      try
        FOutbound.SetCertificateVerdict(LAccept, LAlert);
      finally
        FEngineLock.Leave;
      end;
      // send the resumed flight, or the abort alert of a rejected verdict, then surface the abort
      FlushThenRaiseIfFatal;
      LCertEvent := nil;
      Continue;
    end;
    LGot := FTransport.Read(FReadBuffer, 0, TransportChunk);
    if LGot = 0 then
      raise ETlsTransportTruncated.CreateResFmt(@STruncatedHandshake, [LTotal]);
    Inc(LTotal, LGot);
    FEngineLock.Enter;
    try
      FInbound.ProcessInput(FReadBuffer, 0, LGot);
    finally
      FEngineLock.Leave;
    end;
    FlushThenRaiseIfFatal;
    FEngineLock.Enter;
    try
      DrainEventsOrRaise(FInbound, LPeerClosed, LCertEvent);
    finally
      FEngineLock.Leave;
    end;
  until False;
  // StartHandshake itself can fail the engine (never entering the loop); surface that alert
  FEngineLock.Enter;
  try
    RaiseIfFatal(FInbound);
    FHandshakeState := THandshakeState.Complete;
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.ReadApp(var ADest: TBytes; AMaxLength: Int32;
  out AStatus: TTlsReadStatus): Int32;
var
  LGot: Int32;
  LPeerClosed, LTerminal, LInboundClosed: Boolean;
  LCertEvent: ICertificateReceivedEvent; // unused post-handshake; a verdict parks only mid-handshake
begin
  LInboundClosed := False;
  FEngineLock.Enter;
  try
    RaiseIfInboundCall;
    // 0-RTT bytes precede every 1-RTT byte; reading past them would reorder or lose them
    if FInbound.PendingEarlyData > 0 then
      raise EInvalidOperationTlsLibException.CreateRes(@SEarlyDataUnread);
    FInboundCall := True;
    try
      // surface anything already buffered (app data can arrive coalesced with the peer's
      // final handshake flight) before blocking on the transport
      Result := FInbound.ReadAppData(ADest, 0, AMaxLength);
      LTerminal := FInbound.IsTerminal;
      if Result = 0 then
      begin
        // DrainEvents still runs for its side effect (it raises on a peer fatal alert); the clean
        // close is detected via the engine's persistent flag, not the one-shot Closed event, which
        // the handshake driver may already have drained when a close_notify coalesced with the
        // peer's final flight
        DrainEventsOrRaise(FInbound, LPeerClosed, LCertEvent);
        LInboundClosed := FInbound.IsInboundClosed;
      end;
    finally
      FInboundCall := False;
    end;
  finally
    FEngineLock.Leave;
  end;
  if Result > 0 then
  begin
    // an alert the engine owes goes out now; a dead transport must not lose the bytes
    if LTerminal then
      FlushIfIdle(False);
    AStatus := TTlsReadStatus.Data;
    Exit;
  end;
  if LInboundClosed then
  begin
    AStatus := TTlsReadStatus.CleanEof;
    Exit(0);
  end;
  if System.Length(FReadBuffer) < TransportChunk then
    SetLength(FReadBuffer, TransportChunk);
  repeat
    // a terminal engine takes no more input: reading would block forever with its alert unsent
    if LTerminal then
    begin
      FlushIfIdle(False);
      RaiseFailure;
    end;
    LGot := FTransport.Read(FReadBuffer, 0, TransportChunk);
    if LGot = 0 then
    begin
      // the transport closed. A prior close_notify would have surfaced above as CleanEof,
      // so an EOF here with the connection still live is a possible truncation
      AStatus := TTlsReadStatus.Truncated;
      Exit(0);
    end;
    LInboundClosed := False;
    FEngineLock.Enter;
    try
      FInboundCall := True;
      try
        FInbound.ProcessInput(FReadBuffer, 0, LGot);
        LTerminal := FInbound.IsTerminal;
        if not LTerminal then
        begin
          Result := FInbound.ReadAppData(ADest, 0, AMaxLength);
          if Result = 0 then
          begin
            DrainEventsOrRaise(FInbound, LPeerClosed, LCertEvent);
            LInboundClosed := FInbound.IsInboundClosed;
          end;
        end;
      finally
        FInboundCall := False;
      end;
    finally
      FEngineLock.Leave;
    end;
    // the loop top sends the alert the input provoked, since a read-only caller never writes
    if LTerminal then
      Continue;
    if Result > 0 then
    begin
      AStatus := TTlsReadStatus.Data;
      Exit;
    end;
    if LInboundClosed then
    begin
      AStatus := TTlsReadStatus.CleanEof;
      Exit(0);
    end;
    // no plaintext yet (e.g. a post-handshake ticket / KeyUpdate record): read again
  until False;
end;

function TTlsStreamPump.ReadEarlyData(var ADest: TBytes; AMaxLength: Int32): Int32;
begin
  FEngineLock.Enter;
  try
    RaiseIfInboundCall;
    Result := FInbound.ReadEarlyData(ADest, 0, AMaxLength);
  finally
    FEngineLock.Leave;
  end;
end;

procedure TTlsStreamPump.SealSlice(ALength: Int32);
var
  LTerminal, LClosed, LFault: Boolean;
begin
  LTerminal := False;
  LClosed := False;
  try
    FEngineLock.Enter;
    try
      LTerminal := FOutbound.IsTerminal;
      LClosed := (not LTerminal) and (FWriteClosed or FOutbound.WriteClosed);
      if not (LTerminal or LClosed) then
        FOutbound.Write(FWriteChunk, 0, ALength);
    finally
      FEngineLock.Leave;
    end;
  except
    on Exception do
    begin
      // a failed seal may leave an alert owed: deliver it before surfacing the failure
      LFault := EngineIsTerminal;
      SendPendingQuietly;
      if LFault then
        RaiseFailure;
      raise;
    end;
  end;
  // a terminal engine reports its recorded failure first, not a closed-write error
  if LTerminal then
  begin
    SendPendingQuietly;
    RaiseFailure;
  end;
  // checked here so a closed write side reports a clear error, never counting the bytes as sent
  if LClosed then
    raise EInvalidOperationTlsLibException.CreateRes(@SWriteAfterClose);
end;

procedure TTlsStreamPump.WriteApp(const ABuffer; ACount: Int32);
begin
  WriteApp(ABuffer, ACount, 0);
end;

procedure TTlsStreamPump.WriteApp(const ABuffer; ACount: Int32; AWriteTimeoutMs: Int32);
var
  LOffset, LChunk: Int32;
  LTimed: Boolean;
begin
  if ACount <= 0 then
    Exit;
  LTimed := (AWriteTimeoutMs > 0) and (FTimed <> nil);
  // before W: a callback inside a read would otherwise wait for a writer that waits for E
  RaiseIfInboundCall;
  FWriteLock.Enter;
  try
    if LTimed then
      FTimed.SetWriteTimeout(AWriteTimeoutMs);
    try
      LOffset := 0;
      // the engine seals what it is handed in full: seal and drain one bounded slice at a time
      while LOffset < ACount do
      begin
        LChunk := ACount - LOffset;
        if LChunk > WriteChunk then
          LChunk := WriteChunk;
        // grown on demand and capped, so a stream that only writes small messages never holds 64 KiB
        if System.Length(FWriteChunk) < LChunk then
          SetLength(FWriteChunk, LChunk);
        Move(PByte(@ABuffer)[LOffset], FWriteChunk[0], LChunk);
        SealSlice(LChunk);
        FlushThenRaiseIfFatal;
        Inc(LOffset, LChunk);
      end;
    finally
      // cleared before W is released, or the next sender would see the stale deadline
      if LTimed then
        FTimed.SetWriteTimeout(0);
    end;
  finally
    ReleaseWrite;
  end;
end;

procedure TTlsStreamPump.RequestKeyUpdate(ARequest: TKeyUpdateRequest);
var
  LClosed: Boolean;
begin
  RaiseIfInboundCall;
  FWriteLock.Enter;
  try
    FEngineLock.Enter;
    try
      // a terminal engine reports its recorded failure below, not a closed write side
      LClosed := (not FOutbound.IsTerminal) and (FWriteClosed or FOutbound.WriteClosed);
      if not LClosed then
        FOutbound.RequestKeyUpdate(ARequest);
    finally
      FEngineLock.Leave;
    end;
    if LClosed then
      raise EInvalidOperationTlsLibException.CreateRes(@SWriteAfterClose);
    FlushThenRaiseIfFatal;
  finally
    ReleaseWrite;
  end;
end;

procedure TTlsStreamPump.Close;
begin
  FEngineLock.Enter;
  try
    if FHandshakeState = THandshakeState.Running then
    begin
      if FDeferredClose = TDeferredClose.NotDeferred then
        FDeferredClose := TDeferredClose.DeferredNotify;
      Exit;
    end;
    FOutbound.SendClose;
  finally
    FEngineLock.Leave;
  end;
  FlushIfIdle(True);
end;

procedure TTlsStreamPump.Abort(ADescription: TTlsAlertDescription);
begin
  FEngineLock.Enter;
  try
    if FHandshakeState = THandshakeState.Running then
    begin
      if FDeferredClose = TDeferredClose.NotDeferred then
      begin
        FDeferredClose := TDeferredClose.DeferredAlert;
        FDeferredAlert := ADescription;
      end;
      Exit;
    end;
    FOutbound.SendAlert(ADescription);
  finally
    FEngineLock.Leave;
  end;
  // the connection is already being refused; a dead peer must not mask the reason
  FlushIfIdle(False);
end;

function TTlsStreamPump.CloseWriteSide: Boolean;
begin
  FEngineLock.Enter;
  try
    RaiseIfInboundCall;
    // a close before the handshake even ran has nothing to protect; only a live one is shut down
    Result := (not FWriteClosed) and (FHandshakeState <> THandshakeState.Idle);
    FWriteClosed := True;
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.WriteSideClosed: Boolean;
begin
  FEngineLock.Enter;
  try
    Result := FWriteClosed;
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.IsHandshakeComplete: Boolean;
begin
  Result := FHandshakeState = THandshakeState.Complete;
end;

function TTlsStreamPump.IsHandshakeRunning: Boolean;
begin
  Result := FHandshakeState = THandshakeState.Running;
end;

function TTlsStreamPump.ConfirmHandshakeComplete: Boolean;
begin
  // Complete is final, so a lock-free yes needs no confirmation; a no may only be stale
  if FHandshakeState = THandshakeState.Complete then
    Exit(True);
  FEngineLock.Enter;
  try
    Result := FHandshakeState = THandshakeState.Complete;
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.ConnectionInfo: TTlsConnectionInfo;
begin
  // E may be held across a certificate check; a poller is answered without waiting for it
  if FHandshakeState = THandshakeState.Running then
    Exit(Default(TTlsConnectionInfo));
  FEngineLock.Enter;
  try
    Result := FInbound.ConnectionInfo;
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.PendingAppData: Int32;
begin
  if FHandshakeState = THandshakeState.Running then
    Exit(0);
  FEngineLock.Enter;
  try
    Result := FInbound.PendingAppData;
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes;
begin
  FEngineLock.Enter;
  try
    Result := FInbound.ExportKeyingMaterial(ALabel, ALength);
  finally
    FEngineLock.Leave;
  end;
end;

function TTlsStreamPump.ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
  ALength: Int32): TBytes;
begin
  FEngineLock.Enter;
  try
    Result := FInbound.ExportKeyingMaterial(ALabel, AContext, ALength);
  finally
    FEngineLock.Leave;
  end;
end;

end.
