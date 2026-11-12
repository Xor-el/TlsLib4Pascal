{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsStream;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  SyncObjs,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpTlsConnectionInfo,
  TlpTrustPolicy,
  TlpHandshakeMessages,
  TlpITlsEngine,
  TlpITlsTransport,
  TlpTlsStreamPump;

type
  /// <summary>
  /// The convenience stream: a TStream over an ITlsTransport and a ready ITlsEngine
  /// (built by the caller from a frozen config). It handshakes on first IO (or explicitly),
  /// then Read/Write move application plaintext while the engine and the pump handle the
  /// record layer beneath. It is neutral - no host-library type appears here - so every
  /// adapter reuses it unchanged. The caller owns the engine, the transport, and the
  /// stream; freeing the stream does not close the transport (call CloseNotify first for a
  /// clean shutdown).
  /// One thread may read while others write, close, abort, rekey or query it: reads are
  /// serialised with reads and writes with writes (a write is never interleaved with another),
  /// a close or alert never waits for a busy writer (that writer sends it, so it can be unsent when
  /// the call returns), and the engine underneath must not be called directly while the stream is
  /// in use. A blocked read ends only with bytes or when the host closes the transport. Free the
  /// stream only after every call has returned. Reads, writes and rekeys first wait for the
  /// handshake, under its own lock, which a blocked reader does not hold. A close, alert or
  /// exporter call does not wait for the handshake but can wait for the engine call the handshake
  /// is making, which includes the built-in certificate check and any live revocation fetch.
  /// Callbacks: code the handshake runs (for example the verify callback, key log, credential
  /// resolver, session store or cache, certificate compression cache, ECH key store, revocation
  /// fetcher, verdict resolver or the transport) may call ConnectionInfo, PendingReadBytes,
  /// IsHandshakeComplete, CloseNotify and SendAlert; any read, write, rekey or handshake of a
  /// non-zero count raises EInvalidOperationTlsLibException there, and no other call is
  /// supported. A callback that runs after the handshake (a client session cache storing a
  /// ticket, or dropping sessions on a fatal alert) can run inside a read, a write or an alert
  /// that holds the engine, so it may only query: ConnectionInfo, PendingReadBytes and
  /// IsHandshakeComplete; inside a read, a read, write, rekey, close or alert on the stream
  /// raises. A ticket that arrives with the server's Finished is stored during the handshake, so
  /// follow the stricter rule. A callback must not wait for another thread that reads, writes,
  /// rekeys or handshakes the same stream.
  /// </summary>
  TTlsStream = class(TStream)
  public
  const
    /// <summary>The longest a terminal send (a fatal alert, close_notify) may take on a timed
    /// transport before it is abandoned and the connection latched failed (5 s).</summary>
    DefaultCloseGraceMs = Int32(5000);
  strict private
  var
    FPump: TTlsStreamPump;
    FHandshakeLock: TCriticalSection;
    FReadLock: TCriticalSection;
    FTimed: ITlsTimedTransport;
    FIsClient: Boolean;
    FServerName: string;
    // the handshake side's state: FHandshakeLock guards the failure latch and the handshake cap
    FHandshakeFailed: Boolean;
    FFailureClass: ExceptClass;
    FFailureMessage: string;
    FFailureHasAlert: Boolean;
    FFailureAlert: TTlsAlertDescription;
    // set under FHandshakeLock and FReadLock once the handshake is complete and its cap cleared
    FHandshakeSettled: Boolean;
    // the read side's state: FReadLock guards every field from here to FReadChunk
    FReadClosed: Boolean;
    FTruncated: Boolean;
    FReadChunk: TBytes;
    FVerdictResolver: TCertificateVerdictResolver;
    FVerdictDeadlineMs: Cardinal;
    /// <summary>Runs the handshake once; the caller holds the handshake side.</summary>
    procedure DriveHandshake;
    procedure RequireTimedForCap(AMs: Int32);
    procedure ArmReadCap(AMs: Int32; AApplication: Boolean);
    procedure ClearReadCap(AMs: Int32);
    /// <summary>Drives or waits for the handshake before a write, or refuses when the write side
    /// was closed before it ran.</summary>
    procedure HandshakeForWrite;
    /// <summary>One read cycle; the caller holds the read side.</summary>
    function ReadLocked(var ABuffer; ACount: Longint): Longint;
  public
    /// <summary>Wraps a ready engine and transport. AIsClient selects who opens the
    /// handshake (a client sends the first flight); AServerName is the host used for SNI /
    /// verification, surfaced back through ConnectionInfo. Terminal sends are bounded by
    /// DefaultCloseGraceMs.</summary>
    constructor Create(const ATransport: ITlsTransport; const AEngine: ITlsEngine;
      AIsClient: Boolean; const AServerName: string); overload;
    /// <summary>As above, bounding each terminal send by ACloseGraceMs on a transport that is an
    /// ITlsTimedTransport (zero or less leaves it unbounded).</summary>
    constructor Create(const ATransport: ITlsTransport; const AEngine: ITlsEngine;
      AIsClient: Boolean; const AServerName: string; ACloseGraceMs: Int32); overload;
    /// <summary>Releases the locks. Free only after every call has returned.</summary>
    destructor Destroy; override;

    /// <summary>Sets the out-of-band resolver for a parked peer-certificate verdict, used only
    /// when async certificate verdicts are enabled on the config. It runs after the built-in
    /// pipeline has already accepted the chain and can only additionally reject (augment-only).
    /// Must be set before the handshake; with none set an enabled async verdict fails closed.</summary>
    procedure SetCertificateVerdictResolver(const AResolver: TCertificateVerdictResolver); overload;
    /// <summary>As above, giving the resolver ADeadlineMs as its time budget (0 = none set).</summary>
    procedure SetCertificateVerdictResolver(const AResolver: TCertificateVerdictResolver;
      ADeadlineMs: Cardinal); overload;
    /// <summary>Runs the handshake if it has not already run; a no-op afterwards, without waiting
    /// for a reader. The first Read/Write performs it implicitly, so calling this is optional -
    /// it lets a caller front-load the handshake (and its errors) before any application byte.
    /// A thread that finds another running it waits for it.</summary>
    procedure Handshake; overload;
    /// <summary>As above, bounding the handshake's reads to AReadTimeoutMs in total (zero or less
    /// = block, whereas TTlsConnection.Handshake reads zero as its default); the cap is armed and
    /// cleared inside the handshake side, so it never bounds a reader. A positive value needs an
    /// ITlsTimedTransport.</summary>
    procedure Handshake(AReadTimeoutMs: Int32); overload;
    /// <summary>Whether the handshake has completed successfully; never waits.</summary>
    function IsHandshakeComplete: Boolean;
    /// <summary>The negotiated connection info. Zero values while the handshake is running, so a
    /// thread polling during a slow certificate check is not stalled; that includes a callback the
    /// handshake itself runs.</summary>
    function ConnectionInfo: TTlsConnectionInfo;
    /// <summary>Sends close_notify to shut the write side down cleanly (RFC 9846 6.1);
    /// idempotent. It does not wait for a writer that holds the send side: that writer sends it
    /// before it returns, so the record may still be unsent when this returns. A send on a timed
    /// transport is bounded by the close grace. Called while another thread runs the handshake, it
    /// takes effect as the handshake completes, which that thread sends without raising. A call
    /// before the handshake only latches the write side closed. The transport itself is not
    /// closed - the caller owns it.</summary>
    procedure CloseNotify;
    /// <summary>Refuses the connection with a fatal alert (for example bad_certificate after a
    /// host hook rejects the peer) instead of a clean close; the write side is closed and the
    /// engine terminal. Idempotent, with the same hand-off and timing as CloseNotify: while
    /// another thread runs the handshake, the alert goes out as it completes and every later call
    /// raises it.</summary>
    procedure SendAlert(ADescription: TTlsAlertDescription);
    /// <summary>Asks for fresh traffic keys (TLS 1.3 KeyUpdate; a no-op under TLS 1.2). Drives or
    /// waits for the handshake and then for the send side like a write, and raises once the write
    /// side is closed. Use this, not the engine, while the stream is in use.</summary>
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    /// <summary>The RFC 5705 / 9846 7.5 exporter keyed to this connection, or nil before the
    /// secret exists or after a failure. Use this, not the engine, while the stream is in
    /// use.</summary>
    function ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    /// <summary>Whether the peer closed the transport without a close_notify: a possible
    /// truncation. False after a clean close_notify shutdown. Takes the read side, so it waits
    /// for a read in progress.</summary>
    function TransportTruncated: Boolean;
    /// <summary>Decrypted application bytes already buffered and readable without touching
    /// the transport (for a host's ReceivePending / WaitingData); 0 at once while the handshake
    /// is running.</summary>
    function PendingReadBytes: Int32;

    // TStream
    function Read(var ABuffer; ACount: Longint): Longint; override;
    /// <summary>As Read, giving up with the retryable ETlsReadTimeout when no application data has
    /// arrived within AReadTimeoutMs in total (zero or less = block). The cap is armed and cleared
    /// inside the read side. A positive value needs an ITlsTimedTransport.</summary>
    function ReadTimed(var ABuffer; ACount: Longint; AReadTimeoutMs: Int32): Longint;
    /// <summary>Server only: the 0-RTT bytes the client sent before its handshake finished,
    /// replayable by an attacker (RFC 9846 8, F.5). Returns 0 when none remain. Read raises
    /// while any are unread, so they are never skipped or reordered.</summary>
    function ReadEarlyData(var ABuffer; ACount: Longint): Longint;
    function Write(const ABuffer; ACount: Longint): Longint; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
  end;

implementation

resourcestring
  SNotSeekable = 'a TLS stream is a sequential conduit and cannot be sought';
  SReadTruncated = 'the transport closed without close_notify (possible truncation)';
  SWriteAfterClose = 'the stream write side has been closed';
  SHandshakeCallbackReentry = 'code the handshake calls (a callback or the transport) cannot ' +
    'read, write, rekey or handshake the stream whose handshake is running it';
  SNilStreamArgument = 'a stream needs an engine and a transport (pass both, not nil)';
  SReadTimeoutNeedsTimedTransport = 'a read timeout needs a timed transport (an ' +
    'ITlsTimedTransport), and this stream was given a plain one';

{ TTlsStream }

constructor TTlsStream.Create(const ATransport: ITlsTransport;
  const AEngine: ITlsEngine; AIsClient: Boolean; const AServerName: string);
begin
  Create(ATransport, AEngine, AIsClient, AServerName, DefaultCloseGraceMs);
end;

constructor TTlsStream.Create(const ATransport: ITlsTransport;
  const AEngine: ITlsEngine; AIsClient: Boolean; const AServerName: string;
  ACloseGraceMs: Int32);
begin
  inherited Create;
  if (AEngine = nil) or (ATransport = nil) then
    raise EArgumentTlsLibException.CreateRes(@SNilStreamArgument);
  FHandshakeLock := TCriticalSection.Create;
  FReadLock := TCriticalSection.Create;
  FPump := TTlsStreamPump.Create(AEngine, ATransport, ACloseGraceMs);
  // a transport that cannot bound a read rejects a read timeout rather than ignoring it
  Supports(ATransport, ITlsTimedTransport, FTimed);
  FIsClient := AIsClient;
  FServerName := AServerName;
end;

destructor TTlsStream.Destroy;
begin
  FPump.Free;
  FReadLock.Free;
  FHandshakeLock.Free;
  FTimed := nil;
  inherited Destroy;
end;

procedure TTlsStream.RequireTimedForCap(AMs: Int32);
begin
  if (AMs > 0) and (FTimed = nil) then
    raise EInvalidOperationTlsLibException.CreateRes(@SReadTimeoutNeedsTimedTransport);
end;

procedure TTlsStream.ArmReadCap(AMs: Int32; AApplication: Boolean);
begin
  RequireTimedForCap(AMs);
  if AMs <= 0 then
    Exit;
  if AApplication then
    FTimed.SetApplicationReadTimeout(AMs)
  else
    FTimed.SetReadTimeout(AMs);
end;

procedure TTlsStream.ClearReadCap(AMs: Int32);
begin
  // cleared even when the call raised, so a retried read is not left bounded
  if (AMs > 0) and (FTimed <> nil) then
    FTimed.SetReadTimeout(0);
end;

procedure TTlsStream.DriveHandshake;
begin
  // a failed handshake is permanent for this stream: never re-drive it (a retry would emit a
  // second ClientHello or block on a dead transport, masking the real cause). Re-raise the
  // engine's terminal failure if it has one, else the latched original failure. Build a new
  // stream to retry.
  if FHandshakeFailed then
  begin
    FPump.RaiseFailure;
    // Exception constructors are not virtual, so a latched class cannot rebuild its own state
    if FFailureHasAlert then
      raise ETlsStreamError.Create(FFailureAlert, FFailureMessage);
    if FFailureClass.InheritsFrom(ETlsStreamError) then
      raise FFailureClass.Create(FFailureMessage);
    raise ETlsStreamError.Create(FFailureMessage);
  end;
  // a nil resolver is exactly the inline path; a set one decides a parked async verdict
  try
    FPump.DriveHandshake(FIsClient, FVerdictResolver, FVerdictDeadlineMs);
  except
    on E: Exception do
    begin
      FHandshakeFailed := True;
      // the stream cannot resume a handshake, so a retryable timeout is not retryable here
      if E is ETlsReadTimeout then
        FFailureClass := ETlsHandshakeTimeout
      else
        FFailureClass := ExceptClass(E.ClassType);
      FFailureMessage := E.Message;
      FFailureHasAlert := (E is ETlsStreamError) and ETlsStreamError(E).HasAlert;
      if FFailureHasAlert then
        FFailureAlert := ETlsStreamError(E).Alert;
      raise;
    end;
  end;
end;

procedure TTlsStream.HandshakeForWrite;
begin
  // a close before the handshake only latched the flag; fail here rather than run it and send
  if not FPump.ConfirmHandshakeComplete then
  begin
    if FPump.WriteSideClosed then
      raise EInvalidOperationTlsLibException.CreateRes(@SWriteAfterClose);
    Handshake;
  end;
end;

procedure TTlsStream.SetCertificateVerdictResolver(
  const AResolver: TCertificateVerdictResolver);
begin
  SetCertificateVerdictResolver(AResolver, 0);
end;

procedure TTlsStream.SetCertificateVerdictResolver(
  const AResolver: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
begin
  FVerdictResolver := AResolver;
  FVerdictDeadlineMs := ADeadlineMs;
end;

procedure TTlsStream.Handshake;
begin
  Handshake(0);
end;

procedure TTlsStream.Handshake(AReadTimeoutMs: Int32);
begin
  if FHandshakeSettled then
    Exit;
  FHandshakeLock.Enter;
  try
    // already settled: a reader may hold R by now, and publishing again would wait for it
    if FHandshakeSettled then
      Exit;
    // under H, a running handshake can only be this thread's own: a callback it made
    if FPump.IsHandshakeRunning then
      raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeCallbackReentry);
    if not FPump.ConfirmHandshakeComplete then
    begin
      ArmReadCap(AReadTimeoutMs, False);
      try
        DriveHandshake;
      finally
        ClearReadCap(AReadTimeoutMs);
      end;
    end;
    // published under R, which a reader that sees it takes before it reads the transport
    FReadLock.Enter;
    try
      FHandshakeSettled := True;
    finally
      FReadLock.Leave;
    end;
  finally
    FHandshakeLock.Leave;
  end;
end;

function TTlsStream.IsHandshakeComplete: Boolean;
begin
  Result := FPump.IsHandshakeComplete;
end;

function TTlsStream.ConnectionInfo: TTlsConnectionInfo;
begin
  Result := FPump.ConnectionInfo;
  // overlay the client-side construction host; where that is empty the engine's snapshot
  // already carries the SNI the client requested, as the handshake resolved it
  if FServerName <> '' then
    Result.ServerName := FServerName;
end;

procedure TTlsStream.SendAlert(ADescription: TTlsAlertDescription);
begin
  if FPump.CloseWriteSide then
    FPump.Abort(ADescription);
end;

procedure TTlsStream.CloseNotify;
begin
  if FPump.CloseWriteSide then
    FPump.Close;
end;

procedure TTlsStream.RequestKeyUpdate(ARequest: TKeyUpdateRequest);
begin
  HandshakeForWrite;
  FPump.RequestKeyUpdate(ARequest);
end;

function TTlsStream.ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes;
begin
  Result := FPump.ExportKeyingMaterial(ALabel, ALength);
end;

function TTlsStream.ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
  ALength: Int32): TBytes;
begin
  Result := FPump.ExportKeyingMaterial(ALabel, AContext, ALength);
end;

function TTlsStream.TransportTruncated: Boolean;
begin
  FReadLock.Enter;
  try
    Result := FTruncated;
  finally
    FReadLock.Leave;
  end;
end;

function TTlsStream.PendingReadBytes: Int32;
begin
  Result := FPump.PendingAppData;
end;

function TTlsStream.ReadEarlyData(var ABuffer; ACount: Longint): Longint;
var
  LChunk: Int32;
begin
  if ACount <= 0 then
    Exit(0);
  Handshake;
  FReadLock.Enter;
  try
    LChunk := ACount;
    if LChunk > TTlsStreamPump.TransportChunk then
      LChunk := TTlsStreamPump.TransportChunk;
    if System.Length(FReadChunk) < LChunk then
      SetLength(FReadChunk, LChunk);
    Result := FPump.ReadEarlyData(FReadChunk, LChunk);
    if Result > 0 then
      Move(FReadChunk[0], ABuffer, Result);
  finally
    FReadLock.Leave;
  end;
end;

function TTlsStream.ReadLocked(var ABuffer; ACount: Longint): Longint;
var
  LStatus: TTlsReadStatus;
  LChunk: Int32;
begin
  // a truncation stays an error on every later read, never a clean end of stream
  if FTruncated then
    raise ETlsTransportTruncated.CreateRes(@SReadTruncated);
  if FReadClosed then
    Exit(0);
  // one record per cycle: bound the scratch to a single transport chunk rather than the caller's
  // request, so a huge Read cannot inflate a per-stream buffer. A short read is within the
  // TStream.Read contract; the caller loops for the rest.
  LChunk := ACount;
  if LChunk > TTlsStreamPump.TransportChunk then
    LChunk := TTlsStreamPump.TransportChunk;
  if System.Length(FReadChunk) < LChunk then
    SetLength(FReadChunk, LChunk);
  Result := FPump.ReadApp(FReadChunk, LChunk, LStatus);
  case LStatus of
    TTlsReadStatus.Data:
      Move(FReadChunk[0], ABuffer, Result);
    TTlsReadStatus.CleanEof:
      FReadClosed := True;
    TTlsReadStatus.Truncated:
      begin
        // a stripped close_notify is a truncation, not a graceful EOF
        FReadClosed := True;
        FTruncated := True;
        raise ETlsTransportTruncated.CreateRes(@SReadTruncated);
      end;
  end;
end;

function TTlsStream.Read(var ABuffer; ACount: Longint): Longint;
begin
  if ACount <= 0 then
    Exit(0);
  Handshake;
  FReadLock.Enter;
  try
    Result := ReadLocked(ABuffer, ACount);
  finally
    FReadLock.Leave;
  end;
end;

function TTlsStream.ReadTimed(var ABuffer; ACount: Longint;
  AReadTimeoutMs: Int32): Longint;
begin
  if ACount <= 0 then
    Exit(0);
  // refused before the handshake touches the transport
  RequireTimedForCap(AReadTimeoutMs);
  Handshake;
  FReadLock.Enter;
  try
    ArmReadCap(AReadTimeoutMs, True);
    try
      Result := ReadLocked(ABuffer, ACount);
    finally
      ClearReadCap(AReadTimeoutMs);
    end;
  finally
    FReadLock.Leave;
  end;
end;

function TTlsStream.Write(const ABuffer; ACount: Longint): Longint;
begin
  if ACount <= 0 then
    Exit(0);
  HandshakeForWrite;
  FPump.WriteApp(ABuffer, ACount);
  Result := ACount;
end;

function TTlsStream.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  // tolerate the benign position query some TStream consumers make; refuse real movement
  if (AOffset = 0) and (AOrigin = TSeekOrigin.soCurrent) then
    Exit(0);
  raise ENotSupportedTlsLibException.CreateRes(@SNotSeekable);
end;

end.
