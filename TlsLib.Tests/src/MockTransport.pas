{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockTransport;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  SyncObjs,
  TlpIClock,
  TlpClock,
  TlpTlsLibExceptions,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsConnectionInfo,
  TlpHandshakeMessages,
  TlpITlsEngine,
  TlpITlsEngineInbound,
  TlpITlsEngineOutbound,
  TlpITlsTransport,
  TlpINetSocket,
  TlpTlsConnection,
  TlpTlsStream;

type
  /// <summary>A single-direction in-memory byte pipe with blocking reads. Write appends;
  /// a Read blocks for data or an orderly close (returns 0). The shared boundary the two
  /// single-threaded engines synchronize across in a loopback. A pipe made with a capacity holds
  /// at most that many bytes: a Write blocks while it is full, and unlike an unbounded pipe it
  /// raises once the pipe is closed, so a stalled peer is felt by the sender as on a socket.</summary>
  TMemoryPipe = class sealed(TObject)
  strict private
  var
    FLock: TCriticalSection;
    FEvent: TEvent;
    FSpace: TEvent;
    FParked: TEvent;
    FBuffer: TBytes;
    FHead: Int32;
    FCapacity: Int32;
    FClosed: Boolean;
    FWritten: Int64;
    FStalls: Int64;
    FCorruptAt: Int64;
    function AppendFits(const AData: TBytes; AOffset, ALength: Int32): Int32;
    procedure WriteBounded(const AData: TBytes; AOffset, ALength: Int32);
    function GetWritten: Int64;
    function GetStalls: Int64;
    procedure CorruptWithin(AFrom: Int32; ALength: Int32);
  public
    constructor Create; overload;
    /// <summary>A pipe holding at most ACapacity bytes (zero or less = unbounded).</summary>
    constructor Create(ACapacity: Int32); overload;
    destructor Destroy; override;
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>Appends what fits now, without waiting, and returns the count (all of it when
    /// the pipe is unbounded).</summary>
    function TryWrite(const AData: TBytes; AOffset, ALength: Int32): Int32;
    function Read(var ADest: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Close;
    /// <summary>True when a Read would not block: bytes are buffered, or the pipe is closed. Waits
    /// up to AMs ms for either.</summary>
    function WaitData(AMs: Int32): Boolean;
    /// <summary>True when a Write would not block: there is room, or the pipe is closed. Waits up
    /// to AMs ms for either.</summary>
    function WaitSpace(AMs: Int32): Boolean;
    /// <summary>True while a Read is waiting on an empty, open pipe; waits up to AMs ms for one.</summary>
    function WaitParked(AMs: Int32): Boolean;
    /// <summary>Flips the byte that is the AOffset'th ever written into the pipe.</summary>
    procedure CorruptByteAt(AOffset: Int64);
    /// <summary>The bytes ever written into the pipe.</summary>
    property Written: Int64 read GetWritten;
    /// <summary>How many times a write found less room than it needed.</summary>
    property Stalls: Int64 read GetStalls;
  end;

  /// <summary>A count that grows whenever the exchange under watch does real work.</summary>
  TWedgeProgress = function: Int64 of object;

  /// <summary>Force-closes both loopback pipes when a pump wedges, so it fails as a surfaced EOF
  /// rather than hanging the run: a blocked read returns, a blocked write raises. It fires when no
  /// byte has been written to either pipe for the idle time, when the progress count has not grown
  /// for the stall time (bytes that only keep a livelock busy), or at the backstop however much
  /// moved. Disarmed once the exchange completes.</summary>
  TWedgeWatchdog = class(TThread)
  strict private
  const
    SliceMs = UInt32(50);
  var
    FPipeA, FPipeB: TMemoryPipe;
    FIdleMs: UInt32;
    FBackstopMs: UInt32;
    FStallMs: UInt32;
    FProgress: TWedgeProgress;
    FClock: ITlsMonotonicClock;
    FDone: TEvent;
    FFired: Boolean;
  protected
    procedure Execute; override;
  public
    /// <summary>Fires ADeadlineMs after the start, whether or not bytes move.</summary>
    constructor Create(const APipeA, APipeB: TMemoryPipe; ADeadlineMs: UInt32); overload;
    /// <summary>Fires after AIdleMs with no byte written, or ABackstopMs after the start.</summary>
    constructor Create(const APipeA, APipeB: TMemoryPipe; AIdleMs, ABackstopMs: UInt32); overload;
    /// <summary>As above, and after AStallMs in which AProgress did not grow.</summary>
    constructor Create(const APipeA, APipeB: TMemoryPipe; AIdleMs, ABackstopMs, AStallMs: UInt32;
      const AProgress: TWedgeProgress); overload;
    destructor Destroy; override;
    procedure Disarm; // the exchange finished in time; stop before the deadline
    property Fired: Boolean read FFired;
  end;

  /// <summary>An ITlsTransport over a read pipe and a write pipe (the two directions of a
  /// duplex). CloseWrite drops the transport without a close_notify (a truncation).</summary>
  TMemoryTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FRead: TMemoryPipe;
    FWrite: TMemoryPipe;
  public
    constructor Create(const ARead, AWrite: TMemoryPipe);
    destructor Destroy; override;
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    procedure CloseWrite;
    /// <summary>True while a Read of this transport waits for data; waits up to AMs ms for one.</summary>
    function WaitReadParked(AMs: Int32): Boolean;
  end;

  /// <summary>A transport decorator that measures how much ciphertext the engine had queued when
  /// a write reached the transport: while armed, each Write drains the rest of the engine's
  /// outbound itself (forwarding all of it to the inner transport) and keeps the largest
  /// written-plus-drained total. A bulk write sealed whole shows as one peak of the whole
  /// payload; a sliced one as at most a slice.</summary>
  TPeakProbeTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FInner: ITlsTransport;
    FEngine: ITlsEngine;
    FArmed: Boolean;
    FPeakPending: Int32;
  public
    constructor Create(const AInner: ITlsTransport; const AEngine: ITlsEngine);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    procedure Arm;
    property PeakPending: Int32 read FPeakPending;
  end;

  /// <summary>A transport decorator that models a host socket's receive timeout: once armed, the
  /// next Read raises ETlsReadTimeout (nothing consumed) and every later Read forwards to the
  /// inner transport as usual.</summary>
  TTimeoutOnceTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FInner: ITlsTransport;
    FArmed: Boolean;
  public
    constructor Create(const AInner: ITlsTransport);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    procedure Arm;
  end;

  /// <summary>A transport that swallows writes and fails every Read with a non-TLS exception,
  /// like a socket layer reporting its own error class.</summary>
  TFailingReadTransport = class sealed(TInterfacedObject, ITlsTransport)
  public
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>A transport that counts the bytes written to it and reads as a closed peer.</summary>
  TRecordingTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FWritten: Int32;
  public
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    property Written: Int32 read FWritten;
  end;

  /// <summary>A transport decorator that counts the bytes written through it and remembers the
  /// buffer its last Read and its last Write were handed.</summary>
  TCountingTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FInner: ITlsTransport;
    FWritten: Int32;
    FLastReadBuffer: Pointer;
    FLastWriteBuffer: Pointer;
  public
    constructor Create(const AInner: ITlsTransport);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    property Written: Int32 read FWritten;
    property LastReadBuffer: Pointer read FLastReadBuffer;
    property LastWriteBuffer: Pointer read FLastWriteBuffer;
  end;

  /// <summary>A transport that hands out one scripted wire on the first Read, then reads as a closed
  /// peer; it counts its writes, or fails them like a dead socket when so built.</summary>
  TScriptedTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FWire: TBytes;
    FServed: Boolean;
    FWritesFail: Boolean;
    FWritten: Int32;
  public
    constructor Create(const AWire: TBytes; AWritesFail: Boolean);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    property Written: Int32 read FWritten;
  end;

  /// <summary>A transport whose socket died: every Write fails like a reset connection, naming
  /// its number, and a Read reads as a closed peer. It counts the writes it was asked for.</summary>
  TDeadWriteTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FAttempts: Int32;
  public
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    property Attempts: Int32 read FAttempts;
  end;

  /// <summary>A timed transport over a read pipe and a write pipe: reads wait on the pipe within
  /// an armed cap, and a send takes what the write pipe has room for, so a send under an armed
  /// write deadline never waits past it. Owns the write pipe, as TMemoryTransport does.</summary>
  TPipeTimedTransport = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FRead: TMemoryPipe;
    FWrite: TMemoryPipe;
  strict protected
    function WaitReadable(AMs: Int32): Boolean; override;
    function WaitWritable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(const ARead, AWrite: TMemoryPipe);
    destructor Destroy; override;
    /// <summary>The read cap now armed, 0 when none.</summary>
    function ArmedReadTimeoutMs: Int32;
    procedure CloseWrite;
  end;

  /// <summary>A timed transport whose socket never becomes writable: it serves one scripted wire
  /// on the first read and then reads as closed, and counts the sends that reach it. A send under
  /// an armed write deadline waits for writability and so never reaches it; an unarmed one does.</summary>
  TStalledTransport = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FWire: TBytes;
    FServed: Boolean;
    FSends: Int32;
  strict protected
    function WaitWritable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(const AWire: TBytes; const AClock: ITlsMonotonicClock);
    property Sends: Int32 read FSends;
  end;

  /// <summary>A transport whose Write blocks until Open is called (or a safety bound passes), so a
  /// test can hold a writer inside a send. Reads serve one scripted wire and then read as closed.</summary>
  TGatedTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  const
    // the longest a Write waits for Open, so a failing test cannot hang the run
    GateBoundMs = 20000;
  var
    FWire: TBytes;
    FServed: Boolean;
    FGate: TEvent;
    FEntered: TEvent;
    FWrites: Int32;
    FWritten: Int32;
    FCaptured: TBytes;
  public
    constructor Create(const AWire: TBytes);
    destructor Destroy; override;
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    /// <summary>Lets every blocked and later Write through.</summary>
    procedure Open;
    /// <summary>Whether a Write has entered the transport within AMs ms.</summary>
    function WaitEntered(AMs: Int32): Boolean;
    /// <summary>The writes that entered, read once the writer has been joined.</summary>
    property Writes: Int32 read FWrites;
    /// <summary>The bytes of the writes that completed, read once the writer has been joined.</summary>
    property Written: Int32 read FWritten;
    /// <summary>Those bytes in completion order, read once the writers have joined.</summary>
    property Captured: TBytes read FCaptured;
  end;

  /// <summary>A timed transport that logs the read caps armed ('a' or 'h' and the ms) and cleared
  /// ('c') on its inner one. The first clear waits for a second arm or for EndHold, within the
  /// hold bound, so a clear outside the read side shows as a reordered log.</summary>
  TCapLogTransport = class sealed(TInterfacedObject, ITlsTransport, ITlsTimedTransport)
  strict private
  const
    DefaultHoldBoundMs = Int32(400);
  var
    FHoldBoundMs: Int32;
    FInner: ITlsTimedTransport;
    FLock: TCriticalSection;
    FSecondArm: TEvent;
    FLog: string;
    FArms: Int32;
    FHeld: Boolean;
    procedure Append(const AEntry: string; AArm: Boolean);
  public
    /// <summary>The first clear waits at most the default hold bound.</summary>
    constructor Create(const AInner: ITlsTimedTransport); overload;
    /// <summary>The first clear waits at most AHoldBoundMs, so a failing test cannot hang the
    /// run.</summary>
    constructor Create(const AInner: ITlsTimedTransport; AHoldBoundMs: Int32); overload;
    destructor Destroy; override;
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    procedure UseClock(const AClock: ITlsMonotonicClock);
    procedure SetReadTimeout(AMs: Int32);
    procedure SetApplicationReadTimeout(AMs: Int32);
    procedure SetWriteTimeout(AMs: Int32);
    /// <summary>Lets the held first clear go ahead.</summary>
    procedure EndHold;
    /// <summary>The caps armed and cleared so far, in order.</summary>
    function Log: string;
  end;

  /// <summary>A host resolver that answers one name, any case, with 127.0.0.1 and refuses the
  /// rest, counting the lookups.</summary>
  TMockHostResolver = class sealed(TInterfacedObject, IHostResolver)
  strict private
  var
    FName: string;
    FAsked: Int32;
  public
    constructor Create(const AName: string);
    function TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
    property Asked: Int32 read FAsked;
  end;

  /// <summary>An engine decorator that counts the calls that run inside it at the same time: each
  /// forwarded call yields once inside, so a caller that does not serialise its engine calls shows
  /// as an overlap.</summary>
  TExclusionProbeEngine = class sealed(TInterfacedObject, ITlsEngine, ITlsEngineInbound,
    ITlsEngineOutbound)
  strict private
  var
    FInner: ITlsEngine;
    FLock: TCriticalSection;
    FInside: Int32;
    FOverlaps: Int32;
    procedure Enter;
    procedure Leave;
  public
    constructor Create(const AInner: ITlsEngine);
    destructor Destroy; override;
    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    function WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32): Int32;
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    procedure SendClose;
    procedure SendAlert(ADescription: TTlsAlertDescription); overload;
    procedure SendAlert(ADescription: TTlsAlertDescription; const AReason: string); overload;
    procedure LatchTransportFailure(const AReason: string);
    procedure StartHandshake;
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingAppData: Int32;
    function ReadEarlyData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingEarlyData: Int32;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    function ConnectionInfo: TTlsConnectionInfo;
    function WantsRead: Boolean;
    function WantsWrite: Boolean;
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function IsTerminal: Boolean;
    function IsClosed: Boolean;
    function IsInboundClosed: Boolean;
    function WriteClosed: Boolean;
    function LastError: TTlsError;
    function ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
    /// <summary>How many calls began while another was still inside.</summary>
    function Overlaps: Int32;
  end;

  /// <summary>An engine over a real one that plays another thread's Close: on the first
  /// IsTerminal call after WantsWrite answered False it seals close_notify, which is how a record
  /// is sealed after a writer's last check and before it lets go of the write side. It can also
  /// owe one more byte once the transport has failed, like a record sealed behind a failed send.</summary>
  TSealAfterDrainEngine = class sealed(TInterfacedObject, ITlsEngine, ITlsEngineInbound,
    ITlsEngineOutbound)
  strict private
  var
    FInner: ITlsEngine;
    FDrained: Boolean;
    FSealed: Boolean;
    FOwesAfterLatch: Boolean;
    FOwed: Boolean;
  public
    constructor Create(const AInner: ITlsEngine);
    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    function WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32): Int32;
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    procedure SendClose;
    procedure SendAlert(ADescription: TTlsAlertDescription); overload;
    procedure SendAlert(ADescription: TTlsAlertDescription; const AReason: string); overload;
    procedure LatchTransportFailure(const AReason: string);
    procedure StartHandshake;
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingAppData: Int32;
    function ReadEarlyData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingEarlyData: Int32;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    function ConnectionInfo: TTlsConnectionInfo;
    function WantsRead: Boolean;
    function WantsWrite: Boolean;
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function IsTerminal: Boolean;
    function IsClosed: Boolean;
    function IsInboundClosed: Boolean;
    function WriteClosed: Boolean;
    function LastError: TTlsError;
    function ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
    /// <summary>Whether it sealed the close_notify.</summary>
    property Sealed: Boolean read FSealed;
    /// <summary>Whether a latch leaves one byte owed.</summary>
    property OwesAfterLatch: Boolean read FOwesAfterLatch write FOwesAfterLatch;
  end;

  // a timed transport that keeps the base's default writability wait, sending one byte at a time
  TTestBareTransport = class(TTlsTimedTransportBase)
  strict private
    FSent: Int32;
  strict protected
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(const AClock: ITlsMonotonicClock);
    property Sent: Int32 read FSent;
  end;

  /// <summary>Runs one action of a test on its own thread, keeping the exception it ended with.</summary>
  TActionThread = class(TThread)
  strict private
  var
    FAction: TThreadMethod;
    FError: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const AAction: TThreadMethod);
    property Error: string read FError;
  end;

  /// <summary>The server half of a loopback on its own thread; owns the server stream.</summary>
  TLoopbackServerThread = class abstract(TThread)
  strict protected
  var
    FStream: TTlsStream;
    FTransport: TMemoryTransport;
    FClientTransport: TMemoryTransport;
  public
    constructor Create(const AStream: TTlsStream; const ATransport,
      AClientTransport: TMemoryTransport);
    destructor Destroy; override;
    /// <summary>Ends the client's write side so a waiting server fails, then joins.</summary>
    procedure Finish;
  end;

implementation

resourcestring
  SMockReceiveTimedOut = 'the mock socket receive timeout elapsed';
  SMockSocketFailed = 'the mock socket failed';
  SMockSocketFailedAt = 'the mock socket failed (write %d)';
  SMockPipeClosed = 'the mock pipe was closed';

{ TMemoryPipe }

constructor TMemoryPipe.Create;
begin
  Create(0);
end;

constructor TMemoryPipe.Create(ACapacity: Int32);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  // manual-reset: stays signaled while bytes are buffered or the pipe is closed
  FEvent := TEvent.Create(nil, True, False, '');
  // manual-reset: stays signaled while there is room or the pipe is closed
  FSpace := TEvent.Create(nil, True, True, '');
  // manual-reset: signaled while a Read waits for data
  FParked := TEvent.Create(nil, True, False, '');
  FHead := 0;
  FCapacity := ACapacity;
  FClosed := False;
  FCorruptAt := -1;
end;

destructor TMemoryPipe.Destroy;
begin
  FParked.Free;
  FSpace.Free;
  FEvent.Free;
  FLock.Free;
  inherited Destroy;
end;

function TMemoryPipe.GetWritten: Int64;
begin
  FLock.Acquire;
  try
    Result := FWritten;
  finally
    FLock.Release;
  end;
end;

function TMemoryPipe.GetStalls: Int64;
begin
  FLock.Acquire;
  try
    Result := FStalls;
  finally
    FLock.Release;
  end;
end;

procedure TMemoryPipe.CorruptByteAt(AOffset: Int64);
begin
  FLock.Acquire;
  try
    FCorruptAt := AOffset;
  finally
    FLock.Release;
  end;
end;

procedure TMemoryPipe.CorruptWithin(AFrom: Int32; ALength: Int32);
begin
  // the caller holds the lock and has just appended ALength bytes at AFrom
  if (FCorruptAt >= FWritten) and (FCorruptAt < FWritten + ALength) then
  begin
    FBuffer[AFrom + Int32(FCorruptAt - FWritten)] :=
      FBuffer[AFrom + Int32(FCorruptAt - FWritten)] xor $FF;
    FCorruptAt := -1;
  end;
end;

function TMemoryPipe.AppendFits(const AData: TBytes; AOffset, ALength: Int32): Int32;
var
  LPending: Int32;
begin
  FLock.Acquire;
  try
    if FClosed then
      raise EInOutError.CreateRes(@SMockPipeClosed);
    LPending := System.Length(FBuffer) - FHead;
    Result := FCapacity - LPending;
    if Result > ALength then
      Result := ALength;
    if Result < ALength then
      System.Inc(FStalls);
    if Result > 0 then
    begin
      if FHead > 0 then
      begin
        Move(FBuffer[FHead], FBuffer[0], LPending);
        FHead := 0;
      end;
      SetLength(FBuffer, LPending + Result);
      Move(AData[AOffset], FBuffer[LPending], Result);
      CorruptWithin(LPending, Result);
      System.Inc(FWritten, Result);
      FEvent.SetEvent;
    end;
    if LPending + Result >= FCapacity then
      FSpace.ResetEvent;
  finally
    FLock.Release;
  end;
end;

procedure TMemoryPipe.WriteBounded(const AData: TBytes; AOffset, ALength: Int32);
var
  LDone: Int32;
begin
  LDone := 0;
  while LDone < ALength do
  begin
    System.Inc(LDone, AppendFits(AData, AOffset + LDone, ALength - LDone));
    if LDone < ALength then
      FSpace.WaitFor(INFINITE);
  end;
end;

function TMemoryPipe.TryWrite(const AData: TBytes; AOffset, ALength: Int32): Int32;
begin
  if ALength <= 0 then
    Exit(0);
  if FCapacity <= 0 then
  begin
    Write(AData, AOffset, ALength);
    Exit(ALength);
  end;
  Result := AppendFits(AData, AOffset, ALength);
end;

procedure TMemoryPipe.Write(const AData: TBytes; AOffset, ALength: Int32);
var
  LOld: Int32;
begin
  if ALength <= 0 then
    Exit;
  if FCapacity > 0 then
  begin
    WriteBounded(AData, AOffset, ALength);
    Exit;
  end;
  FLock.Acquire;
  try
    LOld := System.Length(FBuffer);
    SetLength(FBuffer, LOld + ALength);
    Move(AData[AOffset], FBuffer[LOld], ALength);
    CorruptWithin(LOld, ALength);
    System.Inc(FWritten, ALength);
    FEvent.SetEvent;
  finally
    FLock.Release;
  end;
end;

function TMemoryPipe.Read(var ADest: TBytes; AOffset, AMaxLength: Int32): Int32;
var
  LAvail: Int32;
begin
  repeat
    FLock.Acquire;
    try
      LAvail := System.Length(FBuffer) - FHead;
      if LAvail > 0 then
      begin
        Result := LAvail;
        if Result > AMaxLength then
          Result := AMaxLength;
        Move(FBuffer[FHead], ADest[AOffset], Result);
        Inc(FHead, Result);
        if FHead >= System.Length(FBuffer) then
        begin
          FBuffer := nil;
          FHead := 0;
          FEvent.ResetEvent; // drained: block the next reader until more arrives
        end;
        FSpace.SetEvent;
        Exit;
      end;
      if FClosed then
        Exit(0);
    finally
      FLock.Release;
    end;
    FParked.SetEvent;
    FEvent.WaitFor(INFINITE);
    FParked.ResetEvent;
  until False;
end;

procedure TMemoryPipe.Close;
begin
  FLock.Acquire;
  try
    FClosed := True;
    FEvent.SetEvent;
    FSpace.SetEvent;
  finally
    FLock.Release;
  end;
end;

function TMemoryPipe.WaitData(AMs: Int32): Boolean;
begin
  Result := FEvent.WaitFor(Cardinal(AMs)) = wrSignaled;
end;

function TMemoryPipe.WaitSpace(AMs: Int32): Boolean;
begin
  Result := FSpace.WaitFor(Cardinal(AMs)) = wrSignaled;
end;

function TMemoryPipe.WaitParked(AMs: Int32): Boolean;
begin
  Result := FParked.WaitFor(Cardinal(AMs)) = wrSignaled;
end;

{ TWedgeWatchdog }

constructor TWedgeWatchdog.Create(const APipeA, APipeB: TMemoryPipe;
  ADeadlineMs: UInt32);
begin
  Create(APipeA, APipeB, ADeadlineMs, ADeadlineMs);
end;

constructor TWedgeWatchdog.Create(const APipeA, APipeB: TMemoryPipe;
  AIdleMs, ABackstopMs: UInt32);
begin
  Create(APipeA, APipeB, AIdleMs, ABackstopMs, ABackstopMs, nil);
end;

constructor TWedgeWatchdog.Create(const APipeA, APipeB: TMemoryPipe;
  AIdleMs, ABackstopMs, AStallMs: UInt32; const AProgress: TWedgeProgress);
begin
  inherited Create(True);
  FPipeA := APipeA;
  FPipeB := APipeB;
  FIdleMs := AIdleMs;
  FBackstopMs := ABackstopMs;
  FStallMs := AStallMs;
  FProgress := AProgress;
  FClock := TSystemMonotonicClock.Create;
  FDone := TEvent.Create(nil, True, False, '');
  FFired := False;
  FreeOnTerminate := False;
end;

destructor TWedgeWatchdog.Destroy;
begin
  inherited Destroy;
  FDone.Free;
end;

procedure TWedgeWatchdog.Execute;
var
  LMoved, LLastMoved, LDone, LLastDone, LStart, LNow, LMovedAt, LDoneAt: Int64;
begin
  // wait for the exchange to disarm us; if it goes quiet, stops making progress or runs out the
  // backstop the pump has wedged, so close both pipes to unblock its reads and let the test
  // surface the failure
  LLastMoved := FPipeA.Written + FPipeB.Written;
  LLastDone := 0;
  if Assigned(FProgress) then
    LLastDone := FProgress();
  LStart := FClock.NowMonotonicMillis;
  LMovedAt := LStart;
  LDoneAt := LStart;
  while FDone.WaitFor(SliceMs) = wrTimeout do
  begin
    LNow := FClock.NowMonotonicMillis;
    LMoved := FPipeA.Written + FPipeB.Written;
    if LMoved <> LLastMoved then
    begin
      LLastMoved := LMoved;
      LMovedAt := LNow;
    end;
    if Assigned(FProgress) then
    begin
      LDone := FProgress();
      if LDone <> LLastDone then
      begin
        LLastDone := LDone;
        LDoneAt := LNow;
      end;
    end;
    if (LNow - LMovedAt >= FIdleMs) or (LNow - LStart >= FBackstopMs) or
      (Assigned(FProgress) and (LNow - LDoneAt >= FStallMs)) then
    begin
      FFired := True;
      FPipeA.Close;
      FPipeB.Close;
      Exit;
    end;
  end;
end;

procedure TWedgeWatchdog.Disarm;
begin
  FDone.SetEvent;
end;

{ TMemoryTransport }

constructor TMemoryTransport.Create(const ARead, AWrite: TMemoryPipe);
begin
  inherited Create;
  FRead := ARead;
  FWrite := AWrite;
end;

destructor TMemoryTransport.Destroy;
begin
  // each transport owns its write pipe; the paired transports free both pipes exactly once
  FWrite.Free;
  inherited Destroy;
end;

function TMemoryTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FRead.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TMemoryTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  FWrite.Write(ABuffer, AOffset, ALength);
end;

procedure TMemoryTransport.CloseWrite;
begin
  FWrite.Close;
end;

function TMemoryTransport.WaitReadParked(AMs: Int32): Boolean;
begin
  Result := FRead.WaitParked(AMs);
end;

{ TPeakProbeTransport }

constructor TPeakProbeTransport.Create(const AInner: ITlsTransport;
  const AEngine: ITlsEngine);
begin
  inherited Create;
  FInner := AInner;
  FEngine := AEngine;
  FArmed := False;
  FPeakPending := 0;
end;

function TPeakProbeTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FInner.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TPeakProbeTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
var
  LBuf: TBytes;
  LGot, LTotal: Int32;
begin
  FInner.Write(ABuffer, AOffset, ALength);
  if not FArmed then
    Exit;
  // what the engine still holds after this write is what was sealed ahead of it
  LTotal := ALength;
  SetLength(LBuf, 65536);
  repeat
    LGot := FEngine.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
    begin
      FInner.Write(LBuf, 0, LGot);
      Inc(LTotal, LGot);
    end;
  until LGot = 0;
  if LTotal > FPeakPending then
    FPeakPending := LTotal;
end;

procedure TPeakProbeTransport.Arm;
begin
  FArmed := True;
  FPeakPending := 0;
end;

{ TTimeoutOnceTransport }

constructor TTimeoutOnceTransport.Create(const AInner: ITlsTransport);
begin
  inherited Create;
  FInner := AInner;
  FArmed := False;
end;

function TTimeoutOnceTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  if FArmed then
  begin
    FArmed := False;
    raise ETlsReadTimeout.CreateRes(@SMockReceiveTimedOut);
  end;
  Result := FInner.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TTimeoutOnceTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  FInner.Write(ABuffer, AOffset, ALength);
end;

procedure TTimeoutOnceTransport.Arm;
begin
  FArmed := True;
end;

{ TFailingReadTransport }

function TFailingReadTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  raise EInOutError.CreateRes(@SMockSocketFailed);
end;

procedure TFailingReadTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
end;

{ TRecordingTransport }

function TRecordingTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := 0;
end;

procedure TRecordingTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  System.Inc(FWritten, ALength);
end;

{ TCountingTransport }

constructor TCountingTransport.Create(const AInner: ITlsTransport);
begin
  inherited Create;
  FInner := AInner;
end;

function TCountingTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  FLastReadBuffer := Pointer(ABuffer);
  Result := FInner.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TCountingTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  FLastWriteBuffer := Pointer(ABuffer);
  FInner.Write(ABuffer, AOffset, ALength);
  System.Inc(FWritten, ALength);
end;

{ TScriptedTransport }

constructor TScriptedTransport.Create(const AWire: TBytes; AWritesFail: Boolean);
begin
  inherited Create;
  FWire := System.Copy(AWire);
  FWritesFail := AWritesFail;
end;

function TScriptedTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := 0;
  if FServed then
    Exit;
  FServed := True;
  Result := System.Length(FWire);
  if Result > AMaxLength then
    Result := AMaxLength;
  System.Move(FWire[0], ABuffer[AOffset], Result);
end;

procedure TScriptedTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  if FWritesFail then
    raise EInOutError.CreateRes(@SMockSocketFailed);
  System.Inc(FWritten, ALength);
end;

{ TDeadWriteTransport }

function TDeadWriteTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := 0;
end;

procedure TDeadWriteTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  System.Inc(FAttempts);
  raise EInOutError.CreateResFmt(@SMockSocketFailedAt, [FAttempts]);
end;

{ TPipeTimedTransport }

constructor TPipeTimedTransport.Create(const ARead, AWrite: TMemoryPipe);
begin
  inherited Create;
  FRead := ARead;
  FWrite := AWrite;
end;

destructor TPipeTimedTransport.Destroy;
begin
  FWrite.Free;
  inherited Destroy;
end;

function TPipeTimedTransport.WaitReadable(AMs: Int32): Boolean;
begin
  Result := FRead.WaitData(AMs);
end;

function TPipeTimedTransport.WaitWritable(AMs: Int32): Boolean;
begin
  Result := FWrite.WaitSpace(AMs);
end;

function TPipeTimedTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FRead.Read(ABuffer, AOffset, AMaxLength);
end;

function TPipeTimedTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  Result := FWrite.TryWrite(ABuffer, AOffset, ALength);
  if Result > 0 then
    Exit;
  // an armed send waited for room first, so only an unarmed one meets a full pipe
  FWrite.Write(ABuffer, AOffset, ALength);
  Result := ALength;
end;

function TPipeTimedTransport.ArmedReadTimeoutMs: Int32;
begin
  Result := ReadTimeoutMs;
end;

procedure TPipeTimedTransport.CloseWrite;
begin
  FWrite.Close;
end;

{ TStalledTransport }

constructor TStalledTransport.Create(const AWire: TBytes; const AClock: ITlsMonotonicClock);
begin
  inherited Create;
  UseClock(AClock);
  FWire := System.Copy(AWire);
end;

function TStalledTransport.WaitWritable(AMs: Int32): Boolean;
begin
  Result := False;
end;

function TStalledTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := 0;
  if FServed then
    Exit;
  FServed := True;
  Result := System.Length(FWire);
  if Result > AMaxLength then
    Result := AMaxLength;
  System.Move(FWire[0], ABuffer[AOffset], Result);
end;

function TStalledTransport.SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32;
begin
  System.Inc(FSends);
  Result := ALength;
end;

{ TGatedTransport }

constructor TGatedTransport.Create(const AWire: TBytes);
begin
  inherited Create;
  FWire := System.Copy(AWire);
  FGate := TEvent.Create(nil, True, False, '');
  FEntered := TEvent.Create(nil, True, False, '');
end;

destructor TGatedTransport.Destroy;
begin
  FEntered.Free;
  FGate.Free;
  inherited Destroy;
end;

function TGatedTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := 0;
  if FServed then
    Exit;
  FServed := True;
  Result := System.Length(FWire);
  if Result > AMaxLength then
    Result := AMaxLength;
  System.Move(FWire[0], ABuffer[AOffset], Result);
end;

procedure TGatedTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
var
  LOld: Int32;
begin
  System.Inc(FWrites);
  FEntered.SetEvent;
  FGate.WaitFor(GateBoundMs);
  System.Inc(FWritten, ALength);
  LOld := System.Length(FCaptured);
  System.SetLength(FCaptured, LOld + ALength);
  System.Move(ABuffer[AOffset], FCaptured[LOld], ALength);
end;

procedure TGatedTransport.Open;
begin
  FGate.SetEvent;
end;

function TGatedTransport.WaitEntered(AMs: Int32): Boolean;
begin
  Result := FEntered.WaitFor(Cardinal(AMs)) = wrSignaled;
end;

{ TCapLogTransport }

constructor TCapLogTransport.Create(const AInner: ITlsTimedTransport);
begin
  Create(AInner, DefaultHoldBoundMs);
end;

constructor TCapLogTransport.Create(const AInner: ITlsTimedTransport; AHoldBoundMs: Int32);
begin
  inherited Create;
  FHoldBoundMs := AHoldBoundMs;
  FInner := AInner;
  FLock := TCriticalSection.Create;
  FSecondArm := TEvent.Create(nil, True, False, '');
end;

destructor TCapLogTransport.Destroy;
begin
  FSecondArm.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TCapLogTransport.Append(const AEntry: string; AArm: Boolean);
begin
  FLock.Acquire;
  try
    FLog := FLog + AEntry;
    if AArm then
    begin
      System.Inc(FArms);
      if FArms >= 2 then
        FSecondArm.SetEvent;
    end;
  finally
    FLock.Release;
  end;
end;

function TCapLogTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := FInner.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TCapLogTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  FInner.Write(ABuffer, AOffset, ALength);
end;

procedure TCapLogTransport.UseClock(const AClock: ITlsMonotonicClock);
begin
  FInner.UseClock(AClock);
end;

procedure TCapLogTransport.SetReadTimeout(AMs: Int32);
var
  LHold: Boolean;
begin
  if AMs > 0 then
    Append('h' + IntToStr(AMs) + ';', True)
  else
  begin
    FLock.Acquire;
    try
      LHold := not FHeld;
      FHeld := True;
    finally
      FLock.Release;
    end;
    if LHold then
      FSecondArm.WaitFor(Cardinal(FHoldBoundMs));
    Append('c;', False);
  end;
  FInner.SetReadTimeout(AMs);
end;

procedure TCapLogTransport.SetApplicationReadTimeout(AMs: Int32);
begin
  Append('a' + IntToStr(AMs) + ';', True);
  FInner.SetApplicationReadTimeout(AMs);
end;

procedure TCapLogTransport.SetWriteTimeout(AMs: Int32);
begin
  FInner.SetWriteTimeout(AMs);
end;

procedure TCapLogTransport.EndHold;
begin
  FSecondArm.SetEvent;
end;

function TCapLogTransport.Log: string;
begin
  FLock.Acquire;
  try
    Result := FLog;
  finally
    FLock.Release;
  end;
end;

{ TMockHostResolver }

constructor TMockHostResolver.Create(const AName: string);
begin
  inherited Create;
  FName := AName;
end;

function TMockHostResolver.TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
begin
  System.Inc(FAsked);
  AAddress := nil;
  Result := SameText(AHost, FName);
  if Result then
    AAddress := TBytes.Create(127, 0, 0, 1);
end;

{ TExclusionProbeEngine }

constructor TExclusionProbeEngine.Create(const AInner: ITlsEngine);
begin
  inherited Create;
  FInner := AInner;
  FLock := TCriticalSection.Create;
end;

destructor TExclusionProbeEngine.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TExclusionProbeEngine.Enter;
begin
  FLock.Acquire;
  try
    System.Inc(FInside);
    if FInside > 1 then
      System.Inc(FOverlaps);
  finally
    FLock.Release;
  end;
  Sleep(0);
end;

procedure TExclusionProbeEngine.Leave;
begin
  FLock.Acquire;
  try
    System.Dec(FInside);
  finally
    FLock.Release;
  end;
end;

function TExclusionProbeEngine.Overlaps: Int32;
begin
  FLock.Acquire;
  try
    Result := FOverlaps;
  finally
    FLock.Release;
  end;
end;

function TExclusionProbeEngine.ProcessInput(const AWire: TBytes; AOffset,
  ALength: Int32): TTlsOutcome;
begin
  Enter;
  try
    Result := FInner.ProcessInput(AWire, AOffset, ALength);
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.Write(const AData: TBytes; AOffset, ALength: Int32);
begin
  Enter;
  try
    FInner.Write(AData, AOffset, ALength);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.WriteEarlyData(const AData: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  Enter;
  try
    Result := FInner.WriteEarlyData(AData, AOffset, ALength);
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.RequestKeyUpdate(ARequest: TKeyUpdateRequest);
begin
  Enter;
  try
    FInner.RequestKeyUpdate(ARequest);
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.SendClose;
begin
  Enter;
  try
    FInner.SendClose;
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.SendAlert(ADescription: TTlsAlertDescription);
begin
  Enter;
  try
    FInner.SendAlert(ADescription);
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.SendAlert(ADescription: TTlsAlertDescription;
  const AReason: string);
begin
  Enter;
  try
    FInner.SendAlert(ADescription, AReason);
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.LatchTransportFailure(const AReason: string);
begin
  Enter;
  try
    FInner.LatchTransportFailure(AReason);
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.StartHandshake;
begin
  Enter;
  try
    FInner.StartHandshake;
  finally
    Leave;
  end;
end;

procedure TExclusionProbeEngine.SetCertificateVerdict(AAccept: Boolean;
  AAlert: TTlsAlertDescription);
begin
  Enter;
  try
    FInner.SetCertificateVerdict(AAccept, AAlert);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
begin
  Enter;
  try
    Result := FInner.TakeOutgoing(ADest, ADestOffset);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.ReadAppData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
begin
  Enter;
  try
    Result := FInner.ReadAppData(ADest, ADestOffset, AMaxLength);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.PendingAppData: Int32;
begin
  Enter;
  try
    Result := FInner.PendingAppData;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.ReadEarlyData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
begin
  Enter;
  try
    Result := FInner.ReadEarlyData(ADest, ADestOffset, AMaxLength);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.PendingEarlyData: Int32;
begin
  Enter;
  try
    Result := FInner.PendingEarlyData;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.NextEvent(out AEvent: ITlsEvent): Boolean;
begin
  Enter;
  try
    Result := FInner.NextEvent(AEvent);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.ConnectionInfo: TTlsConnectionInfo;
begin
  Enter;
  try
    Result := FInner.ConnectionInfo;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.WantsRead: Boolean;
begin
  Enter;
  try
    Result := FInner.WantsRead;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.WantsWrite: Boolean;
begin
  Enter;
  try
    Result := FInner.WantsWrite;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.IsHandshaking: Boolean;
begin
  Enter;
  try
    Result := FInner.IsHandshaking;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.AwaitingCertificateVerdict: Boolean;
begin
  Enter;
  try
    Result := FInner.AwaitingCertificateVerdict;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.IsTerminal: Boolean;
begin
  Enter;
  try
    Result := FInner.IsTerminal;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.IsClosed: Boolean;
begin
  Enter;
  try
    Result := FInner.IsClosed;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.IsInboundClosed: Boolean;
begin
  Enter;
  try
    Result := FInner.IsInboundClosed;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.WriteClosed: Boolean;
begin
  Enter;
  try
    Result := FInner.WriteClosed;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.LastError: TTlsError;
begin
  Enter;
  try
    Result := FInner.LastError;
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  Enter;
  try
    Result := FInner.ExportKeyingMaterial(ALabel, ALength);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Enter;
  try
    Result := FInner.ExportKeyingMaterial(ALabel, AContext, ALength);
  finally
    Leave;
  end;
end;

function TExclusionProbeEngine.ExportEarlyKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Enter;
  try
    Result := FInner.ExportEarlyKeyingMaterial(ALabel, AContext, ALength);
  finally
    Leave;
  end;
end;

{ TSealAfterDrainEngine }

constructor TSealAfterDrainEngine.Create(const AInner: ITlsEngine);
begin
  inherited Create;
  FInner := AInner;
end;

function TSealAfterDrainEngine.ProcessInput(const AWire: TBytes; AOffset,
  ALength: Int32): TTlsOutcome;
begin
  Result := FInner.ProcessInput(AWire, AOffset, ALength);
end;

procedure TSealAfterDrainEngine.Write(const AData: TBytes; AOffset, ALength: Int32);
begin
  FInner.Write(AData, AOffset, ALength);
end;

function TSealAfterDrainEngine.WriteEarlyData(const AData: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  Result := FInner.WriteEarlyData(AData, AOffset, ALength);
end;

procedure TSealAfterDrainEngine.RequestKeyUpdate(ARequest: TKeyUpdateRequest);
begin
  FInner.RequestKeyUpdate(ARequest);
end;

procedure TSealAfterDrainEngine.SendClose;
begin
  FInner.SendClose;
end;

procedure TSealAfterDrainEngine.SendAlert(ADescription: TTlsAlertDescription);
begin
  FInner.SendAlert(ADescription);
end;

procedure TSealAfterDrainEngine.SendAlert(ADescription: TTlsAlertDescription;
  const AReason: string);
begin
  FInner.SendAlert(ADescription, AReason);
end;

procedure TSealAfterDrainEngine.LatchTransportFailure(const AReason: string);
begin
  FInner.LatchTransportFailure(AReason);
  FOwed := FOwesAfterLatch;
  // owed once, so the recheck that fails to send it is not owed it again
  FOwesAfterLatch := False;
end;

procedure TSealAfterDrainEngine.StartHandshake;
begin
  FInner.StartHandshake;
end;

procedure TSealAfterDrainEngine.SetCertificateVerdict(AAccept: Boolean;
  AAlert: TTlsAlertDescription);
begin
  FInner.SetCertificateVerdict(AAccept, AAlert);
end;

function TSealAfterDrainEngine.TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
begin
  Result := FInner.TakeOutgoing(ADest, ADestOffset);
  if FOwed and (Result = 0) then
  begin
    FOwed := False;
    ADest[ADestOffset] := 0;
    Result := 1;
  end;
end;

function TSealAfterDrainEngine.ReadAppData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FInner.ReadAppData(ADest, ADestOffset, AMaxLength);
end;

function TSealAfterDrainEngine.PendingAppData: Int32;
begin
  Result := FInner.PendingAppData;
end;

function TSealAfterDrainEngine.ReadEarlyData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FInner.ReadEarlyData(ADest, ADestOffset, AMaxLength);
end;

function TSealAfterDrainEngine.PendingEarlyData: Int32;
begin
  Result := FInner.PendingEarlyData;
end;

function TSealAfterDrainEngine.NextEvent(out AEvent: ITlsEvent): Boolean;
begin
  Result := FInner.NextEvent(AEvent);
end;

function TSealAfterDrainEngine.ConnectionInfo: TTlsConnectionInfo;
begin
  Result := FInner.ConnectionInfo;
end;

function TSealAfterDrainEngine.WantsRead: Boolean;
begin
  Result := FInner.WantsRead;
end;

function TSealAfterDrainEngine.WantsWrite: Boolean;
begin
  Result := FInner.WantsWrite or FOwed;
  if not Result then
    FDrained := True;
end;

function TSealAfterDrainEngine.IsHandshaking: Boolean;
begin
  Result := FInner.IsHandshaking;
end;

function TSealAfterDrainEngine.AwaitingCertificateVerdict: Boolean;
begin
  Result := FInner.AwaitingCertificateVerdict;
end;

function TSealAfterDrainEngine.IsTerminal: Boolean;
begin
  if FDrained and not FSealed then
  begin
    FSealed := True;
    FInner.SendClose;
  end;
  Result := FInner.IsTerminal;
end;

function TSealAfterDrainEngine.IsClosed: Boolean;
begin
  Result := FInner.IsClosed;
end;

function TSealAfterDrainEngine.IsInboundClosed: Boolean;
begin
  Result := FInner.IsInboundClosed;
end;

function TSealAfterDrainEngine.WriteClosed: Boolean;
begin
  Result := FInner.WriteClosed;
end;

function TSealAfterDrainEngine.LastError: TTlsError;
begin
  Result := FInner.LastError;
end;

function TSealAfterDrainEngine.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  Result := FInner.ExportKeyingMaterial(ALabel, ALength);
end;

function TSealAfterDrainEngine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := FInner.ExportKeyingMaterial(ALabel, AContext, ALength);
end;

function TSealAfterDrainEngine.ExportEarlyKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := FInner.ExportEarlyKeyingMaterial(ALabel, AContext, ALength);
end;

{ TTestBareTransport }

constructor TTestBareTransport.Create(const AClock: ITlsMonotonicClock);
begin
  inherited Create;
  UseClock(AClock);
end;

function TTestBareTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := 0;
end;

function TTestBareTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  Inc(FSent);
  Result := 1;
end;

{ TActionThread }

constructor TActionThread.Create(const AAction: TThreadMethod);
begin
  inherited Create(True);
  FAction := AAction;
  FreeOnTerminate := False;
end;

procedure TActionThread.Execute;
begin
  try
    FAction;
  except
    on E: Exception do
      FError := E.ClassName + ': ' + E.Message;
  end;
end;

{ TLoopbackServerThread }

constructor TLoopbackServerThread.Create(const AStream: TTlsStream;
  const ATransport, AClientTransport: TMemoryTransport);
begin
  inherited Create(True);
  FStream := AStream;
  FTransport := ATransport;
  FClientTransport := AClientTransport;
  FreeOnTerminate := False;
end;

destructor TLoopbackServerThread.Destroy;
begin
  // EOF the client so a server parked in a read exits and the join cannot hang the run
  FClientTransport.CloseWrite;
  inherited Destroy;
  FStream.Free;
end;

procedure TLoopbackServerThread.Finish;
begin
  FClientTransport.CloseWrite;
  WaitFor;
end;

end.
