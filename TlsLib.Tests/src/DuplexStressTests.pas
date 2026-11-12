{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit DuplexStressTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  SyncObjs,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpIClock,
  TlpClock,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpHandshakeMessages,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlpTlsCredential,
  TlpITlsEngine,
  TlpITlsTransport,
  TlpTlsEngineFactory,
  TlpTlsLibExceptions,
  TlpTlsConnection,
  TlpTlsStream,
  MockTransport,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>How long the messages one writer sends are.</summary>
  TPayloadKind = (
    Tiny,        // 0 to 32 bytes
    SingleByte,  // 0 to 8 bytes, each written with its own call
    Boundary,    // a record's plaintext limit, give or take a few bytes
    Large,       // longer than the pump's write slice
    Mixed);      // all of the above

  /// <summary>What the third party in a close scenario does to the client mid-stream.</summary>
  TCloseKind = (NoClose, CloseNotifyMidStream, AlertMidStream);

  /// <summary>Whether the peers are TTlsStream or TTlsConnection objects.</summary>
  TIoKind = (OnStream, OnConnection);

  /// <summary>What a stress worker was last doing, for the wedge diagnostic.</summary>
  TStressPhase = (Starting, Sending, Rekeying, Receiving, Querying, Closing);

  /// <summary>How a reader's stream ended.</summary>
  TReaderOutcome = (StillReading, EndedWithFin, EndedWithEof, EndedWithAlert);

  /// <summary>One stress scenario: both peers exchange framed messages over bounded pipes.</summary>
  TStressSpec = record
    Wire: UInt16;
    Io: TIoKind;
    Payload: TPayloadKind;
    // messages each writer sends before its FIN
    Frames: Int32;
    // the reader asks for one byte at a time
    SingleByteReads: Boolean;
    // a writer asks for fresh keys after every this many messages (0 = never)
    KeyUpdateEvery: Int32;
    // the capacity of each pipe
    Capacity: Int32;
    // both pipes must have been full at some point
    Backpressure: Boolean;
    // the client's engine counts the calls that run inside it at once
    Probe: Boolean;
    // a third thread per peer polls ConnectionInfo, PendingReadBytes, the exporter and rekeys
    Query: Boolean;
    ClientWriters: Int32;
    // False leaves the server with no writer
    ServerWrites: Boolean;
    // the server is one thread alternating a send with a short read
    ServerAlternates: Boolean;
    Close: TCloseKind;
    // the client has written this many bytes when the close happens
    CloseAtBytes: Int64;
    // the close waits up to this many yields
    CloseSpinMax: Int32;
    // seeds the close's number of yields
    CloseSeed: UInt32;
    // the close comes as soon as the client's handshake is done, racing the writer's first messages
    CloseOnHandshake: Boolean;
    // the server has no writer and its reader must send nothing while the client rekeys
    ReadOnlyServer: Boolean;
    // a byte of the client's stream is flipped at this offset (0 = none), failing the server's reader
    CorruptAt: Int64;
    // the writer ends with its last message, so no later call of it can send a stranded record
    NoFin: Boolean;
    // the client reads for a FIN that a server with no writer never sends
    Wedge: Boolean;
    DeadlineMs: UInt32;
  end;

  /// <summary>The surface a stress worker uses on a peer, which is a TTlsStream or a
  /// TTlsConnection, and owns it.</summary>
  TStressIo = class sealed(TObject)
  strict private
  var
    FStream: TTlsStream;
    FConnection: TTlsConnection;
  public
    constructor Create(const AStream: TTlsStream); overload;
    constructor Create(const AConnection: TTlsConnection); overload;
    destructor Destroy; override;
    /// <summary>Returns once the handshake is complete, driving it if no other thread does.</summary>
    procedure Handshake;
    function Read(var ABuffer; ACount: Int32): Int32;
    function ReadTimed(var ABuffer; ACount, AMs: Int32): Int32;
    procedure Write(const ABuffer; ACount: Int32);
    procedure Rekey(ARequest: TKeyUpdateRequest);
    function Exported: TBytes;
    function Version: UInt16;
    function Pending: Int32;
    procedure CloseNotify;
    procedure SendAlert(ADescription: TTlsAlertDescription);
  end;

  /// <summary>A failure the stress itself detects: a corrupt, lost or reordered byte.</summary>
  EStressFailure = class(Exception);

  /// <summary>Checks a byte stream of framed messages: a header (magic that names the writer, the
  /// writer's sequence number, the length) then a payload whose every byte is a function of its
  /// place. A FIN frame ends a writer.</summary>
  TFrameParser = class sealed(TObject)
  public
  const
    HeaderLength = Int32(12);
    MagicBase = UInt32($F00D0000);
    FinBase = UInt32($F1F10000);
    MaxLength = UInt32(400000);
  strict private
  var
    FExpected: array[0..1] of UInt32;
    FHeader: array[0..HeaderLength - 1] of Byte;
    FHave: Int32;
    FWriter: Int32;
    FSeq: UInt32;
    FLeft: UInt32;
    FPos: UInt32;
    FIsFin: Boolean;
    FFins: Int32;
    FFrames: Int32;
    FBytes: Int64;
    FError: string;
    function Fail(const AMessage: string): Boolean;
    procedure EndOfFrame;
    function EndOfHeader: Boolean;
  public
    /// <summary>The byte every frame of ASeq from AWriter holds at AIndex.</summary>
    class function Pattern(AWriter: Int32; ASeq: UInt32; AIndex: UInt32): Byte; static;
    class procedure PutU32(var ABuffer: TBytes; AOffset: Int32; AValue: UInt32); static;
    class function GetU32(const ABuffer: array of Byte; AOffset: Int32): UInt32; static;
    /// <summary>Consumes ACount bytes; False when they are not the stream the writers sent.</summary>
    function Feed(const ABuffer: TBytes; ACount: Int32): Boolean;
    /// <summary>Whether the bytes fed so far end exactly at a frame boundary.</summary>
    function Idle: Boolean;
    property Fins: Int32 read FFins;
    property Frames: Int32 read FFrames;
    property Bytes: Int64 read FBytes;
    property Error: string read FError;
  end;

  /// <summary>A thread of a stress run that keeps its failure and a note of where it was.</summary>
  TStressWorker = class abstract(TThread)
  strict private
  var
    FTitle: string;
    FEnded: TEvent;
    FError: string;
    FPhase: TStressPhase;
    FSeq: Int32;
    FTolerate: Boolean;
    FStopNote: string;
  protected
    procedure Execute; override;
  strict protected
  var
    FBytes: Int64;
    FAttempted: Int64;
  strict protected
    procedure Run; virtual; abstract;
    procedure Note(APhase: TStressPhase; ASeq: Int32);
  public
    constructor Create(const AName: string; ATolerateStops: Boolean);
    destructor Destroy; override;
    function WaitEnded(AMs: Cardinal): Boolean;
    function Describe: string;
    // bytes whose sending or receiving has completed
    property Bytes: Int64 read FBytes;
    // bytes whose sending has begun
    property Attempted: Int64 read FAttempted;
    property Error: string read FError;
    property Title: string read FTitle;
  end;

  TStressWriter = class sealed(TStressWorker)
  strict private
  var
    FIo: TStressIo;
    FSpec: TStressSpec;
    FWriterId: Int32;
    FSeed: UInt32;
    FReached: TEvent;
    FFinReleased: TEvent;
    FHoldFin: Boolean;
    procedure Send;
  strict protected
    procedure Run; override;
  public
    constructor Create(const AName: string; const AIo: TStressIo; const ASpec: TStressSpec;
      AWriterId: Int32; ASeed: UInt32; AHoldFin: Boolean);
    destructor Destroy; override;
    /// <summary>Whether the writer has sent CloseAtBytes bytes, or ended, within AMs ms.</summary>
    function WaitReached(AMs: Cardinal): Boolean;
    /// <summary>Lets a writer in a close scenario send its FIN once the close was requested.</summary>
    procedure ReleaseFin;
  end;

  TStressReader = class sealed(TStressWorker)
  strict private
  var
    FIo: TStressIo;
    FSingleByte: Boolean;
    FExpectFins: Int32;
    FEofIsEnd: Boolean;
    FAlertIsEnd: Boolean;
    FOutcome: TReaderOutcome;
    FAlert: TTlsAlertDescription;
  strict protected
    procedure Run; override;
  public
    constructor Create(const AName: string; const AIo: TStressIo; ASingleByte: Boolean;
      AExpectFins: Int32; AEofIsEnd, AAlertIsEnd: Boolean);
    property Outcome: TReaderOutcome read FOutcome;
    property Alert: TTlsAlertDescription read FAlert;
  end;

  /// <summary>A peer that is one thread: it sends a message, then reads what has arrived.</summary>
  TStressAlternator = class sealed(TStressWorker)
  strict private
  var
    FIo: TStressIo;
    FSpec: TStressSpec;
    FExpectFins: Int32;
  strict protected
    procedure Run; override;
  public
    constructor Create(const AName: string; const AIo: TStressIo; const ASpec: TStressSpec;
      AExpectFins: Int32);
  end;

  /// <summary>Polls a peer from a third thread until that peer's writer has ended, after which the
  /// other side's reader may be gone and a rekey could block on a full pipe.</summary>
  TStressQuerier = class sealed(TStressWorker)
  strict private
  var
    FIo: TStressIo;
    FWire: UInt16;
    FWriter: TStressWriter;
    FExported: TBytes;
  strict protected
    procedure Run; override;
  public
    constructor Create(const AName: string; const AIo: TStressIo; AWire: UInt16;
      const AWriter: TStressWriter);
    // the first exporter value this thread saw
    property Exported: TBytes read FExported;
  end;

  /// <summary>Closes or refuses the client once its writer has sent enough.</summary>
  TStressCloser = class sealed(TStressWorker)
  strict private
  var
    FIo: TStressIo;
    FWriter: TStressWriter;
    FKind: TCloseKind;
    FSpinMax: Int32;
    FSeed: UInt32;
    FOnHandshake: Boolean;
  strict protected
    procedure Run; override;
  public
    constructor Create(const AName: string; const AIo: TStressIo; const AWriter: TStressWriter;
      AKind: TCloseKind; ASpinMax: Int32; ASeed: UInt32; AOnHandshake: Boolean);
  end;

  /// <summary>Two peers over bounded in-memory pipes, the threads that load them and the watchdog
  /// that fails a wedge instead of hanging the run. Finish returns '' or what went wrong.</summary>
  TStressRun = class sealed(TObject)
  strict private
  const
    // how many 100 ms waits workers get to unwind after the watchdog fires or the run is abandoned
    UnwindWaits = Int32(150);
  var
    FSpec: TStressSpec;
    FC2S: TMemoryPipe;
    FS2C: TMemoryPipe;
    FClientTransport: ITlsTimedTransport;
    FServerTransport: ITlsTimedTransport;
    FClient: TStressIo;
    FServer: TStressIo;
    FClientProbe: TExclusionProbeEngine;
    FWatch: TWedgeWatchdog;
    FWorkers: TObjectList<TStressWorker>;
    FClientWriter: TStressWriter;
    FClientWriter2: TStressWriter;
    FClientReader: TStressReader;
    FServerWriter: TStressWriter;
    FServerReader: TStressReader;
    FServerAlternator: TStressAlternator;
    FClientQuerier: TStressQuerier;
    FServerQuerier: TStressQuerier;
    FCloser: TStressCloser;
    FUnwound: Int32;
    FAbandoning: Boolean;
    FStuck: Boolean;
    // what the server had written when its handshake ended, and what the read-only check found
    FBaseline: Int64;
    FNote: string;
    function NewIo(const AConfig: ITlsClientConfig; const AServerConfig: ITlsServerConfig;
      const ATransport: ITlsTimedTransport): TStressIo;
    function Spawn(const AWorker: TStressWorker): TStressWorker;
    function AwaitEnded(const AWorker: TStressWorker): Boolean;
    function AwaitAll(const AWorkers: array of TStressWorker): Boolean;
    function Failures: string;
    function CheckTraffic: string;
    function CheckClose: string;
    function CheckCorrupt: string;
    function CheckExporters: string;
    function CheckProbe: string;
    function CheckBackpressure: string;
    /// <summary>The read-only server answered nothing while asked to rekey; its first write then
    /// sends the owed reply and a FIN.</summary>
    procedure ServerSpeaksOnce;
  public
    constructor Create(const AClientConfig: ITlsClientConfig;
      const AServerConfig: ITlsServerConfig; const ASpec: TStressSpec);
    destructor Destroy; override;
    /// <summary>Starts every worker; the traffic begins, and with it the handshakes.</summary>
    procedure Start;
    /// <summary>Waits for the traffic to end and returns '' or what went wrong.</summary>
    function Finish: string;
    /// <summary>Closes both pipes and waits for every worker to end; False when one never does.</summary>
    function Abandon: Boolean;
  end;

  TTestDuplexStress = class(TTlsLibAlgorithmTestCase)
  strict private
    // multiplies every message count; TLSLIB_STRESS_LONG=true runs the soak size
    function Scale: Int32;
    function ClientConfig(AWire: UInt16): ITlsClientConfig;
    function ServerConfig(AWire: UInt16): ITlsServerConfig;
    function BaseSpec(AWire: UInt16; APayload: TPayloadKind; AFrames: Int32): TStressSpec;
    function RunToEnd(const ASpec: TStressSpec; const AClientConfig: ITlsClientConfig;
      const AServerConfig: ITlsServerConfig): string;
    procedure RunSpec(const ASpec: TStressSpec);
    procedure RunClose(AWire: UInt16; AKind: TCloseKind);
    procedure RunCorrupt(AWire: UInt16);
  published
    procedure TestTls13TinyMessages;
    procedure TestTls13BoundaryMessages;
    procedure TestTls13LargeMessages;
    procedure TestTls13MixedMessages;
    procedure TestTls13SingleByteWritesAndReads;
    procedure TestTls12TinyMessages;
    procedure TestTls12BoundaryMessages;
    procedure TestTls12MixedMessages;
    procedure TestTls12SingleByteWritesAndReads;
    procedure TestTls13KeyUpdateAfterEveryTinyMessage;
    procedure TestTls13KeyUpdateAfterEveryBoundaryMessage;
    procedure TestTls13KeyUpdateEveryTenthMixedMessage;
    procedure TestTls13ThirdThreadQueriesAndRekeys;
    procedure TestTls12ThirdThreadQueries;
    procedure TestTls13ConnectionsUnderKeyUpdates;
    procedure TestTls12Connections;
    procedure TestTls13TwoWritersKeepMessagesContiguous;
    procedure TestTls12TwoWritersKeepMessagesContiguous;
    procedure TestTls13SingleThreadedPeerAlternatingSendAndRead;
    procedure TestTls13SingleThreadedPeerRekeyingEveryMessage;
    procedure TestReadOnlyEndpointSendsNothingUnderAKeyUpdateStorm;
    procedure TestTls13CloseNotifyMidStreamReachesThePeer;
    procedure TestTls12CloseNotifyMidStreamReachesThePeer;
    procedure TestTls13AlertMidStreamReachesThePeer;
    procedure TestTls12AlertMidStreamReachesThePeer;
    procedure TestTls13FatalErrorFoundByTheReaderReachesThePeer;
    procedure TestTls12FatalErrorFoundByTheReaderReachesThePeer;
    procedure TestCloseRacingTheLastWriteNeverStrandsTheCloseNotify;
    procedure TestEngineCallsNeverOverlapUnderTraffic;
    procedure TestEngineCallsNeverOverlapWhenTheCloseArrives;
    procedure TestAnAbandonedRunUnblocksItsWorkersInsteadOfHanging;
    procedure TestAWedgeFailsWithADiagnosticInsteadOfHanging;
  end;

implementation

const
  ExporterLabel = 'EXPERIMENTAL tlslib duplex stress';
  ExporterLength = Int32(32);
  HandshakeBoundMs = Int32(30000);
  // a TLS 1.3 record around a payload: header, inner type and tag
  RecordOverhead = Int32(22);
  // a whole sealed KeyUpdate record
  KeyUpdateRecordLength = Int32(27);

type
  /// <summary>A small deterministic generator, so a failing run can be repeated.</summary>
  TStressRng = record
  strict private
  var
    FState: UInt32;
  public
    constructor Create(ASeed: UInt32);
    function Next: UInt32;
  end;

{ TStressRng }

constructor TStressRng.Create(ASeed: UInt32);
begin
  FState := ASeed;
  if FState = 0 then
    FState := 1;
end;

function TStressRng.Next: UInt32;
begin
  FState := FState xor (FState shl 13);
  FState := FState xor (FState shr 17);
  FState := FState xor (FState shl 5);
  Result := FState;
end;

{ TStressIo }

constructor TStressIo.Create(const AStream: TTlsStream);
begin
  inherited Create;
  FStream := AStream;
end;

constructor TStressIo.Create(const AConnection: TTlsConnection);
begin
  inherited Create;
  FConnection := AConnection;
end;

destructor TStressIo.Destroy;
begin
  FStream.Free;
  FConnection.Free;
  inherited Destroy;
end;

procedure TStressIo.Handshake;
begin
  if FConnection <> nil then
    FConnection.Handshake(HandshakeBoundMs)
  else
    FStream.Handshake;
end;

function TStressIo.Read(var ABuffer; ACount: Int32): Int32;
begin
  if FConnection <> nil then
    Result := FConnection.Read(ABuffer, ACount)
  else
    Result := FStream.Read(ABuffer, ACount);
end;

function TStressIo.ReadTimed(var ABuffer; ACount, AMs: Int32): Int32;
begin
  if FConnection <> nil then
    Result := FConnection.Read(ABuffer, ACount, AMs)
  else
    Result := FStream.ReadTimed(ABuffer, ACount, AMs);
end;

procedure TStressIo.Write(const ABuffer; ACount: Int32);
begin
  if FConnection <> nil then
    FConnection.Write(ABuffer, ACount)
  else
    FStream.Write(ABuffer, ACount);
end;

procedure TStressIo.Rekey(ARequest: TKeyUpdateRequest);
begin
  if FConnection <> nil then
    FConnection.RequestKeyUpdate(ARequest)
  else
    FStream.RequestKeyUpdate(ARequest);
end;

function TStressIo.Exported: TBytes;
begin
  if FConnection <> nil then
    Result := FConnection.ExportKeyingMaterial(ExporterLabel, ExporterLength)
  else
    Result := FStream.ExportKeyingMaterial(ExporterLabel, ExporterLength);
end;

function TStressIo.Version: UInt16;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedVersion.WireValue
  else
    Result := FStream.ConnectionInfo.NegotiatedVersion.WireValue;
end;

function TStressIo.Pending: Int32;
begin
  if FConnection <> nil then
    Result := FConnection.PendingReadBytes
  else
    Result := FStream.PendingReadBytes;
end;

procedure TStressIo.CloseNotify;
begin
  if FConnection <> nil then
    FConnection.CloseNotify
  else
    FStream.CloseNotify;
end;

procedure TStressIo.SendAlert(ADescription: TTlsAlertDescription);
begin
  if FConnection <> nil then
    FConnection.SendAlert(ADescription)
  else
    FStream.SendAlert(ADescription);
end;

{ TFrameParser }

class function TFrameParser.Pattern(AWriter: Int32; ASeq, AIndex: UInt32): Byte;
begin
  Result := Byte((ASeq * 131 + AIndex * 17 + (AIndex shr 7) * 3 + UInt32(AWriter) * 29) and $FF);
end;

class procedure TFrameParser.PutU32(var ABuffer: TBytes; AOffset: Int32; AValue: UInt32);
begin
  ABuffer[AOffset] := Byte(AValue shr 24);
  ABuffer[AOffset + 1] := Byte(AValue shr 16);
  ABuffer[AOffset + 2] := Byte(AValue shr 8);
  ABuffer[AOffset + 3] := Byte(AValue);
end;

class function TFrameParser.GetU32(const ABuffer: array of Byte; AOffset: Int32): UInt32;
begin
  Result := (UInt32(ABuffer[AOffset]) shl 24) or (UInt32(ABuffer[AOffset + 1]) shl 16) or
    (UInt32(ABuffer[AOffset + 2]) shl 8) or UInt32(ABuffer[AOffset + 3]);
end;

function TFrameParser.Fail(const AMessage: string): Boolean;
begin
  FError := AMessage;
  Result := False;
end;

procedure TFrameParser.EndOfFrame;
begin
  System.Inc(FFrames);
  if FIsFin then
    System.Inc(FFins);
end;

function TFrameParser.EndOfHeader: Boolean;
var
  LMagic: UInt32;
begin
  FHave := 0;
  LMagic := GetU32(FHeader, 0);
  FIsFin := (LMagic and $FFFF0000) = FinBase;
  if (not FIsFin) and ((LMagic and $FFFF0000) <> MagicBase) then
    Exit(Fail(Format('bad magic %x at stream offset %d', [LMagic, FBytes])));
  FWriter := Int32(LMagic and $FFFF);
  if FWriter > 1 then
    Exit(Fail(Format('bad writer id %d at stream offset %d', [FWriter, FBytes])));
  FSeq := GetU32(FHeader, 4);
  if FSeq <> FExpected[FWriter] then
    Exit(Fail(Format('writer %d message %d arrived where %d was due (lost, repeated or ' +
      'interleaved) at stream offset %d', [FWriter, FSeq, FExpected[FWriter], FBytes])));
  System.Inc(FExpected[FWriter]);
  FLeft := GetU32(FHeader, 8);
  FPos := 0;
  if FLeft > MaxLength then
    Exit(Fail(Format('bad length %d in writer %d message %d', [FLeft, FWriter, FSeq])));
  if FLeft = 0 then
    EndOfFrame;
  Result := True;
end;

function TFrameParser.Idle: Boolean;
begin
  Result := (FHave = 0) and (FLeft = 0);
end;

function TFrameParser.Feed(const ABuffer: TBytes; ACount: Int32): Boolean;
var
  LIndex, LRun: Int32;
begin
  LIndex := 0;
  while LIndex < ACount do
  begin
    if FLeft > 0 then
    begin
      LRun := ACount - LIndex;
      if UInt32(LRun) > FLeft then
        LRun := Int32(FLeft);
      while LRun > 0 do
      begin
        if ABuffer[LIndex] <> Pattern(FWriter, FSeq, FPos) then
          Exit(Fail(Format('writer %d message %d holds byte %d where %d was sent, at stream ' +
            'offset %d', [FWriter, FSeq, ABuffer[LIndex], Pattern(FWriter, FSeq, FPos),
            FBytes + LIndex])));
        System.Inc(LIndex);
        System.Inc(FPos);
        System.Dec(FLeft);
        System.Dec(LRun);
      end;
      if FLeft = 0 then
        EndOfFrame;
    end
    else
    begin
      FHeader[FHave] := ABuffer[LIndex];
      System.Inc(FHave);
      System.Inc(LIndex);
      if (FHave = HeaderLength) and (not EndOfHeader) then
        Exit(False);
    end;
  end;
  System.Inc(FBytes, ACount);
  Result := True;
end;

{ TStressWorker }

constructor TStressWorker.Create(const AName: string; ATolerateStops: Boolean);
begin
  inherited Create(True);
  FTitle := AName;
  FTolerate := ATolerateStops;
  FEnded := TEvent.Create(nil, True, False, '');
  FreeOnTerminate := False;
end;

destructor TStressWorker.Destroy;
begin
  inherited Destroy;
  FEnded.Free;
end;

procedure TStressWorker.Execute;
begin
  try
    try
      Run;
    except
      on E: EStressFailure do
        FError := E.Message;
      on E: Exception do
        // a close scenario ends workers with the error a closed or refused connection gives
        if FTolerate and ((E is ETlsStreamError) or (E is EInvalidOperationTlsLibException) or
          (E is ETlsTransportTruncated) or (E is EInOutError)) then
          FStopNote := E.ClassName + ': ' + E.Message
        else
          FError := E.ClassName + ': ' + E.Message;
    end;
  finally
    FEnded.SetEvent;
  end;
end;

procedure TStressWorker.Note(APhase: TStressPhase; ASeq: Int32);
begin
  FPhase := APhase;
  FSeq := ASeq;
end;

function TStressWorker.WaitEnded(AMs: Cardinal): Boolean;
begin
  Result := FEnded.WaitFor(AMs) = wrSignaled;
end;

function TStressWorker.Describe: string;
const
  PhaseNames: array[TStressPhase] of string = ('starting', 'sending', 'rekeying', 'receiving',
    'querying', 'closing');
begin
  Result := Format('%s %s message %d, %d bytes done', [FTitle, PhaseNames[FPhase], FSeq, FBytes]);
  // a worker that is still running may be assigning its strings
  if not WaitEnded(0) then
    Exit;
  if FError <> '' then
    Result := Result + ' (' + FError + ')';
  if FStopNote <> '' then
    Result := Result + ' [stopped: ' + FStopNote + ']';
end;

{ TStressWriter }

constructor TStressWriter.Create(const AName: string; const AIo: TStressIo;
  const ASpec: TStressSpec; AWriterId: Int32; ASeed: UInt32; AHoldFin: Boolean);
begin
  inherited Create(AName, (ASpec.Close <> TCloseKind.NoClose) or (ASpec.CorruptAt > 0));
  FIo := AIo;
  FSpec := ASpec;
  FWriterId := AWriterId;
  FSeed := ASeed;
  FHoldFin := AHoldFin;
  FReached := TEvent.Create(nil, True, False, '');
  FFinReleased := TEvent.Create(nil, True, False, '');
end;

destructor TStressWriter.Destroy;
begin
  inherited Destroy;
  FFinReleased.Free;
  FReached.Free;
end;

function TStressWriter.WaitReached(AMs: Cardinal): Boolean;
begin
  Result := FReached.WaitFor(AMs) = wrSignaled;
end;

procedure TStressWriter.ReleaseFin;
begin
  FFinReleased.SetEvent;
end;

procedure TStressWriter.Run;
begin
  try
    Send;
  finally
    // a closer waiting for this writer must not wait for one that has ended
    FReached.SetEvent;
  end;
end;

procedure TStressWriter.Send;
var
  LRng: TStressRng;
  LMessage: TBytes;
  LSeq, LLength, LIndex: Int32;
  LFin: Boolean;
  LValue: UInt32;
begin
  LRng := TStressRng.Create(FSeed);
  LSeq := 0;
  repeat
    LFin := LSeq >= FSpec.Frames;
    if LFin and FSpec.NoFin then
      Break;
    LLength := 0;
    if not LFin then
      case FSpec.Payload of
        TPayloadKind.Tiny:
          LLength := Int32(LRng.Next mod 33);
        TPayloadKind.SingleByte:
          LLength := Int32(LRng.Next mod 9);
        TPayloadKind.Boundary:
          LLength := 16360 + Int32(LRng.Next mod 49);
        TPayloadKind.Large:
          LLength := 70000 + Int32(LRng.Next mod 130000);
      else
        case LRng.Next mod 6 of
          0: LLength := Int32(LRng.Next mod 4);
          1: LLength := Int32(LRng.Next mod 64);
          2: LLength := 16344 + Int32(LRng.Next mod 80);
          3: LLength := Int32(LRng.Next mod 5000);
          4: LLength := Int32(LRng.Next mod 40000);
        else
          LLength := 65000 + Int32(LRng.Next mod 90000);
        end;
      end;
    SetLength(LMessage, TFrameParser.HeaderLength + LLength);
    if LFin then
      LValue := TFrameParser.FinBase
    else
      LValue := TFrameParser.MagicBase;
    TFrameParser.PutU32(LMessage, 0, LValue + UInt32(FWriterId));
    TFrameParser.PutU32(LMessage, 4, UInt32(LSeq));
    TFrameParser.PutU32(LMessage, 8, UInt32(LLength));
    for LIndex := 0 to LLength - 1 do
      LMessage[TFrameParser.HeaderLength + LIndex] :=
        TFrameParser.Pattern(FWriterId, UInt32(LSeq), UInt32(LIndex));
    // a close scenario's FIN follows the close, so the close is never behind the end of the stream
    if LFin and FHoldFin then
      FFinReleased.WaitFor(20000);
    Note(TStressPhase.Sending, LSeq);
    System.Inc(FAttempted, System.Length(LMessage));
    if FSpec.Payload = TPayloadKind.SingleByte then
      for LIndex := 0 to High(LMessage) do
        FIo.Write(LMessage[LIndex], 1)
    else
      FIo.Write(LMessage[0], System.Length(LMessage));
    System.Inc(FBytes, System.Length(LMessage));
    if (FSpec.CloseAtBytes > 0) and (Bytes >= FSpec.CloseAtBytes) then
      FReached.SetEvent;
    System.Inc(LSeq);
    if (not LFin) and (FSpec.KeyUpdateEvery > 0) and (LSeq mod FSpec.KeyUpdateEvery = 0) then
    begin
      Note(TStressPhase.Rekeying, LSeq);
      FIo.Rekey(TKeyUpdateRequest.UpdateRequested);
    end;
  until LFin;
end;

{ TStressReader }

constructor TStressReader.Create(const AName: string; const AIo: TStressIo;
  ASingleByte: Boolean; AExpectFins: Int32; AEofIsEnd, AAlertIsEnd: Boolean);
begin
  inherited Create(AName, AEofIsEnd or AAlertIsEnd);
  FIo := AIo;
  FSingleByte := ASingleByte;
  FExpectFins := AExpectFins;
  FEofIsEnd := AEofIsEnd;
  FAlertIsEnd := AAlertIsEnd;
end;

procedure TStressReader.Run;
var
  LParser: TFrameParser;
  LBuffer: TBytes;
  LWant, LGot: Int32;
begin
  LParser := TFrameParser.Create;
  try
    SetLength(LBuffer, 16384);
    try
      while LParser.Fins < FExpectFins do
      begin
        if FSingleByte then
          LWant := 1
        else
          LWant := System.Length(LBuffer);
        Note(TStressPhase.Receiving, LParser.Frames);
        LGot := FIo.Read(LBuffer[0], LWant);
        if LGot <= 0 then
        begin
          if not FEofIsEnd then
            raise EStressFailure.CreateFmt('the stream ended after %d bytes, before the FIN',
              [LParser.Bytes]);
          FOutcome := TReaderOutcome.EndedWithEof;
          Exit;
        end;
        if not LParser.Feed(LBuffer, LGot) then
          raise EStressFailure.Create(LParser.Error);
        System.Inc(FBytes, LGot);
      end;
      if (not LParser.Idle) or (LParser.Fins > FExpectFins) then
        raise EStressFailure.CreateFmt('bytes followed the last FIN, at stream offset %d',
          [LParser.Bytes]);
      FOutcome := TReaderOutcome.EndedWithFin;
    except
      on E: ETlsStreamError do
      begin
        if not (FAlertIsEnd and E.HasAlert) then
          raise;
        FOutcome := TReaderOutcome.EndedWithAlert;
        FAlert := E.Alert;
      end;
    end;
  finally
    LParser.Free;
  end;
end;

{ TStressAlternator }

constructor TStressAlternator.Create(const AName: string; const AIo: TStressIo;
  const ASpec: TStressSpec; AExpectFins: Int32);
begin
  inherited Create(AName, False);
  FIo := AIo;
  FSpec := ASpec;
  FExpectFins := AExpectFins;
end;

procedure TStressAlternator.Run;
const
  MessageLength = Int32(1024);
var
  LParser: TFrameParser;
  LMessage, LBuffer: TBytes;
  LSeq, LIndex, LGot: Int32;
  LSentAll, LTimedOut: Boolean;
begin
  LParser := TFrameParser.Create;
  try
    SetLength(LMessage, TFrameParser.HeaderLength + MessageLength);
    SetLength(LBuffer, 16384);
    LSeq := 0;
    LSentAll := False;
    while not (LSentAll and (LParser.Fins >= FExpectFins)) do
    begin
      if not LSentAll then
      begin
        LSentAll := LSeq >= FSpec.Frames;
        if LSentAll then
        begin
          TFrameParser.PutU32(LMessage, 0, TFrameParser.FinBase);
          TFrameParser.PutU32(LMessage, 8, 0);
        end
        else
        begin
          TFrameParser.PutU32(LMessage, 0, TFrameParser.MagicBase);
          TFrameParser.PutU32(LMessage, 8, UInt32(MessageLength));
          for LIndex := 0 to MessageLength - 1 do
            LMessage[TFrameParser.HeaderLength + LIndex] :=
              TFrameParser.Pattern(0, UInt32(LSeq), UInt32(LIndex));
        end;
        TFrameParser.PutU32(LMessage, 4, UInt32(LSeq));
        Note(TStressPhase.Sending, LSeq);
        if LSentAll then
          FIo.Write(LMessage[0], TFrameParser.HeaderLength)
        else
          FIo.Write(LMessage[0], System.Length(LMessage));
        System.Inc(LSeq);
        if (not LSentAll) and (FSpec.KeyUpdateEvery > 0) and (LSeq mod FSpec.KeyUpdateEvery = 0) then
        begin
          Note(TStressPhase.Rekeying, LSeq);
          FIo.Rekey(TKeyUpdateRequest.UpdateRequested);
        end;
      end;
      Note(TStressPhase.Receiving, LParser.Frames);
      LGot := 0;
      LTimedOut := False;
      try
        LGot := FIo.ReadTimed(LBuffer[0], System.Length(LBuffer), 2);
      except
        on ETlsReadTimeout do
          LTimedOut := True;
      end;
      if (LGot = 0) and not LTimedOut then
        raise EStressFailure.CreateFmt('the stream ended after %d bytes, before the FIN',
          [LParser.Bytes]);
      if LGot > 0 then
      begin
        if not LParser.Feed(LBuffer, LGot) then
          raise EStressFailure.Create(LParser.Error);
        System.Inc(FBytes, LGot);
      end;
    end;
    if (not LParser.Idle) or (LParser.Fins > FExpectFins) then
      raise EStressFailure.CreateFmt('bytes followed the last FIN, at stream offset %d',
        [LParser.Bytes]);
  finally
    LParser.Free;
  end;
end;

{ TStressQuerier }

constructor TStressQuerier.Create(const AName: string; const AIo: TStressIo; AWire: UInt16;
  const AWriter: TStressWriter);
begin
  inherited Create(AName, False);
  FIo := AIo;
  FWire := AWire;
  FWriter := AWriter;
end;

procedure TStressQuerier.Run;
var
  LRound: Int32;
  LVersion: UInt16;
  LExported: TBytes;
begin
  LRound := 0;
  repeat
    Note(TStressPhase.Querying, LRound);
    LVersion := FIo.Version;
    // zero while the handshake runs, the negotiated version afterwards
    if (LVersion <> 0) and (LVersion <> FWire) then
      raise EStressFailure.CreateFmt('the connection reports version %x, not %x', [LVersion, FWire]);
    if FIo.Pending < 0 then
      raise EStressFailure.Create('a negative count of pending bytes');
    LExported := FIo.Exported;
    if System.Length(LExported) > 0 then
    begin
      if System.Length(FExported) = 0 then
        FExported := LExported
      else if not CompareMem(@FExported[0], @LExported[0], System.Length(FExported)) then
        raise EStressFailure.Create('the exporter value changed under traffic');
    end;
    if LRound mod 3 = 0 then
    begin
      Note(TStressPhase.Rekeying, LRound);
      if LRound mod 2 = 0 then
        FIo.Rekey(TKeyUpdateRequest.UpdateRequested)
      else
        FIo.Rekey(TKeyUpdateRequest.UpdateNotRequested);
    end;
    System.Inc(LRound);
  until FWriter.WaitEnded(1);
end;

{ TStressCloser }

constructor TStressCloser.Create(const AName: string; const AIo: TStressIo;
  const AWriter: TStressWriter; AKind: TCloseKind; ASpinMax: Int32; ASeed: UInt32;
  AOnHandshake: Boolean);
begin
  inherited Create(AName, False);
  FIo := AIo;
  FWriter := AWriter;
  FKind := AKind;
  FSpinMax := ASpinMax;
  FSeed := ASeed;
  FOnHandshake := AOnHandshake;
end;

procedure TStressCloser.Run;
var
  LSpin: Int32;
  LRng: TStressRng;
begin
  if FOnHandshake then
    FIo.Handshake
  else
    FWriter.WaitReached(INFINITE);
  // the seed makes the close land at a point of the writer's work that a rerun can repeat
  LRng := TStressRng.Create(FSeed);
  if FSpinMax > 0 then
    for LSpin := 1 to Int32(LRng.Next mod UInt32(FSpinMax + 1)) do
      Sleep(0);
  Note(TStressPhase.Closing, 0);
  try
    case FKind of
      TCloseKind.CloseNotifyMidStream:
        FIo.CloseNotify;
      TCloseKind.AlertMidStream:
        FIo.SendAlert(TTlsAlertDescription.InternalError);
    end;
  finally
    FWriter.ReleaseFin;
  end;
end;

{ TStressRun }

constructor TStressRun.Create(const AClientConfig: ITlsClientConfig;
  const AServerConfig: ITlsServerConfig; const ASpec: TStressSpec);
begin
  inherited Create;
  FSpec := ASpec;
  FWorkers := TObjectList<TStressWorker>.Create(True);
  FC2S := TMemoryPipe.Create(ASpec.Capacity);
  FS2C := TMemoryPipe.Create(ASpec.Capacity);
  if ASpec.CorruptAt > 0 then
    FC2S.CorruptByteAt(ASpec.CorruptAt);
  // each transport owns the pipe it writes
  FClientTransport := TPipeTimedTransport.Create(FS2C, FC2S);
  FServerTransport := TPipeTimedTransport.Create(FC2S, FS2C);
  FClient := NewIo(AClientConfig, nil, FClientTransport);
  FServer := NewIo(nil, AServerConfig, FServerTransport);
  FWatch := TWedgeWatchdog.Create(FC2S, FS2C, ASpec.DeadlineMs);
  FWatch.Start;
end;

destructor TStressRun.Destroy;
begin
  // a worker that never unwinds still uses everything below: leave it all to the process
  if FStuck or not Abandon then
    Exit;
  if FWatch <> nil then
  begin
    FWatch.Disarm;
    FWatch.WaitFor;
    FWatch.Free;
  end;
  FWorkers.Free;
  FClient.Free;
  FServer.Free;
  FClientTransport := nil;
  FServerTransport := nil;
  inherited Destroy;
end;

function TStressRun.Abandon: Boolean;
var
  LWorker: TStressWorker;
begin
  FAbandoning := True;
  FC2S.Close;
  FS2C.Close;
  Result := True;
  for LWorker in FWorkers do
    if not AwaitEnded(LWorker) then
      Result := False;
  if not Result then
    FStuck := True;
end;

function TStressRun.NewIo(const AConfig: ITlsClientConfig; const AServerConfig: ITlsServerConfig;
  const ATransport: ITlsTimedTransport): TStressIo;
const
  // long enough to be no part of a healthy run
  CloseGraceMs = Int32(30000);
var
  LEngine: ITlsEngine;
  LStream: TTlsStream;
begin
  if AConfig <> nil then
    LEngine := TTlsEngineFactory.CreateClientEngine(AConfig, 'localhost')
  else
    LEngine := TTlsEngineFactory.CreateServerEngine(AServerConfig);
  if FSpec.Probe and (AConfig <> nil) then
  begin
    FClientProbe := TExclusionProbeEngine.Create(LEngine);
    LEngine := FClientProbe;
  end;
  if FSpec.Io = TIoKind.OnConnection then
  begin
    Result := TStressIo.Create(TTlsConnection.Create(LEngine, ATransport, AConfig <> nil,
      'localhost', nil));
    Exit;
  end;
  LStream := TTlsStream.Create(ATransport as ITlsTransport, LEngine, AConfig <> nil, 'localhost',
    CloseGraceMs);
  Result := TStressIo.Create(LStream);
end;

function TStressRun.Spawn(const AWorker: TStressWorker): TStressWorker;
begin
  FWorkers.Add(AWorker);
  Result := AWorker;
end;

function TStressRun.AwaitEnded(const AWorker: TStressWorker): Boolean;
begin
  repeat
    if AWorker.WaitEnded(100) then
      Exit(True);
    if FWatch.Fired or FAbandoning then
    begin
      System.Inc(FUnwound);
      if FUnwound > UnwindWaits then
        Exit(False);
    end;
  until False;
end;

function TStressRun.AwaitAll(const AWorkers: array of TStressWorker): Boolean;
var
  LIndex: Int32;
begin
  Result := True;
  for LIndex := 0 to High(AWorkers) do
    if (AWorkers[LIndex] <> nil) and not AwaitEnded(AWorkers[LIndex]) then
      Result := False;
end;

procedure TStressRun.ServerSpeaksOnce;
var
  LAfterStorm, LSent, LExpected: Int64;
  LFin: TBytes;
begin
  LAfterStorm := FS2C.Written;
  if LAfterStorm <> FBaseline then
    FNote := Format('the read-only server sent %d bytes while it was asked to rekey; ',
      [LAfterStorm - FBaseline]);
  SetLength(LFin, TFrameParser.HeaderLength);
  TFrameParser.PutU32(LFin, 0, TFrameParser.FinBase);
  TFrameParser.PutU32(LFin, 4, 0);
  TFrameParser.PutU32(LFin, 8, 0);
  FServer.Write(LFin[0], System.Length(LFin));
  LSent := FS2C.Written - LAfterStorm;
  LExpected := TFrameParser.HeaderLength + RecordOverhead + KeyUpdateRecordLength;
  if LSent <> LExpected then
    FNote := FNote + Format('the first write sent %d bytes, not the FIN and one coalesced ' +
      'reply (%d); ', [LSent, LExpected]);
end;

function TStressRun.Failures: string;
var
  LWorker: TStressWorker;
begin
  Result := '';
  for LWorker in FWorkers do
    if LWorker.WaitEnded(0) and (LWorker.Error <> '') then
      Result := Result + LWorker.Describe + '; ';
  if FWatch.Fired then
  begin
    Result := Result + 'the watchdog fired after ' + IntToStr(FSpec.DeadlineMs) + ' ms, where ' +
      'the workers stood: ';
    for LWorker in FWorkers do
      Result := Result + LWorker.Describe + '; ';
  end;
end;

function TStressRun.CheckTraffic: string;
var
  LSent, LReceived: Int64;
begin
  Result := '';
  LSent := FClientWriter.Bytes;
  if FClientWriter2 <> nil then
    System.Inc(LSent, FClientWriter2.Bytes);
  if FServerReader <> nil then
    LReceived := FServerReader.Bytes
  else
    LReceived := FServerAlternator.Bytes;
  if LReceived <> LSent then
    Result := Result + Format('the server read %d bytes of the %d the client sent; ',
      [LReceived, LSent]);
  if (FClientReader <> nil) and (FServerWriter <> nil) then
    if FClientReader.Bytes <> FServerWriter.Bytes then
      Result := Result + Format('the client read %d bytes of the %d the server sent; ',
        [FClientReader.Bytes, FServerWriter.Bytes]);
  if (FClient.Pending <> 0) or (FServer.Pending <> 0) then
    Result := Result + Format('bytes followed the last FIN (%d for the client, %d for the ' +
      'server); ', [FClient.Pending, FServer.Pending]);
end;

function TStressRun.CheckProbe: string;
begin
  Result := '';
  if (FClientProbe <> nil) and (FClientProbe.Overlaps > 0) then
    Result := Format('%d engine calls began while another was inside; ', [FClientProbe.Overlaps]);
end;

function TStressRun.CheckBackpressure: string;
begin
  Result := '';
  if FSpec.Backpressure and ((FC2S.Stalls = 0) or (FS2C.Stalls = 0)) then
    Result := Format('a pipe never filled (%d stalls client to server, %d server to client); ',
      [FC2S.Stalls, FS2C.Stalls]);
end;

function TStressRun.CheckCorrupt: string;
begin
  Result := '';
  if FServerReader.Outcome <> TReaderOutcome.EndedWithAlert then
    Result := 'the server did not end on a fatal error; ';
  if FClientReader.Outcome <> TReaderOutcome.EndedWithAlert then
    Result := Result + 'the client was not sent the alert; '
  else if FClientReader.Alert <> FServerReader.Alert then
    Result := Result + 'the client was sent another alert than the server raised; ';
end;

function TStressRun.CheckClose: string;
begin
  Result := '';
  if FServerReader.Outcome = TReaderOutcome.StillReading then
    Exit('the server read ended with no outcome: ' + FServerReader.Describe);
  case FSpec.Close of
    TCloseKind.CloseNotifyMidStream:
      begin
        if FServerReader.Outcome = TReaderOutcome.EndedWithAlert then
          Result := 'the server read an alert for a close_notify; ';
        // every message the client's Write returned for was on the wire before the close_notify
        if (FServerReader.Bytes < FClientWriter.Bytes) or
          (FServerReader.Bytes > FClientWriter.Attempted) then
          Result := Result + Format('the server read %d bytes; the client completed %d of %d; ',
            [FServerReader.Bytes, FClientWriter.Bytes, FClientWriter.Attempted]);
      end;
    TCloseKind.AlertMidStream:
      if (FServerReader.Outcome <> TReaderOutcome.EndedWithAlert) or
        (FServerReader.Alert <> TTlsAlertDescription.InternalError) then
        Result := Format('the server did not read the client''s internal_error alert (outcome %d, ' +
          'alert %d); ', [Ord(FServerReader.Outcome), Ord(FServerReader.Alert)]);
  end;
end;

function TStressRun.CheckExporters: string;
var
  LClient, LServer: TBytes;
begin
  Result := '';
  LClient := FClient.Exported;
  LServer := FServer.Exported;
  if (System.Length(LClient) <> ExporterLength) or (System.Length(LServer) <> ExporterLength) then
    Exit('an exporter produced no secret; ');
  if not CompareMem(@LClient[0], @LServer[0], ExporterLength) then
    Result := 'the peers derive different exporter secrets; ';
  if (FClientQuerier <> nil) and (System.Length(FClientQuerier.Exported) = ExporterLength) and
    not CompareMem(@FClientQuerier.Exported[0], @LClient[0], ExporterLength) then
    Result := Result + 'the exporter changed under traffic; ';
  if (FServerQuerier <> nil) and (System.Length(FServerQuerier.Exported) = ExporterLength) and
    not CompareMem(@FServerQuerier.Exported[0], @LServer[0], ExporterLength) then
    Result := Result + 'the exporter changed under traffic; ';
end;

procedure TStressRun.Start;
var
  LWorker: TStressWorker;
  LExpectClientFins, LExpectServerFins: Int32;
  LClosing, LAlert: Boolean;
begin
  LClosing := FSpec.Close <> TCloseKind.NoClose;
  LAlert := (FSpec.Close = TCloseKind.AlertMidStream) or (FSpec.CorruptAt > 0);
  LExpectServerFins := FSpec.ClientWriters;
  if FSpec.ServerWrites or FSpec.Wedge or FSpec.ReadOnlyServer then
    LExpectClientFins := 1
  else
    LExpectClientFins := 0;
  FClientWriter := TStressWriter(Spawn(TStressWriter.Create('client writer', FClient, FSpec, 0,
    $C0FFEE, LClosing)));
  if FSpec.ClientWriters > 1 then
    FClientWriter2 := TStressWriter(Spawn(TStressWriter.Create('client writer 2', FClient, FSpec,
      1, $BADF00D, False)));
  if FSpec.ServerAlternates then
    FServerAlternator := TStressAlternator(Spawn(TStressAlternator.Create('server', FServer, FSpec,
      LExpectServerFins)))
  else
  begin
    FServerReader := TStressReader(Spawn(TStressReader.Create('server reader', FServer,
      FSpec.SingleByteReads, LExpectServerFins, LClosing, LAlert)));
    if FSpec.ServerWrites then
      FServerWriter := TStressWriter(Spawn(TStressWriter.Create('server writer', FServer, FSpec, 0,
        $5EED5, False)));
  end;
  if LExpectClientFins > 0 then
    FClientReader := TStressReader(Spawn(TStressReader.Create('client reader', FClient,
      FSpec.SingleByteReads, LExpectClientFins, LAlert, LAlert)));
  if FSpec.Query then
  begin
    FClientQuerier := TStressQuerier(Spawn(TStressQuerier.Create('client querier', FClient,
      FSpec.Wire, FClientWriter)));
    FServerQuerier := TStressQuerier(Spawn(TStressQuerier.Create('server querier', FServer,
      FSpec.Wire, FServerWriter)));
  end;
  if LClosing then
    FCloser := TStressCloser(Spawn(TStressCloser.Create('closer', FClient, FClientWriter,
      FSpec.Close, FSpec.CloseSpinMax, FSpec.CloseSeed, FSpec.CloseOnHandshake)));
  for LWorker in FWorkers do
    LWorker.Start;
  if FSpec.ReadOnlyServer then
  begin
    // everything the server sends from here on is the reader's doing
    FServer.Handshake;
    FBaseline := FS2C.Written;
  end;
end;

function TStressRun.Finish: string;
var
  LClosing: Boolean;
begin
  LClosing := FSpec.Close <> TCloseKind.NoClose;
  FStuck := False;
  if FSpec.CorruptAt > 0 then
  begin
    // the server's alert has to reach the client; only then do the hosts close the sockets
    FStuck := not AwaitAll([FServerReader]);
    FStuck := (not AwaitAll([FClientReader])) or FStuck;
    FC2S.Close;
    FS2C.Close;
  end;
  FStuck := (not AwaitAll([FClientWriter, FClientWriter2, FCloser])) or FStuck;
  if FSpec.Close = TCloseKind.AlertMidStream then
  begin
    // the host closes the socket it refused, but only after the server has read the alert
    FStuck := (not AwaitAll([FServerReader])) or FStuck;
    FS2C.Close;
  end;
  if LClosing then
  begin
    FStuck := (not AwaitAll([FClientReader])) or FStuck;
    // a closed client reads no more: a server still sending must not wait for it
    FS2C.Close;
  end;
  FStuck := (not AwaitAll([FServerWriter, FClientQuerier, FServerQuerier])) or FStuck;
  FStuck := (not AwaitAll([FServerReader, FServerAlternator])) or FStuck;
  if FSpec.ReadOnlyServer and not FStuck then
    ServerSpeaksOnce;
  FStuck := (not AwaitAll([FClientReader])) or FStuck;
  Result := Failures + FNote + CheckProbe + CheckBackpressure;
  if FStuck then
    Result := Result + 'a worker never unwound; ';
  if Result <> '' then
    Exit;
  if FSpec.CorruptAt > 0 then
    Result := CheckCorrupt
  else if LClosing then
    Result := CheckClose
  else
    Result := CheckTraffic + CheckExporters;
end;

{ TTestDuplexStress }

function TTestDuplexStress.Scale: Int32;
begin
  if SwitchEnabled('TLSLIB_STRESS_LONG') then
    Result := 10
  else
    Result := 1;
end;

function TTestDuplexStress.ClientConfig(AWire: UInt16): ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithSupportedVersions(TArray<UInt16>.Create(AWire)).Build;
end;

function TTestDuplexStress.ServerConfig(AWire: UInt16): ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key')))
    .WithSupportedVersions(TArray<UInt16>.Create(AWire)).Build;
end;

function TTestDuplexStress.BaseSpec(AWire: UInt16; APayload: TPayloadKind;
  AFrames: Int32): TStressSpec;
begin
  Result := Default(TStressSpec);
  Result.Wire := AWire;
  Result.Io := TIoKind.OnStream;
  Result.Payload := APayload;
  Result.Frames := AFrames * Scale;
  Result.Capacity := 3000;
  // a message longer than the pipe holds fills it
  Result.Backpressure := APayload in [TPayloadKind.Boundary, TPayloadKind.Large,
    TPayloadKind.Mixed];
  Result.ClientWriters := 1;
  Result.ServerWrites := True;
  // the watchdog only turns a hang into a failure, so the deadline grows with the soak size
  Result.DeadlineMs := 30000 * UInt32(Scale);
end;

function TTestDuplexStress.RunToEnd(const ASpec: TStressSpec; const AClientConfig: ITlsClientConfig;
  const AServerConfig: ITlsServerConfig): string;
var
  LRun: TStressRun;
begin
  LRun := TStressRun.Create(AClientConfig, AServerConfig, ASpec);
  try
    LRun.Start;
    Result := LRun.Finish;
  finally
    LRun.Free;
  end;
end;

procedure TTestDuplexStress.RunSpec(const ASpec: TStressSpec);
begin
  CheckEquals('', RunToEnd(ASpec, ClientConfig(ASpec.Wire), ServerConfig(ASpec.Wire)),
    'both peers moved every byte, in order, both ways');
end;

procedure TTestDuplexStress.TestTls13TinyMessages;
begin
  RunSpec(BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 6000));
end;

procedure TTestDuplexStress.TestTls13BoundaryMessages;
begin
  RunSpec(BaseSpec(TlsWireVersionTls13, TPayloadKind.Boundary, 100));
end;

procedure TTestDuplexStress.TestTls13LargeMessages;
begin
  RunSpec(BaseSpec(TlsWireVersionTls13, TPayloadKind.Large, 16));
end;

procedure TTestDuplexStress.TestTls13MixedMessages;
begin
  RunSpec(BaseSpec(TlsWireVersionTls13, TPayloadKind.Mixed, 150));
end;

procedure TTestDuplexStress.TestTls13SingleByteWritesAndReads;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.SingleByte, 500);
  LSpec.SingleByteReads := True;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls12TinyMessages;
begin
  RunSpec(BaseSpec(TlsWireVersionTls12, TPayloadKind.Tiny, 6000));
end;

procedure TTestDuplexStress.TestTls12BoundaryMessages;
begin
  RunSpec(BaseSpec(TlsWireVersionTls12, TPayloadKind.Boundary, 100));
end;

procedure TTestDuplexStress.TestTls12MixedMessages;
begin
  RunSpec(BaseSpec(TlsWireVersionTls12, TPayloadKind.Mixed, 150));
end;

procedure TTestDuplexStress.TestTls12SingleByteWritesAndReads;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls12, TPayloadKind.SingleByte, 500);
  LSpec.SingleByteReads := True;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13KeyUpdateAfterEveryTinyMessage;
var
  LSpec: TStressSpec;
begin
  // both readers owe a reply after every message
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 2500);
  LSpec.KeyUpdateEvery := 1;
  LSpec.Capacity := 4096;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13KeyUpdateAfterEveryBoundaryMessage;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Boundary, 60);
  LSpec.KeyUpdateEvery := 1;
  LSpec.Capacity := 4096;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13KeyUpdateEveryTenthMixedMessage;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Mixed, 120);
  LSpec.KeyUpdateEvery := 10;
  LSpec.Capacity := 4096;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13ThirdThreadQueriesAndRekeys;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Mixed, 100);
  LSpec.Query := True;
  LSpec.KeyUpdateEvery := 7;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls12ThirdThreadQueries;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls12, TPayloadKind.Mixed, 100);
  LSpec.Query := True;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13ConnectionsUnderKeyUpdates;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Mixed, 100);
  LSpec.Io := TIoKind.OnConnection;
  LSpec.KeyUpdateEvery := 3;
  LSpec.Query := True;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls12Connections;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls12, TPayloadKind.Mixed, 100);
  LSpec.Io := TIoKind.OnConnection;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13TwoWritersKeepMessagesContiguous;
var
  LSpec: TStressSpec;
begin
  // messages longer than the write slice, which a writer must not interleave with the other's
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Large, 8);
  LSpec.ClientWriters := 2;
  LSpec.Capacity := 8192;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls12TwoWritersKeepMessagesContiguous;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls12, TPayloadKind.Large, 8);
  LSpec.ClientWriters := 2;
  LSpec.Capacity := 8192;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13SingleThreadedPeerAlternatingSendAndRead;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 80);
  LSpec.ServerAlternates := True;
  LSpec.KeyUpdateEvery := 10;
  LSpec.Capacity := 4096;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13SingleThreadedPeerRekeyingEveryMessage;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 80);
  LSpec.ServerAlternates := True;
  LSpec.KeyUpdateEvery := 1;
  LSpec.Capacity := 4096;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestReadOnlyEndpointSendsNothingUnderAKeyUpdateStorm;
var
  LSpec: TStressSpec;
begin
  // the client reads what comes back, so every update_requested it sends can be answered
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 1500);
  LSpec.ServerWrites := False;
  LSpec.ReadOnlyServer := True;
  LSpec.KeyUpdateEvery := 1;
  LSpec.Capacity := 4096;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.RunCorrupt(AWire: UInt16);
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(AWire, TPayloadKind.Boundary, 200);
  LSpec.CorruptAt := 400000;
  LSpec.Capacity := 4096;
  // the server stops sending once its read fails
  LSpec.Backpressure := False;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13FatalErrorFoundByTheReaderReachesThePeer;
begin
  RunCorrupt(TlsWireVersionTls13);
end;

procedure TTestDuplexStress.TestTls12FatalErrorFoundByTheReaderReachesThePeer;
begin
  RunCorrupt(TlsWireVersionTls12);
end;

procedure TTestDuplexStress.RunClose(AWire: UInt16; AKind: TCloseKind);
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(AWire, TPayloadKind.Boundary, 200);
  LSpec.Close := AKind;
  LSpec.CloseAtBytes := 300000;
  LSpec.Capacity := 4096;
  // TLS 1.2 ends both directions at a close_notify, so the server has nothing to send there
  LSpec.ServerWrites := AWire = TlsWireVersionTls13;
  LSpec.Backpressure := LSpec.ServerWrites;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestTls13CloseNotifyMidStreamReachesThePeer;
begin
  RunClose(TlsWireVersionTls13, TCloseKind.CloseNotifyMidStream);
end;

procedure TTestDuplexStress.TestTls12CloseNotifyMidStreamReachesThePeer;
begin
  RunClose(TlsWireVersionTls12, TCloseKind.CloseNotifyMidStream);
end;

procedure TTestDuplexStress.TestTls13AlertMidStreamReachesThePeer;
begin
  RunClose(TlsWireVersionTls13, TCloseKind.AlertMidStream);
end;

procedure TTestDuplexStress.TestTls12AlertMidStreamReachesThePeer;
begin
  RunClose(TlsWireVersionTls12, TCloseKind.AlertMidStream);
end;

procedure TTestDuplexStress.TestCloseRacingTheLastWriteNeverStrandsTheCloseNotify;
const
  Rounds = Int32(120);
var
  LSpec: TStressSpec;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClock: ITlsMonotonicClock;
  LSeedBase: UInt32;
  LRound: Int32;
begin
  LClientConfig := ClientConfig(TlsWireVersionTls13);
  LServerConfig := ServerConfig(TlsWireVersionTls13);
  LClock := TSystemMonotonicClock.Create;
  LSeedBase := UInt32(LClock.NowMonotonicMillis);
  for LRound := 0 to Rounds * Scale - 1 do
  begin
    // the close races the last write of a writer that calls nothing afterwards
    LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 1);
    LSpec.Close := TCloseKind.CloseNotifyMidStream;
    LSpec.CloseOnHandshake := True;
    LSpec.NoFin := True;
    LSpec.CloseSpinMax := 60;
    LSpec.CloseSeed := LSeedBase + UInt32(LRound);
    LSpec.ServerWrites := False;
    // a pipe the writer often fills holds the send side while the close is requested
    case LRound mod 3 of
      0: LSpec.Capacity := 0;
      1: LSpec.Capacity := 64;
    else
      LSpec.Capacity := 4096;
    end;
    LSpec.DeadlineMs := 10000;
    CheckEquals('', RunToEnd(LSpec, LClientConfig, LServerConfig),
      Format('round %d, close seed %d: the close_notify reached the server',
      [LRound, LSpec.CloseSeed]));
  end;
end;

procedure TTestDuplexStress.TestEngineCallsNeverOverlapUnderTraffic;
var
  LSpec: TStressSpec;
begin
  // the probe fails any engine call made while another is inside the engine
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Mixed, 40);
  LSpec.Probe := True;
  LSpec.Query := True;
  LSpec.KeyUpdateEvery := 1;
  LSpec.Capacity := 4096;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestEngineCallsNeverOverlapWhenTheCloseArrives;
var
  LSpec: TStressSpec;
begin
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Boundary, 60);
  LSpec.Probe := True;
  LSpec.KeyUpdateEvery := 1;
  LSpec.Capacity := 4096;
  LSpec.Close := TCloseKind.CloseNotifyMidStream;
  LSpec.CloseAtBytes := 100000;
  RunSpec(LSpec);
end;

procedure TTestDuplexStress.TestAnAbandonedRunUnblocksItsWorkersInsteadOfHanging;
var
  LSpec: TStressSpec;
  LRun: TStressRun;
begin
  // the client reads for a FIN that never comes; a failure after Start must not wait for it
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 20);
  LSpec.ServerWrites := False;
  LSpec.Wedge := True;
  LRun := TStressRun.Create(ClientConfig(LSpec.Wire), ServerConfig(LSpec.Wire), LSpec);
  try
    LRun.Start;
    CheckTrue(LRun.Abandon, 'every worker unwound once the pipes were closed');
  finally
    LRun.Free;
  end;
end;

procedure TTestDuplexStress.TestAWedgeFailsWithADiagnosticInsteadOfHanging;
var
  LSpec: TStressSpec;
  LOutcome: string;
begin
  // the client reads for a FIN that never comes: the watchdog must end the run with a report
  LSpec := BaseSpec(TlsWireVersionTls13, TPayloadKind.Tiny, 20);
  LSpec.ServerWrites := False;
  LSpec.Wedge := True;
  LSpec.DeadlineMs := 500;
  LOutcome := RunToEnd(LSpec, ClientConfig(LSpec.Wire), ServerConfig(LSpec.Wire));
  CheckTrue(Pos('the watchdog fired', LOutcome) > 0, 'the wedge is reported, not waited on');
  CheckTrue(Pos('client reader', LOutcome) > 0, 'with where the worker stood');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestDuplexStress);
{$ELSE}
  RegisterTest(TTestDuplexStress.Suite);
{$ENDIF FPC}

end.
