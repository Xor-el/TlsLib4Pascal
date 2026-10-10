{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsEngine;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsVersion,
  TlpTlsContentType,
  TlpTlsLibExceptions,
  TlpTlsAlertProtocol,
  TlpAlertMapping,
  TlpICryptoProvider,
  TlpIKeySchedule,
  TlpIRecordProtection,
  TlpRecordLayer,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpTlsEngineEvents,
  TlpIHandshakeChannel,
  TlpHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeDriver,
  TlpHandshakeConductor,
  TlpEchConfig;

type
  /// <summary>
  /// The default sans-IO engine over a record layer, the alert protocol, and a
  /// driven handshake. It buffers inbound assembly, the outbound queue, decrypted
  /// application data, and the event queue, all as TBytes with explicit
  /// offset/length. Single-threaded: the caller serializes access.
  /// </summary>
  TTlsEngine = class sealed(TInterfacedObject, ITlsEngine)
  strict private
  type
    // decrypted plaintext waiting for the caller: [FHead, FTail) of one buffer, so the byte
    // count the app-read cap bounds is the real one and appends stay amortised O(1)
    TPlaintextQueue = record
    strict private
      FBuffer: TBytes;
      FHead: Int32;
      FTail: Int32;
    public
      procedure Append(const AData: TBytes);
      /// <summary>Moves up to ACount queued bytes into ADest at ADestOffset; the caller has
      /// already clamped ACount to the queue and the destination.</summary>
      procedure Take(var ADest: TBytes; ADestOffset, ACount: Int32);
      function Available: Int32;
    end;
  var
    FRecordLayer: TRecordLayer;
    FEvents: TQueue<ITlsEvent>;
    FConductor: THandshakeConductor;
    FAppQueue: TPlaintextQueue;
    // accepted 0-RTT application data, kept apart because it is replayable
    FEarlyQueue: TPlaintextQueue;
    FMaxAppReadBuffer: Int32;
    FTerminal: Boolean;
    FClosed: Boolean;
    FSentClose: Boolean;
    FHandshakeComplete: Boolean;
    /// <summary>Count of tolerated warning-level alerts received, bounded to guard against a
    /// peer flooding them (RFC 5246 7.2 tolerates warnings, RFC 8446 6 only user_canceled; a flood
    /// is a DoS).</summary>
    FWarningAlertCount: Int32;
    // 0-RTT: a write protection is installed (early or later) and the early-data window is
    // still open until the outcome is known
    FWriteProtectionInstalled: Boolean;
    // the Application write epoch is installed: application data may be sealed (a 1.3 server reaches
    // it at its Finished, half-RTT; a 1.3 client and any 1.2 endpoint at completion). Handshake and
    // early write epochs must not carry application data (RFC 8446 2 / 4.4.4)
    FAppWriteEpoch: Boolean;
    FEarlyDataClosed: Boolean;
    // 0-RTT outbound cap: the ticket's max_early_data budget and how much has gone out as
    // early data (over-budget bytes are not held - the caller resends them, see WriteEarlyData)
    FEarlyDataLimit: Int32;
    FEarlyDataSent: Int32;
    // the negotiated facts, surfaced to callers as one snapshot by ConnectionInfo
    FInfo: TTlsConnectionInfo;
    // set while draining inbound records: a synchronous handshake callback (verify callback,
    // verdict resolver, session store) is re-entering the single-threaded engine if it calls
    // ProcessInput/ReadAppData/SetCertificateVerdict while this is set, so those fail loud
    FDraining: Boolean;
    FLastError: TTlsError;
    // an out-of-range caller slice is misuse, refused locally rather than failed on the wire
    class procedure RequireSlice(const AData: TBytes; AOffset, ALength: Int32;
      AMessage: PResStringRec); static;
    procedure Enqueue(const AEvent: ITlsEvent);
    function IsTls13: Boolean;
    procedure QueueAlertRecord(const AAlert: TTlsAlert);
    procedure AppendAppData(const AData: TBytes);
    function AppReadAvailable: Int32;
    procedure HandleIncomingAlert(const AData: TBytes);
    procedure RouteFragment(const AFragment: TTlsRecordFragment);
    procedure DrainRecordLayer;
    function Fail(const AException: Exception): TTlsOutcome;
  public
    /// <summary>
    /// Builds the engine and wires its handshake in one step: a channel over the
    /// record layer and a driver that installs epochs and reports outcomes back here,
    /// held as the conductor. The initial machine selects the role (a client or server
    /// graph) and whether the engine initiates the first flight.
    /// </summary>
    constructor Create(const AInitialMachine: IHandshakeMachine;
      const ACryptoProvider: ICryptoProvider); overload;
    /// <summary>As above, bounding the inbound Certificate message to AMaxCertificateMessageLength
    /// (the config's certificate-chain budget) so the uncompressed peer chain is capped in step
    /// with the compressed path and the decode-boundary chain-cap gate.</summary>
    constructor Create(const AInitialMachine: IHandshakeMachine;
      const ACryptoProvider: ICryptoProvider;
      AMaxCertificateMessageLength: Int32); overload;
    destructor Destroy; override;

    /// <summary>Builds a wired engine and returns it as an ITlsEngine.</summary>
    class function CreateConfigured(const AInitialMachine: IHandshakeMachine;
      const ACryptoProvider: ICryptoProvider): ITlsEngine; overload; static;
    /// <summary>As above, with the config's Certificate-message cap threaded to the reassembler.</summary>
    class function CreateConfigured(const AInitialMachine: IHandshakeMachine;
      const ACryptoProvider: ICryptoProvider;
      AMaxCertificateMessageLength: Int32): ITlsEngine; overload; static;

    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    function WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32): Int32;
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    procedure SendClose;
    procedure SendAlert(ADescription: TTlsAlertDescription);
    procedure StartHandshake;
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingAppData: Int32;
    function ReadEarlyData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingEarlyData: Int32;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    function WantsRead: Boolean;
    function WantsWrite: Boolean;
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function IsTerminal: Boolean;
    function IsClosed: Boolean;
    function IsInboundClosed: Boolean;
    function WriteClosed: Boolean;
    function LastError: TTlsError;
    function ConnectionInfo: TTlsConnectionInfo;
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
  private
    // reached only by the handshake bridge below
    procedure InstallReadProtection(const AProtection: IRecordProtection);
    procedure InstallWriteProtection(const AProtection: IRecordProtection;
      AEpoch: TTlsEpoch);
    procedure ArmReadProtectionOnChangeCipherSpec(const AProtection: IRecordProtection);
    procedure RevertWriteToPlaintext;
    procedure SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    procedure SetEarlyReadEpoch(AActive: Boolean; AMaxBytes: Int32);
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: TBytes);
    procedure OnVersionNegotiated(const AVersion: TTlsVersion);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnCertificateVerdictNeeded(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes);
    procedure OnPeerCertificateChain(const AChain, AValidatedPath: TArray<TBytes>);
    procedure OnRequestedCertificateAuthorities(const AAuthorities: TArray<TBytes>);
    procedure OnConnectionParams(ACipherSuite, ANamedGroup: UInt16;
      AResumed, AExtendedMasterSecret: Boolean; const AServerName: string);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
    procedure OnWarningAlert(AAlert: TTlsAlertDescription);
    procedure OnEchAccepted;
    procedure OnEchGreased;
    procedure OnEchBackend;
    procedure OnEchServerRejected;
    procedure OnEchRejected(const ARetryConfigs: TBytes; AIsRetryAttempt: Boolean);
  end;

implementation

const
  DefaultMaxAppReadBuffer = Int32(1 shl 20); // 1 MiB advisory backpressure threshold
  PlaintextQueueMinCapacity = Int32(4096);
  PlaintextQueueRetainCapacity = Int32(1 shl 16);
  // the number of warning-level alerts tolerated before a flood is refused; the next one
  // aborts the connection (RFC 5246 7.2 tolerates warnings, RFC 8446 6 only user_canceled; a
  // flood is a DoS)
  MaxWarningAlerts = Int32(4);
  // the most undrained events kept before the informational kinds are dropped: room for a
  // full handshake's worth plus a long run of post-handshake notices, while a caller that never
  // drains cannot grow the queue without bound
  MaxQueuedEvents = Int32(64);

resourcestring
  SPeerFatalAlert = 'the peer sent a fatal alert';
  SPeerClosedDuringHandshake = 'the peer closed the connection during the handshake';
  SWarningAlertInTls13 = 'a warning alert other than user_canceled is not permitted in TLS 1.3';
  STooManyWarningAlerts = 'the peer sent too many warning-level alerts';
  SBogusAlertLevel = 'the alert carries a level that is neither warning nor fatal';
  SReentrantEngineCall =
    'the engine was re-entered from within a handshake callback; it is single-threaded and a ' +
    'callback must not call back into it';
  SLocalFatalAlert = 'a fatal alert was sent';
  SInboundBacklogFull =
    'the framed inbound backlog is full; pull/read before feeding more input (honor WantsRead)';
  SProcessInputSliceOutOfRange = 'the ProcessInput (offset, length) slice is out of range';
  SWriteSliceOutOfRange = 'the Write (offset, length) slice is out of range';
  SWriteAfterClose =
    'Write after the write side was closed (close_notify sent, or received under TLS 1.2) ' +
    'or the connection failed';
  SWriteBeforeWriteEpoch =
    'Write before the application write epoch would send application data in the clear or under ' +
    'the handshake/early keys; drive the handshake first - a TLS 1.3 server may write from its ' +
    'Finished onward, a client and any TLS 1.2 endpoint once complete (0-RTT uses WriteEarlyData)';
  SRecordLimitNoRekey =
    'the write epoch reached its AEAD record limit and could not be rekeyed; ' +
    'the connection was closed';

type
  /// <summary>
  /// Lets the handshake driver install epochs and report outcomes back to the engine, which
  /// owns this bridge and is held by a raw reference.
  /// </summary>
  TEngineHandshakeBridge = class sealed(TInterfacedObject, IRecordEpochInstaller,
    IHandshakeSink, IHandshakeVersionSink, IHandshakeVerdictSink,
    IHandshakeConnectionInfoSink, IEchStatusSink, IWarningAlertSink)
  strict private
  var
    FEngine: TTlsEngine;
  public
    constructor Create(const AEngine: TTlsEngine);
    procedure InstallReadProtection(const AProtection: IRecordProtection);
    procedure InstallWriteProtection(const AProtection: IRecordProtection;
      AEpoch: TTlsEpoch);
    procedure ArmReadProtectionOnChangeCipherSpec(const AProtection: IRecordProtection);
    procedure RevertWriteToPlaintext;
    procedure SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    procedure SetEarlyReadEpoch(AActive: Boolean; AMaxBytes: Int32);
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: TBytes);
    procedure OnVersionNegotiated(const AVersion: TTlsVersion);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnCertificateVerdictNeeded(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes);
    procedure OnPeerCertificateChain(const AChain, AValidatedPath: TArray<TBytes>);
    procedure OnRequestedCertificateAuthorities(const AAuthorities: TArray<TBytes>);
    procedure OnConnectionParams(ACipherSuite, ANamedGroup: UInt16;
      AResumed, AExtendedMasterSecret: Boolean; const AServerName: string);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
    procedure OnWarningAlert(AAlert: TTlsAlertDescription);
    procedure OnEchAccepted;
    procedure OnEchGreased;
    procedure OnEchBackend;
    procedure OnEchServerRejected;
    procedure OnEchRejected(const ARetryConfigs: TBytes; AIsRetryAttempt: Boolean);
  end;

{ TEngineHandshakeBridge }

constructor TEngineHandshakeBridge.Create(const AEngine: TTlsEngine);
begin
  inherited Create;
  FEngine := AEngine;
end;

procedure TEngineHandshakeBridge.InstallReadProtection(
  const AProtection: IRecordProtection);
begin
  FEngine.InstallReadProtection(AProtection);
end;

procedure TEngineHandshakeBridge.InstallWriteProtection(
  const AProtection: IRecordProtection; AEpoch: TTlsEpoch);
begin
  FEngine.InstallWriteProtection(AProtection, AEpoch);
end;

procedure TEngineHandshakeBridge.ArmReadProtectionOnChangeCipherSpec(
  const AProtection: IRecordProtection);
begin
  FEngine.ArmReadProtectionOnChangeCipherSpec(AProtection);
end;

procedure TEngineHandshakeBridge.RevertWriteToPlaintext;
begin
  FEngine.RevertWriteToPlaintext;
end;

procedure TEngineHandshakeBridge.SetRecordSizeLimit(AOutboundLimit,
  AInboundLimit: Int32);
begin
  FEngine.SetRecordSizeLimit(AOutboundLimit, AInboundLimit);
end;

procedure TEngineHandshakeBridge.SetEarlyDataSkip(AMaxBytes: Int32);
begin
  FEngine.SetEarlyDataSkip(AMaxBytes);
end;

procedure TEngineHandshakeBridge.SetEarlyDataLimit(AMaxBytes: Int32);
begin
  FEngine.SetEarlyDataLimit(AMaxBytes);
end;

procedure TEngineHandshakeBridge.SetEarlyReadEpoch(AActive: Boolean; AMaxBytes: Int32);
begin
  FEngine.SetEarlyReadEpoch(AActive, AMaxBytes);
end;

procedure TEngineHandshakeBridge.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  FEngine.OnHandshakeEvent(AEvent);
end;

procedure TEngineHandshakeBridge.OnAlpnSelected(const AProtocol: TBytes);
begin
  FEngine.OnAlpnSelected(AProtocol);
end;

procedure TEngineHandshakeBridge.OnVersionNegotiated(const AVersion: TTlsVersion);
begin
  FEngine.OnVersionNegotiated(AVersion);
end;

procedure TEngineHandshakeBridge.OnOcspStapleReceived(const AStaple: TBytes);
begin
  FEngine.OnOcspStapleReceived(AStaple);
end;

procedure TEngineHandshakeBridge.OnCertificateVerdictNeeded(
  const AChain, AValidatedPath: TArray<TBytes>; const AHostName: string;
  const AStaple: TBytes);
begin
  FEngine.OnCertificateVerdictNeeded(AChain, AValidatedPath, AHostName, AStaple);
end;

procedure TEngineHandshakeBridge.OnPeerCertificateChain(
  const AChain, AValidatedPath: TArray<TBytes>);
begin
  FEngine.OnPeerCertificateChain(AChain, AValidatedPath);
end;

procedure TEngineHandshakeBridge.OnRequestedCertificateAuthorities(
  const AAuthorities: TArray<TBytes>);
begin
  FEngine.OnRequestedCertificateAuthorities(AAuthorities);
end;

procedure TEngineHandshakeBridge.OnConnectionParams(ACipherSuite,
  ANamedGroup: UInt16; AResumed, AExtendedMasterSecret: Boolean;
  const AServerName: string);
begin
  FEngine.OnConnectionParams(ACipherSuite, ANamedGroup, AResumed, AExtendedMasterSecret,
    AServerName);
end;

procedure TEngineHandshakeBridge.OnHandshakeEstablished;
begin
  FEngine.OnHandshakeEstablished;
end;

procedure TEngineHandshakeBridge.OnHandshakeFailed(AAlert: TTlsAlertDescription);
begin
  FEngine.OnHandshakeFailed(AAlert);
end;

procedure TEngineHandshakeBridge.OnWarningAlert(AAlert: TTlsAlertDescription);
begin
  FEngine.OnWarningAlert(AAlert);
end;

procedure TEngineHandshakeBridge.OnEchAccepted;
begin
  FEngine.OnEchAccepted;
end;

procedure TEngineHandshakeBridge.OnEchGreased;
begin
  FEngine.OnEchGreased;
end;

procedure TEngineHandshakeBridge.OnEchBackend;
begin
  FEngine.OnEchBackend;
end;

procedure TEngineHandshakeBridge.OnEchServerRejected;
begin
  FEngine.OnEchServerRejected;
end;

procedure TEngineHandshakeBridge.OnEchRejected(const ARetryConfigs: TBytes;
  AIsRetryAttempt: Boolean);
begin
  FEngine.OnEchRejected(ARetryConfigs, AIsRetryAttempt);
end;

{ TTlsEngine }

constructor TTlsEngine.Create(const AInitialMachine: IHandshakeMachine;
  const ACryptoProvider: ICryptoProvider);
begin
  Create(AInitialMachine, ACryptoProvider, DefaultMaxHandshakeMessageLength);
end;

constructor TTlsEngine.Create(const AInitialMachine: IHandshakeMachine;
  const ACryptoProvider: ICryptoProvider; AMaxCertificateMessageLength: Int32);
var
  LChannel: IHandshakeChannel;
  LBridge: TEngineHandshakeBridge;
  LDriver: THandshakeDriver;
begin
  inherited Create;
  FRecordLayer := TRecordLayer.Create;
  FEvents := TQueue<ITlsEvent>.Create;
  FMaxAppReadBuffer := DefaultMaxAppReadBuffer;
  FTerminal := False;
  FClosed := False;
  FSentClose := False;
  FHandshakeComplete := False;
  FAppWriteEpoch := False;
  FWarningAlertCount := 0;
  FInfo.EchStatus := TEchStatus.NotOffered;
  // a zero wire code until an epoch's keys name the negotiated version
  FInfo.NegotiatedVersion := TTlsVersion.Create(0);
  FLastError := TTlsError.CreateFatal(TTlsAlertDescription.InternalError, '');
  // a cleartext application_data record (before any read epoch key) is unexpected on a
  // real handshake (RFC 8446 5.1)
  FRecordLayer.StrictApplicationData := True;
  // a client stamps its initial ClientHello record with legacy_record_version 0x0301 for
  // backward compatibility before the negotiated version is known (RFC 8446 5.1)
  if AInitialMachine.Initiates then
    FRecordLayer.UseClientInitialRecordVersion;
  LChannel := THandshakeChannel.Create(FRecordLayer, AMaxCertificateMessageLength)
    as IHandshakeChannel;
  LBridge := TEngineHandshakeBridge.Create(Self);
  LDriver := THandshakeDriver.Create(LChannel, LBridge as IRecordEpochInstaller,
    ACryptoProvider, LBridge as IHandshakeSink);
  FConductor := THandshakeConductor.Create(LChannel, LDriver, AInitialMachine);
end;

destructor TTlsEngine.Destroy;
begin
  // free the conductor first: it releases the driver's references to the bridge,
  // whose raw back-reference to this engine must never outlive the engine
  FConductor.Free;
  FEvents.Free;
  FRecordLayer.Free;
  inherited Destroy;
end;

class function TTlsEngine.CreateConfigured(
  const AInitialMachine: IHandshakeMachine;
  const ACryptoProvider: ICryptoProvider): ITlsEngine;
begin
  Result := TTlsEngine.Create(AInitialMachine, ACryptoProvider);
end;

class function TTlsEngine.CreateConfigured(
  const AInitialMachine: IHandshakeMachine;
  const ACryptoProvider: ICryptoProvider;
  AMaxCertificateMessageLength: Int32): ITlsEngine;
begin
  Result := TTlsEngine.Create(AInitialMachine, ACryptoProvider,
    AMaxCertificateMessageLength);
end;

procedure TTlsEngine.Enqueue(const AEvent: ITlsEvent);
begin
  // a caller that never drains must not grow the queue without bound: past the cap the
  // informational kinds are dropped, while the terminal ones and a parked verdict (which the
  // handshake cannot resume without) are always kept
  if (FEvents.Count >= MaxQueuedEvents) and
    not (AEvent.Kind in [TTlsEventKind.PeerAlert, TTlsEventKind.Closed,
    TTlsEventKind.CertificateReceived]) then
    Exit;
  FEvents.Enqueue(AEvent);
end;

procedure TTlsEngine.QueueAlertRecord(const AAlert: TTlsAlert);
var
  LBytes: TBytes;
begin
  LBytes := TTlsAlertProtocol.Encode(AAlert);
  FRecordLayer.Write(TTlsContentType.Alert, LBytes, 0, System.Length(LBytes));
end;

procedure TTlsEngine.AppendAppData(const AData: TBytes);
begin
  if System.Length(AData) = 0 then
    Exit;
  // no hard cap here: the read buffer is bounded by backpressure - DrainRecordLayer stops pulling
  // once the queue reaches FMaxAppReadBuffer, and WantsRead reports False, so a caller that honours
  // it stops feeding. A single pulled record may overshoot the soft cap by at most one record.
  FAppQueue.Append(AData);
end;

function TTlsEngine.AppReadAvailable: Int32;
begin
  Result := FAppQueue.Available;
end;

procedure TTlsEngine.TPlaintextQueue.Append(const AData: TBytes);
var
  LLive, LNeed, LCap: Int32;
begin
  if System.Length(AData) = 0 then
    Exit;
  LLive := FTail - FHead;
  if Int64(FTail) + System.Length(AData) > System.Length(FBuffer) then
  begin
    // reclaim the consumed prefix before growing
    if FHead > 0 then
    begin
      if LLive > 0 then
        System.Move(FBuffer[FHead], FBuffer[0], LLive);
      FHead := 0;
      FTail := LLive;
    end;
    LNeed := FTail + System.Length(AData);
    if LNeed > System.Length(FBuffer) then
    begin
      LCap := System.Length(FBuffer);
      if LCap < PlaintextQueueMinCapacity then
        LCap := PlaintextQueueMinCapacity;
      if LCap <= High(Int32) div 2 then
        LCap := LCap * 2;
      if LCap < LNeed then
        LCap := LNeed;
      System.SetLength(FBuffer, LCap);
    end;
  end;
  System.Move(AData[0], FBuffer[FTail], System.Length(AData));
  Inc(FTail, System.Length(AData));
end;

procedure TTlsEngine.TPlaintextQueue.Take(var ADest: TBytes; ADestOffset, ACount: Int32);
begin
  System.Move(FBuffer[FHead], ADest[ADestOffset], ACount);
  Inc(FHead, ACount);
  if FHead = FTail then
  begin
    FHead := 0;
    FTail := 0;
    // do not pin a buffer sized for a burst
    if System.Length(FBuffer) > PlaintextQueueRetainCapacity then
      FBuffer := nil;
  end;
end;

function TTlsEngine.TPlaintextQueue.Available: Int32;
begin
  Result := FTail - FHead;
end;

class procedure TTlsEngine.RequireSlice(const AData: TBytes; AOffset, ALength: Int32;
  AMessage: PResStringRec);
begin
  if (AOffset < 0) or (ALength < 0) or (Int64(AOffset) + ALength > System.Length(AData)) then
    raise EArgumentTlsLibException.CreateRes(AMessage);
end;

procedure TTlsEngine.HandleIncomingAlert(const AData: TBytes);
var
  LReceived: TReceivedAlert;
begin
  LReceived := TTlsAlertProtocol.Decode(AData, 0, System.Length(AData));
  // a level that is neither warning nor fatal is malformed on the wire (RFC 5246 7.2), close_notify
  // included
  if (LReceived.LevelByte <> TTlsAlertLevel.Warning.ToByte) and not LReceived.IsFatalLevel then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBogusAlertLevel);
  if LReceived.IsCloseNotify then
  begin
    FClosed := True;
    // the peer's write side is closed; release any inbound state and ignore later bytes (RFC 8446 6.1)
    FRecordLayer.DiscardInbound;
    Enqueue(TTlsEvents.MakeClosed);
    // closing before the handshake completes abandons it: a failure, not a half-close
    if not FHandshakeComplete then
    begin
      FTerminal := True;
      FLastError := TTlsError.CreatePeerFatal(LReceived.DescriptionByte, SPeerClosedDuringHandshake);
    end;
    Exit;
  end;
  // a warning-level alert is advisory: tolerated in TLS 1.2 (RFC 5246 7.2) and, in TLS 1.3,
  // only for user_canceled - every other warning is outlawed there (RFC 8446 6). Either way a
  // flood is refused. close_notify is handled above regardless of level.
  if LReceived.LevelByte = TTlsAlertLevel.Warning.ToByte then
  begin
    if (FInfo.NegotiatedVersion.WireValue = TlsWireVersionTls13) and
      not (LReceived.HasKnownDescription and
      (LReceived.Description = TTlsAlertDescription.UserCanceled)) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.DecodeError, @SWarningAlertInTls13);
    Inc(FWarningAlertCount);
    if FWarningAlertCount > MaxWarningAlerts then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnexpectedMessage, @STooManyWarningAlerts);
    Exit; // tolerate this warning and continue
  end;
  // a fatal alert is terminal; carry the peer's raw description byte so a code we do not map
  // (e.g. no_certificate, or a future one) is reported honestly rather than as our internal_error
  Enqueue(TTlsEvents.MakePeerAlert(LReceived));
  FTerminal := True;
  FLastError := TTlsError.CreatePeerFatal(LReceived.DescriptionByte, SPeerFatalAlert);
end;

procedure TTlsEngine.RouteFragment(const AFragment: TTlsRecordFragment);
begin
  // once terminal (fatal alert) or closed (inbound close_notify) nothing further is
  // routed: post-close records must not become app-readable nor overwrite FLastError
  if FTerminal or FClosed then
    Exit;
  // a handshake message that spans records MUST NOT have another record type interleaved
  // between its fragments (RFC 8446 5.1); an application_data or alert record arriving while one
  // is partially buffered is that violation (change_cipher_spec is consumed in the record layer
  // and never reaches here)
  if (AFragment.ContentType <> TTlsContentType.Handshake) and
    FConductor.HasBufferedHandshake then
  begin
    OnHandshakeFailed(TTlsAlertDescription.UnexpectedMessage);
    Exit;
  end;
  case AFragment.ContentType of
    TTlsContentType.ApplicationData:
      begin
        // genuine traffic resets the peer's post-handshake message flood counter
        FConductor.NoteApplicationData;
        if AFragment.Early then
          FEarlyQueue.Append(AFragment.Data)
        else
          AppendAppData(AFragment.Data);
      end;
    TTlsContentType.Handshake:
      // the handshake consumes the fragment and drives its state machine
      FConductor.DeliverHandshake(AFragment.Data, 0, System.Length(AFragment.Data));
    TTlsContentType.Alert:
      HandleIncomingAlert(AFragment.Data);
    // change_cipher_spec is consumed (classified) in the record layer; nothing else reaches here
  end;
end;

procedure TTlsEngine.DrainRecordLayer;
var
  LFragment: TTlsRecordFragment;
begin
  // while a peer-certificate verdict is parked, pull no further records. Decryption is
  // resolved per record at pull time under the currently installed read epoch; the next
  // record may belong to an epoch that is not installed until the parked flight is
  // processed (e.g. post-handshake application data following the not-yet-processed
  // Finished, which installs the application read epoch). Pulling it now would decrypt it
  // under the stale epoch and fail its AEAD. The record stays framed until the verdict
  // resolves and SetCertificateVerdict resumes the drain in the correct epoch order.
  if FConductor.AwaitingVerdict then
    Exit;
  // stop pulling the moment the connection becomes terminal/closed (e.g. a fatal alert or
  // close_notify coalesced ahead of app-data): the trailing record stays framed, undecrypted.
  // Also stop once the app-read buffer is full: unread plaintext applies backpressure (the
  // record stays framed, WantsRead reports False) instead of growing the buffer without bound.
  FDraining := True;
  try
    while (not (FTerminal or FClosed)) and (AppReadAvailable < FMaxAppReadBuffer) and
      FRecordLayer.NextIncoming(LFragment) do
    begin
      RouteFragment(LFragment);
      if FConductor.AwaitingVerdict then
        Break;
    end;
  finally
    FDraining := False;
  end;
end;

function TTlsEngine.Fail(const AException: Exception): TTlsOutcome;
begin
  if not FTerminal then
  begin
    FLastError := TAlertMapping.ErrorFor(AException);
    try
      QueueAlertRecord(FLastError.Alert);
    except
      // if even emitting the alert fails, the engine still becomes terminal
    end;
    FTerminal := True;
  end;
  Result := TTlsOutcome.Fatal;
end;

function TTlsEngine.ProcessInput(const AWire: TBytes; AOffset,
  ALength: Int32): TTlsOutcome;
begin
  if FDraining then
    raise EInvalidOperationTlsLibException.CreateRes(@SReentrantEngineCall);
  // an out-of-range slice is caller misuse, not a peer fault: reject it up front rather than let it
  // reach the failure gate (where a peer-input error, which shares the argument-exception base,
  // correctly becomes a wire alert). The record layer re-checks this as its own defensive guard.
  RequireSlice(AWire, AOffset, ALength, @SProcessInputSliceOutOfRange);
  if FTerminal then
    Exit(TTlsOutcome.Fatal);
  // after an inbound close_notify the peer's write side is closed: discard anything it keeps
  // sending rather than frame it (RFC 8446 6.1). Checked before the backlog bound so a post-close
  // feed never raises. The tail below still reports any already-buffered app data / events.
  if not FClosed then
  begin
    // flow control, not a protocol error: the caller ignored WantsRead and the framed backlog is
    // full. Raise API-misuse WITHOUT going through Fail (no wire alert, engine stays alive); the
    // caller must pull/drain before feeding more.
    if FRecordLayer.InboundBacklogFull then
      raise EInvalidOperationTlsLibException.CreateRes(@SInboundBacklogFull);
    try
      FRecordLayer.ProcessInput(AWire, AOffset, ALength);
      DrainRecordLayer;
    except
      on E: Exception do
        Exit(Fail(E));
    end;
  end;
  if FTerminal then // a received fatal alert or a handshake failure
    Exit(TTlsOutcome.Fatal);
  if (AppReadAvailable > 0) or (FEarlyQueue.Available > 0) or (FEvents.Count > 0) or
    (FRecordLayer.PendingOutgoing > 0) then
    Result := TTlsOutcome.Advanced
  else
    Result := TTlsOutcome.NeedMoreInput;
end;

function TTlsEngine.IsTls13: Boolean;
begin
  Result := FInfo.NegotiatedVersion.WireValue = TlsWireVersionTls13;
end;

procedure TTlsEngine.Write(const AData: TBytes; AOffset, ALength: Int32);
var
  LOffset, LRemaining, LWritten: Int32;
begin
  RequireSlice(AData, AOffset, ALength, @SWriteSliceOutOfRange);
  // writing after our own close_notify or after a fatal is API misuse in either version. An
  // inbound close_notify closes only the read side under TLS 1.3 (RFC 8446 6.1: each half is
  // independent), so a 1.3 write continues; under TLS 1.2 it closes the connection (RFC 5246
  // 7.2.1 discards pending writes - deliberately stricter than a common implementation's
  // half-close, which we do not offer for 1.2).
  if FTerminal or FSentClose or (FClosed and not IsTls13) then
    raise EInvalidOperationTlsLibException.CreateRes(@SWriteAfterClose);
  // refuse application data until the Application write epoch is in force, so it is never sealed in
  // the clear (plaintext / post-HRR-revert epoch), under the handshake keys, or under the early-data
  // keys as replayable 0-RTT (RFC 8446 8). A TLS 1.3 server may write from its Finished
  // onward (half-RTT, RFC 8446 4.4.4); a 1.3 client and any TLS 1.2 endpoint must wait for the
  // handshake to complete (no False-Start). 0-RTT is sent through WriteEarlyData, not here.
  if not (FAppWriteEpoch and (IsTls13 or FHandshakeComplete)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SWriteBeforeWriteEpoch);
  // a zero-length application write is a no-op (after the close/epoch guards): it has nothing to
  // precede an owed KeyUpdate with, and must not put an empty record on the wire (RFC 8446 5.4
  // permits empty application_data; the peer's consecutive-empty-record bound is local policy)
  if ALength <= 0 then
    Exit;
  // a KeyUpdate owed to a peer update_requested must precede our next application data
  // (RFC 8446 4.6.3); flushing here coalesces repeats into one response before the write.
  // A failure to build/flush it is fatal - abort with its alert and do NOT queue the app
  // plaintext behind that alert (the record layer's Write is not blocked by a failed read side).
  if FHandshakeComplete then
    try
      FConductor.FlushPendingKeyUpdate;
    except
      on E: Exception do
      begin
        // re-raise so a failed write is reported rather than silently dropped
        Fail(E);
        raise;
      end;
    end;
  LOffset := AOffset;
  LRemaining := ALength;
  // seal in chunks; the record layer pauses application data at the write epoch's AEAD rekey
  // threshold (RFC 8446 5.5). At each pause send a KeyUpdate (1.3) to rekey the write side and
  // resume; TLS 1.2 has no KeyUpdate, so a write epoch that cannot be rekeyed closes the
  // connection rather than exceed the AEAD safety bound.
  repeat
    // a seal failure (an AEAD nonce-reuse guard, a provider fault) must fail the engine closed
    // rather than escape with the connection non-terminal and half-written
    try
      LWritten := FRecordLayer.Write(TTlsContentType.ApplicationData, AData, LOffset,
        LRemaining);
    except
      on E: Exception do
      begin
        Fail(E);
        raise;
      end;
    end;
    Inc(LOffset, LWritten);
    Dec(LRemaining, LWritten);
    if LRemaining <= 0 then
      Break;
    if FHandshakeComplete then
      try
        FConductor.RequestKeyUpdate(TKeyUpdateRequest.UpdateNotRequested);
      except
        on E: Exception do
        begin
          // re-raise so a mid-write rekey failure is reported rather than silently dropped
          Fail(E);
          raise;
        end;
      end;
    // still at the threshold means the epoch could not be rekeyed (TLS 1.2, or pre-completion):
    // close and refuse rather than spin or exceed the limit
    if FRecordLayer.WriteNeedsKeyUpdate then
    begin
      SendClose;
      raise ERecordLimitTlsLibException.CreateRes(@SRecordLimitNoRekey);
    end;
  until False;
end;

function TTlsEngine.WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32): Int32;
var
  LAccept: Int32;
begin
  Result := 0;
  RequireSlice(AData, AOffset, ALength, @SWriteSliceOutOfRange);
  // only in the open early-data window: handshaking, a (early) write epoch installed,
  // and the client has not yet ended early data
  if FTerminal or FClosed or FSentClose or FHandshakeComplete or FEarlyDataClosed or
    (not FWriteProtectionInstalled) or (ALength <= 0) then
    Exit;
  // cap outbound 0-RTT at the ticket's max_early_data (RFC 8446 4.2.10): send at most the
  // remaining budget as early data and return that count; the caller resends the rest as 1-RTT
  // once the handshake completes
  LAccept := FEarlyDataLimit - FEarlyDataSent;
  if LAccept > ALength then
    LAccept := ALength;
  if LAccept <= 0 then
    Exit;
  // the early epoch cannot be rekeyed, so honor how many bytes the record layer actually sealed
  // (it pauses at the AEAD limit); the caller resends any remainder as 1-RTT after the handshake
  // a seal failure fails the engine closed, as on the 1-RTT write path
  try
    Result := FRecordLayer.Write(TTlsContentType.ApplicationData, AData, AOffset, LAccept);
  except
    on E: Exception do
    begin
      Fail(E);
      raise;
    end;
  end;
  Inc(FEarlyDataSent, Result);
end;

procedure TTlsEngine.RequestKeyUpdate(ARequest: TKeyUpdateRequest);
begin
  // post-handshake only, over an established connection with a live handshake machine
  // (TLS 1.2 machines make this a no-op); the KeyUpdate is protected and queued outbound. An
  // inbound close_notify does not stop 1.3 writes, so it must not stop rekeying them either.
  if FTerminal or FSentClose or (FClosed and not IsTls13) or (not FHandshakeComplete) or
    (not FAppWriteEpoch) then
    Exit;
  // a failure to build the KeyUpdate is fatal: abort with its alert rather than let the
  // exception escape the engine
  try
    FConductor.RequestKeyUpdate(ARequest);
  except
    on E: Exception do
    begin
      Fail(E);
      Exit;
    end;
  end;
end;

function TTlsEngine.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  // available once the connection's exporter secret is derived - for a TLS 1.3 server that is
  // half-RTT (after it sent its Finished), before the peer's Finished (RFC 8446 7.5); TLS 1.2
  // stays gated on completion and on Extended Master Secret. Withheld while parked on an out-of-band peer-certificate verdict,
  // and a failed (terminal) connection exports nothing.
  if FTerminal or (not FConductor.CanExportKeyingMaterial) then
    Exit(nil);
  Result := FConductor.ExportKeyingMaterial(ALabel, ALength);
end;

function TTlsEngine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  if FTerminal or (not FConductor.CanExportKeyingMaterial) then
    Exit(nil);
  Result := FConductor.ExportKeyingMaterial(ALabel, AContext, ALength);
end;

function TTlsEngine.ExportEarlyKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  // TLS 1.3 early exporter: available on a client once it offers 0-RTT and on a server once it
  // accepts 0-RTT; empty on TLS 1.2 and on a failed connection (RFC 8446 7.5)
  if FTerminal or (not FConductor.CanExportEarlyKeyingMaterial) then
    Exit(nil);
  Result := FConductor.ExportEarlyKeyingMaterial(ALabel, AContext, ALength);
end;

procedure TTlsEngine.SendClose;
begin
  if FTerminal or FSentClose then
    Exit;
  FSentClose := True;
  QueueAlertRecord(TTlsAlertProtocol.CloseNotify);
end;

procedure TTlsEngine.SendAlert(ADescription: TTlsAlertDescription);
begin
  if FTerminal then
    Exit;
  QueueAlertRecord(TTlsAlert.CreateFatal(ADescription));
  FTerminal := True;
  FLastError := TTlsError.CreateFatal(ADescription, SLocalFatalAlert,
    TTlsErrorOrigin.Local);
end;

procedure TTlsEngine.StartHandshake;
begin
  // an abort already ended the connection; a hello queued behind its alert would be noise
  if FTerminal then
    Exit;
  // an in-band start failure (ECH/PSK/crypto setup) aborts with its alert rather than escaping
  try
    FConductor.Start;
  except
    on E: Exception do
    begin
      Fail(E);
      Exit;
    end;
  end;
end;

procedure TTlsEngine.SetCertificateVerdict(AAccept: Boolean;
  AAlert: TTlsAlertDescription);
begin
  if FDraining then
    raise EInvalidOperationTlsLibException.CreateRes(@SReentrantEngineCall);
  // a no-op unless the handshake is actually parked on a verdict (idempotent, safe to call);
  // ResolveCertificateVerdict below clears the conductor's park flag
  if not FConductor.AwaitingVerdict then
    Exit;
  // a fatal alert already ended the connection; resuming would queue Finished behind it
  if FTerminal then
    Exit;
  // reject aborts fail-closed (the conductor emits AAlert, making the engine terminal); accept
  // drains the buffered flight and completes the handshake. A malformed/bad-signature record in
  // that buffered flight is fatal: abort with its alert instead of letting the exception escape
  // the engine (and the pump) with no alert on the wire and the engine left non-terminal.
  try
    FConductor.ResolveCertificateVerdict(AAccept, AAlert);
    // with the park cleared, resume pulling the framed remainder of the flight that was held
    // back while parked, so each record decrypts under the epoch installed by the record
    // before it (the Finished installs the application read epoch ahead of any app data)
    if not FTerminal then
      DrainRecordLayer;
  except
    on E: Exception do
    begin
      Fail(E);
      Exit;
    end;
  end;
end;

function TTlsEngine.TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
begin
  Result := FRecordLayer.TakeOutgoing(ADest, ADestOffset);
end;

function TTlsEngine.ReadAppData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
var
  LCapacity, LWant: Int32;
begin
  if FDraining then
    raise EInvalidOperationTlsLibException.CreateRes(@SReentrantEngineCall);
  LCapacity := System.Length(ADest) - ADestOffset;
  if (ADestOffset < 0) or (LCapacity <= 0) or (AMaxLength <= 0) then
    Exit(0);
  LWant := FAppQueue.Available;
  if LWant > AMaxLength then
    LWant := AMaxLength;
  if LWant > LCapacity then
    LWant := LCapacity;
  if LWant <= 0 then
    Exit(0);
  Result := LWant;
  FAppQueue.Take(ADest, ADestOffset, LWant);
  // reading down the buffer relieves backpressure: resume the drain so records held back at the
  // app-read cap (a raw embedder that fed a large buffer) surface, and a KeyUpdate/alert produced
  // while pulling reaches the record layer's outbound queue. Not while parked, and never turning a
  // pull failure into an escape.
  if (not FConductor.AwaitingVerdict) and (not FTerminal) and (not FClosed) and
    (FAppQueue.Available < FMaxAppReadBuffer) then
  begin
    try
      DrainRecordLayer;
    except
      on E: Exception do
        Fail(E);
    end;
  end;
end;

function TTlsEngine.PendingAppData: Int32;
begin
  Result := FAppQueue.Available;
end;

function TTlsEngine.ReadEarlyData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
var
  LCapacity, LWant: Int32;
begin
  if FDraining then
    raise EInvalidOperationTlsLibException.CreateRes(@SReentrantEngineCall);
  LCapacity := System.Length(ADest) - ADestOffset;
  if (ADestOffset < 0) or (LCapacity <= 0) or (AMaxLength <= 0) then
    Exit(0);
  LWant := FEarlyQueue.Available;
  if LWant > AMaxLength then
    LWant := AMaxLength;
  if LWant > LCapacity then
    LWant := LCapacity;
  if LWant <= 0 then
    Exit(0);
  Result := LWant;
  // no drain to resume: the early queue never counts against the app-read cap, since the
  // accepted max_early_data bounds it (the builder refuses a server value of 1 MiB or more)
  FEarlyQueue.Take(ADest, ADestOffset, LWant);
end;

function TTlsEngine.PendingEarlyData: Int32;
begin
  Result := FEarlyQueue.Available;
end;

function TTlsEngine.NextEvent(out AEvent: ITlsEvent): Boolean;
begin
  Result := FEvents.Count > 0;
  if Result then
    AEvent := FEvents.Dequeue
  else
    AEvent := nil;
end;

function TTlsEngine.WantsRead: Boolean;
begin
  Result := (not FTerminal) and (not FClosed) and
    (AppReadAvailable < FMaxAppReadBuffer) and
    (not FRecordLayer.InboundBacklogFull);
end;

function TTlsEngine.WantsWrite: Boolean;
begin
  Result := FRecordLayer.PendingOutgoing > 0;
end;

function TTlsEngine.IsHandshaking: Boolean;
begin
  Result := (not FTerminal) and (not FHandshakeComplete);
end;

function TTlsEngine.AwaitingCertificateVerdict: Boolean;
begin
  Result := FConductor.AwaitingVerdict;
end;

function TTlsEngine.IsTerminal: Boolean;
begin
  Result := FTerminal;
end;

function TTlsEngine.IsClosed: Boolean;
begin
  // finished for reading: failed, or the peer's inbound close_notify arrived
  Result := FTerminal or FClosed;
end;

function TTlsEngine.IsInboundClosed: Boolean;
begin
  Result := FClosed;
end;

function TTlsEngine.WriteClosed: Boolean;
begin
  // the write-closed subset of Write's guards (Write also refuses before the application write
  // epoch is in force - a transient pre-completion state, not reported here). An inbound
  // close_notify closes the write side only under TLS 1.2; under TLS 1.3 it stays open (RFC 8446 6.1).
  Result := FTerminal or FSentClose or (FClosed and not IsTls13);
end;

function TTlsEngine.LastError: TTlsError;
begin
  Result := FLastError;
end;

function TTlsEngine.ConnectionInfo: TTlsConnectionInfo;
begin
  Result := FInfo;
  // copy retry_configs and the ALPN name so a caller cannot mutate the engine's held bytes (the
  // name also rides a resumption ticket); the certificate, path, CA and staple arrays are shared
  // read-only views, not copies
  Result.EchRetryConfigs := System.Copy(FInfo.EchRetryConfigs);
  Result.AlpnProtocol := System.Copy(FInfo.AlpnProtocol);
end;

procedure TTlsEngine.InstallReadProtection(const AProtection: IRecordProtection);
begin
  FRecordLayer.SetReadProtection(AProtection);
end;

procedure TTlsEngine.ArmReadProtectionOnChangeCipherSpec(
  const AProtection: IRecordProtection);
begin
  // the TLS 1.2 read epoch activates on the peer's change_cipher_spec, not here; the keys are
  // derived and owned from now, and the read epoch itself flips when the record layer
  // consumes the CCS
  FRecordLayer.ArmReadProtectionOnChangeCipherSpec(AProtection);
end;

procedure TTlsEngine.InstallWriteProtection(const AProtection: IRecordProtection;
  AEpoch: TTlsEpoch);
begin
  // installing write keys no longer means the handshake is done: in TLS 1.3 the
  // write side moves to the handshake epoch mid-flight. Completion is signalled by
  // the state machine through OnHandshakeEstablished.
  FRecordLayer.SetWriteProtection(AProtection);
  FWriteProtectionInstalled := True; // 0-RTT: the early-data write window can open
  // application data may be sealed only once the Application write epoch is installed (a 1.3 server
  // reaches it at its Finished - half-RTT); handshake/early write epochs must not carry app data
  FAppWriteEpoch := AEpoch = TTlsEpoch.Application;
end;

procedure TTlsEngine.RevertWriteToPlaintext;
begin
  // a HelloRetryRequest rejected the offered 0-RTT: drop the early-data write epoch back to
  // plaintext so the second ClientHello onward goes out in the clear (RFC 8446 4.2.10). No
  // keys-installed event - this is a downgrade of the write epoch, not a new epoch.
  FRecordLayer.RevertWriteToPlaintext;
  FAppWriteEpoch := False;
end;

procedure TTlsEngine.SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);
begin
  FRecordLayer.SetRecordSizeLimit(AOutboundLimit, AInboundLimit);
end;

procedure TTlsEngine.SetEarlyDataSkip(AMaxBytes: Int32);
begin
  FRecordLayer.SetEarlyDataSkip(AMaxBytes);
end;

procedure TTlsEngine.SetEarlyDataLimit(AMaxBytes: Int32);
begin
  FEarlyDataLimit := AMaxBytes;
end;

procedure TTlsEngine.SetEarlyReadEpoch(AActive: Boolean; AMaxBytes: Int32);
begin
  FRecordLayer.SetEarlyReadAccepted(AActive, AMaxBytes);
end;

procedure TTlsEngine.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  // manage the client's early-data buffer as the outcome becomes known
  case AEvent of
    TTlsEventKind.EarlyDataAccepted:
      // the early data was delivered under the 0-RTT keys; nothing more to do
      FEarlyDataClosed := True;
    TTlsEventKind.EarlyDataRejected:
      // the early data already went out under the early keys; on a reject it is discarded, not
      // retransmitted as 1-RTT (RFC 8446 4.2.10 leaves any resend to the application)
      FEarlyDataClosed := True;
  end;
  Enqueue(TTlsEvents.MakeSimple(AEvent));
end;

procedure TTlsEngine.OnAlpnSelected(const AProtocol: TBytes);
begin
  FInfo.AlpnProtocol := AProtocol;
end;

procedure TTlsEngine.OnVersionNegotiated(const AVersion: TTlsVersion);
begin
  FInfo.NegotiatedVersion := AVersion;
  // the record layer needs the version to classify an incoming change_cipher_spec (drop under
  // 1.3 vs reject out of window) before the next record after the peer's hello is pulled
  FRecordLayer.SetNegotiatedVersion(AVersion);
end;

procedure TTlsEngine.OnOcspStapleReceived(const AStaple: TBytes);
begin
  FInfo.PeerOcspStaple := AStaple;
end;

procedure TTlsEngine.OnPeerCertificateChain(const AChain, AValidatedPath: TArray<TBytes>);
begin
  FInfo.PeerCertificates := AChain;
  FInfo.ValidatedPath := AValidatedPath;
end;

procedure TTlsEngine.OnRequestedCertificateAuthorities(
  const AAuthorities: TArray<TBytes>);
begin
  FInfo.RequestedCertificateAuthorities := AAuthorities;
end;

procedure TTlsEngine.OnConnectionParams(ACipherSuite, ANamedGroup: UInt16;
  AResumed, AExtendedMasterSecret: Boolean; const AServerName: string);
begin
  FInfo.CipherSuite := ACipherSuite;
  FInfo.NamedGroup := ANamedGroup;
  FInfo.ServerName := AServerName;
  FInfo.Resumed := AResumed;
  FInfo.ExtendedMasterSecret := AExtendedMasterSecret;
end;

procedure TTlsEngine.OnCertificateVerdictNeeded(const AChain,
  AValidatedPath: TArray<TBytes>; const AHostName: string; const AStaple: TBytes);
begin
  // the built-in pipeline has already accepted this chain; surface it so a host can decide
  // out-of-band (augment-only). The conductor owns the park state (it sets AwaitingVerdict once
  // this flight's effects have been applied); the handshake makes no further progress until
  // SetCertificateVerdict resumes it. The park must not fire after completion.
{$IFDEF DEBUG}
  System.Assert(not FHandshakeComplete);
{$ENDIF DEBUG}
  Enqueue(TTlsEvents.MakeCertificateReceived(AChain, AValidatedPath, AHostName, AStaple));
end;

procedure TTlsEngine.OnHandshakeEstablished;
begin
  FHandshakeComplete := True;
  // a change_cipher_spec is no longer in its legal window once the handshake is done
  FRecordLayer.SetHandshakeComplete;
end;

procedure TTlsEngine.OnHandshakeFailed(AAlert: TTlsAlertDescription);
begin
  if FTerminal then
    Exit;
  FLastError := TTlsError.CreateFatal(AAlert, SLocalFatalAlert,
    TTlsErrorOrigin.Local);
  QueueAlertRecord(TTlsAlert.CreateFatal(AAlert));
  FTerminal := True;
end;

procedure TTlsEngine.OnWarningAlert(AAlert: TTlsAlertDescription);
begin
  // a warning alert does not tear down the connection; suppress it once the connection is
  // terminal or the write half was closed, so nothing is written after our close_notify
  if FTerminal or FSentClose then
    Exit;
  QueueAlertRecord(TTlsAlert.Create(TTlsAlertLevel.Warning, AAlert));
end;

procedure TTlsEngine.OnEchAccepted;
begin
  FInfo.EchStatus := TEchStatus.Accepted;
end;

procedure TTlsEngine.OnEchGreased;
begin
  FInfo.EchStatus := TEchStatus.Greased;
end;

procedure TTlsEngine.OnEchBackend;
begin
  FInfo.EchStatus := TEchStatus.Backend;
end;

procedure TTlsEngine.OnEchServerRejected;
begin
  // the server rejected ECH and completed to the public_name; record it, do not abort
  FInfo.EchStatus := TEchStatus.Rejected;
end;

procedure TTlsEngine.OnEchRejected(const ARetryConfigs: TBytes;
  AIsRetryAttempt: Boolean);
begin
  // the client completed its flight to the public_name; surface the reject (retry_configs
  // and the retry flag) then abort with ech_required - never a plaintext fall-back
  FInfo.EchStatus := TEchStatus.Rejected;
  FInfo.EchRetryConfigs := ARetryConfigs;
  FInfo.EchIsRetryAttempt := AIsRetryAttempt;
  FInfo.EchRejectAborted := True;
  OnHandshakeFailed(TTlsAlertDescription.EchRequired);
end;

end.
