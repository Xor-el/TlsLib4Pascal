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
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsVersion,
  TlpTlsContentType,
  TlpTlsLibExceptions,
  TlpTlsAlertProtocol,
  TlpAlertMapping,
  TlpICryptoProvider,
  TlpIRecordProtection,
  TlpRecordLayer,
  TlpITlsEngine,
  TlpITlsEventSink,
  TlpTlsEngineEvents,
  TlpIHandshakeChannel,
  TlpHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeDriver,
  TlpHandshakeConductor;

type
  /// <summary>
  /// The default sans-IO engine: a shell that plumbs the record layer and the
  /// alert protocol, with no handshake logic yet. It buffers inbound assembly, the
  /// outbound queue, decrypted application data, and the event queue, all as TBytes
  /// with explicit offset/length. Single-threaded: the caller serializes access.
  /// </summary>
  TTlsEngine = class sealed(TInterfacedObject, ITlsEngine, ITlsEventSource)
  strict private
  var
    FRecordLayer: TRecordLayer;
    FEvents: TQueue<ITlsEvent>;
    FSink: ITlsEventSink;
    FConductor: THandshakeConductor;
    FOutbound: TBytes;
    // decrypted application data waiting for the caller, as a queue of record-sized
    // chunks: FAppChunkHead/FAppBytePos is the read cursor, FAppAvail the unread total
    FAppChunks: TArray<TBytes>;
    FAppChunkHead: Int32;
    FAppBytePos: Int32;
    FAppAvail: Int32;
    FMaxAppReadBuffer: Int32;
    FTerminal: Boolean;
    FClosed: Boolean;
    FSentClose: Boolean;
    FHandshakeComplete: Boolean;
    /// <summary>Count of tolerated warning-level alerts received, bounded to guard against a
    /// peer flooding them (RFC 8446 6 leaves the level advisory but a flood is a DoS).</summary>
    FWarningAlertCount: Int32;
    // 0-RTT: a write protection is installed (early or later) and the early-data window is
    // still open until the outcome is known
    FWriteProtectionInstalled: Boolean;
    FEarlyDataClosed: Boolean;
    // 0-RTT outbound cap: the ticket's max_early_data budget, how much has gone out as
    // early data, and any overflow held back to send as 1-RTT once the handshake completes
    FEarlyDataLimit: Int32;
    FEarlyDataSent: Int32;
    FEarlyDataOverflow: TBytes;
    FNegotiatedAlpn: string;
    FNegotiatedVersion: TTlsVersion;
    FPeerOcspStaple: TBytes;
    FPeerCertificates: TArray<TBytes>;
    FRequestedCertificateAuthorities: TArray<TBytes>;
    FNegotiatedCipherSuite: UInt16;
    FNegotiatedGroup: UInt16;
    FPeerServerName: string;
    FIsResumed: Boolean;
    // async peer-certificate verdict: whether the handshake is parked awaiting a verdict,
    // and the advisory deadline the driver enforces (the engine owns no timer)
    FAwaitingVerdict: Boolean;
    FAsyncVerdictDeadlineMs: Cardinal;
    FLastError: TTlsError;
    procedure Enqueue(const AEvent: ITlsEvent);
    procedure PullOutbound;
    procedure QueueAlertRecord(const AAlert: TTlsAlert);
    procedure AppendAppData(const AData: TBytes);
    function AppReadAvailable: Int32;
    procedure HandleIncomingAlert(const AData: TBytes);
    procedure RouteFragment(const AFragment: TTlsRecordFragment);
    procedure DrainRecordLayer;
    function Fail(const AException: Exception): TTlsOutcome;
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    /// Creates an engine and wires its handshake in one exception-safe step, returning
    /// it as an ITlsEngine, so callers do not repeat the create-then-configure sequence
    /// and ConfigureHandshake stays off the public ITlsEngine surface.
    /// </summary>
    class function CreateConfigured(const AInitialMachine: IHandshakeMachine;
      const AProvider: ICryptoProvider;
      AAsyncVerdictDeadlineMs: Cardinal = 0): ITlsEngine; static;

    /// <summary>
    /// Wires the handshake: builds the channel over this engine's record layer and a
    /// driver that installs epochs and reports outcomes back here, then holds the
    /// resulting conductor. The initial state selects the role (a client or server
    /// graph). Call once, before StartHandshake.
    /// </summary>
    procedure ConfigureHandshake(const AInitialMachine: IHandshakeMachine;
      const AProvider: ICryptoProvider; AAsyncVerdictDeadlineMs: Cardinal = 0);

    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    procedure WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32);
    procedure RequestKeyUpdate(ARequestPeerUpdate: Boolean);
    procedure SendClose;
    procedure SendAlert(ADescription: TTlsAlertDescription);
    procedure StartHandshake;
    procedure SetCertificateVerdict(AAccept: Boolean;
      AAlert: TTlsAlertDescription = TTlsAlertDescription.BadCertificate);
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingAppData: Int32;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    function WantsRead: Boolean;
    function WantsWrite: Boolean;
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function AsyncCertificateVerdictDeadlineMs: Cardinal;
    function IsTerminal: Boolean;
    function IsInboundClosed: Boolean;
    function WriteClosed: Boolean;
    function LastError: TTlsError;
    function NegotiatedVersion: TTlsVersion;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
    function NegotiatedAlpnProtocol: string;
    function PeerOcspStaple: TBytes;
    function PeerCertificates: TArray<TBytes>;
    function RequestedCertificateAuthorities: TArray<TBytes>;
    function NegotiatedCipherSuite: UInt16;
    function NegotiatedGroup: UInt16;
    function PeerServerName: string;
    function IsResumed: Boolean;

    // installer + sink operations the handshake bridge forwards to (the engine no
    // longer implements those interfaces directly - see the bridge below)
    procedure InstallReadProtection(const AProtection: IRecordProtection);
    procedure InstallWriteProtection(const AProtection: IRecordProtection);
    procedure RevertWriteToPlaintext;
    procedure SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext: Int32);
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    procedure SetEarlyReadEpoch(AActive: Boolean);
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: string);
    procedure OnVersionNegotiated(const AVersion: TTlsVersion);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnCertificateVerdictNeeded(const AChain: TArray<TBytes>;
      const AHostName: string);
    procedure OnPeerCertificateChain(const AChain: TArray<TBytes>);
    procedure OnRequestedCertificateAuthorities(const AAuthorities: TArray<TBytes>);
    procedure OnConnectionParams(ACipherSuite, ANamedGroup: UInt16; AResumed: Boolean;
      const AServerName: string);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
    // ITlsEventSource
    procedure SetEventSink(const ASink: ITlsEventSink);
  end;

implementation

const
  DefaultMaxAppReadBuffer = Int32(1 shl 20); // 1 MiB advisory backpressure threshold
  // the number of warning-level alerts tolerated before a flood is refused; the next one
  // aborts the connection (RFC 8446 6 leaves the level advisory, but a flood is a DoS)
  MaxWarningAlerts = Int32(4);

resourcestring
  SHandshakeNotConfigured = 'no handshake was configured on this engine';
  SHandshakeAlreadyConfigured = 'a handshake was already configured on this engine';
  SPeerFatalAlert = 'the peer sent a fatal alert';
  SWarningAlertInTls13 = 'a warning alert other than user_canceled is not permitted in TLS 1.3';
  STooManyWarningAlerts = 'the peer sent too many warning-level alerts';
  SBogusAlertLevel = 'the alert carries a level that is neither warning nor fatal';
  SLocalFatalAlert = 'a fatal alert was sent';
  SAppReadBufferFull =
    'unread application data would exceed the read-buffer limit (honor WantsRead)';

type
  /// <summary>
  /// A non-refcounting adapter that lets the handshake driver install epochs and
  /// report outcomes back to the engine. The engine (through its conductor) owns
  /// this bridge, so it holds the engine by a raw reference - taking a counted
  /// interface reference here would be an ownership cycle that leaks the engine.
  /// </summary>
  TEngineHandshakeBridge = class sealed(TInterfacedObject, IRecordEpochInstaller,
    IHandshakeSink, IHandshakeVersionSink, IHandshakeVerdictSink,
    IHandshakeConnectionInfoSink)
  strict private
  var
    FEngine: TTlsEngine;
  public
    constructor Create(const AEngine: TTlsEngine);
    procedure InstallReadProtection(const AProtection: IRecordProtection);
    procedure InstallWriteProtection(const AProtection: IRecordProtection);
    procedure RevertWriteToPlaintext;
    procedure SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext: Int32);
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    procedure SetEarlyReadEpoch(AActive: Boolean);
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: string);
    procedure OnVersionNegotiated(const AVersion: TTlsVersion);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnCertificateVerdictNeeded(const AChain: TArray<TBytes>;
      const AHostName: string);
    procedure OnPeerCertificateChain(const AChain: TArray<TBytes>);
    procedure OnRequestedCertificateAuthorities(const AAuthorities: TArray<TBytes>);
    procedure OnConnectionParams(ACipherSuite, ANamedGroup: UInt16; AResumed: Boolean;
      const AServerName: string);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
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
  const AProtection: IRecordProtection);
begin
  FEngine.InstallWriteProtection(AProtection);
end;

procedure TEngineHandshakeBridge.RevertWriteToPlaintext;
begin
  FEngine.RevertWriteToPlaintext;
end;

procedure TEngineHandshakeBridge.SetRecordSizeLimit(AOutboundPlaintext,
  AInboundPlaintext: Int32);
begin
  FEngine.SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext);
end;

procedure TEngineHandshakeBridge.SetEarlyDataSkip(AMaxBytes: Int32);
begin
  FEngine.SetEarlyDataSkip(AMaxBytes);
end;

procedure TEngineHandshakeBridge.SetEarlyDataLimit(AMaxBytes: Int32);
begin
  FEngine.SetEarlyDataLimit(AMaxBytes);
end;

procedure TEngineHandshakeBridge.SetEarlyReadEpoch(AActive: Boolean);
begin
  FEngine.SetEarlyReadEpoch(AActive);
end;

procedure TEngineHandshakeBridge.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  FEngine.OnHandshakeEvent(AEvent);
end;

procedure TEngineHandshakeBridge.OnAlpnSelected(const AProtocol: string);
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
  const AChain: TArray<TBytes>; const AHostName: string);
begin
  FEngine.OnCertificateVerdictNeeded(AChain, AHostName);
end;

procedure TEngineHandshakeBridge.OnPeerCertificateChain(
  const AChain: TArray<TBytes>);
begin
  FEngine.OnPeerCertificateChain(AChain);
end;

procedure TEngineHandshakeBridge.OnRequestedCertificateAuthorities(
  const AAuthorities: TArray<TBytes>);
begin
  FEngine.OnRequestedCertificateAuthorities(AAuthorities);
end;

procedure TEngineHandshakeBridge.OnConnectionParams(ACipherSuite,
  ANamedGroup: UInt16; AResumed: Boolean; const AServerName: string);
begin
  FEngine.OnConnectionParams(ACipherSuite, ANamedGroup, AResumed, AServerName);
end;

procedure TEngineHandshakeBridge.OnHandshakeEstablished;
begin
  FEngine.OnHandshakeEstablished;
end;

procedure TEngineHandshakeBridge.OnHandshakeFailed(AAlert: TTlsAlertDescription);
begin
  FEngine.OnHandshakeFailed(AAlert);
end;

{ TTlsEngine }

constructor TTlsEngine.Create;
begin
  inherited Create;
  FRecordLayer := TRecordLayer.Create;
  FEvents := TQueue<ITlsEvent>.Create;
  FConductor := nil;
  FMaxAppReadBuffer := DefaultMaxAppReadBuffer;
  FAppChunkHead := 0;
  FAppBytePos := 0;
  FAppAvail := 0;
  FTerminal := False;
  FClosed := False;
  FSentClose := False;
  FHandshakeComplete := False;
  FWarningAlertCount := 0;
  FAwaitingVerdict := False;
  FAsyncVerdictDeadlineMs := 0;
  FNegotiatedCipherSuite := 0;
  FNegotiatedGroup := 0;
  FPeerServerName := '';
  FIsResumed := False;
  FNegotiatedAlpn := '';
  // a zero wire code until an epoch's keys name the negotiated version
  FNegotiatedVersion := TTlsVersion.Create(0);
  FLastError := TTlsError.CreateFatal(TTlsAlertDescription.InternalError, '');
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
  const AProvider: ICryptoProvider;
  AAsyncVerdictDeadlineMs: Cardinal): ITlsEngine;
var
  LEngine: TTlsEngine;
begin
  LEngine := TTlsEngine.Create;
  Result := LEngine; // assign the interface result before the fallible ConfigureHandshake
  LEngine.ConfigureHandshake(AInitialMachine, AProvider, AAsyncVerdictDeadlineMs);
end;

procedure TTlsEngine.ConfigureHandshake(const AInitialMachine: IHandshakeMachine;
  const AProvider: ICryptoProvider; AAsyncVerdictDeadlineMs: Cardinal);
var
  LChannel: IHandshakeChannel;
  LBridge: TEngineHandshakeBridge;
  LDriver: THandshakeDriver;
begin
  if FConductor <> nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeAlreadyConfigured);
  FAsyncVerdictDeadlineMs := AAsyncVerdictDeadlineMs;
  // a real handshake enforces the TLS record-phase rules: a cleartext application_data record
  // (before any read epoch key) is unexpected (RFC 8446 5.1)
  FRecordLayer.StrictApplicationData := True;
  // a client stamps its initial ClientHello record with legacy_record_version 0x0301 for
  // backward compatibility before the negotiated version is known (RFC 8446 5.1)
  if AInitialMachine.Initiates then
    FRecordLayer.UseClientInitialRecordVersion;
  LChannel := THandshakeChannel.Create(FRecordLayer) as IHandshakeChannel;
  LBridge := TEngineHandshakeBridge.Create(Self);
  LDriver := THandshakeDriver.Create(LChannel, LBridge as IRecordEpochInstaller,
    AProvider, LBridge as IHandshakeSink);
  FConductor := THandshakeConductor.Create(LChannel, LDriver, AInitialMachine);
end;

procedure TTlsEngine.Enqueue(const AEvent: ITlsEvent);
begin
  FEvents.Enqueue(AEvent);
  if FSink <> nil then
    FSink.OnEvent(AEvent);
end;

procedure TTlsEngine.PullOutbound;
begin
  FOutbound := TArrayUtilities.Concat(FOutbound, FRecordLayer.TakeOutgoing);
end;

procedure TTlsEngine.QueueAlertRecord(const AAlert: TTlsAlert);
var
  LBytes: TBytes;
begin
  LBytes := TTlsAlertProtocol.Encode(AAlert);
  FRecordLayer.Write(TTlsContentType.Alert, LBytes, 0, System.Length(LBytes));
  PullOutbound;
end;

procedure TTlsEngine.AppendAppData(const AData: TBytes);
begin
  if System.Length(AData) = 0 then
    Exit;
  // bound the buffer: a caller that ignores WantsRead cannot grow it without limit
  if Int64(FAppAvail) + System.Length(AData) > FMaxAppReadBuffer then
    raise EInvalidOperationTlsLibException.CreateRes(@SAppReadBufferFull);
  // drop any fully-consumed chunks at the front (bounds the queue; copies only the
  // few live chunk references, never the payload bytes)
  if FAppChunkHead > 0 then
  begin
    FAppChunks := System.Copy(FAppChunks, FAppChunkHead,
      System.Length(FAppChunks) - FAppChunkHead);
    FAppChunkHead := 0;
  end;
  // enqueue the record's bytes by reference - no O(n^2) recopy of the buffer
  TArrayUtilities.Append<TBytes>(FAppChunks, AData);
  Inc(FAppAvail, System.Length(AData));
end;

function TTlsEngine.AppReadAvailable: Int32;
begin
  Result := FAppAvail;
end;

procedure TTlsEngine.HandleIncomingAlert(const AData: TBytes);
var
  LReceived: TReceivedAlert;
begin
  LReceived := TTlsAlertProtocol.Decode(AData, 0, System.Length(AData));
  if LReceived.IsCloseNotify then
  begin
    FClosed := True;
    Enqueue(TTlsEvents.MakeClosed);
    Exit;
  end;
  // a warning-level alert is advisory: tolerated in TLS 1.2 (RFC 5246 7.2) and, in TLS 1.3,
  // only for user_canceled - every other warning is outlawed there (RFC 8446 6). Either way a
  // flood is refused. close_notify is handled above regardless of level.
  if LReceived.LevelByte = TTlsAlertLevel.Warning.ToByte then
  begin
    if (FNegotiatedVersion.WireValue = TlsWireVersionTls13) and
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
  // a level that is neither warning nor fatal is malformed on the wire (RFC 5246 7.2)
  if not LReceived.IsFatalLevel then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBogusAlertLevel);
  // a fatal alert is terminal
  Enqueue(TTlsEvents.MakePeerAlert(LReceived));
  FTerminal := True;
  if LReceived.HasKnownDescription then
    FLastError := TTlsError.CreateFatal(LReceived.Description, SPeerFatalAlert)
  else
    FLastError := TTlsError.CreateFatal(TTlsAlertDescription.InternalError,
      SPeerFatalAlert);
end;

procedure TTlsEngine.RouteFragment(const AFragment: TTlsRecordFragment);
begin
  // once terminal (fatal alert) or closed (inbound close_notify) nothing further is
  // routed: post-close records must not become app-readable nor overwrite FLastError
  if FTerminal or FClosed then
    Exit;
  case AFragment.ContentType of
    TTlsContentType.ApplicationData:
      begin
        // genuine traffic resets the peer's post-handshake message flood counter
        if FConductor <> nil then
          FConductor.NoteApplicationData;
        AppendAppData(AFragment.Data);
        Enqueue(TTlsEvents.MakeAppData);
      end;
    TTlsContentType.Handshake:
      // a configured handshake consumes the fragment and drives its state machine;
      // otherwise it surfaces as an event for a caller-supplied handshake layer
      if FConductor <> nil then
        FConductor.DeliverHandshake(AFragment.Data, 0, System.Length(AFragment.Data))
      else
        Enqueue(TTlsEvents.MakeHandshakeFragment(AFragment.Data));
    TTlsContentType.Alert:
      HandleIncomingAlert(AFragment.Data);
    // change_cipher_spec is dropped in the record layer; nothing else reaches here
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
  if FAwaitingVerdict then
    Exit;
  // stop pulling the moment the connection becomes terminal/closed (e.g. a fatal alert or
  // close_notify coalesced ahead of app-data): the trailing record stays framed, undecrypted
  while (not (FTerminal or FClosed)) and FRecordLayer.NextIncoming(LFragment) do
  begin
    RouteFragment(LFragment);
    if FAwaitingVerdict then
      Break;
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
  if FTerminal then
    Exit(TTlsOutcome.Fatal);
  try
    FRecordLayer.ProcessInput(AWire, AOffset, ALength);
    DrainRecordLayer;
    // a driven handshake may have written a response flight into the record layer
    PullOutbound;
  except
    on E: Exception do
      Exit(Fail(E));
  end;
  if FTerminal then // a received fatal alert or a handshake failure
    Exit(TTlsOutcome.Fatal);
  if (AppReadAvailable > 0) or (FEvents.Count > 0) or (System.Length(FOutbound) > 0) then
    Result := TTlsOutcome.Advanced
  else
    Result := TTlsOutcome.NeedMoreInput;
end;

procedure TTlsEngine.Write(const AData: TBytes; AOffset, ALength: Int32);
begin
  if FTerminal or FClosed or FSentClose then
    Exit;
  // a KeyUpdate owed to a peer update_requested must precede our next application data
  // (RFC 8446 4.6.3); flushing here coalesces repeats into one response before the write
  if (FConductor <> nil) and FHandshakeComplete then
    FConductor.FlushPendingKeyUpdate;
  FRecordLayer.Write(TTlsContentType.ApplicationData, AData, AOffset, ALength);
  PullOutbound;
end;

procedure TTlsEngine.WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32);
var
  LAccept: Int32;
begin
  // only in the open early-data window: handshaking, a (early) write epoch installed,
  // and the client has not yet ended early data
  if FTerminal or FClosed or FSentClose or FHandshakeComplete or FEarlyDataClosed or
    (not FWriteProtectionInstalled) or (ALength <= 0) then
    Exit;
  // cap outbound 0-RTT at the ticket's max_early_data (RFC 8446 4.2.10): send at most the
  // remaining budget as early data; anything beyond is deferred to 1-RTT after the handshake
  LAccept := FEarlyDataLimit - FEarlyDataSent;
  if LAccept > ALength then
    LAccept := ALength;
  if LAccept > 0 then
  begin
    FRecordLayer.Write(TTlsContentType.ApplicationData, AData, AOffset, LAccept);
    Inc(FEarlyDataSent, LAccept);
  end;
  // hold the over-budget remainder; it is sent as 1-RTT once the handshake completes
  if LAccept < ALength then
    FEarlyDataOverflow := TArrayUtilities.Concat(FEarlyDataOverflow,
      System.Copy(AData, AOffset + LAccept, ALength - LAccept));
  PullOutbound;
end;

procedure TTlsEngine.RequestKeyUpdate(ARequestPeerUpdate: Boolean);
begin
  // post-handshake only, over an established connection with a live handshake machine
  // (TLS 1.2 machines make this a no-op); the KeyUpdate is protected and queued outbound
  if FTerminal or FClosed or FSentClose or (not FHandshakeComplete) or
    (FConductor = nil) then
    Exit;
  FConductor.RequestKeyUpdate(ARequestPeerUpdate);
  PullOutbound;
end;

function TTlsEngine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  // exported keying material is defined only once the handshake has installed the
  // connection secrets; before then there is nothing to export
  if (not FHandshakeComplete) or (FConductor = nil) then
    Exit(nil);
  Result := FConductor.ExportKeyingMaterial(ALabel, AContext, AUseContext, ALength);
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
  FLastError := TTlsError.CreateFatal(ADescription, SLocalFatalAlert);
end;

procedure TTlsEngine.StartHandshake;
begin
  if FConductor = nil then
    raise ENotSupportedTlsLibException.CreateRes(@SHandshakeNotConfigured);
  FConductor.Start;
  PullOutbound;
end;

procedure TTlsEngine.SetCertificateVerdict(AAccept: Boolean;
  AAlert: TTlsAlertDescription);
begin
  // a no-op unless the handshake is actually parked on a verdict (idempotent, safe to call)
  if not FAwaitingVerdict then
    Exit;
  FAwaitingVerdict := False;
  // reject aborts fail-closed (the conductor emits AAlert, making the engine terminal);
  // accept drains the buffered flight and completes the handshake
  FConductor.ResolveCertificateVerdict(AAccept, AAlert);
  // with the park cleared, resume pulling the framed remainder of the flight that was held
  // back while parked, so each record decrypts under the epoch installed by the record
  // before it (the Finished installs the application read epoch ahead of any app data)
  if not FTerminal then
    DrainRecordLayer;
  PullOutbound;
end;

function TTlsEngine.TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
var
  LCapacity: Int32;
begin
  PullOutbound;
  LCapacity := System.Length(ADest) - ADestOffset;
  if (ADestOffset < 0) or (LCapacity <= 0) then
    Exit(0);
  Result := System.Length(FOutbound);
  if Result > LCapacity then
    Result := LCapacity;
  if Result > 0 then
  begin
    Move(FOutbound[0], ADest[ADestOffset], Result);
    FOutbound := System.Copy(FOutbound, Result, System.Length(FOutbound) - Result);
  end;
end;

function TTlsEngine.ReadAppData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
var
  LCapacity, LWant, LDest, LInChunk, LTake: Int32;
begin
  LCapacity := System.Length(ADest) - ADestOffset;
  if (ADestOffset < 0) or (LCapacity <= 0) or (AMaxLength <= 0) then
    Exit(0);
  LWant := FAppAvail;
  if LWant > AMaxLength then
    LWant := AMaxLength;
  if LWant > LCapacity then
    LWant := LCapacity;
  if LWant <= 0 then
    Exit(0);
  Result := LWant;
  LDest := ADestOffset;
  // copy across chunk boundaries, retiring each head chunk as it drains
  while LWant > 0 do
  begin
    LInChunk := System.Length(FAppChunks[FAppChunkHead]) - FAppBytePos;
    LTake := LWant;
    if LTake > LInChunk then
      LTake := LInChunk;
    Move(FAppChunks[FAppChunkHead][FAppBytePos], ADest[LDest], LTake);
    Inc(FAppBytePos, LTake);
    Inc(LDest, LTake);
    Dec(LWant, LTake);
    Dec(FAppAvail, LTake);
    if FAppBytePos >= System.Length(FAppChunks[FAppChunkHead]) then
    begin
      FAppChunks[FAppChunkHead] := nil; // release the consumed chunk
      Inc(FAppChunkHead);
      FAppBytePos := 0;
    end;
  end;
  if FAppAvail = 0 then // fully drained: reset the queue
  begin
    FAppChunks := nil;
    FAppChunkHead := 0;
    FAppBytePos := 0;
  end;
end;

function TTlsEngine.PendingAppData: Int32;
begin
  Result := FAppAvail;
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
    (AppReadAvailable < FMaxAppReadBuffer);
end;

function TTlsEngine.WantsWrite: Boolean;
begin
  Result := System.Length(FOutbound) > 0;
end;

function TTlsEngine.IsHandshaking: Boolean;
begin
  Result := (not FTerminal) and (not FHandshakeComplete);
end;

function TTlsEngine.AwaitingCertificateVerdict: Boolean;
begin
  Result := FAwaitingVerdict;
end;

function TTlsEngine.AsyncCertificateVerdictDeadlineMs: Cardinal;
begin
  Result := FAsyncVerdictDeadlineMs;
end;

function TTlsEngine.IsTerminal: Boolean;
begin
  Result := FTerminal;
end;

function TTlsEngine.IsInboundClosed: Boolean;
begin
  Result := FClosed;
end;

function TTlsEngine.WriteClosed: Boolean;
begin
  // mirrors the guard in Write: these three states each silently drop outbound app data
  Result := FTerminal or FClosed or FSentClose;
end;

function TTlsEngine.LastError: TTlsError;
begin
  Result := FLastError;
end;

function TTlsEngine.NegotiatedVersion: TTlsVersion;
begin
  Result := FNegotiatedVersion;
end;

function TTlsEngine.NegotiatedAlpnProtocol: string;
begin
  Result := FNegotiatedAlpn;
end;

function TTlsEngine.PeerOcspStaple: TBytes;
begin
  Result := FPeerOcspStaple;
end;

function TTlsEngine.PeerCertificates: TArray<TBytes>;
begin
  Result := FPeerCertificates;
end;

function TTlsEngine.RequestedCertificateAuthorities: TArray<TBytes>;
begin
  Result := FRequestedCertificateAuthorities;
end;

function TTlsEngine.NegotiatedCipherSuite: UInt16;
begin
  Result := FNegotiatedCipherSuite;
end;

function TTlsEngine.NegotiatedGroup: UInt16;
begin
  Result := FNegotiatedGroup;
end;

function TTlsEngine.PeerServerName: string;
begin
  Result := FPeerServerName;
end;

function TTlsEngine.IsResumed: Boolean;
begin
  Result := FIsResumed;
end;

procedure TTlsEngine.InstallReadProtection(const AProtection: IRecordProtection);
begin
  FRecordLayer.SetReadProtection(AProtection);
  Enqueue(TTlsEvents.MakeKeysInstalled);
end;

procedure TTlsEngine.InstallWriteProtection(const AProtection: IRecordProtection);
begin
  // installing write keys no longer means the handshake is done: in TLS 1.3 the
  // write side moves to the handshake epoch mid-flight. Completion is signalled by
  // the state machine through OnHandshakeEstablished.
  FRecordLayer.SetWriteProtection(AProtection);
  FWriteProtectionInstalled := True; // 0-RTT: the early-data write window can open
  Enqueue(TTlsEvents.MakeKeysInstalled);
end;

procedure TTlsEngine.RevertWriteToPlaintext;
begin
  // a HelloRetryRequest rejected the offered 0-RTT: drop the early-data write epoch back to
  // plaintext so the second ClientHello onward goes out in the clear (RFC 8446 4.2.10). No
  // keys-installed event - this is a downgrade of the write epoch, not a new epoch.
  FRecordLayer.RevertWriteToPlaintext;
end;

procedure TTlsEngine.SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext: Int32);
begin
  FRecordLayer.SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext);
end;

procedure TTlsEngine.SetEarlyDataSkip(AMaxBytes: Int32);
begin
  FRecordLayer.SetEarlyDataSkip(AMaxBytes);
end;

procedure TTlsEngine.SetEarlyDataLimit(AMaxBytes: Int32);
begin
  FEarlyDataLimit := AMaxBytes;
end;

procedure TTlsEngine.SetEarlyReadEpoch(AActive: Boolean);
begin
  FRecordLayer.SetEarlyReadAccepted(AActive);
end;

procedure TTlsEngine.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  // manage the client's early-data buffer as the outcome becomes known
  case AEvent of
    TTlsEventKind.EarlyDataAccepted:
      // the early data was delivered under the 0-RTT keys; nothing more to do
      FEarlyDataClosed := True;
    TTlsEventKind.EarlyDataRejected:
      // the early data already went out under the early keys; on a reject it is discarded,
      // not retransmitted as 1-RTT (RFC 8446 2.3 leaves any resend to the application, as
      // rustls does). Only the over-budget remainder that never fit in the 0-RTT window
      // (FEarlyDataOverflow) still follows as ordinary application data.
      FEarlyDataClosed := True;
  end;
  Enqueue(TTlsEvents.MakeSimple(AEvent));
end;

procedure TTlsEngine.OnAlpnSelected(const AProtocol: string);
begin
  FNegotiatedAlpn := AProtocol;
end;

procedure TTlsEngine.OnVersionNegotiated(const AVersion: TTlsVersion);
begin
  FNegotiatedVersion := AVersion;
end;

procedure TTlsEngine.OnOcspStapleReceived(const AStaple: TBytes);
begin
  FPeerOcspStaple := AStaple;
end;

procedure TTlsEngine.OnPeerCertificateChain(const AChain: TArray<TBytes>);
begin
  FPeerCertificates := AChain;
end;

procedure TTlsEngine.OnRequestedCertificateAuthorities(
  const AAuthorities: TArray<TBytes>);
begin
  FRequestedCertificateAuthorities := AAuthorities;
end;

procedure TTlsEngine.OnConnectionParams(ACipherSuite, ANamedGroup: UInt16;
  AResumed: Boolean; const AServerName: string);
begin
  FNegotiatedCipherSuite := ACipherSuite;
  FNegotiatedGroup := ANamedGroup;
  FPeerServerName := AServerName;
  FIsResumed := AResumed;
end;

procedure TTlsEngine.OnCertificateVerdictNeeded(const AChain: TArray<TBytes>;
  const AHostName: string);
begin
  // the built-in pipeline has already accepted this chain; park and surface it so a host can
  // decide out-of-band (augment-only). The handshake makes no further progress until
  // SetCertificateVerdict resumes it.
  FAwaitingVerdict := True;
  Enqueue(TTlsEvents.MakeCertificateReceived(AChain, AHostName));
end;

procedure TTlsEngine.OnHandshakeEstablished;
var
  LFlushed: Boolean;
begin
  FHandshakeComplete := True;
  // a change_cipher_spec is no longer in its legal window once the handshake is done
  FRecordLayer.SetHandshakeComplete;
  LFlushed := False;
  // flush any over-budget early data held back by the max_early_data cap; it never went out
  // as 0-RTT, so it follows as ordinary 1-RTT application data
  if System.Length(FEarlyDataOverflow) > 0 then
  begin
    FRecordLayer.Write(TTlsContentType.ApplicationData, FEarlyDataOverflow, 0,
      System.Length(FEarlyDataOverflow));
    FEarlyDataOverflow := nil;
    LFlushed := True;
  end;
  if LFlushed then
    PullOutbound;
end;

procedure TTlsEngine.OnHandshakeFailed(AAlert: TTlsAlertDescription);
begin
  if FTerminal then
    Exit;
  FLastError := TTlsError.CreateFatal(AAlert, SLocalFatalAlert);
  QueueAlertRecord(TTlsAlert.CreateFatal(AAlert));
  FTerminal := True;
end;

procedure TTlsEngine.SetEventSink(const ASink: ITlsEventSink);
begin
  FSink := ASink;
end;

end.
