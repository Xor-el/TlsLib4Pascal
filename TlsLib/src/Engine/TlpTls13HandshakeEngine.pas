{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls13HandshakeEngine;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsLibExceptions,
  TlpAlertMapping,
  TlpIKeySchedule,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpITls13HandshakeEngine,
  TlpTls13HandshakeOutput,
  TlpIHandshakeChannel,
  TlpIHandshakeMachine,
  TlpLeveledHandshakeChannel,
  TlpHandshakeDriver,
  TlpHandshakeConductor,
  TlpEngineOutcome,
  TlpITlsHostExtension,
  TlpISessionApplicationData;

type
  /// <summary>
  /// The TLS 1.3 handshake-only engine: a handshake machine driven over a leveled channel, so the
  /// host that owns record protection exchanges handshake bytes and traffic secrets per level.
  /// The machine must be built for a host that owns record protection; the factory does that.
  /// </summary>
  TTls13HandshakeEngine = class sealed(TInterfacedObject, ITls13HandshakeEngine,
    ITlsCommonEngine, ITlsHostExtensionResults, ITlsSessionApplicationData)
  strict private
  var
    FChannel: TLeveledHandshakeChannel;
    FChannelRef: IHandshakeChannel;
    FOutcome: TEngineOutcome;
    FOutcomeRef: IHandshakeSink;
    FConductor: THandshakeConductor;
    FHostResults: ITlsHostExtensionResults;
    FSessionData: ITlsSessionApplicationData;
    // set while a step runs: a callback that re-enters the engine fails loud
    FDraining: Boolean;
    FStarted: Boolean;
    FCompleteQueued: Boolean;
    FSettled: Boolean;
    // each is answered by the object the factory shares with the machine; nil is not answered
    property HostResults: ITlsHostExtensionResults read FHostResults
      implements ITlsHostExtensionResults;
    property SessionData: ITlsSessionApplicationData read FSessionData
      implements ITlsSessionApplicationData;
    /// <summary>After any handshake step: on a failure drops the sessions it stored or minted
    /// (once), and on completion queues the end of the handshake after the step's outputs.</summary>
    procedure Settle;
  public
    /// <summary>Wires the machine over a leveled channel. The machine is built for a host that
    /// owns record protection; a nil AHostResults or ASessionData is not answered.</summary>
    constructor Create(const AMachine: IHandshakeMachine;
      AMaxCertificateMessageLength: Int32; const AHostResults: ITlsHostExtensionResults;
      const ASessionData: ITlsSessionApplicationData);
    destructor Destroy; override;

    procedure StartHandshake;
    function ProvideHandshakeData(ALevel: TTlsEpoch; const AData: TBytes;
      AOffset, ALength: Int32): TTlsOutcome;
    function NextOutput(out AOutput: TTls13HandshakeOutput): Boolean;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);
    procedure LatchTransportFailure(const AReason: string);
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function IsTerminal: Boolean;
    function LastError: TTlsError;
    function ConnectionInfo: TTlsConnectionInfo;
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
  end;

implementation

resourcestring
  SReentrantEngineCall =
    'the engine was re-entered from within a handshake callback; it is single-threaded and a ' +
    'callback must not call back into it';
  SHandshakeAlreadyStarted = 'StartHandshake was already called on this engine';
  SProvideSliceOutOfRange = 'the ProvideHandshakeData (offset, length) slice is out of range';
  SWrongInputLevel = 'handshake data arrived at a level other than the one being read';

{ TTls13HandshakeEngine }

constructor TTls13HandshakeEngine.Create(const AMachine: IHandshakeMachine;
  AMaxCertificateMessageLength: Int32; const AHostResults: ITlsHostExtensionResults;
  const ASessionData: ITlsSessionApplicationData);
var
  LDriver: THandshakeDriver;
begin
  inherited Create;
  FHostResults := AHostResults;
  FSessionData := ASessionData;
  FChannel := TLeveledHandshakeChannel.Create(AMaxCertificateMessageLength);
  FChannelRef := FChannel as IHandshakeChannel;
  FOutcome := TEngineOutcome.Create;
  FOutcomeRef := FOutcome as IHandshakeSink;
  LDriver := THandshakeDriver.Create(FChannelRef, FChannelRef as IEpochKeyInstaller,
    FOutcomeRef);
  FConductor := THandshakeConductor.Create(FChannelRef, LDriver, AMachine);
end;

destructor TTls13HandshakeEngine.Destroy;
begin
  // the conductor owns the driver, which holds the channel and the outcome
  FConductor.Free;
  inherited Destroy;
end;

procedure TTls13HandshakeEngine.Settle;
var
  LKeep, LI: Int32;
begin
  if FOutcome.IsTerminal then
  begin
    // an alert follows what the machine had produced, as on a record engine, under the write keys
    // installed by then; of the rest only those keys outlive the failure
    LKeep := -1;
    if FOutcome.LastError.Origin = TTlsErrorOrigin.Local then
      for LI := FChannel.Queue.Count - 1 downto 0 do
        if FChannel.Queue[LI].Kind = TTls13HandshakeOutputKind.HandshakeData then
        begin
          LKeep := LI;
          Break;
        end;
    for LI := FChannel.Queue.Count - 1 downto 0 do
      if (FOutcome.LastError.Origin <> TTlsErrorOrigin.Local) or
        ((LI > LKeep) and (FChannel.Queue[LI].Kind <> TTls13HandshakeOutputKind.WriteSecret)) then
        FChannel.Queue.Delete(LI);
    if not FSettled then
    begin
      FSettled := True;
      try
        FConductor.ForgetSessionsOnFatal;
      except
        // a failing session store must not mask the failure that already ended the connection
      end;
    end;
    Exit;
  end;
  if FOutcome.IsEstablished and not FCompleteQueued then
  begin
    FCompleteQueued := True;
    FChannel.Enqueue(TTls13HandshakeOutputKind.HandshakeComplete, FChannel.WriteLevel, nil);
  end;
end;

procedure TTls13HandshakeEngine.StartHandshake;
begin
  if FOutcome.IsTerminal then
    Exit;
  if FDraining then
    raise EInvalidOperationTlsLibException.CreateRes(@SReentrantEngineCall);
  if FStarted then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeAlreadyStarted);
  FStarted := True;
  FDraining := True;
  try
    try
      FConductor.Start;
    except
      on E: Exception do
        FOutcome.Fail(TAlertMapping.ErrorFor(E));
    end;
  finally
    FDraining := False;
  end;
  Settle;
end;

function TTls13HandshakeEngine.ProvideHandshakeData(ALevel: TTlsEpoch;
  const AData: TBytes; AOffset, ALength: Int32): TTlsOutcome;
begin
  if FDraining then
    raise EInvalidOperationTlsLibException.CreateRes(@SReentrantEngineCall);
  // an out-of-range slice is caller misuse, not a peer fault
  if (AOffset < 0) or (ALength < 0) or (Int64(AOffset) + ALength > System.Length(AData)) then
    raise EArgumentTlsLibException.CreateRes(@SProvideSliceOutOfRange);
  if FOutcome.IsTerminal then
    Exit(TTlsOutcome.Fatal);
  if ALevel <> FChannel.ReadLevel then
  begin
    FOutcome.OnHandshakeFailed(TTlsAlertDescription.UnexpectedMessage, SWrongInputLevel);
    Settle;
    Exit(TTlsOutcome.Fatal);
  end;
  FDraining := True;
  try
    try
      // the host carries application data itself, so the flood count restarts with each delivery
      FConductor.NoteApplicationData;
      FConductor.DeliverHandshake(AData, AOffset, ALength);
    except
      on E: Exception do
        FOutcome.Fail(TAlertMapping.ErrorFor(E));
    end;
  finally
    FDraining := False;
  end;
  Settle;
  if FOutcome.IsTerminal then
    Exit(TTlsOutcome.Fatal);
  if (FOutcome.Events.Count > 0) or (FChannel.Queue.Count > 0) then
    Exit(TTlsOutcome.Advanced);
  Result := TTlsOutcome.NeedMoreInput;
end;

function TTls13HandshakeEngine.NextOutput(out AOutput: TTls13HandshakeOutput): Boolean;
begin
  AOutput := Default(TTls13HandshakeOutput);
  Result := FChannel.TryTake(AOutput);
end;

function TTls13HandshakeEngine.NextEvent(out AEvent: ITlsEvent): Boolean;
begin
  Result := FOutcome.NextEvent(AEvent);
end;

procedure TTls13HandshakeEngine.SetCertificateVerdict(AAccept: Boolean;
  AAlert: TTlsAlertDescription);
begin
  if FDraining then
    raise EInvalidOperationTlsLibException.CreateRes(@SReentrantEngineCall);
  // a no-op unless the handshake is actually parked on a verdict, and once a failure ended it
  if (not FConductor.AwaitingVerdict) or FOutcome.IsTerminal then
    Exit;
  FDraining := True;
  try
    try
      FConductor.ResolveCertificateVerdict(AAccept, AAlert);
    except
      on E: Exception do
        FOutcome.Fail(TAlertMapping.ErrorFor(E));
    end;
  finally
    FDraining := False;
  end;
  Settle;
end;

procedure TTls13HandshakeEngine.LatchTransportFailure(const AReason: string);
begin
  // not a fatal alert, so sessions stay (RFC 5246 7.2.1)
  if FOutcome.IsTerminal then
    Exit;
  FSettled := True;
  FOutcome.Fail(TTlsError.CreateFatal(TTlsAlertDescription.InternalError, AReason,
    TTlsErrorOrigin.Transport));
  // the transport is gone, so nothing queued can be sent
  FChannel.Queue.Clear;
end;

function TTls13HandshakeEngine.IsHandshaking: Boolean;
begin
  Result := (not FOutcome.IsTerminal) and (not FOutcome.IsEstablished);
end;

function TTls13HandshakeEngine.AwaitingCertificateVerdict: Boolean;
begin
  Result := FConductor.AwaitingVerdict;
end;

function TTls13HandshakeEngine.IsTerminal: Boolean;
begin
  Result := FOutcome.IsTerminal;
end;

function TTls13HandshakeEngine.LastError: TTlsError;
begin
  Result := FOutcome.LastError;
end;

function TTls13HandshakeEngine.ConnectionInfo: TTlsConnectionInfo;
begin
  Result := FOutcome.Info;
end;

function TTls13HandshakeEngine.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  // nothing before the exporter secret exists, while parked, or once failed
  if FOutcome.IsTerminal or (not FConductor.CanExportKeyingMaterial) then
    Exit(nil);
  Result := FConductor.ExportKeyingMaterial(ALabel, ALength);
end;

function TTls13HandshakeEngine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  if FOutcome.IsTerminal or (not FConductor.CanExportKeyingMaterial) then
    Exit(nil);
  Result := FConductor.ExportKeyingMaterial(ALabel, AContext, ALength);
end;

function TTls13HandshakeEngine.ExportEarlyKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  // available on a client once it offers 0-RTT and on a server once it accepts it
  if FOutcome.IsTerminal or (not FConductor.CanExportEarlyKeyingMaterial) then
    Exit(nil);
  Result := FConductor.ExportEarlyKeyingMaterial(ALabel, AContext, ALength);
end;

end.
