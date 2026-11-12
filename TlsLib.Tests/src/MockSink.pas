{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockSink;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsAlert,
  TlpITlsEngine,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeStage,
  TlpHandshakeMessage,
  TlpHandshakeMessages;

type
  /// <summary>A handshake sink double that records what the driver reports: event count and the
  /// last event, whether the handshake was established, and any failure alert and its reason. A
  /// test that does not care about the recordings simply ignores them (it doubles as a silent
  /// sink).</summary>
  TMockHandshakeSink = class sealed(TInterfacedObject, IHandshakeSink)
  strict private
  var
    FEventCount: Int32;
    FLastEvent: TTlsEventKind;
    FEstablished: Boolean;
    FFailed: Boolean;
    FFailedAlert: TTlsAlertDescription;
    FFailedReason: string;
  public
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: TBytes);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription; const AReason: string);
    property EventCount: Int32 read FEventCount;
    property LastEvent: TTlsEventKind read FLastEvent;
    property Established: Boolean read FEstablished;
    property Failed: Boolean read FFailed;
    property FailedAlert: TTlsAlertDescription read FFailedAlert;
    property FailedReason: string read FFailedReason;
  end;

  // forwards to a real machine; Inject makes the next RequestKeyUpdate seal ABytes as a
  // handshake message, so a test can send a message the real machine never would
  TEffectInjectingMachine = class sealed(TInterfacedObject, IHandshakeMachine)
  strict private
  var
    FInner: IHandshakeMachine;
    FInjected: TBytes;
  public
    constructor Create(const AInner: IHandshakeMachine);
    procedure Inject(const ABytes: TBytes);
    function Initiates: Boolean;
    function Stage: THandshakeStage;
    function Start: TArray<THandshakeEffect>;
    function ProcessMessage(const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
    function RequestKeyUpdate(ARequest: TKeyUpdateRequest): TArray<THandshakeEffect>;
    function TakePendingKeyUpdate: TArray<THandshakeEffect>;
    function ResumeAfterVerdict: TArray<THandshakeEffect>;
    function ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function CanExportKeyingMaterial: Boolean;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
    function CanExportEarlyKeyingMaterial: Boolean;
    procedure ForgetSessionsOnFatal;
  end;

implementation

{ TMockHandshakeSink }

procedure TMockHandshakeSink.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  Inc(FEventCount);
  FLastEvent := AEvent;
end;

procedure TMockHandshakeSink.OnAlpnSelected(const AProtocol: TBytes);
begin
end;

procedure TMockHandshakeSink.OnOcspStapleReceived(const AStaple: TBytes);
begin
end;

procedure TMockHandshakeSink.OnHandshakeEstablished;
begin
  FEstablished := True;
end;

procedure TMockHandshakeSink.OnHandshakeFailed(AAlert: TTlsAlertDescription;
  const AReason: string);
begin
  FFailed := True;
  FFailedAlert := AAlert;
  FFailedReason := AReason;
end;

{ TEffectInjectingMachine }

constructor TEffectInjectingMachine.Create(const AInner: IHandshakeMachine);
begin
  inherited Create;
  FInner := AInner;
end;

procedure TEffectInjectingMachine.Inject(const ABytes: TBytes);
begin
  FInjected := ABytes;
end;

function TEffectInjectingMachine.Initiates: Boolean;
begin
  Result := FInner.Initiates;
end;

function TEffectInjectingMachine.Stage: THandshakeStage;
begin
  Result := FInner.Stage;
end;

function TEffectInjectingMachine.Start: TArray<THandshakeEffect>;
begin
  Result := FInner.Start;
end;

function TEffectInjectingMachine.ProcessMessage(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  Result := FInner.ProcessMessage(AMessage);
end;

function TEffectInjectingMachine.RequestKeyUpdate(
  ARequest: TKeyUpdateRequest): TArray<THandshakeEffect>;
begin
  if System.Length(FInjected) = 0 then
    Exit(FInner.RequestKeyUpdate(ARequest));
  Result := TArray<THandshakeEffect>.Create(THandshakeEffects.SendHandshake(FInjected));
  FInjected := nil;
end;

function TEffectInjectingMachine.TakePendingKeyUpdate: TArray<THandshakeEffect>;
begin
  Result := FInner.TakePendingKeyUpdate;
end;

function TEffectInjectingMachine.ResumeAfterVerdict: TArray<THandshakeEffect>;
begin
  Result := FInner.ResumeAfterVerdict;
end;

function TEffectInjectingMachine.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  Result := FInner.ExportKeyingMaterial(ALabel, ALength);
end;

function TEffectInjectingMachine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := FInner.ExportKeyingMaterial(ALabel, AContext, ALength);
end;

function TEffectInjectingMachine.CanExportKeyingMaterial: Boolean;
begin
  Result := FInner.CanExportKeyingMaterial;
end;

function TEffectInjectingMachine.ExportEarlyKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := FInner.ExportEarlyKeyingMaterial(ALabel, AContext, ALength);
end;

function TEffectInjectingMachine.CanExportEarlyKeyingMaterial: Boolean;
begin
  Result := FInner.CanExportEarlyKeyingMaterial;
end;

procedure TEffectInjectingMachine.ForgetSessionsOnFatal;
begin
  FInner.ForgetSessionsOnFatal;
end;

end.
