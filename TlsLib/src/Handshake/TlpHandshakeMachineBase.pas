{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeMachineBase;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpNegotiationTypes,
  TlpITranscriptHash,
  TlpTranscriptHash,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpHandshakeStage,
  TlpHandshakeMessages,
  TlpHandshakeMessage,
  TlpHandshakeEffect,
  TlpIHandshakeMachine;

type
  /// <summary>
  /// The version-neutral plumbing shared by the TLS 1.2 and 1.3 handshake machines:
  /// the extension codec, transcript hash, and selected suite, plus the single failure
  /// channel - ProcessMessage turns an in-band protocol exception into a Fail effect and
  /// everything else propagates as an internal fault. A concrete machine supplies Start
  /// and Route (the per-phase routing); the key schedule is version-specific and held by
  /// the derived per-version base.
  /// </summary>
  THandshakeMachineBase = class abstract(TInterfacedObject, IHandshakeMachine)
  strict protected
    FCodec: IExtensionBlockCodec;
    FTranscript: ITranscriptHash;
    FSelectedSuite: TTlsCipherSuite;
    FRenegotiationRefused: Boolean;
    FStage: THandshakeStage;
    /// <summary>Routes one message to its phase handler.</summary>
    function Route(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; virtual; abstract;
    /// <summary>Marks the handshake established (Stage = Connected). Called where a machine emits
    /// its HandshakeEstablished, so Stage = Connected iff that event was emitted.</summary>
    procedure MarkConnected;
    /// <summary>Suspends the machine for an out-of-band peer-certificate verdict: sets Stage =
    /// ParkedForVerdict and returns the AwaitCertificateVerdict effect the driver reports.</summary>
    function ParkForVerdict(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes): THandshakeEffect;
    /// <summary>The withheld continuation resumed after a message-less verdict park; nil by
    /// default, overridden by the clients' reverify-on-resume park. ResumeAfterVerdict clears the
    /// park stage and returns this.</summary>
    function ContinueAfterVerdict: TArray<THandshakeEffect>; virtual;
    /// <summary>The effect that aborts on a message arriving out of phase.</summary>
    class function Unexpected: TArray<THandshakeEffect>; static;
    /// <summary>Refuses a post-handshake renegotiation request: the first is answered with a
    /// warning no_renegotiation and the connection continues; a second is fatal (RFC 5246 7.2.2,
    /// RFC 5746 4.2). Used by the TLS 1.2 machines, which do not renegotiate.</summary>
    function RefuseRenegotiation: TArray<THandshakeEffect>;
  public
    constructor Create(const AExtensionRegistry: IExtensionRegistry);
    /// <summary>A responder (server) by default; the client machines override to True.</summary>
    function Initiates: Boolean; virtual;
    /// <summary>The coarse handshake stage; starts Handshaking, MarkConnected/ParkForVerdict/
    /// ResumeAfterVerdict move it.</summary>
    function Stage: THandshakeStage;
    function Start: TArray<THandshakeEffect>; virtual; abstract;
    function ProcessMessage(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>No post-handshake KeyUpdate by default (TLS 1.2 and pre-established); the
    /// TLS 1.3 base overrides these.</summary>
    function RequestKeyUpdate(ARequest: TKeyUpdateRequest)
      : TArray<THandshakeEffect>; virtual;
    function TakePendingKeyUpdate: TArray<THandshakeEffect>; virtual;
    /// <summary>Resumes a message-less verdict park: clears the park stage (back to Handshaking)
    /// and returns the machine's withheld continuation (ContinueAfterVerdict). The client machines
    /// supply the continuation by overriding ContinueAfterVerdict.</summary>
    function ResumeAfterVerdict: TArray<THandshakeEffect>;
    /// <summary>No exporter until a machine derives its secrets; concrete versions override.</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes; virtual;
    /// <summary>No exporter available by default; concrete versions override.</summary>
    function CanExportKeyingMaterial: Boolean; virtual;
  end;

implementation

{ THandshakeMachineBase }

constructor THandshakeMachineBase.Create(const AExtensionRegistry: IExtensionRegistry);
begin
  inherited Create;
  FCodec := TExtensionBlockCodec.Create(AExtensionRegistry);
  FTranscript := TTranscriptHash.Create; // deferred until the suite is known
end;

function THandshakeMachineBase.Initiates: Boolean;
begin
  Result := False;
end;

function THandshakeMachineBase.Stage: THandshakeStage;
begin
  Result := FStage;
end;

procedure THandshakeMachineBase.MarkConnected;
begin
  FStage := THandshakeStage.Connected;
end;

function THandshakeMachineBase.ParkForVerdict(const AChain,
  AValidatedPath: TArray<TBytes>; const AHostName: string;
  const AStaple: TBytes): THandshakeEffect;
begin
  FStage := THandshakeStage.ParkedForVerdict;
  Result := THandshakeEffects.AwaitCertificateVerdict(AChain, AValidatedPath,
    AHostName, AStaple);
end;

function THandshakeMachineBase.ContinueAfterVerdict: TArray<THandshakeEffect>;
begin
  Result := nil;
end;

class function THandshakeMachineBase.Unexpected: TArray<THandshakeEffect>;
begin
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.Fail(TTlsAlertDescription.UnexpectedMessage));
end;

function THandshakeMachineBase.RefuseRenegotiation: TArray<THandshakeEffect>;
begin
  if FRenegotiationRefused then
    Result := TArray<THandshakeEffect>.Create(
      THandshakeEffects.Fail(TTlsAlertDescription.IllegalParameter))
  else
  begin
    FRenegotiationRefused := True;
    Result := TArray<THandshakeEffect>.Create(
      THandshakeEffects.SendWarningAlert(TTlsAlertDescription.NoRenegotiation));
  end;
end;

function THandshakeMachineBase.RequestKeyUpdate(
  ARequest: TKeyUpdateRequest): TArray<THandshakeEffect>;
begin
  Result := nil;
end;

function THandshakeMachineBase.TakePendingKeyUpdate: TArray<THandshakeEffect>;
begin
  Result := nil;
end;

function THandshakeMachineBase.ResumeAfterVerdict: TArray<THandshakeEffect>;
begin
  // the out-of-band verdict resolved: leave the park and hand back the withheld continuation
  FStage := THandshakeStage.Handshaking;
  Result := ContinueAfterVerdict;
end;

function THandshakeMachineBase.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  Result := nil;
end;

function THandshakeMachineBase.CanExportKeyingMaterial: Boolean;
begin
  Result := False;
end;

function THandshakeMachineBase.ProcessMessage(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  try
    Result := Route(AMessage);
  except
    // an in-band protocol failure surfaces as a Fail effect, not a raised exception
    on E: EPeerInputTlsLibException do
      Result := TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(TTlsAlertDescription.IllegalParameter));
    on E: EFatalAlertTlsLibException do
      Result := TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(E.AlertDescription));
  end;
end;

end.
