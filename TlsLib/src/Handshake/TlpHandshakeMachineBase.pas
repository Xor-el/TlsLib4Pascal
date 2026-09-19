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
    /// <summary>Routes one message to its phase handler.</summary>
    function Route(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; virtual; abstract;
    /// <summary>The effect that aborts on a message arriving out of phase.</summary>
    class function Unexpected: TArray<THandshakeEffect>; static;
  public
    constructor Create(const AExtensionRegistry: IExtensionRegistry);
    /// <summary>A responder (server) by default; the client machines override to True.</summary>
    function Initiates: Boolean; virtual;
    function Start: TArray<THandshakeEffect>; virtual; abstract;
    function ProcessMessage(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>No post-handshake KeyUpdate by default (TLS 1.2 and pre-established); the
    /// TLS 1.3 base overrides these.</summary>
    function RequestKeyUpdate(ARequestPeerUpdate: Boolean)
      : TArray<THandshakeEffect>; virtual;
    function TakePendingKeyUpdate: TArray<THandshakeEffect>; virtual;
    /// <summary>No withheld continuation by default; the TLS 1.3 client overrides for its
    /// reverify-on-resume park.</summary>
    function ResumeAfterVerdict: TArray<THandshakeEffect>; virtual;
    /// <summary>No exporter until a machine derives its secrets; concrete versions override.</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes; virtual;
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

class function THandshakeMachineBase.Unexpected: TArray<THandshakeEffect>;
begin
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.Fail(TTlsAlertDescription.UnexpectedMessage));
end;

function THandshakeMachineBase.RequestKeyUpdate(
  ARequestPeerUpdate: Boolean): TArray<THandshakeEffect>;
begin
  Result := nil;
end;

function THandshakeMachineBase.TakePendingKeyUpdate: TArray<THandshakeEffect>;
begin
  Result := nil;
end;

function THandshakeMachineBase.ResumeAfterVerdict: TArray<THandshakeEffect>;
begin
  Result := nil;
end;

function THandshakeMachineBase.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  Result := nil;
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
