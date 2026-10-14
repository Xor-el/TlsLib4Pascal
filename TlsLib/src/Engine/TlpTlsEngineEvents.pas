{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsEngineEvents;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsAlertProtocol,
  TlpTrustPolicy,
  TlpITlsEngine;

type
  /// <summary>Factory for the concrete engine events (held as ITlsEvent).</summary>
  TTlsEvents = class sealed(TObject)
  public
    class function MakeSimple(AKind: TTlsEventKind): ITlsEvent; static;
    class function MakePeerAlert(const AAlert: TReceivedAlert): ITlsEvent; static;
    class function MakeCertificateReceived(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes;
      APosture: TRevocationPosture): ITlsEvent; static;
  end;

implementation

type
  TSimpleEvent = class(TInterfacedObject, ITlsEvent)
  strict private
  var
    FKind: TTlsEventKind;
  public
    constructor Create(AKind: TTlsEventKind);
    function Kind: TTlsEventKind;
  end;

  TPeerAlertEvent = class(TInterfacedObject, ITlsEvent, IPeerAlertEvent)
  strict private
  var
    FAlert: TReceivedAlert;
  public
    constructor Create(const AAlert: TReceivedAlert);
    function Kind: TTlsEventKind;
    function Alert: TReceivedAlert;
  end;

  TCertificateReceivedEvent = class(TInterfacedObject, ITlsEvent,
    ICertificateReceivedEvent)
  strict private
  var
    FChain: TArray<TBytes>;
    FValidatedPath: TArray<TBytes>;
    FHostName: string;
    FOcspStaple: TBytes;
    FRevocationPosture: TRevocationPosture;
  public
    constructor Create(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes; APosture: TRevocationPosture);
    function Kind: TTlsEventKind;
    function Chain: TArray<TBytes>;
    function ValidatedPath: TArray<TBytes>;
    function HostName: string;
    function OcspStaple: TBytes;
    function RevocationPosture: TRevocationPosture;
  end;

{ TSimpleEvent }

constructor TSimpleEvent.Create(AKind: TTlsEventKind);
begin
  inherited Create;
  FKind := AKind;
end;

function TSimpleEvent.Kind: TTlsEventKind;
begin
  Result := FKind;
end;

{ TPeerAlertEvent }

constructor TPeerAlertEvent.Create(const AAlert: TReceivedAlert);
begin
  inherited Create;
  FAlert := AAlert;
end;

function TPeerAlertEvent.Kind: TTlsEventKind;
begin
  Result := TTlsEventKind.PeerAlert;
end;

function TPeerAlertEvent.Alert: TReceivedAlert;
begin
  Result := FAlert;
end;

{ TCertificateReceivedEvent }

constructor TCertificateReceivedEvent.Create(const AChain,
  AValidatedPath: TArray<TBytes>; const AHostName: string; const AStaple: TBytes;
  APosture: TRevocationPosture);
begin
  inherited Create;
  FRevocationPosture := APosture;
  FChain := TArrayUtilities.DeepCopy<Byte>(AChain);
  FValidatedPath := TArrayUtilities.DeepCopy<Byte>(AValidatedPath);
  FHostName := AHostName;
  FOcspStaple := System.Copy(AStaple);
end;

function TCertificateReceivedEvent.Kind: TTlsEventKind;
begin
  Result := TTlsEventKind.CertificateReceived;
end;

function TCertificateReceivedEvent.Chain: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FChain);
end;

function TCertificateReceivedEvent.ValidatedPath: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FValidatedPath);
end;

function TCertificateReceivedEvent.HostName: string;
begin
  Result := FHostName;
end;

function TCertificateReceivedEvent.OcspStaple: TBytes;
begin
  Result := System.Copy(FOcspStaple);
end;

function TCertificateReceivedEvent.RevocationPosture: TRevocationPosture;
begin
  Result := FRevocationPosture;
end;

{ TTlsEvents }

class function TTlsEvents.MakeSimple(AKind: TTlsEventKind): ITlsEvent;
begin
  Result := TSimpleEvent.Create(AKind);
end;

class function TTlsEvents.MakePeerAlert(const AAlert: TReceivedAlert): ITlsEvent;
begin
  Result := TPeerAlertEvent.Create(AAlert);
end;

class function TTlsEvents.MakeCertificateReceived(const AChain,
  AValidatedPath: TArray<TBytes>; const AHostName: string;
  const AStaple: TBytes; APosture: TRevocationPosture): ITlsEvent;
begin
  Result := TCertificateReceivedEvent.Create(AChain, AValidatedPath, AHostName, AStaple,
    APosture);
end;

end.
