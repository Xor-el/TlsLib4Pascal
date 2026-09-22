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
  TlpTlsAlertProtocol,
  TlpITlsEngine;

type
  /// <summary>Factory for the concrete engine events (held as ITlsEvent).</summary>
  TTlsEvents = class sealed(TObject)
  public
    class function MakeSimple(AKind: TTlsEventKind): ITlsEvent; static;
    class function MakeAppData: ITlsEvent; static;
    class function MakeClosed: ITlsEvent; static;
    class function MakeKeysInstalled: ITlsEvent; static;
    class function MakePeerAlert(const AAlert: TReceivedAlert): ITlsEvent; static;
    class function MakeCertificateReceived(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes): ITlsEvent; static;
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
    class function DeepCopy(const AChain: TArray<TBytes>): TArray<TBytes>; static;
  public
    constructor Create(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes);
    function Kind: TTlsEventKind;
    function Chain: TArray<TBytes>;
    function ValidatedPath: TArray<TBytes>;
    function HostName: string;
    function OcspStaple: TBytes;
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

class function TCertificateReceivedEvent.DeepCopy(
  const AChain: TArray<TBytes>): TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(AChain));
  for LI := 0 to System.High(AChain) do
    Result[LI] := System.Copy(AChain[LI]);
end;

constructor TCertificateReceivedEvent.Create(const AChain,
  AValidatedPath: TArray<TBytes>; const AHostName: string; const AStaple: TBytes);
begin
  inherited Create;
  FChain := DeepCopy(AChain);
  FValidatedPath := DeepCopy(AValidatedPath);
  FHostName := AHostName;
  FOcspStaple := System.Copy(AStaple);
end;

function TCertificateReceivedEvent.Kind: TTlsEventKind;
begin
  Result := TTlsEventKind.CertificateReceived;
end;

function TCertificateReceivedEvent.Chain: TArray<TBytes>;
begin
  Result := DeepCopy(FChain);
end;

function TCertificateReceivedEvent.ValidatedPath: TArray<TBytes>;
begin
  Result := DeepCopy(FValidatedPath);
end;

function TCertificateReceivedEvent.HostName: string;
begin
  Result := FHostName;
end;

function TCertificateReceivedEvent.OcspStaple: TBytes;
begin
  Result := System.Copy(FOcspStaple);
end;

{ TTlsEvents }

class function TTlsEvents.MakeSimple(AKind: TTlsEventKind): ITlsEvent;
begin
  Result := TSimpleEvent.Create(AKind);
end;

class function TTlsEvents.MakeAppData: ITlsEvent;
begin
  Result := TSimpleEvent.Create(TTlsEventKind.AppData);
end;

class function TTlsEvents.MakeClosed: ITlsEvent;
begin
  Result := TSimpleEvent.Create(TTlsEventKind.Closed);
end;

class function TTlsEvents.MakeKeysInstalled: ITlsEvent;
begin
  Result := TSimpleEvent.Create(TTlsEventKind.KeysInstalled);
end;

class function TTlsEvents.MakePeerAlert(const AAlert: TReceivedAlert): ITlsEvent;
begin
  Result := TPeerAlertEvent.Create(AAlert);
end;

class function TTlsEvents.MakeCertificateReceived(const AChain,
  AValidatedPath: TArray<TBytes>; const AHostName: string;
  const AStaple: TBytes): ITlsEvent;
begin
  Result := TCertificateReceivedEvent.Create(AChain, AValidatedPath, AHostName, AStaple);
end;

end.
