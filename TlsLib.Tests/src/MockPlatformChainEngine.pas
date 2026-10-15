{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockPlatformChainEngine;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsAlert,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine;

type
  /// <summary>
  /// A scripted <see cref="IPlatformChainEngine" /> for the OS-delegate template tests: it returns a
  /// configured outcome/alert and records the last request and per-role call counts, so the request
  /// shaping and role dispatch can be asserted without a real platform trust engine. Never for
  /// production use.
  /// </summary>
  TMockPlatformChainEngine = class sealed(TInterfacedObject, IPlatformChainEngine)
  strict private
  type
    TStep = record
      Returns: Boolean;
      Result: TPlatformChainResult;
      Alert: TTlsAlertDescription;
    end;
  var
    FCaps: TPlatformChainCapabilities;
    FSteps: TArray<TStep>;
    FRequests: TArray<TPlatformChainRequest>;
    FLast: TPlatformChainRequest;
    FServerCalls: Integer;
    FClientCalls: Integer;
    function Run(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
  public
    constructor Create(ACaps: TPlatformChainCapabilities; AReturns: Boolean;
      const AResult: TPlatformChainResult; AAlert: TTlsAlertDescription);
    /// <summary>Scripts the outcome of the next evaluation after the ones already scripted; the last
    /// scripted outcome repeats for any further call.</summary>
    procedure ThenReturn(AReturns: Boolean; const AResult: TPlatformChainResult;
      AAlert: TTlsAlertDescription);
    function Capabilities: TPlatformChainCapabilities;
    function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>The request the last Evaluate* call received, for asserting the delegate's shaping.</summary>
    property Last: TPlatformChainRequest read FLast;
    /// <summary>Every request received, in call order.</summary>
    property Requests: TArray<TPlatformChainRequest> read FRequests;
    property ServerCalls: Integer read FServerCalls;
    property ClientCalls: Integer read FClientCalls;
  end;

implementation

{ TMockPlatformChainEngine }

constructor TMockPlatformChainEngine.Create(ACaps: TPlatformChainCapabilities;
  AReturns: Boolean; const AResult: TPlatformChainResult; AAlert: TTlsAlertDescription);
begin
  inherited Create;
  FCaps := ACaps;
  ThenReturn(AReturns, AResult, AAlert);
end;

procedure TMockPlatformChainEngine.ThenReturn(AReturns: Boolean;
  const AResult: TPlatformChainResult; AAlert: TTlsAlertDescription);
begin
  SetLength(FSteps, Length(FSteps) + 1);
  FSteps[High(FSteps)].Returns := AReturns;
  FSteps[High(FSteps)].Result := AResult;
  FSteps[High(FSteps)].Alert := AAlert;
end;

function TMockPlatformChainEngine.Capabilities: TPlatformChainCapabilities;
begin
  Result := FCaps;
end;

function TMockPlatformChainEngine.Run(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LStep: Integer;
begin
  FLast := ARequest;
  SetLength(FRequests, Length(FRequests) + 1);
  FRequests[High(FRequests)] := ARequest;
  LStep := Length(FRequests) - 1;
  if LStep > High(FSteps) then
    LStep := High(FSteps);
  AResult := FSteps[LStep].Result;
  AAlert := FSteps[LStep].Alert;
  Result := FSteps[LStep].Returns;
end;

function TMockPlatformChainEngine.EvaluateServer(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  Inc(FServerCalls);
  Result := Run(ARequest, AResult, AAlert);
end;

function TMockPlatformChainEngine.EvaluateClient(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  Inc(FClientCalls);
  Result := Run(ARequest, AResult, AAlert);
end;

end.
