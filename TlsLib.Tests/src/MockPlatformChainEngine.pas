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
  TMockPlatformChainEngine = class(TInterfacedObject, IPlatformChainEngine)
  strict private
    FCaps: TPlatformChainCapabilities;
    FReturns: Boolean;
    FResult: TPlatformChainResult;
    FAlert: TTlsAlertDescription;
    FLast: TPlatformChainRequest;
    FServerCalls: Integer;
    FClientCalls: Integer;
    function Run(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
  public
    constructor Create(ACaps: TPlatformChainCapabilities; AReturns: Boolean;
      const AResult: TPlatformChainResult; AAlert: TTlsAlertDescription);
    function Capabilities: TPlatformChainCapabilities;
    function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>The request the last Evaluate* call received, for asserting the delegate's shaping.</summary>
    property Last: TPlatformChainRequest read FLast;
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
  FReturns := AReturns;
  FResult := AResult;
  FAlert := AAlert;
end;

function TMockPlatformChainEngine.Capabilities: TPlatformChainCapabilities;
begin
  Result := FCaps;
end;

function TMockPlatformChainEngine.Run(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  FLast := ARequest;
  AResult := FResult;
  AAlert := FAlert;
  Result := FReturns;
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
