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
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTrustPolicy,
  TlpSystemTrustBase,
  TlpICertificateVerifierSource,
  TlpOSDelegateVerifier,
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

  /// <summary>
  /// An <see cref="IPlatformChainEngine" /> that decides by roots like a platform engine: a chain
  /// is trusted when its last certificate is a root of the set the request selects - the server
  /// Anchors as the exclusive root when non-empty and the engine declares ExclusiveServerAnchors
  /// (without it they are ignored, as a real engine would), else the OS roots it was built with
  /// (plus the ExtraAnchors under NativeAnchorUnion); a client request only ever uses its Anchors.
  /// A trusted chain is returned as its own path with only the matched root exempt, as a real
  /// engine reports; an untrusted one fails with NoTrustAnchor / unknown_ca. Records every request. Never for production use.
  /// </summary>
  TAnchorAwarePlatformChainEngine = class sealed(TInterfacedObject, IPlatformChainEngine)
  strict private
    FCaps: TPlatformChainCapabilities;
    FOsRoots: TArray<TBytes>;
    FRequests: TArray<TPlatformChainRequest>;
    FServerCalls: Integer;
    FClientCalls: Integer;
    function Judge(const ARequest: TPlatformChainRequest; const ARoots: TArray<TBytes>;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
  public
    constructor Create(ACaps: TPlatformChainCapabilities; const AOsRoots: TArray<TBytes>);
    function Capabilities: TPlatformChainCapabilities;
    function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>Every request received, in call order.</summary>
    property Requests: TArray<TPlatformChainRequest> read FRequests;
    property ServerCalls: Integer read FServerCalls;
    property ClientCalls: Integer read FClientCalls;
  end;

  /// <summary>The library's OS verifier source over an engine that is never asked, so a config
  /// can hold an in-module verifier on any host. Never for production use.</summary>
  TFakeOsVerifierSources = class sealed(TObject)
  strict private
    class function Engine: IPlatformChainEngine; static;
  public
    class function Server: IServerCertificateVerifierSource; static;
    class function Client: IClientCertificateVerifierSource; static;
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

{ TAnchorAwarePlatformChainEngine }

constructor TAnchorAwarePlatformChainEngine.Create(ACaps: TPlatformChainCapabilities;
  const AOsRoots: TArray<TBytes>);
begin
  inherited Create;
  FCaps := ACaps;
  FOsRoots := AOsRoots;
end;

function TAnchorAwarePlatformChainEngine.Capabilities: TPlatformChainCapabilities;
begin
  Result := FCaps;
end;

function TAnchorAwarePlatformChainEngine.Judge(const ARequest: TPlatformChainRequest;
  const ARoots: TArray<TBytes>; out AResult: TPlatformChainResult;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LRoot: Int32;
begin
  SetLength(FRequests, Length(FRequests) + 1);
  FRequests[High(FRequests)] := ARequest;
  AResult := Default(TPlatformChainResult);
  AAlert := TTlsAlertDescription.UnknownCa;
  AResult.Failure := TPlatformChainFailure.NoTrustAnchor;
  Result := False;
  if Length(ARequest.Chain) = 0 then
    Exit;
  for LRoot := 0 to High(ARoots) do
    if TArrayUtilities.AreEqual(ARequest.Chain[High(ARequest.Chain)], ARoots[LRoot]) then
    begin
      AResult.Failure := TPlatformChainFailure.None;
      AResult.Outcome := TLiveRevocationOutcome.Good;
      AResult.Path := ARequest.Chain;
      AResult.PolicyExempt := TArray<TBytes>.Create(ARoots[LRoot]);
      Exit(True);
    end;
end;

function TAnchorAwarePlatformChainEngine.EvaluateServer(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LRoots: TArray<TBytes>;
begin
  Inc(FServerCalls);
  if (Length(ARequest.Anchors) > 0) and
    (TPlatformChainCapability.ExclusiveServerAnchors in FCaps) then
    LRoots := ARequest.Anchors
  else if TPlatformChainCapability.NativeAnchorUnion in FCaps then
    LRoots := TArrayUtilities.Concat<TBytes>(FOsRoots, ARequest.ExtraAnchors)
  else
    LRoots := FOsRoots;
  Result := Judge(ARequest, LRoots, AResult, AAlert);
end;

function TAnchorAwarePlatformChainEngine.EvaluateClient(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  Inc(FClientCalls);
  Result := Judge(ARequest, ARequest.Anchors, AResult, AAlert);
end;

{ TFakeOsVerifierSources }

class function TFakeOsVerifierSources.Engine: IPlatformChainEngine;
begin
  Result := TMockPlatformChainEngine.Create([], False, Default(TPlatformChainResult),
    TTlsAlertDescription.BadCertificate) as IPlatformChainEngine;
end;

class function TFakeOsVerifierSources.Server: IServerCertificateVerifierSource;
begin
  Result := TOSVerifierSource.Create(Engine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IServerCertificateVerifierSource;
end;

class function TFakeOsVerifierSources.Client: IClientCertificateVerifierSource;
begin
  Result := TOSVerifierSource.Create(Engine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IClientCertificateVerifierSource;
end;

end.
