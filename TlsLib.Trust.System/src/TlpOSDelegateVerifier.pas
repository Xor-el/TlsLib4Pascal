{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpOSDelegateVerifier;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpIPkixProvider,
  TlpIClock,
  TlpClock,
  TlpServerName,
  TlpTrustPolicy,
  TlpCertificateStrengthPolicy,
  TlpChainAlgorithmPolicy,
  TlpCertificateVerifier,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpICertificateVerifierSource,
  TlpSystemTrustBase,
  TlpSystemTrustExceptions,
  TlpIPlatformChainEngine,
  TlpOSLiveRevocation;

type
  /// <summary>The connection-scoped policy an OS delegate applies around its platform engine. Built
  /// from the trust context by the source; Anchors is the exclusive client-CA root (client role
  /// only).</summary>
  TOSDelegatePolicy = record
    Pkix: IPkixProvider;
    Clock: ITlsClock;
    Posture: TRevocationPosture;
    Fetch: TSystemTrustFetch;
    Deferral: TVerdictDeferral;
    StrengthPolicy: TCertificateStrengthPolicy;
    AdvertisedSchemes: TArray<UInt16>;
    Anchors: TArray<TBytes>;
    DeadlineMs: Cardinal;
    class function FromServerContext(const AContext: TServerTrustContext;
      AFetch: TSystemTrustFetch): TOSDelegatePolicy; static;
    class function FromClientContext(const AContext: TClientTrustContext;
      AFetch: TSystemTrustFetch): TOSDelegatePolicy; static;
  end;

  /// <summary>What every OS delegate does around its platform engine, matching each platform's order:
  /// the platform builds and trusts the path; an engine that renders its own revocation outcome has it
  /// decided (by the one revocation-decision table at the configured posture) before the chain-algorithm/
  /// key-strength policy, so a chain that is both revoked and weak reports the revocation alert; an
  /// engine that renders none runs strength first and decides revocation from the handshake staple. A
  /// definitive stapled Revoked always wins under every posture, and an indeterminate case defers to the
  /// async park only when a live fetch will decide it there. Then the identity the platform did not
  /// match is matched here (an IP literal against iPAddress SANs, or the full RFC 6125 identity for an
  /// engine that checks no host). Fail-closed throughout.</summary>
  TOSDelegateVerifierBase = class abstract(TInterfacedObject)
  strict private
    FEngine: IPlatformChainEngine;
    FPolicy: TOSDelegatePolicy;
    function DeferToLive: Boolean;
    function RevocationCheck: TPlatformRevocationCheck;
    function StapleOutcome(const APath: TArray<TBytes>;
      const AStaple: TBytes): TLiveRevocationOutcome;
  strict protected
    function BuildRequest(const AChain: TArray<TBytes>; const AServerName: TServerName;
      const AStaple: TBytes): TPlatformChainRequest;
    /// <summary>The shared tail after a True engine result: strength -> revocation -> identity.</summary>
    function Complete(const AResult: TPlatformChainResult; const AServerName: TServerName;
      const AStaple: TBytes; out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
    property Engine: IPlatformChainEngine read FEngine;
    property Policy: TOSDelegatePolicy read FPolicy;
  public
    constructor Create(const AEngine: IPlatformChainEngine;
      const APolicy: TOSDelegatePolicy);
  end;

  TOSDelegateServerVerifier = class sealed(TOSDelegateVerifierBase, IServerCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

  TOSDelegateClientVerifier = class sealed(TOSDelegateVerifierBase, IClientCertificateVerifier)
  public
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>The OS delegate's verifier source for either role: builds a delegate verifier around the
  /// platform engine from the connection's trust context, so posture, clock, strength policy and (for
  /// a client certificate) the exclusive client-CA anchors are injected the same way the built-in
  /// verifier receives them. AFetch fixes the inline behaviour: CacheOnly (no socket) or Live (an
  /// indeterminate revocation defers to the async park). Refuses at construction a Live fetch on an
  /// engine without live fetch, and at verifier creation a Live fetch without the live-revocation
  /// verdict, or - for an engine that renders no revocation outcome - a Hard client posture without
  /// it.</summary>
  TOSVerifierSource = class sealed(TInterfacedObject, IServerCertificateVerifierSource,
    IClientCertificateVerifierSource)
  strict private
    FEngine: IPlatformChainEngine;
    FFetch: TSystemTrustFetch;
  public
    constructor Create(const AEngine: IPlatformChainEngine; AFetch: TSystemTrustFetch);
    function CreateServerVerifier(const AContext: TServerTrustContext): IServerCertificateVerifier;
    function CreateClientVerifier(const AContext: TClientTrustContext): IClientCertificateVerifier;
  end;

  /// <summary>The OS-native live-revocation resolver over a platform engine: re-runs the engine with
  /// network fetch on (revocation only, requiring a positive response so an indeterminate surfaces)
  /// off the engine thread in the async park, applies the strength policy over the path it built, and
  /// hands the tri-state outcome to the shared verdict. Bound to one certificate role. Host-owned.</summary>
  TOSDelegateLiveResolver = class sealed(TOSLiveRevocationResolver)
  strict private
    FEngine: IPlatformChainEngine;
    FPolicy: TOSDelegatePolicy;
  strict protected
    function EvaluateLive(const AChain: TArray<TBytes>; const AHostName: string;
      const AStaple: TBytes; out AOutcome: TLiveRevocationOutcome;
      out ARejectAlert: TTlsAlertDescription): Boolean; override;
  public
    constructor Create(const AEngine: IPlatformChainEngine; ARole: TPeerRole;
      const APolicy: TOSDelegatePolicy; const AFallback: TCertificateVerdictResolver);
  end;

implementation

{ TOSDelegatePolicy }

class function TOSDelegatePolicy.FromServerContext(const AContext: TServerTrustContext;
  AFetch: TSystemTrustFetch): TOSDelegatePolicy;
begin
  Result := Default(TOSDelegatePolicy);
  Result.Pkix := AContext.Pkix;
  Result.Clock := AContext.Clock;
  Result.Posture := AContext.RevocationPosture;
  Result.Fetch := AFetch;
  Result.Deferral := AContext.Deferral;
  Result.StrengthPolicy := AContext.StrengthPolicy;
  Result.AdvertisedSchemes := AContext.AdvertisedSignatureSchemes;
  // the server path trusts the OS roots, so no exclusive anchor set
  Result.Anchors := nil;
  Result.DeadlineMs := 0;
end;

class function TOSDelegatePolicy.FromClientContext(const AContext: TClientTrustContext;
  AFetch: TSystemTrustFetch): TOSDelegatePolicy;
begin
  Result := Default(TOSDelegatePolicy);
  Result.Pkix := AContext.Pkix;
  Result.Clock := AContext.Clock;
  Result.Posture := AContext.RevocationPosture;
  Result.Fetch := AFetch;
  Result.Deferral := AContext.Deferral;
  Result.StrengthPolicy := AContext.StrengthPolicy;
  Result.AdvertisedSchemes := AContext.AdvertisedSignatureSchemes;
  // a client certificate is authenticated only against the configured client-CA anchors
  if AContext.TrustStore <> nil then
    Result.Anchors := AContext.TrustStore.RootCertificates
  else
    Result.Anchors := nil;
  Result.DeadlineMs := 0;
end;

{ TOSDelegateVerifierBase }

constructor TOSDelegateVerifierBase.Create(const AEngine: IPlatformChainEngine;
  const APolicy: TOSDelegatePolicy);
begin
  inherited Create;
  FEngine := AEngine;
  FPolicy := APolicy;
end;

function TOSDelegateVerifierBase.DeferToLive: Boolean;
begin
  // Windows/Apple defer on a Live fetch; an engine that renders no cached revocation outcome (Android)
  // defers when the live-revocation verdict is armed, since the staple is its only inline source
  Result := (FPolicy.Fetch = TSystemTrustFetch.Live) or
    ((not (TPlatformChainCapability.CachedRevocation in FEngine.Capabilities)) and
    (FPolicy.Deferral = TVerdictDeferral.LiveRevocation));
end;

function TOSDelegateVerifierBase.RevocationCheck: TPlatformRevocationCheck;
begin
  case TRevocationDecision.EffectivePosture(FPolicy.Posture, DeferToLive) of
    TRevocationPosture.Off:
      Result := TPlatformRevocationCheck.None;
    TRevocationPosture.Hard:
      Result := TPlatformRevocationCheck.RequirePositive;
  else
    Result := TPlatformRevocationCheck.BestEffort;
  end;
end;

function TOSDelegateVerifierBase.StapleOutcome(const APath: TArray<TBytes>;
  const AStaple: TBytes): TLiveRevocationOutcome;
var
  LClock: ITlsClock;
begin
  // a nil clock means system time (as the delegates accept), so a staple is still authenticated
  LClock := FPolicy.Clock;
  if LClock = nil then
    LClock := TSystemClock.Create as ITlsClock;
  case TCertificateVerifier.StapleVerdict(FPolicy.Pkix, LClock, APath, AStaple) of
    TStapleVerdict.GoodFresh, TStapleVerdict.GoodUnbounded:
      Result := TLiveRevocationOutcome.Good;
    TStapleVerdict.Revoked:
      Result := TLiveRevocationOutcome.Revoked;
  else
    Result := TLiveRevocationOutcome.Indeterminate;
  end;
end;

function TOSDelegateVerifierBase.BuildRequest(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AStaple: TBytes): TPlatformChainRequest;
begin
  Result := Default(TPlatformChainRequest);
  Result.Chain := AChain;
  Result.Anchors := FPolicy.Anchors;
  Result.ServerName := AServerName;
  Result.OcspStaple := AStaple;
  Result.Revocation := RevocationCheck;
  Result.NetworkAllowed := False;
  Result.Clock := FPolicy.Clock;
  Result.DeadlineMs := 0;
end;

function TOSDelegateVerifierBase.Complete(const AResult: TPlatformChainResult;
  const AServerName: TServerName; const AStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
var
  LStaple: TLiveRevocationOutcome;
begin
  AVerified := Default(TVerifiedChain);
  // without a provider or a built path there is nothing to decide over - fail closed
  if (FPolicy.Pkix = nil) or (System.Length(AResult.Path) = 0) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit(False);
  end;
  // an engine that renders its own revocation outcome (the OS folds revocation into its chain
  // verdict) decides it before the strength policy, so a chain that is both revoked and weak still
  // reports the revocation alert; an engine that renders none defers revocation to the staple below
  if TPlatformChainCapability.CachedRevocation in Engine.Capabilities then
    if not TRevocationDecision.Decide(AResult.Outcome, FPolicy.Posture, DeferToLive, AAlert) then
      Exit(False);
  // strength over the OS-built path, the engine's exempt certificates skipped
  if not TChainAlgorithmPolicy.Check(FPolicy.Pkix.Certificates, AResult.Path,
    AResult.PolicyExempt, FPolicy.StrengthPolicy, FPolicy.AdvertisedSchemes, AAlert) then
    Exit(False);
  // a definitive stapled Revoked overrides under every posture (a staple the engine did not fold in,
  // e.g. under Off); an engine with no revocation outcome of its own decides revocation from it here
  LStaple := StapleOutcome(AResult.Path, AStaple);
  if TPlatformChainCapability.CachedRevocation in Engine.Capabilities then
  begin
    if LStaple = TLiveRevocationOutcome.Revoked then
    begin
      AAlert := TTlsAlertDescription.CertificateRevoked;
      Exit(False);
    end;
  end
  else if not TRevocationDecision.Decide(LStaple, FPolicy.Posture, DeferToLive, AAlert) then
    Exit(False);
  // identity: an engine that matched the DNS host leaves only an IP literal to re-check; one that
  // checked no host has the full identity matched here (an empty client-role name fires neither)
  if TPlatformChainCapability.DnsIdentity in Engine.Capabilities then
  begin
    if TDelegatePostChecks.RejectIpMismatch(AServerName, FPolicy.Pkix, AResult.Path, AAlert) then
      Exit(False);
  end
  else if TDelegatePostChecks.RejectNameMismatch(AServerName, FPolicy.Pkix, AResult.Path, AAlert) then
    Exit(False);
  AVerified.Path := AResult.Path;
  AVerified.Outcome := TVerificationOutcome.Trusted;
  Result := True;
end;

{ TOSDelegateServerVerifier }

function TOSDelegateServerVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
var
  LRequest: TPlatformChainRequest;
  LResult: TPlatformChainResult;
begin
  AVerified := Default(TVerifiedChain);
  LRequest := BuildRequest(AChain, AServerName, AOcspStaple);
  if not Engine.EvaluateServer(LRequest, LResult, AAlert) then
    Exit(False);
  Result := Complete(LResult, AServerName, AOcspStaple, AVerified, AAlert);
end;

{ TOSDelegateClientVerifier }

function TOSDelegateClientVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
var
  LRequest: TPlatformChainRequest;
  LResult: TPlatformChainResult;
  LNoName: TServerName;
begin
  AVerified := Default(TVerifiedChain);
  LNoName := Default(TServerName);
  LRequest := BuildRequest(AChain, LNoName, nil);
  if not Engine.EvaluateClient(LRequest, LResult, AAlert) then
    Exit(False);
  Result := Complete(LResult, LNoName, nil, AVerified, AAlert);
end;

{ TOSVerifierSource }

constructor TOSVerifierSource.Create(const AEngine: IPlatformChainEngine;
  AFetch: TSystemTrustFetch);
begin
  inherited Create;
  if (AFetch = TSystemTrustFetch.Live) and
    not (TPlatformChainCapability.LiveFetch in AEngine.Capabilities) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  FEngine := AEngine;
  FFetch := AFetch;
end;

function TOSVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  if TDelegatePostChecks.LiveNeedsLiveRevocation(FFetch, AContext.Deferral) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SLiveNeedsLiveRevocationVerdict);
  Result := TOSDelegateServerVerifier.Create(FEngine,
    TOSDelegatePolicy.FromServerContext(AContext, FFetch)) as IServerCertificateVerifier;
end;

function TOSVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
begin
  if TDelegatePostChecks.LiveNeedsLiveRevocation(FFetch, AContext.Deferral) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SLiveNeedsLiveRevocationVerdict);
  // an engine that renders no cached revocation outcome cannot satisfy a Hard client posture without
  // the live-revocation verdict (a client certificate is never stapled)
  if not (TPlatformChainCapability.CachedRevocation in FEngine.Capabilities) and
    TDelegatePostChecks.HardNeedsLiveRevocation(AContext.RevocationPosture, AContext.Deferral) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SHardNeedsLiveRevocationVerdict);
  Result := TOSDelegateClientVerifier.Create(FEngine,
    TOSDelegatePolicy.FromClientContext(AContext, FFetch)) as IClientCertificateVerifier;
end;

{ TOSDelegateLiveResolver }

constructor TOSDelegateLiveResolver.Create(const AEngine: IPlatformChainEngine;
  ARole: TPeerRole; const APolicy: TOSDelegatePolicy;
  const AFallback: TCertificateVerdictResolver);
begin
  inherited Create(APolicy.Posture, ARole, AFallback);
  if not (TPlatformChainCapability.LiveFetch in AEngine.Capabilities) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  FEngine := AEngine;
  FPolicy := APolicy;
end;

function TOSDelegateLiveResolver.EvaluateLive(const AChain: TArray<TBytes>;
  const AHostName: string; const AStaple: TBytes;
  out AOutcome: TLiveRevocationOutcome; out ARejectAlert: TTlsAlertDescription): Boolean;
var
  LRequest: TPlatformChainRequest;
  LResult: TPlatformChainResult;
  LTrusted: Boolean;
begin
  LRequest := Default(TPlatformChainRequest);
  LRequest.Chain := AChain;
  LRequest.Anchors := FPolicy.Anchors;
  LRequest.OcspStaple := AStaple;
  LRequest.Revocation := TPlatformRevocationCheck.RequirePositive;
  LRequest.NetworkAllowed := True;
  LRequest.Clock := FPolicy.Clock;
  LRequest.DeadlineMs := FPolicy.DeadlineMs;
  // the base already stripped an IP literal via OsHostName, so a non-empty host is a DNS name
  if AHostName <> '' then
    LRequest.ServerName := TServerName.DnsName(AHostName)
  else
    LRequest.ServerName := Default(TServerName);
  if FExpectedPeer = TPeerRole.Server then
    LTrusted := FEngine.EvaluateServer(LRequest, LResult, ARejectAlert)
  else
    LTrusted := FEngine.EvaluateClient(LRequest, LResult, ARejectAlert);
  if not LTrusted then
    Exit(False);
  // apply the strength policy over the live-built path when the platform trusted revocation too
  if LResult.Outcome = TLiveRevocationOutcome.Good then
  begin
    if (FPolicy.Pkix = nil) or (System.Length(LResult.Path) = 0) then
    begin
      ARejectAlert := TTlsAlertDescription.InternalError;
      Exit(False);
    end;
    if not TChainAlgorithmPolicy.Check(FPolicy.Pkix.Certificates, LResult.Path,
      LResult.PolicyExempt, FPolicy.StrengthPolicy, FPolicy.AdvertisedSchemes, ARejectAlert) then
      Exit(False);
  end;
  AOutcome := LResult.Outcome;
  Result := True;
end;

end.
