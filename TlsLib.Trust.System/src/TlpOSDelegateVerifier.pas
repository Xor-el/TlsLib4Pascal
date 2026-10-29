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
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  TlpTlsAlert,
  TlpPkixDomainTypes,
  TlpDateTimeUtilities,
  TlpIPkixProvider,
  TlpIClock,
  TlpClock,
  TlpServerName,
  TlpTrustPolicy,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpChainAlgorithmPolicy,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTrustTypes,
  TlpITlsConfig,
  TlpSignatureSchemeRegistry,
  TlpICertificateVerifierSource,
  TlpCertificateVerifierSource,
  TlpSystemTrustBase,
  TlpSystemTrustExceptions,
  TlpIPlatformChainEngine,
  TlpOSLiveRevocation;

type
  /// <summary>The connection-scoped policy an OS delegate applies around its platform engine. Built
  /// from the trust context by the source; Anchors is the exclusive trust root (always set for the
  /// client role; for the server role set by a HostRoots source, by the live re-check of a
  /// client config that trusts its store roots (WebPki), else empty = the OS roots); CheckHostName
  /// mirrors the client config so a delegate honours a disabled name check the same way the
  /// built-in verifier does (server role only; a client cert has no name to match).</summary>
  TOSDelegatePolicy = record
    Pkix: IPkixProvider;
    Clock: ITlsClock;
    Posture: TRevocationPosture;
    Fetch: TSystemTrustFetch;
    Deferral: TVerdictDeferral;
    StrengthPolicy: TCertificateStrengthPolicy;
    ChainLimits: TCertificateChainLimits;
    AdvertisedSchemes: TArray<UInt16>;
    Anchors: TArray<TBytes>;
    // the store Anchors come from when there is one, read by the portable path builder for a client path
    AnchorStore: ITrustAnchorStore;
    // host roots trusted with the OS roots, server role only (see TPlatformChainRequest)
    ExtraAnchors: TArray<TBytes>;
    // the OS and host distrust sets, refused on any accepted path
    Distrusted: TArray<TBytes>;
    Intermediates: TArray<TBytes>;
    CheckHostName: Boolean;
    // must-staple (RFC 7633 4.3.3) binds only to a server leaf on the initial handshake the client
    // asked to staple; both are left unset (never-must-staple) for a client certificate
    StatusRequestOffered: Boolean;
    Occasion: TVerificationOccasion;
    // the augment-only reject hook, carried so a delegate honours it the same way the built-in
    // verifier does; InsecureSkipVerify is deliberately NOT a delegate bypass (a delegate never
    // skips the OS engine it was chosen for), only the reject callback is applied
    Dangerous: TDangerousTrust;
    DeadlineMs: Cardinal;
    class function FromServerContext(const AContext: TServerTrustContext;
      AFetch: TSystemTrustFetch): TOSDelegatePolicy; static;
    class function FromClientContext(const AContext: TClientTrustContext;
      AFetch: TSystemTrustFetch): TOSDelegatePolicy; static;
    /// <summary>The live re-check policy for the server certificate a client verifies: the roots
    /// and the distrust set come from ARootsOf when it is the OS verifier source (the config's
    /// own, or the one a host source decorates), else from the config's trust store. Raises when
    /// ARootsOf is neither the OS source nor backed by a trust store, since the roots it trusts
    /// cannot be read.</summary>
    class function FromClientConfig(const AConfig: ITlsClientConfig;
      const ARootsOf: IServerCertificateVerifierSource): TOSDelegatePolicy; static;
    /// <summary>The live re-check policy for the client certificate a server verifies: the
    /// client-CA store is the exclusive root.</summary>
    class function FromServerConfig(const AConfig: ITlsServerConfig): TOSDelegatePolicy; static;
  strict private
    class function FromCommonConfig(const AConfig: ITlsCommonConfig): TOSDelegatePolicy; static;
  end;

  /// <summary>The server evaluation with OS and host roots, the same on every engine. An
  /// engine with NativeAnchorUnion is asked once with the roots; any other first evaluates against the
  /// OS roots and, only when that failed for want of a trust anchor, again with the host roots as the
  /// exclusive root, whose verdict then stands (its alert too, unless it also found no anchor). A path
  /// that holds an ADistrusted certificate is refused on every accepted path, whichever root ended it
  /// (a host distrust entry must bind OS-rooted paths as well as host-rooted ones). A request with
  /// Anchors on an engine that cannot honour them as the exclusive root is refused with
  /// internal_error before the engine is called, so it is never judged against the OS
  /// roots.</summary>
  TDelegateEvaluation = class sealed(TObject)
  public
    class function EvaluateServer(const AEngine: IPlatformChainEngine;
      const ARequest: TPlatformChainRequest; const ADistrusted: TArray<TBytes>;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>True when any certificate of APath is byte-equal to one of ADistrusted.</summary>
    class function PathIsDistrusted(const APath, ADistrusted: TArray<TBytes>): Boolean; static;
    /// <summary>ACerts from index AFirst on, minus any ADistrusted certificate (earlier entries are
    /// kept): the client path withholds them so a platform that reports no path cannot use them.
    /// Mirrors TCertificateVerifier.WithoutDistrusted, which works on the built-in store and its
    /// withheld flag; this one takes the raw DER list the OS delegate carries. AWithheld is only
    /// ever set to True: the caller initialises it.</summary>
    class function WithoutDistrusted(const ACerts, ADistrusted: TArray<TBytes>; AFirst: Int32;
      var AWithheld: Boolean): TArray<TBytes>; static;
    /// <summary>Gives a client result whose engine reported no anchor (PolicyExempt empty) the path
    /// the portable validator builds from the distrust-filtered AChain and AIntermediates to the
    /// policy's AnchorStore at the policy clock (system time when nil), ending at the anchor, which
    /// becomes the one exempt certificate (the leaf itself when it is the anchor); a result that
    /// already carries an anchor is returned as is. False with the validator's alert when no path
    /// builds (unknown_ca read as bad_certificate when AWithheld, the built-in rule) or when the
    /// built path holds a distrusted certificate (bad_certificate: the built path is re-encoded, so
    /// the byte filter alone cannot be trusted); internal_error without a provider.</summary>
    class function AnchorClientPath(const APolicy: TOSDelegatePolicy;
      const AChain, AIntermediates: TArray<TBytes>; AWithheld: Boolean;
      var AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean; static;
  end;

  /// <summary>What every OS delegate does around its platform engine, matching each platform's order:
  /// the platform builds and trusts the path; the name constraints of its anchor and intermediates
  /// are enforced first, as no platform is trusted to seed the anchor's own; an engine that renders
  /// its own revocation outcome has it decided (by the one revocation-decision table at the
  /// configured posture) before the chain-algorithm/key-strength policy, so a chain that is both
  /// revoked and weak reports the revocation alert; an engine that renders none runs strength first
  /// and decides revocation from the handshake staple. A definitive stapled Revoked always wins under
  /// every posture, and an indeterminate case defers to the async park only when a live fetch will
  /// decide it there. RFC 7633 must-staple is enforced, then the leaf SANs are matched here (SAN-only,
  /// RFC 9525) for every engine - the platform's own host match is never trusted to stand in for it.
  /// Fail-closed throughout.</summary>
  TOSDelegateVerifierBase = class abstract(TInterfacedObject)
  strict private
    FEngine: IPlatformChainEngine;
    FPolicy: TOSDelegatePolicy;
    function DeferToLive: Boolean;
    function RevocationCheck: TPlatformRevocationCheck;
  strict protected
    function BuildRequest(const AChain: TArray<TBytes>; const AServerName: TServerName;
      const AStaple: TBytes): TPlatformChainRequest;
    /// <summary>The shared tail after a True engine result: name constraints -> engine revocation ->
    /// strength -> end entity -> staple -> identity.</summary>
    function Complete(const AResult: TPlatformChainResult; const AServerName: TServerName;
      const AStaple: TBytes; out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>Runs the configured augment-only reject hook last, over a chain the engine already
    /// trusted; a rejection clears AVerified and reports certificate_unknown (mirrors the built-in
    /// verifier). No-op when no callback is configured.</summary>
    function ApplyDangerous(const AChain: TArray<TBytes>; const AHostName: string;
      var AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
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

  /// <summary>A handshake whose engine reports no anchor has its path built by the portable
  /// validator to the configured client-CA anchors.</summary>
  TOSDelegateClientVerifier = class sealed(TOSDelegateVerifierBase, IClientCertificateVerifier)
  public
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>The OS delegate's verifier source for either role: builds a delegate verifier around the
  /// platform engine from the connection's trust context, so posture, clock, strength policy and (for
  /// a client certificate) the exclusive client-CA anchors are injected the same way the built-in
  /// verifier receives them. AFetch fixes the inline behaviour: CacheOnly (no socket) or Live (an
  /// indeterminate revocation defers to the async park; so does a cache-only one when the
  /// live-revocation verdict is armed). The server role trusts AHostRoots with the OS roots
  /// (OsAndHostRoots) or alone (HostRoots: one pass, the OS roots never vouch; OS distrust still
  /// applies), refusing a path through any ADistrusted certificate (the factory adds the OS list to
  /// the host's where the platform exposes one); a distrusted host root is not handed to the engine.
  /// The source holds its own copy of the arrays and
  /// hands out copies. Under OsAndHostRoots the engine is checked against the host roots as given,
  /// and when the distrust set then removes every one the source trusts the OS roots only. Refuses
  /// at construction a Live fetch on an engine without live fetch, host
  /// roots on an engine that can trust neither with the OS roots nor alone, HostRoots without roots
  /// or on an engine without exclusive server roots, and at verifier creation a Live fetch without
  /// the live-revocation verdict, or - for an engine that renders no revocation outcome - a Hard
  /// client posture without it.</summary>
  TOSVerifierSource = class sealed(TInterfacedObject, IServerCertificateVerifierSource,
    IClientCertificateVerifierSource)
  strict private
    FEngine: IPlatformChainEngine;
    FFetch: TSystemTrustFetch;
    FAnchors: TArray<TBytes>;
    FExtraAnchors: TArray<TBytes>;
    FDistrusted: TArray<TBytes>;
  public
    constructor Create(const AEngine: IPlatformChainEngine; AFetch: TSystemTrustFetch;
      AScope: TSystemTrustRootScope; const AHostRoots, ADistrusted: TArray<TBytes>);
    function CreateServerVerifier(const AContext: TServerTrustContext): IServerCertificateVerifier;
    /// <summary>The exclusive server trust root (empty = the OS roots apply). The three roots
    /// accessors let the live re-check build against the same roots as the inline pass; all are
    /// empty for a client-only source. A stapled revocation response may be decided by the
    /// configured PKIX provider instead of the OS.</summary>
    function Anchors: TArray<TBytes>;
    /// <summary>Host roots trusted with the OS roots.</summary>
    function ExtraAnchors: TArray<TBytes>;
    /// <summary>The distrust set the source was built with (the host's, plus the OS list where the
    /// platform exposes one and the factory read it), refused on any accepted path.</summary>
    function Distrusted: TArray<TBytes>;
    function CreateClientVerifier(const AContext: TClientTrustContext): IClientCertificateVerifier;
  end;

  /// <summary>The OS-native live-revocation resolver over a platform engine: re-runs the engine with
  /// network fetch on (revocation only, requiring a positive response so an indeterminate surfaces)
  /// off the engine thread in the async park, enforces the name constraints and applies the strength
  /// policy over the path it built (for a client engine that reports no anchor, the path the portable
  /// validator builds to the configured anchors), and hands the tri-state outcome to the shared
  /// verdict. Bound to one certificate role. Host-owned.</summary>
  TOSDelegateLiveResolver = class sealed(TOSLiveRevocationResolverBase)
  strict private
    FEngine: IPlatformChainEngine;
    FPolicy: TOSDelegatePolicy;
  strict protected
    function EvaluateLive(const AChain: TArray<TBytes>; const AHostName: string;
      const AStaple: TBytes; ADeadlineMs: Cardinal; out AOutcome: TLiveRevocationOutcome;
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
  Result.ChainLimits := AContext.ChainLimits;
  Result.AdvertisedSchemes := AContext.AdvertisedSignatureSchemes;
  Result.CheckHostName := AContext.CheckHostName;
  Result.Dangerous := AContext.Dangerous;
  Result.Intermediates := AContext.Intermediates;
  // carry the must-staple binding inputs so the delegate enforces RFC 7633 as the built-in does
  Result.StatusRequestOffered := AContext.StatusRequestOffered;
  Result.Occasion := AContext.Occasion;
  // the source overlays its own roots; the context carries none
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
  Result.ChainLimits := AContext.ChainLimits;
  Result.AdvertisedSchemes := AContext.AdvertisedSignatureSchemes;
  Result.Dangerous := AContext.Dangerous;
  Result.Intermediates := AContext.Intermediates;
  // a client certificate carries no server name to match
  Result.CheckHostName := False;
  // a client certificate is never must-staple (the client never asks to staple it)
  Result.StatusRequestOffered := False;
  Result.Occasion := TVerificationOccasion.InitialHandshake;
  // a client certificate is authenticated only against the configured client-CA anchors
  Result.Anchors := nil;
  Result.Distrusted := nil;
  if AContext.TrustStore <> nil then
  begin
    Result.AnchorStore := AContext.TrustStore;
    Result.Anchors := AContext.TrustStore.RootCertificates;
    Result.Distrusted := AContext.TrustStore.DistrustedCertificates;
  end;
  Result.DeadlineMs := 0;
end;

class function TOSDelegatePolicy.FromCommonConfig(const AConfig: ITlsCommonConfig)
  : TOSDelegatePolicy;
begin
  Result := Default(TOSDelegatePolicy);
  Result.Pkix := AConfig.Pkix;
  Result.Clock := AConfig.Clock;
  Result.Posture := AConfig.RevocationPosture;
  Result.Fetch := TSystemTrustFetch.Live;
  Result.StrengthPolicy := AConfig.CertificateStrengthPolicy;
  Result.ChainLimits := AConfig.CertificateChainLimits;
  Result.AdvertisedSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
  Result.DeadlineMs := AConfig.AsyncCertificateVerdict.DeadlineMs;
  Result.Intermediates := AConfig.IntermediateCertificates;
end;

class function TOSDelegatePolicy.FromClientConfig(const AConfig: ITlsClientConfig;
  const ARootsOf: IServerCertificateVerifierSource): TOSDelegatePolicy;
var
  LSource: TOSVerifierSource;
begin
  Result := FromCommonConfig(AConfig);
  Result.CheckHostName := AConfig.CheckServerName;
  // the live pass uses the roots of the inline one, which only the OS source has
  if ARootsOf is TOSVerifierSource then
  begin
    LSource := ARootsOf as TOSVerifierSource;
    Result.Anchors := LSource.Anchors;
    Result.ExtraAnchors := LSource.ExtraAnchors;
    Result.Distrusted := LSource.Distrusted;
  end
  else if AConfig.TrustStore <> nil then
  begin
    Result.Anchors := AConfig.TrustStore.RootCertificates;
    Result.Distrusted := AConfig.TrustStore.DistrustedCertificates;
  end
  // the built-in source with no store is a PSK-only or skip-verify config: no server certificate
  else if ARootsOf is TBuiltInServerVerifierSource then
    raise EArgumentTlsLibException.CreateRes(@SLiveNeedsServerVerification)
  // a wrapped source would be re-checked against the OS roots while it trusted others
  else if ARootsOf <> nil then
    raise EArgumentTlsLibException.CreateRes(@SLiveNeedsKnownRoots);
end;

class function TOSDelegatePolicy.FromServerConfig(const AConfig: ITlsServerConfig)
  : TOSDelegatePolicy;
begin
  Result := FromCommonConfig(AConfig);
  // a client certificate carries no server name to match
  Result.CheckHostName := False;
  if AConfig.TrustStore <> nil then
  begin
    Result.AnchorStore := AConfig.TrustStore;
    Result.Anchors := AConfig.TrustStore.RootCertificates;
    Result.Distrusted := AConfig.TrustStore.DistrustedCertificates;
  end;
end;

{ TDelegateEvaluation }

class function TDelegateEvaluation.EvaluateServer(const AEngine: IPlatformChainEngine;
  const ARequest: TPlatformChainRequest; const ADistrusted: TArray<TBytes>;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LCapabilities: TPlatformChainCapabilities;
  LExclusive: TPlatformChainRequest;
  LExclusiveResult: TPlatformChainResult;
  LExclusiveAlert: TTlsAlertDescription;
begin
  LCapabilities := AEngine.Capabilities;
  // an engine that ignores Anchors would judge the chain against the OS roots instead
  if (System.Length(ARequest.Anchors) > 0) and
    not (TPlatformChainCapability.ExclusiveServerAnchors in LCapabilities) then
  begin
    AResult := Default(TPlatformChainResult);
    AAlert := TTlsAlertDescription.InternalError;
    Exit(False);
  end;
  // an exclusive Anchors already is the host's choice of roots, so only the OS-roots case has a union
  if (System.Length(ARequest.ExtraAnchors) = 0) or (System.Length(ARequest.Anchors) > 0) then
    Result := AEngine.EvaluateServer(ARequest, AResult, AAlert)
  else
  begin
    Result := AEngine.EvaluateServer(ARequest, AResult, AAlert);
    if (not Result) and (AResult.Failure = TPlatformChainFailure.NoTrustAnchor) and
      (TPlatformChainCapability.ExclusiveServerAnchors in LCapabilities) and
      not (TPlatformChainCapability.NativeAnchorUnion in LCapabilities) then
    begin
      LExclusive := ARequest;
      LExclusive.Anchors := ARequest.ExtraAnchors;
      LExclusive.ExtraAnchors := nil;
      Result := AEngine.EvaluateServer(LExclusive, LExclusiveResult, LExclusiveAlert);
      // a second evaluation that found no anchor either leaves the first one's verdict standing
      if Result or (LExclusiveResult.Failure <> TPlatformChainFailure.NoTrustAnchor) then
      begin
        AResult := LExclusiveResult;
        AAlert := LExclusiveAlert;
      end;
    end;
  end;
  if Result and TDelegateEvaluation.PathIsDistrusted(AResult.Path, ADistrusted) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Result := False;
  end;
end;

class function TDelegateEvaluation.PathIsDistrusted(const APath, ADistrusted: TArray<TBytes>)
  : Boolean;
var
  LPath, LDistrusted: Int32;
begin
  for LPath := 0 to System.High(APath) do
    for LDistrusted := 0 to System.High(ADistrusted) do
      if TArrayUtilities.AreEqual(APath[LPath], ADistrusted[LDistrusted]) then
        Exit(True);
  Result := False;
end;

class function TDelegateEvaluation.WithoutDistrusted(const ACerts, ADistrusted: TArray<TBytes>;
  AFirst: Int32; var AWithheld: Boolean): TArray<TBytes>;
var
  LI, LJ, LCount: Int32;
  LKeep: Boolean;
begin
  SetLength(Result, System.Length(ACerts));
  LCount := 0;
  for LI := 0 to System.High(ACerts) do
  begin
    LKeep := True;
    if LI >= AFirst then
      for LJ := 0 to System.High(ADistrusted) do
        if TArrayUtilities.AreEqual(ACerts[LI], ADistrusted[LJ]) then
        begin
          LKeep := False;
          AWithheld := True;
          Break;
        end;
    if LKeep then
    begin
      Result[LCount] := ACerts[LI];
      Inc(LCount);
    end;
  end;
  SetLength(Result, LCount);
end;

class function TDelegateEvaluation.AnchorClientPath(const APolicy: TOSDelegatePolicy;
  const AChain, AIntermediates: TArray<TBytes>; AWithheld: Boolean;
  var AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LClock: ITlsClock;
  LPath: TArray<TBytes>;
begin
  if System.Length(AResult.PolicyExempt) > 0 then
    Exit(True);
  if APolicy.Pkix = nil then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit(False);
  end;
  LClock := APolicy.Clock;
  if LClock = nil then
    LClock := TSystemClock.Create as ITlsClock;
  LPath := AChain;
  try
    APolicy.Pkix.PathValidation.ValidateCertificatePath(AChain, APolicy.AnchorStore,
      AIntermediates, TDateTimeUtilities.UnixMsToDateTime(Int64(LClock.NowUnixMillis)),
      TCertKeyPurpose.ClientAuth, LPath);
  except
    on E: EFatalAlertTlsLibException do
    begin
      AAlert := E.AlertDescription;
      if AWithheld and (AAlert = TTlsAlertDescription.UnknownCa) then
        AAlert := TTlsAlertDescription.BadCertificate;
      Exit(False);
    end;
  end;
  if PathIsDistrusted(LPath, APolicy.Distrusted) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  AResult.Path := LPath;
  AResult.PolicyExempt := TArray<TBytes>.Create(LPath[System.High(LPath)]);
  Result := True;
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
  // an armed live-revocation verdict always parks a delegate, so a cache-only indeterminate is left to
  // it rather than rejected inline under Hard
  Result := (FPolicy.Fetch = TSystemTrustFetch.Live) or
    (FPolicy.Deferral = TVerdictDeferral.LiveRevocation);
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

function TOSDelegateVerifierBase.BuildRequest(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AStaple: TBytes): TPlatformChainRequest;
begin
  Result := Default(TPlatformChainRequest);
  Result.Chain := AChain;
  Result.Anchors := FPolicy.Anchors;
  Result.ExtraAnchors := FPolicy.ExtraAnchors;
  Result.Intermediates := FPolicy.Intermediates;
  // with the name check off, withhold the host from an engine that matches it internally so it does
  // not reject a name mismatch the built-in verifier would have skipped (Complete skips the re-check)
  if (not FPolicy.CheckHostName) and
    (TPlatformChainCapability.DnsIdentity in FEngine.Capabilities) then
    Result.ServerName := Default(TServerName)
  else
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
  LRoots: TArray<TBytes>;
begin
  AVerified := Default(TVerifiedChain);
  // without a provider or a built path there is nothing to decide over - fail closed
  if (FPolicy.Pkix = nil) or (System.Length(AResult.Path) = 0) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit(False);
  end;
  // path validity (name constraints) precedes revocation and strength, as in the built-in verifier
  if TDelegatePostChecks.RejectNameConstraintViolation(FPolicy.Pkix, AResult.Path, AAlert) then
    Exit(False);
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
  // a CA certificate is admitted as the end entity only when it is itself one of these roots
  LRoots := TArrayUtilities.Concat<TBytes>(AResult.PolicyExempt, FPolicy.Anchors);
  LRoots := TArrayUtilities.Concat<TBytes>(LRoots, FPolicy.ExtraAnchors);
  if not TEndEntityPolicy.Admits(FPolicy.Pkix.Certificates, AResult.Path, LRoots, AAlert) then
    Exit(False);
  // a definitive stapled Revoked overrides under every posture (a staple the engine did not fold in,
  // e.g. under Off); an engine with no revocation outcome of its own decides revocation from it here
  if TPlatformChainCapability.CachedRevocation in Engine.Capabilities then
  begin
    if TDelegatePostChecks.RejectStapledRevoked(FPolicy.Pkix, FPolicy.Clock, AResult.Path,
      AStaple, AAlert) then
      Exit(False);
  end
  else if not TRevocationDecision.Decide(TDelegatePostChecks.StapleOutcome(FPolicy.Pkix,
    FPolicy.Clock, AResult.Path, AStaple), FPolicy.Posture, DeferToLive, AAlert) then
    Exit(False);
  // RFC 7633: the TLS Feature well-formedness is a hard invariant for either role; a must-staple
  // server leaf additionally demands a current Good staple when the client asked to staple on the
  // initial handshake. No OS engine enforces this, so the library does (built-in verifier parity)
  if TDelegatePostChecks.RejectMustStaple(FPolicy.Pkix, FPolicy.Clock, AResult.Path, AStaple,
    FPolicy.StatusRequestOffered, FPolicy.Occasion, AAlert) then
    Exit(False);
  // identity: the library matches the leaf's SANs itself (SAN-only, RFC 9525) rather than trust an
  // engine that may fall back to the deprecated subject CN; the host still reached the engine for
  // name-constraint checks. An empty name (a client certificate) never fires, and with the name
  // check off there is nothing to match - built-in verifier parity either way
  if FPolicy.CheckHostName then
    if TDelegatePostChecks.RejectNameMismatch(AServerName, FPolicy.Pkix, AResult.Path, AAlert) then
      Exit(False);
  AVerified.Path := AResult.Path;
  AVerified.Outcome := TVerificationOutcome.Trusted;
  Result := True;
end;

function TOSDelegateVerifierBase.ApplyDangerous(const AChain: TArray<TBytes>;
  const AHostName: string; var AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // augment-only: the hook can only additionally reject a chain the engine trusted, never rescue one
  // it rejected (a rejection already returned)
  Result := TVerifyCallbackGate.Admits(FPolicy.Dangerous.VerifyCallback, AChain, AVerified,
    AHostName, AAlert);
  if not Result then
    AVerified := Default(TVerifiedChain);
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
  // resource caps before the OS engine sees the chain, as the built-in verifier does
  if (System.Length(AChain) = 0) or not Policy.ChainLimits.AdmitsChain(AChain) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  // an empty server name cannot be matched, so fail closed under an enabled name check rather than
  // let the engine trust a chain whose identity was never checked (built-in parity)
  if Policy.CheckHostName and AServerName.IsEmpty then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  LRequest := BuildRequest(AChain, AServerName, AOcspStaple);
  if not TDelegateEvaluation.EvaluateServer(Engine, LRequest, Policy.Distrusted, LResult,
    AAlert) then
    Exit(False);
  if not Complete(LResult, AServerName, AOcspStaple, AVerified, AAlert) then
    Exit(False);
  Result := ApplyDangerous(AChain, AServerName.ToString, AVerified, AAlert);
end;

{ TOSDelegateClientVerifier }

function TOSDelegateClientVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
var
  LRequest: TPlatformChainRequest;
  LResult: TPlatformChainResult;
  LNoName: TServerName;
  LWithheld: Boolean;
begin
  AVerified := Default(TVerifiedChain);
  if (System.Length(AChain) = 0) or not Policy.ChainLimits.AdmitsChain(AChain) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  LNoName := Default(TServerName);
  LRequest := BuildRequest(AChain, LNoName, nil);
  // withhold distrusted intermediates: an engine that reports no path (Android) hides them
  LWithheld := False;
  LRequest.Chain := TDelegateEvaluation.WithoutDistrusted(AChain, Policy.Distrusted, 1, LWithheld);
  LRequest.Intermediates := TDelegateEvaluation.WithoutDistrusted(Policy.Intermediates,
    Policy.Distrusted, 0, LWithheld);
  if not Engine.EvaluateClient(LRequest, LResult, AAlert) then
  begin
    // built-in parity: an unknown CA once a distrusted certificate is withheld is bad_certificate
    if LWithheld and (AAlert = TTlsAlertDescription.UnknownCa) then
      AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  if TDelegateEvaluation.PathIsDistrusted(LResult.Path, Policy.Distrusted) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  if not TDelegateEvaluation.AnchorClientPath(Policy, LRequest.Chain, LRequest.Intermediates,
    LWithheld, LResult, AAlert) then
    Exit(False);
  if not Complete(LResult, LNoName, nil, AVerified, AAlert) then
    Exit(False);
  // a client certificate carries no host, so the augment hook sees an empty name (built-in parity)
  Result := ApplyDangerous(AChain, '', AVerified, AAlert);
end;

{ TOSVerifierSource }

constructor TOSVerifierSource.Create(const AEngine: IPlatformChainEngine;
  AFetch: TSystemTrustFetch; AScope: TSystemTrustRootScope;
  const AHostRoots, ADistrusted: TArray<TBytes>);
var
  LStore: ITrustAnchorStore;
  LUsable: TArray<TBytes>;
begin
  inherited Create;
  if (AFetch = TSystemTrustFetch.Live) and
    not (TPlatformChainCapability.LiveFetch in AEngine.Capabilities) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  FAnchors := nil;
  FExtraAnchors := nil;
  // a distrusted host root is never handed to the engine, so no path is built through it
  LStore := TTrustAnchorStore.Create(AHostRoots, ADistrusted) as ITrustAnchorStore;
  LUsable := LStore.RootCertificates;
  if AScope = TSystemTrustRootScope.HostRoots then
  begin
    if System.Length(LUsable) = 0 then
      raise EArgumentTlsLibException.CreateRes(@SHostRootsNeedRoots);
    if not (TPlatformChainCapability.ExclusiveServerAnchors in AEngine.Capabilities) then
      raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SEngineCannotTrustHostRootsAlone);
    FAnchors := LUsable;
  end
  else
  begin
    // judged on the raw roots so the refusal does not depend on the host's runtime distrust list
    if (System.Length(AHostRoots) > 0) and
      (AEngine.Capabilities * [TPlatformChainCapability.NativeAnchorUnion,
      TPlatformChainCapability.ExclusiveServerAnchors] = []) then
      raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SEngineCannotTrustOsAndHostRoots);
    FExtraAnchors := LUsable;
  end;
  FEngine := AEngine;
  FFetch := AFetch;
  FDistrusted := TArrayUtilities.DeepCopy<Byte>(ADistrusted);
end;

function TOSVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
var
  LPolicy: TOSDelegatePolicy;
begin
  if TDelegatePostChecks.LiveNeedsLiveRevocation(FFetch, AContext.Deferral) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SLiveNeedsLiveRevocationVerdict);
  LPolicy := TOSDelegatePolicy.FromServerContext(AContext, FFetch);
  LPolicy.Anchors := FAnchors;
  LPolicy.ExtraAnchors := FExtraAnchors;
  LPolicy.Distrusted := FDistrusted;
  Result := TOSDelegateServerVerifier.Create(FEngine, LPolicy) as IServerCertificateVerifier;
end;

function TOSVerifierSource.Anchors: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FAnchors);
end;

function TOSVerifierSource.ExtraAnchors: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FExtraAnchors);
end;

function TOSVerifierSource.Distrusted: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FDistrusted);
end;

function TOSVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LPolicy: TOSDelegatePolicy;
begin
  if TDelegatePostChecks.LiveNeedsLiveRevocation(FFetch, AContext.Deferral) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SLiveNeedsLiveRevocationVerdict);
  // an engine that renders no cached revocation outcome cannot satisfy a Hard client posture without
  // the live-revocation verdict (a client certificate is never stapled)
  if not (TPlatformChainCapability.CachedRevocation in FEngine.Capabilities) and
    TRevocationDecision.HardNeedsLiveRevocation(AContext.RevocationPosture,
    AContext.Deferral = TVerdictDeferral.LiveRevocation) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SHardNeedsLiveRevocationVerdict);
  LPolicy := TOSDelegatePolicy.FromClientContext(AContext, FFetch);
  Result := TOSDelegateClientVerifier.Create(FEngine, LPolicy) as IClientCertificateVerifier;
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
  const AHostName: string; const AStaple: TBytes; ADeadlineMs: Cardinal;
  out AOutcome: TLiveRevocationOutcome; out ARejectAlert: TTlsAlertDescription): Boolean;
var
  LRequest: TPlatformChainRequest;
  LResult: TPlatformChainResult;
  LTrusted, LWithheld: Boolean;
begin
  LRequest := Default(TPlatformChainRequest);
  LRequest.Chain := AChain;
  LRequest.Anchors := FPolicy.Anchors;
  LRequest.ExtraAnchors := FPolicy.ExtraAnchors;
  LRequest.Intermediates := FPolicy.Intermediates;
  LRequest.OcspStaple := AStaple;
  LRequest.Revocation := TPlatformRevocationCheck.RequirePositive;
  LRequest.NetworkAllowed := True;
  LRequest.Clock := FPolicy.Clock;
  // the tighter of the resolver's own budget and the host's for this park; 0 means none
  LRequest.DeadlineMs := FPolicy.DeadlineMs;
  if (ADeadlineMs <> 0) and ((LRequest.DeadlineMs = 0) or (ADeadlineMs < LRequest.DeadlineMs)) then
    LRequest.DeadlineMs := ADeadlineMs;
  // the base already stripped an IP literal via OsHostName, so a non-empty host is a DNS name;
  // withhold it from a name-matching engine when the name check is off, as BuildRequest does
  if (AHostName <> '') and (FPolicy.CheckHostName or
    not (TPlatformChainCapability.DnsIdentity in FEngine.Capabilities)) then
    LRequest.ServerName := TServerName.DnsName(AHostName)
  else
    LRequest.ServerName := Default(TServerName);
  if FExpectedPeer = TPeerRole.Server then
    LTrusted := TDelegateEvaluation.EvaluateServer(FEngine, LRequest, FPolicy.Distrusted,
      LResult, ARejectAlert)
  else
  begin
    LWithheld := False;
    LRequest.Chain := TDelegateEvaluation.WithoutDistrusted(AChain, FPolicy.Distrusted, 1,
      LWithheld);
    LRequest.Intermediates := TDelegateEvaluation.WithoutDistrusted(FPolicy.Intermediates,
      FPolicy.Distrusted, 0, LWithheld);
    LTrusted := FEngine.EvaluateClient(LRequest, LResult, ARejectAlert);
    if (not LTrusted) and LWithheld and (ARejectAlert = TTlsAlertDescription.UnknownCa) then
      ARejectAlert := TTlsAlertDescription.BadCertificate;
    if LTrusted and TDelegateEvaluation.PathIsDistrusted(LResult.Path, FPolicy.Distrusted) then
    begin
      ARejectAlert := TTlsAlertDescription.BadCertificate;
      LTrusted := False;
    end;
    if LTrusted and not TDelegateEvaluation.AnchorClientPath(FPolicy, LRequest.Chain,
      LRequest.Intermediates, LWithheld, LResult, ARejectAlert) then
      LTrusted := False;
  end;
  if not LTrusted then
    Exit(False);
  if TDelegatePostChecks.RejectNameConstraintViolation(FPolicy.Pkix, LResult.Path,
    ARejectAlert) then
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
