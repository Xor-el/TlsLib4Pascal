{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCertificateVerifier;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpServerName,
  TlpEndpointIdentity,
  TlpCertificateLimits,
  TlpChainAlgorithmPolicy,
  TlpTrustPolicy,
  TlpCertificateStrengthPolicy,
  TlpDateTimeUtilities,
  TlpIClock,
  TlpTrustTypes,
  TlpICertificateTrust;

type
  /// <summary>The stapled OCSP outcome the trust decision acts on (RFC 6960): a current
  /// Good response, a definitive Revoked, or an indeterminate outcome (absent,
  /// unauthorized, unknown, or outside its validity window).</summary>
  // GoodUnbounded: a Good response with no nextUpdate, recent enough to accept inline but never
  // to settle revocation (a live check, when configured, must still run)
  TStapleVerdict = (GoodFresh, GoodUnbounded, Revoked, Indeterminate);

  /// <summary>A default in-memory trust store over a fixed set of root CA DERs.</summary>
  TTrustAnchorStore = class sealed(TInterfacedObject, ITrustAnchorStore)
  strict private
  var
    FRoots: TArray<TBytes>;
  public
    constructor Create(const ARoots: TArray<TBytes>);
    function RootCertificates: TArray<TBytes>;
  end;

  /// <summary>Unions several anchor sources: RootCertificates is the concatenation of
  /// every child store's roots, resolved on each call. Used when more than one anchor
  /// contribution is configured. (A harvested OS store is an immutable snapshot; per-call
  /// resolution matters only for a caller-supplied store whose own roots vary.)</summary>
  TUnionTrustAnchorStore = class sealed(TInterfacedObject, ITrustAnchorStore)
  strict private
  var
    FStores: TArray<ITrustAnchorStore>;
  public
    constructor Create(const AStores: TArray<ITrustAnchorStore>);
    function RootCertificates: TArray<TBytes>;
  end;

  /// <summary>
  /// The ordered certificate-trust pipeline (RFC 8446 4.4.2 / RFC 5280 / RFC 6125),
  /// fail-closed: the provider validates the chain to a trusted root for the role's
  /// extendedKeyUsage (certificate_expired / unknown_ca / bad_certificate /
  /// unsupported_certificate), then - for a server certificate - matches the leaf's SANs
  /// against the connected name (bad_certificate). One instance serves both roles: it
  /// verifies a server certificate for a client and a client certificate for a server.
  /// </summary>
  TCertificateVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier,
    IClientCertificateVerifier)
  strict private
  var
    FPkix: IPkixProvider;
    FClock: ITlsClock;
    FTrustStore: ITrustAnchorStore;
    FCheckHostName: Boolean;
    FChainLimits: TCertificateChainLimits;
    FRevocationPosture: TRevocationPosture;
    /// <summary>Untrusted intermediates that seed PKIX path building when the peer sends an
    /// incomplete chain; empty validates the chain exactly as received.</summary>
    FIntermediates: TArray<TBytes>;
    FDangerous: TDangerousTrust;
    /// <summary>How a verdict is deferred out-of-band. Only LiveRevocation defers an indeterminate
    /// stapled outcome to the resolver (the live OCSP/CRL fetch at the park); None and HostDecision
    /// decide it inline by the posture.</summary>
    FDeferral: TVerdictDeferral;
    /// <summary>Whether the client offered status_request, and whether this is the initial
    /// handshake or a resumption: must-staple binds only to an initial-handshake server
    /// certificate the client actually asked to have stapled (RFC 7633 4.3.3).</summary>
    FStatusRequestOffered: Boolean;
    FOccasion: TVerificationOccasion;
    /// <summary>The chain-algorithm policy (advertised-scheme filter + key-strength floors),
    /// applied only when the engine set it via SetChainAlgorithmPolicy; a verifier built through
    /// the bare constructors (no advertised set to filter against) does not run it.</summary>
    FChainPolicyEnabled: Boolean;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertisedSchemes: TArray<UInt16>;
    /// <summary>The injected clock as a UTC wall-clock instant, so every time-based cert
    /// check (chain validity, PKIX path date, OCSP responder validity) shares one source.</summary>
    function ValidationTimeUtc: TDateTime;
    /// <summary>The built-in trust pipeline (chain caps, PKIX with the role's EKU, revocation,
    /// endpoint identity, pinning), run unless InsecureSkipVerify bypasses it. ACheckName
    /// enables the RFC 6125 match against AServerName (a server certificate only); AKeyPurpose
    /// is the extendedKeyUsage the path must carry.</summary>
    function VerifyPipeline(const AChain: TArray<TBytes>;
      const AServerName: TServerName; ACheckName: Boolean; const AOcspStaple: TBytes;
      AKeyPurpose: TCertKeyPurpose; out AValidatedChain: TArray<TBytes>;
      out ARevocationSettled: Boolean; out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>The stapled-OCSP revocation + must-staple step (RFC 6960 / RFC 7633),
    /// in-band only. A malformed TLS Feature extension is a hard bad_certificate. A
    /// definitive Revoked fails (certificate_revoked); a current Good passes. A must-staple
    /// leaf demands a current Good staple only when the client asked for one on the initial
    /// handshake (RFC 7633 4.3.3). An indeterminate outcome is deferred to the live-revocation
    /// resolver when one runs, else accepted under Soft/Off and rejected under Hard.</summary>
    function CheckRevocation(const AChain: TArray<TBytes>; const AOcspStaple: TBytes;
      AKeyPurpose: TCertKeyPurpose; out ASettled: Boolean;
      out AAlert: TTlsAlertDescription): Boolean;
  public
    /// <summary>The stapled OCSP verdict for a leaf (RFC 6960), shared by the built-in
    /// pipeline and an OS delegate that runs its own post-check: a current Good response, a
    /// definitive Revoked, or an indeterminate outcome (absent, unauthorized, unknown, or
    /// outside its validity window). A nil provider or clock cannot render a verdict, so it
    /// returns Indeterminate. AClock supplies both the responder-validity time and the
    /// freshness window.</summary>
    class function StapleVerdict(const APkix: IPkixProvider;
      const AClock: ITlsClock; const AChain: TArray<TBytes>;
      const AStaple: TBytes): TStapleVerdict; static;
    /// <summary>A verifier with the conservative default chain limits and soft-fail
    /// revocation. AClock backs the stapled-OCSP freshness window (RFC 6960).</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean); overload;
    /// <summary>A verifier with caller-tuned chain limits and revocation posture.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean;
      const AChainLimits: TCertificateChainLimits;
      ARevocationPosture: TRevocationPosture); overload;
    /// <summary>As above, plus the dangerous escape hatches (InsecureSkipVerify bypasses the
    /// built-in pipeline, and a VerifyCallback that can only additionally reject) and ADeferral:
    /// LiveRevocation defers an indeterminate stapled-revocation outcome to the out-of-band verdict
    /// resolver (live OCSP/CRL); None and HostDecision decide it inline by the posture.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean;
      const AChainLimits: TCertificateChainLimits;
      ARevocationPosture: TRevocationPosture;
      const ADangerous: TDangerousTrust;
      ADeferral: TVerdictDeferral); overload;
    /// <summary>As above, plus AIntermediates: untrusted intermediate certificates seeded into
    /// PKIX path building for a peer that sends an incomplete chain (e.g. a leaf-only server).
    /// They never anchor a path and never bypass validation; empty behaves exactly as the
    /// overload without it.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean;
      const AChainLimits: TCertificateChainLimits;
      ARevocationPosture: TRevocationPosture;
      const ADangerous: TDangerousTrust; ADeferral: TVerdictDeferral;
      const AIntermediates: TArray<TBytes>); overload;
    /// <summary>As above, plus the must-staple gating inputs: AStatusRequestOffered is whether the
    /// client offered status_request, and AOccasion whether this is the initial handshake or a
    /// resumption. Must-staple (RFC 7633) is enforced only for an initial-handshake server
    /// certificate the client asked to have stapled.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean;
      const AChainLimits: TCertificateChainLimits;
      ARevocationPosture: TRevocationPosture;
      const ADangerous: TDangerousTrust; ADeferral: TVerdictDeferral;
      const AIntermediates: TArray<TBytes>; AStatusRequestOffered: Boolean;
      AOccasion: TVerificationOccasion); overload;
    /// <summary>Turns on the chain-algorithm policy for this verifier: the peer chain must be
    /// signed only with a scheme in AAdvertised (and never MD5/SHA-1) and its keys must meet
    /// APolicy. The engine calls this from the verifier source with the connection's advertised
    /// signature schemes; a bare-constructed verifier leaves it off.</summary>
    procedure SetChainAlgorithmPolicy(const APolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// SPKI public-key pinning as a decorator over any server-certificate verifier (augments,
  /// never a bypass): the inner verifier must accept the chain AND some presented certificate's
  /// SubjectPublicKeyInfo SHA-256 must match a configured pin, else bad_certificate. Composing
  /// it over the source output pins uniformly over the built-in pipeline and an OS delegate.
  /// </summary>
  TPinningVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
  strict private
  var
    FInner: IServerCertificateVerifier;
    FPins: TArray<TBytes>;
    FCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    function PinsMatch(const AChain: TArray<TBytes>): Boolean;
  public
    constructor Create(const AInner: IServerCertificateVerifier;
      const APins: TArray<TBytes>; const ACryptoProvider: ICryptoProvider;
      const APkixProvider: IPkixProvider);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

implementation

{ TTrustAnchorStore }

constructor TTrustAnchorStore.Create(const ARoots: TArray<TBytes>);
begin
  inherited Create;
  FRoots := ARoots;
end;

function TTrustAnchorStore.RootCertificates: TArray<TBytes>;
var
  LI: Int32;
begin
  // a deep defensive copy: System.Copy alone shares the inner TBytes, so copy each
  // entry too - a caller cannot mutate the frozen trust store's certificates
  Result := nil;
  SetLength(Result, System.Length(FRoots));
  for LI := 0 to System.High(FRoots) do
    Result[LI] := System.Copy(FRoots[LI]);
end;

{ TUnionTrustAnchorStore }

constructor TUnionTrustAnchorStore.Create(const AStores: TArray<ITrustAnchorStore>);
begin
  inherited Create;
  FStores := AStores;
end;

function TUnionTrustAnchorStore.RootCertificates: TArray<TBytes>;
var
  LI, LJ, LPos, LTotal: Int32;
  LChildResults: TArray<TArray<TBytes>>;
begin
  SetLength(LChildResults, System.Length(FStores));
  LTotal := 0;
  for LI := 0 to System.High(FStores) do
  begin
    if FStores[LI] = nil then
      Continue;
    LChildResults[LI] := FStores[LI].RootCertificates;
    Inc(LTotal, System.Length(LChildResults[LI]));
  end;
  Result := nil;
  SetLength(Result, LTotal);
  LPos := 0;
  for LI := 0 to System.High(LChildResults) do
    for LJ := 0 to System.High(LChildResults[LI]) do
    begin
      Result[LPos] := LChildResults[LI][LJ];
      Inc(LPos);
    end;
end;

{ TCertificateVerifier }

constructor TCertificateVerifier.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean);
begin
  Create(APkix, AClock, ATrustStore, ACheckHostName,
    TCertificateChainLimits.Defaults, TRevocationPosture.Soft);
end;

constructor TCertificateVerifier.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean; const AChainLimits: TCertificateChainLimits;
  ARevocationPosture: TRevocationPosture);
var
  LNoDangerous: TDangerousTrust;
begin
  LNoDangerous := Default(TDangerousTrust);
  Create(APkix, AClock, ATrustStore, ACheckHostName, AChainLimits,
    ARevocationPosture, LNoDangerous, TVerdictDeferral.None);
end;

constructor TCertificateVerifier.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean; const AChainLimits: TCertificateChainLimits;
  ARevocationPosture: TRevocationPosture;
  const ADangerous: TDangerousTrust; ADeferral: TVerdictDeferral);
begin
  Create(APkix, AClock, ATrustStore, ACheckHostName, AChainLimits,
    ARevocationPosture, ADangerous, ADeferral, nil);
end;

constructor TCertificateVerifier.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean; const AChainLimits: TCertificateChainLimits;
  ARevocationPosture: TRevocationPosture;
  const ADangerous: TDangerousTrust; ADeferral: TVerdictDeferral;
  const AIntermediates: TArray<TBytes>);
begin
  Create(APkix, AClock, ATrustStore, ACheckHostName, AChainLimits,
    ARevocationPosture, ADangerous, ADeferral, AIntermediates, False,
    TVerificationOccasion.InitialHandshake);
end;

constructor TCertificateVerifier.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean; const AChainLimits: TCertificateChainLimits;
  ARevocationPosture: TRevocationPosture;
  const ADangerous: TDangerousTrust; ADeferral: TVerdictDeferral;
  const AIntermediates: TArray<TBytes>; AStatusRequestOffered: Boolean;
  AOccasion: TVerificationOccasion);
begin
  inherited Create;
  FPkix := APkix;
  FClock := AClock;
  FTrustStore := ATrustStore;
  FCheckHostName := ACheckHostName;
  FChainLimits := AChainLimits;
  FRevocationPosture := ARevocationPosture;
  FIntermediates := AIntermediates;
  FDangerous := ADangerous;
  FDeferral := ADeferral;
  FStatusRequestOffered := AStatusRequestOffered;
  FOccasion := AOccasion;
end;

function TCertificateVerifier.ValidationTimeUtc: TDateTime;
begin
  // UnixMsToDateTime yields a UTC instant
  Result := TDateTimeUtilities.UnixMsToDateTime(Int64(FClock.NowUnixMillis));
end;

procedure TCertificateVerifier.SetChainAlgorithmPolicy(
  const APolicy: TCertificateStrengthPolicy; const AAdvertised: TArray<UInt16>);
begin
  FStrengthPolicy := APolicy;
  FAdvertisedSchemes := AAdvertised;
  FChainPolicyEnabled := True;
end;

class function TCertificateVerifier.StapleVerdict(const APkix: IPkixProvider;
  const AClock: ITlsClock; const AChain: TArray<TBytes>;
  const AStaple: TBytes): TStapleVerdict;
var
  LStatus: TOcspStatus;
  LThisUpdate, LNextUpdate: TDateTime;
  LNowMs, LNextMs: Int64;
begin
  Result := TStapleVerdict.Indeterminate;
  // a public entry point: without a provider or a clock no verdict can be rendered
  if (APkix = nil) or (AClock = nil) then
    Exit;
  // a staple needs the issuer (the next chain entry) to authenticate it
  if (System.Length(AStaple) = 0) or (System.Length(AChain) < 2) then
    Exit;
  if not APkix.Revocation.ValidateOcspStaple(AChain[0], AChain[1], AStaple,
    TDateTimeUtilities.UnixMsToDateTime(Int64(AClock.NowUnixMillis)), LStatus,
    LThisUpdate, LNextUpdate) then
    Exit;
  if LStatus = TOcspStatus.Revoked then
  begin
    Result := TStapleVerdict.Revoked;
    Exit;
  end;
  if LStatus = TOcspStatus.Good then
  begin
    LNowMs := Int64(AClock.NowUnixMillis);
    if LNextUpdate = 0 then
      LNextMs := 0 // no nextUpdate carried
    else
      LNextMs := TDateTimeUtilities.DateTimeToUnixMs(LNextUpdate);
    case TRevocationDecision.OcspFreshness(LNowMs,
      TDateTimeUtilities.DateTimeToUnixMs(LThisUpdate), LNextMs) of
      TOcspFreshness.Fresh:
        Result := TStapleVerdict.GoodFresh;
      TOcspFreshness.Unbounded:
        Result := TStapleVerdict.GoodUnbounded;
    end;
  end;
  // an Unknown status, or a Good one outside its window, stays Indeterminate
end;

function TCertificateVerifier.CheckRevocation(const AChain: TArray<TBytes>;
  const AOcspStaple: TBytes; AKeyPurpose: TCertKeyPurpose; out ASettled: Boolean;
  out AAlert: TTlsAlertDescription): Boolean;
const
  // RFC 7633 TLS Feature id: status_request means the certificate is must-staple
  MustStapleFeature = UInt16(5);
var
  LFeatures: TArray<UInt16>;
  LMustStaple: Boolean;
  LVerdict: TStapleVerdict;
  LI: Int32;
begin
  // settled = a definitive, authenticated revocation verdict was reached inline (a current Good, or
  // a Revoked that rejects); an indeterminate outcome deferred to the live park is NOT settled
  ASettled := False;
  // the RFC 7633 TLS Feature extension well-formedness is a hard invariant, enforced
  // regardless of posture, role, or occasion: a value that is not a SEQUENCE OF INTEGER is fatal
  if not FPkix.Certificates.TlsFeatures(AChain[0], LFeatures) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Result := False;
    Exit;
  end;
  // must-staple binds only to a server certificate on the initial handshake that the client
  // asked to have stapled (RFC 7633 4.3.3): a client never asks to staple a client certificate,
  // no Certificate is on the wire on a resumption, and a client that did not offer status_request
  // cannot demand what it did not request
  LMustStaple := FStatusRequestOffered and
    (FOccasion = TVerificationOccasion.InitialHandshake) and
    (AKeyPurpose = TCertKeyPurpose.ServerAuth);
  if LMustStaple then
  begin
    LMustStaple := False;
    for LI := 0 to System.High(LFeatures) do
      if LFeatures[LI] = MustStapleFeature then
      begin
        LMustStaple := True;
        Break;
      end;
  end;

  LVerdict := StapleVerdict(FPkix, FClock, AChain, AOcspStaple);

  if LVerdict = TStapleVerdict.Revoked then
  begin
    // a definitive, authenticated revocation aborts under every posture: the posture
    // governs how an unknown/indeterminate outcome is treated, never a known Revoked in hand
    AAlert := TTlsAlertDescription.CertificateRevoked;
    Result := False;
    Exit;
  end;

  if LVerdict = TStapleVerdict.GoodFresh then
  begin
    // a current, authenticated Good settles revocation inline: a configured live-revocation park
    // would only re-fetch what the staple already answered, so the caller may skip it
    ASettled := True;
    Result := True;
    Exit;
  end;

  if LVerdict = TStapleVerdict.GoodUnbounded then
  begin
    // without nextUpdate the responder promises newer information at any time (RFC 6960 4.2.2.1),
    // so this Good satisfies the inline gate but does not stand in for a configured live check
    Result := True;
    Exit;
  end;

  // indeterminate outcome (no staple / unauthorized / unknown / stale):
  //  - a must-staple leaf still requires a current Good staple even under Soft/Off, and even
  //    when a live resolver exists (a live fetch does not satisfy a leaf that demands stapling,
  //    RFC 7633): always reject.
  //  - else, when the verdict is deferred to a live-revocation resolver (the live OCSP/CRL fetch
  //    at the park), accept here so the handshake reaches the park and the resolver renders the
  //    posture's verdict. This makes a Hard posture reachable for a staple-less peer (e.g. a
  //    client certificate, never stapled). A host-decision park does not defer the revocation
  //    gate: the posture still decides inline, as with no deferral.
  //  - else, decide inline by the posture: only Hard rejects.
  if LMustStaple then
  begin
    AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
    Result := False;
  end
  else
    Result := TRevocationDecision.Decide(TLiveRevocationOutcome.Indeterminate,
      FRevocationPosture, FDeferral = TVerdictDeferral.LiveRevocation, AAlert);
end;

function TCertificateVerifier.VerifyPipeline(const AChain: TArray<TBytes>;
  const AServerName: TServerName; ACheckName: Boolean; const AOcspStaple: TBytes;
  AKeyPurpose: TCertKeyPurpose; out AValidatedChain: TArray<TBytes>;
  out ARevocationSettled: Boolean; out AAlert: TTlsAlertDescription): Boolean;
var
  LI, LTotal: Int32;
  // the chain PKIX actually validated: when the peer sent an incomplete chain that path
  // building completed from the configured intermediates, this carries the assembled path
  // (with the recovered issuer), so revocation sees it rather than the bare leaf
  LEffectiveChain: TArray<TBytes>;
  LLeaf: IInspectedCertificate;
begin
  Result := False;
  AValidatedChain := nil;
  ARevocationSettled := False;
  AAlert := TTlsAlertDescription.BadCertificate;
  if System.Length(AChain) = 0 then
    Exit;
  // no configured anchor set means there is no basis to trust any certificate: surface the
  // precise alert rather than dereference a nil store (a PSK-only client is refused at Build,
  // so this is the belt-and-braces backstop)
  if FTrustStore = nil then
  begin
    AAlert := TTlsAlertDescription.UnknownCa;
    Exit;
  end;

  // resource caps before any PKIX work: an over-long chain or oversize certificate is
  // rejected up front (anti-DoS) rather than handed to the path builder
  if System.Length(AChain) > FChainLimits.MaxChainLength then
    Exit;
  LTotal := 0;
  for LI := 0 to System.High(AChain) do
  begin
    if System.Length(AChain[LI]) > FChainLimits.MaxCertificateLength then
      Exit;
    Inc(LTotal, System.Length(AChain[LI]));
    if LTotal > FChainLimits.MaxTotalChainLength then
      Exit;
  end;

  // path validation (validity + PKIX) is the provider's job; it raises the reason, and hands
  // back the chain it actually validated (the assembled path when it completed an incomplete one)
  LEffectiveChain := AChain;
  try
    FPkix.PathValidation.ValidateCertificatePath(AChain, FTrustStore.RootCertificates,
      FIntermediates, ValidationTimeUtc, AKeyPurpose, LEffectiveChain);
  except
    on E: EFatalAlertTlsLibException do
    begin
      AAlert := E.AlertDescription;
      Exit;
    end;
  end;

  // chain-algorithm policy over the validated chain: every non-anchor certificate must be
  // signed with an advertised scheme (MD5/SHA-1 refused outright) and meet the key-strength
  // floors. Post-PKIX so it sees the assembled path; the anchor exemption keys off the roots.
  if FChainPolicyEnabled and
    (not TChainAlgorithmPolicy.Check(FPkix.Certificates, LEffectiveChain,
    FTrustStore.RootCertificates, FStrengthPolicy, FAdvertisedSchemes, AAlert)) then
    Exit;

  // revocation via the stapled OCSP response (RFC 6960), in-band only; run over the validated
  // chain so a staple can be authenticated against a recovered issuer the peer did not send
  if not CheckRevocation(LEffectiveChain, AOcspStaple, AKeyPurpose, ARevocationSettled,
    AAlert) then
    Exit;

  // endpoint identity (RFC 6125) over the leaf's dNSName / iPAddress SANs (server cert only)
  if ACheckName then
  begin
    // an empty name cannot verify against anything; the factory fails closed before a
    // checking verifier is reached, so reject explicitly rather than rely on Matches
    if AServerName.IsEmpty then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;
    LLeaf := FPkix.Certificates.Parse(AChain[0]);
    if not TEndpointIdentity.Matches(AServerName, LLeaf.DnsNames, LLeaf.IpAddresses) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;
  end;

  // the path PKIX validated (with the anchor and any recovered issuer), so a pinning
  // decorator matches over the real chain of trust, not the certificates the peer sent
  AValidatedChain := LEffectiveChain;
  Result := True;
end;

function TCertificateVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LValidated: TArray<TBytes>;
  LSettled: Boolean;
begin
  Result := False;
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.BadCertificate;
  if System.Length(AChain) = 0 then
    Exit;
  // the loud escape hatch: skip the built-in pipeline entirely (tests / pinned dev peers)
  if FDangerous.InsecureSkipVerify then
    // with no path validation nothing binds AChain[1..] to the leaf, so a pin may only be a
    // leaf pin here: the validated chain is the leaf alone (never the peer-supplied rest). No
    // revocation ran, so the outcome stays Trusted (a configured live park still runs)
    AVerified.Path := TArray<TBytes>.Create(System.Copy(AChain[0]))
  else
  begin
    if not VerifyPipeline(AChain, AServerName, FCheckHostName, AOcspStaple,
      TCertKeyPurpose.ServerAuth, LValidated, LSettled, AAlert) then
      Exit;
    AVerified.Path := LValidated;
    if LSettled then
      AVerified.Outcome := TVerificationOutcome.RevocationSettledInline;
  end;
  // the augment-only hook runs last and can only additionally reject; it can never rescue a
  // chain the pipeline (when run) already rejected, since a rejection has returned above
  if Assigned(FDangerous.VerifyCallback) then
    if not FDangerous.VerifyCallback(AChain, AServerName.ToString) then
    begin
      // a custom augment verifier's rejection is an unspecified acceptability problem, not a
      // corrupt/bad-signature certificate: certificate_unknown, not bad_certificate (RFC 8446 6.2)
      AVerified := Default(TVerifiedChain);
      AAlert := TTlsAlertDescription.CertificateUnknown;
      Exit;
    end;
  Result := True;
end;

function TCertificateVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LValidated: TArray<TBytes>;
  LSettled: Boolean;
begin
  Result := False;
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.BadCertificate;
  if System.Length(AChain) = 0 then
    Exit;
  // a client certificate carries no host identity and is never stapled: verify the chain
  // for the clientAuth role, with no endpoint-identity match and no OCSP staple
  if FDangerous.InsecureSkipVerify then
    AVerified.Path := TArray<TBytes>.Create(System.Copy(AChain[0]))
  else
  begin
    if not VerifyPipeline(AChain, Default(TServerName), False, nil,
      TCertKeyPurpose.ClientAuth, LValidated, LSettled, AAlert) then
      Exit;
    AVerified.Path := LValidated;
    if LSettled then
      AVerified.Outcome := TVerificationOutcome.RevocationSettledInline;
  end;
  if Assigned(FDangerous.VerifyCallback) then
    if not FDangerous.VerifyCallback(AChain, '') then
    begin
      AVerified := Default(TVerifiedChain);
      AAlert := TTlsAlertDescription.CertificateUnknown;
      Exit;
    end;
  Result := True;
end;

{ TPinningVerifier }

constructor TPinningVerifier.Create(const AInner: IServerCertificateVerifier;
  const APins: TArray<TBytes>; const ACryptoProvider: ICryptoProvider;
  const APkixProvider: IPkixProvider);
begin
  inherited Create;
  FInner := AInner;
  FPins := APins;
  FCrypto := ACryptoProvider;
  FPkix := APkixProvider;
end;

function TPinningVerifier.PinsMatch(const AChain: TArray<TBytes>): Boolean;
var
  LHash: IHash;
  LSpki, LDigest: TBytes;
  LI, LJ: Int32;
begin
  Result := True;
  if System.Length(FPins) = 0 then
    Exit;
  // some certificate on the validated path must carry a pinned public key (SPKI-SHA256)
  for LI := 0 to System.High(AChain) do
  begin
    try
      LSpki := FPkix.Certificates.PublicKeyInfo(AChain[LI]);
    except
      // defensive: a parse/encode failure yields no SPKI, so the cert cannot match a pin - it
      // must never turn a pin decision into a raised internal_error
      on Exception do
        Continue;
    end;
    LHash := FCrypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
    LHash.Update(LSpki, 0, System.Length(LSpki));
    LDigest := LHash.DoFinal;
    for LJ := 0 to System.High(FPins) do
      if TArrayUtilities.AreEqual(LDigest, FPins[LJ]) then
        Exit;
  end;
  Result := False;
end;

function TPinningVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // pinning augments the inner verdict; it can only additionally reject. It matches the pin
  // against the chain the inner verifier actually validated (RFC 7469 6), never the presented
  // certificates, so an attacker cannot append a pinned leaf to a chain that validated by
  // another path.
  Result := FInner.VerifyServerCertificate(AChain, AServerName, AOcspStaple,
    AVerified, AAlert);
  if not Result then
    Exit;
  if not PinsMatch(AVerified.Path) then
  begin
    AVerified := Default(TVerifiedChain);
    AAlert := TTlsAlertDescription.BadCertificate;
    Result := False;
  end;
end;

end.
