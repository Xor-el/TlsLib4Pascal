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
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpEndpointIdentity,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpDateTimeUtilities,
  TlpIClock,
  TlpICertificateTrust;

type
  /// <summary>The stapled OCSP outcome the trust decision acts on (RFC 6960): a current
  /// Good response, a definitive Revoked, or an indeterminate outcome (absent,
  /// unauthorized, unknown, or outside its validity window).</summary>
  TStapleVerdict = (GoodFresh, Revoked, Indeterminate);

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
  /// every child store's roots, resolved on each call so a live source (e.g. an OS store)
  /// stays current. Used when more than one anchor contribution is configured.</summary>
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
  /// fail-closed: the provider validates the chain to a trusted root (certificate_expired
  /// / unknown_ca / bad_certificate), then the leaf's dNSName SAN is matched against the
  /// expected host (bad_certificate). All X.509 / PKIX work stays inside the provider.
  /// </summary>
  TCertificateVerifier = class sealed(TInterfacedObject, ICertificateVerifier)
  strict private
  var
    FProvider: ICryptoProvider;
    FClock: ITlsClock;
    FTrustStore: ITrustAnchorStore;
    FCheckHostName: Boolean;
    FChainLimits: TCertificateChainLimits;
    FRevocationPosture: TRevocationPosture;
    FCertificatePins: TArray<TBytes>;
    /// <summary>Untrusted intermediates that seed PKIX path building when the peer sends an
    /// incomplete chain; empty validates the chain exactly as received.</summary>
    FIntermediates: TArray<TBytes>;
    FDangerous: TDangerousTrust;
    /// <summary>Whether an out-of-band async certificate-verdict resolver runs after the pipeline
    /// (the live OCSP/CRL fetch at the park). When set, an indeterminate stapled outcome is
    /// DEFERRED to that resolver instead of being decided inline by the posture.</summary>
    FAsyncVerdictEnabled: Boolean;
    /// <summary>The injected clock as a UTC wall-clock instant, so every time-based cert
    /// check (chain validity, PKIX path date, OCSP responder validity) shares one source.</summary>
    function ValidationTimeUtc: TDateTime;
    /// <summary>The built-in trust pipeline (chain caps, PKIX, revocation, endpoint
    /// identity, pinning), run unless InsecureSkipVerify bypasses it.</summary>
    function VerifyPipeline(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>Optional SPKI public-key pinning (augments PKIX, never a bypass): when pins
    /// are configured, some certificate in the chain must have a SubjectPublicKeyInfo whose
    /// SHA-256 matches one pin, else bad_certificate.</summary>
    function CheckPinning(const AChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>The stapled OCSP verdict for the leaf, collapsed to what the trust
    /// decision needs: a current Good response, a definitive Revoked, or an
    /// indeterminate outcome (no staple, unauthorized, unknown, or stale).</summary>
    function EvaluateStaple(const AChain: TArray<TBytes>;
      const AOcspStaple: TBytes): TStapleVerdict;
    /// <summary>The stapled-OCSP revocation + must-staple step (RFC 6960 / RFC 7633),
    /// in-band only. A malformed TLS Feature extension is a hard bad_certificate. A
    /// definitive Revoked fails (certificate_revoked); a current Good passes. A must-staple
    /// leaf demands a current Good staple regardless of posture. An indeterminate outcome is
    /// deferred to the async verdict resolver when one runs (live OCSP/CRL), else accepted under
    /// Soft/Off and rejected under Hard.</summary>
    function CheckRevocation(const AChain: TArray<TBytes>; const AOcspStaple: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
  public
    /// <summary>A verifier with the conservative default chain limits and soft-fail
    /// revocation. AClock backs the stapled-OCSP freshness window (RFC 6960).</summary>
    constructor Create(const AProvider: ICryptoProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean); overload;
    /// <summary>A verifier with caller-tuned chain limits, revocation posture, and optional
    /// SPKI pins.</summary>
    constructor Create(const AProvider: ICryptoProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean;
      const AChainLimits: TCertificateChainLimits;
      ARevocationPosture: TRevocationPosture;
      const APins: TArray<TBytes> = nil); overload;
    /// <summary>As above, plus the dangerous escape hatches (InsecureSkipVerify bypasses the
    /// built-in pipeline, and a VerifyCallback that can only additionally reject) and
    /// AAsyncVerdictEnabled: when True, an indeterminate stapled-revocation outcome is deferred to
    /// the out-of-band verdict resolver (live OCSP/CRL) rather than decided inline by the posture.</summary>
    constructor Create(const AProvider: ICryptoProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean;
      const AChainLimits: TCertificateChainLimits;
      ARevocationPosture: TRevocationPosture; const APins: TArray<TBytes>;
      const ADangerous: TDangerousTrust;
      AAsyncVerdictEnabled: Boolean); overload;
    /// <summary>As above, plus AIntermediates: untrusted intermediate certificates seeded into
    /// PKIX path building for a peer that sends an incomplete chain (e.g. a leaf-only server).
    /// They never anchor a path and never bypass validation; empty behaves exactly as the
    /// overload without it.</summary>
    constructor Create(const AProvider: ICryptoProvider; const AClock: ITlsClock;
      const ATrustStore: ITrustAnchorStore; ACheckHostName: Boolean;
      const AChainLimits: TCertificateChainLimits;
      ARevocationPosture: TRevocationPosture; const APins: TArray<TBytes>;
      const ADangerous: TDangerousTrust; AAsyncVerdictEnabled: Boolean;
      const AIntermediates: TArray<TBytes>); overload;
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
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
  LI, LJ: Int32;
  LChild: TArray<TBytes>;
begin
  Result := nil;
  for LI := 0 to System.High(FStores) do
  begin
    if FStores[LI] = nil then
      Continue;
    LChild := FStores[LI].RootCertificates;
    for LJ := 0 to System.High(LChild) do
      TArrayUtilities.Append<TBytes>(Result, System.Copy(LChild[LJ]));
  end;
end;

{ TCertificateVerifier }

constructor TCertificateVerifier.Create(const AProvider: ICryptoProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean);
begin
  Create(AProvider, AClock, ATrustStore, ACheckHostName,
    TCertificateChainLimits.Defaults, TRevocationPosture.Soft);
end;

constructor TCertificateVerifier.Create(const AProvider: ICryptoProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean; const AChainLimits: TCertificateChainLimits;
  ARevocationPosture: TRevocationPosture; const APins: TArray<TBytes>);
var
  LNoDangerous: TDangerousTrust;
begin
  LNoDangerous := Default(TDangerousTrust);
  Create(AProvider, AClock, ATrustStore, ACheckHostName, AChainLimits,
    ARevocationPosture, APins, LNoDangerous, False);
end;

constructor TCertificateVerifier.Create(const AProvider: ICryptoProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean; const AChainLimits: TCertificateChainLimits;
  ARevocationPosture: TRevocationPosture; const APins: TArray<TBytes>;
  const ADangerous: TDangerousTrust; AAsyncVerdictEnabled: Boolean);
begin
  Create(AProvider, AClock, ATrustStore, ACheckHostName, AChainLimits,
    ARevocationPosture, APins, ADangerous, AAsyncVerdictEnabled, nil);
end;

constructor TCertificateVerifier.Create(const AProvider: ICryptoProvider;
  const AClock: ITlsClock; const ATrustStore: ITrustAnchorStore;
  ACheckHostName: Boolean; const AChainLimits: TCertificateChainLimits;
  ARevocationPosture: TRevocationPosture; const APins: TArray<TBytes>;
  const ADangerous: TDangerousTrust; AAsyncVerdictEnabled: Boolean;
  const AIntermediates: TArray<TBytes>);
begin
  inherited Create;
  FProvider := AProvider;
  FClock := AClock;
  FTrustStore := ATrustStore;
  FCheckHostName := ACheckHostName;
  FChainLimits := AChainLimits;
  FRevocationPosture := ARevocationPosture;
  FCertificatePins := APins;
  FIntermediates := AIntermediates;
  FDangerous := ADangerous;
  FAsyncVerdictEnabled := AAsyncVerdictEnabled;
end;

function TCertificateVerifier.ValidationTimeUtc: TDateTime;
begin
  // UnixMsToDateTime yields a UTC instant
  Result := TDateTimeUtilities.UnixMsToDateTime(Int64(FClock.NowUnixMillis));
end;

function TCertificateVerifier.CheckPinning(const AChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LHash: IHash;
  LSpki, LDigest: TBytes;
  LI, LJ: Int32;
begin
  Result := True;
  if System.Length(FCertificatePins) = 0 then
    Exit;
  // some certificate in the chain must present a pinned public key (SPKI-SHA256)
  for LI := 0 to System.High(AChain) do
  begin
    LSpki := FProvider.Certificates.PublicKeyInfo(AChain[LI]);
    LHash := FProvider.Primitives.CreateHash(THashAlgorithm.SHA_256);
    LHash.Update(LSpki, 0, System.Length(LSpki));
    LDigest := LHash.DoFinal;
    for LJ := 0 to System.High(FCertificatePins) do
      if TArrayUtilities.AreEqual(LDigest, FCertificatePins[LJ]) then
        Exit;
  end;
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := False;
end;

function TCertificateVerifier.EvaluateStaple(const AChain: TArray<TBytes>;
  const AOcspStaple: TBytes): TStapleVerdict;
var
  LStatus: TOcspStatus;
  LThisUpdate, LNextUpdate: TDateTime;
  LNowMs: Int64;
begin
  Result := TStapleVerdict.Indeterminate;
  // a staple needs the issuer (the next chain entry) to authenticate it
  if (System.Length(AOcspStaple) = 0) or (System.Length(AChain) < 2) then
    Exit;
  if not FProvider.Revocation.ValidateOcspStaple(AChain[0], AChain[1], AOcspStaple,
    ValidationTimeUtc, LStatus, LThisUpdate, LNextUpdate) then
    Exit;
  if LStatus = TOcspStatus.Revoked then
  begin
    Result := TStapleVerdict.Revoked;
    Exit;
  end;
  if LStatus = TOcspStatus.Good then
  begin
    // accept a Good response only inside its own validity window
    LNowMs := Int64(FClock.NowUnixMillis);
    if (LNowMs >= TDateTimeUtilities.DateTimeToUnixMs(LThisUpdate)) and
      ((LNextUpdate = 0) or
      (LNowMs < TDateTimeUtilities.DateTimeToUnixMs(LNextUpdate))) then
      Result := TStapleVerdict.GoodFresh;
  end;
  // an Unknown status, or a Good one outside its window, stays Indeterminate
end;

function TCertificateVerifier.CheckRevocation(const AChain: TArray<TBytes>;
  const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
const
  // RFC 7633 TLS Feature id: status_request means the certificate is must-staple
  MustStapleFeature = UInt16(5);
var
  LFeatures: TArray<UInt16>;
  LMustStaple: Boolean;
  LVerdict: TStapleVerdict;
  LI: Int32;
begin
  // the RFC 7633 TLS Feature extension well-formedness is a hard invariant, enforced
  // regardless of posture: a value that is not a SEQUENCE OF INTEGER is fatal
  if not FProvider.Certificates.TlsFeatures(AChain[0], LFeatures) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Result := False;
    Exit;
  end;
  LMustStaple := False;
  for LI := 0 to System.High(LFeatures) do
    if LFeatures[LI] = MustStapleFeature then
    begin
      LMustStaple := True;
      Break;
    end;

  LVerdict := EvaluateStaple(AChain, AOcspStaple);

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
    Result := True;
    Exit;
  end;

  // indeterminate outcome (no staple / unauthorized / unknown / stale):
  //  - a must-staple leaf still requires a current Good staple, even under Soft/Off, and even
  //    when a live resolver exists - a leaf that demands stapling is not satisfied by a live
  //    fetch (RFC 7633). Always reject.
  //  - else, when an out-of-band verdict resolver will run (live OCSP/CRL at the park), DEFER
  //    to it: accept here so the handshake reaches the park, where the resolver renders the
  //    posture's verdict over a live fetch. This is what makes a Hard posture reachable for a
  //    peer that carries no staple (e.g. a client certificate, which is never stapled).
  //  - else (no live channel), decide inline by the posture: only Hard rejects.
  if LMustStaple then
    Result := False
  else if FAsyncVerdictEnabled then
    Result := True
  else
    Result := FRevocationPosture <> TRevocationPosture.Hard;
  if not Result then
    AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
end;

function TCertificateVerifier.VerifyPipeline(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LI, LTotal: Int32;
  // the chain PKIX actually validated: when the peer sent an incomplete chain that path
  // building completed from the configured intermediates, this carries the assembled path
  // (with the recovered issuer), so revocation and pinning see it rather than the bare leaf
  LEffectiveChain: TArray<TBytes>;
begin
  Result := False;
  AAlert := TTlsAlertDescription.BadCertificate;
  if System.Length(AChain) = 0 then
    Exit;

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
    FProvider.PathValidation.ValidateCertificatePath(AChain, FTrustStore.RootCertificates,
      FIntermediates, ValidationTimeUtc, LEffectiveChain);
  except
    on E: EFatalAlertTlsLibException do
    begin
      AAlert := E.AlertDescription;
      Exit;
    end;
  end;

  // revocation via the stapled OCSP response (RFC 6960), in-band only; run over the validated
  // chain so a staple can be authenticated against a recovered issuer the peer did not send
  if not CheckRevocation(LEffectiveChain, AOcspStaple, AAlert) then
    Exit;

  // endpoint identity (RFC 6125) over the leaf's dNSName / iPAddress SAN entries
  if FCheckHostName and (AHostName <> '') then
    if not TEndpointIdentity.Matches(AHostName,
      FProvider.Certificates.DnsNames(AChain[0]),
      FProvider.Certificates.IpAddresses(AChain[0])) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

  // optional SPKI pinning augments the validated chain; it never bypasses it. Pin against the
  // validated chain so a pin on a recovered intermediate matches even for a leaf-only peer
  if not CheckPinning(LEffectiveChain, AAlert) then
    Exit;

  Result := True;
end;

function TCertificateVerifier.Verify(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := False;
  AAlert := TTlsAlertDescription.BadCertificate;
  if System.Length(AChain) = 0 then
    Exit;
  // the loud escape hatch: skip the built-in pipeline entirely (tests / pinned dev peers)
  if not FDangerous.InsecureSkipVerify then
    if not VerifyPipeline(AChain, AHostName, AOcspStaple, AAlert) then
      Exit;
  // the augment-only hook runs last and can only additionally reject; it can never rescue a
  // chain the pipeline (when run) already rejected, since a rejection has returned above
  if Assigned(FDangerous.VerifyCallback) then
    if not FDangerous.VerifyCallback(AChain, AHostName) then
    begin
      // a custom augment verifier's rejection is an unspecified acceptability problem, not a
      // corrupt/bad-signature certificate: certificate_unknown, not bad_certificate (RFC 8446 6.2)
      AAlert := TTlsAlertDescription.CertificateUnknown;
      Exit;
    end;
  Result := True;
end;

end.
