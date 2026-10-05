{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpLiveRevocation;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpPkixDomainTypes,
  TlpArrayUtilities,
  TlpIPkixProvider,
  TlpIClock,
  TlpIHttpFetcher,
  TlpTrustPolicy,
  TlpDateTimeUtilities;

type
  /// <summary>Which live revocation source(s) to consult, in order.</summary>
  TLiveRevocationMethod = (Ocsp, Crl, OcspThenCrl);

  /// <summary>
  /// The driver-edge live revocation check for the async certificate-verdict seam: given an
  /// accepted peer chain it fetches OCSP (RFC 6960) and/or CRL (RFC 5280) status through the
  /// injected IHttpFetcher and returns a fail-closed verdict. It performs no IO itself; the
  /// fetcher owns every socket.
  ///
  /// Fail-closed matrix (augment-only: it can only additionally reject a chain the built-in
  /// pipeline already accepted, never resurrect one):
  ///   * a definitive, issuer-authenticated Revoked (OCSP or CRL) ALWAYS rejects;
  ///   * a current Good accepts;
  ///   * indeterminate (no responder URL, unreachable, malformed, unknown, stale, or a chain
  ///     with no issuer to authenticate against) is treated per the posture - Soft/Off accept
  ///     (soft-fail), Hard rejects. The default when unspecified is the stricter Hard.
  /// </summary>
  TLiveRevocationChecker = class sealed(TObject)
  strict private
  const
    OcspRequestContentType = 'application/ocsp-request';
    // bound a live revocation body: the responder URL comes from the peer's own certificate
    // (AIA / CDP), so a hostile or compromised one could return an unbounded body; an oversize
    // one is treated as Indeterminate rather than parsed
    MaxOcspResponseBytes = Int32(64 * 1024);
    // real public CRLs reach ~16 MB for the busiest CAs, so keep generous headroom while still
    // bounding memory - a cap that rejects a legitimate large CRL would disable revocation exactly
    // where it matters most (Soft) or falsely reject the peer (Hard)
    MaxCrlBytes = Int32(32 * 1024 * 1024);
    // a certificate rarely carries more than two of either; the cap bounds how many third parties
    // learn which certificate is being checked, and the work, whatever the peer's certificate lists
    MaxOcspAttempts = Int32(3);
    MaxCrlAttempts = Int32(3);
    // the least a fetch is given, so a nearly spent budget still lets one attempt complete a TLS
    // exchange instead of failing instantly
    MinAttemptMs = Int64(250);
  var
    FPkix: IPkixProvider;
    FClock: ITlsClock;
    FFetcher: IHttpFetcher;
    FPosture: TRevocationPosture;
    FMethod: TLiveRevocationMethod;
    FDeadlineMs: Cardinal;
    FIssuerCandidates: TArray<TBytes>;
    function EvaluateOcsp(const ALeaf, AIssuer: TBytes; const AResponderUrl: string;
      ATimeoutMs: Cardinal): TLiveRevocationOutcome;
    function EvaluateCrl(const ALeaf, AIssuer: TBytes; const ACrlUrl: string;
      ATimeoutMs: Cardinal): TLiveRevocationOutcome;
    /// <summary>AUrls without repeats, in order, at most ACap of them.</summary>
    class function DistinctCapped(const AUrls: TArray<string>;
      ACap: Int32): TArray<string>; static;
    /// <summary>The timeout for the next attempt, given when the check began, the latest instant
    /// seen so far (so a clock stepped back never returns spent time) and how many attempts remain
    /// to share what is left of the budget; False when the budget is spent.</summary>
    function NextTimeout(AStartMs: Int64; var ALatestMs: Int64; AAttemptsLeft: Int32;
      out ATimeoutMs: Cardinal): Boolean;
  public
    /// <summary>Builds a checker over an injected provider and fetcher. APosture governs how
    /// an indeterminate result is treated (Hard rejects, Soft/Off accept). ADeadlineMs is the
    /// total time one check may spend fetching across every OCSP and CRL attempt, measured on
    /// the injected clock (0 leaves each fetch's timeout to the fetcher, with no shared deadline).
    /// Each attempt gets a fair share of what remains, so one dead responder cannot starve the
    /// next; a host should keep it within its async-verdict budget.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const AFetcher: IHttpFetcher; APosture: TRevocationPosture;
      AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal); overload;
    /// <summary>As above, plus a set of candidate issuer certificates (configured trust anchors and
    /// intermediates) used to recover the issuer when a peer presents a leaf-only chain - the normal
    /// mutual-TLS client case, where the issuing CA is a configured anchor rather than sent on the
    /// wire (RFC 8446 4.4.2). Candidates must come from local configuration, never the peer.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const AFetcher: IHttpFetcher; APosture: TRevocationPosture;
      AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
      const AIssuerCandidates: TArray<TBytes>); overload;
    /// <summary>The tri-state live outcome for the chain (leaf = AChain[0], issuer =
    /// AChain[1]). When the chain carries no issuer entry the issuer is recovered from the configured
    /// candidates if any qualify; failing that the outcome is Indeterminate (nothing authenticates a
    /// revocation).</summary>
    function Evaluate(const AChain: TArray<TBytes>): TLiveRevocationOutcome;
    /// <summary>Signature-compatible with the stream verdict resolver (the host name is
    /// not used for revocation): assign it to TTlsStream.SetCertificateVerdictResolver to run
    /// live revocation as the out-of-band verdict for a parked handshake. On reject, ARejectAlert
    /// is certificate_revoked for a definitive Revoked and bad_certificate_status_response for a
    /// hard-fail indeterminate.</summary>
    function ResolveVerdict(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
  end;

implementation

{ TLiveRevocationChecker }

constructor TLiveRevocationChecker.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const AFetcher: IHttpFetcher; APosture: TRevocationPosture;
  AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal);
begin
  inherited Create;
  FPkix := APkix;
  FClock := AClock;
  FFetcher := AFetcher;
  FPosture := APosture;
  FMethod := AMethod;
  FDeadlineMs := ADeadlineMs;
end;

constructor TLiveRevocationChecker.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const AFetcher: IHttpFetcher; APosture: TRevocationPosture;
  AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
  const AIssuerCandidates: TArray<TBytes>);
begin
  Create(APkix, AClock, AFetcher, APosture, AMethod, ADeadlineMs);
  FIssuerCandidates := AIssuerCandidates;
end;

class function TLiveRevocationChecker.DistinctCapped(const AUrls: TArray<string>;
  ACap: Int32): TArray<string>;
var
  LI: Int32;
begin
  Result := nil;
  for LI := 0 to System.High(AUrls) do
  begin
    if System.Length(Result) >= ACap then
      Break;
    if not (TArrayUtilities.Contains<string>(Result, AUrls[LI])) then
      TArrayUtilities.Append<string>(Result, AUrls[LI]);
  end;
end;

function TLiveRevocationChecker.NextTimeout(AStartMs: Int64; var ALatestMs: Int64;
  AAttemptsLeft: Int32; out ATimeoutMs: Cardinal): Boolean;
var
  LNowMs, LRemaining, LFloor, LShare: Int64;
begin
  ATimeoutMs := 0;
  // no budget: each fetch's own timeout applies and nothing is shared
  if FDeadlineMs = 0 then
    Exit(True);
  // the clock is wall time: elapsed time only ever grows, so a step back cannot give back time
  // already spent, and a step forward only ends the check early (indeterminate, which the
  // posture decides)
  LNowMs := Int64(FClock.NowUnixMillis);
  if LNowMs < ALatestMs then
    LNowMs := ALatestMs;
  ALatestMs := LNowMs;
  LRemaining := Int64(FDeadlineMs) - (LNowMs - AStartMs);
  if LRemaining > Int64(FDeadlineMs) then
    LRemaining := Int64(FDeadlineMs);
  LFloor := MinAttemptMs;
  if LFloor > Int64(FDeadlineMs) then
    LFloor := Int64(FDeadlineMs);
  if LRemaining < LFloor then
    Exit(False);
  LShare := LRemaining div AAttemptsLeft;
  if LShare < LFloor then
    LShare := LFloor;
  ATimeoutMs := Cardinal(LShare);
  Result := True;
end;

function TLiveRevocationChecker.EvaluateOcsp(const ALeaf, AIssuer: TBytes;
  const AResponderUrl: string; ATimeoutMs: Cardinal): TLiveRevocationOutcome;
var
  LRequest, LResponse: TBytes;
  LStatus: TOcspStatus;
  LThisUpdate, LNextUpdate: TDateTime;
  LNowMs, LNextMs: Int64;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  if (AResponderUrl = '') or (FFetcher = nil) then
    Exit;
  if not FPkix.Revocation.BuildOcspRequest(ALeaf, AIssuer, LRequest) then
    Exit;
  // unreachable / non-2xx / empty body -> indeterminate (never a silent pass)
  if not FFetcher.Post(AResponderUrl, OcspRequestContentType, LRequest, ATimeoutMs,
    MaxOcspResponseBytes, LResponse) then
    Exit;
  if System.Length(LResponse) > MaxOcspResponseBytes then
    Exit;
  // reuse the in-band parser: it authenticates the response (issuer- or delegated-signed)
  // and binds the CertID to this leaf; a malformed/unauthorized response is indeterminate.
  // the responder-validity date comes from the injected clock, like the window below
  if not FPkix.Revocation.ValidateOcspStaple(ALeaf, AIssuer, LResponse,
    TDateTimeUtilities.UnixMsToDateTime(Int64(FClock.NowUnixMillis)), LStatus,
    LThisUpdate, LNextUpdate) then
    Exit;
  case LStatus of
    TOcspStatus.Revoked:
      Result := TLiveRevocationOutcome.Revoked;
    TOcspStatus.Good:
      begin
        // honor the response validity window; a Good outside it is indeterminate. A live check
        // never settles inline, so a no-nextUpdate Good within the max age is accepted too
        LNowMs := Int64(FClock.NowUnixMillis);
        if LNextUpdate = 0 then
          LNextMs := 0
        else
          LNextMs := TDateTimeUtilities.DateTimeToUnixMs(LNextUpdate);
        if TRevocationDecision.OcspFreshness(LNowMs,
          TDateTimeUtilities.DateTimeToUnixMs(LThisUpdate), LNextMs) in
          [TOcspFreshness.Fresh, TOcspFreshness.Unbounded] then
          Result := TLiveRevocationOutcome.Good;
      end;
  end;
end;

function TLiveRevocationChecker.EvaluateCrl(const ALeaf, AIssuer: TBytes;
  const ACrlUrl: string; ATimeoutMs: Cardinal): TLiveRevocationOutcome;
var
  LCrl: TBytes;
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  if (ACrlUrl = '') or (FFetcher = nil) then
    Exit;
  if not FFetcher.Get(ACrlUrl, ATimeoutMs, MaxCrlBytes, LCrl) then
    Exit;
  if System.Length(LCrl) > MaxCrlBytes then
    Exit;
  // an unparseable, issuer-unverifiable or out-of-window CRL is indeterminate, never trusted;
  // the validity window is judged at the injected clock, not the wall clock
  if not FPkix.Revocation.CheckCrlRevocation(ALeaf, AIssuer, LCrl,
    TDateTimeUtilities.UnixMsToDateTime(Int64(FClock.NowUnixMillis)), LRevoked,
    LThisUpdate, LNextUpdate) then
    Exit;
  if LRevoked then
    Result := TLiveRevocationOutcome.Revoked
  else
    Result := TLiveRevocationOutcome.Good;
end;

function TLiveRevocationChecker.Evaluate(
  const AChain: TArray<TBytes>): TLiveRevocationOutcome;
var
  LLeaf, LIssuer: TBytes;
  LUrls, LOcspUrls, LCrlUrls: TArray<string>;
  LI, LLeft: Int32;
  LStartMs, LLatestMs: Int64;
  LTimeout: Cardinal;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  // Off suppresses the live fetch entirely (its network + privacy cost): no OCSP POST
  // and no CRL GET. The outcome is Indeterminate, which the posture accepts under Off (soft); a
  // stapled Revoked is still honored upstream by the built-in pipeline before the park.
  if FPosture = TRevocationPosture.Off then
    Exit;
  if System.Length(AChain) = 0 then
    Exit;
  LLeaf := AChain[0];
  // a revocation check needs the issuer to authenticate the response. It is normally the next chain
  // entry; when the peer presented a leaf only (a mutual-TLS client whose issuing CA is a configured
  // anchor, not sent on the wire), recover it from the configured candidates - Indeterminate if none
  // qualify (nothing authenticates a revocation)
  if System.Length(AChain) >= 2 then
    LIssuer := AChain[1]
  else if not FPkix.Revocation.TryFindIssuer(LLeaf, FIssuerCandidates, LIssuer) then
    Exit;

  // the attempts in order: each OCSP responder, then each CRL point, every list de-duplicated and
  // capped. The first definitive answer settles it; an indeterminate one moves on to the next.
  LOcspUrls := nil;
  LCrlUrls := nil;
  if FMethod in [TLiveRevocationMethod.Ocsp, TLiveRevocationMethod.OcspThenCrl] then
    if FPkix.Revocation.TryGetOcspResponderUrls(LLeaf, LUrls) then
      LOcspUrls := DistinctCapped(LUrls, MaxOcspAttempts);
  if FMethod in [TLiveRevocationMethod.Crl, TLiveRevocationMethod.OcspThenCrl] then
    if FPkix.Revocation.TryGetCrlDistributionPoints(LLeaf, LUrls) then
      LCrlUrls := DistinctCapped(LUrls, MaxCrlAttempts);

  LStartMs := Int64(FClock.NowUnixMillis);
  LLatestMs := LStartMs;
  LLeft :=System.Length(LOcspUrls) + System.Length(LCrlUrls);
  for LI := 0 to System.High(LOcspUrls) do
  begin
    if not NextTimeout(LStartMs, LLatestMs, LLeft, LTimeout) then
      Exit(TLiveRevocationOutcome.Indeterminate);
    Result := EvaluateOcsp(LLeaf, LIssuer, LOcspUrls[LI], LTimeout);
    if Result <> TLiveRevocationOutcome.Indeterminate then
      Exit;
    Dec(LLeft);
  end;
  for LI := 0 to System.High(LCrlUrls) do
  begin
    if not NextTimeout(LStartMs, LLatestMs, LLeft, LTimeout) then
      Exit(TLiveRevocationOutcome.Indeterminate);
    Result := EvaluateCrl(LLeaf, LIssuer, LCrlUrls[LI], LTimeout);
    if Result <> TLiveRevocationOutcome.Indeterminate then
      Exit;
    Dec(LLeft);
  end;

  Result := TLiveRevocationOutcome.Indeterminate;
end;

function TLiveRevocationChecker.ResolveVerdict(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  // authenticate against the validated path (issuer at index 1) when the pipeline produced one,
  // so the leaf's issuer comes from PKIX, not a re-guess over configured candidates. The shared
  // table sets certificate_revoked on a definitive Revoked and bad_certificate_status_response on
  // a hard-fail indeterminate; the accept paths leave the pre-set default (unused).
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := TRevocationDecision.Decide(
    Evaluate(ACtx.RevocationPath), FPosture, False, ARejectAlert);
end;

end.
