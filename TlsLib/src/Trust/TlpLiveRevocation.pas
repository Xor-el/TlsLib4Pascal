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
  TlpTlsLibExceptions,
  TlpPkixDomainTypes,
  TlpArrayUtilities,
  TlpIPkixProvider,
  TlpIClock,
  TlpClock,
  TlpIHttpFetcher,
  TlpTrustPolicy,
  TlpDateTimeUtilities;

type
  /// <summary>Which live revocation source(s) to consult, in order.</summary>
  TLiveRevocationMethod = (Ocsp, Crl, OcspThenCrl);

  /// <summary>The optional knobs of a <see cref="TLiveRevocationChecker" /> beyond its mandatory
  /// inputs. A freshly declared value carries the defaults, so a caller sets only the fields it
  /// needs; the checker refuses a value outside the documented bounds.</summary>
  TLiveRevocationOptions = record
  strict private
  const
    DefaultResponderCap = Int32(3);
    DefaultMinAttemptMs = Cardinal(250);
    // real public CRLs reach ~16 MB for the busiest CAs, so keep generous headroom while still
    // bounding memory - a cap that rejects a legitimate large CRL would disable revocation exactly
    // where it matters most (Soft) or falsely reject the peer (Hard)
    DefaultMaxCrlBytes = Int32(32 * 1024 * 1024);
  public
    /// <summary>Candidate issuer certificates (configured trust anchors and intermediates) used to
    /// recover the issuer when a peer presents a leaf only - the normal mutual-TLS client case,
    /// where the issuing CA is a configured anchor rather than sent on the wire (RFC 8446 4.4.2).
    /// Candidates must come from local configuration, never the peer. Default: none.</summary>
    IssuerCandidates: TArray<TBytes>;
    /// <summary>The most OCSP responders one check asks, in certificate order, after repeats are
    /// dropped (1..8, default 3). Each responder asked learns which certificate is being checked.</summary>
    MaxOcspResponders: Int32;
    /// <summary>The most CRL distribution points one check fetches (1..8, default 3).</summary>
    MaxCrlDistributionPoints: Int32;
    /// <summary>The least time, in milliseconds, one fetch is given from the shared budget
    /// (1..60000, default 250); at least 1 because a zero timeout leaves the fetch unbounded.</summary>
    MinAttemptMs: Cardinal;
    /// <summary>The largest CRL body fetched, in bytes (4096..256 MiB, default 32 MiB); a larger one
    /// is indeterminate rather than parsed.</summary>
    MaxCrlBytes: Int32;
    class operator Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
      AOptions: TLiveRevocationOptions);
  end;

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
  ///     (soft-fail), Hard rejects. The posture is the one passed at construction.
  ///
  /// Only the leaf is checked, against its issuer: an intermediate's own revocation is not
  /// consulted here (the OS-native live path does check the whole chain).
  /// </summary>
  TLiveRevocationChecker = class sealed(TObject)
  strict private
  const
    OcspRequestContentType = 'application/ocsp-request';
    // bound a live revocation body: the responder URL comes from the peer's own certificate
    // (AIA / CDP), so a hostile or compromised one could return an unbounded body; an oversize
    // one is treated as Indeterminate rather than parsed
    MaxOcspResponseBytes = Int32(64 * 1024);
    // the limits the options may take: a certificate rarely lists more than two responders, and each
    // one asked learns which certificate is being checked
    ResponderCapCeiling = Int32(8);
    MinAttemptCeilingMs = Cardinal(60000);
    // the bounds catch a unit slip (a size meant as MiB given as bytes) that would silently disable
    // CRL checking or reject every peer
    CrlBytesFloor = Int32(4096);
    CrlBytesCeiling = Int32(256 * 1024 * 1024);
  var
    FPkix: IPkixProvider;
    FClock: ITlsClock;
    FTicks: ITlsMonotonicClock;
    FFetcher: IHttpFetcher;
    FPosture: TRevocationPosture;
    FMethod: TLiveRevocationMethod;
    FDeadlineMs: Cardinal;
    FIssuerCandidates: TArray<TBytes>;
    FMaxOcspResponders: Int32;
    FMaxCrlPoints: Int32;
    FMinAttemptMs: Int64;
    FMaxCrlBytes: Int32;
    class function OptionsValid(const AOptions: TLiveRevocationOptions): Boolean; static;
    function EvaluateOcsp(const ALeaf, AIssuer, ARequest: TBytes; const AResponderUrl: string;
      ATimeoutMs: Cardinal): TLiveRevocationOutcome;
    function EvaluateCrl(const ALeaf, AIssuer: TBytes; const ACrlUrl: string;
      ATimeoutMs: Cardinal): TLiveRevocationOutcome;
    /// <summary>The identity of a responder URL: its scheme and host in lower case, a default port
    /// dropped and an empty path as "/", everything else exact (RFC 9110 4.2.3). Two URLs with the
    /// same identity are one responder; the path and query are case-sensitive, so they are never
    /// folded.</summary>
    class function UrlIdentity(const AUrl: string): string; static;
    /// <summary>AUrls without repeats (by identity), in order, the first spelling of each kept,
    /// at most ACap of them.</summary>
    class function DistinctCapped(const AUrls: TArray<string>;
      ACap: Int32): TArray<string>; static;
    /// <summary>The timeout for the next attempt, given when the check began and how many
    /// attempts remain to share what is left of the budget ADeadlineMs; False when the budget is
    /// spent.</summary>
    function NextTimeout(AStartMs: Int64; AAttemptsLeft: Int32; ADeadlineMs: Cardinal;
      out ATimeoutMs: Cardinal): Boolean;
    function EvaluateWithin(const AChain: TArray<TBytes>;
      ADeadlineMs: Cardinal): TLiveRevocationOutcome;
  public
    /// <summary>Builds a checker over an injected provider, fetcher and clocks. APosture governs
    /// how an indeterminate result is treated (Hard rejects, Soft/Off accept). ADeadlineMs is the
    /// total time one check may spend fetching across every OCSP and CRL attempt, measured on
    /// ATicks (0 leaves each fetch's timeout to the fetcher, with no shared deadline); pass
    /// Config.MonotonicClock to share the connection's clock.
    /// Each attempt gets a fair share of what remains, so one dead responder cannot starve the
    /// next; a host should keep it within its async-verdict budget.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const ATicks: ITlsMonotonicClock; const AFetcher: IHttpFetcher;
      APosture: TRevocationPosture; AMethod: TLiveRevocationMethod;
      ADeadlineMs: Cardinal); overload;
    /// <summary>As above, with the options set explicitly. Raises when a provider, clock or fetcher
    /// is nil (a missing fetcher would otherwise read as an indeterminate result, which the soft
    /// posture accepts) or when an option is outside its bounds.</summary>
    constructor Create(const APkix: IPkixProvider; const AClock: ITlsClock;
      const ATicks: ITlsMonotonicClock; const AFetcher: IHttpFetcher;
      APosture: TRevocationPosture; AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
      const AOptions: TLiveRevocationOptions); overload;
    /// <summary>The tri-state live outcome for the leaf (leaf = AChain[0], issuer =
    /// AChain[1]); intermediates are not checked. When the chain carries no issuer entry the issuer
    /// is recovered from the configured candidates if any qualify; failing that the outcome is
    /// Indeterminate (nothing authenticates a revocation).</summary>
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

resourcestring
  SInvalidLiveRevocationOptions = 'the live revocation options must allow 1 to 8 OCSP responders ' +
    'and 1 to 8 CRL distribution points, a minimum attempt time of 1 to 60000 ms and a CRL size ' +
    'cap of 4096 bytes to 256 MiB';
  SNilLiveRevocationInput = 'a PKIX provider, clock and HTTP fetcher are required (pass ' +
    'instances, not nil)';

{ TLiveRevocationOptions }

class operator TLiveRevocationOptions.Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
  AOptions: TLiveRevocationOptions);
begin
  // a freshly declared options value means the defaults, so an omitted knob is safe
  AOptions.IssuerCandidates := nil;
  AOptions.MaxOcspResponders := DefaultResponderCap;
  AOptions.MaxCrlDistributionPoints := DefaultResponderCap;
  AOptions.MinAttemptMs := DefaultMinAttemptMs;
  AOptions.MaxCrlBytes := DefaultMaxCrlBytes;
end;

{ TLiveRevocationChecker }

class function TLiveRevocationChecker.OptionsValid(
  const AOptions: TLiveRevocationOptions): Boolean;
begin
  Result := (AOptions.MaxOcspResponders >= 1) and
    (AOptions.MaxOcspResponders <= ResponderCapCeiling) and
    (AOptions.MaxCrlDistributionPoints >= 1) and
    (AOptions.MaxCrlDistributionPoints <= ResponderCapCeiling) and
    (AOptions.MinAttemptMs >= 1) and (AOptions.MinAttemptMs <= MinAttemptCeilingMs) and
    (AOptions.MaxCrlBytes >= CrlBytesFloor) and (AOptions.MaxCrlBytes <= CrlBytesCeiling);
end;

constructor TLiveRevocationChecker.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const ATicks: ITlsMonotonicClock; const AFetcher: IHttpFetcher;
  APosture: TRevocationPosture; AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal);
var
  LOptions: TLiveRevocationOptions;
begin
  Create(APkix, AClock, ATicks, AFetcher, APosture, AMethod, ADeadlineMs, LOptions);
end;

constructor TLiveRevocationChecker.Create(const APkix: IPkixProvider;
  const AClock: ITlsClock; const ATicks: ITlsMonotonicClock; const AFetcher: IHttpFetcher;
  APosture: TRevocationPosture; AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
  const AOptions: TLiveRevocationOptions);
begin
  inherited Create;
  if (APkix = nil) or (AClock = nil) or (ATicks = nil) or (AFetcher = nil) then
    raise EArgumentTlsLibException.CreateRes(@SNilLiveRevocationInput);
  if not OptionsValid(AOptions) then
    raise EArgumentTlsLibException.CreateRes(@SInvalidLiveRevocationOptions);
  FPkix := APkix;
  FClock := AClock;
  FTicks := ATicks;
  FFetcher := AFetcher;
  FPosture := APosture;
  FMethod := AMethod;
  FDeadlineMs := ADeadlineMs;
  // own the candidates: a caller changing its array later must not change the checker
  FIssuerCandidates := TArrayUtilities.DeepCopy<Byte>(AOptions.IssuerCandidates);
  FMaxOcspResponders := AOptions.MaxOcspResponders;
  FMaxCrlPoints := AOptions.MaxCrlDistributionPoints;
  FMinAttemptMs := AOptions.MinAttemptMs;
  FMaxCrlBytes := AOptions.MaxCrlBytes;
end;

class function TLiveRevocationChecker.UrlIdentity(const AUrl: string): string;
const
  SchemeSeparator = '://';
var
  LSchemeEnd, LAuthorityEnd, LAt, LLength: Int32;
  LScheme, LAuthority, LRest: string;
begin
  LSchemeEnd := Pos(SchemeSeparator, AUrl);
  // not a scheme-qualified URL: nothing to normalise, compare it as it is
  if LSchemeEnd <= 1 then
    Exit(AUrl);
  // a scheme is a letter then letters, digits, '+', '-' or '.' (RFC 3986 3.1); anything else before
  // the separator means this is no scheme, so the string is compared as it is
  for LAt := 1 to LSchemeEnd - 1 do
    if not (((AUrl[LAt] >= 'a') and (AUrl[LAt] <= 'z')) or
      ((AUrl[LAt] >= 'A') and (AUrl[LAt] <= 'Z')) or
      ((LAt > 1) and (((AUrl[LAt] >= '0') and (AUrl[LAt] <= '9')) or (AUrl[LAt] = '+') or
      (AUrl[LAt] = '-') or (AUrl[LAt] = '.')))) then
      Exit(AUrl);
  LScheme := LowerCase(Copy(AUrl, 1, LSchemeEnd - 1));
  LAuthorityEnd := LSchemeEnd + System.Length(SchemeSeparator);
  while (LAuthorityEnd <= System.Length(AUrl)) and (AUrl[LAuthorityEnd] <> '/') and
    (AUrl[LAuthorityEnd] <> '?') and (AUrl[LAuthorityEnd] <> '#') do
    Inc(LAuthorityEnd);
  LAuthority := Copy(AUrl, LSchemeEnd + System.Length(SchemeSeparator),
    LAuthorityEnd - LSchemeEnd - System.Length(SchemeSeparator));
  LRest := Copy(AUrl, LAuthorityEnd, System.Length(AUrl));
  // userinfo is case-sensitive; the host and port after it are not
  LAt := System.Length(LAuthority);
  while (LAt > 0) and (LAuthority[LAt] <> '@') do
    Dec(LAt);
  LAuthority := Copy(LAuthority, 1, LAt) + LowerCase(Copy(LAuthority, LAt + 1,
    System.Length(LAuthority)));
  // a default port, or a bare colon, names the same server as none
  LLength := System.Length(LAuthority);
  if (LLength > 0) and (LAuthority[LLength] = ':') then
    Delete(LAuthority, LLength, 1)
  else if (LScheme = 'http') and (LLength >= 3) and
    (Copy(LAuthority, LLength - 2, 3) = ':80') then
    Delete(LAuthority, LLength - 2, 3)
  else if (LScheme = 'https') and (LLength >= 4) and
    (Copy(LAuthority, LLength - 3, 4) = ':443') then
    Delete(LAuthority, LLength - 3, 4);
  // an empty path is the root
  if (LRest = '') or (LRest[1] = '?') or (LRest[1] = '#') then
    LRest := '/' + LRest;
  Result := LScheme + SchemeSeparator + LAuthority + LRest;
end;

class function TLiveRevocationChecker.DistinctCapped(const AUrls: TArray<string>;
  ACap: Int32): TArray<string>;
var
  LI: Int32;
  LKeys: TArray<string>;
  LKey: string;
begin
  Result := nil;
  LKeys := nil;
  for LI := 0 to System.High(AUrls) do
  begin
    if System.Length(Result) >= ACap then
      Break;
    LKey := UrlIdentity(AUrls[LI]);
    if not (TArrayUtilities.Contains<string>(LKeys, LKey)) then
    begin
      TArrayUtilities.Append<string>(LKeys, LKey);
      TArrayUtilities.Append<string>(Result, AUrls[LI]);
    end;
  end;
end;

function TLiveRevocationChecker.NextTimeout(AStartMs: Int64; AAttemptsLeft: Int32;
  ADeadlineMs: Cardinal; out ATimeoutMs: Cardinal): Boolean;
var
  LRemaining, LFloor, LShare: Int64;
begin
  ATimeoutMs := 0;
  // no budget: each fetch's own timeout applies and nothing is shared
  if ADeadlineMs = 0 then
    Exit(True);
  LRemaining := Int64(ADeadlineMs) - (FTicks.NowMonotonicMillis - AStartMs);
  LFloor := FMinAttemptMs;
  if LFloor > Int64(ADeadlineMs) then
    LFloor := Int64(ADeadlineMs);
  if LRemaining < LFloor then
    Exit(False);
  LShare := LRemaining div AAttemptsLeft;
  if LShare < LFloor then
    LShare := LFloor;
  ATimeoutMs := Cardinal(LShare);
  Result := True;
end;

function TLiveRevocationChecker.EvaluateOcsp(const ALeaf, AIssuer, ARequest: TBytes;
  const AResponderUrl: string; ATimeoutMs: Cardinal): TLiveRevocationOutcome;
var
  LResponse: TBytes;
  LStatus: TOcspStatus;
  LThisUpdate, LNextUpdate: TDateTime;
  LNowMs, LNextMs: Int64;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  if AResponderUrl = '' then
    Exit;
  // unreachable / non-2xx / empty body -> indeterminate (never a silent pass)
  if not FFetcher.Post(AResponderUrl, OcspRequestContentType, ARequest, ATimeoutMs,
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
  if ACrlUrl = '' then
    Exit;
  if not FFetcher.Get(ACrlUrl, ATimeoutMs, FMaxCrlBytes, LCrl) then
    Exit;
  if System.Length(LCrl) > FMaxCrlBytes then
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
begin
  Result := EvaluateWithin(AChain, FDeadlineMs);
end;

function TLiveRevocationChecker.EvaluateWithin(const AChain: TArray<TBytes>;
  ADeadlineMs: Cardinal): TLiveRevocationOutcome;
var
  LLeaf, LIssuer, LRequest: TBytes;
  LUrls, LOcspUrls, LCrlUrls: TArray<string>;
  LI, LLeft: Int32;
  LStartMs: Int64;
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
      LOcspUrls := DistinctCapped(LUrls, FMaxOcspResponders);
  if FMethod in [TLiveRevocationMethod.Crl, TLiveRevocationMethod.OcspThenCrl] then
    if FPkix.Revocation.TryGetCrlDistributionPoints(LLeaf, LUrls) then
      LCrlUrls := DistinctCapped(LUrls, FMaxCrlPoints);
  // the request depends only on the leaf and its issuer, so it is built once for every responder;
  // one that cannot be built leaves no OCSP attempt, and no budget is shared with it
  if System.Length(LOcspUrls) > 0 then
    if not FPkix.Revocation.BuildOcspRequest(LLeaf, LIssuer, LRequest) then
      LOcspUrls := nil;

  LStartMs := FTicks.NowMonotonicMillis;
  LLeft := System.Length(LOcspUrls) + System.Length(LCrlUrls);
  for LI := 0 to System.High(LOcspUrls) do
  begin
    if not NextTimeout(LStartMs, LLeft, ADeadlineMs, LTimeout) then
      Exit(TLiveRevocationOutcome.Indeterminate);
    Result := EvaluateOcsp(LLeaf, LIssuer, LRequest, LOcspUrls[LI], LTimeout);
    if Result <> TLiveRevocationOutcome.Indeterminate then
      Exit;
    Dec(LLeft);
  end;
  for LI := 0 to System.High(LCrlUrls) do
  begin
    if not NextTimeout(LStartMs, LLeft, ADeadlineMs, LTimeout) then
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
var
  LDeadlineMs: Cardinal;
begin
  // authenticate against the validated path (issuer at index 1) when the pipeline produced one,
  // so the leaf's issuer comes from PKIX, not a re-guess over configured candidates. The shared
  // table sets certificate_revoked on a definitive Revoked and bad_certificate_status_response on
  // a hard-fail indeterminate; the accept paths leave the pre-set default (unused).
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  // the budget the host set for the park binds as well as the checker's own; the tighter one wins
  LDeadlineMs := FDeadlineMs;
  if (ACtx.DeadlineMs <> 0) and ((LDeadlineMs = 0) or (ACtx.DeadlineMs < LDeadlineMs)) then
    LDeadlineMs := ACtx.DeadlineMs;
  Result := TRevocationDecision.Decide(
    EvaluateWithin(ACtx.RevocationPath, LDeadlineMs), FPosture, False, ARejectAlert);
end;

end.
