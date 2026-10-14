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
  SyncObjs,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpPkixDomainTypes,
  TlpArrayUtilities,
  TlpDataEncoding,
  TlpIPkixProvider,
  TlpIClock,
  TlpHttpUrl,
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
    DefaultCachedResponses = Int32(64);
  public
    /// <summary>Candidate issuer certificates (configured trust anchors and intermediates) used to
    /// recover the issuer when a peer presents a leaf only - the normal mutual-TLS client case,
    /// where the issuing CA is a configured anchor rather than sent on the wire (RFC 9846 4.5.1).
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
    /// <summary>The most fetched responses kept for later checks (0..1024, default 64; 0 turns the
    /// cache off). Together they never hold more than MaxCrlBytes of bodies.</summary>
    MaxCachedResponses: Int32;
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
  ///     (soft-fail), Hard rejects. A parked verdict is decided at the stricter of the posture
  ///     passed at construction and the one the configuration carries in the context.
  ///
  /// Only the leaf is checked, against its issuer: an intermediate's own revocation is not
  /// consulted here (the OS-native live path does check the whole chain).
  ///
  /// A bounded cache keeps the fetched OCSP responses and CRLs that carry a nextUpdate. A cached
  /// response is re-authenticated and re-judged against the injected clock on every use, is never
  /// used at or past its nextUpdate nor kept longer than a day, and an indeterminate result is
  /// never cached.
  /// </summary>
  TLiveRevocationChecker = class sealed(TObject)
  strict private
  type
    TCachedResponse = record
      Key: string;
      Body: TBytes;
      ExpiresMs: Int64;
      Revoked: Boolean;
    end;
    // oldest first; evicts from the front to stay within both the entry and the byte bounds
    TResponseCache = class sealed(TObject)
    strict private
    var
      FLock: TCriticalSection;
      FEntries: TArray<TCachedResponse>;
      FMaxEntries: Int32;
      FMaxBytes: Int64;
      FBytes: Int64;
      function IndexOf(const AKey: string): Int32;
      procedure RemoveAt(AIndex: Int32);
    public
      constructor Create(AMaxEntries: Int32; AMaxBytes: Int64);
      destructor Destroy; override;
      /// <summary>The live body for AKey; an entry at or past its expiry is dropped.</summary>
      function TryGet(const AKey: string; ANowMs: Int64; out ABody: TBytes): Boolean;
      /// <summary>Keeps ABody for AKey until AExpiresMs. A live Revoked entry is never replaced by
      /// a response that is not Revoked.</summary>
      procedure Put(const AKey: string; const ABody: TBytes; ANowMs, AExpiresMs: Int64;
        ARevoked: Boolean);
    end;
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
    CachedResponsesCeiling = Int32(1024);
    // a cached answer never outlives this, so a later revocation is seen within a day
    CacheMaxLifetimeMs = Int64(24) * 60 * 60 * 1000;
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
    FCache: TResponseCache;
    class function OptionsValid(const AOptions: TLiveRevocationOptions): Boolean; static;
    /// <summary>The outcome ARawResponse yields for the leaf: authenticated against the issuer and
    /// judged against the injected clock. ANextUpdateMs is the response's nextUpdate (0 when it
    /// carried none).</summary>
    function ClassifyOcsp(const ALeaf, AIssuer, ARawResponse: TBytes;
      out ANextUpdateMs: Int64): TLiveRevocationOutcome;
    /// <summary>The CRL counterpart of ClassifyOcsp.</summary>
    function ClassifyCrl(const ALeaf, AIssuer, ARawCrl: TBytes;
      out ANextUpdateMs: Int64): TLiveRevocationOutcome;
    /// <summary>Keeps a definitive answer that carries a nextUpdate, until that time or the
    /// cache lifetime, whichever is sooner.</summary>
    procedure Remember(const AKey: string; const ABody: TBytes;
      AOutcome: TLiveRevocationOutcome; ANextUpdateMs: Int64);
    function EvaluateOcsp(const ALeaf, AIssuer, ARequest: TBytes; const AResponderUrl: string;
      ATimeoutMs: Cardinal): TLiveRevocationOutcome;
    function EvaluateCrl(const ALeaf, AIssuer: TBytes; const ACrlUrl: string;
      ATimeoutMs: Cardinal): TLiveRevocationOutcome;
    /// <summary>The canonical text (THttpUrl.ToString) of AUrls without repeats, in order, at most
    /// ACap of them. Two spellings of one responder (RFC 9110 4.2.3) are one entry, and a URL that
    /// is not a well-formed http(s) URL is dropped.</summary>
    class function DistinctCapped(const AUrls: TArray<string>;
      ACap: Int32): TArray<string>; static;
    /// <summary>The timeout for the next attempt, given when the check began and how many
    /// attempts remain to share what is left of the budget ADeadlineMs; False when the budget is
    /// spent.</summary>
    function NextTimeout(AStartMs: Int64; AAttemptsLeft: Int32; ADeadlineMs: Cardinal;
      out ATimeoutMs: Cardinal): Boolean;
    function EvaluateWithin(const AChain: TArray<TBytes>; ADeadlineMs: Cardinal;
      APosture: TRevocationPosture): TLiveRevocationOutcome;
  public
    /// <summary>Builds a checker over an injected provider, fetcher and clocks. APosture governs
    /// how an indeterminate result is treated (Hard rejects, Soft/Off accept); a parked verdict is
    /// decided at the stricter of APosture and the posture the context carries, so a checker built
    /// Off still fetches for a Soft or Hard configuration. ADeadlineMs is the
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
    destructor Destroy; override;
    /// <summary>The tri-state live outcome for the leaf (leaf = AChain[0], issuer =
    /// AChain[1]); intermediates are not checked. When the chain carries no issuer entry the issuer
    /// is recovered from the configured candidates if any qualify; failing that the outcome is
    /// Indeterminate (nothing authenticates a revocation).</summary>
    function Evaluate(const AChain: TArray<TBytes>): TLiveRevocationOutcome;
    /// <summary>Signature-compatible with the stream verdict resolver (the host name is
    /// not used for revocation): assign it to TTlsStream.SetCertificateVerdictResolver to run
    /// live revocation as the out-of-band verdict for a parked handshake. On reject, ARejectAlert
    /// is certificate_revoked for a definitive Revoked and bad_certificate_status_response for a
    /// hard-fail indeterminate. The verdict is decided at the stricter of this checker's posture
    /// and ACtx.RevocationPosture (Hard over Soft over Off).</summary>
    function ResolveVerdict(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
  end;

implementation

resourcestring
  SInvalidLiveRevocationOptions = 'the live revocation options must allow 1 to 8 OCSP responders ' +
    'and 1 to 8 CRL distribution points, a minimum attempt time of 1 to 60000 ms, a CRL size ' +
    'cap of 4096 bytes to 256 MiB and 0 to 1024 cached responses';
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
  AOptions.MaxCachedResponses := DefaultCachedResponses;
end;

{ TLiveRevocationChecker.TResponseCache }

constructor TLiveRevocationChecker.TResponseCache.Create(AMaxEntries: Int32;
  AMaxBytes: Int64);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FMaxEntries := AMaxEntries;
  FMaxBytes := AMaxBytes;
end;

destructor TLiveRevocationChecker.TResponseCache.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TLiveRevocationChecker.TResponseCache.IndexOf(const AKey: string): Int32;
var
  LI: Int32;
begin
  Result := -1;
  for LI := 0 to System.High(FEntries) do
    if FEntries[LI].Key = AKey then
      Exit(LI);
end;

procedure TLiveRevocationChecker.TResponseCache.RemoveAt(AIndex: Int32);
var
  LI: Int32;
begin
  Dec(FBytes, System.Length(FEntries[AIndex].Body));
  for LI := AIndex to System.High(FEntries) - 1 do
    FEntries[LI] := FEntries[LI + 1];
  SetLength(FEntries, System.Length(FEntries) - 1);
end;

function TLiveRevocationChecker.TResponseCache.TryGet(const AKey: string; ANowMs: Int64;
  out ABody: TBytes): Boolean;
var
  LIndex: Int32;
begin
  ABody := nil;
  Result := False;
  FLock.Enter;
  try
    LIndex := IndexOf(AKey);
    if LIndex < 0 then
      Exit;
    if FEntries[LIndex].ExpiresMs <= ANowMs then
    begin
      RemoveAt(LIndex);
      Exit;
    end;
    ABody := System.Copy(FEntries[LIndex].Body);
    Result := True;
  finally
    FLock.Leave;
  end;
end;

procedure TLiveRevocationChecker.TResponseCache.Put(const AKey: string;
  const ABody: TBytes; ANowMs, AExpiresMs: Int64; ARevoked: Boolean);
var
  LIndex: Int32;
  LEntry: TCachedResponse;
begin
  if (FMaxEntries = 0) or (System.Length(ABody) > FMaxBytes) then
    Exit;
  FLock.Enter;
  try
    LIndex := IndexOf(AKey);
    if LIndex >= 0 then
    begin
      // a revocation already held and still live is not softened by a later answer
      if FEntries[LIndex].Revoked and (not ARevoked) and
        (FEntries[LIndex].ExpiresMs > ANowMs) then
        Exit;
      RemoveAt(LIndex);
    end;
    while (System.Length(FEntries) > 0) and
      ((System.Length(FEntries) >= FMaxEntries) or
      (FBytes + System.Length(ABody) > FMaxBytes)) do
      RemoveAt(0);
    LEntry.Key := AKey;
    LEntry.Body := System.Copy(ABody);
    LEntry.ExpiresMs := AExpiresMs;
    LEntry.Revoked := ARevoked;
    SetLength(FEntries, System.Length(FEntries) + 1);
    FEntries[System.High(FEntries)] := LEntry;
    Inc(FBytes, System.Length(ABody));
  finally
    FLock.Leave;
  end;
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
    (AOptions.MaxCrlBytes >= CrlBytesFloor) and (AOptions.MaxCrlBytes <= CrlBytesCeiling) and
    (AOptions.MaxCachedResponses >= 0) and
    (AOptions.MaxCachedResponses <= CachedResponsesCeiling);
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
  FCache := TResponseCache.Create(AOptions.MaxCachedResponses, FMaxCrlBytes);
end;

destructor TLiveRevocationChecker.Destroy;
begin
  FCache.Free;
  inherited Destroy;
end;

class function TLiveRevocationChecker.DistinctCapped(const AUrls: TArray<string>;
  ACap: Int32): TArray<string>;
var
  LI: Int32;
  LUrl: THttpUrl;
begin
  Result := nil;
  for LI := 0 to System.High(AUrls) do
  begin
    if System.Length(Result) >= ACap then
      Break;
    // a URL the library could not fetch safely is dropped without using up the cap
    if THttpUrl.TryParse(AUrls[LI], LUrl) and
      (not (TArrayUtilities.Contains<string>(Result, LUrl.ToString))) then
      TArrayUtilities.Append<string>(Result, LUrl.ToString);
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

function TLiveRevocationChecker.ClassifyOcsp(const ALeaf, AIssuer, ARawResponse: TBytes;
  out ANextUpdateMs: Int64): TLiveRevocationOutcome;
var
  LStatus: TOcspStatus;
  LThisUpdate, LNextUpdate: TDateTime;
  LNowMs: Int64;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  ANextUpdateMs := 0;
  // reuse the in-band parser: it authenticates the response (issuer- or delegated-signed)
  // and binds the CertID to this leaf; a malformed/unauthorized response is indeterminate.
  // the responder-validity date comes from the injected clock, like the window below
  if not FPkix.Revocation.ValidateOcspStaple(ALeaf, AIssuer, ARawResponse,
    TDateTimeUtilities.UnixMsToDateTime(Int64(FClock.NowUnixMillis)), LStatus,
    LThisUpdate, LNextUpdate) then
    Exit;
  if LNextUpdate <> 0 then
    ANextUpdateMs := TDateTimeUtilities.DateTimeToUnixMs(LNextUpdate);
  case LStatus of
    TOcspStatus.Revoked:
      Result := TLiveRevocationOutcome.Revoked;
    TOcspStatus.Good:
      begin
        // honor the response validity window; a Good outside it is indeterminate. A live check
        // never settles inline, so a no-nextUpdate Good within the max age is accepted too
        LNowMs := Int64(FClock.NowUnixMillis);
        if TRevocationDecision.OcspFreshness(LNowMs,
          TDateTimeUtilities.DateTimeToUnixMs(LThisUpdate), ANextUpdateMs) in
          [TOcspFreshness.Fresh, TOcspFreshness.Unbounded] then
          Result := TLiveRevocationOutcome.Good;
      end;
  end;
end;

function TLiveRevocationChecker.ClassifyCrl(const ALeaf, AIssuer, ARawCrl: TBytes;
  out ANextUpdateMs: Int64): TLiveRevocationOutcome;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  ANextUpdateMs := 0;
  // an unparseable, issuer-unverifiable or out-of-window CRL is indeterminate, never trusted;
  // the validity window is judged at the injected clock, not the wall clock
  if not FPkix.Revocation.CheckCrlRevocation(ALeaf, AIssuer, ARawCrl,
    TDateTimeUtilities.UnixMsToDateTime(Int64(FClock.NowUnixMillis)), LRevoked,
    LThisUpdate, LNextUpdate) then
    Exit;
  if LNextUpdate <> 0 then
    ANextUpdateMs := TDateTimeUtilities.DateTimeToUnixMs(LNextUpdate);
  if LRevoked then
    Result := TLiveRevocationOutcome.Revoked
  else
    Result := TLiveRevocationOutcome.Good;
end;

procedure TLiveRevocationChecker.Remember(const AKey: string; const ABody: TBytes;
  AOutcome: TLiveRevocationOutcome; ANextUpdateMs: Int64);
var
  LNowMs, LExpiresMs: Int64;
begin
  // a response without nextUpdate promises newer information at any time (RFC 6960 4.2.2.1)
  if (AOutcome = TLiveRevocationOutcome.Indeterminate) or (ANextUpdateMs = 0) then
    Exit;
  LNowMs := Int64(FClock.NowUnixMillis);
  LExpiresMs := ANextUpdateMs;
  if LExpiresMs > LNowMs + CacheMaxLifetimeMs then
    LExpiresMs := LNowMs + CacheMaxLifetimeMs;
  // an answer already past its nextUpdate (a Revoked is not window-checked) must not displace a live one
  if LExpiresMs <= LNowMs then
    Exit;
  FCache.Put(AKey, ABody, LNowMs, LExpiresMs, AOutcome = TLiveRevocationOutcome.Revoked);
end;

function TLiveRevocationChecker.EvaluateOcsp(const ALeaf, AIssuer, ARequest: TBytes;
  const AResponderUrl: string; ATimeoutMs: Cardinal): TLiveRevocationOutcome;
var
  LResponse: TBytes;
  LKey: string;
  LNextMs: Int64;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  if AResponderUrl = '' then
    Exit;
  // the request holds only the CertID, so it names the certificate whichever responder answers
  LKey := 'ocsp:' + TDataEncoding.HexEncode(ARequest);
  if FCache.TryGet(LKey, Int64(FClock.NowUnixMillis), LResponse) then
  begin
    Result := ClassifyOcsp(ALeaf, AIssuer, LResponse, LNextMs);
    if Result <> TLiveRevocationOutcome.Indeterminate then
      Exit;
  end;
  // unreachable / non-2xx / empty body -> indeterminate (never a silent pass)
  if not FFetcher.Post(AResponderUrl, OcspRequestContentType, ARequest, ATimeoutMs,
    MaxOcspResponseBytes, LResponse) then
    Exit;
  if System.Length(LResponse) > MaxOcspResponseBytes then
    Exit;
  Result := ClassifyOcsp(ALeaf, AIssuer, LResponse, LNextMs);
  Remember(LKey, LResponse, Result, LNextMs);
end;

function TLiveRevocationChecker.EvaluateCrl(const ALeaf, AIssuer: TBytes;
  const ACrlUrl: string; ATimeoutMs: Cardinal): TLiveRevocationOutcome;
var
  LCrl: TBytes;
  LKey: string;
  LNextMs: Int64;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  if ACrlUrl = '' then
    Exit;
  LKey := 'crl:' + ACrlUrl;
  if FCache.TryGet(LKey, Int64(FClock.NowUnixMillis), LCrl) then
  begin
    Result := ClassifyCrl(ALeaf, AIssuer, LCrl, LNextMs);
    if Result <> TLiveRevocationOutcome.Indeterminate then
      Exit;
  end;
  if not FFetcher.Get(ACrlUrl, ATimeoutMs, FMaxCrlBytes, LCrl) then
    Exit;
  if System.Length(LCrl) > FMaxCrlBytes then
    Exit;
  Result := ClassifyCrl(ALeaf, AIssuer, LCrl, LNextMs);
  Remember(LKey, LCrl, Result, LNextMs);
end;

function TLiveRevocationChecker.Evaluate(
  const AChain: TArray<TBytes>): TLiveRevocationOutcome;
begin
  Result := EvaluateWithin(AChain, FDeadlineMs, FPosture);
end;

function TLiveRevocationChecker.EvaluateWithin(const AChain: TArray<TBytes>;
  ADeadlineMs: Cardinal; APosture: TRevocationPosture): TLiveRevocationOutcome;
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
  if APosture = TRevocationPosture.Off then
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
  LPosture: TRevocationPosture;
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
  // the configuration's posture holds even when this checker was built with a laxer one
  LPosture := TRevocationDecision.Stricter(FPosture, ACtx.RevocationPosture);
  Result := TRevocationDecision.Decide(
    EvaluateWithin(ACtx.RevocationPath, LDeadlineMs, LPosture), LPosture, False, ARejectAlert);
end;

end.
