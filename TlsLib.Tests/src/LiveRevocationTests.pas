{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit LiveRevocationTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  TlpDateTimeUtilities,
  MockClock,
  MockHttpFetcher,
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpPkixDomainTypes,
  TlpIHttpFetcher,
  TlpIPkixProvider,
  TlpTrustPolicy,
  TlpLiveRevocation,
  SpyRevocationProvider,
  TlsLibTestBase;

type
  /// <summary>
  /// Live OCSP/CRL revocation over the injected IHttpFetcher. Proves the
  /// provider request/URL/CRL primitives and the checker's fail-closed matrix: a definitive
  /// live Revoked ALWAYS aborts (every posture), Good accepts, and an unreachable/malformed/
  /// no-issuer result follows the posture (Soft accepts, Hard rejects).
  /// </summary>
  TTestLiveRevocation = class(TTlsLibAlgorithmTestCase)
  strict private
    function CaCert: TBytes;
    function LeafCert: TBytes;
    function OcspGood: TBytes;
    function OcspRevoked: TBytes;
    function CrlGood: TBytes;
    function CrlRevoked: TBytes;
    function CrlStale: TBytes;
    function Field(const AName: string): TBytes;
    function Chain: TArray<TBytes>;
    function NewChecker(const AFetcher: IHttpFetcher; APosture: TRevocationPosture;
      AMethod: TLiveRevocationMethod): TLiveRevocationChecker;
    // the checker's accept/reject verdict for a server-presented chain, via the resolver seam
    function Accepts(const AChecker: TLiveRevocationChecker;
      const AChain: TArray<TBytes>): Boolean;
    function NowUtc: TDateTime;
    // scripted responders: the spy lists the URLs, the fetcher answers each one and takes time on
    // the mock clock, and the checker runs under a total budget
    procedure Arrange(AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
      const AOcspUrls, ACrlUrls: TArray<string>); overload;
    procedure Arrange(AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
      const AOcspUrls, ACrlUrls: TArray<string>;
      const AOptions: TLiveRevocationOptions); overload;
    function OptionsAreRefused(const AOptions: TLiveRevocationOptions): Boolean;
    /// <summary>How many responders a check asks when the certificate lists AFirst and ASecond.</summary>
    function ResponderAttempts(const AFirst, ASecond: string): Int32;
    procedure CheckUrls(const AExpected: array of string; const AActual: TArray<string>;
      const AMessage: string);
    procedure CheckTimeouts(const AExpected: array of Cardinal;
      const AActual: TArray<Cardinal>; const AMessage: string);
  strict private
  var
    FClock: TMockClock;
    FClockRef: ITlsClock;
    FFetcher: TMockHttpFetcher;
    FFetcherRef: IHttpFetcher;
    FSpy: TSpyPkixProvider;
    FSpyRef: IPkixProvider;
    FChecker: TLiveRevocationChecker;
  published
    // provider primitives
    procedure TestOcspResponderUrlExtracted;
    procedure TestOcspResponderUrlsExtractedInOrder;
    procedure TestOnlyHttpAccessLocationsAreReturned;
    // every responder, one shared budget
    procedure TestDeadFirstResponderFallsThroughToSecond;
    procedure TestRevokedOnSecondResponderRejects;
    procedure TestConclusiveAnswerStopsIteration;
    procedure TestDuplicateResponderQueriedOnce;
    procedure TestResponderCapBoundsAttempts;
    procedure TestSharedDeadlineStopsFurtherAttempts;
    procedure TestDeadlineSpansOcspAndCrl;
    procedure TestPerAttemptTimeoutIsFairShare;
    procedure TestFloorFrontLoadsAndStops;
    procedure TestBudgetBelowFloorStillAttemptsOnce;
    procedure TestZeroBudgetLeavesTimeoutToFetcher;
    procedure TestParkBudgetTightensTheCheckersOwn;
    procedure TestClockStepBackDoesNotGiveBackSpentTime;
    // the responder policy: request built once, URL equivalence, tunable limits
    procedure TestOcspRequestBuiltOncePerCheck;
    procedure TestUnbuildableRequestSkipsOcsp;
    procedure TestDedupIgnoresSchemeAndHostCase;
    procedure TestDedupDefaultPortAndEmptyPath;
    procedure TestDedupEquivalenceEdges;
    procedure TestCrlDedupUsesSameEquivalence;
    procedure TestDedupHappensBeforeTheCap;
    procedure TestFreshOptionsCarryDefaults;
    procedure TestResponderCapIsTunable;
    procedure TestCrlPointCapIsTunable;
    procedure TestMinAttemptIsTunable;
    procedure TestMaxCrlBytesIsTunable;
    procedure TestInvalidOptionsAreRefused;
    procedure TestNilInputsAreRefused;
    procedure TestIssuerCandidatesAreCopied;
    procedure TestCrlUrlsDistinctAndCapped;
    procedure TestCrlDistributionPointsExtracted;
    procedure TestBuildOcspRequestNonEmpty;
    procedure TestCertificatePeerInfoExtracted;
    procedure TestCrlRevocationDetectsRevoked;
    procedure TestCrlRevocationDetectsNotRevoked;
    procedure TestCrlWindowUsesInjectedValidationTime;
    procedure TestCrlExpiredAtInjectedTimeIsIndeterminate;
    procedure TestLiveCrlUsesInjectedClockEndToEnd;
    // checker fail-closed matrix (OCSP)
    procedure TestLiveOcspGoodAccepts;
    procedure TestLiveOcspRevokedRejectsUnderEveryPosture;
    procedure TestLiveOcspUnreachableIsPostureGated;
    procedure TestLiveOcspMalformedIsIndeterminate;
    procedure TestLiveOcspOversizeIsIndeterminate;
    // checker fail-closed matrix (CRL)
    procedure TestLiveCrlRevokedRejects;
    procedure TestLiveCrlGoodAccepts;
    procedure TestLiveCrlOversizeIsIndeterminate;
    procedure TestLiveCrlStaleIsIndeterminate;
    procedure TestOffPosturePerformsNoFetch;
    // edges
    procedure TestChainWithoutIssuerIsIndeterminate;
    procedure TestResolveVerdictRejectsRevoked;
    procedure TestFetchBodyCapsArePassed;
    // a live Good without nextUpdate (RFC 6960 4.2.2.1) is accepted within the max age and
    // Indeterminate beyond it; a live check never settles inline, so no park is skipped by it
    procedure TestLiveGoodWithoutNextUpdateWithinMaxAgeIsGood;
    procedure TestLiveGoodWithoutNextUpdateBeyondMaxAgeIsIndeterminate;
  end;

  /// <summary>
  /// CRL scope enforcement (RFC 5280 6.3.3 / 5.2): a validly issuer-signed CRL is authoritative
  /// for the leaf only when its scope covers it. A wrong-shard, CA-only, partial-reasons,
  /// indirect, delta, relative-name or unknown-critical CRL is Indeterminate (never a silent
  /// Good, so a substituted legitimate CRL cannot hide a revocation), and an entry's reason
  /// decides: removeFromCRL is not a revocation, certificateHold is.
  /// </summary>
  TTestCrlScope = class(TTlsLibAlgorithmTestCase)
  strict private
    function Field(const AName: string): TBytes;
    function Chain: TArray<TBytes>;
    function NowUtc: TDateTime;
    /// <summary>Classifies a CRL as 'Revoked', 'Good' or 'Indeterminate' through the provider primitive.</summary>
    function Classify(const ACrlField: string): string;
    procedure CheckClassified(const ACrlField, AExpected, AWhy: string);
    function NewChecker(const ACrl: TBytes; APosture: TRevocationPosture): TLiveRevocationChecker;
    // the checker's accept/reject verdict for a server-presented chain, via the resolver seam
    function Accepts(const AChecker: TLiveRevocationChecker;
      const AChain: TArray<TBytes>): Boolean;
  published
    procedure TestInScopeCrlsAreAuthoritative;
    procedure TestCrlWithoutNextUpdateIsAgeBounded;
    procedure TestWrongShardCrlIsIndeterminate;
    procedure TestOnlyContainsCaCertsCrlIsIndeterminateForLeaf;
    procedure TestOnlyContainsUserCertsCrlCoversLeaf;
    procedure TestOnlySomeReasonsCrlIsIndeterminate;
    procedure TestIndirectCrlIsIndeterminate;
    procedure TestUnknownCriticalExtensionIsIndeterminate;
    procedure TestDeltaCrlIsIndeterminate;
    procedure TestRelativeNameIdpIsIndeterminate;
    procedure TestRemoveFromCrlEntryIsNotRevoked;
    procedure TestCertificateHoldEntryIsRevoked;
    procedure TestLiveWrongShardCrlIsPostureGated;
    procedure TestLiveInScopeCrlRevokesAndAccepts;
  end;

  /// <summary>
  /// A CRL, an OCSP response or a delegated responder certificate signed with SHA-1 does not
  /// authenticate (RFC 8446 4.4.2.4): the outcome is Indeterminate, never Good or Revoked, while
  /// the same artifacts signed with SHA-256 are authoritative.
  /// </summary>
  TTestWeakRevocationSignatures = class(TTlsLibAlgorithmTestCase)
  strict private
    function Field(const AName: string): TBytes;
    function CrlAuthoritative(const ACrlField: string; out ARevoked: Boolean): Boolean;
    function OcspAuthoritative(const AResponseField: string; out AStatus: TOcspStatus): Boolean;
  published
    procedure TestCrlSignedWithSha256IsAuthoritative;
    procedure TestCrlSignedWithSha1IsNotAuthoritative;
    procedure TestOcspSignedWithSha256IsAuthoritative;
    procedure TestOcspSignedWithSha1IsNotAuthoritative;
    procedure TestDelegatedResponderCertificateSignedWithSha1IsNotAuthoritative;
  end;

  /// <summary>
  /// An RSASSA-PKCS1-v1_5 signature over a DigestInfo without the NULL parameters (RFC 8017 9.2) does
  /// not authenticate a CRL or an OCSP response: the same artifacts with the canonical DigestInfo are
  /// authoritative.
  /// </summary>
  TTestStrictPkcs1RevocationSignatures = class(TTlsLibAlgorithmTestCase)
  strict private
    function Field(const AName: string): TBytes;
    function CrlAuthoritative(const ACrlField: string): Boolean;
    function OcspAuthoritative(const AResponseField: string): Boolean;
  published
    procedure TestCrlWithCanonicalDigestInfoIsAuthoritative;
    procedure TestCrlWithoutDigestInfoNullIsNotAuthoritative;
    procedure TestOcspWithCanonicalDigestInfoIsAuthoritative;
    procedure TestOcspWithoutDigestInfoNullIsNotAuthoritative;
  end;

  /// <summary>The one revocation-decision table every verifier and resolver applies (RFC 6960):
  /// a definitive Revoked rejects under every posture (certificate_revoked), a Good accepts, and an
  /// indeterminate outcome follows the effective posture - Hard rejects (bad_certificate_status_response)
  /// unless deferral to a live check lowers it to Soft.</summary>
  TTestRevocationDecision = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestDecideTruthTable;
    procedure TestEffectivePosture;
    // the one OCSP window classification the staple and live paths share
    procedure TestOcspFreshness;
  end;

implementation

{ TTestLiveRevocation }

function TTestLiveRevocation.Field(const AName: string): TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/LiveRevocation.txt');
  try
    Result := DecodeHex(LV.Values[AName]);
  finally
    LV.Free;
  end;
end;

function TTestLiveRevocation.CaCert: TBytes;
begin
  Result := Field('ca_cert');
end;

function TTestLiveRevocation.LeafCert: TBytes;
begin
  Result := Field('leaf_cert');
end;

function TTestLiveRevocation.OcspGood: TBytes;
begin
  Result := Field('ocsp_good');
end;

function TTestLiveRevocation.OcspRevoked: TBytes;
begin
  Result := Field('ocsp_revoked');
end;

function TTestLiveRevocation.CrlGood: TBytes;
begin
  Result := Field('crl_good');
end;

function TTestLiveRevocation.CrlRevoked: TBytes;
begin
  Result := Field('crl_revoked');
end;

function TTestLiveRevocation.CrlStale: TBytes;
begin
  Result := Field('crl_stale');
end;

function TTestLiveRevocation.Chain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(LeafCert, CaCert);
end;

function TTestLiveRevocation.NewChecker(const AFetcher: IHttpFetcher;
  APosture: TRevocationPosture;
  AMethod: TLiveRevocationMethod): TLiveRevocationChecker;
begin
  Result := TLiveRevocationChecker.Create(Pkix, TSystemClock.Create as ITlsClock,
    AFetcher, APosture, AMethod, 0);
end;

function TTestLiveRevocation.Accepts(const AChecker: TLiveRevocationChecker;
  const AChain: TArray<TBytes>): Boolean;
var
  LCtx: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  LCtx := Default(TCertificateVerdictContext);
  LCtx.PeerRole := TPeerRole.Server;
  LCtx.Chain := AChain;
  Result := AChecker.ResolveVerdict(LCtx, LAlert);
end;

procedure TTestLiveRevocation.CheckUrls(const AExpected: array of string;
  const AActual: TArray<string>; const AMessage: string);
var
  LI: Int32;
begin
  CheckEquals(System.Length(AExpected), System.Length(AActual), AMessage + ' (count)');
  for LI := 0 to System.High(AExpected) do
    CheckEquals(AExpected[LI], AActual[LI], AMessage + ' (#' + IntToStr(LI) + ')');
end;

procedure TTestLiveRevocation.CheckTimeouts(const AExpected: array of Cardinal;
  const AActual: TArray<Cardinal>; const AMessage: string);
var
  LI: Int32;
begin
  CheckEquals(System.Length(AExpected), System.Length(AActual), AMessage + ' (count)');
  for LI := 0 to System.High(AExpected) do
    CheckEquals(AExpected[LI], AActual[LI], AMessage + ' (#' + IntToStr(LI) + ')');
end;

procedure TTestLiveRevocation.Arrange(AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
  const AOcspUrls, ACrlUrls: TArray<string>);
var
  LOptions: TLiveRevocationOptions;
begin
  Arrange(AMethod, ADeadlineMs, AOcspUrls, ACrlUrls, LOptions);
end;

procedure TTestLiveRevocation.Arrange(AMethod: TLiveRevocationMethod; ADeadlineMs: Cardinal;
  const AOcspUrls, ACrlUrls: TArray<string>; const AOptions: TLiveRevocationOptions);
begin
  FClockRef := nil;
  FFetcherRef := nil;
  FSpyRef := nil;
  FClock := TMockClock.Create(UInt64(TDateTimeUtilities.CurrentUnixMs));
  FClockRef := FClock as ITlsClock;
  FFetcher := TMockHttpFetcher.Create;
  FFetcherRef := FFetcher as IHttpFetcher;
  FFetcher.AttachClock(FClock);
  FSpy := TSpyPkixProvider.Create(Pkix);
  FSpyRef := FSpy as IPkixProvider;
  if AOcspUrls <> nil then
    FSpy.OverrideOcspUrls(AOcspUrls);
  if ACrlUrls <> nil then
    FSpy.OverrideCrlUrls(ACrlUrls);
  FChecker := Own<TLiveRevocationChecker>(TLiveRevocationChecker.Create(FSpyRef, FClockRef,
    FFetcherRef, TRevocationPosture.Hard, AMethod, ADeadlineMs, AOptions));
end;

procedure TTestLiveRevocation.TestOcspResponderUrlExtracted;
var
  LUrls: TArray<string>;
begin
  CheckTrue(Pkix.Revocation.TryGetOcspResponderUrls(LeafCert, LUrls),
    'the leaf AIA carries an OCSP responder URL');
  CheckUrls(['http://ocsp.tlslib.test/'], LUrls, 'the OCSP URL is extracted verbatim');
end;

procedure TTestLiveRevocation.TestOcspResponderUrlsExtractedInOrder;
var
  LUrls: TArray<string>;
begin
  // every http(s) responder in certificate order, the ldap entry skipped, the repeat kept (the
  // checker, not the provider, decides what to fetch)
  CheckTrue(Pkix.Revocation.TryGetOcspResponderUrls(Field('multi_ocsp_cert'), LUrls),
    'the certificate lists several responders');
  CheckUrls(['http://a.test/', 'http://b.test/', 'http://a.test/', 'https://c.test/',
    'http://d.test/'], LUrls, 'the fetchable responders in order');
end;

procedure TTestLiveRevocation.TestDeadFirstResponderFallsThroughToSecond;
var
  LA, LB: string;
begin
  LA := 'http://a.test/';
  LB := 'http://b.test/';
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA, LB), nil);
  FFetcher.ScriptPost(LA, False, nil, 0);
  FFetcher.ScriptPost(LB, True, OcspGood, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Good,
    'the live second responder settles it');
  CheckUrls([LA, LB], FFetcher.PostUrls, 'both responders were asked, in order');
  // control: with only the dead responder there is nothing to fall through to
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA), nil);
  FFetcher.ScriptPost(LA, False, nil, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
    'a lone dead responder is indeterminate');
end;

procedure TTestLiveRevocation.TestRevokedOnSecondResponderRejects;
var
  LA, LB: string;
begin
  LA := 'http://a.test/';
  LB := 'http://b.test/';
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA, LB), nil);
  // the first answers with garbage, which is indeterminate, not an answer
  FFetcher.ScriptPost(LA, True, TBytes.Create(1, 2, 3), 0);
  FFetcher.ScriptPost(LB, True, OcspRevoked, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Revoked,
    'a revocation from the second responder is found');
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA, LB), nil);
  FFetcher.ScriptPost(LA, True, TBytes.Create(1, 2, 3), 0);
  FFetcher.ScriptPost(LB, True, OcspGood, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Good,
    'control: the same layout with a good second answer is good');
end;

procedure TTestLiveRevocation.TestConclusiveAnswerStopsIteration;
var
  LA, LB: string;
begin
  LA := 'http://a.test/';
  LB := 'http://b.test/';
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA, LB), nil);
  FFetcher.ScriptPost(LA, True, OcspGood, 0);
  FFetcher.ScriptPost(LB, True, OcspRevoked, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Good, 'the first answer stands');
  CheckEquals(1, FFetcher.PostCount, 'no further responder is asked after a conclusive answer');
  // a revocation is just as conclusive: it is never traded for a later good answer
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA, LB), nil);
  FFetcher.ScriptPost(LA, True, OcspRevoked, 0);
  FFetcher.ScriptPost(LB, True, OcspGood, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Revoked, 'a revocation stands');
  CheckEquals(1, FFetcher.PostCount, 'and stops the search');
end;

procedure TTestLiveRevocation.TestDuplicateResponderQueriedOnce;
var
  LA, LB: string;
begin
  LA := 'http://a.test/';
  LB := 'http://b.test/';
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA, LA, LB), nil);
  FFetcher.ScriptPost(LA, False, nil, 0);
  FFetcher.ScriptPost(LB, False, nil, 0);
  FChecker.Evaluate(Chain);
  CheckUrls([LA, LB], FFetcher.PostUrls, 'a repeated responder is asked once');
end;

procedure TTestLiveRevocation.TestResponderCapBoundsAttempts;
begin
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test/',
    'http://b.test/', 'http://c.test/', 'http://d.test/', 'http://e.test/'), nil);
  FChecker.Evaluate(Chain);
  CheckEquals(3, FFetcher.PostCount, 'at most three responders are asked');
end;

procedure TTestLiveRevocation.TestSharedDeadlineStopsFurtherAttempts;
var
  LA, LB: string;
begin
  LA := 'http://a.test/';
  LB := 'http://b.test/';
  // the first responder spends the whole budget, so the second is never asked
  Arrange(TLiveRevocationMethod.Ocsp, 1000, TArray<string>.Create(LA, LB), nil);
  FFetcher.ScriptPost(LA, False, nil, 1000);
  FFetcher.ScriptPost(LB, True, OcspGood, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
    'a spent budget ends the check indeterminate');
  CheckEquals(1, FFetcher.PostCount, 'the second responder is not asked');
  // control: a fast failure leaves the budget for the second responder
  Arrange(TLiveRevocationMethod.Ocsp, 1000, TArray<string>.Create(LA, LB), nil);
  FFetcher.ScriptPost(LA, False, nil, 10);
  FFetcher.ScriptPost(LB, True, OcspGood, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Good,
    'with budget left the second responder answers');
end;

procedure TTestLiveRevocation.TestDeadlineSpansOcspAndCrl;
var
  LA, LC: string;
begin
  LA := 'http://a.test/';
  LC := 'http://c.test/ca.crl';
  Arrange(TLiveRevocationMethod.OcspThenCrl, 1000, TArray<string>.Create(LA),
    TArray<string>.Create(LC));
  FFetcher.ScriptPost(LA, False, nil, 1000);
  FChecker.Evaluate(Chain);
  CheckEquals(0, FFetcher.GetCount, 'an OCSP attempt that spent the budget leaves none for the CRL');
  Arrange(TLiveRevocationMethod.OcspThenCrl, 1000, TArray<string>.Create(LA),
    TArray<string>.Create(LC));
  FFetcher.ScriptPost(LA, False, nil, 10);
  FChecker.Evaluate(Chain);
  CheckEquals(1, FFetcher.GetCount, 'control: a fast OCSP failure leaves the CRL its turn');
end;

procedure TTestLiveRevocation.TestPerAttemptTimeoutIsFairShare;
begin
  // two OCSP attempts and one CRL share 3000 ms; each failure is instant, so each attempt gets its
  // share of what is left and the last one gets all of it
  Arrange(TLiveRevocationMethod.OcspThenCrl, 3000,
    TArray<string>.Create('http://a.test/', 'http://b.test/'),
    TArray<string>.Create('http://c.test/ca.crl'));
  FChecker.Evaluate(Chain);
  CheckTimeouts([1000, 1500], FFetcher.PostTimeouts, 'the OCSP attempts split the budget');
  CheckTimeouts([3000], FFetcher.GetTimeouts, 'the CRL attempt gets what is left');
end;

procedure TTestLiveRevocation.TestFloorFrontLoadsAndStops;
var
  LA, LB, LC: string;
begin
  LA := 'http://a.test/';
  LB := 'http://b.test/';
  LC := 'http://c.test/';
  // each attempt burns the 250 ms floor it was given, so the third has under a floor left
  Arrange(TLiveRevocationMethod.Ocsp, 600, TArray<string>.Create(LA, LB, LC), nil);
  FFetcher.ScriptPost(LA, False, nil, 250);
  FFetcher.ScriptPost(LB, False, nil, 250);
  FFetcher.ScriptPost(LC, False, nil, 250);
  FChecker.Evaluate(Chain);
  CheckTimeouts([250, 250], FFetcher.PostTimeouts, 'no attempt is given less than the floor');
end;

procedure TTestLiveRevocation.TestBudgetBelowFloorStillAttemptsOnce;
begin
  Arrange(TLiveRevocationMethod.Ocsp, 100, TArray<string>.Create('http://a.test/'), nil);
  FChecker.Evaluate(Chain);
  CheckTimeouts([100], FFetcher.PostTimeouts,
    'a budget below the floor is still spent on one attempt, not turned into no check');
end;

procedure TTestLiveRevocation.TestZeroBudgetLeavesTimeoutToFetcher;
var
  LA, LB, LC: string;
begin
  LA := 'http://a.test/';
  LB := 'http://b.test/';
  LC := 'http://c.test/';
  // no budget means no shared deadline: every attempt runs with the fetcher's own timeout, however
  // long the earlier ones took
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(LA, LB, LC), nil);
  FFetcher.ScriptPost(LA, False, nil, 3600000);
  FFetcher.ScriptPost(LB, False, nil, 3600000);
  FChecker.Evaluate(Chain);
  CheckEquals(3, FFetcher.PostCount, 'every capped attempt runs');
  CheckTimeouts([0, 0, 0], FFetcher.PostTimeouts, 'each is left to the fetcher');
end;

procedure TTestLiveRevocation.TestParkBudgetTightensTheCheckersOwn;

  procedure Resolve(ACheckerMs, AParkMs: Cardinal; const AExpected: array of Cardinal;
    const AMessage: string);
  var
    LCtx: TCertificateVerdictContext;
    LAlert: TTlsAlertDescription;
  begin
    Arrange(TLiveRevocationMethod.Ocsp, ACheckerMs, TArray<string>.Create('http://a.test/'), nil);
    LCtx := Default(TCertificateVerdictContext);
    LCtx.PeerRole := TPeerRole.Server;
    LCtx.Chain := Chain;
    LCtx.DeadlineMs := AParkMs;
    FChecker.ResolveVerdict(LCtx, LAlert);
    CheckTimeouts(AExpected, FFetcher.PostTimeouts, AMessage);
  end;

begin
  // the host's park budget bounds the fetch even when the checker was built with none or a longer
  // one, and never extends the checker's own
  Resolve(0, 2000, [2000], 'a park budget bounds a checker with none');
  Resolve(5000, 2000, [2000], 'a shorter park budget wins');
  Resolve(5000, 9000, [5000], 'a longer park budget does not extend the checker');
  Resolve(5000, 0, [5000], 'no park budget leaves the checker as built');
end;

procedure TTestLiveRevocation.TestClockStepBackDoesNotGiveBackSpentTime;
begin
  // the first attempt spends 2000 of 3000 ms, then the clock steps back 5 s: the last attempt must
  // still be offered only the 1000 ms that is left, not a restored budget
  Arrange(TLiveRevocationMethod.Ocsp, 3000, TArray<string>.Create('http://a.test/',
    'http://b.test/', 'http://c.test/'), nil);
  FFetcher.ScriptPost('http://a.test/', False, nil, 2000);
  FFetcher.ScriptPost('http://b.test/', False, nil, -5000);
  FChecker.Evaluate(Chain);
  CheckTimeouts([1000, 500, 1000], FFetcher.PostTimeouts,
    'time already spent is not returned by a clock step back');
end;

function TTestLiveRevocation.OptionsAreRefused(const AOptions: TLiveRevocationOptions): Boolean;
var
  LChecker: TLiveRevocationChecker;
begin
  Result := False;
  try
    LChecker := TLiveRevocationChecker.Create(Pkix, TSystemClock.Create as ITlsClock,
      TMockHttpFetcher.Create as IHttpFetcher, TRevocationPosture.Hard,
      TLiveRevocationMethod.Ocsp, 0, AOptions);
    LChecker.Free;
  except
    on E: EArgumentTlsLibException do
      Result := True;
  end;
end;

procedure TTestLiveRevocation.TestOcspRequestBuiltOncePerCheck;
begin
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test/',
    'http://b.test/', 'http://c.test/'), nil);
  FChecker.Evaluate(Chain);
  CheckEquals(1, FSpy.BuildRequestCount, 'the request is built once for every responder');
  CheckEquals(3, FFetcher.PostCount, 'and sent to each');
  // control: a CRL-only check never needs an OCSP request
  Arrange(TLiveRevocationMethod.Crl, 0, nil, TArray<string>.Create('http://a.test/1.crl'));
  FChecker.Evaluate(Chain);
  CheckEquals(0, FSpy.BuildRequestCount, 'no request is built when OCSP is not consulted');
end;

procedure TTestLiveRevocation.TestUnbuildableRequestSkipsOcsp;
begin
  // a request that cannot be built leaves no OCSP attempt, and the CRL gets the whole budget
  Arrange(TLiveRevocationMethod.OcspThenCrl, 1000, TArray<string>.Create('http://a.test/',
    'http://b.test/'), TArray<string>.Create('http://c.test/1.crl'));
  FSpy.FailOcspRequest;
  FChecker.Evaluate(Chain);
  CheckEquals(0, FFetcher.PostCount, 'no responder is asked without a request');
  CheckEquals(1, FSpy.BuildRequestCount, 'the build was tried once');
  CheckTimeouts([1000], FFetcher.GetTimeouts, 'the CRL attempt is not charged for the dropped ones');
  // control: a buildable request asks both responders
  Arrange(TLiveRevocationMethod.OcspThenCrl, 1000, TArray<string>.Create('http://a.test/',
    'http://b.test/'), TArray<string>.Create('http://c.test/1.crl'));
  FChecker.Evaluate(Chain);
  CheckEquals(2, FFetcher.PostCount, 'control: both responders are asked');
end;

procedure TTestLiveRevocation.TestDedupIgnoresSchemeAndHostCase;
var
  LOptions: TLiveRevocationOptions;
begin
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://OCSP.A.test/x',
    'HTTP://ocsp.a.test/x', 'http://b.test/'), nil);
  FChecker.Evaluate(Chain);
  CheckUrls(['http://OCSP.A.test/x', 'http://b.test/'], FFetcher.PostUrls,
    'scheme and host case do not make a second responder, and the first spelling is what is asked');
  // control: path and query are case-sensitive, so these are all different responders
  LOptions.MaxOcspResponders := 8;
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test/X',
    'http://a.test/x', 'http://a.test/?A=1', 'http://a.test/?a=1'), nil, LOptions);
  FChecker.Evaluate(Chain);
  CheckEquals(4, FFetcher.PostCount, 'paths and queries differing only in case stay distinct');
end;

procedure TTestLiveRevocation.TestDedupDefaultPortAndEmptyPath;
var
  LOptions: TLiveRevocationOptions;
begin
  LOptions.MaxOcspResponders := 8;
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test',
    'http://a.test:80/', 'HTTP://A.TEST:80'), nil, LOptions);
  FChecker.Evaluate(Chain);
  CheckUrls(['http://a.test'], FFetcher.PostUrls,
    'a default port and an empty path name the same responder');
  // control: another port, or another scheme, is another responder
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test:8080/',
    'https://a.test:80/', 'https://a.test/'), nil, LOptions);
  FChecker.Evaluate(Chain);
  CheckEquals(3, FFetcher.PostCount, 'a non-default port and a different scheme stay distinct');
end;

function TTestLiveRevocation.ResponderAttempts(const AFirst, ASecond: string): Int32;
var
  LOptions: TLiveRevocationOptions;
begin
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create(AFirst, ASecond), nil, LOptions);
  FChecker.Evaluate(Chain);
  Result := FFetcher.PostCount;
end;

procedure TTestLiveRevocation.TestDedupEquivalenceEdges;
begin
  // spellings of one responder collapse to a single attempt
  CheckEquals(1, ResponderAttempts('https://a.test:443/', 'https://a.test/'),
    'the https default port');
  CheckEquals(1, ResponderAttempts('http://a.test:/', 'http://a.test/'), 'a bare colon');
  CheckEquals(1, ResponderAttempts('http://[::1]:80/', 'http://[::1]/'),
    'an IPv6 host with the default port');
  CheckEquals(1, ResponderAttempts('http://a.test?x', 'http://a.test/?x'),
    'a query straight after the authority');
  // different responders stay two attempts
  CheckEquals(2, ResponderAttempts('http://User@a.test/', 'http://user@a.test/'),
    'userinfo is case-sensitive');
  CheckEquals(2, ResponderAttempts('http://a.test:180/', 'http://a.test/'),
    'a port that merely ends in 80 is not the default');
  CheckEquals(2, ResponderAttempts('http://a.test:8080/', 'http://a.test/'),
    'another port');
  CheckEquals(2, ResponderAttempts('http://a.test:8080/', 'http://a.test:8000/'),
    'two non-default ports that share a prefix stay distinct');
  CheckEquals(2, ResponderAttempts('Foo?u=http://x', 'foo?u=http://x'),
    'a string that is not a scheme-qualified URL is compared as written');
end;

procedure TTestLiveRevocation.TestCrlDedupUsesSameEquivalence;
begin
  Arrange(TLiveRevocationMethod.Crl, 0, nil, TArray<string>.Create('http://A.test/1.crl',
    'http://a.test/1.crl'));
  FChecker.Evaluate(Chain);
  CheckEquals(1, FFetcher.GetCount, 'CRL points use the same host-case equivalence');
  // control: a path differing in case is another point
  Arrange(TLiveRevocationMethod.Crl, 0, nil, TArray<string>.Create('http://a.test/1.CRL',
    'http://a.test/1.crl'));
  FChecker.Evaluate(Chain);
  CheckEquals(2, FFetcher.GetCount, 'a path differing in case is a different distribution point');
end;

procedure TTestLiveRevocation.TestDedupHappensBeforeTheCap;
begin
  // three attempts are allowed: the repeat must not use one of them
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test/', 'HTTP://A.TEST/',
    'http://b.test/', 'http://c.test/'), nil);
  FChecker.Evaluate(Chain);
  CheckUrls(['http://a.test/', 'http://b.test/', 'http://c.test/'], FFetcher.PostUrls,
    'the repeat is dropped before the cap is applied');
end;

procedure TTestLiveRevocation.TestFreshOptionsCarryDefaults;
var
  LOptions: TLiveRevocationOptions;
begin
  CheckEquals(3, LOptions.MaxOcspResponders, 'OCSP responder cap');
  CheckEquals(3, LOptions.MaxCrlDistributionPoints, 'CRL point cap');
  CheckEquals(250, Int32(LOptions.MinAttemptMs), 'minimum attempt time');
  CheckEquals(32 * 1024 * 1024, LOptions.MaxCrlBytes, 'CRL size cap');
  CheckEquals(0, System.Length(LOptions.IssuerCandidates), 'no issuer candidates');
end;

procedure TTestLiveRevocation.TestResponderCapIsTunable;
var
  LOptions: TLiveRevocationOptions;
  LUrls: TArray<string>;
begin
  LUrls := TArray<string>.Create('http://a.test/', 'http://b.test/', 'http://c.test/');
  LOptions.MaxOcspResponders := 1;
  Arrange(TLiveRevocationMethod.Ocsp, 0, LUrls, nil, LOptions);
  FChecker.Evaluate(Chain);
  CheckEquals(1, FFetcher.PostCount, 'a cap of one asks one responder');
  Arrange(TLiveRevocationMethod.Ocsp, 0, LUrls, nil);
  FChecker.Evaluate(Chain);
  CheckEquals(3, FFetcher.PostCount, 'control: the default asks all three');
end;

procedure TTestLiveRevocation.TestCrlPointCapIsTunable;
var
  LOptions: TLiveRevocationOptions;
  LUrls: TArray<string>;
begin
  LUrls := TArray<string>.Create('http://a.test/1.crl', 'http://b.test/2.crl',
    'http://c.test/3.crl');
  LOptions.MaxCrlDistributionPoints := 1;
  Arrange(TLiveRevocationMethod.Crl, 0, nil, LUrls, LOptions);
  FChecker.Evaluate(Chain);
  CheckEquals(1, FFetcher.GetCount, 'a cap of one fetches one distribution point');
  Arrange(TLiveRevocationMethod.Crl, 0, nil, LUrls);
  FChecker.Evaluate(Chain);
  CheckEquals(3, FFetcher.GetCount, 'control: the default fetches all three');
end;

procedure TTestLiveRevocation.TestMinAttemptIsTunable;
var
  LOptions: TLiveRevocationOptions;
  LUrls: TArray<string>;
begin
  LUrls := TArray<string>.Create('http://a.test/', 'http://b.test/', 'http://c.test/');
  // each attempt burns the 200 ms it is given out of 600
  LOptions.MinAttemptMs := 100;
  Arrange(TLiveRevocationMethod.Ocsp, 600, LUrls, nil, LOptions);
  FFetcher.ScriptPost('http://a.test/', False, nil, 200);
  FFetcher.ScriptPost('http://b.test/', False, nil, 200);
  FFetcher.ScriptPost('http://c.test/', False, nil, 200);
  FChecker.Evaluate(Chain);
  CheckTimeouts([200, 200, 200], FFetcher.PostTimeouts, 'a lower floor lets all three share the budget');
  // control: the default floor raises each to 250 and runs out after two
  Arrange(TLiveRevocationMethod.Ocsp, 600, LUrls, nil);
  FFetcher.ScriptPost('http://a.test/', False, nil, 200);
  FFetcher.ScriptPost('http://b.test/', False, nil, 200);
  FFetcher.ScriptPost('http://c.test/', False, nil, 200);
  FChecker.Evaluate(Chain);
  CheckTimeouts([250, 250], FFetcher.PostTimeouts, 'the default floor');
end;

procedure TTestLiveRevocation.TestMaxCrlBytesIsTunable;
var
  LOptions: TLiveRevocationOptions;
  LBody: TBytes;
begin
  LBody := nil;
  SetLength(LBody, 9000);
  LOptions.MaxCrlBytes := 8192;
  Arrange(TLiveRevocationMethod.Crl, 0, nil, TArray<string>.Create('http://a.test/1.crl'),
    LOptions);
  FFetcher.ScriptGet('http://a.test/1.crl', True, LBody, 0);
  CheckTrue(FChecker.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
    'a body over the cap is indeterminate');
  CheckEquals(8192, FFetcher.LastMaxBytes, 'the cap is what the fetcher is told');
  CheckEquals(0, FSpy.CrlParseCount, 'and it is never parsed');
  // control: the default cap lets the same body reach the parser
  Arrange(TLiveRevocationMethod.Crl, 0, nil, TArray<string>.Create('http://a.test/1.crl'));
  FFetcher.ScriptGet('http://a.test/1.crl', True, LBody, 0);
  FChecker.Evaluate(Chain);
  CheckEquals(1, FSpy.CrlParseCount, 'control: under the default cap it is parsed');
end;

procedure TTestLiveRevocation.TestInvalidOptionsAreRefused;
var
  LOptions: TLiveRevocationOptions;
begin
  // each limit one past either bound is refused; each exact bound is accepted. Every group ends on
  // a valid value, so the next group starts from a valid record
  LOptions.MaxOcspResponders := 0;
  CheckTrue(OptionsAreRefused(LOptions), 'zero OCSP responders');
  LOptions.MaxOcspResponders := 9;
  CheckTrue(OptionsAreRefused(LOptions), 'nine OCSP responders');
  LOptions.MaxOcspResponders := 1;
  CheckFalse(OptionsAreRefused(LOptions), 'one OCSP responder');
  LOptions.MaxOcspResponders := 8;
  CheckFalse(OptionsAreRefused(LOptions), 'eight OCSP responders');
  LOptions.MaxCrlDistributionPoints := 0;
  CheckTrue(OptionsAreRefused(LOptions), 'zero CRL points');
  LOptions.MaxCrlDistributionPoints := 9;
  CheckTrue(OptionsAreRefused(LOptions), 'nine CRL points');
  LOptions.MaxCrlDistributionPoints := 8;
  CheckFalse(OptionsAreRefused(LOptions), 'eight CRL points');
  LOptions.MinAttemptMs := 0;
  CheckTrue(OptionsAreRefused(LOptions), 'a zero floor would leave a fetch unbounded');
  LOptions.MinAttemptMs := 60001;
  CheckTrue(OptionsAreRefused(LOptions), 'a floor over a minute');
  LOptions.MinAttemptMs := 1;
  CheckFalse(OptionsAreRefused(LOptions), 'a one millisecond floor');
  LOptions.MinAttemptMs := 60000;
  CheckFalse(OptionsAreRefused(LOptions), 'a one minute floor');
  LOptions.MaxCrlBytes := 4095;
  CheckTrue(OptionsAreRefused(LOptions), 'a CRL cap under 4 KiB');
  LOptions.MaxCrlBytes := 256 * 1024 * 1024 + 1;
  CheckTrue(OptionsAreRefused(LOptions), 'a CRL cap over 256 MiB');
  LOptions.MaxCrlBytes := 4096;
  CheckFalse(OptionsAreRefused(LOptions), 'a 4 KiB CRL cap');
  LOptions.MaxCrlBytes := 256 * 1024 * 1024;
  CheckFalse(OptionsAreRefused(LOptions), 'a 256 MiB CRL cap');
end;

procedure TTestLiveRevocation.TestNilInputsAreRefused;
var
  LOptions: TLiveRevocationOptions;
  LChecker: TLiveRevocationChecker;
  LFetcher: IHttpFetcher;
  LClock: ITlsClock;

  function Refused(const APkix: IPkixProvider; const AClock: ITlsClock;
    const AFetcher: IHttpFetcher): Boolean;
  begin
    Result := False;
    try
      LChecker := TLiveRevocationChecker.Create(APkix, AClock, AFetcher,
        TRevocationPosture.Hard, TLiveRevocationMethod.Ocsp, 0, LOptions);
      LChecker.Free;
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  LFetcher := TMockHttpFetcher.Create as IHttpFetcher;
  LClock := TSystemClock.Create as ITlsClock;
  CheckTrue(Refused(nil, LClock, LFetcher), 'a nil provider is refused');
  CheckTrue(Refused(Pkix, nil, LFetcher), 'a nil clock is refused');
  CheckTrue(Refused(Pkix, LClock, nil), 'a nil fetcher is refused');
  CheckFalse(Refused(Pkix, LClock, LFetcher), 'control: all three present is accepted');
end;

procedure TTestLiveRevocation.TestIssuerCandidatesAreCopied;
var
  LOptions: TLiveRevocationOptions;
begin
  // the checker owns its candidates: changing the caller's array afterwards must not change which
  // issuer a leaf-only chain resolves to
  LOptions.IssuerCandidates := TArray<TBytes>.Create(System.Copy(CaCert));
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test/'), nil, LOptions);
  FFetcher.ScriptPost('http://a.test/', True, OcspGood, 0);
  LOptions.IssuerCandidates[0][8] := LOptions.IssuerCandidates[0][8] xor $FF;
  CheckTrue(FChecker.Evaluate(TArray<TBytes>.Create(LeafCert)) = TLiveRevocationOutcome.Good,
    'the issuer is still found from the checker''s own copy');
  // control: the same change made before the checker is built does break issuer recovery, so the
  // change above would have shown had the checker kept the caller's array
  LOptions.IssuerCandidates := TArray<TBytes>.Create(System.Copy(CaCert));
  LOptions.IssuerCandidates[0][8] := LOptions.IssuerCandidates[0][8] xor $FF;
  Arrange(TLiveRevocationMethod.Ocsp, 0, TArray<string>.Create('http://a.test/'), nil, LOptions);
  FFetcher.ScriptPost('http://a.test/', True, OcspGood, 0);
  CheckTrue(FChecker.Evaluate(TArray<TBytes>.Create(LeafCert)) =
    TLiveRevocationOutcome.Indeterminate, 'a damaged candidate no longer yields the issuer');
end;

procedure TTestLiveRevocation.TestCrlUrlsDistinctAndCapped;
begin
  Arrange(TLiveRevocationMethod.Crl, 0, nil, TArray<string>.Create('http://a.test/1.crl',
    'http://a.test/1.crl', 'http://b.test/2.crl', 'http://c.test/3.crl', 'http://d.test/4.crl',
    'http://e.test/5.crl'));
  FChecker.Evaluate(Chain);
  CheckUrls(['http://a.test/1.crl', 'http://b.test/2.crl', 'http://c.test/3.crl'],
    FFetcher.GetUrls, 'a repeated distribution point is fetched once and only three are tried');
end;

procedure TTestLiveRevocation.TestOnlyHttpAccessLocationsAreReturned;
var
  LOcsp: TArray<string>;
  LUrls: TArray<string>;
begin
  // the access locations come from the peer's certificate, so only http(s) is ever handed to a
  // fetcher: the ldap and file OCSP entries are skipped for the later HTTP one, and the ldap and
  // ftp distribution points are dropped
  CheckTrue(Pkix.Revocation.TryGetOcspResponderUrls(Field('scheme_cert'), LOcsp),
    'the HTTP responder after the other schemes is found');
  CheckUrls(['HTTP://ocsp.good.test/'], LOcsp, 'the http responder is the one returned');
  CheckTrue(Pkix.Revocation.TryGetCrlDistributionPoints(Field('scheme_cert'), LUrls),
    'the https distribution point is found');
  CheckEquals(1, System.Length(LUrls), 'only the https distribution point survives');
  CheckEquals('https://crl.good.test/ca.crl', LUrls[0], 'the https URL');
end;

procedure TTestLiveRevocation.TestCrlDistributionPointsExtracted;
var
  LUrls: TArray<string>;
begin
  CheckTrue(Pkix.Revocation.TryGetCrlDistributionPoints(LeafCert, LUrls),
    'the leaf carries a CRL distribution point');
  CheckTrue(System.Length(LUrls) >= 1, 'at least one CRL URL is returned');
  CheckEquals('http://crl.tlslib.test/ca.crl', LUrls[0], 'the CRL URL is extracted');
end;

procedure TTestLiveRevocation.TestBuildOcspRequestNonEmpty;
var
  LReq: TBytes;
begin
  CheckTrue(Pkix.Revocation.BuildOcspRequest(LeafCert, CaCert, LReq),
    'an OCSP request is built for the leaf/issuer');
  CheckTrue(System.Length(LReq) > 0, 'the OCSP request is non-empty DER');
end;

procedure TTestLiveRevocation.TestCertificatePeerInfoExtracted;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
begin
  // the neutral peer-identity accessor an adapter's native verify hook (Synapse GetPeer*)
  // reads, so no adapter touches a crypto-backend type
  CheckTrue(Pkix.Certificates.PeerInfo(LeafCert, LSubject, LIssuer, LCommonName,
    LSerialHex), 'peer info is extracted from the leaf');
  CheckEquals('localhost', LCommonName, 'the leaf common name is localhost');
  CheckTrue(Pos('localhost', LSubject) > 0, 'the subject DN carries the common name');
  CheckTrue(Pos('TlsLib Live CA', LIssuer) > 0, 'the issuer DN is the CA');
  CheckTrue(LSerialHex <> '', 'a serial number is reported');
end;

function TTestLiveRevocation.NowUtc: TDateTime;
begin
  Result := TDateTimeUtilities.UnixMsToDateTime(TDateTimeUtilities.CurrentUnixMs);
end;

procedure TTestLiveRevocation.TestCrlRevocationDetectsRevoked;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  CheckTrue(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlRevoked, NowUtc,
    LRevoked, LThisUpdate, LNextUpdate), 'the issuer-signed CRL parses and verifies');
  CheckTrue(LRevoked, 'the leaf serial is listed as revoked in the CRL');
end;

procedure TTestLiveRevocation.TestCrlRevocationDetectsNotRevoked;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  CheckTrue(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlGood, NowUtc,
    LRevoked, LThisUpdate, LNextUpdate), 'the issuer-signed CRL parses and verifies');
  CheckFalse(LRevoked, 'the leaf is not listed in the good CRL');
end;

procedure TTestLiveRevocation.TestCrlWindowUsesInjectedValidationTime;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  // the stale CRL is out of window at the current time, but the check reports its window; judged
  // at an injected time INSIDE that window the same CRL is authoritative - proving the injected
  // clock, not the wall clock, drives CRL freshness
  CheckFalse(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlStale, NowUtc,
    LRevoked, LThisUpdate, LNextUpdate), 'the stale CRL is indeterminate at the current time');
  CheckTrue(LNextUpdate > 0, 'the CRL reports a nextUpdate window');
  CheckTrue(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlStale,
    LThisUpdate + (LNextUpdate - LThisUpdate) / 2, LRevoked, LThisUpdate, LNextUpdate),
    'the same CRL verifies when the injected time is inside its window');
  // and one day before thisUpdate it is not yet valid -> indeterminate
  CheckFalse(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlStale,
    LThisUpdate - 1, LRevoked, LThisUpdate, LNextUpdate),
    'the CRL is not yet valid before its thisUpdate');
end;

procedure TTestLiveRevocation.TestLiveCrlUsesInjectedClockEndToEnd;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
  LMidMs: Int64;
begin
  // end-to-end: derive the stale CRL's window, then drive the checker with a MockClock parked
  // inside it. The stale CRL - indeterminate at the wall clock - now reads Good, proving the
  // checker feeds its injected clock through to the CRL freshness judgement.
  CheckFalse(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlStale, NowUtc,
    LRevoked, LThisUpdate, LNextUpdate), 'the stale CRL is indeterminate now');
  LMidMs := (TDateTimeUtilities.DateTimeToUnixMs(LThisUpdate) +
    TDateTimeUtilities.DateTimeToUnixMs(LNextUpdate)) div 2;
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, CrlStale);
  LChecker := TLiveRevocationChecker.Create(Pkix,
    TMockClock.Create(UInt64(LMidMs)) as ITlsClock, LFetcher as IHttpFetcher,
    TRevocationPosture.Hard, TLiveRevocationMethod.Crl, 0);
  try
    CheckTrue(Accepts(LChecker, Chain),
      'under a clock inside the CRL window the stale CRL is authoritative and accepts');
  finally
    LChecker.Free;
  end;
end;

procedure TTestLiveRevocation.TestCrlExpiredAtInjectedTimeIsIndeterminate;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  // capture the good CRL's window, then judge it one day past nextUpdate: indeterminate
  CheckTrue(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlGood, NowUtc,
    LRevoked, LThisUpdate, LNextUpdate), 'the good CRL verifies at the current time');
  CheckTrue(LNextUpdate > 0, 'the good CRL reports a nextUpdate window');
  CheckFalse(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlGood,
    LNextUpdate + 1, LRevoked, LThisUpdate, LNextUpdate),
    'a CRL judged past its nextUpdate is indeterminate');
end;

procedure TTestLiveRevocation.TestLiveOcspGoodAccepts;
var
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, OcspGood);
  LChecker := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Ocsp);
  try
    CheckTrue(LChecker.Evaluate(Chain) = TLiveRevocationOutcome.Good,
      'a fresh Good OCSP response yields Good');
    CheckTrue(Accepts(LChecker, Chain), 'a Good live status accepts, even under Hard');
    CheckEquals('http://ocsp.tlslib.test/', LFetcher.LastPostUrl,
      'the checker POSTed to the AIA responder URL');
  finally
    LChecker.Free;
  end;
end;

procedure TTestLiveRevocation.TestFetchBodyCapsArePassed;
var
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  // the checker bounds each peer-chosen download so a hostile responder cannot make the fetcher
  // buffer an unbounded body: 64 KiB for an OCSP response, 32 MiB for a CRL
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, OcspGood);
  LChecker := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Ocsp);
  try
    LChecker.Evaluate(Chain);
    CheckEquals(64 * 1024, LFetcher.LastMaxBytes, 'the OCSP POST is bounded at 64 KiB');
  finally
    LChecker.Free;
  end;

  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, CrlGood);
  LChecker := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Crl);
  try
    LChecker.Evaluate(Chain);
    CheckEquals(32 * 1024 * 1024, LFetcher.LastMaxBytes, 'the CRL GET is bounded at 32 MiB');
  finally
    LChecker.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveOcspRevokedRejectsUnderEveryPosture;
var
  LFetcher: TMockHttpFetcher;
  LSoft, LHard: TLiveRevocationChecker;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, OcspRevoked);
  LSoft := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Soft,
    TLiveRevocationMethod.Ocsp);
  LHard := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Ocsp);
  try
    CheckTrue(LSoft.Evaluate(Chain) = TLiveRevocationOutcome.Revoked,
      'a Revoked OCSP response yields Revoked');
    // a definitive live revocation aborts regardless of posture (fail-closed, exit gate)
    CheckFalse(Accepts(LSoft, Chain), 'Revoked rejects even under Soft');
    CheckFalse(Accepts(LHard, Chain), 'Revoked rejects under Hard');
  finally
    LSoft.Free;
    LHard.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveOcspOversizeIsIndeterminate;
var
  LFetcher: TMockHttpFetcher;
  LSpy: TSpyPkixProvider;
  LSpyPkix: IPkixProvider;
  LSoft, LHard, LSized: TLiveRevocationChecker;
  LOversize: TBytes;
begin
  // a responder body past the size cap is a DoS vector (the responder URL comes from the peer's
  // own certificate), not a valid response: it is treated as indeterminate, never parsed, and
  // posture-gated - Soft accepts, Hard rejects. The spy proves the cap short-circuits BEFORE the
  // parser (a garbage body would be rejected by the parser too, so the outcome alone is not enough)
  System.SetLength(LOversize, (64 * 1024) + 1);
  System.FillChar(LOversize[0], System.Length(LOversize), $30);
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, LOversize);
  LSpy := TSpyPkixProvider.Create(Pkix);
  LSpyPkix := LSpy;
  LSoft := TLiveRevocationChecker.Create(LSpyPkix, TSystemClock.Create as ITlsClock,
    LFetcher as IHttpFetcher, TRevocationPosture.Soft, TLiveRevocationMethod.Ocsp, 0);
  LHard := TLiveRevocationChecker.Create(LSpyPkix, TSystemClock.Create as ITlsClock,
    LFetcher as IHttpFetcher, TRevocationPosture.Hard, TLiveRevocationMethod.Ocsp, 0);
  try
    CheckTrue(LSoft.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
      'an oversize OCSP body is indeterminate');
    CheckEquals(0, LSpy.OcspParseCount,
      'the cap rejected the oversize body before the OCSP parser was reached');
    CheckTrue(Accepts(LSoft, Chain), 'Soft soft-fails an oversize responder body');
    CheckFalse(Accepts(LHard, Chain), 'Hard rejects an oversize responder body');
  finally
    LSoft.Free;
    LHard.Free;
  end;

  // control: an in-cap body DOES reach the parser through the same spy, so the 0 above is a real
  // short-circuit, not a spy that never counts
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, OcspGood);
  LSpy := TSpyPkixProvider.Create(Pkix);
  LSpyPkix := LSpy;
  LSized := TLiveRevocationChecker.Create(LSpyPkix, TSystemClock.Create as ITlsClock,
    LFetcher as IHttpFetcher, TRevocationPosture.Hard, TLiveRevocationMethod.Ocsp, 0);
  try
    CheckTrue(LSized.Evaluate(Chain) = TLiveRevocationOutcome.Good,
      'an in-cap Good response parses to Good');
    CheckEquals(1, LSpy.OcspParseCount, 'an in-cap body reaches the OCSP parser exactly once');
  finally
    LSized.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveOcspUnreachableIsPostureGated;
var
  LFetcher: TMockHttpFetcher;
  LSoft, LHard: TLiveRevocationChecker;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(False, nil); // responder unreachable
  LSoft := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Soft,
    TLiveRevocationMethod.Ocsp);
  LHard := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Ocsp);
  try
    CheckTrue(LSoft.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
      'an unreachable responder is indeterminate');
    CheckTrue(Accepts(LSoft, Chain), 'Soft soft-fails an unreachable responder');
    CheckFalse(Accepts(LHard, Chain), 'Hard rejects an unreachable responder');
  finally
    LSoft.Free;
    LHard.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveOcspMalformedIsIndeterminate;
var
  LFetcher: TMockHttpFetcher;
  LHard: TLiveRevocationChecker;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, TBytes.Create(1, 2, 3, 4, 5)); // garbage, not an OCSP response
  LHard := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Ocsp);
  try
    CheckTrue(LHard.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
      'a malformed response is indeterminate, never trusted');
    CheckFalse(Accepts(LHard, Chain), 'Hard rejects a malformed response');
  finally
    LHard.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveCrlRevokedRejects;
var
  LFetcher: TMockHttpFetcher;
  LSoft: TLiveRevocationChecker;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, CrlRevoked);
  LSoft := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Soft,
    TLiveRevocationMethod.Crl);
  try
    CheckTrue(LSoft.Evaluate(Chain) = TLiveRevocationOutcome.Revoked,
      'a CRL listing the leaf yields Revoked');
    CheckFalse(Accepts(LSoft, Chain), 'a CRL revocation rejects even under Soft');
    CheckEquals('http://crl.tlslib.test/ca.crl', LFetcher.LastGetUrl,
      'the checker GET the CRL distribution point');
  finally
    LSoft.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveCrlGoodAccepts;
var
  LFetcher: TMockHttpFetcher;
  LHard: TLiveRevocationChecker;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, CrlGood);
  LHard := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Crl);
  try
    CheckTrue(LHard.Evaluate(Chain) = TLiveRevocationOutcome.Good,
      'a CRL not listing the leaf yields Good');
    CheckTrue(Accepts(LHard, Chain), 'a clean CRL accepts');
  finally
    LHard.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveCrlOversizeIsIndeterminate;
var
  LFetcher: TMockHttpFetcher;
  LSpy: TSpyPkixProvider;
  LSpyPkix: IPkixProvider;
  LSoft, LHard, LSized: TLiveRevocationChecker;
  LOversize: TBytes;
begin
  // symmetric with the OCSP cap: a CRL past the size cap (the CDP URL is peer-chosen too) is a DoS
  // vector, treated as indeterminate and posture-gated, and the spy proves the parser is never
  // reached. The cap is 32 MiB, so build one byte past it
  System.SetLength(LOversize, (32 * 1024 * 1024) + 1);
  System.FillChar(LOversize[0], System.Length(LOversize), $30);
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, LOversize);
  LSpy := TSpyPkixProvider.Create(Pkix);
  LSpyPkix := LSpy;
  LSoft := TLiveRevocationChecker.Create(LSpyPkix, TSystemClock.Create as ITlsClock,
    LFetcher as IHttpFetcher, TRevocationPosture.Soft, TLiveRevocationMethod.Crl, 0);
  LHard := TLiveRevocationChecker.Create(LSpyPkix, TSystemClock.Create as ITlsClock,
    LFetcher as IHttpFetcher, TRevocationPosture.Hard, TLiveRevocationMethod.Crl, 0);
  try
    CheckTrue(LSoft.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
      'an oversize CRL is indeterminate');
    CheckEquals(0, LSpy.CrlParseCount,
      'the cap rejected the oversize CRL before the CRL parser was reached');
    CheckTrue(Accepts(LSoft, Chain), 'Soft soft-fails an oversize CRL');
    CheckFalse(Accepts(LHard, Chain), 'Hard rejects an oversize CRL');
  finally
    LSoft.Free;
    LHard.Free;
  end;

  // control: an in-cap CRL DOES reach the parser through the same spy
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, CrlGood);
  LSpy := TSpyPkixProvider.Create(Pkix);
  LSpyPkix := LSpy;
  LSized := TLiveRevocationChecker.Create(LSpyPkix, TSystemClock.Create as ITlsClock,
    LFetcher as IHttpFetcher, TRevocationPosture.Hard, TLiveRevocationMethod.Crl, 0);
  try
    CheckTrue(LSized.Evaluate(Chain) = TLiveRevocationOutcome.Good,
      'an in-cap clean CRL parses to Good');
    CheckEquals(1, LSpy.CrlParseCount, 'an in-cap CRL reaches the CRL parser exactly once');
  finally
    LSized.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveCrlStaleIsIndeterminate;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  // a validly-signed but expired CRL (nextUpdate in the past), leaf absent: without the window
  // check it reads as a definitive Good; the window check makes it indeterminate, defeating a
  // stale-CRL replay. The provider primitive reports it directly, and the checker follows the
  // posture (Hard rejects).
  CheckFalse(Pkix.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlStale, NowUtc,
    LRevoked, LThisUpdate, LNextUpdate),
    'a stale CRL (out of its validity window) is not authoritative');
  CheckFalse(LRevoked, 'a stale CRL yields no definitive revocation');

  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, CrlStale);
  LChecker := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Crl);
  try
    CheckTrue(LChecker.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
      'a stale CRL yields Indeterminate, never a silent Good');
    CheckFalse(Accepts(LChecker, Chain),
      'Hard posture rejects the indeterminate stale-CRL outcome');
  finally
    LChecker.Free;
  end;
end;

procedure TTestLiveRevocation.TestOffPosturePerformsNoFetch;
var
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  // Off suppresses the live fetch entirely (network + privacy cost): even with a Revoked OCSP
  // and CRL primed, the checker never calls the fetcher and yields Indeterminate -> accept (Off
  // is soft). A stapled Revoked would still be caught upstream, before the park.
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, OcspRevoked);
  LFetcher.SetGet(True, CrlRevoked);
  LChecker := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Off,
    TLiveRevocationMethod.OcspThenCrl);
  try
    CheckTrue(LChecker.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
      'Off yields Indeterminate without consulting any responder');
    CheckTrue(Accepts(LChecker, Chain), 'Off accepts the indeterminate outcome (soft)');
    CheckEquals(0, LFetcher.PostCount, 'Off performs no OCSP POST');
    CheckEquals(0, LFetcher.GetCount, 'Off performs no CRL GET');
  finally
    LChecker.Free;
  end;
end;

procedure TTestLiveRevocation.TestChainWithoutIssuerIsIndeterminate;
var
  LFetcher: TMockHttpFetcher;
  LHard: TLiveRevocationChecker;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, OcspGood);
  LHard := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.OcspThenCrl);
  try
    // no issuer entry means nothing can authenticate a revocation response
    CheckTrue(LHard.Evaluate(TArray<TBytes>.Create(LeafCert)) =
      TLiveRevocationOutcome.Indeterminate,
      'a chain without an issuer is indeterminate');
    CheckFalse(Accepts(LHard, TArray<TBytes>.Create(LeafCert)),
      'Hard rejects an unauthenticatable chain');
  finally
    LHard.Free;
  end;
end;

procedure TTestLiveRevocation.TestResolveVerdictRejectsRevoked;
var
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
  LAlert: TTlsAlertDescription;
  LCtx: TCertificateVerdictContext;
begin
  // the checker plugs into the verdict resolver seam: a live Revoked -> reject, and it
  // must abort with certificate_revoked, not the generic bad_certificate
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, OcspRevoked);
  LChecker := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Soft,
    TLiveRevocationMethod.Ocsp);
  try
    LAlert := TTlsAlertDescription.BadCertificate;
    LCtx := Default(TCertificateVerdictContext);
    LCtx.Chain := Chain;
    LCtx.HostName := 'localhost';
    CheckFalse(LChecker.ResolveVerdict(LCtx, LAlert),
      'ResolveVerdict rejects a live-revoked chain');
    CheckTrue(LAlert = TTlsAlertDescription.CertificateRevoked,
      'a live Revoked aborts with certificate_revoked');
  finally
    LChecker.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveGoodWithoutNextUpdateWithinMaxAgeIsGood;
var
  LV: TStringList;
  LLeaf, LCa, LResponse: TBytes;
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  LV := LoadVectorFields('Certs/OcspNoNextUpdate.txt');
  try
    LLeaf := DecodeHex(LV.Values['leaf_cert']);
    LCa := DecodeHex(LV.Values['ca_cert']);
    LResponse := DecodeHex(LV.Values['ocsp_good_nonext']);
  finally
    LV.Free;
  end;
  // derive the clock from the response's own thisUpdate so the vector stays durable
  CheckTrue(Pkix.Revocation.ValidateOcspStaple(LLeaf, LCa, LResponse,
    TDateTimeUtilities.ToUniversalTime(Now), LStatus, LThis, LNext),
    'the CA-signed response is authoritative');
  CheckTrue(LNext = 0, 'the response carries no nextUpdate');
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, LResponse);
  LChecker := TLiveRevocationChecker.Create(Pkix,
    TMockClock.Create(UInt64(TDateTimeUtilities.DateTimeToUnixMs(LThis) + 3600 * 1000))
    as ITlsClock, LFetcher as IHttpFetcher, TRevocationPosture.Hard,
    TLiveRevocationMethod.Ocsp, 0);
  try
    CheckTrue(LChecker.Evaluate(TArray<TBytes>.Create(LLeaf, LCa)) =
      TLiveRevocationOutcome.Good,
      'a live Good without nextUpdate, one hour old, yields Good');
    CheckTrue(Accepts(LChecker, TArray<TBytes>.Create(LLeaf, LCa)),
      'a recent live Good accepts under Hard');
  finally
    LChecker.Free;
  end;
end;

procedure TTestLiveRevocation.TestLiveGoodWithoutNextUpdateBeyondMaxAgeIsIndeterminate;
var
  LV: TStringList;
  LLeaf, LCa, LResponse: TBytes;
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
  LFetcher: TMockHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  LV := LoadVectorFields('Certs/OcspNoNextUpdate.txt');
  try
    LLeaf := DecodeHex(LV.Values['leaf_cert']);
    LCa := DecodeHex(LV.Values['ca_cert']);
    LResponse := DecodeHex(LV.Values['ocsp_good_nonext']);
  finally
    LV.Free;
  end;
  CheckTrue(Pkix.Revocation.ValidateOcspStaple(LLeaf, LCa, LResponse,
    TDateTimeUtilities.ToUniversalTime(Now), LStatus, LThis, LNext),
    'the CA-signed response is authoritative');
  // one millisecond past the max age: a responder that promised newer information at any time
  // has not been asked for it, so a replayed old Good is not a Good
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetPost(True, LResponse);
  LChecker := TLiveRevocationChecker.Create(Pkix,
    TMockClock.Create(UInt64(TDateTimeUtilities.DateTimeToUnixMs(LThis) +
    TRevocationDecision.OcspUnboundedMaxAgeMs + 1)) as ITlsClock, LFetcher as IHttpFetcher,
    TRevocationPosture.Hard, TLiveRevocationMethod.Ocsp, 0);
  try
    CheckTrue(LChecker.Evaluate(TArray<TBytes>.Create(LLeaf, LCa)) =
      TLiveRevocationOutcome.Indeterminate,
      'a live Good without nextUpdate past the max age is Indeterminate');
    CheckFalse(Accepts(LChecker, TArray<TBytes>.Create(LLeaf, LCa)),
      'Hard rejects the indeterminate outcome');
  finally
    LChecker.Free;
  end;
end;

{ TTestCrlScope }

function TTestCrlScope.Field(const AName: string): TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/CrlScope.txt');
  try
    Result := DecodeHex(LV.Values[AName]);
  finally
    LV.Free;
  end;
end;

function TTestCrlScope.Chain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(Field('leaf_cert'), Field('ca_cert'));
end;

function TTestCrlScope.NowUtc: TDateTime;
begin
  Result := TDateTimeUtilities.UnixMsToDateTime(TDateTimeUtilities.CurrentUnixMs);
end;

function TTestCrlScope.Classify(const ACrlField: string): string;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  if not Pkix.Revocation.CheckCrlRevocation(Field('leaf_cert'), Field('ca_cert'),
    Field(ACrlField), NowUtc, LRevoked, LThisUpdate, LNextUpdate) then
    Result := 'Indeterminate'
  else if LRevoked then
    Result := 'Revoked'
  else
    Result := 'Good';
end;

procedure TTestCrlScope.CheckClassified(const ACrlField, AExpected, AWhy: string);
begin
  CheckEquals(AExpected, Classify(ACrlField), ACrlField + ': ' + AWhy);
end;

function TTestCrlScope.NewChecker(const ACrl: TBytes;
  APosture: TRevocationPosture): TLiveRevocationChecker;
var
  LFetcher: TMockHttpFetcher;
begin
  LFetcher := TMockHttpFetcher.Create;
  LFetcher.SetGet(True, ACrl);
  Result := TLiveRevocationChecker.Create(Pkix, TSystemClock.Create as ITlsClock,
    LFetcher as IHttpFetcher, APosture, TLiveRevocationMethod.Crl, 0);
end;

function TTestCrlScope.Accepts(const AChecker: TLiveRevocationChecker;
  const AChain: TArray<TBytes>): Boolean;
var
  LCtx: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  LCtx := Default(TCertificateVerdictContext);
  LCtx.PeerRole := TPeerRole.Server;
  LCtx.Chain := AChain;
  Result := AChecker.ResolveVerdict(LCtx, LAlert);
end;

procedure TTestCrlScope.TestInScopeCrlsAreAuthoritative;
begin
  // the leaf's own shard (IDP fullName == leaf CDP) and a whole-scope CRL (no IDP) are
  // authoritative both ways: they detect the revocation and they clear the leaf
  CheckClassified('crl_shard1_revoked', 'Revoked', 'the leaf shard lists the serial');
  CheckClassified('crl_shard1_clean', 'Good', 'the leaf shard does not list the serial');
  CheckClassified('crl_noidp_revoked', 'Revoked', 'a whole-scope CRL lists the serial');
  CheckClassified('crl_noidp_clean', 'Good', 'a whole-scope CRL does not list the serial');
end;

procedure TTestCrlScope.TestCrlWithoutNextUpdateIsAgeBounded;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  // a CRL that omits nextUpdate is current only for a bounded time after thisUpdate (2020-01-01),
  // so replaying it years later cannot mask a revocation
  CheckClassified('crl_noidp_nonextupdate', 'Indeterminate', 'years past thisUpdate');
  CheckTrue(Pkix.Revocation.CheckCrlRevocation(Field('leaf_cert'), Field('ca_cert'),
    Field('crl_noidp_nonextupdate'), EncodeDate(2020, 1, 3), LRevoked, LThisUpdate,
    LNextUpdate), 'authoritative shortly after thisUpdate');
  CheckFalse(LRevoked, 'the leaf is not listed');
  CheckFalse(Pkix.Revocation.CheckCrlRevocation(Field('leaf_cert'), Field('ca_cert'),
    Field('crl_noidp_nonextupdate'), EncodeDate(2020, 1, 9), LRevoked, LThisUpdate,
    LNextUpdate), 'indeterminate once past the age bound');
end;

procedure TTestCrlScope.TestWrongShardCrlIsIndeterminate;
begin
  // validly signed, in window, empty - but its IDP names a shard the leaf does not point to,
  // so it says nothing about the leaf (RFC 5280 6.3.3 (b)(2)(i)); before scope enforcement
  // this read as a silent Good under every posture
  CheckClassified('crl_shard2_clean', 'Indeterminate',
    'a CRL scoped to another shard is not authoritative for the leaf');
end;

procedure TTestCrlScope.TestOnlyContainsCaCertsCrlIsIndeterminateForLeaf;
begin
  CheckClassified('crl_onlyca', 'Indeterminate',
    'an onlyContainsCACerts CRL does not cover an end-entity leaf');
end;

procedure TTestCrlScope.TestOnlyContainsUserCertsCrlCoversLeaf;
begin
  // the scope flag matches the leaf kind and the fullName matches its CDP: authoritative
  CheckClassified('crl_onlyuser', 'Good',
    'an onlyContainsUserCerts CRL on the leaf shard covers the end-entity leaf');
end;

procedure TTestCrlScope.TestOnlySomeReasonsCrlIsIndeterminate;
begin
  CheckClassified('crl_somereasons', 'Indeterminate',
    'a CRL covering only some reasons is not the complete CRL');
end;

procedure TTestCrlScope.TestIndirectCrlIsIndeterminate;
begin
  CheckClassified('crl_indirect', 'Indeterminate',
    'an indirect CRL is not processed');
end;

procedure TTestCrlScope.TestUnknownCriticalExtensionIsIndeterminate;
begin
  CheckClassified('crl_unknown_critical', 'Indeterminate',
    'a CRL with an unrecognized critical extension is unusable (RFC 5280 5.2)');
end;

procedure TTestCrlScope.TestDeltaCrlIsIndeterminate;
begin
  CheckClassified('crl_delta', 'Indeterminate',
    'a delta CRL is never authoritative on its own');
end;

procedure TTestCrlScope.TestRelativeNameIdpIsIndeterminate;
begin
  CheckClassified('crl_relative_dp', 'Indeterminate',
    'an IDP nameRelativeToCRLIssuer cannot be matched against the leaf full-name CDP');
end;

procedure TTestCrlScope.TestRemoveFromCrlEntryIsNotRevoked;
begin
  // RFC 5280 5.3.1: removeFromCRL lifts a hold; the entry does not revoke the leaf
  CheckClassified('crl_removefromcrl', 'Good',
    'an entry with reason removeFromCRL is not a revocation');
end;

procedure TTestCrlScope.TestCertificateHoldEntryIsRevoked;
begin
  CheckClassified('crl_hold', 'Revoked', 'certificateHold is a revocation');
end;

procedure TTestCrlScope.TestLiveWrongShardCrlIsPostureGated;
var
  LSoft, LHard: TLiveRevocationChecker;
begin
  // end-to-end: the fetcher returns the legitimately-signed wrong-shard CRL for the leaf's
  // CDP URL. The outcome is Indeterminate, so Hard rejects and Soft accepts - Hard rejects
  // ONLY because the wrong-scope CRL is non-authoritative (a clean in-scope CRL accepts
  // under Hard in TestLiveInScopeCrlRevokesAndAccepts)
  LSoft := NewChecker(Field('crl_shard2_clean'), TRevocationPosture.Soft);
  LHard := NewChecker(Field('crl_shard2_clean'), TRevocationPosture.Hard);
  try
    CheckTrue(LHard.Evaluate(Chain) = TLiveRevocationOutcome.Indeterminate,
      'a live wrong-shard CRL yields Indeterminate, never a silent Good');
    CheckFalse(Accepts(LHard, Chain), 'Hard rejects the wrong-shard CRL');
    CheckTrue(Accepts(LSoft, Chain), 'Soft accepts the indeterminate outcome');
  finally
    LSoft.Free;
    LHard.Free;
  end;
end;

procedure TTestCrlScope.TestLiveInScopeCrlRevokesAndAccepts;
var
  LRevoked, LClean: TLiveRevocationChecker;
begin
  LRevoked := NewChecker(Field('crl_shard1_revoked'), TRevocationPosture.Soft);
  LClean := NewChecker(Field('crl_shard1_clean'), TRevocationPosture.Hard);
  try
    CheckTrue(LRevoked.Evaluate(Chain) = TLiveRevocationOutcome.Revoked,
      'the leaf shard CRL listing the serial yields Revoked');
    CheckFalse(Accepts(LRevoked, Chain), 'a shard revocation rejects even under Soft');
    CheckTrue(LClean.Evaluate(Chain) = TLiveRevocationOutcome.Good,
      'the clean leaf shard CRL yields Good');
    CheckTrue(Accepts(LClean, Chain), 'a clean in-scope CRL accepts under Hard');
  finally
    LRevoked.Free;
    LClean.Free;
  end;
end;

{ TTestWeakRevocationSignatures }

function TTestWeakRevocationSignatures.Field(const AName: string): TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/WeakRevocation.txt');
  try
    Result := DecodeHex(LV.Values[AName]);
  finally
    LV.Free;
  end;
end;

function TTestWeakRevocationSignatures.CrlAuthoritative(const ACrlField: string;
  out ARevoked: Boolean): Boolean;
var
  LThisUpdate, LNextUpdate: TDateTime;
begin
  Result := Pkix.Revocation.CheckCrlRevocation(Field('leaf_cert'), Field('ca_cert'),
    Field(ACrlField), TDateTimeUtilities.ToUniversalTime(Now), ARevoked, LThisUpdate,
    LNextUpdate);
end;

function TTestWeakRevocationSignatures.OcspAuthoritative(const AResponseField: string;
  out AStatus: TOcspStatus): Boolean;
var
  LThisUpdate, LNextUpdate: TDateTime;
begin
  Result := Pkix.Revocation.ValidateOcspStaple(Field('leaf_cert'), Field('ca_cert'),
    Field(AResponseField), TDateTimeUtilities.ToUniversalTime(Now), AStatus, LThisUpdate,
    LNextUpdate);
end;

procedure TTestWeakRevocationSignatures.TestCrlSignedWithSha256IsAuthoritative;
var
  LRevoked: Boolean;
begin
  CheckTrue(CrlAuthoritative('crl_clean_sha256', LRevoked), 'clean CRL is authoritative');
  CheckFalse(LRevoked, 'the leaf is not listed');
  CheckTrue(CrlAuthoritative('crl_revoked_sha256', LRevoked), 'revoking CRL is authoritative');
  CheckTrue(LRevoked, 'the leaf is listed');
end;

procedure TTestWeakRevocationSignatures.TestCrlSignedWithSha1IsNotAuthoritative;
var
  LRevoked: Boolean;
begin
  CheckFalse(CrlAuthoritative('crl_clean_sha1', LRevoked),
    'a SHA-1 CRL must not clear the leaf');
  CheckFalse(CrlAuthoritative('crl_revoked_sha1', LRevoked),
    'a SHA-1 CRL is not an authenticated revocation either');
end;

procedure TTestWeakRevocationSignatures.TestOcspSignedWithSha256IsAuthoritative;
var
  LStatus: TOcspStatus;
begin
  CheckTrue(OcspAuthoritative('ocsp_ca_sha256', LStatus), 'issuer-signed response');
  CheckEquals(Ord(TOcspStatus.Good), Ord(LStatus), 'issuer-signed status');
  CheckTrue(OcspAuthoritative('ocsp_delegated_ok', LStatus), 'delegated response');
  CheckEquals(Ord(TOcspStatus.Good), Ord(LStatus), 'delegated status');
end;

procedure TTestWeakRevocationSignatures.TestOcspSignedWithSha1IsNotAuthoritative;
var
  LStatus: TOcspStatus;
begin
  CheckFalse(OcspAuthoritative('ocsp_ca_sha1', LStatus),
    'a SHA-1 issuer signature does not authenticate the response');
end;

procedure TTestWeakRevocationSignatures.TestDelegatedResponderCertificateSignedWithSha1IsNotAuthoritative;
var
  LStatus: TOcspStatus;
begin
  CheckFalse(OcspAuthoritative('ocsp_delegated_sha1cert', LStatus),
    'a responder certificate the issuer signed with SHA-1 delegates nothing');
end;

{ TTestStrictPkcs1RevocationSignatures }

function TTestStrictPkcs1RevocationSignatures.Field(const AName: string): TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/Pkcs1StrictDigestInfo.txt');
  try
    Result := DecodeHex(LV.Values[AName]);
  finally
    LV.Free;
  end;
end;

function TTestStrictPkcs1RevocationSignatures.CrlAuthoritative(const ACrlField: string): Boolean;
var
  LRevoked: Boolean;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  Result := Pkix.Revocation.CheckCrlRevocation(Field('leaf_cert'), Field('ca_cert'),
    Field(ACrlField), TDateTimeUtilities.ToUniversalTime(Now), LRevoked, LThisUpdate,
    LNextUpdate);
end;

function TTestStrictPkcs1RevocationSignatures.OcspAuthoritative(
  const AResponseField: string): Boolean;
var
  LStatus: TOcspStatus;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  Result := Pkix.Revocation.ValidateOcspStaple(Field('leaf_cert'), Field('ca_cert'),
    Field(AResponseField), TDateTimeUtilities.ToUniversalTime(Now), LStatus, LThisUpdate,
    LNextUpdate) and (LStatus = TOcspStatus.Good);
end;

procedure TTestStrictPkcs1RevocationSignatures.TestCrlWithCanonicalDigestInfoIsAuthoritative;
begin
  CheckTrue(CrlAuthoritative('crl_clean'), 'the control CRL is authoritative');
end;

procedure TTestStrictPkcs1RevocationSignatures.TestCrlWithoutDigestInfoNullIsNotAuthoritative;
begin
  CheckFalse(CrlAuthoritative('crl_clean_nonull'),
    'a CRL whose signature omits the DigestInfo NULL does not clear the leaf');
end;

procedure TTestStrictPkcs1RevocationSignatures.TestOcspWithCanonicalDigestInfoIsAuthoritative;
begin
  CheckTrue(OcspAuthoritative('ocsp_good'), 'the control response is authoritative');
end;

procedure TTestStrictPkcs1RevocationSignatures.TestOcspWithoutDigestInfoNullIsNotAuthoritative;
begin
  CheckFalse(OcspAuthoritative('ocsp_good_nonull'),
    'a response whose signature omits the DigestInfo NULL is not authenticated');
end;

{ TTestRevocationDecision }

procedure TTestRevocationDecision.TestOcspFreshness;
const
  ThisMs = Int64(1700000000000);
  MaxAge = TRevocationDecision.OcspUnboundedMaxAgeMs;
begin
  // a response is never fresh before its thisUpdate, with or without nextUpdate
  CheckEquals(Ord(TOcspFreshness.Stale),
    Ord(TRevocationDecision.OcspFreshness(ThisMs - 1, ThisMs, 0)), 'not yet valid, unbounded');
  CheckEquals(Ord(TOcspFreshness.Stale),
    Ord(TRevocationDecision.OcspFreshness(ThisMs - 1, ThisMs, ThisMs + MaxAge)),
    'not yet valid, bounded');
  // with nextUpdate the window is [thisUpdate, nextUpdate)
  CheckEquals(Ord(TOcspFreshness.Fresh),
    Ord(TRevocationDecision.OcspFreshness(ThisMs, ThisMs, ThisMs + 1)), 'at thisUpdate');
  CheckEquals(Ord(TOcspFreshness.Fresh),
    Ord(TRevocationDecision.OcspFreshness(ThisMs + 2 * MaxAge, ThisMs, ThisMs + 3 * MaxAge)),
    'inside a window longer than the unbounded max age is still Fresh');
  CheckEquals(Ord(TOcspFreshness.Stale),
    Ord(TRevocationDecision.OcspFreshness(ThisMs + 1, ThisMs, ThisMs + 1)), 'at nextUpdate');
  // without nextUpdate the response is Unbounded up to and including the max age, then Stale
  CheckEquals(Ord(TOcspFreshness.Unbounded),
    Ord(TRevocationDecision.OcspFreshness(ThisMs, ThisMs, 0)), 'unbounded at thisUpdate');
  CheckEquals(Ord(TOcspFreshness.Unbounded),
    Ord(TRevocationDecision.OcspFreshness(ThisMs + MaxAge, ThisMs, 0)), 'unbounded at max age');
  CheckEquals(Ord(TOcspFreshness.Stale),
    Ord(TRevocationDecision.OcspFreshness(ThisMs + MaxAge + 1, ThisMs, 0)),
    'stale one past the max age');
end;

procedure TTestRevocationDecision.TestDecideTruthTable;
var
  LOutcome: TLiveRevocationOutcome;
  LPosture: TRevocationPosture;
  LDeferIdx: Integer;
  LDefer, LResult, LExpected: Boolean;
  LAlert, LAlert2: TTlsAlertDescription;
begin
  for LOutcome := Low(TLiveRevocationOutcome) to High(TLiveRevocationOutcome) do
    for LPosture := Low(TRevocationPosture) to High(TRevocationPosture) do
      for LDeferIdx := 0 to 1 do
      begin
        LDefer := LDeferIdx = 1;
        LAlert := TTlsAlertDescription.InternalError; // sentinel: untouched on accept
        LResult := TRevocationDecision.Decide(LOutcome, LPosture, LDefer, LAlert);
        case LOutcome of
          TLiveRevocationOutcome.Good:
            LExpected := True;
          TLiveRevocationOutcome.Revoked:
            LExpected := False;
        else
          LExpected := TRevocationDecision.EffectivePosture(LPosture, LDefer) <>
            TRevocationPosture.Hard;
        end;
        CheckTrue(LResult = LExpected, 'Decide verdict');
        if LResult then
          CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert),
            'the alert is left untouched on accept')
        else if LOutcome = TLiveRevocationOutcome.Revoked then
          CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
            'a Revoked outcome aborts certificate_revoked')
        else
          CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
            'an undeferred Hard indeterminate aborts bad_certificate_status_response');
        // deferral is expressed as an effective posture: Decide(o,p,d) = Decide(o, eff(p,d), False)
        CheckTrue(LResult = TRevocationDecision.Decide(LOutcome,
          TRevocationDecision.EffectivePosture(LPosture, LDefer), False, LAlert2),
          'Decide via the effective posture matches');
      end;
end;

procedure TTestRevocationDecision.TestEffectivePosture;
begin
  CheckEquals(Ord(TRevocationPosture.Off),
    Ord(TRevocationDecision.EffectivePosture(TRevocationPosture.Off, False)), 'Off inline');
  CheckEquals(Ord(TRevocationPosture.Off),
    Ord(TRevocationDecision.EffectivePosture(TRevocationPosture.Off, True)), 'Off deferred');
  CheckEquals(Ord(TRevocationPosture.Soft),
    Ord(TRevocationDecision.EffectivePosture(TRevocationPosture.Soft, False)), 'Soft inline');
  CheckEquals(Ord(TRevocationPosture.Soft),
    Ord(TRevocationDecision.EffectivePosture(TRevocationPosture.Soft, True)), 'Soft deferred');
  CheckEquals(Ord(TRevocationPosture.Hard),
    Ord(TRevocationDecision.EffectivePosture(TRevocationPosture.Hard, False)), 'Hard inline stays Hard');
  CheckEquals(Ord(TRevocationPosture.Soft),
    Ord(TRevocationDecision.EffectivePosture(TRevocationPosture.Hard, True)), 'Hard deferred becomes Soft');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestLiveRevocation);
  RegisterTest(TTestCrlScope);
  RegisterTest(TTestWeakRevocationSignatures);
  RegisterTest(TTestStrictPkcs1RevocationSignatures);
  RegisterTest(TTestRevocationDecision);
{$ELSE}
  RegisterTest(TTestLiveRevocation.Suite);
  RegisterTest(TTestCrlScope.Suite);
  RegisterTest(TTestWeakRevocationSignatures.Suite);
  RegisterTest(TTestStrictPkcs1RevocationSignatures.Suite);
  RegisterTest(TTestRevocationDecision.Suite);
{$ENDIF FPC}

end.
