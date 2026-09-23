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
  TlpIHttpFetcher,
  TlpTrustPolicy,
  TlpLiveRevocation,
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
    function NowUtc: TDateTime;
  published
    // provider primitives
    procedure TestOcspResponderUrlExtracted;
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
    // checker fail-closed matrix (CRL)
    procedure TestLiveCrlRevokedRejects;
    procedure TestLiveCrlGoodAccepts;
    procedure TestLiveCrlStaleIsIndeterminate;
    procedure TestOffPosturePerformsNoFetch;
    // edges
    procedure TestChainWithoutIssuerIsIndeterminate;
    procedure TestResolveVerdictRejectsRevoked;
  end;

  /// <summary>The one revocation-decision table every verifier and resolver applies (RFC 6960):
  /// a definitive Revoked rejects under every posture (certificate_revoked), a Good accepts, and an
  /// indeterminate outcome follows the effective posture - Hard rejects (bad_certificate_status_response)
  /// unless deferral to a live check lowers it to Soft.</summary>
  TTestRevocationDecision = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestDecideTruthTable;
    procedure TestEffectivePosture;
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

procedure TTestLiveRevocation.TestOcspResponderUrlExtracted;
var
  LUrl: string;
begin
  CheckTrue(Pkix.Revocation.TryGetOcspResponderUrl(LeafCert, LUrl),
    'the leaf AIA carries an OCSP responder URL');
  CheckEquals('http://ocsp.tlslib.test/', LUrl, 'the OCSP URL is extracted verbatim');
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
  // reads, so no adapter touches a CryptoLib type
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
    CheckTrue(LChecker.CheckChain(Chain),
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
    CheckTrue(LChecker.CheckChain(Chain), 'a Good live status accepts, even under Hard');
    CheckEquals('http://ocsp.tlslib.test/', LFetcher.LastPostUrl,
      'the checker POSTed to the AIA responder URL');
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
    CheckFalse(LSoft.CheckChain(Chain), 'Revoked rejects even under Soft');
    CheckFalse(LHard.CheckChain(Chain), 'Revoked rejects under Hard');
  finally
    LSoft.Free;
    LHard.Free;
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
    CheckTrue(LSoft.CheckChain(Chain), 'Soft soft-fails an unreachable responder');
    CheckFalse(LHard.CheckChain(Chain), 'Hard rejects an unreachable responder');
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
    CheckFalse(LHard.CheckChain(Chain), 'Hard rejects a malformed response');
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
    CheckFalse(LSoft.CheckChain(Chain), 'a CRL revocation rejects even under Soft');
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
    CheckTrue(LHard.CheckChain(Chain), 'a clean CRL accepts');
  finally
    LHard.Free;
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
    CheckFalse(LChecker.CheckChain(Chain),
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
    CheckTrue(LChecker.CheckChain(Chain), 'Off accepts the indeterminate outcome (soft)');
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
    CheckFalse(LHard.CheckChain(TArray<TBytes>.Create(LeafCert)),
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

{ TTestRevocationDecision }

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
  RegisterTest(TTestRevocationDecision);
{$ELSE}
  RegisterTest(TTestLiveRevocation.Suite);
  RegisterTest(TTestRevocationDecision.Suite);
{$ENDIF FPC}

end.
