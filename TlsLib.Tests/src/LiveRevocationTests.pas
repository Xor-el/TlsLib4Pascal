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
  /// A fake IHttpFetcher: it returns a preset response (or a failure) for GET and POST,
  /// so the live-revocation checker's fetch/parse/verdict logic is exercised with no real
  /// network. Records the last URL for assertions.
  /// </summary>
  TFakeHttpFetcher = class(TInterfacedObject, IHttpFetcher)
  strict private
  var
    FGetOk, FPostOk: Boolean;
    FGetBody, FPostBody: TBytes;
    FLastPostUrl, FLastGetUrl: string;
    FGetCount, FPostCount: Int32;
  public
    constructor Create;
    function Get(const AUrl: string; ATimeoutMs: Cardinal;
      out AResponse: TBytes): Boolean;
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean;
    procedure SetPost(AOk: Boolean; const ABody: TBytes);
    procedure SetGet(AOk: Boolean; const ABody: TBytes);
    property LastPostUrl: string read FLastPostUrl;
    property LastGetUrl: string read FLastGetUrl;
    /// <summary>How many times Get/Post were invoked (0 proves no live fetch happened).</summary>
    property GetCount: Int32 read FGetCount;
    property PostCount: Int32 read FPostCount;
  end;

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
  published
    // provider primitives
    procedure TestOcspResponderUrlExtracted;
    procedure TestCrlDistributionPointsExtracted;
    procedure TestBuildOcspRequestNonEmpty;
    procedure TestCertificatePeerInfoExtracted;
    procedure TestCrlRevocationDetectsRevoked;
    procedure TestCrlRevocationDetectsNotRevoked;
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

implementation

{ TFakeHttpFetcher }

constructor TFakeHttpFetcher.Create;
begin
  inherited Create;
  FGetOk := False;
  FPostOk := False;
end;

function TFakeHttpFetcher.Get(const AUrl: string; ATimeoutMs: Cardinal;
  out AResponse: TBytes): Boolean;
begin
  Inc(FGetCount);
  FLastGetUrl := AUrl;
  Result := FGetOk;
  if Result then
    AResponse := System.Copy(FGetBody)
  else
    AResponse := nil;
end;

function TFakeHttpFetcher.Post(const AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean;
begin
  Inc(FPostCount);
  FLastPostUrl := AUrl;
  Result := FPostOk;
  if Result then
    AResponse := System.Copy(FPostBody)
  else
    AResponse := nil;
end;

procedure TFakeHttpFetcher.SetPost(AOk: Boolean; const ABody: TBytes);
begin
  FPostOk := AOk;
  FPostBody := ABody;
end;

procedure TFakeHttpFetcher.SetGet(AOk: Boolean; const ABody: TBytes);
begin
  FGetOk := AOk;
  FGetBody := ABody;
end;

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
  Result := TLiveRevocationChecker.Create(Provider, TSystemClock.Create as ITlsClock,
    AFetcher, APosture, AMethod, 0);
end;

procedure TTestLiveRevocation.TestOcspResponderUrlExtracted;
var
  LUrl: string;
begin
  CheckTrue(Provider.Revocation.TryGetOcspResponderUrl(LeafCert, LUrl),
    'the leaf AIA carries an OCSP responder URL');
  CheckEquals('http://ocsp.tlslib.test/', LUrl, 'the OCSP URL is extracted verbatim');
end;

procedure TTestLiveRevocation.TestCrlDistributionPointsExtracted;
var
  LUrls: TArray<string>;
begin
  CheckTrue(Provider.Revocation.TryGetCrlDistributionPoints(LeafCert, LUrls),
    'the leaf carries a CRL distribution point');
  CheckTrue(System.Length(LUrls) >= 1, 'at least one CRL URL is returned');
  CheckEquals('http://crl.tlslib.test/ca.crl', LUrls[0], 'the CRL URL is extracted');
end;

procedure TTestLiveRevocation.TestBuildOcspRequestNonEmpty;
var
  LReq: TBytes;
begin
  CheckTrue(Provider.Revocation.BuildOcspRequest(LeafCert, CaCert, LReq),
    'an OCSP request is built for the leaf/issuer');
  CheckTrue(System.Length(LReq) > 0, 'the OCSP request is non-empty DER');
end;

procedure TTestLiveRevocation.TestCertificatePeerInfoExtracted;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
begin
  // the neutral peer-identity accessor an adapter's native verify hook (Synapse GetPeer*)
  // reads, so no adapter touches a CryptoLib type
  CheckTrue(Provider.Certificates.PeerInfo(LeafCert, LSubject, LIssuer, LCommonName,
    LSerialHex), 'peer info is extracted from the leaf');
  CheckEquals('localhost', LCommonName, 'the leaf common name is localhost');
  CheckTrue(Pos('localhost', LSubject) > 0, 'the subject DN carries the common name');
  CheckTrue(Pos('TlsLib Live CA', LIssuer) > 0, 'the issuer DN is the CA');
  CheckTrue(LSerialHex <> '', 'a serial number is reported');
end;

procedure TTestLiveRevocation.TestCrlRevocationDetectsRevoked;
var
  LRevoked: Boolean;
begin
  CheckTrue(Provider.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlRevoked, LRevoked),
    'the issuer-signed CRL parses and verifies');
  CheckTrue(LRevoked, 'the leaf serial is listed as revoked in the CRL');
end;

procedure TTestLiveRevocation.TestCrlRevocationDetectsNotRevoked;
var
  LRevoked: Boolean;
begin
  CheckTrue(Provider.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlGood, LRevoked),
    'the issuer-signed CRL parses and verifies');
  CheckFalse(LRevoked, 'the leaf is not listed in the good CRL');
end;

procedure TTestLiveRevocation.TestLiveOcspGoodAccepts;
var
  LFetcher: TFakeHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LSoft, LHard: TLiveRevocationChecker;
begin
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LSoft, LHard: TLiveRevocationChecker;
begin
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LHard: TLiveRevocationChecker;
begin
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LSoft: TLiveRevocationChecker;
begin
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LHard: TLiveRevocationChecker;
begin
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  // a validly-signed but expired CRL (nextUpdate in the past), leaf absent: without the window
  // check it reads as a definitive Good; the window check makes it indeterminate, defeating a
  // stale-CRL replay. The provider primitive reports it directly, and the checker follows the
  // posture (Hard rejects).
  CheckFalse(Provider.Revocation.CheckCrlRevocation(LeafCert, CaCert, CrlStale, LRevoked),
    'a stale CRL (out of its validity window) is not authoritative');
  CheckFalse(LRevoked, 'a stale CRL yields no definitive revocation');

  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LChecker: TLiveRevocationChecker;
begin
  // Off suppresses the live fetch entirely (network + privacy cost): even with a Revoked OCSP
  // and CRL primed, the checker never calls the fetcher and yields Indeterminate -> accept (Off
  // is soft). A stapled Revoked would still be caught upstream, before the park.
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LHard: TLiveRevocationChecker;
begin
  LFetcher := TFakeHttpFetcher.Create;
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
  LFetcher: TFakeHttpFetcher;
  LChecker: TLiveRevocationChecker;
  LAlert: TTlsAlertDescription;
begin
  // the checker plugs into the Tier-2 verdict resolver seam: a live Revoked -> reject, and it
  // must abort with certificate_revoked, not the generic bad_certificate
  LFetcher := TFakeHttpFetcher.Create;
  LFetcher.SetPost(True, OcspRevoked);
  LChecker := NewChecker(LFetcher as IHttpFetcher, TRevocationPosture.Soft,
    TLiveRevocationMethod.Ocsp);
  try
    LAlert := TTlsAlertDescription.BadCertificate;
    CheckFalse(LChecker.ResolveVerdict(Chain, 'localhost', LAlert),
      'ResolveVerdict rejects a live-revoked chain');
    CheckTrue(LAlert = TTlsAlertDescription.CertificateRevoked,
      'a live Revoked aborts with certificate_revoked');
  finally
    LChecker.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestLiveRevocation);
{$ELSE}
  RegisterTest(TTestLiveRevocation.Suite);
{$ENDIF FPC}

end.
