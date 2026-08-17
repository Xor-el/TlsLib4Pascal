{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit OcspStaplingTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  TlpDateTimeUtilities,
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlsLibTestBase;

type
  /// <summary>
  /// Stapled OCSP (RFC 6960) + RFC 7633 TLS Feature coverage: the provider verdict
  /// seam and the trust pipeline's revocation posture, driven by fixed vectors whose
  /// validity windows keep them durable.
  /// </summary>
  TTestOcspStapling = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function V(const AName: string): TBytes;
    function Chain: TArray<TBytes>;
    function ChainFor(const ALeafName: string): TArray<TBytes>;
    function VerifierFor(APosture: TRevocationPosture;
      AAsyncResolver: Boolean = False): ICertificateVerifier;
    function VerifyStaple(APosture: TRevocationPosture; const AStaple: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
    function VerifyChain(APosture: TRevocationPosture; const AChain: TArray<TBytes>;
      const AStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
    function LeafSpkiPin: TBytes;
    function VerifyWithPins(const APins: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    // provider verdict seam (ValidateOcspStaple / CertificateTlsFeatures)
    procedure TestValidateStapleGood;
    procedure TestValidateStapleRevoked;
    procedure TestValidateStapleDelegatedResponder;
    procedure TestValidateStapleUnauthorizedSigner;
    procedure TestValidateStapleWrongIssuer;
    procedure TestValidateStapleMalformed;
    procedure TestTlsFeaturesAbsentIsEmpty;
    procedure TestTlsFeaturesMustStaple;
    procedure TestTlsFeaturesMalformedRejected;
    // trust pipeline revocation posture
    procedure TestGoodStapleCompletes;
    procedure TestRevokedStapleAbortsCertificateRevoked;
    procedure TestDelegatedGoodStapleCompletes;
    procedure TestStaleStapleSoftCompletes;
    procedure TestStaleStapleHardAborts;
    procedure TestUnauthorizedStapleHardAborts;
    procedure TestNoStapleSoftCompletes;
    procedure TestNoStapleHardAborts;
    procedure TestOffSkipsStaleStaple;
    procedure TestOffStillRejectsRevokedStaple;
    // Hard with a live verdict resolver: an indeterminate/no-staple outcome is deferred to the
    // resolver (accepted here so the handshake reaches the park), not rejected inline. This is
    // what makes Hard reachable for a never-stapled peer (a client certificate).
    procedure TestNoStapleHardWithResolverDefers;
    procedure TestRevokedStapleAbortsEvenWithResolver;
    procedure TestMustStapleMissingStapleAbortsEvenWithResolver;
    // must-staple (RFC 7633) + TLS Feature well-formedness
    procedure TestMustStapleWithGoodStapleCompletes;
    procedure TestMustStapleMissingStapleAbortsUnderSoft;
    procedure TestMustStapleMissingStapleAbortsUnderOff;
    procedure TestMustStapleNonMatchingStapleAborts;
    procedure TestMalformedTlsFeatureAbortsBadCertificate;
    // SPKI public-key pinning
    procedure TestPinningMatchCompletes;
    procedure TestPinningNoMatchAbortsBadCertificate;
  end;

implementation

{ TTestOcspStapling }

procedure TTestOcspStapling.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Certs/OcspStapling.txt');
end;

procedure TTestOcspStapling.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestOcspStapling.V(const AName: string): TBytes;
begin
  Result := DecodeHex(FVec.Values[AName]);
end;

function TTestOcspStapling.Chain: TArray<TBytes>;
begin
  // leaf first, then its issuer (the intermediate that signs the staple)
  Result := TArray<TBytes>.Create(V('leaf_cert'), V('issuer_cert'));
end;

function TTestOcspStapling.VerifierFor(APosture: TRevocationPosture;
  AAsyncResolver: Boolean): ICertificateVerifier;
var
  LNoDangerous: TDangerousTrust;
begin
  // AAsyncResolver models an out-of-band verdict resolver (live OCSP/CRL) running at the park;
  // when set, an indeterminate stapled outcome is deferred to it instead of decided inline
  LNoDangerous := Default(TDangerousTrust);
  Result := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(V('root_cert')))
    as ITrustAnchorStore, False, TCertificateChainLimits.Defaults, APosture, nil,
    LNoDangerous, AAsyncResolver) as ICertificateVerifier;
end;

function TTestOcspStapling.ChainFor(const ALeafName: string): TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(V(ALeafName), V('issuer_cert'));
end;

function TTestOcspStapling.VerifyStaple(APosture: TRevocationPosture;
  const AStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := VerifierFor(APosture).Verify(Chain, '', AStaple, AAlert);
end;

function TTestOcspStapling.VerifyChain(APosture: TRevocationPosture;
  const AChain: TArray<TBytes>; const AStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := VerifierFor(APosture).Verify(AChain, '', AStaple, AAlert);
end;

function TTestOcspStapling.LeafSpkiPin: TBytes;
var
  LSpki: TBytes;
  LHash: IHash;
begin
  LSpki := Provider.CertificatePublicKeyInfo(V('leaf_cert'));
  LHash := Provider.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LSpki, 0, System.Length(LSpki));
  Result := LHash.DoFinal;
end;

function TTestOcspStapling.VerifyWithPins(const APins: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: ICertificateVerifier;
begin
  // revocation Off isolates the pinning step from the stapled-OCSP step
  LVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(V('root_cert')))
    as ITrustAnchorStore, False, TCertificateChainLimits.Defaults,
    TRevocationPosture.Off, APins) as ICertificateVerifier;
  Result := LVerifier.Verify(Chain, '', nil, AAlert);
end;

procedure TTestOcspStapling.TestValidateStapleGood;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  CheckTrue(Provider.ValidateOcspStaple(V('leaf_cert'), V('issuer_cert'),
    V('ocsp_good'), TDateTimeUtilities.ToUniversalTime(Now), LStatus, LThis, LNext),
    'an issuer-signed response about the leaf is authoritative');
  CheckEquals(Ord(TOcspStatus.Good), Ord(LStatus), 'the status is Good');
  CheckTrue(LNext > LThis, 'the validity window is well ordered');
end;

procedure TTestOcspStapling.TestValidateStapleRevoked;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  CheckTrue(Provider.ValidateOcspStaple(V('leaf_cert'), V('issuer_cert'),
    V('ocsp_revoked'), TDateTimeUtilities.ToUniversalTime(Now), LStatus, LThis,
    LNext), 'a revoked response is authoritative');
  CheckEquals(Ord(TOcspStatus.Revoked), Ord(LStatus), 'the status is Revoked');
end;

procedure TTestOcspStapling.TestValidateStapleDelegatedResponder;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  // signed by an id-kp-OCSPSigning responder the issuer delegated to (RFC 6960 4.2.2.2)
  CheckTrue(Provider.ValidateOcspStaple(V('leaf_cert'), V('issuer_cert'),
    V('ocsp_good_delegated'), TDateTimeUtilities.ToUniversalTime(Now), LStatus,
    LThis, LNext), 'a delegated responder is authoritative');
  CheckEquals(Ord(TOcspStatus.Good), Ord(LStatus), 'the status is Good');
end;

procedure TTestOcspStapling.TestValidateStapleUnauthorizedSigner;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  // signed by an unrelated CA the issuer never delegated to
  CheckFalse(Provider.ValidateOcspStaple(V('leaf_cert'), V('issuer_cert'),
    V('ocsp_unauthorized'), TDateTimeUtilities.ToUniversalTime(Now), LStatus,
    LThis, LNext), 'an unauthorized signer leaves the status indeterminate');
end;

procedure TTestOcspStapling.TestValidateStapleWrongIssuer;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  // the CertID names the real issuer, so it does not match an unrelated one
  CheckFalse(Provider.ValidateOcspStaple(V('leaf_cert'), V('other_ca_cert'),
    V('ocsp_good'), TDateTimeUtilities.ToUniversalTime(Now), LStatus, LThis, LNext),
    'a response whose CertID does not match the issuer is indeterminate');
end;

procedure TTestOcspStapling.TestValidateStapleMalformed;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  CheckFalse(Provider.ValidateOcspStaple(V('leaf_cert'), V('issuer_cert'),
    TBytes.Create(1, 2, 3, 4), TDateTimeUtilities.ToUniversalTime(Now), LStatus,
    LThis, LNext), 'an unparseable response returns False, never raises');
end;

procedure TTestOcspStapling.TestTlsFeaturesAbsentIsEmpty;
var
  LFeatures: TArray<UInt16>;
begin
  CheckTrue(Provider.CertificateTlsFeatures(V('leaf_cert'), LFeatures),
    'a certificate without the TLS Feature extension is well formed');
  CheckEquals(0, System.Length(LFeatures), 'it carries no features');
end;

procedure TTestOcspStapling.TestTlsFeaturesMustStaple;
var
  LFeatures: TArray<UInt16>;
begin
  CheckTrue(Provider.CertificateTlsFeatures(V('muststaple_leaf_cert'), LFeatures),
    'a well-formed TLS Feature extension parses');
  CheckEquals(1, System.Length(LFeatures), 'it lists one feature');
  CheckEquals(5, LFeatures[0], 'the feature is status_request (5)');
end;

procedure TTestOcspStapling.TestTlsFeaturesMalformedRejected;
var
  LFeatures: TArray<UInt16>;
begin
  // the extension value is a bare INTEGER, not a SEQUENCE OF INTEGER
  CheckFalse(Provider.CertificateTlsFeatures(V('badfeature_leaf_cert'), LFeatures),
    'a non-SEQUENCE TLS Feature value is rejected as malformed');
end;

procedure TTestOcspStapling.TestGoodStapleCompletes;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyStaple(TRevocationPosture.Soft, V('ocsp_good'), LAlert),
    'a current Good staple lets the chain validate');
end;

procedure TTestOcspStapling.TestRevokedStapleAbortsCertificateRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyStaple(TRevocationPosture.Soft, V('ocsp_revoked'), LAlert),
    'a revoked staple aborts even under soft-fail');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestOcspStapling.TestDelegatedGoodStapleCompletes;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyStaple(TRevocationPosture.Soft, V('ocsp_good_delegated'), LAlert),
    'a Good staple from a delegated responder lets the chain validate');
end;

procedure TTestOcspStapling.TestStaleStapleSoftCompletes;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyStaple(TRevocationPosture.Soft, V('ocsp_stale'), LAlert),
    'a stale staple is indeterminate, which soft-fail accepts');
end;

procedure TTestOcspStapling.TestStaleStapleHardAborts;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyStaple(TRevocationPosture.Hard, V('ocsp_stale'), LAlert),
    'a stale staple is indeterminate, which hard-fail rejects');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOcspStapling.TestUnauthorizedStapleHardAborts;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyStaple(TRevocationPosture.Hard, V('ocsp_unauthorized'), LAlert),
    'an unauthorized staple is indeterminate, which hard-fail rejects');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOcspStapling.TestNoStapleSoftCompletes;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyStaple(TRevocationPosture.Soft, nil, LAlert),
    'a missing staple is accepted under soft-fail');
end;

procedure TTestOcspStapling.TestNoStapleHardAborts;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyStaple(TRevocationPosture.Hard, nil, LAlert),
    'a missing staple is rejected under hard-fail');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOcspStapling.TestNoStapleHardWithResolverDefers;
var
  LAlert: TTlsAlertDescription;
begin
  // with a live verdict resolver, a no-staple leaf under Hard is accepted here (deferred) so the
  // handshake reaches the park where the resolver decides - not rejected inline
  CheckTrue(VerifierFor(TRevocationPosture.Hard, {AAsyncResolver=} True)
    .Verify(Chain, '', nil, LAlert),
    'a missing staple under Hard is deferred to the resolver, not rejected inline');
end;

procedure TTestOcspStapling.TestRevokedStapleAbortsEvenWithResolver;
var
  LAlert: TTlsAlertDescription;
begin
  // a definitive stapled Revoked is authoritative and short-circuits before any deferral
  CheckFalse(VerifierFor(TRevocationPosture.Hard, {AAsyncResolver=} True)
    .Verify(Chain, '', V('ocsp_revoked'), LAlert),
    'a revoked staple aborts even when a resolver is present');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestOcspStapling.TestMustStapleMissingStapleAbortsEvenWithResolver;
var
  LAlert: TTlsAlertDescription;
begin
  // RFC 7633: a must-staple leaf demands a current Good staple; a live fetch does not satisfy it,
  // so it is rejected inline even with a resolver present (the deferral never applies)
  CheckFalse(VerifierFor(TRevocationPosture.Hard, {AAsyncResolver=} True)
    .Verify(ChainFor('muststaple_leaf_cert'), '', nil, LAlert),
    'a must-staple leaf with no staple aborts even with a resolver present');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOcspStapling.TestOffSkipsStaleStaple;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyStaple(TRevocationPosture.Off, V('ocsp_stale'), LAlert),
    'with revocation off the stapled response is not consulted');
end;

procedure TTestOcspStapling.TestOffStillRejectsRevokedStaple;
var
  LAlert: TTlsAlertDescription;
begin
  // the posture governs only unknown/indeterminate status; a definitive, authenticated
  // Revoked in hand is honored under every posture, Off included
  CheckFalse(VerifyStaple(TRevocationPosture.Off, V('ocsp_revoked'), LAlert),
    'a definitive revoked staple aborts even with revocation off');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestOcspStapling.TestMustStapleWithGoodStapleCompletes;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyChain(TRevocationPosture.Soft, ChainFor('muststaple_leaf_cert'),
    V('ocsp_muststaple_good'), LAlert),
    'a must-staple leaf with a current Good staple validates');
end;

procedure TTestOcspStapling.TestMustStapleMissingStapleAbortsUnderSoft;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyChain(TRevocationPosture.Soft, ChainFor('muststaple_leaf_cert'),
    nil, LAlert),
    'a must-staple leaf with no staple aborts even under soft-fail');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOcspStapling.TestMustStapleMissingStapleAbortsUnderOff;
var
  LAlert: TTlsAlertDescription;
begin
  // must-staple overrides the posture: it is enforced even with revocation off
  CheckFalse(VerifyChain(TRevocationPosture.Off, ChainFor('muststaple_leaf_cert'),
    nil, LAlert),
    'a must-staple leaf with no staple aborts even with revocation off');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOcspStapling.TestMustStapleNonMatchingStapleAborts;
var
  LAlert: TTlsAlertDescription;
begin
  // a staple about a different certificate does not satisfy must-staple
  CheckFalse(VerifyChain(TRevocationPosture.Soft, ChainFor('muststaple_leaf_cert'),
    V('ocsp_good'), LAlert),
    'a must-staple leaf is not satisfied by a staple about another certificate');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOcspStapling.TestMalformedTlsFeatureAbortsBadCertificate;
var
  LAlert: TTlsAlertDescription;
begin
  // a non-SEQUENCE TLS Feature value is fatal regardless of posture or staple
  CheckFalse(VerifyChain(TRevocationPosture.Off, ChainFor('badfeature_leaf_cert'),
    nil, LAlert),
    'a malformed TLS Feature extension aborts the handshake');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestOcspStapling.TestPinningMatchCompletes;
var
  LAlert: TTlsAlertDescription;
begin
  // pinning the leaf's SPKI lets the chain validate (pinning augments PKIX)
  CheckTrue(VerifyWithPins(TArray<TBytes>.Create(LeafSpkiPin), LAlert),
    'a chain whose leaf SPKI matches a pin validates');
end;

procedure TTestOcspStapling.TestPinningNoMatchAbortsBadCertificate;
var
  LWrongPin: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // a pin that matches no certificate in the chain rejects it
  LWrongPin := LeafSpkiPin;
  LWrongPin[0] := LWrongPin[0] xor $FF;
  CheckFalse(VerifyWithPins(TArray<TBytes>.Create(LWrongPin), LAlert),
    'a chain that matches no pin is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestOcspStapling);
{$ELSE}
  RegisterTest(TTestOcspStapling.Suite);
{$ENDIF FPC}

end.
