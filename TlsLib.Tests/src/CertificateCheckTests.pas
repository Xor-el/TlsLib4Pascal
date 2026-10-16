{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CertificateCheckTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpPkixDomainTypes,
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  MockPkixProvider,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>
  /// The provider certificate introspection seam used by the handshake to police a
  /// leaf's key: the keyUsage extension (RFC 5280 4.2.1.3) that must permit signing
  /// and the id-RSASSA-PSS key type (RFC 9846 4.3.3) the rsa_pss_rsae schemes reject.
  /// Driven by single-certificate vectors parsed in isolation.
  /// </summary>
  TTestCertificateChecks = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function V(const AName: string): TBytes;
    function Permits(const ACertName: string; AUsage: TCertKeyUsage): Boolean;
  protected
    procedure SetUp; override;
  published
    // basicConstraints cA (IsCertificateAuthority)
    procedure TestCaCertificateIsAnAuthority;
    procedure TestSelfSignedCaCertificateIsAnAuthority;
    procedure TestEndEntityCertificateIsNotAnAuthority;
    procedure TestMalformedCertIsNotDeterminedAsAuthority;
    // keyUsage (CertificateKeyUsagePermits)
    procedure TestDigitalSignatureCertPermitsSigning;
    procedure TestKeyEnciphermentCertForbidsSigning;
    procedure TestKeyAgreementCertForbidsSigning;
    procedure TestAbsentKeyUsagePermitsSigning;
    procedure TestKeyEnciphermentCertPermitsEncipherment;
    procedure TestMalformedCertLeavesUsagePermitted;
    // id-RSASSA-PSS key type (CertificateKeyIsRsaPss)
    procedure TestRsaPssKeyIsDetected;
    procedure TestNormalRsaKeyIsNotPss;
    procedure TestEcKeyIsNotPss;
    procedure TestMalformedCertIsNotPss;
    // provider composition (TPkixProviderBuilder)
    procedure TestPkixBuilderHoldsASuppliedPathValidator;
  end;

implementation

{ TTestCertificateChecks }

procedure TTestCertificateChecks.SetUp;
begin
  inherited SetUp;
  FVec := Own<TStringList>(LoadVectorFields('Certs/KeyUsagePss.txt'));
end;

function TTestCertificateChecks.V(const AName: string): TBytes;
begin
  Result := DecodeHex(FVec.Values[AName]);
end;

procedure TTestCertificateChecks.TestCaCertificateIsAnAuthority;
begin
  CheckEquals(Ord(TCertAnswer.Yes),
    Ord(Pkix.Certificates.IsCertificateAuthority(
      TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'caleaf_cert'))),
    'a certificate asserting cA=TRUE is an authority');
end;

procedure TTestCertificateChecks.TestSelfSignedCaCertificateIsAnAuthority;
begin
  CheckEquals(Ord(TCertAnswer.Yes),
    Ord(Pkix.Certificates.IsCertificateAuthority(
      TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'selfca_cert'))),
    'a self-signed certificate asserting cA=TRUE is an authority');
end;

procedure TTestCertificateChecks.TestEndEntityCertificateIsNotAnAuthority;
begin
  CheckEquals(Ord(TCertAnswer.No),
    Ord(Pkix.Certificates.IsCertificateAuthority(
      TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'leaf_cert'))),
    'a certificate with cA=FALSE is not an authority');
end;

procedure TTestCertificateChecks.TestMalformedCertIsNotDeterminedAsAuthority;
begin
  CheckEquals(Ord(TCertAnswer.Undetermined),
    Ord(Pkix.Certificates.IsCertificateAuthority(TBytes.Create(7, 7, 7))),
    'a malformed certificate cannot be determined');
end;

function TTestCertificateChecks.Permits(const ACertName: string;
  AUsage: TCertKeyUsage): Boolean;
var
  LAnswer: TCertAnswer;
begin
  // asserts the certificate yields a determined answer (never Undetermined) and reports
  // whether it permits the usage
  LAnswer := Pkix.Certificates.KeyUsagePermits(V(ACertName), AUsage);
  CheckTrue(LAnswer <> TCertAnswer.Undetermined, 'the certificate should parse');
  Result := LAnswer = TCertAnswer.Yes;
end;

procedure TTestCertificateChecks.TestDigitalSignatureCertPermitsSigning;
begin
  CheckTrue(Permits('ku_digsig_cert', TCertKeyUsage.DigitalSignature),
    'a digitalSignature keyUsage permits signing');
end;

procedure TTestCertificateChecks.TestKeyEnciphermentCertForbidsSigning;
begin
  CheckFalse(Permits('ku_keyenc_cert', TCertKeyUsage.DigitalSignature),
    'a keyEncipherment-only keyUsage forbids signing');
end;

procedure TTestCertificateChecks.TestKeyAgreementCertForbidsSigning;
begin
  CheckFalse(Permits('ku_keyagree_cert', TCertKeyUsage.DigitalSignature),
    'a keyAgreement-only keyUsage forbids signing (the ECDSAKeyUsage case)');
end;

procedure TTestCertificateChecks.TestAbsentKeyUsagePermitsSigning;
begin
  CheckTrue(Permits('ku_none_cert', TCertKeyUsage.DigitalSignature),
    'an absent keyUsage extension imposes no restriction');
end;

procedure TTestCertificateChecks.TestKeyEnciphermentCertPermitsEncipherment;
begin
  CheckTrue(Permits('ku_keyenc_cert', TCertKeyUsage.KeyEncipherment),
    'a keyEncipherment keyUsage permits key transport');
end;

procedure TTestCertificateChecks.TestMalformedCertLeavesUsagePermitted;
begin
  // a certificate that does not parse cannot restrict usage: the answer is Undetermined
  CheckEquals(Ord(TCertAnswer.Undetermined),
    Ord(Pkix.Certificates.KeyUsagePermits(
    TBytes.Create(1, 2, 3, 4), TCertKeyUsage.DigitalSignature)),
    'a malformed certificate cannot be determined');
end;

procedure TTestCertificateChecks.TestRsaPssKeyIsDetected;
begin
  CheckEquals(Ord(TCertAnswer.Yes),
    Ord(Pkix.Certificates.KeyIsRsaPss(V('rsapss_cert'))),
    'an id-RSASSA-PSS SubjectPublicKeyInfo is detected');
end;

procedure TTestCertificateChecks.TestNormalRsaKeyIsNotPss;
begin
  CheckEquals(Ord(TCertAnswer.No),
    Ord(Pkix.Certificates.KeyIsRsaPss(V('rsa_normal_cert'))),
    'an rsaEncryption key is not id-RSASSA-PSS');
end;

procedure TTestCertificateChecks.TestEcKeyIsNotPss;
begin
  CheckEquals(Ord(TCertAnswer.No),
    Ord(Pkix.Certificates.KeyIsRsaPss(V('ku_digsig_cert'))),
    'an ecPublicKey key is not id-RSASSA-PSS');
end;

procedure TTestCertificateChecks.TestMalformedCertIsNotPss;
begin
  CheckEquals(Ord(TCertAnswer.Undetermined),
    Ord(Pkix.Certificates.KeyIsRsaPss(TBytes.Create(9, 9, 9))),
    'a malformed certificate cannot be determined');
end;

procedure TTestCertificateChecks.TestPkixBuilderHoldsASuppliedPathValidator;
var
  LValidator: ICertificatePathValidator;
  LBuilder: IPkixProviderBuilder;
  LProvider: IPkixProvider;
begin
  LValidator := TCountingPathValidator.Create(Pkix.PathValidation) as ICertificatePathValidator;
  LBuilder := TPkixProviderBuilder.Create as IPkixProviderBuilder;
  LProvider := LBuilder.WithPathValidation(LValidator).Build;
  CheckTrue(LProvider.PathValidation = LValidator, 'the supplied path validator is held as-is');
  CheckTrue(LProvider.Certificates <> nil, 'an unsupplied inspector is defaulted');
  CheckTrue(LProvider.Revocation <> nil, 'an unsupplied revocation checker is defaulted');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateChecks);
{$ELSE}
  RegisterTest(TTestCertificateChecks.Suite);
{$ENDIF FPC}

end.
