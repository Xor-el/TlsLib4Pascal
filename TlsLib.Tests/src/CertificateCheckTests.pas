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
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlsLibTestBase;

type
  /// <summary>
  /// The provider certificate introspection seam used by the handshake to police a
  /// leaf's key: the keyUsage extension (RFC 5280 4.2.1.3) that must permit signing
  /// and the id-RSASSA-PSS key type (RFC 8446 4.2.3) the rsa_pss_rsae schemes reject.
  /// Driven by single-certificate vectors parsed in isolation.
  /// </summary>
  TTestCertificateChecks = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function V(const AName: string): TBytes;
    function Permits(const ACertName: string; AUsage: TCertKeyUsage): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
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
  end;

implementation

{ TTestCertificateChecks }

procedure TTestCertificateChecks.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Certs/KeyUsagePss.txt');
end;

procedure TTestCertificateChecks.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestCertificateChecks.V(const AName: string): TBytes;
begin
  Result := DecodeHex(FVec.Values[AName]);
end;

function TTestCertificateChecks.Permits(const ACertName: string;
  AUsage: TCertKeyUsage): Boolean;
var
  LAnswer: TCertAnswer;
begin
  // asserts the certificate yields a determined answer (never Undetermined) and reports
  // whether it permits the usage
  LAnswer := Provider.Certificates.KeyUsagePermits(V(ACertName), AUsage);
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
    Ord(Provider.Certificates.KeyUsagePermits(
    TBytes.Create(1, 2, 3, 4), TCertKeyUsage.DigitalSignature)),
    'a malformed certificate cannot be determined');
end;

procedure TTestCertificateChecks.TestRsaPssKeyIsDetected;
begin
  CheckEquals(Ord(TCertAnswer.Yes),
    Ord(Provider.Certificates.KeyIsRsaPss(V('rsapss_cert'))),
    'an id-RSASSA-PSS SubjectPublicKeyInfo is detected');
end;

procedure TTestCertificateChecks.TestNormalRsaKeyIsNotPss;
begin
  CheckEquals(Ord(TCertAnswer.No),
    Ord(Provider.Certificates.KeyIsRsaPss(V('rsa_normal_cert'))),
    'an rsaEncryption key is not id-RSASSA-PSS');
end;

procedure TTestCertificateChecks.TestEcKeyIsNotPss;
begin
  CheckEquals(Ord(TCertAnswer.No),
    Ord(Provider.Certificates.KeyIsRsaPss(V('ku_digsig_cert'))),
    'an ecPublicKey key is not id-RSASSA-PSS');
end;

procedure TTestCertificateChecks.TestMalformedCertIsNotPss;
begin
  CheckEquals(Ord(TCertAnswer.Undetermined),
    Ord(Provider.Certificates.KeyIsRsaPss(TBytes.Create(9, 9, 9))),
    'a malformed certificate cannot be determined');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateChecks);
{$ELSE}
  RegisterTest(TTestCertificateChecks.Suite);
{$ENDIF FPC}

end.
