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
    // id-RSASSA-PSS key type (CertificateHasRsaPssKey)
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
begin
  // asserts the certificate parsed (method result True) and reports the permission
  CheckTrue(Provider.Certificates.KeyUsagePermits(V(ACertName), AUsage, Result),
    'the certificate should parse');
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
var
  LPermitted: Boolean;
begin
  // a certificate that does not parse cannot restrict usage: result False, permitted True
  CheckFalse(Provider.Certificates.KeyUsagePermits(
    TBytes.Create(1, 2, 3, 4), TCertKeyUsage.DigitalSignature, LPermitted),
    'a malformed certificate cannot be determined');
  CheckTrue(LPermitted, 'an undeterminable certificate imposes no restriction');
end;

procedure TTestCertificateChecks.TestRsaPssKeyIsDetected;
var
  LIsRsaPss: Boolean;
begin
  CheckTrue(Provider.Certificates.HasRsaPssKey(V('rsapss_cert'), LIsRsaPss),
    'the certificate should parse');
  CheckTrue(LIsRsaPss, 'an id-RSASSA-PSS SubjectPublicKeyInfo is detected');
end;

procedure TTestCertificateChecks.TestNormalRsaKeyIsNotPss;
var
  LIsRsaPss: Boolean;
begin
  CheckTrue(Provider.Certificates.HasRsaPssKey(V('rsa_normal_cert'), LIsRsaPss),
    'the certificate should parse');
  CheckFalse(LIsRsaPss, 'an rsaEncryption key is not id-RSASSA-PSS');
end;

procedure TTestCertificateChecks.TestEcKeyIsNotPss;
var
  LIsRsaPss: Boolean;
begin
  CheckTrue(Provider.Certificates.HasRsaPssKey(V('ku_digsig_cert'), LIsRsaPss),
    'the certificate should parse');
  CheckFalse(LIsRsaPss, 'an ecPublicKey key is not id-RSASSA-PSS');
end;

procedure TTestCertificateChecks.TestMalformedCertIsNotPss;
var
  LIsRsaPss: Boolean;
begin
  CheckFalse(Provider.Certificates.HasRsaPssKey(TBytes.Create(9, 9, 9), LIsRsaPss),
    'a malformed certificate cannot be determined');
  CheckFalse(LIsRsaPss, 'an undeterminable certificate is not reported as PSS');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateChecks);
{$ELSE}
  RegisterTest(TTestCertificateChecks.Suite);
{$ENDIF FPC}

end.
