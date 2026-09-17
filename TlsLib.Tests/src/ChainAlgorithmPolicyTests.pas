{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ChainAlgorithmPolicyTests;

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
  TlpTlsAlert,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpTrustPolicy,
  TlpCertificateStrengthPolicy,
  TlpNegotiationTypes,
  TlpChainAlgorithmPolicy,
  TlsLibTestBase;

type
  TTestChainAlgorithmPolicy = class(TTlsLibAlgorithmTestCase)
  private
    FEc: TStringList;
    FRsa: TStringList;
    function EcCert(const AName: string): TBytes;
    function RsaCert(const AName: string): TBytes;
    // the default advertised signature schemes (what a stock config offers)
    function Advertised: TArray<UInt16>;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEcP256LeafKeyFacts;
    procedure TestRsa2048LeafKeyFacts;
    procedure TestAcceptsStandardEcChain;
    procedure TestAcceptsStandardRsaChain;
    procedure TestAcceptsChainIncludingAnchor;
    procedure TestRejectsRsaBelowFloor;
    procedure TestRejectsUnadvertisedScheme;
    procedure TestRejectsDisallowedCurve;
  end;

implementation

{ TTestChainAlgorithmPolicy }

procedure TTestChainAlgorithmPolicy.SetUp;
begin
  inherited SetUp;
  FEc := LoadVectorFields('Certs/EcP256Chain.txt');
  FRsa := LoadVectorFields('Certs/Rsa2048Chain.txt');
end;

procedure TTestChainAlgorithmPolicy.TearDown;
begin
  FEc.Free;
  FRsa.Free;
  inherited TearDown;
end;

function TTestChainAlgorithmPolicy.EcCert(const AName: string): TBytes;
begin
  Result := DecodeHex(FEc.Values[AName]);
end;

function TTestChainAlgorithmPolicy.RsaCert(const AName: string): TBytes;
begin
  Result := DecodeHex(FRsa.Values[AName]);
end;

function TTestChainAlgorithmPolicy.Advertised: TArray<UInt16>;
begin
  Result := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
    TSignatureSchemes.EcdsaSecp384r1Sha384, TSignatureSchemes.EcdsaSecp521r1Sha512,
    TSignatureSchemes.RsaPssRsaeSha256, TSignatureSchemes.RsaPssRsaeSha384,
    TSignatureSchemes.RsaPssRsaeSha512, TSignatureSchemes.Ed25519,
    TSignatureSchemes.Ed448, TSignatureSchemes.RsaPkcs1Sha256,
    TSignatureSchemes.RsaPkcs1Sha384, TSignatureSchemes.RsaPkcs1Sha512);
end;

procedure TTestChainAlgorithmPolicy.TestEcP256LeafKeyFacts;
var
  LFacts: TCertKeyFacts;
begin
  CheckTrue(Provider.Certificates.Parse(EcCert('leaf_cert')).KeyFacts(LFacts),
    'the P-256 leaf key is classifiable');
  CheckTrue(LFacts.Kind = TCertKeyKind.Ecdsa, 'ECDSA key');
  CheckEquals(Integer(TNamedGroupCatalog.Secp256r1), Integer(LFacts.EcNamedGroup),
    'secp256r1 named group');
  CheckEquals(256, LFacts.Bits, 'P-256 field size');
end;

procedure TTestChainAlgorithmPolicy.TestRsa2048LeafKeyFacts;
var
  LFacts: TCertKeyFacts;
begin
  CheckTrue(Provider.Certificates.Parse(RsaCert('leaf_cert')).KeyFacts(LFacts),
    'the RSA leaf key is classifiable');
  CheckTrue(LFacts.Kind = TCertKeyKind.Rsa, 'RSA key');
  CheckEquals(2048, LFacts.Bits, 'RSA-2048 modulus');
end;

procedure TTestChainAlgorithmPolicy.TestAcceptsStandardEcChain;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TChainAlgorithmPolicy.Check(Provider.Certificates,
    TArray<TBytes>.Create(EcCert('leaf_cert')),
    TArray<TBytes>.Create(EcCert('root_cert')),
    TCertificateStrengthPolicy.Defaults, Advertised, LAlert),
    'a P-256 leaf signed with an advertised ECDSA scheme is accepted');
end;

procedure TTestChainAlgorithmPolicy.TestAcceptsStandardRsaChain;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TChainAlgorithmPolicy.Check(Provider.Certificates,
    TArray<TBytes>.Create(RsaCert('leaf_cert')),
    TArray<TBytes>.Create(RsaCert('root_cert')),
    TCertificateStrengthPolicy.Defaults, Advertised, LAlert),
    'an RSA-2048 leaf signed with an advertised scheme is accepted');
end;

procedure TTestChainAlgorithmPolicy.TestAcceptsChainIncludingAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  // the root appears at index > 0 and is DER-equal to a configured anchor, so it is exempt;
  // the leaf is still checked
  CheckTrue(TChainAlgorithmPolicy.Check(Provider.Certificates,
    TArray<TBytes>.Create(EcCert('leaf_cert'), EcCert('root_cert')),
    TArray<TBytes>.Create(EcCert('root_cert')),
    TCertificateStrengthPolicy.Defaults, Advertised, LAlert),
    'a chain that includes the trusted anchor is accepted');
end;

procedure TTestChainAlgorithmPolicy.TestRejectsRsaBelowFloor;
var
  LPolicy: TCertificateStrengthPolicy;
  LAlert: TTlsAlertDescription;
begin
  LPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.MinRsaModulusBits := 4096; // the 2048 leaf is now below the floor
  CheckFalse(TChainAlgorithmPolicy.Check(Provider.Certificates,
    TArray<TBytes>.Create(RsaCert('leaf_cert')),
    TArray<TBytes>.Create(RsaCert('root_cert')), LPolicy, Advertised, LAlert),
    'an RSA-2048 leaf is rejected under a 4096-bit floor');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a weak key is unsupported_certificate');
end;

procedure TTestChainAlgorithmPolicy.TestRejectsUnadvertisedScheme;
var
  LAlert: TTlsAlertDescription;
begin
  // advertise only RSA-PKCS1 schemes: the ECDSA-signed P-256 leaf now has no match
  CheckFalse(TChainAlgorithmPolicy.Check(Provider.Certificates,
    TArray<TBytes>.Create(EcCert('leaf_cert')),
    TArray<TBytes>.Create(EcCert('root_cert')),
    TCertificateStrengthPolicy.Defaults,
    TArray<UInt16>.Create(TSignatureSchemes.RsaPkcs1Sha256), LAlert),
    'a chain signed with an unadvertised scheme is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'an unadvertised algorithm is unsupported_certificate');
end;

procedure TTestChainAlgorithmPolicy.TestRejectsDisallowedCurve;
var
  LPolicy: TCertificateStrengthPolicy;
  LAlert: TTlsAlertDescription;
begin
  LPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  CheckFalse(TChainAlgorithmPolicy.Check(Provider.Certificates,
    TArray<TBytes>.Create(EcCert('leaf_cert')),
    TArray<TBytes>.Create(EcCert('root_cert')), LPolicy, Advertised, LAlert),
    'a P-256 leaf is rejected when the allowlist admits only P-384');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a disallowed curve is unsupported_certificate');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestChainAlgorithmPolicy);
{$ELSE}
  RegisterTest(TTestChainAlgorithmPolicy.Suite);
{$ENDIF FPC}

end.
