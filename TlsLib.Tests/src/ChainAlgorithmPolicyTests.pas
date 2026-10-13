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
  TlpPkixDomainTypes,
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
    FPss: TStringList;
    function EcCert(const AName: string): TBytes;
    function RsaCert(const AName: string): TBytes;
    function PssCert(const AName: string): TBytes;
    // the default advertised signature schemes (what a stock config offers)
    function Advertised: TArray<UInt16>;
  protected
    procedure SetUp; override;
  published
    procedure TestEcP256LeafKeyFacts;
    procedure TestRsa2048LeafKeyFacts;
    procedure TestAcceptsStandardEcChain;
    procedure TestAcceptsStandardRsaChain;
    procedure TestAcceptsChainIncludingAnchor;
    procedure TestRejectsRsaBelowFloor;
    procedure TestRejectsUnadvertisedScheme;
    procedure TestRejectsDisallowedCurve;
    procedure TestAcceptsRsaPssPssIssuerWhenAdvertised;
    procedure TestRejectsRsaPssPssIssuerWhenOnlyRsaeAdvertised;
    procedure TestSignatureHashStandings;
    procedure TestDefaultsAdmitNoDeprecatedHash;
    procedure TestAdmittedSha1KeepsTheKeyFloors;
    procedure TestMd5IsRefusedEvenWhenNamedInThePolicy;
  end;

  /// <summary>The end-entity rule both verifiers share: a CA certificate is no identity unless the
  /// operator trusts that very certificate as an anchor.</summary>
  TTestEndEntityPolicy = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestAdmitsAnEndEntityCertificate;
    procedure TestRefusesACaCertificateThatIsNotAnAnchor;
    procedure TestAdmitsACaCertificateThatIsItselfAnAnchor;
    procedure TestRefusesACaCertificateWhenAnotherCertificateIsTheAnchor;
    procedure TestRefusesALeafItCannotDetermine;
    procedure TestRefusesAnEmptyPath;
  end;

implementation

{ TTestEndEntityPolicy }

procedure TTestEndEntityPolicy.TestAdmitsAnEndEntityCertificate;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TEndEntityPolicy.Admits(Pkix.Certificates,
    TArray<TBytes>.Create(CriticalExtensionsCertificate('leaf_cert'),
    CriticalExtensionsCertificate('root_cert')),
    TArray<TBytes>.Create(CriticalExtensionsCertificate('root_cert')), LAlert),
    'a cA=FALSE leaf is admitted');
end;

procedure TTestEndEntityPolicy.TestRefusesACaCertificateThatIsNotAnAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(TEndEntityPolicy.Admits(Pkix.Certificates,
    TArray<TBytes>.Create(CriticalExtensionsCertificate('caleaf_cert'),
    CriticalExtensionsCertificate('root_cert')),
    TArray<TBytes>.Create(CriticalExtensionsCertificate('root_cert')), LAlert),
    'a cA=TRUE leaf under a root is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestEndEntityPolicy.TestAdmitsACaCertificateThatIsItselfAnAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TEndEntityPolicy.Admits(Pkix.Certificates,
    TArray<TBytes>.Create(CriticalExtensionsCertificate('selfca_cert')),
    TArray<TBytes>.Create(CriticalExtensionsCertificate('selfca_cert')), LAlert),
    'a directly trusted self-signed CA certificate is admitted');
end;

procedure TTestEndEntityPolicy.TestRefusesACaCertificateWhenAnotherCertificateIsTheAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(TEndEntityPolicy.Admits(Pkix.Certificates,
    TArray<TBytes>.Create(CriticalExtensionsCertificate('selfca_cert')),
    TArray<TBytes>.Create(CriticalExtensionsCertificate('root_cert')), LAlert),
    'the same certificate is refused when it is not the configured anchor');
end;

procedure TTestEndEntityPolicy.TestRefusesALeafItCannotDetermine;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(TEndEntityPolicy.Admits(Pkix.Certificates,
    TArray<TBytes>.Create(TBytes.Create(1, 2, 3)),
    TArray<TBytes>.Create(TBytes.Create(1, 2, 3)), LAlert),
    'an undeterminable answer fails closed even for an anchor-identical leaf');
end;

procedure TTestEndEntityPolicy.TestRefusesAnEmptyPath;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(TEndEntityPolicy.Admits(Pkix.Certificates, nil, nil, LAlert),
    'a path with no certificate is refused');
end;

{ TTestChainAlgorithmPolicy }

procedure TTestChainAlgorithmPolicy.TestSignatureHashStandings;
var
  LHash: TCertSignatureHash;
begin
  // the one table the chain policy and the revocation floor both read
  for LHash := Low(TCertSignatureHash) to High(TCertSignatureHash) do
    case LHash of
      TCertSignatureHash.Md5:
        CheckEquals(Ord(TCertSignatureHashStanding.Forbidden), Ord(LHash.Standing), 'MD5');
      TCertSignatureHash.Sha1:
        CheckEquals(Ord(TCertSignatureHashStanding.Deprecated), Ord(LHash.Standing), 'SHA-1');
    else
      CheckEquals(Ord(TCertSignatureHashStanding.Current), Ord(LHash.Standing),
        'every other hash is current');
    end;
end;

procedure TTestChainAlgorithmPolicy.TestDefaultsAdmitNoDeprecatedHash;
begin
  CheckTrue(TCertificateStrengthPolicy.Defaults.AllowedDeprecatedHashes = [],
    'the presets admit no deprecated hash');
end;

procedure TTestChainAlgorithmPolicy.TestAdmittedSha1KeepsTheKeyFloors;
var
  LVec: TStringList;
  LAlert: TTlsAlertDescription;
  LPolicy: TCertificateStrengthPolicy;
  LChain: TArray<TBytes>;
begin
  LVec := LoadVectorFields('Certs/LegacyHashChain.txt');
  try
    // the SHA-1-signed 2048-bit issuer alone, so the hash and the key are the only things judged
    LChain := TArray<TBytes>.Create(DecodeHex(LVec.Values['issuer_sha1_cert']));
    LPolicy := TCertificateStrengthPolicy.Defaults;
    CheckFalse(TChainAlgorithmPolicy.Check(Pkix.Certificates, LChain, nil, LPolicy,
      Advertised, LAlert), 'SHA-1 is refused unless named');
    CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'refusal alert');
    LPolicy.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
    CheckTrue(TChainAlgorithmPolicy.Check(Pkix.Certificates, LChain, nil, LPolicy,
      Advertised, LAlert), 'naming SHA-1 admits the certificate');
    LPolicy.MinRsaModulusBits := 3072;
    CheckFalse(TChainAlgorithmPolicy.Check(Pkix.Certificates, LChain, nil, LPolicy,
      Advertised, LAlert), 'admitting SHA-1 does not relax the RSA key floor');
    CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert), 'key floor alert');
  finally
    LVec.Free;
  end;
end;

procedure TTestChainAlgorithmPolicy.TestMd5IsRefusedEvenWhenNamedInThePolicy;
var
  LVec: TStringList;
  LAlert: TTlsAlertDescription;
  LPolicy: TCertificateStrengthPolicy;
begin
  LVec := LoadVectorFields('Certs/LegacyHashChain.txt');
  try
    LPolicy := TCertificateStrengthPolicy.Defaults;
    LPolicy.AllowedDeprecatedHashes := [TCertSignatureHash.Md5, TCertSignatureHash.Sha1];
    CheckFalse(TChainAlgorithmPolicy.Check(Pkix.Certificates,
      TArray<TBytes>.Create(DecodeHex(LVec.Values['issuer_md5_cert'])), nil, LPolicy, Advertised,
      LAlert), 'an MD5-signed certificate is refused by the policy itself');
    CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'alert');
  finally
    LVec.Free;
  end;
end;

procedure TTestChainAlgorithmPolicy.SetUp;
begin
  inherited SetUp;
  FEc := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
  FRsa := Own<TStringList>(LoadVectorFields('Certs/Rsa2048Chain.txt'));
  FPss := Own<TStringList>(LoadVectorFields('Certs/KeyUsagePss.txt'));
end;

function TTestChainAlgorithmPolicy.EcCert(const AName: string): TBytes;
begin
  Result := DecodeHex(FEc.Values[AName]);
end;

function TTestChainAlgorithmPolicy.RsaCert(const AName: string): TBytes;
begin
  Result := DecodeHex(FRsa.Values[AName]);
end;

function TTestChainAlgorithmPolicy.PssCert(const AName: string): TBytes;
begin
  Result := DecodeHex(FPss.Values[AName]);
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
  CheckTrue(Pkix.Certificates.Parse(EcCert('leaf_cert')).KeyFacts(LFacts),
    'the P-256 leaf key is classifiable');
  CheckTrue(LFacts.Kind = TSignatureKeyKind.Ecdsa, 'ECDSA key');
  CheckEquals(Integer(TNamedGroupCatalog.Secp256r1), Integer(LFacts.EcNamedGroup),
    'secp256r1 named group');
  CheckEquals(256, LFacts.Bits, 'P-256 field size');
end;

procedure TTestChainAlgorithmPolicy.TestRsa2048LeafKeyFacts;
var
  LFacts: TCertKeyFacts;
begin
  CheckTrue(Pkix.Certificates.Parse(RsaCert('leaf_cert')).KeyFacts(LFacts),
    'the RSA leaf key is classifiable');
  CheckTrue(LFacts.Kind = TSignatureKeyKind.Rsa, 'RSA key');
  CheckEquals(2048, LFacts.Bits, 'RSA-2048 modulus');
end;

procedure TTestChainAlgorithmPolicy.TestAcceptsStandardEcChain;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TChainAlgorithmPolicy.Check(Pkix.Certificates,
    TArray<TBytes>.Create(EcCert('leaf_cert')),
    TArray<TBytes>.Create(EcCert('root_cert')),
    TCertificateStrengthPolicy.Defaults, Advertised, LAlert),
    'a P-256 leaf signed with an advertised ECDSA scheme is accepted');
end;

procedure TTestChainAlgorithmPolicy.TestAcceptsStandardRsaChain;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TChainAlgorithmPolicy.Check(Pkix.Certificates,
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
  CheckTrue(TChainAlgorithmPolicy.Check(Pkix.Certificates,
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
  CheckFalse(TChainAlgorithmPolicy.Check(Pkix.Certificates,
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
  CheckFalse(TChainAlgorithmPolicy.Check(Pkix.Certificates,
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
  CheckFalse(TChainAlgorithmPolicy.Check(Pkix.Certificates,
    TArray<TBytes>.Create(EcCert('leaf_cert')),
    TArray<TBytes>.Create(EcCert('root_cert')), LPolicy, Advertised, LAlert),
    'a P-256 leaf is rejected when the allowlist admits only P-384');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a disallowed curve is unsupported_certificate');
end;

procedure TTestChainAlgorithmPolicy.TestAcceptsRsaPssPssIssuerWhenAdvertised;
var
  LAlert: TTlsAlertDescription;
  LPss: TBytes;
begin
  // the self-signed id-RSASSA-PSS cert stands in for both leaf and issuer: its PSS-restricted
  // issuer key means the leaf's signature is rsa_pss_pss_sha256, which here is advertised. The
  // issuer copy at index 1 is the configured anchor, so only the leaf is checked.
  LPss := PssCert('rsapss_cert');
  CheckTrue(TChainAlgorithmPolicy.Check(Pkix.Certificates,
    TArray<TBytes>.Create(LPss, LPss), TArray<TBytes>.Create(LPss),
    TCertificateStrengthPolicy.Defaults,
    TArray<UInt16>.Create(TSignatureSchemes.RsaPssPssSha256), LAlert),
    'a PSS-restricted issuer with rsa_pss_pss_sha256 advertised is accepted');
end;

procedure TTestChainAlgorithmPolicy.TestRejectsRsaPssPssIssuerWhenOnlyRsaeAdvertised;
var
  LAlert: TTlsAlertDescription;
  LPss: TBytes;
begin
  // the default offer carries rsa_pss_rsae_* but not rsa_pss_pss_*: an id-RSASSA-PSS issuer
  // requires the pss_pss scheme, so the chain is refused rather than matched against rsae
  LPss := PssCert('rsapss_cert');
  CheckFalse(TChainAlgorithmPolicy.Check(Pkix.Certificates,
    TArray<TBytes>.Create(LPss, LPss), TArray<TBytes>.Create(LPss),
    TCertificateStrengthPolicy.Defaults, Advertised, LAlert),
    'a PSS-restricted issuer is rejected when only rsa_pss_rsae_* is advertised');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'an unmatched pss_pss requirement is unsupported_certificate');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestChainAlgorithmPolicy);
  RegisterTest(TTestEndEntityPolicy);
{$ELSE}
  RegisterTest(TTestChainAlgorithmPolicy.Suite);
  RegisterTest(TTestEndEntityPolicy.Suite);
{$ENDIF FPC}

end.
