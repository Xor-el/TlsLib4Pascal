{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Tests for the TlsLib.Compliance refusing providers: the primitives, signing and PKIX
/// decorators, each in strict and relaxed mode, over fakes that place operations in or out of
/// the OS module on any host.</summary>
unit ComplianceProviderTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpICryptoProvider,
  TlpICryptoBackendReport,
  TlpISystemSigningKey,
  TlpISigningKey,
  TlpImportedCredential,
  TlpSystemCryptoTypes,
  TlpOSCryptoProvider,
  TlpSecretBuffer,
  TlpISecretBuffer,
  TlpPkixDomainTypes,
  TlpIPkixProvider,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpCompliancePresets,
  TlpComplianceCryptoProvider,
  TlpCompliancePkixProvider,
  MockCompliance,
  MockPkixProvider,
  TlsLibTestCertificates,
  TlsLibTestProviders,
  TlsLibTestBase;

type
  TTestComplianceCryptoPrimitives = class(TTlsLibAlgorithmTestCase)
  strict private
    // every operation in the OS module except the AEADs kept portable
    function SystemOver(APortableAeads: TComplianceAeadSet): ICryptoProvider;
    function RequireModuleRules: TComplianceRules;
    function RefusesRandom(const AProvider: ICryptoProvider): Boolean;
    function RefusesHash(const AProvider: ICryptoProvider; AAlgorithm: THashAlgorithm): Boolean;
    function RefusesHmac(const AProvider: ICryptoProvider; AAlgorithm: THashAlgorithm): Boolean;
    function RefusesHkdf(const AProvider: ICryptoProvider; AAlgorithm: THashAlgorithm): Boolean;
    function RefusesPrf(const AProvider: ICryptoProvider; AAlgorithm: THashAlgorithm): Boolean;
    function RefusesAead(const AProvider: ICryptoProvider; AAlgorithm: TAeadAlgorithm): Boolean;
    function RefusesKeyAgreement(const AProvider: ICryptoProvider;
      AAlgorithm: TKeyAgreementAlgorithm): Boolean;
    function RefusesKem(const AProvider: ICryptoProvider; AAlgorithm: TKemAlgorithm): Boolean;
    function ComputePrf(const AProvider: ICryptoProvider; const ALabel: string): ISecretBuffer;
    function RefusesLabel(const AProvider: ICryptoProvider; const ALabel: string): Boolean;
  strict protected
    function CreateCrypto: ICryptoProvider; override;
  published
    procedure TestChaChaRefusedStrict;
    procedure TestChaChaRefusedRelaxed;
    procedure TestAes256AllowedUnderCnsa1;
    procedure TestAes128RefusedUnderCnsa1Strict;
    procedure TestAes128RefusedUnderCnsa1Relaxed;
    procedure TestAesAllowedUnderFips;
    procedure TestX25519RefusedStrict;
    procedure TestX25519RefusedRelaxed;
    procedure TestP256AllowedFips;
    procedure TestP384AllowedCnsa1;
    procedure TestP256RefusedCnsa1Strict;
    procedure TestP256RefusedCnsa1Relaxed;
    procedure TestCurveOutsideNarrowedGroupsRefused;
    procedure TestKemAlwaysRefusedBothModes;
    procedure TestStrictRefusesPortableAead;
    procedure TestStrictAllowsSystemAeadBesidePortableOne;
    procedure TestRelaxedForwardsPortableAead;
    procedure TestStrictRefusesRandomOnPortableBase;
    procedure TestRelaxedForwardsRandomOnPortableBase;
    procedure TestStrictAcceptsRandomOnSystemBase;
    procedure TestStrictRefusesHashOnPortableBase;
    procedure TestRelaxedForwardsHashOnPortableBase;
    procedure TestStrictRefusesHmacOnPortableBase;
    procedure TestRelaxedForwardsHmacOnPortableBase;
    procedure TestStrictAcceptsHashAndHmacOnSystemBase;
    procedure TestStrictRefusesKeyAgreementOnPortableBase;
    procedure TestRelaxedForwardsKeyAgreementOnPortableBase;
    procedure TestStrictAcceptsComposedHkdfUnderAllowComposed;
    procedure TestStrictRefusesComposedHkdfUnderRequireModule;
    procedure TestStrictRefusesPortableHkdfUnderAllowComposed;
    procedure TestRelaxedForwardsComposedHkdfUnderRequireModule;
    procedure TestStrictAcceptsComposedPrfUnderAllowComposed;
    procedure TestStrictRefusesComposedPrfUnderRequireModule;
    procedure TestStrictRefusesPortablePrfUnderAllowComposed;
    procedure TestRelaxedForwardsComposedPrfUnderRequireModule;
    procedure TestPrfRefusesPlainMasterSecretLabelStrict;
    procedure TestPrfRefusesPlainMasterSecretLabelRelaxed;
    procedure TestPrfAllowsExtendedMasterSecretLabel;
    procedure TestPrfAllowsOtherLabels;
    procedure TestPrfLabelMatchIsExact;
    procedure TestPrfPlainLabelPassesWithoutEmsRequirement;
    procedure TestRefusalIsFatalInternalError;
    procedure TestRefusalIsCaughtAsBaseException;
    procedure TestHpkeX25519SuiteUnavailable;
    procedure TestHpkeChaChaSuiteUnavailable;
    procedure TestHpkeP256SuiteAvailable;
    procedure TestHpkeHasNoMlKemSuite;
    procedure TestComposeKeepsBaseReportIdentity;
    procedure TestComposeOverBaseWithoutReportClaimsNone;
    procedure TestComposeFacetsAreStable;
    procedure TestPrimitivesRejectNilReport;
    procedure TestStrictFollowsOsReportForAes;
  end;

  TTestComplianceSigningCrypto = class(TTlsLibAlgorithmTestCase)
  strict private
  var
    FKeys: TStringList;
    FPfx: TStringList;
    // a provider over a fake signing facet that hands out AKey; verifiers are OS-served when
    // ANativeVerifiers
    function SigningOver(const AKey: ISigningKey; ANativeVerifiers: Boolean): ICryptoProvider;
    function SystemKey(const ASchemes: array of TSignatureScheme): ISigningKey;
    function PortableKey(const ASchemes: array of TSignatureScheme): ISigningKey;
    function ImportRefused(const ASigning: ISigningCrypto; const AKeyName: string): Boolean;
    function SignerRefused(const ASigning: ISigningCrypto; AScheme: TSignatureScheme;
      const AKey: ISigningKey): Boolean;
    function VerifierRefused(const ASigning: ISigningCrypto; AScheme: TSignatureScheme): Boolean;
    function Pkcs12Refused(const ASigning: ISigningCrypto; const AName: string): Boolean;
  strict protected
    function CreateCrypto: ICryptoProvider; override;
  protected
    procedure SetUp; override;
  published
    procedure TestEd25519KeyImportRefusedRelaxed;
    procedure TestEd25519SystemKeyRefusedStrict;
    procedure TestKeyWithNoAllowedSchemeRefusedByEveryImportPath;
    procedure TestMixedKeyNarrowedToAllowedSchemes;
    procedure TestNarrowingKeepsKeyOrder;
    procedure TestPortableKeyRefusedStrict;
    procedure TestPortableKeyAdmittedRelaxedAndNarrowed;
    procedure TestSystemKeyAdmittedStrict;
    procedure TestSystemKeyKeepsMarkerWhenNarrowed;
    procedure TestSignerRefusesDisallowedSchemeStrict;
    procedure TestSignerRefusesDisallowedSchemeRelaxed;
    procedure TestSignerGrantedForSystemKeyStrict;
    procedure TestStrictSignerRefusesPortableKey;
    procedure TestRelaxedSignerAcceptsPortableKey;
    procedure TestVerifierRefusesDisallowedSchemeStrict;
    procedure TestVerifierRefusesDisallowedSchemeRelaxed;
    procedure TestStrictVerifierWithoutMarkerRefused;
    procedure TestStrictVerifierWithMarkerReturned;
    procedure TestRelaxedVerifierWithoutMarkerReturned;
    procedure TestPkcs12PortableKeyRefusedStrict;
    procedure TestPkcs12PortableKeyAdmittedRelaxedAndNarrowed;
    procedure TestPkcs12KeepsCertificateChain;
    procedure TestPkcs12Ed25519KeyRefusedRelaxed;
    procedure TestPkcs12SystemKeyAdmittedStrict;
    procedure TestSigningRejectsNilReport;
  end;

  TTestCompliancePkix = class(TTlsLibAlgorithmTestCase)
  strict private
  var
    FSpy: TMockPkixProvider;
    FSpyRef: IPkixProvider;
    FLeaf: TBytes;
    FRoot: TBytes;
    function Provider(AEnforcement: TComplianceEnforcement): IPkixProvider;
    function PathAlert(AEnforcement: TComplianceEnforcement; const AAnchor: TBytes;
      out AFailed: Boolean): TTlsAlertDescription;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestStrictPathValidationRaisesInternalError;
    procedure TestStrictPathValidationDoesNotReachBase;
    procedure TestRelaxedPathValidationForwards;
    procedure TestRelaxedPathValidationPropagatesBaseFailure;
    procedure TestStrictOcspStapleIndeterminate;
    procedure TestStrictBuildOcspRequestIndeterminate;
    procedure TestStrictOcspResponderUrlsIndeterminate;
    procedure TestStrictCrlDistributionPointsIndeterminate;
    procedure TestStrictCrlRevocationIndeterminate;
    procedure TestStrictFindIssuerIndeterminate;
    procedure TestRelaxedOcspStapleForwards;
    procedure TestRelaxedBuildOcspRequestForwards;
    procedure TestRelaxedOcspResponderUrlsForward;
    procedure TestRelaxedCrlDistributionPointsForward;
    procedure TestRelaxedCrlRevocationForwards;
    procedure TestRelaxedFindIssuerForwards;
    procedure TestInspectorIsBaseInspector;
    procedure TestFacetsAreStable;
    procedure TestProviderRejectsNilBase;
    procedure TestPathValidatorRejectsNilInner;
    procedure TestRevocationCheckerRejectsNilInner;
  end;

implementation

const
  SPassword = 'tlslib';
  // the ML-KEM-768 codepoint of the HPKE post-quantum draft
  HpkeKemMlKem768 = UInt16($0041);

{ TTestComplianceCryptoPrimitives }

function TTestComplianceCryptoPrimitives.CreateCrypto: ICryptoProvider;
begin
  Result := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
end;

function TTestComplianceCryptoPrimitives.SystemOver(
  APortableAeads: TComplianceAeadSet): ICryptoProvider;
begin
  Result := TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create(APortableAeads) as ICryptoBackendReport, nil);
end;

function TTestComplianceCryptoPrimitives.RequireModuleRules: TComplianceRules;
begin
  Result := TCompliancePresets.Fips140_3;
  Result.Kdf := TKdfRule.RequireModule;
end;

function TTestComplianceCryptoPrimitives.RefusesRandom(const AProvider: ICryptoProvider): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.GetRandom;
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.RefusesHash(const AProvider: ICryptoProvider;
  AAlgorithm: THashAlgorithm): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateHash(AAlgorithm);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.RefusesHmac(const AProvider: ICryptoProvider;
  AAlgorithm: THashAlgorithm): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateHmac(AAlgorithm);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.RefusesHkdf(const AProvider: ICryptoProvider;
  AAlgorithm: THashAlgorithm): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateHkdf(AAlgorithm);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.RefusesPrf(const AProvider: ICryptoProvider;
  AAlgorithm: THashAlgorithm): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateTls12Prf(AAlgorithm);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.RefusesAead(const AProvider: ICryptoProvider;
  AAlgorithm: TAeadAlgorithm): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateAead(AAlgorithm);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.RefusesKeyAgreement(const AProvider: ICryptoProvider;
  AAlgorithm: TKeyAgreementAlgorithm): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateKeyAgreement(AAlgorithm);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.RefusesKem(const AProvider: ICryptoProvider;
  AAlgorithm: TKemAlgorithm): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateKem(AAlgorithm);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceCryptoPrimitives.ComputePrf(const AProvider: ICryptoProvider;
  const ALabel: string): ISecretBuffer;
begin
  Result := AProvider.Primitives.CreateTls12Prf(THashAlgorithm.SHA_256).Compute(
    TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')), ALabel,
    DecodeHex('f0e1d2c3b4a5968778695a4b3c2d1e0f'), 48);
end;

function TTestComplianceCryptoPrimitives.RefusesLabel(const AProvider: ICryptoProvider;
  const ALabel: string): Boolean;
begin
  Result := False;
  try
    ComputePrf(AProvider, ALabel);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

procedure TTestComplianceCryptoPrimitives.TestChaChaRefusedStrict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.CHACHA20_POLY1305), 'ChaCha is not allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestChaChaRefusedRelaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.CHACHA20_POLY1305),
    'an allowlist refuses in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestAes256AllowedUnderCnsa1;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_256_GCM), 'AES-256 is the CNSA AEAD');
end;

procedure TTestComplianceCryptoPrimitives.TestAes128RefusedUnderCnsa1Strict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM), 'AES-128 is outside CNSA');
end;

procedure TTestComplianceCryptoPrimitives.TestAes128RefusedUnderCnsa1Relaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM),
    'the rules refuse AES-128 in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestAesAllowedUnderFips;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM), 'AES-128 is allowed');
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_256_GCM), 'AES-256 is allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestX25519RefusedStrict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.X25519),
    'X25519 is not allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestX25519RefusedRelaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.X25519),
    'an allowlist refuses in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestP256AllowedFips;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'P-256 is allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestP384AllowedCnsa1;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckFalse(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP384R1),
    'P-384 is the CNSA curve');
end;

procedure TTestComplianceCryptoPrimitives.TestP256RefusedCnsa1Strict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'P-256 is outside CNSA');
end;

procedure TTestComplianceCryptoPrimitives.TestP256RefusedCnsa1Relaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'the rules refuse P-256 in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestCurveOutsideNarrowedGroupsRefused;
var
  LRules: TComplianceRules;
  LProvider: ICryptoProvider;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    LRules, TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP384R1),
    'a curve no group names is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestKemAlwaysRefusedBothModes;
var
  LStrict, LRelaxed: ICryptoProvider;
begin
  LStrict := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  LRelaxed := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesKem(LStrict, TKemAlgorithm.ML_KEM_768), 'no KEM in strict mode');
  CheckTrue(RefusesKem(LRelaxed, TKemAlgorithm.ML_KEM_768), 'no KEM in relaxed mode');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortableAead;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(
    SystemOver([TAeadAlgorithm.AES_128_GCM]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM),
    'an allowed AEAD the module does not serve is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAllowsSystemAeadBesidePortableOne;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(
    SystemOver([TAeadAlgorithm.AES_128_GCM]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_256_GCM),
    'only the portable AEAD is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsPortableAead;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(
    SystemOver([TAeadAlgorithm.AES_128_GCM]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM),
    'relaxed mode passes a platform fact through');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesRandomOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckTrue(RefusesRandom(LProvider), 'a base with no report is portable');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsRandomOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesRandom(LProvider), 'relaxed mode forwards the random generator');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAcceptsRandomOnSystemBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesRandom(LProvider), 'a module random generator is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesHashOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckTrue(RefusesHash(LProvider, THashAlgorithm.SHA_256), 'a portable hash is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsHashOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesHash(LProvider, THashAlgorithm.SHA_256), 'relaxed mode forwards the hash');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesHmacOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckTrue(RefusesHmac(LProvider, THashAlgorithm.SHA_384), 'a portable HMAC is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsHmacOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesHmac(LProvider, THashAlgorithm.SHA_384), 'relaxed mode forwards the HMAC');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAcceptsHashAndHmacOnSystemBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesHash(LProvider, THashAlgorithm.SHA_512), 'a module hash is accepted');
  CheckFalse(RefusesHmac(LProvider, THashAlgorithm.SHA_512), 'a module HMAC is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesKeyAgreementOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'an allowed curve the module does not serve is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsKeyAgreementOnPortableBase;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'relaxed mode forwards an allowed curve');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAcceptsComposedHkdfUnderAllowComposed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesHkdf(LProvider, THashAlgorithm.SHA_256),
    'HKDF over the module HMAC is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesComposedHkdfUnderRequireModule;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    RequireModuleRules, TComplianceEnforcement.Strict);
  CheckTrue(RefusesHkdf(LProvider, THashAlgorithm.SHA_256),
    'a composed HKDF is refused when the module must serve it');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortableHkdfUnderAllowComposed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckTrue(RefusesHkdf(LProvider, THashAlgorithm.SHA_256),
    'allowing composition does not allow a portable HMAC underneath');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsComposedHkdfUnderRequireModule;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    RequireModuleRules, TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesHkdf(LProvider, THashAlgorithm.SHA_256),
    'relaxed mode forwards the composed HKDF');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAcceptsComposedPrfUnderAllowComposed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesPrf(LProvider, THashAlgorithm.SHA_256),
    'the PRF over the module HMAC is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesComposedPrfUnderRequireModule;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    RequireModuleRules, TComplianceEnforcement.Strict);
  CheckTrue(RefusesPrf(LProvider, THashAlgorithm.SHA_256),
    'a composed PRF is refused when the module must serve it');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortablePrfUnderAllowComposed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckTrue(RefusesPrf(LProvider, THashAlgorithm.SHA_256),
    'allowing composition does not allow a portable HMAC underneath');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsComposedPrfUnderRequireModule;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    RequireModuleRules, TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesPrf(LProvider, THashAlgorithm.SHA_256),
    'relaxed mode forwards the composed PRF');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfRefusesPlainMasterSecretLabelStrict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesLabel(LProvider, 'master secret'),
    'the plain master secret is not approved without Extended Master Secret');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfRefusesPlainMasterSecretLabelRelaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesLabel(LProvider, 'master secret'),
    'the label is refused in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfAllowsExtendedMasterSecretLabel;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(ComputePrf(LProvider, 'extended master secret').ConstantTimeAreEqual(
    ComputePrf(Crypto, 'extended master secret')),
    'the wrapped PRF gives the inner PRF output');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfAllowsOtherLabels;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesLabel(LProvider, 'key expansion'), 'key expansion is allowed');
  CheckFalse(RefusesLabel(LProvider, 'client finished'), 'the finished label is allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfLabelMatchIsExact;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesLabel(LProvider, 'master secret '), 'a trailing space is another label');
  CheckFalse(RefusesLabel(LProvider, 'Master Secret'), 'the label is case sensitive');
  CheckFalse(RefusesLabel(LProvider, 'master secre'), 'a prefix is another label');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfPlainLabelPassesWithoutEmsRequirement;
var
  LRules: TComplianceRules;
  LProvider: ICryptoProvider;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Requirements := LRules.Requirements - [TComplianceRequirement.ExtendedMasterSecret];
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    LRules, TComplianceEnforcement.Strict);
  CheckFalse(RefusesLabel(LProvider, 'master secret'),
    'the label is refused only when the rules require Extended Master Secret');
end;

procedure TTestComplianceCryptoPrimitives.TestRefusalIsFatalInternalError;
var
  LProvider: ICryptoProvider;
  LRaised: Boolean;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  LRaised := False;
  try
    LProvider.Primitives.CreateAead(TAeadAlgorithm.CHACHA20_POLY1305);
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      CheckTrue(E is EComplianceRefusedTlsLibException, 'the refusal type');
      CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(E.AlertDescription), 'alert');
    end;
  end;
  CheckTrue(LRaised, 'a refusal is a fatal alert exception');
end;

procedure TTestComplianceCryptoPrimitives.TestRefusalIsCaughtAsBaseException;
var
  LProvider: ICryptoProvider;
  LRaised: Boolean;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  LRaised := False;
  try
    LProvider.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
  except
    on EBaseTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a probe that catches the library base exception sees the refusal');
end;

procedure TTestComplianceCryptoPrimitives.TestHpkeX25519SuiteUnavailable;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(LProvider.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM) = nil, 'the X25519 KEM is not instantiable');
end;

procedure TTestComplianceCryptoPrimitives.TestHpkeChaChaSuiteUnavailable;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(LProvider.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.CHACHA20_POLY1305) = nil, 'the ChaCha AEAD is not instantiable');
end;

procedure TTestComplianceCryptoPrimitives.TestHpkeP256SuiteAvailable;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(LProvider.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM) <> nil, 'an allowed suite is still instantiable');
end;

procedure TTestComplianceCryptoPrimitives.TestHpkeHasNoMlKemSuite;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(LProvider.Hpke.Suite(HpkeKemMlKem768, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM) = nil, 'no suite is built over ML-KEM');
  CheckEquals(0, System.Length(LProvider.Hpke.SupportedSuites(HpkeKemMlKem768)),
    'and none is listed');
end;

procedure TTestComplianceCryptoPrimitives.TestComposeKeepsBaseReportIdentity;
var
  LReport, LFound: ICryptoBackendReport;
  LProvider: ICryptoProvider;
begin
  LReport := TFakeBackendReport.Create([]) as ICryptoBackendReport;
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(LReport, nil),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(Supports(LProvider, ICryptoBackendReport, LFound), 'the report is still offered');
  CheckTrue(LFound = LReport, 'and it is the base report itself');
end;

procedure TTestComplianceCryptoPrimitives.TestComposeOverBaseWithoutReportClaimsNone;
var
  LProvider: ICryptoProvider;
  LFound: ICryptoBackendReport;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckFalse(Supports(LProvider, ICryptoBackendReport, LFound),
    'a provider with no map reads as wholly portable');
end;

procedure TTestComplianceCryptoPrimitives.TestComposeFacetsAreStable;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckTrue(LProvider.Primitives = LProvider.Primitives, 'the same primitives every call');
  CheckTrue(LProvider.Signing = LProvider.Signing, 'the same signing facet every call');
end;

procedure TTestComplianceCryptoPrimitives.TestPrimitivesRejectNilReport;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TComplianceCryptoPrimitives.Create(Crypto.Primitives, TCompliancePresets.Fips140_3, nil,
      TComplianceEnforcement.Strict).Free;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil report is rejected');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictFollowsOsReportForAes;
var
  LBase, LProvider: ICryptoProvider;
  LReport: ICryptoBackendReport;
  LAead: TAeadAlgorithm;
begin
  LBase := TOSCryptoProvider.Compose(Crypto);
  if not Supports(LBase, ICryptoBackendReport, LReport) then
  begin
    SkipTest('no OS overlay engaged, so there is no backend report');
    Exit;
  end;
  LProvider := TComplianceCryptoProvider.Compose(LBase, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  for LAead := TAeadAlgorithm.AES_128_GCM to TAeadAlgorithm.AES_256_GCM do
    CheckTrue((LReport.AeadBackend(LAead).Backend <> TCryptoBackend.System) =
      RefusesAead(LProvider, LAead), 'strict mode follows the real report');
end;

{ TTestComplianceSigningCrypto }

function TTestComplianceSigningCrypto.CreateCrypto: ICryptoProvider;
begin
  Result := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
end;

procedure TTestComplianceSigningCrypto.SetUp;
begin
  inherited SetUp;
  FKeys := Own<TStringList>(LoadVectorFields('Certs/ImportKeys.txt'));
  FPfx := Own<TStringList>(LoadVectorFields('Certs/Pkcs12.txt'));
end;

function TTestComplianceSigningCrypto.SigningOver(const AKey: ISigningKey;
  ANativeVerifiers: Boolean): ICryptoProvider;
begin
  Result := TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport,
    TFakeSigningCrypto.Create(AKey, ANativeVerifiers) as ISigningCrypto);
end;

function TTestComplianceSigningCrypto.SystemKey(
  const ASchemes: array of TSignatureScheme): ISigningKey;
var
  LSchemes: TArray<TSignatureScheme>;
  LI: Int32;
begin
  LSchemes := nil;
  SetLength(LSchemes, System.Length(ASchemes));
  for LI := 0 to System.High(ASchemes) do
    LSchemes[LI] := ASchemes[LI];
  Result := TFakeSystemSigningKey.Create(LSchemes) as ISigningKey;
end;

function TTestComplianceSigningCrypto.PortableKey(
  const ASchemes: array of TSignatureScheme): ISigningKey;
var
  LSchemes: TArray<TSignatureScheme>;
  LI: Int32;
begin
  LSchemes := nil;
  SetLength(LSchemes, System.Length(ASchemes));
  for LI := 0 to System.High(ASchemes) do
    LSchemes[LI] := ASchemes[LI];
  Result := TFakeSigningKey.Create(LSchemes) as ISigningKey;
end;

function TTestComplianceSigningCrypto.ImportRefused(const ASigning: ISigningCrypto;
  const AKeyName: string): Boolean;
begin
  Result := False;
  try
    ASigning.ImportSigningKey(DecodeHex(FKeys.Values[AKeyName]), nil);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceSigningCrypto.SignerRefused(const ASigning: ISigningCrypto;
  AScheme: TSignatureScheme; const AKey: ISigningKey): Boolean;
begin
  Result := False;
  try
    ASigning.CreateSignatureSigner(AScheme, AKey);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceSigningCrypto.VerifierRefused(const ASigning: ISigningCrypto;
  AScheme: TSignatureScheme): Boolean;
begin
  Result := False;
  try
    ASigning.CreateSignatureVerifier(AScheme, nil);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

function TTestComplianceSigningCrypto.Pkcs12Refused(const ASigning: ISigningCrypto;
  const AName: string): Boolean;
begin
  Result := False;
  try
    ASigning.ImportPkcs12(DecodeHex(FPfx.Values[AName]), TSecretBuffer.FromString(SPassword));
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

procedure TTestComplianceSigningCrypto.TestEd25519KeyImportRefusedRelaxed;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed).Signing;
  CheckTrue(ImportRefused(LSigning, 'ed25519_pkcs8_der'), 'an EdDSA key has no allowed scheme');
end;

procedure TTestComplianceSigningCrypto.TestEd25519SystemKeyRefusedStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ED25519]), True), TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).Signing;
  CheckTrue(ImportRefused(LSigning, 'ed25519_pkcs8_der'),
    'the allowlist refuses a module key too');
end;

procedure TTestComplianceSigningCrypto.TestKeyWithNoAllowedSchemeRefusedByEveryImportPath;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ED448]), True), TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).Signing;
  CheckTrue(ImportRefused(LSigning, 'ed448_pkcs8_der'), 'the key import path');
  CheckTrue(Pkcs12Refused(LSigning, 'ed25519_pfx'), 'the PKCS#12 import path');
end;

procedure TTestComplianceSigningCrypto.TestMixedKeyNarrowedToAllowedSchemes;
var
  LSigning: ISigningCrypto;
  LKey: ISigningKey;
  LSchemes: TArray<TSignatureScheme>;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256]),
    True), TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  LKey := LSigning.ImportSigningKey(DecodeHex(FKeys.Values['ec256_pkcs8_der']), nil);
  LSchemes := LKey.CapableSchemes;
  CheckEquals(1, System.Length(LSchemes), 'the disallowed scheme is dropped');
  CheckEquals(Ord(TSignatureScheme.ECDSA_SECP256R1_SHA256), Ord(LSchemes[0]), 'the kept scheme');
end;

procedure TTestComplianceSigningCrypto.TestNarrowingKeepsKeyOrder;
var
  LSigning: ISigningCrypto;
  LSchemes: TArray<TSignatureScheme>;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.ECDSA_SECP256R1_SHA256]), True), TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).Signing;
  LSchemes := LSigning.ImportSigningKey(DecodeHex(FKeys.Values['ec256_pkcs8_der']), nil)
    .CapableSchemes;
  CheckEquals(2, System.Length(LSchemes), 'both schemes are allowed');
  CheckEquals(Ord(TSignatureScheme.ECDSA_SECP384R1_SHA384), Ord(LSchemes[0]), 'the key order');
  CheckEquals(Ord(TSignatureScheme.ECDSA_SECP256R1_SHA256), Ord(LSchemes[1]), 'and its tail');
end;

procedure TTestComplianceSigningCrypto.TestPortableKeyRefusedStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).Signing;
  CheckTrue(ImportRefused(LSigning, 'ec256_pkcs8_der'),
    'a key the module did not import is refused');
end;

procedure TTestComplianceSigningCrypto.TestPortableKeyAdmittedRelaxedAndNarrowed;
var
  LSigning: ISigningCrypto;
  LKey: ISigningKey;
  LSchemes: TArray<TSignatureScheme>;
  LI: Int32;
  LSeen: Boolean;
begin
  LSigning := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Signing;
  LKey := LSigning.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  LSchemes := LKey.CapableSchemes;
  CheckTrue(System.Length(LSchemes) > 0, 'the key keeps the schemes the rules allow');
  LSeen := False;
  for LI := 0 to System.Length(LSchemes) - 1 do
  begin
    CheckTrue(LSchemes[LI] in TCompliancePresets.Cnsa1.SignatureSchemes,
      'every capable scheme is allowed');
    LSeen := LSeen or (LSchemes[LI] = TSignatureScheme.RSA_PSS_RSAE_SHA384);
  end;
  CheckTrue(LSeen, 'an allowed scheme the key can sign is kept');
end;

procedure TTestComplianceSigningCrypto.TestSystemKeyAdmittedStrict;
var
  LSigning: ISigningCrypto;
  LKey: ISigningKey;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  LKey := LSigning.ImportSigningKey(DecodeHex(FKeys.Values['ec256_pkcs8_der']), nil);
  CheckEquals(1, System.Length(LKey.CapableSchemes), 'a module key is admitted');
end;

procedure TTestComplianceSigningCrypto.TestSystemKeyKeepsMarkerWhenNarrowed;
var
  LSigning: ISigningCrypto;
  LKey: ISigningKey;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256]),
    True), TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  LKey := LSigning.ImportSigningKey(DecodeHex(FKeys.Values['ec256_pkcs8_der']), nil);
  CheckTrue(Supports(LKey, ISystemSigningKey), 'the narrowed key is still a module key');
end;

procedure TTestComplianceSigningCrypto.TestSignerRefusesDisallowedSchemeStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(SignerRefused(LSigning, TSignatureScheme.ED25519,
    SystemKey([TSignatureScheme.ED25519])), 'EdDSA is not an allowed scheme');
end;

procedure TTestComplianceSigningCrypto.TestSignerRefusesDisallowedSchemeRelaxed;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed).Signing;
  CheckTrue(SignerRefused(LSigning, TSignatureScheme.ED25519,
    PortableKey([TSignatureScheme.ED25519])), 'the allowlist refuses in relaxed mode too');
end;

procedure TTestComplianceSigningCrypto.TestSignerGrantedForSystemKeyStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckFalse(SignerRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256,
    SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256])),
    'an allowed scheme over a module key is granted');
end;

procedure TTestComplianceSigningCrypto.TestStrictSignerRefusesPortableKey;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(SignerRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256,
    PortableKey([TSignatureScheme.ECDSA_SECP256R1_SHA256])),
    'a key outside the module signs nothing in strict mode');
end;

procedure TTestComplianceSigningCrypto.TestRelaxedSignerAcceptsPortableKey;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed).Signing;
  CheckFalse(SignerRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256,
    PortableKey([TSignatureScheme.ECDSA_SECP256R1_SHA256])),
    'relaxed mode passes a platform fact through');
end;

procedure TTestComplianceSigningCrypto.TestVerifierRefusesDisallowedSchemeStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(SigningOver(nil, True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(VerifierRefused(LSigning, TSignatureScheme.ED25519), 'EdDSA is not allowed');
end;

procedure TTestComplianceSigningCrypto.TestVerifierRefusesDisallowedSchemeRelaxed;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(SigningOver(nil, False),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed).Signing;
  CheckTrue(VerifierRefused(LSigning, TSignatureScheme.ED25519),
    'the allowlist refuses in relaxed mode too');
end;

procedure TTestComplianceSigningCrypto.TestStrictVerifierWithoutMarkerRefused;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(SigningOver(nil, False),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(VerifierRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    'a verifier the module does not serve is refused');
end;

procedure TTestComplianceSigningCrypto.TestStrictVerifierWithMarkerReturned;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(SigningOver(nil, True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckFalse(VerifierRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    'a module verifier is returned');
end;

procedure TTestComplianceSigningCrypto.TestRelaxedVerifierWithoutMarkerReturned;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(SigningOver(nil, False),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed).Signing;
  CheckFalse(VerifierRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    'relaxed mode returns the portable verifier');
end;

procedure TTestComplianceSigningCrypto.TestPkcs12PortableKeyRefusedStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).Signing;
  CheckTrue(Pkcs12Refused(LSigning, 'ec_pfx'), 'a PKCS#12 key outside the module is refused');
end;

procedure TTestComplianceSigningCrypto.TestPkcs12PortableKeyAdmittedRelaxedAndNarrowed;
var
  LSigning: ISigningCrypto;
  LCredential: TImportedCredential;
  LSchemes: TArray<TSignatureScheme>;
begin
  LSigning := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Signing;
  LCredential := LSigning.ImportPkcs12(DecodeHex(FPfx.Values['rsa_pfx']),
    TSecretBuffer.FromString(SPassword));
  LSchemes := LCredential.PrivateKey.CapableSchemes;
  CheckTrue(System.Length(LSchemes) > 0, 'the key keeps the schemes the rules allow');
  CheckTrue(LSchemes[0] in TCompliancePresets.Cnsa1.SignatureSchemes, 'and only those');
end;

procedure TTestComplianceSigningCrypto.TestPkcs12KeepsCertificateChain;
var
  LSigning: ISigningCrypto;
  LCredential, LExpected: TImportedCredential;
begin
  LSigning := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed).Signing;
  LCredential := LSigning.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(SPassword));
  LExpected := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(SPassword));
  CheckTrue(System.Length(LExpected.CertificateChain) > 0, 'the fixture holds a chain');
  CheckEquals(System.Length(LExpected.CertificateChain),
    System.Length(LCredential.CertificateChain), 'the chain is returned whole');
end;

procedure TTestComplianceSigningCrypto.TestPkcs12Ed25519KeyRefusedRelaxed;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed).Signing;
  CheckTrue(Pkcs12Refused(LSigning, 'ed25519_pfx'), 'an EdDSA PKCS#12 key has no allowed scheme');
end;

procedure TTestComplianceSigningCrypto.TestPkcs12SystemKeyAdmittedStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckFalse(Pkcs12Refused(LSigning, 'ec_pfx'), 'a module PKCS#12 key is admitted');
end;

procedure TTestComplianceSigningCrypto.TestSigningRejectsNilReport;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TComplianceSigningCrypto.Create(Crypto.Signing, TCompliancePresets.Fips140_3, nil,
      TComplianceEnforcement.Strict).Free;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil report is rejected');
end;

{ TTestCompliancePkix }

procedure TTestCompliancePkix.SetUp;
begin
  inherited SetUp;
  FSpy := TMockPkixProvider.Create(Pkix);
  FSpyRef := FSpy as IPkixProvider;
  FLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  FRoot := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert');
end;

procedure TTestCompliancePkix.TearDown;
begin
  FSpyRef := nil;
  FSpy := nil;
  inherited TearDown;
end;

function TTestCompliancePkix.Provider(AEnforcement: TComplianceEnforcement): IPkixProvider;
begin
  Result := TCompliancePkixProvider.Create(FSpyRef, AEnforcement) as IPkixProvider;
end;

function TTestCompliancePkix.PathAlert(AEnforcement: TComplianceEnforcement;
  const AAnchor: TBytes; out AFailed: Boolean): TTlsAlertDescription;
var
  LEffective: TArray<TBytes>;
begin
  AFailed := False;
  Result := TTlsAlertDescription.CloseNotify;
  LEffective := nil;
  try
    Provider(AEnforcement).PathValidation.ValidateCertificatePath(
      TArray<TBytes>.Create(FLeaf),
      TTrustAnchorStore.Create(TArray<TBytes>.Create(AAnchor)) as ITrustAnchorStore, nil,
      NowUtc, TCertKeyPurpose.ServerAuth, LEffective);
  except
    on E: EFatalAlertTlsLibException do
    begin
      AFailed := True;
      Result := E.AlertDescription;
    end;
  end;
end;

procedure TTestCompliancePkix.TestStrictPathValidationRaisesInternalError;
var
  LFailed: Boolean;
  LAlert: TTlsAlertDescription;
begin
  LAlert := PathAlert(TComplianceEnforcement.Strict, FRoot, LFailed);
  CheckTrue(LFailed, 'a strict provider refuses the chain');
  CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert), 'with internal_error');
end;

procedure TTestCompliancePkix.TestStrictPathValidationDoesNotReachBase;
var
  LFailed: Boolean;
begin
  PathAlert(TComplianceEnforcement.Strict, FRoot, LFailed);
  CheckEquals(0, FSpy.PathBuildCount, 'no portable path build ran');
end;

procedure TTestCompliancePkix.TestRelaxedPathValidationForwards;
var
  LFailed: Boolean;
begin
  PathAlert(TComplianceEnforcement.Relaxed, FRoot, LFailed);
  CheckFalse(LFailed, 'the chain validates through the base');
  CheckEquals(1, FSpy.PathBuildCount, 'by one path build');
end;

procedure TTestCompliancePkix.TestRelaxedPathValidationPropagatesBaseFailure;
var
  LFailed: Boolean;
  LAlert: TTlsAlertDescription;
begin
  LAlert := PathAlert(TComplianceEnforcement.Relaxed,
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root2_cert'), LFailed);
  CheckTrue(LFailed, 'a chain to another root fails');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'with the base alert');
end;

procedure TTestCompliancePkix.TestStrictOcspStapleIndeterminate;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  LThis := 1;
  LNext := 1;
  CheckFalse(Provider(TComplianceEnforcement.Strict).Revocation.ValidateOcspStaple(FLeaf, FRoot,
    nil, NowUtc, LStatus, LThis, LNext), 'indeterminate');
  CheckEquals(0, FSpy.OcspParseCount, 'the base was not asked');
end;

procedure TTestCompliancePkix.TestStrictBuildOcspRequestIndeterminate;
var
  LRequest: TBytes;
begin
  LRequest := TBytes.Create(1);
  CheckFalse(Provider(TComplianceEnforcement.Strict).Revocation.BuildOcspRequest(FLeaf, FRoot,
    LRequest), 'indeterminate');
  CheckEquals(0, System.Length(LRequest), 'the out is cleared');
  CheckEquals(0, FSpy.BuildRequestCount, 'the base was not asked');
end;

procedure TTestCompliancePkix.TestStrictOcspResponderUrlsIndeterminate;
var
  LUrls: TArray<string>;
begin
  FSpy.OverrideOcspUrls(TArray<string>.Create('http://ocsp.test/'));
  LUrls := TArray<string>.Create('stale');
  CheckFalse(Provider(TComplianceEnforcement.Strict).Revocation.TryGetOcspResponderUrls(FLeaf,
    LUrls), 'indeterminate although the base knows URLs');
  CheckEquals(0, System.Length(LUrls), 'the out is cleared');
end;

procedure TTestCompliancePkix.TestStrictCrlDistributionPointsIndeterminate;
var
  LUrls: TArray<string>;
begin
  FSpy.OverrideCrlUrls(TArray<string>.Create('http://crl.test/'));
  LUrls := TArray<string>.Create('stale');
  CheckFalse(Provider(TComplianceEnforcement.Strict).Revocation.TryGetCrlDistributionPoints(
    FLeaf, LUrls), 'indeterminate although the base knows URLs');
  CheckEquals(0, System.Length(LUrls), 'the out is cleared');
end;

procedure TTestCompliancePkix.TestStrictCrlRevocationIndeterminate;
var
  LRevoked: Boolean;
  LThis, LNext: TDateTime;
begin
  LRevoked := True;
  LThis := 1;
  LNext := 1;
  CheckFalse(Provider(TComplianceEnforcement.Strict).Revocation.CheckCrlRevocation(FLeaf, FRoot,
    nil, NowUtc, LRevoked, LThis, LNext), 'indeterminate');
  CheckFalse(LRevoked, 'the revoked out is cleared');
  CheckEquals(0, FSpy.CrlParseCount, 'the base was not asked');
end;

procedure TTestCompliancePkix.TestStrictFindIssuerIndeterminate;
var
  LIssuer: TBytes;
begin
  LIssuer := TBytes.Create(1);
  CheckFalse(Provider(TComplianceEnforcement.Strict).Revocation.TryFindIssuer(FLeaf,
    TArray<TBytes>.Create(FRoot), LIssuer), 'indeterminate although the root issued the leaf');
  CheckEquals(0, System.Length(LIssuer), 'the out is cleared');
  CheckEquals(0, FSpy.FindIssuerCount, 'the base was not asked');
end;

procedure TTestCompliancePkix.TestRelaxedOcspStapleForwards;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  Provider(TComplianceEnforcement.Relaxed).Revocation.ValidateOcspStaple(FLeaf, FRoot, nil,
    NowUtc, LStatus, LThis, LNext);
  CheckEquals(1, FSpy.OcspParseCount, 'the base was asked');
end;

procedure TTestCompliancePkix.TestRelaxedBuildOcspRequestForwards;
var
  LRequest: TBytes;
begin
  CheckTrue(Provider(TComplianceEnforcement.Relaxed).Revocation.BuildOcspRequest(FLeaf, FRoot,
    LRequest), 'the base builds the request');
  CheckTrue(System.Length(LRequest) > 0, 'a request comes back');
  CheckEquals(1, FSpy.BuildRequestCount, 'from the base');
end;

procedure TTestCompliancePkix.TestRelaxedOcspResponderUrlsForward;
var
  LUrls: TArray<string>;
begin
  FSpy.OverrideOcspUrls(TArray<string>.Create('http://ocsp.test/'));
  CheckTrue(Provider(TComplianceEnforcement.Relaxed).Revocation.TryGetOcspResponderUrls(FLeaf,
    LUrls), 'the base answers');
  CheckEquals(1, System.Length(LUrls), 'with its URL');
end;

procedure TTestCompliancePkix.TestRelaxedCrlDistributionPointsForward;
var
  LUrls: TArray<string>;
begin
  FSpy.OverrideCrlUrls(TArray<string>.Create('http://crl.test/'));
  CheckTrue(Provider(TComplianceEnforcement.Relaxed).Revocation.TryGetCrlDistributionPoints(
    FLeaf, LUrls), 'the base answers');
  CheckEquals(1, System.Length(LUrls), 'with its URL');
end;

procedure TTestCompliancePkix.TestRelaxedCrlRevocationForwards;
var
  LRevoked: Boolean;
  LThis, LNext: TDateTime;
begin
  Provider(TComplianceEnforcement.Relaxed).Revocation.CheckCrlRevocation(FLeaf, FRoot, nil,
    NowUtc, LRevoked, LThis, LNext);
  CheckEquals(1, FSpy.CrlParseCount, 'the base was asked');
end;

procedure TTestCompliancePkix.TestRelaxedFindIssuerForwards;
var
  LIssuer: TBytes;
begin
  CheckTrue(Provider(TComplianceEnforcement.Relaxed).Revocation.TryFindIssuer(FLeaf,
    TArray<TBytes>.Create(FRoot), LIssuer), 'the base finds the issuer');
  CheckEqualBytes('the root', FRoot, LIssuer);
  CheckEquals(1, FSpy.FindIssuerCount, 'from the base');
end;

procedure TTestCompliancePkix.TestInspectorIsBaseInspector;
begin
  CheckTrue(Provider(TComplianceEnforcement.Strict).Certificates = FSpyRef.Certificates,
    'parsing is kept in strict mode');
  CheckTrue(Provider(TComplianceEnforcement.Relaxed).Certificates = FSpyRef.Certificates,
    'and in relaxed mode');
end;

procedure TTestCompliancePkix.TestFacetsAreStable;
var
  LProvider: IPkixProvider;
begin
  LProvider := Provider(TComplianceEnforcement.Strict);
  CheckTrue(LProvider.PathValidation = LProvider.PathValidation, 'the same validator every call');
  CheckTrue(LProvider.Revocation = LProvider.Revocation, 'the same checker every call');
end;

procedure TTestCompliancePkix.TestProviderRejectsNilBase;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TCompliancePkixProvider.Create(nil, TComplianceEnforcement.Strict).Free;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil base is rejected');
end;

procedure TTestCompliancePkix.TestPathValidatorRejectsNilInner;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TCompliancePathValidator.Create(nil, TComplianceEnforcement.Strict).Free;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil validator is rejected');
end;

procedure TTestCompliancePkix.TestRevocationCheckerRejectsNilInner;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TComplianceRevocationChecker.Create(nil, TComplianceEnforcement.Strict).Free;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil checker is rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestComplianceCryptoPrimitives);
  RegisterTest(TTestComplianceSigningCrypto);
  RegisterTest(TTestCompliancePkix);
{$ELSE}
  RegisterTest(TTestComplianceCryptoPrimitives.Suite);
  RegisterTest(TTestComplianceSigningCrypto.Suite);
  RegisterTest(TTestCompliancePkix.Suite);
{$ENDIF FPC}

end.
