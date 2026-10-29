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
  TlpIKeySchedule,
  TlpTls12KeySchedule,
  TlpICryptoBackendReport,
  TlpISystemSigningKey,
  TlpISigningKey,
  TlpImportedCredential,
  TlpSystemCryptoTypes,
  TlpSystemCryptoBase,
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
  TlpComplianceHpke,
  TlpCompliancePkixProvider,
  MockCompliance,
  MockCryptoProvider,
  MockSystemCrypto,
  MockPkixProvider,
  TlsLibTestCertificates,
  TlsLibTestProviders,
  TlsLibTestBase;

type
  TTestComplianceCryptoPrimitives = class(TTlsLibAlgorithmTestCase)
  strict private
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
    // the refusal message of a label, empty when the label is computed
    function LabelRefusal(const AProvider: ICryptoProvider; const ALabel: string): string;
    // a provider over a fake base that reports AReport
    function ProviderOver(const AReport: ICryptoBackendReport; const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement): ICryptoProvider;
    // a provider over a fake base whose HPKE is the foreign AHpke
    function HpkeOver(const AHpke: IHpkeCrypto; const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement): ICryptoProvider;
    // how many of the three key operations of AHpke refuse AKem
    function RefusedKeyOperations(const AHpke: IHpkeCrypto; AKem: UInt16): Int32;
    // a TLS 1.2 schedule over AProvider holding a premaster secret and both randoms
    function NewSchedule(const AProvider: ICryptoProvider): ITls12KeySchedule;
    // a provider over a base that has APrimitives and reports AReport, under Fips140_3
    function KdfProviderOver(const APrimitives: ICryptoPrimitives;
      const AReport: ICryptoBackendReport; AEnforcement: TComplianceEnforcement): ICryptoProvider;
    function HkdfExpandRefused(const AProvider: ICryptoProvider): Boolean;
    // a provider whose module serves the TLS 1.2 PRF, under ARules
    function ModulePrfProvider(const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement): ICryptoProvider;
    procedure CheckHkdfVector(const AProvider: ICryptoProvider; const ASalt, AIkm, AInfo, APrk,
      AOkm: string; ALength: Int32);
  strict protected
    function CreateCrypto: ICryptoProvider; override;
  published
    procedure TestStrictRefusesPortableRandomOnSystemBase;
    procedure TestRelaxedForwardsPortableRandomOnSystemBase;
    procedure TestStrictRefusesPortableHashBesideSystemOne;
    procedure TestRelaxedForwardsPortableHashBesideSystemOne;
    procedure TestStrictRefusesPortableHmacBesideSystemOne;
    procedure TestStrictRefusesPortableCurveBesideSystemOne;
    procedure TestKeyScheduleRefusesPlainMasterSecret;
    procedure TestKeyScheduleDerivesExtendedMasterSecret;
    procedure TestComposeRejectsNilBase;
    procedure TestRebuiltHpkeIsNotFiltered;
    procedure TestForeignHpkeIsNotTheBaseFacet;
    procedure TestForeignHpkeRelaxedRefusesKemOutsideRules;
    procedure TestForeignHpkeRelaxedRefusesAeadOutsideRules;
    procedure TestForeignHpkeRelaxedKeepsAllowedSuite;
    procedure TestForeignHpkeRelaxedDoesNotFilterHashes;
    procedure TestForeignHpkeRelaxedRefusesUnknownKemAndAead;
    procedure TestForeignHpkeRelaxedFiltersSupportedSuites;
    procedure TestForeignHpkeRelaxedListsNoSuiteForRefusedKem;
    procedure TestForeignHpkeRelaxedPublicKeyAndEncapsulationFollowKem;
    procedure TestForeignHpkeRelaxedOtherKemKeyOperationsRefuse;
    procedure TestForeignHpkeRelaxedAllowedKemReachesBase;
    procedure TestForeignHpkeStrictOffersNothing;
    procedure TestForeignHpkeStrictKeyOperationsRefuse;
    procedure TestComplianceHpkeRejectsNilInner;
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
    procedure TestStrictRequireModuleRefusesAnExporterLabel;
    procedure TestStrictRequireModuleWithoutEmsPassesMasterSecret;
    procedure TestStrictRequireModuleWithoutEmsRefusesAnExporterLabelAsNotKeySchedule;
    procedure TestStrictRequireModuleAllowsTheOtherKeyScheduleLabels;
    procedure TestStrictRequireModuleKeyScheduleLabelMatchIsExact;
    procedure TestStrictAllowComposedAllowsAnExporterLabel;
    procedure TestRelaxedRequireModuleAllowsAnExporterLabel;
    procedure TestRefusalIsFatalInternalError;
    procedure TestRefusalIsCaughtAsBaseException;
    procedure TestHpkeX25519SuiteUnavailable;
    procedure TestHpkeChaChaSuiteUnavailable;
    procedure TestHpkeP256SuiteAvailable;
    procedure TestHpkeHasNoMlKemSuite;
    procedure TestComposeKeepsBaseReportIdentity;
    procedure TestComposeDecidesByTheGivenReport;
    procedure TestComposeWithAGivenReportKeepsTheBaseReport;
    procedure TestComposeRejectsNilDecisionReport;
    procedure TestComposeOverBaseWithoutReportClaimsNone;
    procedure TestSuppliedHpkeFacetAnswerIsTheBaseReportAnswer;
    procedure TestRebuiltHpkeFacetAnswerIsTheBaseReportAnswer;
    procedure TestComposeFacetsAreStable;
    procedure TestPrimitivesRejectNilReport;
    procedure TestStrictFollowsOsReportForAes;
    procedure TestHkdfNeverReachesTheInnerFacetStrict;
    procedure TestHkdfNeverReachesTheInnerFacetRelaxed;
    procedure TestStrictHkdfOverAPortableHmacIsRefused;
    procedure TestPrfIsServedByTheInnerFacetWhenTheReportSaysSystem;
    procedure TestPrfIsComposedWhenTheReportSaysComposed;
    procedure TestComposedPrfComputesTheReferenceOutput;
    procedure TestStrictComposedPrfRefusesAPortableHmac;
    procedure TestHkdfRfc5869VectorsThroughTheOsProvider;
  end;

  TTestComplianceSigningCrypto = class(TTlsLibAlgorithmTestCase)
  strict private
  var
    FKeys: TStringList;
    FPfx: TStringList;
    // input for a fake signing facet, which ignores what it is given
    FFakeInput: TBytes;
    // a provider over a fake signing facet that hands out AKey; verifiers are OS-served when
    // ANativeVerifiers
    function SigningOver(const AKey: ISigningKey; ANativeVerifiers: Boolean): ICryptoProvider;
    // as SigningOver, over a base with no backend report
    function ReportlessOver(const AKey: ISigningKey): ICryptoProvider;
    function SystemKey(const ASchemes: array of TSignatureScheme): ISigningKey;
    function PortableKey(const ASchemes: array of TSignatureScheme): ISigningKey;
    function ImportRefused(const ASigning: ISigningCrypto; const AData: TBytes): Boolean;
    function SignerRefused(const ASigning: ISigningCrypto; AScheme: TSignatureScheme;
      const AKey: ISigningKey): Boolean;
    function VerifierRefused(const ASigning: ISigningCrypto; AScheme: TSignatureScheme): Boolean;
    function Pkcs12Refused(const ASigning: ISigningCrypto; const AData: TBytes): Boolean;
  strict protected
    function CreateCrypto: ICryptoProvider; override;
  protected
    procedure SetUp; override;
  published
    procedure TestEd25519KeyImportRefusedRelaxed;
    procedure TestEd25519SystemKeyRefusedStrict;
    procedure TestKeyWithNoAllowedSchemeRefusedByEveryImportPath;
    procedure TestImportHandsTheInputUnchangedToTheInnerFacet;
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
    procedure TestStrictRefusesMarkedKeyImportOverBaseWithoutReport;
    procedure TestStrictRefusesSignerForMarkedKeyOverBaseWithoutReport;
    procedure TestStrictRefusesMarkedVerifierOverBaseWithoutReport;
    procedure TestRelaxedAdmitsMarkedKeyOverBaseWithoutReport;
    procedure TestNilKeyFromBaseRefused;
    procedure TestStrictVerifierPlacementFollowsReportNotMarker;
    procedure TestStrictVerifierRefusedWhenReportPlacesItOutside;
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
    // checks the provider's name-constraint answers over the name-constrained fixture root
    procedure CheckNameConstraintAnswers(AEnforcement: TComplianceEnforcement);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestStrictPathValidationRaisesInternalError;
    procedure TestStrictPathValidationDoesNotReachBase;
    procedure TestRelaxedPathValidationForwards;
    procedure TestRelaxedPathValidationPropagatesBaseFailure;
    procedure TestStrictNameConstraintsAdmitAnswersAsTheBaseDoes;
    procedure TestRelaxedNameConstraintsAdmitAnswersAsTheBaseDoes;
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

type
  // primitives that count the key derivations asked of them
  TCountingKdfPrimitives = class sealed(TForwardingCryptoPrimitives)
  strict private
  var
    FHkdfs: Int32;
    FPrfs: Int32;
  public
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf; override;
    function CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf; override;
    property Hkdfs: Int32 read FHkdfs;
    property Prfs: Int32 read FPrfs;
  end;

const
  Pkcs12Password = 'tlslib';
  // the ML-KEM-768 codepoint of the IANA HPKE KEM registry
  HpkeKemMlKem768 = UInt16($0041);
  // RFC 5869 appendix A, test cases 1 to 3 (SHA-256)
  Rfc5869Ikm22 = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
  Rfc5869Salt13 = '000102030405060708090a0b0c';
  Rfc5869Info10 = 'f0f1f2f3f4f5f6f7f8f9';
  Rfc5869Prk1 = '077709362c2e32df0ddc3f0dc47bba63' + '90b6c73bb50f9c3122ec844ad7c2b3e5';
  Rfc5869Okm1 = '3cb25f25faacd57a90434f64d0362f2a' + '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
    '34007208d5b887185865';
  Rfc5869Ikm80 = '000102030405060708090a0b0c0d0e0f' + '101112131415161718191a1b1c1d1e1f' +
    '202122232425262728292a2b2c2d2e2f' + '303132333435363738393a3b3c3d3e3f' +
    '404142434445464748494a4b4c4d4e4f';
  Rfc5869Salt80 = '606162636465666768696a6b6c6d6e6f' + '707172737475767778797a7b7c7d7e7f' +
    '808182838485868788898a8b8c8d8e8f' + '909192939495969798999a9b9c9d9e9f' +
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
  Rfc5869Info80 = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
    'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
    'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
  Rfc5869Prk2 = '06a6b88c5853361a06104c9ceb35b45c' + 'ef760014904671014a193f40c15fc244';
  Rfc5869Okm2 = 'b11e398dc80327a1c8e7f78c596a4934' + '4f012eda2d4efad8a050cc4c19afa97c' +
    '59045a99cac7827271cb41c65e590e09' + 'da3275600c2f09b8367793a9aca3db71' +
    'cc30c58179ec3e87c14c01d5c1f3434f' + '1d87';
  Rfc5869Prk3 = '19ef24a32c717b167f33a91d6f648bdf' + '96596776afdb6377ac434c1c293ccb04';
  Rfc5869Okm3 = '8da4e775a563c18f715f802a063c5a31' + 'b8a11f5c5ee1879ec3454e5f3c738d2d' +
    '9d201395faa4b61a96c8';

{ TCountingKdfPrimitives }

function TCountingKdfPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Inc(FHkdfs);
  Result := inherited CreateHkdf(AAlgorithm);
end;

function TCountingKdfPrimitives.CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
begin
  Inc(FPrfs);
  Result := inherited CreateTls12Prf(AAlgorithm);
end;

{ TTestComplianceCryptoPrimitives }

function TTestComplianceCryptoPrimitives.CreateCrypto: ICryptoProvider;
begin
  Result := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
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

function TTestComplianceCryptoPrimitives.LabelRefusal(const AProvider: ICryptoProvider;
  const ALabel: string): string;
begin
  Result := '';
  try
    ComputePrf(AProvider, ALabel);
  except
    on E: EComplianceRefusedTlsLibException do
      Result := E.Message;
  end;
end;

procedure TTestComplianceCryptoPrimitives.TestChaChaRefusedStrict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.CHACHA20_POLY1305), 'ChaCha is not allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestChaChaRefusedRelaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.CHACHA20_POLY1305),
    'an allowlist refuses in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestAes256AllowedUnderCnsa1;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_256_GCM), 'AES-256 is the CNSA AEAD');
end;

procedure TTestComplianceCryptoPrimitives.TestAes128RefusedUnderCnsa1Strict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM), 'AES-128 is outside CNSA');
end;

procedure TTestComplianceCryptoPrimitives.TestAes128RefusedUnderCnsa1Relaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM),
    'the rules refuse AES-128 in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestAesAllowedUnderFips;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM), 'AES-128 is allowed');
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_256_GCM), 'AES-256 is allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestX25519RefusedStrict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.X25519),
    'X25519 is not allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestX25519RefusedRelaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.X25519),
    'an allowlist refuses in relaxed mode too');
end;

procedure TTestComplianceCryptoPrimitives.TestP256AllowedFips;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'P-256 is allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestP384AllowedCnsa1;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckFalse(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP384R1),
    'P-384 is the CNSA curve');
end;

procedure TTestComplianceCryptoPrimitives.TestP256RefusedCnsa1Strict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'P-256 is outside CNSA');
end;

procedure TTestComplianceCryptoPrimitives.TestP256RefusedCnsa1Relaxed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    LRules, TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP384R1),
    'a curve no group names is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestKemAlwaysRefusedBothModes;
var
  LStrict, LRelaxed: ICryptoProvider;
begin
  LStrict := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  LRelaxed := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckTrue(RefusesKem(LStrict, TKemAlgorithm.ML_KEM_768), 'no KEM in strict mode');
  CheckTrue(RefusesKem(LRelaxed, TKemAlgorithm.ML_KEM_768), 'no KEM in relaxed mode');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortableAead;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(
    TComplianceFakes.SystemOver([TAeadAlgorithm.AES_128_GCM]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesAead(LProvider, TAeadAlgorithm.AES_128_GCM),
    'an allowed AEAD the module does not serve is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAllowsSystemAeadBesidePortableOne;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(
    TComplianceFakes.SystemOver([TAeadAlgorithm.AES_128_GCM]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesAead(LProvider, TAeadAlgorithm.AES_256_GCM),
    'only the portable AEAD is refused');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsPortableAead;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(
    TComplianceFakes.SystemOver([TAeadAlgorithm.AES_128_GCM]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesHkdf(LProvider, THashAlgorithm.SHA_256),
    'HKDF over the module HMAC is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesComposedHkdfUnderRequireModule;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    RequireModuleRules, TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesHkdf(LProvider, THashAlgorithm.SHA_256),
    'relaxed mode forwards the composed HKDF');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAcceptsComposedPrfUnderAllowComposed;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesPrf(LProvider, THashAlgorithm.SHA_256),
    'the PRF over the module HMAC is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesComposedPrfUnderRequireModule;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    RequireModuleRules, TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesPrf(LProvider, THashAlgorithm.SHA_256),
    'relaxed mode forwards the composed PRF');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfRefusesPlainMasterSecretLabelStrict;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(ComputePrf(LProvider, 'extended master secret').ConstantTimeAreEqual(
    ComputePrf(Crypto, 'extended master secret')),
    'the wrapped PRF gives the inner PRF output');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfAllowsOtherLabels;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesLabel(LProvider, 'key expansion'), 'key expansion is allowed');
  CheckFalse(RefusesLabel(LProvider, 'client finished'), 'the finished label is allowed');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfLabelMatchIsExact;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    LRules, TComplianceEnforcement.Strict);
  CheckFalse(RefusesLabel(LProvider, 'master secret'),
    'the label is refused only when the rules require Extended Master Secret');
end;

function TTestComplianceCryptoPrimitives.ModulePrfProvider(const ARules: TComplianceRules;
  AEnforcement: TComplianceEnforcement): ICryptoProvider;
var
  LReport: TFakeBackendReport;
begin
  LReport := TFakeBackendReport.Create([]);
  LReport.NativePrf := True;
  Result := ProviderOver(LReport as ICryptoBackendReport, ARules, AEnforcement);
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRequireModuleRefusesAnExporterLabel;
var
  LProvider: ICryptoProvider;
begin
  LProvider := ModulePrfProvider(RequireModuleRules, TComplianceEnforcement.Strict);
  CheckTrue(RefusesLabel(LProvider, 'EXPORTER-my-app'),
    'an exporter label would be composed over the module HMAC');
  CheckTrue(RefusesLabel(LProvider, ''), 'and so would an empty one');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRequireModuleWithoutEmsPassesMasterSecret;
var
  LRules: TComplianceRules;
begin
  LRules := RequireModuleRules;
  LRules.Requirements := LRules.Requirements - [TComplianceRequirement.ExtendedMasterSecret];
  CheckEquals('', LabelRefusal(ModulePrfProvider(LRules, TComplianceEnforcement.Strict),
    'master secret'), 'master secret is a key-schedule label');
end;

procedure TTestComplianceCryptoPrimitives.
  TestStrictRequireModuleWithoutEmsRefusesAnExporterLabelAsNotKeySchedule;
var
  LRules: TComplianceRules;
  LMessage: string;
begin
  LRules := RequireModuleRules;
  LRules.Requirements := LRules.Requirements - [TComplianceRequirement.ExtendedMasterSecret];
  LMessage := LabelRefusal(ModulePrfProvider(LRules, TComplianceEnforcement.Strict),
    'EXPORTER-my-app');
  CheckTrue(Pos('not a key-schedule label', LMessage) > 0, 'refused as not a key-schedule label');
  CheckEquals(0, Pos('plain master secret', LMessage), 'and not as the plain master secret');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRequireModuleAllowsTheOtherKeyScheduleLabels;
var
  LProvider: ICryptoProvider;
begin
  LProvider := ModulePrfProvider(RequireModuleRules, TComplianceEnforcement.Strict);
  CheckFalse(RefusesLabel(LProvider, 'extended master secret'), 'extended master secret');
  CheckFalse(RefusesLabel(LProvider, 'key expansion'), 'key expansion');
  CheckFalse(RefusesLabel(LProvider, 'client finished'), 'client finished');
  CheckFalse(RefusesLabel(LProvider, 'server finished'), 'server finished');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRequireModuleKeyScheduleLabelMatchIsExact;
var
  LProvider: ICryptoProvider;
begin
  LProvider := ModulePrfProvider(RequireModuleRules, TComplianceEnforcement.Strict);
  CheckTrue(RefusesLabel(LProvider, 'key expansion '), 'a trailing space is an exporter label');
  CheckTrue(RefusesLabel(LProvider, 'Client Finished'), 'the label is case sensitive');
  CheckTrue(RefusesLabel(LProvider, 'server finishe'), 'a prefix is an exporter label');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictAllowComposedAllowsAnExporterLabel;
var
  LProvider: ICryptoProvider;
begin
  LProvider := ModulePrfProvider(TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckFalse(RefusesLabel(LProvider, 'EXPORTER-my-app'),
    'the rules accept a derivation composed over the module HMAC');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedRequireModuleAllowsAnExporterLabel;
var
  LProvider: ICryptoProvider;
begin
  LProvider := ModulePrfProvider(RequireModuleRules, TComplianceEnforcement.Relaxed);
  CheckFalse(RefusesLabel(LProvider, 'EXPORTER-my-app'), 'relaxed mode refuses no derivation');
end;

procedure TTestComplianceCryptoPrimitives.TestRefusalIsFatalInternalError;
var
  LProvider: ICryptoProvider;
  LRaised: Boolean;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(LProvider.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM) = nil, 'the X25519 KEM is not instantiable');
end;

procedure TTestComplianceCryptoPrimitives.TestHpkeChaChaSuiteUnavailable;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(LProvider.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.CHACHA20_POLY1305) = nil, 'the ChaCha AEAD is not instantiable');
end;

procedure TTestComplianceCryptoPrimitives.TestHpkeP256SuiteAvailable;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(LProvider.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM) <> nil, 'an allowed suite is still instantiable');
end;

procedure TTestComplianceCryptoPrimitives.TestHpkeHasNoMlKemSuite;
var
  LProvider: ICryptoProvider;
begin
  // a guard: fails only if a base learns an ML-KEM-768 suite (IANA HPKE KEM registry)
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
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
  LProvider := TComplianceCryptoProvider.Compose(
    TComplianceFakes.FakeSystemBase(LReport, nil, nil), TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckTrue(Supports(LProvider, ICryptoBackendReport, LFound), 'the report is still offered');
  CheckTrue(LFound = LReport, 'and it is the base report itself');
end;

procedure TTestComplianceCryptoPrimitives.TestSuppliedHpkeFacetAnswerIsTheBaseReportAnswer;
var
  LBaseReport, LReport: ICryptoBackendReport;
  LProvider: ICryptoProvider;
  LExpected, LActual: TCryptoBackendEntry;
begin
  // the rules restrict the supplied facet; they do not re-describe what the base reports, which
  // for a facet that is no composition over the base's primitives is portable
  LBaseReport := TFakeBackendReport.Create([]) as ICryptoBackendReport;
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(
    LBaseReport, nil, TFakeHpke.Create as IHpkeCrypto), TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed);
  CheckTrue(Supports(LProvider, ICryptoBackendReport, LReport), 'the report is offered');
  LExpected := LBaseReport.FacetBackend(TCryptoFacet.Hpke);
  LActual := LReport.FacetBackend(TCryptoFacet.Hpke);
  CheckEquals(Ord(LExpected.Backend), Ord(LActual.Backend), 'the backend is the base answer');
  CheckEquals(Ord(LExpected.Reason), Ord(LActual.Reason), 'the reason is the base answer');
end;

procedure TTestComplianceCryptoPrimitives.TestRebuiltHpkeFacetAnswerIsTheBaseReportAnswer;
var
  LBaseReport, LReport: ICryptoBackendReport;
  LProvider: ICryptoProvider;
  LComposition: IHpkeComposition;
  LActual: TCryptoBackendEntry;
begin
  // the rebuilt composition runs over the refusing primitives; its report line stays the base's
  LBaseReport := TBareBackendReport.Create(True) as ICryptoBackendReport;
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(
    LBaseReport, nil, nil), TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  CheckTrue(Supports(LProvider.Hpke, IHpkeComposition, LComposition),
    'the base HPKE is rebuilt, not wrapped');
  CheckTrue(Supports(LProvider, ICryptoBackendReport, LReport), 'the report is offered');
  LActual := LReport.FacetBackend(TCryptoFacet.Hpke);
  CheckEquals(Ord(TCryptoBackend.Composed), Ord(LActual.Backend),
    'the facet is still reported composed');
  CheckEquals(Ord(LBaseReport.FacetBackend(TCryptoFacet.Hpke).Reason), Ord(LActual.Reason),
    'with the base reason');
end;

procedure TTestComplianceCryptoPrimitives.TestComposeDecidesByTheGivenReport;
var
  LBase, LProvider: ICryptoProvider;
begin
  LBase := TComplianceFakes.SystemOver([]);
  CheckFalse(RefusesRandom(TComplianceCryptoProvider.Compose(LBase, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict)), 'control: the base report places it in the module');
  LProvider := TComplianceCryptoProvider.Compose(LBase, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict, TPortableOnlyReport.Create(False) as ICryptoBackendReport);
  CheckTrue(RefusesRandom(LProvider), 'the given report decides, not the base');
end;

procedure TTestComplianceCryptoPrimitives.TestComposeWithAGivenReportKeepsTheBaseReport;
var
  LBaseReport, LFound: ICryptoBackendReport;
  LProvider: ICryptoProvider;
begin
  LBaseReport := TFakeBackendReport.Create([]) as ICryptoBackendReport;
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(LBaseReport, nil,
    nil), TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict,
    TPortableOnlyReport.Create(False) as ICryptoBackendReport);
  CheckTrue(Supports(LProvider, ICryptoBackendReport, LFound), 'a report is offered');
  CheckTrue(LFound = LBaseReport, 'it still describes the base');
end;

procedure TTestComplianceCryptoPrimitives.TestComposeRejectsNilDecisionReport;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TComplianceCryptoProvider.Compose(Crypto, TCompliancePresets.Fips140_3,
      TComplianceEnforcement.Strict, nil);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil decision report');
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

function TTestComplianceCryptoPrimitives.ProviderOver(const AReport: ICryptoBackendReport;
  const ARules: TComplianceRules; AEnforcement: TComplianceEnforcement): ICryptoProvider;
begin
  Result := TComplianceCryptoProvider.Compose(
    TComplianceFakes.FakeSystemBase(AReport, nil, nil), ARules, AEnforcement);
end;

function TTestComplianceCryptoPrimitives.HpkeOver(const AHpke: IHpkeCrypto;
  const ARules: TComplianceRules; AEnforcement: TComplianceEnforcement): ICryptoProvider;
begin
  Result := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil, AHpke), ARules, AEnforcement);
end;

function TTestComplianceCryptoPrimitives.RefusedKeyOperations(const AHpke: IHpkeCrypto;
  AKem: UInt16): Int32;
var
  LPublic: TBytes;
  LPrivate: ISecretBuffer;
begin
  Result := 0;
  try
    AHpke.ImportRecipientKey(AKem, nil);
  except
    on EComplianceRefusedTlsLibException do
      Inc(Result);
  end;
  try
    AHpke.GenerateKeyPair(AKem, LPublic, LPrivate);
  except
    on EComplianceRefusedTlsLibException do
      Inc(Result);
  end;
  try
    AHpke.ImportPrivateKey(AKem, nil);
  except
    on EComplianceRefusedTlsLibException do
      Inc(Result);
  end;
end;

function TTestComplianceCryptoPrimitives.KdfProviderOver(const APrimitives: ICryptoPrimitives;
  const AReport: ICryptoBackendReport; AEnforcement: TComplianceEnforcement): ICryptoProvider;
var
  LBase: ICryptoProvider;
begin
  LBase := TOverlayCryptoProvider.Create(Crypto, APrimitives, nil, AReport, nil);
  Result := TComplianceCryptoProvider.Compose(LBase, TCompliancePresets.Fips140_3, AEnforcement);
end;

function TTestComplianceCryptoPrimitives.HkdfExpandRefused(
  const AProvider: ICryptoProvider): Boolean;
begin
  Result := False;
  try
    AProvider.Primitives.CreateHkdf(THashAlgorithm.SHA_256).Expand(
      TSecretBuffer.From(DecodeHex(Rfc5869Prk1)), DecodeHex(Rfc5869Info10), 42);
  except
    on EComplianceRefusedTlsLibException do
      Result := True;
  end;
end;

procedure TTestComplianceCryptoPrimitives.CheckHkdfVector(const AProvider: ICryptoProvider;
  const ASalt, AIkm, AInfo, APrk, AOkm: string; ALength: Int32);
var
  LHkdf: IHkdf;
  LPrk: ISecretBuffer;
begin
  LHkdf := AProvider.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
  LPrk := LHkdf.Extract(TSecretBuffer.From(DecodeHex(ASalt)), TSecretBuffer.From(DecodeHex(AIkm)));
  CheckEqualBytes('HKDF-Extract PRK', DecodeHex(APrk), LPrk.ToBytes);
  CheckEqualBytes('HKDF-Expand OKM', DecodeHex(AOkm),
    LHkdf.Expand(LPrk, DecodeHex(AInfo), ALength).ToBytes);
end;

procedure TTestComplianceCryptoPrimitives.TestHkdfNeverReachesTheInnerFacetStrict;
var
  LInner: TCountingKdfPrimitives;
  LRef: ICryptoPrimitives;
  LProvider: ICryptoProvider;
  LBefore: Int32;
begin
  LInner := TCountingKdfPrimitives.Create(Crypto.Primitives);
  LRef := LInner;
  LProvider := KdfProviderOver(LRef, TFakeBackendReport.Create([]) as ICryptoBackendReport,
    TComplianceEnforcement.Strict);
  // building the base probes its HPKE suites through the inner HKDF
  LBefore := LInner.Hkdfs;
  CheckHkdfVector(LProvider, Rfc5869Salt13, Rfc5869Ikm22, Rfc5869Info10, Rfc5869Prk1,
    Rfc5869Okm1, 42);
  CheckEquals(LBefore, LInner.Hkdfs, 'the inner HKDF, which may expand natively, is not asked');
end;

procedure TTestComplianceCryptoPrimitives.TestHkdfNeverReachesTheInnerFacetRelaxed;
var
  LInner: TCountingKdfPrimitives;
  LRef: ICryptoPrimitives;
  LProvider: ICryptoProvider;
  LBefore: Int32;
begin
  LInner := TCountingKdfPrimitives.Create(Crypto.Primitives);
  LRef := LInner;
  LProvider := KdfProviderOver(LRef, TFakeBackendReport.Create([]) as ICryptoBackendReport,
    TComplianceEnforcement.Relaxed);
  LBefore := LInner.Hkdfs;
  CheckHkdfVector(LProvider, Rfc5869Salt13, Rfc5869Ikm22, Rfc5869Info10, Rfc5869Prk1,
    Rfc5869Okm1, 42);
  CheckEquals(LBefore, LInner.Hkdfs, 'relaxed mode composes it too');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictHkdfOverAPortableHmacIsRefused;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableHmacs := [THashAlgorithm.SHA_256];
  CheckTrue(HkdfExpandRefused(ProviderOver(LRef, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict)), 'the derivation is only as good as its HMAC');
  CheckFalse(HkdfExpandRefused(ProviderOver(TFakeBackendReport.Create([])
    as ICryptoBackendReport, TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict)),
    'control: the same derivation over a module HMAC runs');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfIsServedByTheInnerFacetWhenTheReportSaysSystem;
var
  LInner: TCountingKdfPrimitives;
  LInnerRef: ICryptoPrimitives;
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
  LProvider: ICryptoProvider;
begin
  LInner := TCountingKdfPrimitives.Create(Crypto.Primitives);
  LInnerRef := LInner;
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.NativePrf := True;
  LProvider := KdfProviderOver(LInnerRef, LRef, TComplianceEnforcement.Strict);
  LProvider.Primitives.CreateTls12Prf(THashAlgorithm.SHA_256);
  CheckEquals(1, LInner.Prfs, 'the module PRF is the one handed back');
end;

procedure TTestComplianceCryptoPrimitives.TestPrfIsComposedWhenTheReportSaysComposed;
var
  LInner: TCountingKdfPrimitives;
  LRef: ICryptoPrimitives;
  LProvider: ICryptoProvider;
begin
  LInner := TCountingKdfPrimitives.Create(Crypto.Primitives);
  LRef := LInner;
  LProvider := KdfProviderOver(LRef, TFakeBackendReport.Create([]) as ICryptoBackendReport,
    TComplianceEnforcement.Strict);
  LProvider.Primitives.CreateTls12Prf(THashAlgorithm.SHA_256);
  CheckEquals(0, LInner.Prfs, 'a PRF the module does not serve is assembled over the HMAC');
end;

procedure TTestComplianceCryptoPrimitives.TestComposedPrfComputesTheReferenceOutput;
var
  LProvider: ICryptoProvider;
begin
  LProvider := ProviderOver(TFakeBackendReport.Create([]) as ICryptoBackendReport,
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(ComputePrf(LProvider, 'key expansion').ConstantTimeAreEqual(
    ComputePrf(Crypto, 'key expansion')), 'the composition agrees with the portable PRF');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictComposedPrfRefusesAPortableHmac;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableHmacs := [THashAlgorithm.SHA_256];
  CheckTrue(RefusesPrf(ProviderOver(LRef, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict), THashAlgorithm.SHA_256), 'no PRF over a portable HMAC');
end;

procedure TTestComplianceCryptoPrimitives.TestHkdfRfc5869VectorsThroughTheOsProvider;
var
  LBase, LProvider: ICryptoProvider;
begin
  LBase := TOSCryptoProvider.Compose(Crypto);
  if not TOSCryptoProvider.HasNativeFacets or not Supports(LBase, ICryptoBackendReport) then
  begin
    SkipTest('no OS overlay engaged');
    Exit;
  end;
  LProvider := TComplianceCryptoProvider.Compose(LBase, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict);
  CheckHkdfVector(LProvider, Rfc5869Salt13, Rfc5869Ikm22, Rfc5869Info10, Rfc5869Prk1,
    Rfc5869Okm1, 42);
  CheckHkdfVector(LProvider, Rfc5869Salt80, Rfc5869Ikm80, Rfc5869Info80, Rfc5869Prk2,
    Rfc5869Okm2, 82);
  CheckHkdfVector(LProvider, '', Rfc5869Ikm22, '', Rfc5869Prk3, Rfc5869Okm3, 42);
end;

function TTestComplianceCryptoPrimitives.NewSchedule(
  const AProvider: ICryptoProvider): ITls12KeySchedule;
begin
  Result := TTls12KeySchedule.Create(AProvider, THashAlgorithm.SHA_256, 16,
    TAeadAlgorithm.AES_128_GCM) as ITls12KeySchedule;
  Result.SetPreMasterSecret(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  Result.SetRandoms(DecodeHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
    DecodeHex('ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100'));
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortableRandomOnSystemBase;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableRandom := True;
  CheckTrue(RefusesRandom(ProviderOver(LRef, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict)), 'the report places the random generator outside');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsPortableRandomOnSystemBase;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableRandom := True;
  CheckFalse(RefusesRandom(ProviderOver(LRef, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed)), 'relaxed mode forwards it');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortableHashBesideSystemOne;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
  LProvider: ICryptoProvider;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableHashes := [THashAlgorithm.SHA_384];
  LProvider := ProviderOver(LRef, TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesHash(LProvider, THashAlgorithm.SHA_384), 'the portable SHA-384 is refused');
  CheckFalse(RefusesHash(LProvider, THashAlgorithm.SHA_256), 'the module SHA-256 is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestRelaxedForwardsPortableHashBesideSystemOne;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableHashes := [THashAlgorithm.SHA_384];
  CheckFalse(RefusesHash(ProviderOver(LRef, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed), THashAlgorithm.SHA_384), 'relaxed mode forwards it');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortableHmacBesideSystemOne;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
  LProvider: ICryptoProvider;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableHmacs := [THashAlgorithm.SHA_384];
  LProvider := ProviderOver(LRef, TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesHmac(LProvider, THashAlgorithm.SHA_384), 'the portable HMAC is refused');
  CheckFalse(RefusesHmac(LProvider, THashAlgorithm.SHA_256), 'the module HMAC is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestStrictRefusesPortableCurveBesideSystemOne;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
  LProvider: ICryptoProvider;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableCurves := [TKeyAgreementAlgorithm.SECP384R1];
  LProvider := ProviderOver(LRef, TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP384R1),
    'the portable P-384 is refused');
  CheckFalse(RefusesKeyAgreement(LProvider, TKeyAgreementAlgorithm.SECP256R1),
    'the module P-256 is accepted');
end;

procedure TTestComplianceCryptoPrimitives.TestKeyScheduleRefusesPlainMasterSecret;
var
  LSchedule: ITls12KeySchedule;
  LRaised: Boolean;
begin
  LSchedule := NewSchedule(TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict));
  LRaised := False;
  try
    LSchedule.DeriveMasterSecret;
  except
    on EComplianceRefusedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a schedule over the provider cannot derive without the extension');
  CheckTrue(LSchedule.MasterSecret = nil, 'no master secret exists');
end;

procedure TTestComplianceCryptoPrimitives.TestKeyScheduleDerivesExtendedMasterSecret;
var
  LSchedule: ITls12KeySchedule;
begin
  LSchedule := NewSchedule(TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict));
  LSchedule.DeriveExtendedMasterSecret(
    DecodeHex('0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100'));
  CheckTrue(LSchedule.MasterSecret <> nil, 'the extended master secret is derived');
end;

procedure TTestComplianceCryptoPrimitives.TestComposeRejectsNilBase;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TComplianceCryptoProvider.Compose(nil, TCompliancePresets.Fips140_3,
      TComplianceEnforcement.Strict);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil base is rejected');
end;

procedure TTestComplianceCryptoPrimitives.TestRebuiltHpkeIsNotFiltered;
var
  LProvider: ICryptoProvider;
  LComposition: IHpkeComposition;
begin
  LProvider := TComplianceCryptoProvider.Compose(TComplianceFakes.SystemOver([]),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict);
  CheckTrue(Supports(LProvider.Hpke, IHpkeComposition, LComposition),
    'the base composition is kept');
  CheckTrue(LComposition.ComposedOver = LProvider.Primitives,
    'and composed over the refusing primitives');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeIsNotTheBaseFacet;
var
  LFake: IHpkeCrypto;
begin
  LFake := TFakeHpke.Create as IHpkeCrypto;
  CheckFalse(HpkeOver(LFake, TCompliancePresets.Cnsa1, TComplianceEnforcement.Relaxed).Hpke =
    LFake, 'the foreign facet is decorated');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedRefusesKemOutsideRules;
var
  LHpke: IHpkeCrypto;
begin
  LHpke := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke;
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA384,
    THpkeAead.AES_256_GCM) = nil, 'X25519 is outside the rules');
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256, THpkeKdf.HKDF_SHA384,
    THpkeAead.AES_256_GCM) = nil, 'P-256 is outside the rules');
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P521_HKDF_SHA512, THpkeKdf.HKDF_SHA384,
    THpkeAead.AES_256_GCM) = nil, 'P-521 is outside the rules');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedRefusesAeadOutsideRules;
var
  LHpke: IHpkeCrypto;
begin
  LHpke := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke;
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P384_HKDF_SHA384, THpkeKdf.HKDF_SHA384,
    THpkeAead.AES_128_GCM) = nil, 'AES-128 is outside the rules');
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P384_HKDF_SHA384, THpkeKdf.HKDF_SHA384,
    THpkeAead.CHACHA20_POLY1305) = nil, 'ChaCha is outside the rules');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedKeepsAllowedSuite;
var
  LHpke: IHpkeCrypto;
begin
  LHpke := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke;
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P384_HKDF_SHA384, THpkeKdf.HKDF_SHA384,
    THpkeAead.AES_256_GCM) <> nil, 'P-384 with AES-256 passes');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedDoesNotFilterHashes;
var
  LHpke: IHpkeCrypto;
begin
  LHpke := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke;
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P384_HKDF_SHA384, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_256_GCM) <> nil, 'the suite KDF is the base''s to judge');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedRefusesUnknownKemAndAead;
var
  LHpke: IHpkeCrypto;
begin
  LHpke := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Relaxed).Hpke;
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_X448_HKDF_SHA512, THpkeKdf.HKDF_SHA512,
    THpkeAead.AES_256_GCM) = nil, 'X448 names no allowed group');
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.EXPORT_ONLY) = nil, 'export-only is no allowed AEAD');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedFiltersSupportedSuites;
var
  LSuites: TArray<THpkeSuiteId>;
begin
  LSuites := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke.SupportedSuites(THpkeKem.DHKEM_P384_HKDF_SHA384);
  CheckEquals(1, System.Length(LSuites), 'only the AES-256 suite is left');
  CheckEquals(THpkeAead.AES_256_GCM, LSuites[0].Aead, 'it is the AES-256 one');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedListsNoSuiteForRefusedKem;
begin
  CheckEquals(0, System.Length(HpkeOver(TFakeHpke.Create as IHpkeCrypto,
    TCompliancePresets.Cnsa1, TComplianceEnforcement.Relaxed).Hpke.SupportedSuites(
    THpkeKem.DHKEM_X25519_HKDF_SHA256)), 'no X25519 suite is listed');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedPublicKeyAndEncapsulationFollowKem;
var
  LHpke: IHpkeCrypto;
begin
  LHpke := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke;
  CheckTrue(LHpke.ValidatePublicKey(THpkeKem.DHKEM_P384_HKDF_SHA384, TBytes.Create(1)),
    'an allowed KEM key is judged by the base');
  CheckFalse(LHpke.ValidatePublicKey(THpkeKem.DHKEM_X25519_HKDF_SHA256, TBytes.Create(1)),
    'a refused KEM key is invalid');
  CheckTrue(System.Length(LHpke.RandomEncapsulation(THpkeKem.DHKEM_P384_HKDF_SHA384)) > 0,
    'an allowed KEM yields an encapsulation');
  CheckTrue(LHpke.RandomEncapsulation(THpkeKem.DHKEM_X25519_HKDF_SHA256) = nil,
    'a refused KEM yields none');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedOtherKemKeyOperationsRefuse;
var
  LFake: TFakeHpke;
  LRef: IHpkeCrypto;
begin
  LFake := TFakeHpke.Create;
  LRef := LFake;
  CheckEquals(3, RefusedKeyOperations(HpkeOver(LRef, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke, THpkeKem.DHKEM_X25519_HKDF_SHA256),
    'import, generate and private import refuse a KEM outside the rules');
  CheckEquals(0, LFake.RecipientImports + LFake.KeyPairs + LFake.PrivateImports,
    'the base was not reached');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeRelaxedAllowedKemReachesBase;
var
  LFake: TFakeHpke;
  LRef: IHpkeCrypto;
begin
  LFake := TFakeHpke.Create;
  LRef := LFake;
  CheckEquals(0, RefusedKeyOperations(HpkeOver(LRef, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Relaxed).Hpke, THpkeKem.DHKEM_P384_HKDF_SHA384),
    'an allowed KEM is not refused');
  CheckEquals(1, LFake.RecipientImports, 'the recipient import reached the base');
  CheckEquals(1, LFake.KeyPairs, 'the key pair reached the base');
  CheckEquals(1, LFake.PrivateImports, 'the private import reached the base');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeStrictOffersNothing;
var
  LHpke: IHpkeCrypto;
begin
  LHpke := HpkeOver(TFakeHpke.Create as IHpkeCrypto, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Strict).Hpke;
  CheckTrue(LHpke.Suite(THpkeKem.DHKEM_P384_HKDF_SHA384, THpkeKdf.HKDF_SHA384,
    THpkeAead.AES_256_GCM) = nil, 'not even an allowed suite');
  CheckEquals(0, System.Length(LHpke.SupportedSuites(THpkeKem.DHKEM_P384_HKDF_SHA384)),
    'no suite is listed');
  CheckFalse(LHpke.ValidatePublicKey(THpkeKem.DHKEM_P384_HKDF_SHA384, TBytes.Create(1)),
    'no public key is valid');
  CheckTrue(LHpke.RandomEncapsulation(THpkeKem.DHKEM_P384_HKDF_SHA384) = nil,
    'no encapsulation is made');
end;

procedure TTestComplianceCryptoPrimitives.TestForeignHpkeStrictKeyOperationsRefuse;
var
  LFake: TFakeHpke;
  LRef: IHpkeCrypto;
begin
  LFake := TFakeHpke.Create;
  LRef := LFake;
  CheckEquals(3, RefusedKeyOperations(HpkeOver(LRef, TCompliancePresets.Cnsa1,
    TComplianceEnforcement.Strict).Hpke, THpkeKem.DHKEM_P384_HKDF_SHA384),
    'every key operation refuses, even for an allowed KEM');
  CheckEquals(0, LFake.RecipientImports + LFake.KeyPairs + LFake.PrivateImports,
    'the base was not reached');
end;

procedure TTestComplianceCryptoPrimitives.TestComplianceHpkeRejectsNilInner;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TComplianceHpke.Create(nil, TCompliancePresets.Cnsa1, TComplianceEnforcement.Strict).Free;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil inner facet is rejected');
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
  FFakeInput := TBytes.Create(1, 2, 3);
end;

function TTestComplianceSigningCrypto.SigningOver(const AKey: ISigningKey;
  ANativeVerifiers: Boolean): ICryptoProvider;
begin
  Result := TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport,
    TFakeSigningCrypto.Create(AKey, ANativeVerifiers) as ISigningCrypto, nil);
end;

function TTestComplianceSigningCrypto.ReportlessOver(const AKey: ISigningKey): ICryptoProvider;
begin
  Result := TComplianceFakes.FakeSystemBase(nil,
    TFakeSigningCrypto.Create(AKey, True) as ISigningCrypto, nil);
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
  const AData: TBytes): Boolean;
begin
  Result := False;
  try
    ASigning.ImportSigningKey(AData, nil);
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
  const AData: TBytes): Boolean;
begin
  Result := False;
  try
    ASigning.ImportPkcs12(AData, TSecretBuffer.FromString(Pkcs12Password));
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
  CheckTrue(ImportRefused(LSigning, DecodeHex(FKeys.Values['ed25519_pkcs8_der'])),
    'an EdDSA key has no allowed scheme');
end;

procedure TTestComplianceSigningCrypto.TestEd25519SystemKeyRefusedStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ED25519]), True), TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).Signing;
  CheckTrue(ImportRefused(LSigning, FFakeInput), 'the allowlist refuses a module key too');
end;

procedure TTestComplianceSigningCrypto.TestKeyWithNoAllowedSchemeRefusedByEveryImportPath;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ED448]), True), TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).Signing;
  CheckTrue(ImportRefused(LSigning, FFakeInput), 'the key import path');
  CheckTrue(Pkcs12Refused(LSigning, FFakeInput), 'the PKCS#12 import path');
end;

procedure TTestComplianceSigningCrypto.TestImportHandsTheInputUnchangedToTheInnerFacet;
var
  LInner: TFakeSigningCrypto;
  LHeld, LSigning: ISigningCrypto;
  LInput: TBytes;
begin
  // an armored input: the decorator must not decode it before the inner facet sees it
  LInput := TEncoding.ASCII.GetBytes(
    '-----BEGIN PRIVATE KEY-----' + sLineBreak + 'AQID' + sLineBreak +
    '-----END PRIVATE KEY-----' + sLineBreak);
  LInner := TFakeSigningCrypto.Create(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True);
  LHeld := LInner;
  LSigning := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, LHeld, nil),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  LSigning.ImportSigningKey(LInput, nil);
  CheckEquals(System.Length(LInput), System.Length(LInner.ImportedInput), 'same length');
  CheckTrue(CompareMem(@LInput[0], @LInner.ImportedInput[0], System.Length(LInput)),
    'same bytes');
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
  LKey := LSigning.ImportSigningKey(FFakeInput, nil);
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
  LSchemes := LSigning.ImportSigningKey(FFakeInput, nil).CapableSchemes;
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
  CheckTrue(ImportRefused(LSigning, DecodeHex(FKeys.Values['ec256_pkcs8_der'])),
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
  LKey := LSigning.ImportSigningKey(FFakeInput, nil);
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
  LKey := LSigning.ImportSigningKey(FFakeInput, nil);
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
  CheckTrue(Pkcs12Refused(LSigning, DecodeHex(FPfx.Values['ec_pfx'])),
    'a PKCS#12 key outside the module is refused');
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
    TSecretBuffer.FromString(Pkcs12Password));
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
    TSecretBuffer.FromString(Pkcs12Password));
  LExpected := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(Pkcs12Password));
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
  CheckTrue(Pkcs12Refused(LSigning, DecodeHex(FPfx.Values['ed25519_pfx'])),
    'an EdDSA PKCS#12 key has no allowed scheme');
end;

procedure TTestComplianceSigningCrypto.TestPkcs12SystemKeyAdmittedStrict;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    SigningOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256]), True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckFalse(Pkcs12Refused(LSigning, FFakeInput), 'a module PKCS#12 key is admitted');
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

procedure TTestComplianceSigningCrypto.TestStrictRefusesMarkedKeyImportOverBaseWithoutReport;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    ReportlessOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256])),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(ImportRefused(LSigning, FFakeInput),
    'a marker proves nothing when the base reports nothing');
end;

procedure TTestComplianceSigningCrypto.TestStrictRefusesSignerForMarkedKeyOverBaseWithoutReport;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    ReportlessOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256])),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(SignerRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256,
    SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256])), 'no signer is granted');
end;

procedure TTestComplianceSigningCrypto.TestStrictRefusesMarkedVerifierOverBaseWithoutReport;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(ReportlessOver(nil),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(VerifierRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    'a marked verifier proves nothing either');
end;

procedure TTestComplianceSigningCrypto.TestRelaxedAdmitsMarkedKeyOverBaseWithoutReport;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(
    ReportlessOver(SystemKey([TSignatureScheme.ECDSA_SECP256R1_SHA256])),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed).Signing;
  CheckFalse(ImportRefused(LSigning, FFakeInput), 'relaxed mode passes the fact through');
end;

procedure TTestComplianceSigningCrypto.TestNilKeyFromBaseRefused;
var
  LStrict, LRelaxed: ISigningCrypto;
begin
  LStrict := TComplianceCryptoProvider.Compose(SigningOver(nil, True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  LRelaxed := TComplianceCryptoProvider.Compose(SigningOver(nil, True),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed).Signing;
  CheckTrue(ImportRefused(LStrict, FFakeInput), 'no key is refused in strict mode');
  CheckTrue(ImportRefused(LRelaxed, FFakeInput), 'and in relaxed mode');
end;

procedure TTestComplianceSigningCrypto.TestStrictVerifierPlacementFollowsReportNotMarker;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(
    TFakeVerifierReport.Create(True) as ICryptoBackendReport,
    TFakeSigningCrypto.Create(nil, False) as ISigningCrypto, nil),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckFalse(VerifierRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    'the report places the verifier in the module');
end;

procedure TTestComplianceSigningCrypto.TestStrictVerifierRefusedWhenReportPlacesItOutside;
var
  LSigning: ISigningCrypto;
begin
  LSigning := TComplianceCryptoProvider.Compose(TComplianceFakes.FakeSystemBase(
    TFakeVerifierReport.Create(False) as ICryptoBackendReport,
    TFakeSigningCrypto.Create(nil, True) as ISigningCrypto, nil),
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Strict).Signing;
  CheckTrue(VerifierRefused(LSigning, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    'the report places the verifier outside, whatever marker it carries');
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

procedure TTestCompliancePkix.CheckNameConstraintAnswers(AEnforcement: TComplianceEnforcement);
var
  LRoot: TBytes;
begin
  LRoot := TTlsLibTestCertificates.Field('Certs/NameConstrainedChain.txt', 'root_cert');
  CheckTrue(Provider(AEnforcement).PathValidation.NameConstraintsAdmit(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/NameConstrainedChain.txt', 'direct_in_scope_leaf_cert'),
    LRoot)), 'a leaf inside the anchor constraints is admitted');
  CheckFalse(Provider(AEnforcement).PathValidation.NameConstraintsAdmit(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/NameConstrainedChain.txt',
    'direct_out_of_scope_leaf_cert'), LRoot)), 'a leaf outside them is refused');
end;

procedure TTestCompliancePkix.TestStrictNameConstraintsAdmitAnswersAsTheBaseDoes;
begin
  CheckNameConstraintAnswers(TComplianceEnforcement.Strict);
  CheckEquals(0, FSpy.PathBuildCount, 'no portable path build ran');
end;

procedure TTestCompliancePkix.TestRelaxedNameConstraintsAdmitAnswersAsTheBaseDoes;
begin
  CheckNameConstraintAnswers(TComplianceEnforcement.Relaxed);
end;

procedure TTestCompliancePkix.TestStrictOcspStapleIndeterminate;
var
  LStatus: TOcspStatus;
  LThis, LNext: TDateTime;
begin
  LThis := 1;
  LNext := 1;
  LStatus := TOcspStatus.Good;
  CheckFalse(Provider(TComplianceEnforcement.Strict).Revocation.ValidateOcspStaple(FLeaf, FRoot,
    nil, NowUtc, LStatus, LThis, LNext), 'indeterminate');
  CheckEquals(Ord(TOcspStatus.Unknown), Ord(LStatus), 'the status out is Unknown');
  CheckTrue(LThis = 0, 'the thisUpdate out is cleared');
  CheckTrue(LNext = 0, 'the nextUpdate out is cleared');
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
  CheckEquals(0, FSpy.OcspUrlsCount, 'the base was not asked');
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
  CheckEquals(0, FSpy.CrlUrlsCount, 'the base was not asked');
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
  CheckTrue(LThis = 0, 'the thisUpdate out is cleared');
  CheckTrue(LNext = 0, 'the nextUpdate out is cleared');
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
  CheckEquals(1, FSpy.OcspUrlsCount, 'from the base');
end;

procedure TTestCompliancePkix.TestRelaxedCrlDistributionPointsForward;
var
  LUrls: TArray<string>;
begin
  FSpy.OverrideCrlUrls(TArray<string>.Create('http://crl.test/'));
  CheckTrue(Provider(TComplianceEnforcement.Relaxed).Revocation.TryGetCrlDistributionPoints(
    FLeaf, LUrls), 'the base answers');
  CheckEquals(1, System.Length(LUrls), 'with its URL');
  CheckEquals(1, FSpy.CrlUrlsCount, 'from the base');
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
