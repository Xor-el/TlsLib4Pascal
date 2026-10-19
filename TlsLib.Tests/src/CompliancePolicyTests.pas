{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Tests for the TlsLib.Compliance policy: construction under both enforcement modes,
/// the Admit checklist over configs built by the facade, and the Windows module attestation.
/// Fakes place the module and the backends on any host.</summary>
unit CompliancePolicyTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpICryptoBackendReport,
  TlpISigningKey,
  TlpSecretBuffer,
  TlpSession,
  TlpCertificateStrengthPolicy,
  TlpCipherSuiteCatalog,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpNamedGroups,
  TlpINegotiation,
  TlpINamedGroup,
  TlpTlsLibExceptions,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpICertificateTrust,
  TlpIKeyLog,
  TlpICertificateVerifierSource,
  TlpCertificateVerifierSource,
  TlpIEch,
  TlpEchClient,
  TlpISession,
  TlpInMemorySessionCache,
  TlpAntiReplay,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsConfigBuilder,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpIComplianceReport,
  TlpIModuleAttestation,
  TlpICompliancePolicy,
  TlpCompliancePolicy,
  TlpCompliancePresets,
  TlpComplianceTls,
  TlpOSModuleAttestation,
  TlpWindowsModuleAttestation,
  MockCompliance,
  MockKeyLog,
  MockCertificateVerifiers,
  TlsLibTestCertificates,
  TlsLibTestProviders,
  TlsLibTestBase;

type
  /// <summary>The helpers the policy suites share; it has no tests and is not registered.</summary>
  TCompliancePolicyTestCase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    function CreateCrypto: ICryptoProvider; override;
    function Identity: TModuleIdentity;
    // every operation in the OS module, signing left to the portable facet
    function SystemBase: ICryptoProvider;
    // as SystemBase, and an imported key is an OS-served P-256 key
    function SystemBaseWithKey: ICryptoProvider;
    function Attestation(AStatus: TModuleStatus): IModuleAttestation;
    function NewPolicy(const ARules: TComplianceRules; const ABase: ICryptoProvider;
      AStatus: TModuleStatus; AEnforcement: TComplianceEnforcement): ICompliancePolicy;
    function StrictPolicy: ICompliancePolicy;
    function RelaxedPolicy: ICompliancePolicy;
    function HasKind(const AFindings: TArray<TComplianceFinding>;
      AKind: TComplianceFindingKind): Boolean;
    function ReportHasKind(const AReport: IComplianceReport;
      AKind: TComplianceFindingKind): Boolean;
    function ClientBuilder(const APolicy: ICompliancePolicy): ITlsClientConfigBuilder;
    function ServerBuilder(const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
    function Credential(const ACrypto: ICryptoProvider): TTlsCredential;
    // whether Admit raised; AFindings holds what the exception carried, else the report's
    function ClientAdmit(const APolicy: ICompliancePolicy; const AConfig: ITlsClientConfig;
      out AFindings: TArray<TComplianceFinding>): Boolean;
    function ServerAdmit(const APolicy: ICompliancePolicy; const AConfig: ITlsServerConfig;
      out AFindings: TArray<TComplianceFinding>): Boolean;
  end;

  TTestCompliancePolicy = class(TCompliancePolicyTestCase)
  strict private
    // whether construction raised EComplianceUnmet; AFindings holds what it carried
    function Construct(const ARules: TComplianceRules; const ABase: ICryptoProvider;
      AStatus: TModuleStatus; AEnforcement: TComplianceEnforcement;
      out AFindings: TArray<TComplianceFinding>): Boolean;
    function ArgumentRefused(const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement): Boolean;
  published
    procedure TestStrictFakeValidatedSystemConstructs;
    procedure TestCnsa1NamesItsPreset;
    procedure TestStrictNotValidatedRaises;
    procedure TestRelaxedNotValidatedReports;
    procedure TestStrictUnknownStatusRaises;
    procedure TestStrictPortableBaseRaisesNoBackendReport;
    procedure TestRelaxedPortableBaseReportsNoBackendReport;
    procedure TestStrictPortableAeadRaisesAlgorithmOutsideModule;
    procedure TestRelaxedPortableAeadReports;
    procedure TestStrictHandBuiltEd25519Raises;
    procedure TestRelaxedHandBuiltEd25519NotCompliant;
    procedure TestEmptyVersionsRaiseArgument;
    procedure TestUnknownVersionRaisesArgument;
    procedure TestEmptySuitesRaiseArgument;
    procedure TestUnknownSuiteRaisesArgument;
    procedure TestSuiteAeadOutsideAeadsRaisesArgument;
    procedure TestVersionWithoutSuiteRaisesArgument;
    procedure TestEmptyGroupsRaiseArgument;
    procedure TestX25519GroupRaisesArgument;
    procedure TestHybridGroupRaisesArgument;
    procedure TestEmptySchemesRaiseArgument;
    procedure TestEmptyCurvesRaiseArgument;
    procedure TestUnusableRulesRaiseArgumentInRelaxedToo;
    procedure TestNilBaseCryptoRaisesArgument;
    procedure TestNilBasePkixRaisesArgument;
    procedure TestNilAttestationRaisesArgument;
    procedure TestKdfComposedDisclosed;
    procedure TestKdfRequireModuleRaisesStrictOnComposed;
    procedure TestRulesReturnsClone;
    procedure TestAccessorsReturnConstructionInputs;
    procedure TestPlatformFindingsInFixedOrder;
    procedure TestPolicyCryptoRefusesChaCha;
    procedure TestPolicyPkixKeepsBaseInspector;
    procedure TestOsAttestationMatchesPlatform;
  end;

  TTestComplianceAdmit = class(TCompliancePolicyTestCase)
  strict private
    function ForeignClient(const ACrypto: ICryptoProvider;
      const APkix: IPkixProvider): ITlsClientConfig;
    function Psk: TExternalPsk;
    function CredentialBuilder(const APolicy: ICompliancePolicy;
      const ACredential: TTlsCredential): ITlsServerConfigBuilder;
    function Ed25519Credential: TTlsCredential;
    function PortableP256Credential: TTlsCredential;
    function AcceptAll(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
    // early data needs resumption and a cache to build, so the violation is the only fault
    function EarlyDataClientBuilder(const APolicy: ICompliancePolicy;
      const AVerification: IServerVerificationBuilder): ITlsClientConfigBuilder;
  published
    procedure TestBaselineClientAdmitsStrict;
    procedure TestBaselineServerAdmitsStrict;
    procedure TestForeignCryptoRefused;
    procedure TestForeignPkixRefused;
    procedure TestFacadeConfigHoldsPolicyProviders;
    procedure TestVersionNotAllowedRefused;
    procedure TestCipherSuiteNotAllowedRefused;
    procedure TestNamedGroupNotAllowedRefused;
    procedure TestPreferredGroupNotAllowedRefused;
    procedure TestSignatureSchemeNotAllowedRefused;
    procedure TestEmsNotRequiredRefused;
    procedure TestEarlyDataClientRefused;
    procedure TestEarlyDataServerRefused;
    procedure TestEchGreaseRefused;
    procedure TestExternalPskRefused;
    procedure TestTls12PskRefused;
    procedure TestKeyLogRefused;
    procedure TestDangerousSkipRefused;
    procedure TestVerifyCallbackAllowed;
    procedure TestStrengthBelowRulesRefused;
    procedure TestEd25519CredentialKeyBelowRules;
    procedure TestEd25519CredentialSchemesNotAllowed;
    procedure TestEd25519CredentialOutsideModule;
    procedure TestPortableCredentialOutsideModuleStrict;
    procedure TestPortableCredentialRelaxedDoesNotRaise;
    procedure TestSystemCredentialAdmits;
    procedure TestWebPkiVerifierChainOutsideModule;
    procedure TestInstanceVerifierChainOutsideModule;
    procedure TestSystemVerifierSourceAdmitted;
    procedure TestStapleRequestedRefused;
    procedure TestGreaseAllowed;
    procedure TestMtlsServerWebPkiClientVerifierRefused;
    procedure TestMtlsServerFakeSystemSourceAdmits;
    procedure TestServerWithoutClientAuthNeedsNoClientVerifier;
    procedure TestRevocationOffDisclosed;
    procedure TestServerDisclosesSniCredentials;
    procedure TestEvaluateNeverRaises;
    procedure TestEvaluateRejectsNilConfig;
    procedure TestAdmitStrictRaisesPlatformFinding;
    procedure TestAdmitRelaxedKeepsPlatformFinding;
    procedure TestAdmitRelaxedRaisesConfigurationFinding;
    procedure TestRelaxedRaisedFindingsAreConfigurationOnly;
    procedure TestAdmitReturnsReportRelaxedWithPlatformFindings;
    procedure TestBuildClientAdmits;
    procedure TestBuildServerAdmits;
    procedure TestBuildClientRaisesOnViolation;
    procedure TestBuildServerRaisesOnViolation;
    procedure TestFacadeServerNarrowsKeySchemes;
    procedure TestFacadeClientRequiresEms;
    procedure TestFacadeServerRequiresEms;
    procedure TestFacadeEmsIsNotForcedOnTls13Only;
    procedure TestFacadeResumptionOnWithAes256;
    procedure TestFacadeResumptionOffWithoutAes256;
    procedure TestFacadeCipherSuitesHoldTheRules;
    procedure TestFacadeGroupsHoldTheRules;
    procedure TestFacadeSchemesHoldTheRules;
    procedure TestFacadeVersionsAreTheRules;
    procedure TestFacadeRequestsNoStaple;
    procedure TestFacadeClientRejectsNilPolicy;
    procedure TestFacadeClientRejectsNilVerification;
    procedure TestFacadeServerRejectsNilPolicy;
    procedure TestFacadeBuildRejectsNilPolicy;
  end;

{$IFDEF TLSLIB_MSWINDOWS}
  TTestWindowsModuleAttestation = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestReadsBuildAndModuleVersion;
    procedure TestTableValidated22621And20348;
    procedure TestTableNotValidated26100_22631_19045;
    procedure TestTableWindows10BuildsAreUnknownCertificate;
    procedure TestLookupMissesUnlistedBuild;
    procedure TestStatusFollowsTheTable;
    procedure TestDescribeNamesTheOutcome;
  end;

  TTestWindowsCompliance = class(TCompliancePolicyTestCase)
  published
    procedure TestStrictPassesOnValidatedBuild;
    procedure TestStrictRaisesNotValidatedOnOtherBuilds;
    procedure TestRelaxedReportsNotValidatedOnOtherBuilds;
    procedure TestOsVerifierClientKeepsStrengthFloors;
    procedure TestLiveClientKeepsStrengthFloors;
  end;
{$ENDIF TLSLIB_MSWINDOWS}

implementation

resourcestring
  SBranchNotValidated = 'build %d is not validated; the validated branch does not apply';
  SBranchValidated = 'build %d is validated; the not-validated branch does not apply';

{ TCompliancePolicyTestCase }

function TCompliancePolicyTestCase.CreateCrypto: ICryptoProvider;
begin
  Result := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
end;

function TCompliancePolicyTestCase.Identity: TModuleIdentity;
begin
  Result := Default(TModuleIdentity);
  Result.OsName := 'Windows';
  Result.OsVersion := '10.0.20348.1';
  Result.Certificate := '5410';
end;

function TCompliancePolicyTestCase.SystemBase: ICryptoProvider;
begin
  Result := TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil);
end;

function TCompliancePolicyTestCase.SystemBaseWithKey: ICryptoProvider;
var
  LKey: ISigningKey;
begin
  // the key must expose the public key of the leaf it signs for
  LKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256), Pkix.Certificates.Parse(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert')).PublicKeyInfo)
    as ISigningKey;
  Result := TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport,
    TFakeSigningCrypto.Create(LKey, True) as ISigningCrypto);
end;

function TCompliancePolicyTestCase.Attestation(AStatus: TModuleStatus): IModuleAttestation;
begin
  Result := TFakeModuleAttestation.Create(AStatus, Identity) as IModuleAttestation;
end;

function TCompliancePolicyTestCase.NewPolicy(const ARules: TComplianceRules;
  const ABase: ICryptoProvider; AStatus: TModuleStatus;
  AEnforcement: TComplianceEnforcement): ICompliancePolicy;
begin
  Result := TCompliancePolicy.Create(ARules, ABase, Pkix, Attestation(AStatus),
    AEnforcement) as ICompliancePolicy;
end;

function TCompliancePolicyTestCase.StrictPolicy: ICompliancePolicy;
begin
  Result := NewPolicy(TCompliancePresets.Fips140_3, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
end;

function TCompliancePolicyTestCase.RelaxedPolicy: ICompliancePolicy;
begin
  Result := NewPolicy(TCompliancePresets.Fips140_3, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
end;

function TCompliancePolicyTestCase.HasKind(const AFindings: TArray<TComplianceFinding>;
  AKind: TComplianceFindingKind): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to System.Length(AFindings) - 1 do
    if AFindings[LI].Kind = AKind then
      Result := True;
end;

function TCompliancePolicyTestCase.ReportHasKind(const AReport: IComplianceReport;
  AKind: TComplianceFindingKind): Boolean;
begin
  Result := HasKind(AReport.Findings, AKind);
end;

function TCompliancePolicyTestCase.ClientBuilder(
  const APolicy: ICompliancePolicy): ITlsClientConfigBuilder;
begin
  Result := TComplianceTls.Client(APolicy, TServerVerification.VerifierSource(
    TFakeSystemVerifierSource.Create as IServerCertificateVerifierSource));
end;

function TCompliancePolicyTestCase.ServerBuilder(
  const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
begin
  Result := TComplianceTls.Server(APolicy, Credential(APolicy.Crypto));
end;

function TCompliancePolicyTestCase.Credential(const ACrypto: ICryptoProvider): TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'));
  Result.PrivateKey := ACrypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key'), nil);
end;

function TCompliancePolicyTestCase.ClientAdmit(const APolicy: ICompliancePolicy;
  const AConfig: ITlsClientConfig; out AFindings: TArray<TComplianceFinding>): Boolean;
begin
  Result := False;
  AFindings := nil;
  try
    AFindings := APolicy.Admit(AConfig).Findings;
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      Result := True;
      AFindings := E.Findings;
    end;
  end;
end;

function TCompliancePolicyTestCase.ServerAdmit(const APolicy: ICompliancePolicy;
  const AConfig: ITlsServerConfig; out AFindings: TArray<TComplianceFinding>): Boolean;
begin
  Result := False;
  AFindings := nil;
  try
    AFindings := APolicy.Admit(AConfig).Findings;
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      Result := True;
      AFindings := E.Findings;
    end;
  end;
end;

{ TTestCompliancePolicy }

function TTestCompliancePolicy.Construct(const ARules: TComplianceRules;
  const ABase: ICryptoProvider; AStatus: TModuleStatus; AEnforcement: TComplianceEnforcement;
  out AFindings: TArray<TComplianceFinding>): Boolean;
begin
  Result := False;
  AFindings := nil;
  try
    NewPolicy(ARules, ABase, AStatus, AEnforcement);
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      Result := True;
      AFindings := E.Findings;
    end;
  end;
end;

function TTestCompliancePolicy.ArgumentRefused(const ARules: TComplianceRules;
  AEnforcement: TComplianceEnforcement): Boolean;
begin
  Result := False;
  try
    NewPolicy(ARules, SystemBase, TModuleStatus.Validated, AEnforcement);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

procedure TTestCompliancePolicy.TestStrictFakeValidatedSystemConstructs;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LPolicy.PlatformReport.Verdict),
    'the platform is compliant');
  CheckEquals('Fips140_3', LPolicy.PlatformReport.Preset, 'the rules name their preset');
end;

procedure TTestCompliancePolicy.TestCnsa1NamesItsPreset;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Cnsa1, SystemBase, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  CheckEquals('Cnsa1', LPolicy.PlatformReport.Preset, 'the tightest preset');
end;

procedure TTestCompliancePolicy.TestStrictNotValidatedRaises;
var
  LFindings: TArray<TComplianceFinding>;
begin
  CheckTrue(Construct(TCompliancePresets.Fips140_3, SystemBase, TModuleStatus.NotValidated,
    TComplianceEnforcement.Strict, LFindings), 'strict refuses');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ModuleNotValidated), 'names the module');
end;

procedure TTestCompliancePolicy.TestRelaxedNotValidatedReports;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, SystemBase, TModuleStatus.NotValidated,
    TComplianceEnforcement.Relaxed);
  CheckTrue(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.ModuleNotValidated),
    'the finding is reported');
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LPolicy.PlatformReport.Verdict),
    'and is never silent');
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(LPolicy.PlatformReport.ModuleStatus),
    'the status is carried');
end;

procedure TTestCompliancePolicy.TestStrictUnknownStatusRaises;
var
  LFindings: TArray<TComplianceFinding>;
begin
  CheckTrue(Construct(TCompliancePresets.Fips140_3, SystemBase, TModuleStatus.Unknown,
    TComplianceEnforcement.Strict, LFindings), 'an unknown module is not a validated one');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ModuleNotValidated), 'names the module');
end;

procedure TTestCompliancePolicy.TestStrictPortableBaseRaisesNoBackendReport;
var
  LFindings: TArray<TComplianceFinding>;
begin
  CheckTrue(Construct(TCompliancePresets.Fips140_3, Crypto, TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'strict refuses a wholly portable base');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.NoBackendReport), 'names the missing report');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.AlgorithmOutsideModule),
    'and counts every algorithm as outside');
end;

procedure TTestCompliancePolicy.TestRelaxedPortableBaseReportsNoBackendReport;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, Crypto, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  CheckTrue(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.NoBackendReport),
    'reported');
end;

procedure TTestCompliancePolicy.TestStrictPortableAeadRaisesAlgorithmOutsideModule;
var
  LBase: ICryptoProvider;
  LFindings: TArray<TComplianceFinding>;
begin
  LBase := TComplianceFakes.FakeSystemBase(TFakeBackendReport.Create(
    [TAeadAlgorithm.AES_128_GCM]) as ICryptoBackendReport, nil);
  CheckTrue(Construct(TCompliancePresets.Fips140_3, LBase, TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'strict refuses');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.AlgorithmOutsideModule),
    'the portable AEAD is named');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.NoBackendReport),
    'the base does report');
end;

procedure TTestCompliancePolicy.TestRelaxedPortableAeadReports;
var
  LBase: ICryptoProvider;
  LPolicy: ICompliancePolicy;
begin
  LBase := TComplianceFakes.FakeSystemBase(TFakeBackendReport.Create(
    [TAeadAlgorithm.AES_128_GCM]) as ICryptoBackendReport, nil);
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, LBase, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  CheckTrue(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.AlgorithmOutsideModule),
    'reported');
end;

procedure TTestCompliancePolicy.TestStrictHandBuiltEd25519Raises;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  Include(LRules.SignatureSchemes, TSignatureScheme.ED25519);
  CheckTrue(Construct(LRules, SystemBase, TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'strict refuses rules outside every preset');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.RulesOutsidePresets), 'names the rules');
end;

procedure TTestCompliancePolicy.TestRelaxedHandBuiltEd25519NotCompliant;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
begin
  LRules := TCompliancePresets.Fips140_3;
  Include(LRules.SignatureSchemes, TSignatureScheme.ED25519);
  LPolicy := NewPolicy(LRules, SystemBase, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LPolicy.PlatformReport.Verdict),
    'never compliant');
  CheckEquals('', LPolicy.PlatformReport.Preset, 'no preset holds it');
  CheckTrue(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.RulesOutsidePresets),
    'reported');
end;

procedure TTestCompliancePolicy.TestEmptyVersionsRaiseArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := nil;
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'no version');
end;

procedure TTestCompliancePolicy.TestUnknownVersionRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls11);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'TLS 1.1 is not offerable');
end;

procedure TTestCompliancePolicy.TestEmptySuitesRaiseArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.CipherSuites := nil;
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'no suite');
end;

procedure TTestCompliancePolicy.TestUnknownSuiteRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256, $FFFF);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'a suite the catalog lacks');
end;

procedure TTestCompliancePolicy.TestSuiteAeadOutsideAeadsRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Aeads := [TAeadAlgorithm.AES_256_GCM];
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict),
    'an AES-128 suite with no AES-128 AEAD');
end;

procedure TTestCompliancePolicy.TestVersionWithoutSuiteRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict),
    'TLS 1.2 is offered with only a TLS 1.3 suite');
end;

procedure TTestCompliancePolicy.TestEmptyGroupsRaiseArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.NamedGroups := nil;
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'no group');
end;

procedure TTestCompliancePolicy.TestX25519GroupRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'only NIST groups');
end;

procedure TTestCompliancePolicy.TestHybridGroupRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.SecP256r1MlKem768,
    TNamedGroupCatalog.Secp256r1);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'no hybrid group');
end;

procedure TTestCompliancePolicy.TestEmptySchemesRaiseArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [];
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'no scheme');
end;

procedure TTestCompliancePolicy.TestEmptyCurvesRaiseArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AllowedEcCurves := nil;
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict),
    'an empty list would allow any curve');
end;

procedure TTestCompliancePolicy.TestUnusableRulesRaiseArgumentInRelaxedToo;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.CipherSuites := nil;
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Relaxed), 'relaxed does not excuse it');
end;

procedure TTestCompliancePolicy.TestNilBaseCryptoRaisesArgument;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TCompliancePolicy.Create(TCompliancePresets.Fips140_3, nil, Pkix,
      Attestation(TModuleStatus.Validated), TComplianceEnforcement.Relaxed);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil crypto');
end;

procedure TTestCompliancePolicy.TestNilBasePkixRaisesArgument;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TCompliancePolicy.Create(TCompliancePresets.Fips140_3, SystemBase, nil,
      Attestation(TModuleStatus.Validated), TComplianceEnforcement.Relaxed);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil PKIX');
end;

procedure TTestCompliancePolicy.TestNilAttestationRaisesArgument;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TCompliancePolicy.Create(TCompliancePresets.Fips140_3, SystemBase, Pkix, nil,
      TComplianceEnforcement.Relaxed);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil attestation');
end;

procedure TTestCompliancePolicy.TestKdfComposedDisclosed;
var
  LDisclosures: TArray<string>;
begin
  LDisclosures := StrictPolicy.PlatformReport.Disclosures;
  CheckEquals(1, System.Length(LDisclosures), 'one disclosure, however many derivations');
  CheckTrue(Pos('composed', LDisclosures[0]) > 0, 'it names the composed derivation');
end;

procedure TTestCompliancePolicy.TestKdfRequireModuleRaisesStrictOnComposed;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Kdf := TKdfRule.RequireModule;
  CheckTrue(Construct(LRules, SystemBase, TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'strict refuses a composed derivation');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.KdfOutsideModule), 'names it');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.AlgorithmOutsideModule),
    'the primitives themselves are in the module');
end;

procedure TTestCompliancePolicy.TestRulesReturnsClone;
var
  LPolicy: ICompliancePolicy;
  LRules: TComplianceRules;
begin
  LPolicy := StrictPolicy;
  LRules := LPolicy.Rules;
  LRules.Versions[0] := TlsWireVersionTls12;
  LRules.Strength.AllowedEcCurves[0] := TNamedGroupCatalog.Secp521r1;
  CheckEquals(TlsWireVersionTls13, LPolicy.Rules.Versions[0], 'versions are not shared');
  CheckEquals(TNamedGroupCatalog.Secp256r1, LPolicy.Rules.Strength.AllowedEcCurves[0],
    'curves are not shared');
end;

procedure TTestCompliancePolicy.TestAccessorsReturnConstructionInputs;
var
  LAttestation: IModuleAttestation;
  LPolicy: ICompliancePolicy;
begin
  LAttestation := Attestation(TModuleStatus.Validated);
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3, SystemBase, Pkix,
    LAttestation, TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  CheckTrue(LPolicy.Attestation = LAttestation, 'attestation');
  CheckEquals(Ord(TComplianceEnforcement.Relaxed), Ord(LPolicy.Enforcement), 'enforcement');
  CheckTrue(LPolicy.Crypto <> nil, 'crypto');
  CheckTrue(LPolicy.Pkix <> nil, 'pkix');
  CheckTrue(LPolicy.Crypto = LPolicy.Crypto, 'the providers are stable');
end;

procedure TTestCompliancePolicy.TestPlatformFindingsInFixedOrder;
var
  LBase: ICryptoProvider;
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LBase := TComplianceFakes.FakeSystemBase(TFakeBackendReport.Create(
    [TAeadAlgorithm.AES_128_GCM]) as ICryptoBackendReport, nil);
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, LBase, TModuleStatus.NotValidated,
    TComplianceEnforcement.Relaxed);
  LFindings := LPolicy.PlatformReport.Findings;
  CheckEquals(2, System.Length(LFindings), 'the AEAD and the module');
  CheckEquals(Ord(TComplianceFindingKind.AlgorithmOutsideModule), Ord(LFindings[0].Kind),
    'backends first');
  CheckEquals(Ord(TComplianceFindingKind.ModuleNotValidated), Ord(LFindings[1].Kind),
    'the module last');
end;

procedure TTestCompliancePolicy.TestPolicyCryptoRefusesChaCha;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    RelaxedPolicy.Crypto.Primitives.CreateAead(TAeadAlgorithm.CHACHA20_POLY1305);
  except
    on EComplianceRefusedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the policy provider carries the rules');
end;

procedure TTestCompliancePolicy.TestPolicyPkixKeepsBaseInspector;
begin
  CheckTrue(StrictPolicy.Pkix.Certificates = Pkix.Certificates,
    'parsing stays with the base');
end;

procedure TTestCompliancePolicy.TestOsAttestationMatchesPlatform;
var
  LAttestation: IModuleAttestation;
begin
  LAttestation := TOSModuleAttestation.Current;
  CheckTrue(LAttestation <> nil, 'never nil');
{$IFDEF TLSLIB_MSWINDOWS}
  CheckEquals('Windows', LAttestation.Identity.OsName, 'the Windows arm answers');
{$ELSE}
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(LAttestation.Status(TModuleStandard.Fips140_3)),
    'no module table ships here');
  CheckEquals('', LAttestation.Identity.OsName, 'and nothing is attested');
{$ENDIF TLSLIB_MSWINDOWS}
end;

{ TTestComplianceAdmit }

function TTestComplianceAdmit.ForeignClient(const ACrypto: ICryptoProvider;
  const APkix: IPkixProvider): ITlsClientConfig;
var
  LProfile: TTlsConfigProfile;
begin
  LProfile := TTlsConfigProfile.Default;
  LProfile.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LProfile.SignatureSchemes := TSignatureSchemeRegistry.CreateDefault;
  LProfile.NamedGroups := TNamedGroups.CreateDefaultRegistry(Crypto);
  LProfile.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
  LProfile.PreferredGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  Result := TTlsConfigBuilder.CreateFromProfile(ACrypto, APkix, LProfile).Client
    .WithServerVerification(TServerVerification.VerifierSource(
    TFakeSystemVerifierSource.Create as IServerCertificateVerifierSource).Build).Build;
end;

function TTestComplianceAdmit.Psk: TExternalPsk;
begin
  Result.Identity := TBytes.Create($61, $62);
  Result.Secret := TSecretBuffer.From(TBytes.Create($00, $11, $22, $33, $44, $55, $66, $77,
    $88, $99, $AA, $BB, $CC, $DD, $EE, $FF));
  Result.Context := nil;
  Result.Hash := THashAlgorithm.SHA_256;
end;

function TTestComplianceAdmit.CredentialBuilder(const APolicy: ICompliancePolicy;
  const ACredential: TTlsCredential): ITlsServerConfigBuilder;
begin
  Result := TComplianceTls.Server(APolicy, ACredential);
end;

function TTestComplianceAdmit.Ed25519Credential: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/Ed25519Chain.txt', 'leaf_cert'));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/Ed25519Chain.txt', 'leaf_key'), nil);
end;

function TTestComplianceAdmit.PortableP256Credential: TTlsCredential;
begin
  Result := Credential(Crypto);
end;

function TTestComplianceAdmit.EarlyDataClientBuilder(const APolicy: ICompliancePolicy;
  const AVerification: IServerVerificationBuilder): ITlsClientConfigBuilder;
begin
  Result := TComplianceTls.Client(APolicy, AVerification).WithSessionCache(
    TInMemorySessionCache.Create as ISessionCache);
  Result.Tls13.WithEarlyData(True);
end;

function TTestComplianceAdmit.AcceptAll(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := True;
end;

procedure TTestComplianceAdmit.TestBaselineClientAdmitsStrict;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Admit(ClientBuilder(LPolicy).Build);
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'compliant');
  CheckEquals(0, System.Length(LReport.Findings), 'no finding');
end;

procedure TTestComplianceAdmit.TestBaselineServerAdmitsStrict;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Admit(ServerBuilder(LPolicy).Build);
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'compliant');
  CheckEquals(0, System.Length(LReport.Findings), 'no finding');
end;

procedure TTestComplianceAdmit.TestForeignCryptoRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ForeignClient(Crypto, LPolicy.Pkix), LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ForeignCryptoProvider), 'names the crypto');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.ForeignPkixProvider),
    'the PKIX provider is the policy one');
end;

procedure TTestComplianceAdmit.TestForeignPkixRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ForeignClient(LPolicy.Crypto, Pkix), LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ForeignPkixProvider), 'names the PKIX');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.ForeignCryptoProvider),
    'the crypto provider is the policy one');
end;

procedure TTestComplianceAdmit.TestFacadeConfigHoldsPolicyProviders;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsClientConfig;
begin
  LPolicy := StrictPolicy;
  LConfig := ClientBuilder(LPolicy).Build;
  CheckTrue(LConfig.Crypto = LPolicy.Crypto, 'crypto');
  CheckTrue(LConfig.Pkix = LPolicy.Pkix, 'pkix');
end;

procedure TTestComplianceAdmit.TestVersionNotAllowedRefused;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)).Build, LFindings),
    'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.VersionNotAllowed), 'names TLS 1.2');
end;

procedure TTestComplianceAdmit.TestCipherSuiteNotAllowedRefused;
var
  LPolicy: ICompliancePolicy;
  LRules: TComplianceRules;
  LBuilder: ICipherSuiteRegistryBuilder;
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LPolicy := NewPolicy(TCompliancePresets.Cnsa1, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LBuilder := TCipherSuiteRegistryBuilder.Create as ICipherSuiteRegistryBuilder;
  LRules := LPolicy.Rules;
  for LI := 0 to System.Length(LRules.CipherSuites) - 1 do
  begin
    CheckTrue(TCipherSuiteCatalog.TryGet(LRules.CipherSuites[LI], LSuite), 'catalog');
    LBuilder.Add(LSuite);
  end;
  CheckTrue(TCipherSuiteCatalog.TryGet(TCipherSuites13.Aes128GcmSha256, LSuite), 'catalog');
  LBuilder.Add(LSuite);
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithCipherSuites(LBuilder.Build).Build,
    LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names AES-128');
end;

procedure TTestComplianceAdmit.TestNamedGroupNotAllowedRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(
    TNamedGroups.CreateDefaultRegistry(Crypto)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.NamedGroupNotAllowed), 'names X25519');
end;

procedure TTestComplianceAdmit.TestPreferredGroupNotAllowedRefused;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LBuilder: INamedGroupRegistryBuilder;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  // the registry is complete, so only the preference list can name a group outside the rules
  LBuilder := TNamedGroups.CreateDefaultRegistry(Crypto).ToBuilder;
  LBuilder.Prune(TNamedGroupCatalog.X25519);
  LBuilder.Prune(TNamedGroupCatalog.X25519MlKem768);
  LBuilder.Prune(TNamedGroupCatalog.SecP256r1MlKem768);
  LBuilder.Prune(TNamedGroupCatalog.MlKem768);
  LBuilder.Prune(TNamedGroupCatalog.Secp384r1);
  LBuilder.Prune(TNamedGroupCatalog.Secp521r1);
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(LBuilder.Build)
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.NamedGroupNotAllowed),
    'names the preferred P-384');
end;

procedure TTestComplianceAdmit.TestSignatureSchemeNotAllowedRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithSignatureSchemes(
    TSignatureSchemeRegistry.CreateDefault).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.SignatureSchemeNotAllowed),
    'names Ed25519');
end;

procedure TTestComplianceAdmit.TestEmsNotRequiredRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).Tls12
    .WithExtendedMasterSecret(False).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ExtendedMasterSecretNotRequired),
    'names extended master secret');
end;

procedure TTestComplianceAdmit.TestEarlyDataClientRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, EarlyDataClientBuilder(LPolicy, TServerVerification
    .VerifierSource(TFakeSystemVerifierSource.Create as IServerCertificateVerifierSource))
    .Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.EarlyDataEnabled), 'names early data');
end;

procedure TTestComplianceAdmit.TestEarlyDataServerRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ServerAdmit(LPolicy, ServerBuilder(LPolicy).Tls13.WithEarlyData(1024)
    .WithAntiReplay(TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy).Build,
    LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.EarlyDataEnabled), 'names early data');
end;

procedure TTestComplianceAdmit.TestEchGreaseRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).Tls13.WithEch(TEchClientModes.Grease)
    .Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.EchConfigured), 'GREASE ECH counts');
end;

procedure TTestComplianceAdmit.TestExternalPskRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(Psk)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ExternalPskConfigured), 'names the PSK');
end;

procedure TTestComplianceAdmit.TestTls12PskRefused;
var
  LPolicy: ICompliancePolicy;
  LPsk: TTls12Psk;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LPsk.Identity := TBytes.Create($61, $62);
  LPsk.Secret := TSecretBuffer.From(TBytes.Create($00, $11, $22, $33, $44, $55, $66, $77));
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).Tls12.WithPreSharedKey(LPsk).Build,
    LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.Tls12PskConfigured), 'names the PSK');
end;

procedure TTestComplianceAdmit.TestKeyLogRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithDangerousKeyLog(
    TMockKeyLog.Create as IKeyLog).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.KeyLogConfigured), 'names the key log');
end;

procedure TTestComplianceAdmit.TestDangerousSkipRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.DangerousSkip).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.DangerousTrustConfigured),
    'names the skip');
end;

procedure TTestComplianceAdmit.TestVerifyCallbackAllowed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithCertificateVerifyCallback(
    AcceptAll).Build, LFindings), 'a callback can only add rejections');
end;

procedure TTestComplianceAdmit.TestStrengthBelowRulesRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.VerifierSource(TFakeSystemVerifierSource.Create
    as IServerCertificateVerifierSource).WithMinimumStrength(
    TCertificateStrengthPolicy.Defaults).Build).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.StrengthBelowRules), 'names the floors');
end;

procedure TTestComplianceAdmit.TestEd25519CredentialKeyBelowRules;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ServerAdmit(LPolicy, CredentialBuilder(LPolicy, Ed25519Credential).Build,
    LFindings), 'a configuration finding refuses even in relaxed mode');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules), 'names the key');
end;

procedure TTestComplianceAdmit.TestEd25519CredentialSchemesNotAllowed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ServerAdmit(LPolicy, CredentialBuilder(LPolicy, Ed25519Credential).Build,
    LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CredentialSchemesNotAllowed),
    'names the schemes');
end;

procedure TTestComplianceAdmit.TestEd25519CredentialOutsideModule;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
  LReport := LPolicy.Evaluate(CredentialBuilder(LPolicy, Ed25519Credential).Build);
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyOutsideModule),
    'a portable key is outside the module');
end;

procedure TTestComplianceAdmit.TestPortableCredentialOutsideModuleStrict;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
  LFindings: TArray<TComplianceFinding>;
begin
  // a relaxed policy imports the portable key; the strict one then judges the config
  LConfig := CredentialBuilder(RelaxedPolicy, PortableP256Credential).Build;
  LPolicy := StrictPolicy;
  CheckTrue(ServerAdmit(LPolicy, LConfig, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CredentialKeyOutsideModule),
    'names the key');
end;

procedure TTestComplianceAdmit.TestPortableCredentialRelaxedDoesNotRaise;
var
  LPolicy: ICompliancePolicy;
  LBase: ICryptoProvider;
  LConfig: ITlsServerConfig;
  LFindings: TArray<TComplianceFinding>;
begin
  LBase := TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil);
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, LBase, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  LConfig := CredentialBuilder(LPolicy, Credential(LPolicy.Crypto)).Build;
  CheckFalse(ServerAdmit(LPolicy, LConfig, LFindings), 'a platform finding does not raise');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CredentialKeyOutsideModule),
    'but it is reported');
end;

procedure TTestComplianceAdmit.TestSystemCredentialAdmits;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ServerAdmit(LPolicy, ServerBuilder(LPolicy).Build, LFindings), 'admitted');
  CheckEquals(0, System.Length(LFindings), 'with no finding');
end;

procedure TTestComplianceAdmit.TestWebPkiVerifierChainOutsideModule;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, TComplianceTls.Client(LPolicy, TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the portable chain check is outside the module');
end;

procedure TTestComplianceAdmit.TestInstanceVerifierChainOutsideModule;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.Custom(TFixedVerdictVerifier.CreateAccepting(False)
    as IServerCertificateVerifier)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'where a custom verifier runs cannot be seen');
end;

procedure TTestComplianceAdmit.TestSystemVerifierSourceAdmitted;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(ClientBuilder(LPolicy).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'an OS-marked source is in the module');
end;

procedure TTestComplianceAdmit.TestStapleRequestedRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithOcspStaplingRequest(True).Build,
    LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.StapleVerifiedOutsideModule),
    'names the staple');
end;

procedure TTestComplianceAdmit.TestGreaseAllowed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithGrease(True).Build, LFindings),
    'GREASE values are never negotiated');
end;

procedure TTestComplianceAdmit.TestMtlsServerWebPkiClientVerifierRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore).Build).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the client chain check is portable');
end;

procedure TTestComplianceAdmit.TestMtlsServerFakeSystemSourceAdmits;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.VerifierSource(
    TFakeSystemVerifierSource.Create as IClientCertificateVerifierSource,
    TTlsLibTestCertificates.EcP256RootStore).WithMinimumStrength(LPolicy.Rules.Strength)
    .Build).Build, LFindings), 'admitted');
end;

procedure TTestComplianceAdmit.TestServerWithoutClientAuthNeedsNoClientVerifier;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithPeerAuth(TClientAuthMode.None)
    .Build, LFindings), 'no client chain is checked, so the built-in source is not a finding');
end;

procedure TTestComplianceAdmit.TestRevocationOffDisclosed;
var
  LPolicy: ICompliancePolicy;
  LBase, LOff: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LBase := LPolicy.Evaluate(ClientBuilder(LPolicy).Build);
  LOff := LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.VerifierSource(TFakeSystemVerifierSource.Create
    as IServerCertificateVerifierSource).WithMinimumStrength(LPolicy.Rules.Strength)
    .WithRevocation(TRevocationPosture.Off).Build).Build);
  CheckEquals(System.Length(LBase.Disclosures) + 1, System.Length(LOff.Disclosures),
    'revocation off adds one disclosure');
  CheckEquals(0, System.Length(LOff.Findings), 'and no finding');
end;

procedure TTestComplianceAdmit.TestServerDisclosesSniCredentials;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(ServerBuilder(LPolicy).Build);
  CheckEquals(System.Length(LPolicy.PlatformReport.Disclosures) + 1,
    System.Length(LReport.Disclosures), 'credentials chosen by name are not size-checked');
end;

procedure TTestComplianceAdmit.TestEvaluateNeverRaises;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.DangerousSkip).Build);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict), 'reported, not raised');
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.DangerousTrustConfigured), 'the finding');
end;

procedure TTestComplianceAdmit.TestEvaluateRejectsNilConfig;
var
  LRaised: Boolean;
  LNone: ITlsClientConfig;
begin
  LRaised := False;
  LNone := nil;
  try
    StrictPolicy.Evaluate(LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil config');
end;

procedure TTestComplianceAdmit.TestAdmitStrictRaisesPlatformFinding;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, TComplianceTls.Client(LPolicy, TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore)).Build, LFindings), 'strict raises');
end;

procedure TTestComplianceAdmit.TestAdmitRelaxedKeepsPlatformFinding;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckFalse(ClientAdmit(LPolicy, TComplianceTls.Client(LPolicy, TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore)).Build, LFindings), 'relaxed does not raise');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'and is never silent');
end;

procedure TTestComplianceAdmit.TestAdmitRelaxedRaisesConfigurationFinding;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ClientAdmit(LPolicy, EarlyDataClientBuilder(LPolicy, TServerVerification
    .VerifierSource(TFakeSystemVerifierSource.Create as IServerCertificateVerifierSource))
    .Build, LFindings), 'a configuration finding is never relaxed');
end;

procedure TTestComplianceAdmit.TestRelaxedRaisedFindingsAreConfigurationOnly;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ClientAdmit(LPolicy, EarlyDataClientBuilder(LPolicy, TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore)).Build, LFindings), 'raised');
  CheckTrue(System.Length(LFindings) > 0, 'carries findings');
  for LI := 0 to System.Length(LFindings) - 1 do
    CheckEquals(Ord(TComplianceFindingCategory.Configuration), Ord(LFindings[LI].Category),
      'only configuration findings: ' + LFindings[LI].Describe);
end;

procedure TTestComplianceAdmit.TestAdmitReturnsReportRelaxedWithPlatformFindings;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, Crypto, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  LReport := LPolicy.Admit(ClientBuilder(LPolicy).Build);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict), 'never compliant');
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.NoBackendReport),
    'it carries the platform findings');
end;

procedure TTestComplianceAdmit.TestBuildClientAdmits;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(TComplianceTls.BuildClient(LPolicy, ClientBuilder(LPolicy)) <> nil, 'built');
end;

procedure TTestComplianceAdmit.TestBuildServerAdmits;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(TComplianceTls.BuildServer(LPolicy, ServerBuilder(LPolicy)) <> nil, 'built');
end;

procedure TTestComplianceAdmit.TestBuildClientRaisesOnViolation;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsClientConfigBuilder;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LBuilder := EarlyDataClientBuilder(LPolicy, TServerVerification.VerifierSource(
    TFakeSystemVerifierSource.Create as IServerCertificateVerifierSource));
  LRaised := False;
  try
    TComplianceTls.BuildClient(LPolicy, LBuilder);
  except
    on EComplianceUnmetTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'refused at build');
end;

procedure TTestComplianceAdmit.TestBuildServerRaisesOnViolation;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LBuilder := ServerBuilder(LPolicy);
  LBuilder.Tls13.WithEarlyData(1024).WithAntiReplay(
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  LRaised := False;
  try
    TComplianceTls.BuildServer(LPolicy, LBuilder);
  except
    on EComplianceUnmetTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'refused at build');
end;

procedure TTestComplianceAdmit.TestFacadeServerNarrowsKeySchemes;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LSchemes: TArray<TSignatureScheme>;
begin
  LPolicy := StrictPolicy;
  LCredential := Credential(LPolicy.Crypto);
  LCredential.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    LCredential.PrivateKey.PublicKeyInfo) as ISigningKey;
  LSchemes := TComplianceTls.Server(LPolicy, LCredential).Build.Credential.PrivateKey
    .CapableSchemes;
  CheckEquals(1, System.Length(LSchemes), 'only the allowed scheme is left');
  CheckEquals(Ord(TSignatureScheme.ECDSA_SECP256R1_SHA256), Ord(LSchemes[0]), 'which one');
end;

procedure TTestComplianceAdmit.TestFacadeClientRequiresEms;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientBuilder(LPolicy).Build.RequireExtendedMasterSecret, 'client');
end;

procedure TTestComplianceAdmit.TestFacadeServerRequiresEms;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ServerBuilder(LPolicy).Build.RequireExtendedMasterSecret, 'server');
end;

procedure TTestComplianceAdmit.TestFacadeEmsIsNotForcedOnTls13Only;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  CheckFalse(ClientBuilder(LPolicy).Build.RequireExtendedMasterSecret,
    'the TLS 1.2 facet is not touched where TLS 1.2 is not offered');
end;

procedure TTestComplianceAdmit.TestFacadeResumptionOnWithAes256;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientBuilder(LPolicy).Build.Resumption, 'tickets are sealed with AES-256-GCM');
end;

procedure TTestComplianceAdmit.TestFacadeResumptionOffWithoutAes256;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Aeads := [TAeadAlgorithm.AES_128_GCM];
  LRules.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256, TCipherSuites12.EcdheRsaAes128GcmSha256);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  CheckFalse(ClientBuilder(LPolicy).Build.Resumption, 'tickets could not be sealed');
end;

procedure TTestComplianceAdmit.TestFacadeCipherSuitesHoldTheRules;
var
  LPolicy: ICompliancePolicy;
  LSuites: TArray<TTlsCipherSuite>;
  LI: Int32;
begin
  LPolicy := NewPolicy(TCompliancePresets.Cnsa1, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LSuites := ClientBuilder(LPolicy).Build.CipherSuites.Items;
  CheckEquals(3, System.Length(LSuites), 'count');
  for LI := 0 to 2 do
    CheckEquals(LPolicy.Rules.CipherSuites[LI], LSuites[LI].Common.Code,
      'rule order, item ' + IntToStr(LI));
end;

procedure TTestComplianceAdmit.TestFacadeGroupsHoldTheRules;
var
  LPolicy: ICompliancePolicy;
  LGroups: TArray<INamedGroup>;
  LConfig: ITlsClientConfig;
begin
  LPolicy := StrictPolicy;
  LConfig := ClientBuilder(LPolicy).Build;
  LGroups := LConfig.NamedGroups.Items;
  CheckEquals(3, System.Length(LGroups), 'count');
  CheckEquals(TNamedGroupCatalog.Secp256r1, LGroups[0].Code, 'first');
  CheckEquals(TNamedGroupCatalog.Secp384r1, LGroups[1].Code, 'second');
  CheckEquals(TNamedGroupCatalog.Secp521r1, LGroups[2].Code, 'third');
  CheckEquals(3, System.Length(LConfig.PreferredGroups), 'the preference is the rules');
end;

procedure TTestComplianceAdmit.TestFacadeSchemesHoldTheRules;
var
  LPolicy: ICompliancePolicy;
  LSchemes: TArray<TSignatureScheme>;
  LI: Int32;
begin
  LPolicy := NewPolicy(TCompliancePresets.Cnsa1, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LSchemes := ClientBuilder(LPolicy).Build.SignatureSchemes.Items;
  CheckEquals(3, System.Length(LSchemes), 'count');
  for LI := 0 to 2 do
    CheckTrue(LSchemes[LI] in LPolicy.Rules.SignatureSchemes, 'allowed ' + IntToStr(LI));
end;

procedure TTestComplianceAdmit.TestFacadeVersionsAreTheRules;
var
  LPolicy: ICompliancePolicy;
  LVersions: TArray<UInt16>;
begin
  LPolicy := StrictPolicy;
  LVersions := ClientBuilder(LPolicy).Build.SupportedVersions;
  CheckEquals(2, System.Length(LVersions), 'count');
  CheckEquals(TlsWireVersionTls13, LVersions[0], 'first');
  CheckEquals(TlsWireVersionTls12, LVersions[1], 'second');
end;

procedure TTestComplianceAdmit.TestFacadeRequestsNoStaple;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ClientBuilder(LPolicy).Build.RequestOcspStapling, 'the staple check is not in-module');
end;

procedure TTestComplianceAdmit.TestFacadeClientRejectsNilPolicy;
var
  LRaised: Boolean;
  LNone: ICompliancePolicy;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.Client(LNone, TServerVerification.VerifierSource(
      TFakeSystemVerifierSource.Create as IServerCertificateVerifierSource));
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil policy');
end;

procedure TTestComplianceAdmit.TestFacadeClientRejectsNilVerification;
var
  LRaised: Boolean;
  LNone: IServerVerificationBuilder;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.Client(StrictPolicy, LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil verification');
end;

procedure TTestComplianceAdmit.TestFacadeServerRejectsNilPolicy;
var
  LRaised: Boolean;
  LNone: ICompliancePolicy;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.Server(LNone, Credential(Crypto));
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil policy');
end;

procedure TTestComplianceAdmit.TestFacadeBuildRejectsNilPolicy;
var
  LRaised: Boolean;
  LNone: ICompliancePolicy;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.BuildClient(LNone, ClientBuilder(StrictPolicy));
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil policy');
end;

{$IFDEF TLSLIB_MSWINDOWS}

{ TTestWindowsModuleAttestation }

procedure TTestWindowsModuleAttestation.TestReadsBuildAndModuleVersion;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := TWindowsModuleAttestation.Create.Identity;
  CheckTrue(LIdentity.OsBuild > 0, 'the build');
  CheckEquals(1, Pos('10.0.', LIdentity.OsVersion), 'the version starts with 10.0.');
  CheckTrue(LIdentity.ModuleFileVersion <> '', 'the module file version');
  CheckEquals('bcryptprimitives.dll', LIdentity.ModuleName, 'the module');
  CheckTrue(LIdentity.LegacyFipsPolicy <> TLegacyFipsPolicy.Unknown, 'the legacy flag');
end;

procedure TTestWindowsModuleAttestation.TestTableValidated22621And20348;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckTrue(TWindowsModuleAttestation.Lookup(22621, LEntry), '22621 listed');
  CheckTrue(LEntry.Fips140_3, '22621 validated');
  CheckEquals('5410', LEntry.Certificate, '22621 certificate');
  CheckTrue(TWindowsModuleAttestation.Lookup(20348, LEntry), '20348 listed');
  CheckTrue(LEntry.Fips140_3, '20348 validated');
  CheckEquals('5410', LEntry.Certificate, '20348 certificate');
end;

procedure TTestWindowsModuleAttestation.TestTableNotValidated26100_22631_19045;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckTrue(TWindowsModuleAttestation.Lookup(26100, LEntry), '26100 listed');
  CheckFalse(LEntry.Fips140_3, '26100 not validated');
  CheckTrue(TWindowsModuleAttestation.Lookup(22631, LEntry), '22631 listed');
  CheckFalse(LEntry.Fips140_3, '22631 not validated');
  CheckTrue(TWindowsModuleAttestation.Lookup(19045, LEntry), '19045 listed');
  CheckFalse(LEntry.Fips140_3, '19045 not validated');
  CheckTrue(TWindowsModuleAttestation.Lookup(26200, LEntry), '26200 listed');
  CheckFalse(LEntry.Fips140_3, '26200 not validated');
end;

procedure TTestWindowsModuleAttestation.TestTableWindows10BuildsAreUnknownCertificate;
var
  LEntry: TWindowsModuleEntry;
  LBuilds: array [0 .. 3] of UInt32;
  LI: Int32;
begin
  LBuilds[0] := 19045;
  LBuilds[1] := 19044;
  LBuilds[2] := 17763;
  LBuilds[3] := 14393;
  for LI := 0 to 3 do
  begin
    CheckTrue(TWindowsModuleAttestation.Lookup(LBuilds[LI], LEntry), 'listed ' + IntToStr(LI));
    CheckEquals('Unknown', LEntry.Certificate, 'certificate ' + IntToStr(LI));
  end;
end;

procedure TTestWindowsModuleAttestation.TestLookupMissesUnlistedBuild;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckFalse(TWindowsModuleAttestation.Lookup(12345, LEntry), 'unlisted');
  CheckFalse(LEntry.Fips140_3, 'the out entry is cleared');
  CheckEquals('', LEntry.Product, 'with no product');
end;

procedure TTestWindowsModuleAttestation.TestStatusFollowsTheTable;
var
  LAttestation: IModuleAttestation;
  LEntry: TWindowsModuleEntry;
  LExpected: TModuleStatus;
begin
  LAttestation := TWindowsModuleAttestation.Create as IModuleAttestation;
  if TWindowsModuleAttestation.Lookup(LAttestation.Identity.OsBuild, LEntry) and
    LEntry.Fips140_3 then
    LExpected := TModuleStatus.Validated
  else
    LExpected := TModuleStatus.NotValidated;
  CheckEquals(Ord(LExpected), Ord(LAttestation.Status(TModuleStandard.Fips140_3)),
    'the status is the table row for the detected build');
end;

procedure TTestWindowsModuleAttestation.TestDescribeNamesTheOutcome;
var
  LAttestation: IModuleAttestation;
begin
  LAttestation := TWindowsModuleAttestation.Create as IModuleAttestation;
  CheckTrue(Pos(LAttestation.Identity.OsVersion, LAttestation.Describe) > 0,
    'the OS version is in the description');
end;

{ TTestWindowsCompliance }

procedure TTestWindowsCompliance.TestStrictPassesOnValidatedBuild;
var
  LAttestation: IModuleAttestation;
  LPolicy: ICompliancePolicy;
begin
  LAttestation := TOSModuleAttestation.Current;
  if LAttestation.Status(TModuleStandard.Fips140_3) <> TModuleStatus.Validated then
  begin
    SkipTest(Format(SBranchNotValidated, [LAttestation.Identity.OsBuild]));
    Exit;
  end;
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS), Pkix, LAttestation,
    TComplianceEnforcement.Strict) as ICompliancePolicy;
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LPolicy.PlatformReport.Verdict),
    'the validated build is compliant');
end;

procedure TTestWindowsCompliance.TestStrictRaisesNotValidatedOnOtherBuilds;
var
  LAttestation: IModuleAttestation;
  LFindings: TArray<TComplianceFinding>;
  LRaised: Boolean;
begin
  LAttestation := TOSModuleAttestation.Current;
  if LAttestation.Status(TModuleStandard.Fips140_3) = TModuleStatus.Validated then
  begin
    SkipTest(Format(SBranchValidated, [LAttestation.Identity.OsBuild]));
    Exit;
  end;
  LRaised := False;
  LFindings := nil;
  try
    TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
      TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS), Pkix, LAttestation,
      TComplianceEnforcement.Strict);
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      LFindings := E.Findings;
    end;
  end;
  CheckTrue(LRaised, 'strict refuses a build the table does not validate');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ModuleNotValidated), 'names the module');
end;

procedure TTestWindowsCompliance.TestRelaxedReportsNotValidatedOnOtherBuilds;
var
  LAttestation: IModuleAttestation;
  LPolicy: ICompliancePolicy;
begin
  LAttestation := TOSModuleAttestation.Current;
  if LAttestation.Status(TModuleStandard.Fips140_3) = TModuleStatus.Validated then
  begin
    SkipTest(Format(SBranchValidated, [LAttestation.Identity.OsBuild]));
    Exit;
  end;
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS), Pkix, LAttestation,
    TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  CheckTrue(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.ModuleNotValidated),
    'reported');
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LPolicy.PlatformReport.Verdict),
    'never compliant');
end;

procedure TTestWindowsCompliance.TestOsVerifierClientKeepsStrengthFloors;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
  LReport := LPolicy.Evaluate(TComplianceTls.Client(LPolicy).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the OS verifier is in the module');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.StrengthBelowRules),
    'the strength floors are the rules');
end;

procedure TTestWindowsCompliance.TestLiveClientKeepsStrengthFloors;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
  LReport := LPolicy.Evaluate(TComplianceTls.Client(LPolicy, TRevocationPosture.Soft,
    1000).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the live OS verifier is in the module');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.StrengthBelowRules),
    'the strength floors survive the live setup');
end;

{$ENDIF TLSLIB_MSWINDOWS}

initialization

{$IFDEF FPC}
  RegisterTest(TTestCompliancePolicy);
  RegisterTest(TTestComplianceAdmit);
{$ELSE}
  RegisterTest(TTestCompliancePolicy.Suite);
  RegisterTest(TTestComplianceAdmit.Suite);
{$ENDIF FPC}

{$IFDEF TLSLIB_MSWINDOWS}
{$IFDEF FPC}
  RegisterTest(TTestWindowsModuleAttestation);
  RegisterTest(TTestWindowsCompliance);
{$ELSE}
  RegisterTest(TTestWindowsModuleAttestation.Suite);
  RegisterTest(TTestWindowsCompliance.Suite);
{$ENDIF FPC}
{$ENDIF TLSLIB_MSWINDOWS}

end.
