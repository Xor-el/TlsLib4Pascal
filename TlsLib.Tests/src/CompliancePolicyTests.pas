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
  TlpDefaultCryptoProvider,
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
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpITlsCredentialResolver,
  TlpITlsServerCredentialSet,
  TlpCredentialResolvers,
  TlpAntiReplay,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsConfigBuilder,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpIComplianceReport,
  TlpIModuleAttestation,
  TlpICompliancePolicy,
  TlpIComplianceCredentialResolver,
  TlpCompliancePolicy,
  TlpCompliancePresets,
  TlpComplianceTls,
  TlpOSModuleAttestation,
  TlpWindowsModuleAttestation,
  TlpOSSystemTrust,
  TlpITrustAnchorStore,
  TlpISystemVerifierSource,
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
    // the first finding of AKind; fails the test when there is none
    function FindingOfKind(const AFindings: TArray<TComplianceFinding>;
      AKind: TComplianceFindingKind): TComplianceFinding;
    function CountOfKind(const AFindings: TArray<TComplianceFinding>;
      AKind: TComplianceFindingKind): Int32;
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
    procedure TestStrictPortableVerificationRaises;
    procedure TestRelaxedPortableVerificationReportsOnlyThatScheme;
    procedure TestStrictForeignHpkeRaisesAlgorithmOutsideModule;
    procedure TestRelaxedForeignHpkeReports;
    procedure TestForeignHpkeIsNotAFindingWhenRulesForbidEch;
    procedure TestRebuiltHpkeIsNotAFinding;
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
    // the 2048-bit RSA leaf with an OS-served key that exposes the leaf's public key
    function Rsa2048Credential: TTlsCredential;
    function AcceptAll(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
    // early data needs resumption and a cache to build, so the violation is the only fault
    function EarlyDataClientBuilder(const APolicy: ICompliancePolicy;
      const AVerification: IServerVerificationBuilder): ITlsClientConfigBuilder;
    // a TLS 1.3 server builder over the policy providers that skips the facade
    function RawServer(const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
    // a server config holding AResolver exactly as given, the policy's wrapper not applied
    function RawResolverConfig(const APolicy: ICompliancePolicy;
      const AResolver: ITlsServerCredentialResolver): ITlsServerConfig;
    function MtlsServerBuilder(const APolicy: ICompliancePolicy;
      APosture: TRevocationPosture): ITlsServerConfigBuilder;
    function Disclosed(const AReport: IComplianceReport; const AFragment: string): Boolean;
    // strict rules whose only AEAD is AES-128-GCM, so tickets could not be sealed
    function Aes128Policy: ICompliancePolicy;
    // a relaxed policy whose RSA key must be 3072 or 4096 bits
    function LargeRsaPolicy: ICompliancePolicy;
    function Resolved(const AResolver: ITlsServerCredentialResolver;
      out ACredential: TTlsCredential): Boolean;
    // a relaxed Fips140_3 policy that offers only AVersions
    function VersionPolicy(const AVersions: TArray<UInt16>): ICompliancePolicy;
    function Tls12Psk: TTls12Psk;
    function HasServerNameFinding(const AReport: IComplianceReport): Boolean;
    // a key that signs only with ED25519 beside the P-256 certificate of Credential
    function Ed25519OnlyKeyCredential(const ACrypto: ICryptoProvider): TTlsCredential;
    // the groups of the rules built over the policy crypto, none of them the policy's objects
    function OwnCryptoGroups(const APolicy: ICompliancePolicy): INamedGroupRegistry;
    function CatalogSuite: TTlsCipherSuite;
    // whether a strict policy refuses a client whose suites are the rules' with ASuite for its code
    function SuiteAdmit(const ASuite: TTlsCipherSuite;
      out AFindings: TArray<TComplianceFinding>): Boolean;
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
    procedure TestForeignClassicalRegistryRefused;
    procedure TestGroupsOverPolicyCryptoButNotItsObjectsRefused;
    procedure TestListedForeignGroupBesideThePolicysRefused;
    procedure TestPrunedPolicyGroupsAdmitted;
    procedure TestHostGroupWithAllowedCodeRefused;
    procedure TestRelaxedRefusesForeignGroup;
    procedure TestServerForeignGroupRefused;
    procedure TestPreferredGroupResolvedToForeignObjectRefused;
    procedure TestCatalogSuiteRecordAdmitted;
    procedure TestSuiteWithAlteredHashRefused;
    procedure TestSuiteWithAlteredPrfRefused;
    procedure TestSuiteWithAlteredKeyLengthRefused;
    procedure TestSuiteWithAlteredAeadRefused;
    procedure TestSuiteWithAlteredProtocolRefused;
    procedure TestSuiteWithAlteredKeyExchangeRefused;
    procedure TestSuiteWithAlteredAuthRefused;
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
    procedure TestRsaCredentialOfListedSizeAdmits;
    procedure TestRsaCredentialInsideRangeButUnlistedIsBelowRules;
    procedure TestRsaCredentialFollowsTheRangeWithoutExactSizes;
    procedure TestWebPkiVerifierChainOutsideModule;
    procedure TestInstanceVerifierChainOutsideModule;
    procedure TestSystemVerifierSourceAdmitted;
    procedure TestStapleRequestedRefused;
    procedure TestMtlsServerWebPkiClientVerifierRefused;
    procedure TestMtlsServerFakeSystemSourceAdmits;
    procedure TestServerWithoutClientAuthNeedsNoClientVerifier;
    procedure TestRevocationOffDisclosed;
    procedure TestServerWithoutClientAuthHasNoPeerDisclosure;
    procedure TestMtlsServerDisclosesRevocationOff;
    procedure TestMtlsServerDisclosesRsaPeerChainRange;
    procedure TestClientDisclosesRsaPeerChainRange;
    procedure TestClientHasNoRsaDisclosureWithoutExactSizes;
    procedure TestPlainServerHasNoDisclosure;
    procedure TestWeakSniEntryIsBelowRules;
    procedure TestListedResolverWeakEntryIsBelowRulesNotUnchecked;
    procedure TestDefaultSharedWithAnSniEntryIsReportedOnce;
    procedure TestRawCustomResolverIsUnchecked;
    procedure TestRawCustomResolverIsRefusedEvenInRelaxed;
    procedure TestCheckedResolverIsNotReportedUnchecked;
    procedure TestResolverCheckedByAnotherPolicyIsUnchecked;
    procedure TestPskOnlyServerHasNoResolverFinding;
    procedure TestCheckedResolverPassesAnAdmittedCredential;
    procedure TestCheckedResolverRefusesRsaOffTheExactSizes;
    procedure TestCheckedResolverRefusesAWrongCurve;
    procedure TestCheckedResolverRefusesAPortableKeyInStrict;
    procedure TestCheckedResolverAdmitsAPortableKeyInRelaxed;
    procedure TestCheckedResolverAnswersFalseWhenTheInnerDoes;
    procedure TestCheckedResolverNarrowsTheKey;
    procedure TestCheckedResolverRefusesAnEmptyChain;
    procedure TestCheckedResolverRefusesAKeyWithNoAllowedScheme;
    procedure TestCheckedResolverRefusesAChainWithNoKey;
    procedure TestCheckedResolverPropagatesAnInnerFault;
    procedure TestCheckedResolverRejectsNilInner;
    procedure TestCheckedResolverExposesItsInner;
    procedure TestFacadeServerResolverRejectsNilResolver;
    procedure TestFacadeServerResolverRejectsNilPolicy;
    procedure TestFacadeServerResolverBuildsAdmittedConfig;
    procedure TestFacadeServerResolverChecksListedEntries;
    procedure TestFacadeServerResolverNarrowsListedEntriesBeforeChecking;
    procedure TestFacadeServerCredentialSubjectIsNumbered;
    procedure TestEvaluateCredentialUnreadableCertificateIsUndetermined;
    procedure TestEvaluateCredentialWithoutChainIsUndetermined;
    procedure TestEvaluateCredentialWithoutKeyIsUndetermined;
    procedure TestEvaluateCredentialReportsExtraSchemes;
    procedure TestEvaluateCredentialOfAGoodCredentialHasNoFinding;
    procedure TestTicketAeadNotAllowedWhenServerSealsWithoutAes256;
    procedure TestExplicitTicketKeysUnderAes128AreRefused;
    procedure TestStoreWithDefaultTicketKeysUnderAes128IsRefused;
    procedure TestStoreOnlyServerGetsNoTicketFinding;
    procedure TestClientGetsNoTicketFinding;
    procedure TestFleetTicketKeysDisclosed;
    procedure TestMtlsServerDisclosesAHostOwnedRevocationResolver;
    procedure TestClientWithoutServerNameCheckIsRefused;
    procedure TestRequiredPskClientNeedsNoServerNameFinding;
    procedure TestRequiredTls12PskClientNeedsNoServerNameFinding;
    procedure TestPskClientWithCertificatePathGetsServerNameFinding;
    procedure TestOptionalPskClientGetsServerNameFinding;
    procedure TestOptionalTls12PskClientGetsServerNameFinding;
    procedure TestRequiredPskClientIsNotHeldToStrengthFloors;
    procedure TestRequiredPskClientHasNoRsaPeerChainDisclosure;
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

  TTestComplianceRoots = class(TCompliancePolicyTestCase)
  strict private
    // builds the Roots client; skips and returns False where the platform has no OS verifier
    function ConfigOrSkip(const APolicy: ICompliancePolicy; const ARoots: TSystemTrustRoots;
      out AConfig: ITlsClientConfig): Boolean;
    function SourceOf(const AConfig: ITlsClientConfig): ISystemVerifierSource;
  published
    procedure TestHostRootsClientKeepsChainInModuleAndFloors;
    procedure TestHostRootsSourceCarriesTheRootsAlone;
    procedure TestOsAndHostRootsSourceCarriesExtraAnchors;
    procedure TestOsRootsSourceCarriesNeither;
    procedure TestRootsClientRejectsNilPolicy;
    procedure TestBuildClientRejectsNilBuilder;
    procedure TestBuildServerRejectsNilBuilder;
  end;

{$IFDEF TLSLIB_MSWINDOWS}
  TTestWindowsModuleAttestation = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestReadsBuildAndModuleVersion;
    procedure TestTableValidated22621And20348;
    procedure TestTableNotValidated26100_22631_19045;
    procedure TestValidatedRowsCarryTheirStandardLevelAndDates;
    procedure TestNotValidatedRowsHaveNoCertificate;
    procedure TestDescribeNamesNoStandardWhenNotValidated;
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
    procedure TestLiveClientCarriesTheHostRootsAlone;
    procedure TestLiveClientCarriesNoHostRootsForOsRoots;
  end;
{$ENDIF TLSLIB_MSWINDOWS}

implementation

type
  // a resolver that answers one credential and does not list it, as a host-owned one
  TPlainCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver)
  strict private
  var
    FCredential: TTlsCredential;
    FResolves: Boolean;
  public
    constructor Create(const ACredential: TTlsCredential; AResolves: Boolean);
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
  end;

  // a host-written resolver that lists the credentials it may select
  TListedCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver,
    ITlsServerCredentialSet)
  strict private
  var
    FCredentials: TArray<TTlsCredential>;
  public
    constructor Create(const ACredentials: TArray<TTlsCredential>);
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
    function Credentials: TArray<TTlsCredential>;
  end;

  // a resolver whose lookup fails, as a host resolver backed by a store that is down
  TFailingCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver)
  public
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
  end;

resourcestring
  SResolverStoreDown = 'the credential store is down';
  SBranchNotValidated = 'build %d is not validated; the validated branch does not apply';
  SBranchValidated = 'build %d is validated; the not-validated branch does not apply';

{ TPlainCredentialResolver }

constructor TPlainCredentialResolver.Create(const ACredential: TTlsCredential;
  AResolves: Boolean);
begin
  inherited Create;
  FCredential := ACredential;
  FResolves := AResolves;
end;

function TPlainCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  ACredential := FCredential;
  Result := FResolves;
end;

{ TListedCredentialResolver }

constructor TListedCredentialResolver.Create(const ACredentials: TArray<TTlsCredential>);
begin
  inherited Create;
  FCredentials := ACredentials;
end;

function TListedCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  ACredential := FCredentials[0];
  Result := True;
end;

function TListedCredentialResolver.Credentials: TArray<TTlsCredential>;
begin
  Result := FCredentials;
end;

{ TFailingCredentialResolver }

function TFailingCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  ACredential := Default(TTlsCredential);
  raise EInvalidOperationTlsLibException.CreateRes(@SResolverStoreDown);
end;

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
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil, nil);
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
    TFakeSigningCrypto.Create(LKey, True) as ISigningCrypto, nil);
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

function TCompliancePolicyTestCase.FindingOfKind(const AFindings: TArray<TComplianceFinding>;
  AKind: TComplianceFindingKind): TComplianceFinding;
var
  LI: Int32;
  LFound: Boolean;
begin
  Result := Default(TComplianceFinding);
  LFound := False;
  for LI := 0 to System.Length(AFindings) - 1 do
    if not LFound and (AFindings[LI].Kind = AKind) then
    begin
      Result := AFindings[LI];
      LFound := True;
    end;
  CheckTrue(LFound, 'a finding of the expected kind');
end;

function TCompliancePolicyTestCase.CountOfKind(const AFindings: TArray<TComplianceFinding>;
  AKind: TComplianceFindingKind): Int32;
var
  LI: Int32;
begin
  Result := 0;
  for LI := 0 to System.Length(AFindings) - 1 do
    if AFindings[LI].Kind = AKind then
      Inc(Result);
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
    [TAeadAlgorithm.AES_128_GCM]) as ICryptoBackendReport, nil, nil);
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
    [TAeadAlgorithm.AES_128_GCM]) as ICryptoBackendReport, nil, nil);
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
  CheckEquals(1, System.Length(LDisclosures), 'one per fact, however many derivations');
  CheckTrue(Pos('composed', LDisclosures[0]) > 0, 'it names the composed derivation');
end;

procedure TTestCompliancePolicy.TestStrictPortableVerificationRaises;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
  LFindings: TArray<TComplianceFinding>;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableVerification := [TSignatureScheme.ECDSA_SECP256R1_SHA256];
  CheckTrue(Construct(TCompliancePresets.Fips140_3,
    TComplianceFakes.FakeSystemBase(LRef, nil, nil), TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'strict refuses a host that cannot verify');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.AlgorithmOutsideModule), 'the kind');
  CheckEquals('verification ECDSA_SECP256R1_SHA256', LFindings[0].Subject, 'the subject');
end;

procedure TTestCompliancePolicy.TestRelaxedPortableVerificationReportsOnlyThatScheme;
var
  LReport: TFakeBackendReport;
  LRef: ICryptoBackendReport;
  LFindings: TArray<TComplianceFinding>;
begin
  LReport := TFakeBackendReport.Create([]);
  LRef := LReport;
  LReport.PortableVerification := [TSignatureScheme.RSA_PSS_RSAE_SHA384];
  LFindings := NewPolicy(TCompliancePresets.Fips140_3,
    TComplianceFakes.FakeSystemBase(LRef, nil, nil), TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed).PlatformReport.Findings;
  CheckEquals(1, System.Length(LFindings), 'one scheme, one finding');
  CheckEquals('verification RSA_PSS_RSAE_SHA384', LFindings[0].Subject, 'the subject');
end;

procedure TTestCompliancePolicy.TestStrictForeignHpkeRaisesAlgorithmOutsideModule;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  Exclude(LRules.Requirements, TComplianceRequirement.NoEch);
  CheckTrue(Construct(LRules, TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil, TFakeHpke.Create as IHpkeCrypto),
    TModuleStatus.Validated, TComplianceEnforcement.Strict, LFindings),
    'strict refuses ECH over a foreign HPKE');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.AlgorithmOutsideModule), 'the kind');
  CheckEquals('HPKE', LFindings[System.High(LFindings)].Subject, 'the subject');
end;

procedure TTestCompliancePolicy.TestRelaxedForeignHpkeReports;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  Exclude(LRules.Requirements, TComplianceRequirement.NoEch);
  LFindings := NewPolicy(LRules, TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil, TFakeHpke.Create as IHpkeCrypto),
    TModuleStatus.Validated, TComplianceEnforcement.Relaxed).PlatformReport.Findings;
  CheckEquals('HPKE', LFindings[System.High(LFindings)].Subject, 'reported');
end;

procedure TTestCompliancePolicy.TestForeignHpkeIsNotAFindingWhenRulesForbidEch;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil, TFakeHpke.Create as IHpkeCrypto),
    TModuleStatus.Validated, TComplianceEnforcement.Strict);
  CheckEquals(0, System.Length(LPolicy.PlatformReport.Findings), 'nothing uses HPKE');
end;

procedure TTestCompliancePolicy.TestRebuiltHpkeIsNotAFinding;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
begin
  LRules := TCompliancePresets.Fips140_3;
  Exclude(LRules.Requirements, TComplianceRequirement.NoEch);
  LPolicy := NewPolicy(LRules, SystemBase, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  CheckFalse(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.AlgorithmOutsideModule),
    'the refusing primitives already place the composition');
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
    [TAeadAlgorithm.AES_128_GCM]) as ICryptoBackendReport, nil, nil);
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
  CheckTrue(LAttestation.Identity.OsBuild > 0, 'it read the build');
  CheckTrue(LAttestation.Status(TModuleStandard.Fips140_3) <> TModuleStatus.Unknown,
    'and judged it');
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

function TTestComplianceAdmit.Rsa2048Credential: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_cert'));
  Result.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.RSA_PSS_RSAE_SHA256), Pkix.Certificates.Parse(
    Result.CertificateChain[0]).PublicKeyInfo) as ISigningKey;
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

function TTestComplianceAdmit.RawServer(
  const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
var
  LProfile: TTlsConfigProfile;
begin
  LProfile := TTlsConfigProfile.Default;
  LProfile.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LProfile.SignatureSchemes := TSignatureSchemeRegistry.CreateDefault;
  LProfile.NamedGroups := TNamedGroups.CreateDefaultRegistry(Crypto);
  LProfile.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
  LProfile.PreferredGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  Result := TTlsConfigBuilder.CreateFromProfile(APolicy.Crypto, APolicy.Pkix, LProfile).Server;
end;

function TTestComplianceAdmit.RawResolverConfig(const APolicy: ICompliancePolicy;
  const AResolver: ITlsServerCredentialResolver): ITlsServerConfig;
begin
  Result := RawServer(APolicy).WithCredentialResolver(AResolver).Build;
end;

function TTestComplianceAdmit.MtlsServerBuilder(const APolicy: ICompliancePolicy;
  APosture: TRevocationPosture): ITlsServerConfigBuilder;
begin
  Result := ServerBuilder(APolicy).WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.VerifierSource(
    TFakeSystemVerifierSource.Create as IClientCertificateVerifierSource,
    TTlsLibTestCertificates.EcP256RootStore).WithMinimumStrength(APolicy.Rules.Strength)
    .WithRevocation(APosture).Build);
end;

function TTestComplianceAdmit.Disclosed(const AReport: IComplianceReport;
  const AFragment: string): Boolean;
var
  LDisclosures: TArray<string>;
  LI: Int32;
begin
  Result := False;
  LDisclosures := AReport.Disclosures;
  for LI := 0 to System.Length(LDisclosures) - 1 do
    if Pos(AFragment, LDisclosures[LI]) > 0 then
      Result := True;
end;

function TTestComplianceAdmit.Aes128Policy: ICompliancePolicy;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Aeads := [TAeadAlgorithm.AES_128_GCM];
  LRules.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256, TCipherSuites12.EcdheRsaAes128GcmSha256);
  Result := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
end;

function TTestComplianceAdmit.LargeRsaPolicy: ICompliancePolicy;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
  Result := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
end;

function TTestComplianceAdmit.Resolved(const AResolver: ITlsServerCredentialResolver;
  out ACredential: TTlsCredential): Boolean;
begin
  Result := AResolver.TryResolve(Default(TTlsClientHelloInfo), ACredential);
end;

function TTestComplianceAdmit.VersionPolicy(const AVersions: TArray<UInt16>): ICompliancePolicy;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := AVersions;
  Result := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
end;

function TTestComplianceAdmit.Tls12Psk: TTls12Psk;
begin
  Result.Identity := TBytes.Create($61, $62);
  Result.Secret := TSecretBuffer.From(TBytes.Create($00, $11, $22, $33, $44, $55, $66, $77));
end;

function TTestComplianceAdmit.HasServerNameFinding(const AReport: IComplianceReport): Boolean;
var
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  Result := False;
  LFindings := AReport.Findings;
  for LI := 0 to System.Length(LFindings) - 1 do
    if (LFindings[LI].Kind = TComplianceFindingKind.DangerousTrustConfigured) and
      (LFindings[LI].Subject = 'ServerName') then
      Result := True;
end;

function TTestComplianceAdmit.Ed25519OnlyKeyCredential(
  const ACrypto: ICryptoProvider): TTlsCredential;
begin
  Result := Credential(ACrypto);
  Result.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519), Result.PrivateKey.PublicKeyInfo) as ISigningKey;
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
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  // the registry is the policy's own, so only the preference list can name a group outside
  // the rules
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(LPolicy.NamedGroups)
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.NamedGroupNotAllowed),
    'names the preferred P-384');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.ForeignNamedGroup), 'no foreign group');
end;

procedure TTestComplianceAdmit.TestForeignClassicalRegistryRefused;
var
  LPolicy: ICompliancePolicy;
  LBuilder: INamedGroupRegistryBuilder;
  LFindings: TArray<TComplianceFinding>;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  // X25519 is pruned, so every remaining code is allowed and only the provider is foreign
  LBuilder := TNamedGroups.CreateClassicalRegistry(TDefaultCryptoProvider.Shared).ToBuilder;
  LBuilder.Prune(TNamedGroupCatalog.X25519);
  LRaised := False;
  try
    TComplianceTls.BuildClient(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(LBuilder.Build));
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      LFindings := E.Findings;
    end;
  end;
  CheckTrue(LRaised, 'BuildClient refuses');
  CheckEquals(6, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'each of the 3 groups is found listed and preferred');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.NamedGroupNotAllowed),
    'every code is allowed');
end;

procedure TTestComplianceAdmit.TestGroupsOverPolicyCryptoButNotItsObjectsRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(
    OwnCryptoGroups(LPolicy)).Build, LFindings), 'refused');
  CheckEquals(6, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'the identity is the objects, not the provider');
end;

procedure TTestComplianceAdmit.TestListedForeignGroupBesideThePolicysRefused;
var
  LPolicy: ICompliancePolicy;
  LBuilder: INamedGroupRegistryBuilder;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  // the preference list names the policy's own P-256 only, so just the listing is foreign
  LBuilder := LPolicy.NamedGroups.ToBuilder;
  LBuilder.Prune(TNamedGroupCatalog.Secp384r1);
  LBuilder.Add(TNamedGroups.CreateNistEcdh(LPolicy.Crypto, 'secp384r1'));
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(LBuilder.Build)
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1)).Build,
    LFindings), 'refused');
  CheckEquals(1, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'only the foreign P-384');
  CheckEquals('secp384r1', FindingOfKind(LFindings,
    TComplianceFindingKind.ForeignNamedGroup).Subject, 'names P-384');
end;

procedure TTestComplianceAdmit.TestPrunedPolicyGroupsAdmitted;
var
  LPolicy: ICompliancePolicy;
  LBuilder: INamedGroupRegistryBuilder;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LBuilder := LPolicy.NamedGroups.ToBuilder;
  LBuilder.Prune(TNamedGroupCatalog.Secp384r1);
  LBuilder.Prune(TNamedGroupCatalog.Secp521r1);
  CheckFalse(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(LBuilder.Build)
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1)).Build,
    LFindings), 'admitted');
end;

procedure TTestComplianceAdmit.TestHostGroupWithAllowedCodeRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
  LFinding: TComplianceFinding;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(
    TNamedGroups.CreateRegistry(TArray<INamedGroup>.Create(
    TFakeNamedGroup.Create(TNamedGroupCatalog.Secp256r1) as INamedGroup)))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1)).Build,
    LFindings), 'refused');
  LFinding := FindingOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup);
  CheckEquals('secp256r1', LFinding.Subject, 'names the group');
  CheckTrue(Pos('ICompliancePolicy.NamedGroups', LFinding.Message) > 0, 'says where to get them');
end;

function TTestComplianceAdmit.OwnCryptoGroups(
  const APolicy: ICompliancePolicy): INamedGroupRegistry;
var
  LRules: TComplianceRules;
  LGroups: TArray<INamedGroup>;
  LI: Int32;
begin
  LRules := APolicy.Rules;
  System.SetLength(LGroups, System.Length(LRules.NamedGroups));
  for LI := 0 to System.Length(LRules.NamedGroups) - 1 do
    LGroups[LI] := TNamedGroups.CreateNistEcdh(APolicy.Crypto,
      TNamedGroupCatalog.Name(LRules.NamedGroups[LI]));
  Result := TNamedGroups.CreateRegistry(LGroups);
end;

function TTestComplianceAdmit.CatalogSuite: TTlsCipherSuite;
begin
  CheckTrue(TCipherSuiteCatalog.TryGet(TCipherSuites12.EcdheEcdsaAes256GcmSha384, Result),
    'catalog');
end;

function TTestComplianceAdmit.SuiteAdmit(const ASuite: TTlsCipherSuite;
  out AFindings: TArray<TComplianceFinding>): Boolean;
var
  LPolicy: ICompliancePolicy;
  LRules: TComplianceRules;
  LBuilder: ICipherSuiteRegistryBuilder;
  LSuite: TTlsCipherSuite;
  LI: Int32;
begin
  LPolicy := StrictPolicy;
  LRules := LPolicy.Rules;
  // ASuite first, so it stands for its code and the rule suites fill the other versions
  LBuilder := TCipherSuiteRegistryBuilder.Create as ICipherSuiteRegistryBuilder;
  LBuilder.Add(ASuite);
  for LI := 0 to System.Length(LRules.CipherSuites) - 1 do
  begin
    CheckTrue(TCipherSuiteCatalog.TryGet(LRules.CipherSuites[LI], LSuite), 'catalog');
    LBuilder.Add(LSuite);
  end;
  Result := ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithCipherSuites(LBuilder.Build).Build,
    AFindings);
end;

procedure TTestComplianceAdmit.TestCatalogSuiteRecordAdmitted;
var
  LFindings: TArray<TComplianceFinding>;
begin
  CheckFalse(SuiteAdmit(CatalogSuite, LFindings), 'the catalog record is admitted');
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredHashRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Common.Hash := THashAlgorithm.SHA_256;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names the suite');
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredPrfRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Prf := THashAlgorithm.SHA_256;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names the suite');
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredKeyLengthRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Common.KeyLength := 16;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names the suite');
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredAeadRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Common.Aead := TAeadAlgorithm.AES_128_GCM;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names the suite');
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredProtocolRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Protocol := TSuiteProtocol.Tls13;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names the suite');
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredKeyExchangeRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.KeyExchange := TKeyExchangeMethod.Decoupled;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names the suite');
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredAuthRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Auth := TAuthMethod.Rsa;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CipherSuiteNotAllowed), 'names the suite');
end;

procedure TTestComplianceAdmit.TestRelaxedRefusesForeignGroup;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
  LFinding: TComplianceFinding;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(
    OwnCryptoGroups(LPolicy)).Build, LFindings), 'relaxed still refuses');
  LFinding := FindingOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup);
  CheckEquals(Ord(TComplianceFindingCategory.Configuration), Ord(LFinding.Category),
    'a configuration finding');
end;

procedure TTestComplianceAdmit.TestServerForeignGroupRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithNamedGroups(
    OwnCryptoGroups(LPolicy)).Build, LFindings), 'refused');
  CheckEquals(6, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'each of the 3 groups is found listed and preferred');
end;

procedure TTestComplianceAdmit.TestPreferredGroupResolvedToForeignObjectRefused;
var
  LPolicy: ICompliancePolicy;
  LRegistry: INamedGroupRegistry;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  // Items lists the policy's own groups, but the engine resolves P-384 through TryGet
  LRegistry := TFakeGroupRegistry.Create(LPolicy.NamedGroups, TNamedGroups.CreateNistEcdh(
    LPolicy.Crypto, 'secp384r1')) as INamedGroupRegistry;
  CheckTrue(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithNamedGroups(LRegistry).Build,
    LFindings), 'refused');
  CheckEquals(1, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'only the resolved group');
  CheckEquals('secp384r1', FindingOfKind(LFindings,
    TComplianceFindingKind.ForeignNamedGroup).Subject, 'names P-384');
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
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil, nil);
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

procedure TTestComplianceAdmit.TestRsaCredentialOfListedSizeAdmits;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(CredentialBuilder(LPolicy, Rsa2048Credential).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    '2048 is one of the exact sizes');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyUndetermined),
    'and the key is determined');
end;

procedure TTestComplianceAdmit.TestRsaCredentialInsideRangeButUnlistedIsBelowRules;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LReport := LPolicy.Evaluate(CredentialBuilder(LPolicy, Rsa2048Credential).Build);
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    '2048 is inside the range but not an exact size');
end;

procedure TTestComplianceAdmit.TestRsaCredentialFollowsTheRangeWithoutExactSizes;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.RsaModulusBits := nil;
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  LReport := LPolicy.Evaluate(CredentialBuilder(LPolicy, Rsa2048Credential).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    'the range alone admits 2048');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyUndetermined),
    'and the key is determined');
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

procedure TTestComplianceAdmit.TestServerWithoutClientAuthHasNoPeerDisclosure;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build), 'peer chain'),
    'no client chain is verified, so the range does not apply');
end;

procedure TTestComplianceAdmit.TestMtlsServerDisclosesRevocationOff;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Disclosed(LPolicy.Evaluate(MtlsServerBuilder(LPolicy,
    TRevocationPosture.Soft).Build), 'revocation checking is off'), 'control: on');
  CheckTrue(Disclosed(LPolicy.Evaluate(MtlsServerBuilder(LPolicy,
    TRevocationPosture.Off).Build), 'revocation checking is off'), 'off is disclosed');
end;

procedure TTestComplianceAdmit.TestMtlsServerDisclosesRsaPeerChainRange;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(MtlsServerBuilder(LPolicy,
    TRevocationPosture.Soft).Build), 'size range'), 'a verified client chain is held to it');
end;

procedure TTestComplianceAdmit.TestClientDisclosesRsaPeerChainRange;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Build), 'size range'),
    'the server chain is held to the range, not to the exact sizes');
  CheckFalse(Disclosed(LPolicy.PlatformReport, 'size range'), 'the platform report has none');
end;

procedure TTestComplianceAdmit.TestClientHasNoRsaDisclosureWithoutExactSizes;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.RsaModulusBits := nil;
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  CheckFalse(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Build), 'size range'),
    'the range alone is enforced everywhere');
end;

procedure TTestComplianceAdmit.TestPlainServerHasNoDisclosure;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(ServerBuilder(LPolicy).Build);
  CheckEquals(System.Length(LPolicy.PlatformReport.Disclosures),
    System.Length(LReport.Disclosures), 'the credentials are checked, not disclosed');
  CheckEquals(0, System.Length(LReport.Findings), 'and none is found');
end;

procedure TTestComplianceAdmit.TestWeakSniEntryIsBelowRules;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  LFindings := LPolicy.Evaluate(ServerBuilder(LPolicy).WithSniCredential('localhost',
    Ed25519Credential).Build).Findings;
  CheckEquals('credential 2 (CN=localhost)',
    FindingOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules).Subject,
    'the SNI credential is checked too, named by its place in the set and its common name');
end;

procedure TTestComplianceAdmit.TestListedResolverWeakEntryIsBelowRulesNotUnchecked;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
  LReport := LPolicy.Evaluate(RawResolverConfig(LPolicy, TListedCredentialResolver.Create(
    TArray<TTlsCredential>.Create(Credential(LPolicy.Crypto), Ed25519Credential))
    as ITlsServerCredentialResolver));
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    'a resolver that lists its credentials is checked entry by entry');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialResolverUnchecked),
    'and is not reported as uninspectable');
end;

procedure TTestComplianceAdmit.TestDefaultSharedWithAnSniEntryIsReportedOnce;
var
  LPolicy: ICompliancePolicy;
  LWeak: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  LWeak := Ed25519Credential;
  LFindings := LPolicy.Evaluate(RawServer(LPolicy).WithCredential(LWeak)
    .WithSniCredential('localhost', LWeak).Build).Findings;
  CheckEquals(1, CountOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules),
    'the credential the default shares with an entry is listed once');
end;

procedure TTestComplianceAdmit.TestRawCustomResolverIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(RawResolverConfig(LPolicy,
    TPlainCredentialResolver.Create(Credential(LPolicy.Crypto), True)
    as ITlsServerCredentialResolver)), TComplianceFindingKind.CredentialResolverUnchecked),
    'a resolver the policy cannot see into is reported');
end;

procedure TTestComplianceAdmit.TestRawCustomResolverIsRefusedEvenInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ServerAdmit(LPolicy, RawResolverConfig(LPolicy, TPlainCredentialResolver.Create(
    Credential(LPolicy.Crypto), True) as ITlsServerCredentialResolver), LFindings),
    'the finding is a configuration one');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CredentialResolverUnchecked), 'which');
end;

procedure TTestComplianceAdmit.TestCheckedResolverIsNotReportedUnchecked;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(RawResolverConfig(LPolicy, LPolicy.CheckedCredentialResolver(
    TPlainCredentialResolver.Create(Credential(LPolicy.Crypto), True)
    as ITlsServerCredentialResolver)));
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialResolverUnchecked),
    'the wrapper of this policy checks each credential itself');
end;

procedure TTestComplianceAdmit.TestResolverCheckedByAnotherPolicyIsUnchecked;
var
  LOwner, LOther: ICompliancePolicy;
begin
  LOwner := StrictPolicy;
  LOther := StrictPolicy;
  CheckTrue(ReportHasKind(LOther.Evaluate(RawResolverConfig(LOther,
    LOwner.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    Credential(LOwner.Crypto), True) as ITlsServerCredentialResolver))),
    TComplianceFindingKind.CredentialResolverUnchecked),
    'a wrapper bound to a different policy instance is not trusted');
end;

procedure TTestComplianceAdmit.TestPskOnlyServerHasNoResolverFinding;
var
  LPolicy: ICompliancePolicy;
  LRules: TComplianceRules;
  LReport: IComplianceReport;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Requirements := LRules.Requirements - [TComplianceRequirement.NoExternalPsk];
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  LReport := LPolicy.Evaluate(RawServer(LPolicy).Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(Psk)).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialResolverUnchecked),
    'no certificate is presented, so no resolver is involved');
end;

procedure TTestComplianceAdmit.TestCheckedResolverPassesAnAdmittedCredential;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := Credential(LPolicy.Crypto);
  CheckTrue(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver), LResolved), 'admitted');
  CheckTrue(TArrayUtilities.AreEqual(LGiven.CertificateChain[0], LResolved.CertificateChain[0]),
    'with its own chain');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesRsaOffTheExactSizes;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := LargeRsaPolicy;
  CheckFalse(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    Rsa2048Credential, True) as ITlsServerCredentialResolver), LResolved),
    'a 2048-bit key is not one of 3072 and 4096');
  CheckEquals(0, System.Length(LResolved.CertificateChain), 'and nothing is handed out');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAWrongCurve;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  CheckFalse(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    Credential(LPolicy.Crypto), True) as ITlsServerCredentialResolver), LResolved),
    'a P-256 key is outside the allowed curves');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAPortableKeyInStrict;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    PortableP256Credential, True) as ITlsServerCredentialResolver), LResolved),
    'strict refuses a key the module does not serve');
end;

procedure TTestComplianceAdmit.TestCheckedResolverAdmitsAPortableKeyInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    PortableP256Credential, True) as ITlsServerCredentialResolver), LResolved),
    'relaxed reports a platform finding and still admits');
end;

procedure TTestComplianceAdmit.TestCheckedResolverAnswersFalseWhenTheInnerDoes;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    Credential(LPolicy.Crypto), False) as ITlsServerCredentialResolver), LResolved),
    'an inner refusal stands');
  CheckEquals(0, System.Length(LResolved.CertificateChain), 'and nothing is handed out');
end;

procedure TTestComplianceAdmit.TestCheckedResolverNarrowsTheKey;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := Credential(LPolicy.Crypto);
  LGiven.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    LGiven.PrivateKey.PublicKeyInfo) as ISigningKey;
  CheckTrue(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver), LResolved), 'admitted once narrowed');
  CheckEquals(1, System.Length(LResolved.PrivateKey.CapableSchemes), 'only the allowed scheme');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAnEmptyChain;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    Default(TTlsCredential), True) as ITlsServerCredentialResolver), LResolved),
    'an inner answer that holds no certificate is refused');
  CheckEquals(0, System.Length(LResolved.CertificateChain), 'and nothing is handed out');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAKeyWithNoAllowedScheme;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(
    Ed25519OnlyKeyCredential(LPolicy.Crypto), True) as ITlsServerCredentialResolver),
    LResolved), 'a key whose schemes miss the rules is refused once narrowed');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAChainWithNoKey;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := Credential(LPolicy.Crypto);
  LGiven.PrivateKey := nil;
  CheckFalse(Resolved(LPolicy.CheckedCredentialResolver(TPlainCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver), LResolved),
    'a certificate with no private key can sign nothing');
end;

procedure TTestComplianceAdmit.TestCheckedResolverPropagatesAnInnerFault;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LRaised := False;
  try
    Resolved(LPolicy.CheckedCredentialResolver(TFailingCredentialResolver.Create
      as ITlsServerCredentialResolver), LResolved);
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a fault of the host resolver is not swallowed into a refusal');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRejectsNilInner;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    StrictPolicy.CheckedCredentialResolver(nil);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil inner');
end;

procedure TTestComplianceAdmit.TestCheckedResolverExposesItsInner;
var
  LPolicy: ICompliancePolicy;
  LInner: ITlsServerCredentialResolver;
  LChecked: IComplianceCredentialResolver;
begin
  LPolicy := StrictPolicy;
  LInner := TPlainCredentialResolver.Create(Credential(LPolicy.Crypto), True)
    as ITlsServerCredentialResolver;
  CheckTrue(Supports(LPolicy.CheckedCredentialResolver(LInner), IComplianceCredentialResolver,
    LChecked), 'the wrapper is marked');
  CheckTrue(LChecked.Inner = LInner, 'and answers the resolver it checks');
  CheckTrue(LChecked.Policy = LPolicy, 'for the policy that made it');
end;

procedure TTestComplianceAdmit.TestFacadeServerResolverRejectsNilResolver;
var
  LMessage: string;
  LNone: ITlsServerCredentialResolver;
begin
  LMessage := '';
  LNone := nil;
  try
    TComplianceTls.Server(StrictPolicy, LNone);
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals('the credential resolver must not be nil', LMessage,
    'the facade names the resolver it was given, not the wrapper''s inner');
end;

procedure TTestComplianceAdmit.TestFacadeServerResolverRejectsNilPolicy;
var
  LMessage: string;
  LNone: ITlsServerCredentialResolver;
  LPolicy: ICompliancePolicy;
begin
  LMessage := '';
  LNone := nil;
  LPolicy := nil;
  try
    TComplianceTls.Server(LPolicy, LNone);
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals('the compliance policy must not be nil', LMessage,
    'the policy is checked before the resolver');
end;

procedure TTestComplianceAdmit.TestFacadeServerResolverBuildsAdmittedConfig;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
  LChecked: IComplianceCredentialResolver;
begin
  LPolicy := StrictPolicy;
  LConfig := TComplianceTls.BuildServer(LPolicy, TComplianceTls.Server(LPolicy,
    TPlainCredentialResolver.Create(Credential(LPolicy.Crypto), True)
    as ITlsServerCredentialResolver));
  CheckTrue(Supports(LConfig.CredentialResolver, IComplianceCredentialResolver, LChecked),
    'the built config holds the checking wrapper');
  CheckTrue(LChecked.Policy = LPolicy, 'of this policy');
end;

procedure TTestComplianceAdmit.TestFacadeServerResolverChecksListedEntries;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
  LRefused: Boolean;
begin
  LPolicy := RelaxedPolicy;
  LRefused := False;
  try
    TComplianceTls.BuildServer(LPolicy, TComplianceTls.Server(LPolicy,
      TSniCredentialResolver.ForCredential(Ed25519Credential)));
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRefused := True;
      LFindings := E.Findings;
    end;
  end;
  CheckTrue(LRefused, 'a weak static entry behind the wrapper fails the build');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules), 'for its key');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.CredentialResolverUnchecked),
    'and not as an uninspectable resolver');
end;

procedure TTestComplianceAdmit.TestFacadeServerResolverNarrowsListedEntriesBeforeChecking;
var
  LPolicy: ICompliancePolicy;
  LGiven: TTlsCredential;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LGiven := Credential(LPolicy.Crypto);
  LGiven.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    LGiven.PrivateKey.PublicKeyInfo) as ISigningKey;
  LReport := LPolicy.Evaluate(TComplianceTls.Server(LPolicy,
    TSniCredentialResolver.ForCredential(LGiven)).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialSchemesNotAllowed),
    'the wrapper narrows this key before it judges it, so the build check does too');
end;

procedure TTestComplianceAdmit.TestFacadeServerCredentialSubjectIsNumbered;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  LFindings := LPolicy.Evaluate(TComplianceTls.Server(LPolicy, Ed25519Credential).Build)
    .Findings;
  CheckEquals('credential 1 (CN=localhost)',
    FindingOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules).Subject,
    'the facade credential is the first of the set');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialUnreadableCertificateIsUndetermined;
var
  LCredential: TTlsCredential;
begin
  LCredential := Credential(StrictPolicy.Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(TBytes.Create(1, 2, 3));
  CheckTrue(ReportHasKind(StrictPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyUndetermined), 'reported, not raised');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialWithoutChainIsUndetermined;
var
  LCredential: TTlsCredential;
begin
  LCredential := Credential(StrictPolicy.Crypto);
  LCredential.CertificateChain := nil;
  CheckTrue(ReportHasKind(StrictPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyUndetermined), 'a credential with no certificate');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialWithoutKeyIsUndetermined;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LCredential := Credential(LPolicy.Crypto);
  LCredential.PrivateKey := nil;
  CheckTrue(ReportHasKind(LPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyUndetermined), 'a certificate with no private key');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialReportsExtraSchemes;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LCredential := Credential(LPolicy.Crypto);
  LCredential.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256),
    LCredential.PrivateKey.PublicKeyInfo) as ISigningKey;
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('ED25519', FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialSchemesNotAllowed).Message) > 0,
    'an allowed scheme beside a forbidden one is not enough, and the extra is named');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialOfAGoodCredentialHasNoFinding;
var
  LPolicy: ICompliancePolicy;
begin
  // a guard: it also passes without the checks and pins only the clean case
  LPolicy := StrictPolicy;
  CheckEquals(0, System.Length(LPolicy.EvaluateCredential(Credential(LPolicy.Crypto)).Findings),
    'none');
end;

procedure TTestComplianceAdmit.TestTicketAeadNotAllowedWhenServerSealsWithoutAes256;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
begin
  LPolicy := Aes128Policy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).Build),
    TComplianceFindingKind.TicketAeadNotAllowed), 'the facade turns resumption off');
  LBuilder := ServerBuilder(LPolicy).WithResumption(True);
  CheckTrue(ReportHasKind(LPolicy.Evaluate(LBuilder.Build),
    TComplianceFindingKind.TicketAeadNotAllowed), 'the default ticket keys seal with AES-256');
end;

procedure TTestComplianceAdmit.TestExplicitTicketKeysUnderAes128AreRefused;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
begin
  LPolicy := Aes128Policy;
  LBuilder := ServerBuilder(LPolicy).WithResumption(True).WithSessionTicketKeys(
    TStekTicketKeyManager.Create(LPolicy.Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager);
  CheckTrue(ReportHasKind(LPolicy.Evaluate(LBuilder.Build),
    TComplianceFindingKind.TicketAeadNotAllowed), 'keys the host supplies seal with AES-256 too');
end;

procedure TTestComplianceAdmit.TestStoreWithDefaultTicketKeysUnderAes128IsRefused;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
begin
  LPolicy := Aes128Policy;
  LBuilder := ServerBuilder(LPolicy).WithResumption(True).WithSessionStore(
    TInMemorySessionStore.Create(LPolicy.Crypto.Primitives.GetRandom) as ISessionStore)
    .WithDefaultSessionTicketKeys;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(LBuilder.Build),
    TComplianceFindingKind.TicketAeadNotAllowed),
    'a store beside the default ticket keys still seals tickets');
end;

procedure TTestComplianceAdmit.TestStoreOnlyServerGetsNoTicketFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := Aes128Policy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithResumption(True)
    .WithSessionStore(TInMemorySessionStore.Create(LPolicy.Crypto.Primitives.GetRandom)
    as ISessionStore).Build), TComplianceFindingKind.TicketAeadNotAllowed),
    'a stateful store seals nothing');
end;

procedure TTestComplianceAdmit.TestClientGetsNoTicketFinding;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsClientConfig;
begin
  LPolicy := Aes128Policy;
  LConfig := ClientBuilder(LPolicy).Build;
  CheckTrue(LConfig.Resumption, 'a client keeps resumption, it only opens tickets');
  CheckEquals(0, System.Length(LPolicy.Evaluate(LConfig).Findings), 'and has no finding');
end;

procedure TTestComplianceAdmit.TestFleetTicketKeysDisclosed;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    TFleetTicketKeyManager.Create as IFleetTicketKeyManager).Build), 'entered by the host'),
    'keys the host enters are not generated by the policy crypto');
  CheckFalse(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build), 'entered by the host'),
    'the default keys are');
end;

procedure TTestComplianceAdmit.TestMtlsServerDisclosesAHostOwnedRevocationResolver;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(MtlsServerBuilder(LPolicy, TRevocationPosture.Soft)
    .WithLiveRevocationVerdict(1000).Build), 'host-owned'),
    'a live-revocation resolver of the host cannot be inspected');
  CheckFalse(Disclosed(LPolicy.Evaluate(MtlsServerBuilder(LPolicy,
    TRevocationPosture.Soft).Build), 'host-owned'), 'control: no resolver, no disclosure');
  CheckFalse(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build), 'host-owned'),
    'a server that verifies no client chain has none');
end;

procedure TTestComplianceAdmit.TestClientWithoutServerNameCheckIsRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy)
    .WithDangerousDisableServerNameCheck.Build, LFindings), 'refused');
  CheckEquals('ServerName', FindingOfKind(LFindings,
    TComplianceFindingKind.DangerousTrustConfigured).Subject, 'named for the host-name match');
end;

procedure TTestComplianceAdmit.TestRequiredPskClientNeedsNoServerNameFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls13));
  CheckFalse(HasServerNameFinding(LPolicy.Evaluate(ClientBuilder(LPolicy)
    .WithDangerousDisableServerNameCheck.Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(Psk)).Build)),
    'a TLS 1.3 client that requires its PSK reaches no certificate to match');
end;

procedure TTestComplianceAdmit.TestRequiredTls12PskClientNeedsNoServerNameFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls12));
  CheckFalse(HasServerNameFinding(LPolicy.Evaluate(ClientBuilder(LPolicy)
    .WithDangerousDisableServerNameCheck.Tls12.WithPreSharedKey(Tls12Psk).Build)),
    'a TLS 1.2 client that requires its PSK reaches no certificate to match');
end;

procedure TTestComplianceAdmit.TestPskClientWithCertificatePathGetsServerNameFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12));
  CheckTrue(HasServerNameFinding(LPolicy.Evaluate(ClientBuilder(LPolicy)
    .WithDangerousDisableServerNameCheck.Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(Psk)).Build)),
    'TLS 1.2 ignores an external PSK, so that handshake ends in a certificate');
end;

procedure TTestComplianceAdmit.TestOptionalPskClientGetsServerNameFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls13));
  CheckTrue(HasServerNameFinding(LPolicy.Evaluate(ClientBuilder(LPolicy)
    .WithDangerousDisableServerNameCheck.Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(Psk)).WithExternalPskRequired(False).Build)),
    'a PSK the server may skip falls back to a certificate');
end;

procedure TTestComplianceAdmit.TestOptionalTls12PskClientGetsServerNameFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls12));
  CheckTrue(HasServerNameFinding(LPolicy.Evaluate(ClientBuilder(LPolicy)
    .WithDangerousDisableServerNameCheck.Tls12.WithPreSharedKey(Tls12Psk)
    .WithPreSharedKeyRequired(False).Build)),
    'a TLS 1.2 PSK offered beside the certificate suites falls back to a certificate');
end;

procedure TTestComplianceAdmit.TestRequiredPskClientIsNotHeldToStrengthFloors;
var
  LPolicy: ICompliancePolicy;
  LLoose: IServerVerification;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls13));
  LLoose := TServerVerification.VerifierSource(TFakeSystemVerifierSource.Create
    as IServerCertificateVerifierSource).WithMinimumStrength(
    TCertificateStrengthPolicy.Defaults).Build;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    LLoose).Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(Psk)).Build),
    TComplianceFindingKind.StrengthBelowRules), 'a client that verifies no chain has no floors');
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    LLoose).Build), TComplianceFindingKind.StrengthBelowRules),
    'control: the same verification without the PSK is held to them');
end;

procedure TTestComplianceAdmit.TestRequiredPskClientHasNoRsaPeerChainDisclosure;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls13));
  CheckFalse(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(Psk)).Build), 'size range'),
    'a client that verifies no chain holds no chain to a range');
  CheckTrue(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Build), 'size range'),
    'control: the client without the PSK does');
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
  CheckTrue(ServerBuilder(LPolicy).Build.Resumption, 'tickets are sealed with AES-256-GCM');
end;

procedure TTestComplianceAdmit.TestFacadeResumptionOffWithoutAes256;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := Aes128Policy;
  CheckFalse(ServerBuilder(LPolicy).Build.Resumption, 'tickets could not be sealed');
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

{ TTestComplianceRoots }

function TTestComplianceRoots.ConfigOrSkip(const APolicy: ICompliancePolicy;
  const ARoots: TSystemTrustRoots; out AConfig: ITlsClientConfig): Boolean;
begin
  AConfig := nil;
  Result := TOSSystemTrust.Supports(TSystemTrustMode.Delegate);
  if not Result then
  begin
    SkipTest('this platform has no OS verifier');
    Exit;
  end;
  AConfig := TComplianceTls.Client(APolicy, ARoots).Build;
end;

function TTestComplianceRoots.SourceOf(const AConfig: ITlsClientConfig): ISystemVerifierSource;
begin
  Result := nil;
  CheckTrue(Supports(AConfig.ServerVerifierSource, ISystemVerifierSource, Result),
    'the verification is an OS-marked source');
end;

procedure TTestComplianceRoots.TestHostRootsClientKeepsChainInModuleAndFloors;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsClientConfig;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
  if not ConfigOrSkip(LPolicy, TSystemTrustRoots.HostRoots(
    TTlsLibTestCertificates.EcP256RootStore), LConfig) then
    Exit;
  LReport := LPolicy.Evaluate(LConfig);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'host roots are still verified by the OS verifier');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.StrengthBelowRules),
    'and the floors are the rules');
end;

procedure TTestComplianceRoots.TestHostRootsSourceCarriesTheRootsAlone;
var
  LConfig: ITlsClientConfig;
  LSource: ISystemVerifierSource;
begin
  if not ConfigOrSkip(RelaxedPolicy, TSystemTrustRoots.HostRoots(
    TTlsLibTestCertificates.EcP256RootStore), LConfig) then
    Exit;
  LSource := SourceOf(LConfig);
  CheckEquals(1, System.Length(LSource.Anchors), 'the host root is the exclusive anchor');
  CheckEqualBytes('the host root', TTlsLibTestCertificates.EcP256RootStore.RootCertificates[0],
    LSource.Anchors[0]);
  CheckEquals(0, System.Length(LSource.ExtraAnchors), 'nothing beside the OS roots');
end;

procedure TTestComplianceRoots.TestOsAndHostRootsSourceCarriesExtraAnchors;
var
  LConfig: ITlsClientConfig;
  LSource: ISystemVerifierSource;
begin
  if not ConfigOrSkip(RelaxedPolicy, TSystemTrustRoots.OsAndHostRoots(
    TTlsLibTestCertificates.EcP256RootStore), LConfig) then
    Exit;
  LSource := SourceOf(LConfig);
  CheckEquals(0, System.Length(LSource.Anchors), 'the OS roots still apply');
  CheckEquals(1, System.Length(LSource.ExtraAnchors), 'the host root beside them');
  CheckEqualBytes('the host root', TTlsLibTestCertificates.EcP256RootStore.RootCertificates[0],
    LSource.ExtraAnchors[0]);
end;

procedure TTestComplianceRoots.TestOsRootsSourceCarriesNeither;
var
  LConfig: ITlsClientConfig;
  LSource: ISystemVerifierSource;
begin
  if not ConfigOrSkip(RelaxedPolicy, TSystemTrustRoots.OsRoots, LConfig) then
    Exit;
  LSource := SourceOf(LConfig);
  CheckEquals(0, System.Length(LSource.Anchors), 'no exclusive anchor');
  CheckEquals(0, System.Length(LSource.ExtraAnchors), 'no extra anchor');
end;

procedure TTestComplianceRoots.TestRootsClientRejectsNilPolicy;
var
  LRaised: Boolean;
  LNone: ICompliancePolicy;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.Client(LNone, TSystemTrustRoots.OsRoots);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil policy');
end;

procedure TTestComplianceRoots.TestBuildClientRejectsNilBuilder;
var
  LRaised: Boolean;
  LNone: ITlsClientConfigBuilder;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.BuildClient(StrictPolicy, LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil builder');
end;

procedure TTestComplianceRoots.TestBuildServerRejectsNilBuilder;
var
  LRaised: Boolean;
  LNone: ITlsServerConfigBuilder;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.BuildServer(StrictPolicy, LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil builder');
end;

{$IFDEF TLSLIB_MSWINDOWS}

{ TTestWindowsModuleAttestation }

procedure TTestWindowsModuleAttestation.TestReadsBuildAndModuleVersion;
var
  LAttestation: IModuleAttestation;
  LIdentity: TModuleIdentity;
begin
  LAttestation := TWindowsModuleAttestation.Create as IModuleAttestation;
  LIdentity := LAttestation.Identity;
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
  CheckTrue(LEntry.Validated, '22621 validated');
  CheckEquals('5410', LEntry.Certificate, '22621 certificate');
  CheckTrue(TWindowsModuleAttestation.Lookup(20348, LEntry), '20348 listed');
  CheckTrue(LEntry.Validated, '20348 validated');
  CheckEquals('5410', LEntry.Certificate, '20348 certificate');
end;

procedure TTestWindowsModuleAttestation.TestValidatedRowsCarryTheirStandardLevelAndDates;
var
  LEntry: TWindowsModuleEntry;
  LBuilds: array [0 .. 1] of UInt32;
  LI: Int32;
begin
  LBuilds[0] := 22621;
  LBuilds[1] := 20348;
  for LI := 0 to 1 do
  begin
    CheckTrue(TWindowsModuleAttestation.Lookup(LBuilds[LI], LEntry), 'listed ' + IntToStr(LI));
    CheckEquals(Ord(TModuleStandard.Fips140_3), Ord(LEntry.Standard), 'standard ' + IntToStr(LI));
    CheckEquals(1, Int32(LEntry.Level), 'level ' + IntToStr(LI));
    CheckEquals('2026-08-31', LEntry.ValidatedOn, 'validated on ' + IntToStr(LI));
    CheckEquals('2031-08-30', LEntry.Sunset, 'sunset ' + IntToStr(LI));
  end;
end;

procedure TTestWindowsModuleAttestation.TestTableNotValidated26100_22631_19045;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckTrue(TWindowsModuleAttestation.Lookup(26100, LEntry), '26100 listed');
  CheckFalse(LEntry.Validated, '26100 not validated');
  CheckTrue(TWindowsModuleAttestation.Lookup(22631, LEntry), '22631 listed');
  CheckFalse(LEntry.Validated, '22631 not validated');
  CheckTrue(TWindowsModuleAttestation.Lookup(19045, LEntry), '19045 listed');
  CheckFalse(LEntry.Validated, '19045 not validated');
  CheckTrue(TWindowsModuleAttestation.Lookup(26200, LEntry), '26200 listed');
  CheckFalse(LEntry.Validated, '26200 not validated');
end;

procedure TTestWindowsModuleAttestation.TestNotValidatedRowsHaveNoCertificate;
var
  LEntry: TWindowsModuleEntry;
  LBuilds: array [0 .. 6] of UInt32;
  LI: Int32;
begin
  LBuilds[0] := 22631;
  LBuilds[1] := 26100;
  LBuilds[2] := 26200;
  LBuilds[3] := 19045;
  LBuilds[4] := 19044;
  LBuilds[5] := 17763;
  LBuilds[6] := 14393;
  for LI := 0 to 6 do
  begin
    CheckTrue(TWindowsModuleAttestation.Lookup(LBuilds[LI], LEntry), 'listed ' + IntToStr(LI));
    CheckFalse(LEntry.Validated, 'not validated ' + IntToStr(LI));
    CheckEquals('', LEntry.Certificate, 'certificate ' + IntToStr(LI));
    CheckEquals('', LEntry.ValidatedOn, 'no validation date ' + IntToStr(LI));
    CheckEquals('', LEntry.Sunset, 'no sunset ' + IntToStr(LI));
  end;
end;

procedure TTestWindowsModuleAttestation.TestLookupMissesUnlistedBuild;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckFalse(TWindowsModuleAttestation.Lookup(12345, LEntry), 'unlisted');
  CheckFalse(LEntry.Validated, 'the out entry is cleared');
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
    LEntry.Validated then
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
  if LAttestation.Status(TModuleStandard.Fips140_3) = TModuleStatus.Validated then
  begin
    CheckTrue(Pos('FIPS 140-3 Level 1', LAttestation.Describe) > 0, 'the standard and level');
    CheckTrue(Pos('validated 2026-08-31, sunset 2031-08-30', LAttestation.Describe) > 0,
      'the row''s own dates');
  end
  else
    CheckTrue(Pos('no validated module', LAttestation.Describe) > 0, 'the outcome');
end;

procedure TTestWindowsModuleAttestation.TestDescribeNamesNoStandardWhenNotValidated;
var
  LAttestation: IModuleAttestation;
begin
  LAttestation := TWindowsModuleAttestation.Create as IModuleAttestation;
  if LAttestation.Status(TModuleStandard.Fips140_3) = TModuleStatus.Validated then
  begin
    SkipTest('this build is validated, so its description names the standard');
    Exit;
  end;
  CheckEquals(0, Pos('FIPS', LAttestation.Describe), 'no standard is claimed');
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
  LReport := LPolicy.Evaluate(TComplianceTls.Client(LPolicy, TSystemTrustRoots.OsRoots).Build);
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
  LReport := LPolicy.Evaluate(TComplianceTls.Client(LPolicy, TSystemTrustRoots.OsRoots,
    TRevocationPosture.Soft, 1000).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the live OS verifier is in the module');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.StrengthBelowRules),
    'the strength floors survive the live setup');
end;

procedure TTestWindowsCompliance.TestLiveClientCarriesTheHostRootsAlone;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsClientConfig;
  LSource: ISystemVerifierSource;
  LReport: IComplianceReport;
  LStore: ITrustAnchorStore;
begin
  LPolicy := RelaxedPolicy;
  LStore := TTlsLibTestCertificates.EcP256RootStore;
  LConfig := TComplianceTls.Client(LPolicy, TSystemTrustRoots.HostRoots(LStore),
    TRevocationPosture.Soft, 1000).Build;
  CheckTrue(Supports(LConfig.ServerVerifierSource, ISystemVerifierSource, LSource),
    'the live source is OS-marked');
  CheckEquals(1, System.Length(LSource.Anchors), 'the host root is the exclusive anchor');
  CheckEqualBytes('the host root', LStore.RootCertificates[0], LSource.Anchors[0]);
  CheckEquals(0, System.Length(LSource.ExtraAnchors), 'nothing beside the OS roots');
  LReport := LPolicy.Evaluate(LConfig);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.StrengthBelowRules),
    'the strength floors survive the live setup');
end;

procedure TTestWindowsCompliance.TestLiveClientCarriesNoHostRootsForOsRoots;
var
  LConfig: ITlsClientConfig;
  LSource: ISystemVerifierSource;
begin
  LConfig := TComplianceTls.Client(RelaxedPolicy, TSystemTrustRoots.OsRoots,
    TRevocationPosture.Soft, 1000).Build;
  CheckTrue(Supports(LConfig.ServerVerifierSource, ISystemVerifierSource, LSource),
    'the live source is OS-marked');
  CheckEquals(0, System.Length(LSource.Anchors) + System.Length(LSource.ExtraAnchors),
    'no host root');
end;

{$ENDIF TLSLIB_MSWINDOWS}

initialization

{$IFDEF FPC}
  RegisterTest(TTestCompliancePolicy);
  RegisterTest(TTestComplianceAdmit);
  RegisterTest(TTestComplianceRoots);
{$ELSE}
  RegisterTest(TTestCompliancePolicy.Suite);
  RegisterTest(TTestComplianceAdmit.Suite);
  RegisterTest(TTestComplianceRoots.Suite);
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
