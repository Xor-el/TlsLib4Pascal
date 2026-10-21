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
  TlpISystemSigningKey,
  TlpSecretBuffer,
  TlpSession,
  TlpCertificateStrengthPolicy,
  TlpPkixDomainTypes,
  TlpEnumUtilities,
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
  TlpEchConfig,
  TlpInMemoryEchKeyStore,
  TlpEchKeyGen,
  TlpSystemCryptoBase,
  TlpISession,
  TlpISecretBuffer,
  TlpIClock,
  TlpClock,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpITlsCredentialResolver,
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
  TlpIComplianceTicketKeys,
  TlpComplianceTicketKeys,
  TlpCompliancePolicy,
  TlpCompliancePresets,
  TlpComplianceTls,
  TlpOSModuleAttestation,
  TlpUnattestedModule,
  TlpOSCryptoProvider,
  TlpWindowsModuleDecision,
  TlpWindowsModuleAttestation,
  TlpOSSystemTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpIPlatformChainEngine,
  TlpSystemTrustBase,
  TlpSystemTrustExceptions,
  TlpOSDelegateVerifier,
  TlpTrustTypes,
  TlpServerName,
  TlpTlsAlert,
  MockPlatformChainEngine,
  MockCompliance,
  MockNamedGroups,
  MockCryptoProvider,
  MockSystemCrypto,
  MockRandom,
  MockKeyLog,
  MockCertificateVerifiers,
  MockCredentialResolvers,
  MockVerifyHooks,
  TlsLibTestCertificates,
  TlsLibTestProviders,
  TlsLibTestBase,
  TlsLibHandshakeTestBase;

type
  /// <summary>The helpers the policy suites share; it has no tests and is not registered.</summary>
  TCompliancePolicyTestCase = class abstract(TTlsLibHandshakeTestCase)
  strict protected
    function CreateCrypto: ICryptoProvider; override;
    function Identity: TModuleIdentity;
    // the OS module serves every operation and the TLS 1.2 PRF; an imported key is OS-served
    function SystemBaseWithKey: ICryptoProvider;
    // rules of Fips140_3 narrowed to TLS 1.2 and its suites
    function Tls12OnlyRules: TComplianceRules;
    function Attestation(AStatus: TModuleStatus): IModuleAttestation;
    // a validated attestation that covers no crypto provider
    function UncoveredAttestation: IModuleAttestation;
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
    // the default profile over the test crypto, offering TLS 1.3 and secp256r1 only
    function Tls13Profile: TTlsConfigProfile;
    // a TLS 1.3 server builder over the policy providers that skips the facade
    function RawServer(const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
    function MtlsServerBuilder(const APolicy: ICompliancePolicy;
      APosture: TRevocationPosture): ITlsServerConfigBuilder;
    function Disclosed(const AReport: IComplianceReport; const AFragment: string): Boolean;
    // strict rules whose only AEAD is AES-128-GCM, so tickets could not be sealed
    function Aes128Policy: ICompliancePolicy;
    // Fips140_3 narrowed to an RSA floor of 3072
    function Rsa3072Policy: ICompliancePolicy;
    function ClientBuilder(const APolicy: ICompliancePolicy): ITlsClientConfigBuilder;
    function ServerBuilder(const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
    // the facade server offering TLS 1.3 only, with the TLS 1.2 setting it made taken back
    function Tls13OnlyServerBuilder(const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
    // the P-256 server credential with an OS-served key of ASchemes over the leaf's public key
    function MarkedKeyCredential(const ACrypto: ICryptoProvider;
      const ASchemes: TArray<TSignatureScheme>): TTlsCredential;
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
    // whether a relaxed policy over an attestation with these module versions discloses them
    function DisclosesRevision(AStatus: TModuleStatus;
      const AFileVersion, AListedVersion: string): Boolean;
    // a Fips140_3 policy whose attestation has AStatus and gives ADisclosures
    function DisclosingPolicy(AStatus: TModuleStatus; const ADisclosures: TArray<string>;
      AEnforcement: TComplianceEnforcement): ICompliancePolicy;
    // a policy over a module whose HMAC is portable, so every derivation is outside it
    function PortableHmacPolicy(const ARules: TComplianceRules;
      ANativePrf: Boolean): ICompliancePolicy;
    // a policy whose report places everything in the module, HKDF included
    function ModuleReportPolicy(const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement): ICompliancePolicy;
  published
    procedure TestStrictFakeValidatedSystemConstructs;
    procedure TestCnsa1NamesItsPreset;
    procedure TestStrictNotValidatedRaises;
    procedure TestRelaxedNotValidatedReports;
    procedure TestRelaxedUncoveredCryptoReportsItAndEverythingOutside;
    procedure TestStrictUncoveredCryptoRaises;
    procedure TestCoveredCryptoHasNoCoverageFinding;
    procedure TestHostAttestationIsDisclosedAndNotAttested;
    procedure TestPlatformAttestationIsNotDisclosedAsHost;
    procedure TestIsPlatformIsAClassCheck;
    procedure TestUnattestedModuleAttestsNothing;
    procedure TestOsAttestationAttestsOnlyWhereATableShips;
    procedure TestPolicyReadsTheAttestationOnce;
    procedure TestStrictHistoricalModuleRaises;
    procedure TestRelaxedHistoricalModuleReports;
    procedure TestStrictUnknownStatusRaises;
    procedure TestStrictPortableBaseRaisesNoBackendReport;
    procedure TestRelaxedPortableBaseReportsNoBackendReport;
    procedure TestStrictPortableAeadRaisesAlgorithmOutsideModule;
    procedure TestRelaxedPortableAeadReports;
    procedure TestStrictHandBuiltEd25519RaisesArgument;
    procedure TestRelaxedHandBuiltEd25519RaisesArgument;
    procedure TestRulesWiderThanAPresetRaiseArgumentInBothModes;
    procedure TestDroppedRequirementRaisesArgumentInBothModes;
    procedure TestNarrowerRulesAreAcceptedInBothModes;
    procedure TestPolicyOverNarrowerRulesNamesThePreset;
    procedure TestEmptyVersionsRaiseArgument;
    procedure TestUnknownVersionRaisesArgument;
    procedure TestEmptySuitesRaiseArgument;
    procedure TestUnknownSuiteRaisesArgument;
    procedure TestSuiteAeadOutsideAeadsRaisesArgument;
    procedure TestVersionWithoutSuiteRaisesArgument;
    procedure TestEmptyGroupsRaiseArgument;
    procedure TestX25519GroupRaisesArgument;
    procedure TestHybridGroupRaisesArgument;
    procedure TestDuplicateSuiteRaisesArgument;
    procedure TestDuplicateGroupRaisesArgument;
    procedure TestEmptySchemesRaiseArgument;
    procedure TestEmptyCurvesRaiseArgument;
    procedure TestUnusableRulesRaiseArgumentInRelaxedToo;
    procedure TestNilBaseCryptoRaisesArgument;
    procedure TestNilBasePkixRaisesArgument;
    procedure TestNilAttestationRaisesArgument;
    procedure TestComposedKdfCapsTheVerdictAtPrimitivesInModule;
    procedure TestTls12OnlyRulesWithTheModulePrfAreCompliant;
    procedure TestTls12OnlyRulesWithAComposedPrfArePrimitivesInModule;
    procedure TestTls13OnlyRulesAreCappedWhateverThePrfIs;
    procedure TestRequireModuleAcceptsTls12OnlyRulesWithTheModulePrf;
    procedure TestRequireModuleRefusesTls12OnlyRulesWithAComposedPrf;
    procedure TestRequireModuleIgnoresTheTls13SuitesOfRulesThatOfferNoTls13;
    procedure TestRequireModuleIgnoresTheTls12SuitesOfRulesThatOfferNoTls12;
    procedure TestStrictPortableVerificationRaises;
    procedure TestRelaxedPortableVerificationReportsOnlyThatScheme;
    procedure TestForeignHpkeIsNotAFindingWhenRulesForbidEch;
    procedure TestKdfRequireModuleRaisesStrictOnComposed;
    procedure TestRulesReturnsClone;
    procedure TestAccessorsReturnConstructionInputs;
    procedure TestPlatformFindingsInFixedOrder;
    procedure TestPolicyCryptoRefusesChaCha;
    procedure TestPolicyPkixKeepsBaseInspector;
    procedure TestOsAttestationMatchesPlatform;
    procedure TestListedModuleVersionDifferingIsDisclosed;
    procedure TestListedModuleVersionMatchingIsNotDisclosed;
    procedure TestNoListedModuleVersionIsNotDisclosed;
    procedure TestNotValidatedModuleVersionIsNotDisclosed;
    procedure TestCnsa1DisclosesTheInternalSha256;
    procedure TestFips140_3DoesNotDiscloseTheInternalSha256;
    procedure TestStrictCnsa1Sha256OutsideTheModuleRaises;
    procedure TestStrictCnsa1Sha256HmacOutsideTheModuleRaises;
    procedure TestStrictCnsa1IgnoresSha512OutsideTheModule;
    procedure TestRelaxedPolicyDisclosesThatPortableCodeIsNotRefused;
    procedure TestStrictPolicyDoesNotDiscloseThePortableCodeLimit;
    procedure TestRelaxedDisclosureReachesAConfigReport;
    procedure TestGcmRulesDiscloseTheIvConstruction;
    procedure TestIvDisclosureNamesTheCounterAndTheStandards;
    procedure TestIvDisclosureReachesAConfigReport;
    procedure TestIvDisclosureLeavesTheVerdictAlone;
    procedure TestGcmDisclosureCitesScenario1aAfterTheConstruction;
    procedure TestPolicyAppendsTheAttestationDisclosures;
    procedure TestPolicyAppendsTheAttestationDisclosuresWhateverTheStatus;
    procedure TestAttestationDisclosuresReachAConfigReport;
    procedure TestAttestationWithoutDisclosuresAddsNone;
    procedure TestAttestationDisclosuresNeverRefuseAStrictPolicy;
    procedure TestExporterDisclosureIsOnAPlatformReportOfferingTls12;
    procedure TestExporterDisclosureIsOnAConfigReportOfferingTls12;
    procedure TestExporterDisclosureIsOnACredentialReport;
    procedure TestExporterDisclosureIsAbsentWhenTls12IsNotOffered;
    procedure TestExporterDisclosureLeavesTheVerdictAlone;
    procedure TestExporterIsDisclosedRefusedUnderStrictRequireModule;
    procedure TestExporterIsNotDisclosedComposedUnderStrictRequireModule;
    procedure TestExporterIsDisclosedComposedUnderRelaxedRequireModule;
    procedure TestExporterIsDisclosedComposedUnderStrictAllowComposed;
    procedure TestExporterDisclosureIsAbsentUnderRelaxedRequireModuleWithoutTls12;
    procedure TestPortableKdfIsNotAModuleService;
    procedure TestModulePrfBesidePortableHmacIsAModuleService;
    procedure TestHkdfIsOutsideTheModuleWhateverTheReportNames;
    procedure TestHkdfOutsideTheModuleStillLeavesTls12OnlyRulesCompliant;
    procedure TestRequireModuleRefusesHkdfWhateverTheReportNames;
    procedure TestRsaRangeWithMinAboveMaxRaisesArgumentInBothModes;
    procedure TestRsaSizesOutsideTheRangeRaiseArgumentInBothModes;
    procedure TestRsaRangeMessageNeedsAtLeastOneListedSize;
    procedure TestNotValidatedModuleKeepsNoCertificate;
    procedure TestNotValidatedReportPrintsNoCertificate;
    procedure TestValidatedReportPrintsTheCertificate;
  end;

  TTestComplianceAdmit = class(TCompliancePolicyTestCase)
  strict private
    function ForeignClient(const ACrypto: ICryptoProvider;
      const APkix: IPkixProvider): ITlsClientConfig;
    function Psk: TExternalPsk;
    // the 2048-bit RSA leaf with an OS-served key that exposes the leaf's public key
    function Rsa2048Credential: TTlsCredential;
    // early data needs resumption and a policy-scoped cache, so the violation is the only fault
    function EarlyDataClientBuilder(const APolicy: ICompliancePolicy;
      const AVerification: IServerVerificationBuilder): ITlsClientConfigBuilder;
    // AResolver as given, unwrapped, on a server with no resumption state: the only fault
    function RawResolverConfig(const APolicy: ICompliancePolicy;
      const AResolver: ITlsServerCredentialResolver): ITlsServerConfig;
    // a relaxed policy whose RSA key must be 3072 or 4096 bits
    function LargeRsaPolicy: ICompliancePolicy;
    // a relaxed Fips140_3 policy that offers only AVersions
    function VersionPolicy(const AVersions: TArray<UInt16>): ICompliancePolicy;
    function Tls12Psk: TTls12Psk;
    function HasServerNameFinding(const AReport: IComplianceReport): Boolean;
    // the groups of the rules built over the policy crypto, none of them the policy's objects
    function OwnCryptoGroups(const APolicy: ICompliancePolicy): INamedGroupRegistry;
    // a credential of the KeyUsagePss leaf ACertField with a key holding that leaf's public key
    function KeyUsageCredential(const APolicy: ICompliancePolicy;
      const ACertField: string): TTlsCredential;
    function CatalogSuite: TTlsCipherSuite;
    // whether a strict policy refuses a client built over the rules' suites once a host registry
    // swaps in ASuite for its code
    function SuiteAdmit(const ASuite: TTlsCipherSuite;
      out AFindings: TArray<TComplianceFinding>): Boolean;
    // the same for a server
    function ServerSuiteAdmit(const ASuite: TTlsCipherSuite;
      out AFindings: TArray<TComplianceFinding>): Boolean;
    // the rules' suites as the catalog defines them, and with ASuite swapped in for its code
    procedure SuiteSets(const APolicy: ICompliancePolicy; const ASuite: TTlsCipherSuite;
      out AClean, AAltered: TArray<TTlsCipherSuite>);
    // AFindings name the CatalogSuite record as off-catalog and leave its code allowed
    procedure CheckDiffersFromCatalog(const AFindings: TArray<TComplianceFinding>);
    // an ECH key store of one P-256 / AES-256-GCM entry the policy crypto can serve
    function EchKeyStore(const APolicy: ICompliancePolicy): IEchServerKeyStore;
    // a strict Fips140_3 policy whose module serves the TLS 1.2 PRF of every hash but SHA-256
    function Sha256PrfComposedPolicy: ICompliancePolicy;
    // a facade client offering TLS 1.2 only, with exactly the suites ACodes
    function Tls12Client(const APolicy: ICompliancePolicy;
      const ACodes: array of UInt16): ITlsClientConfig;
    // rules that allow only the ECDSA schemes, on a strict policy
    function EcdsaOnlyPolicy: ICompliancePolicy;
  published
    procedure TestBaselineClientAdmitsStrict;
    procedure TestBaselineServerAdmitsStrict;
    procedure TestTls12OnlyClientIsCompliantWhenTheModuleServesThePrf;
    procedure TestTls12OnlyServerIsCompliantWhenTheModuleServesThePrf;
    procedure TestTls13OnlyClientIsCappedWhenTheModuleServesThePrf;
    procedure TestForeignCryptoRefused;
    procedure TestForeignPkixRefused;
    procedure TestFacadeConfigHoldsPolicyProviders;
    procedure TestVersionNotAllowedRefused;
    procedure TestCipherSuiteNotAllowedRefused;
    procedure TestListedAndPreferredDisallowedGroupIsReportedOnce;
    procedure TestNamedGroupNotAllowedRefused;
    procedure TestPreferredGroupNotAllowedRefused;
    procedure TestForeignClassicalRegistryRefused;
    procedure TestGroupsOverPolicyCryptoButNotItsObjectsRefused;
    procedure TestListedForeignGroupNoPreferenceNamesIsAdmitted;
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
    procedure TestServerSuiteWithAlteredHashRefused;
    procedure TestSignatureSchemeNotAllowedRefused;
    procedure TestEmsNotRequiredRefused;
    procedure TestEarlyDataClientRefused;
    procedure TestEarlyDataServerRefused;
    procedure TestEchGreaseRefused;
    procedure TestKeyedEchServerIsEchConfigured;
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
    procedure TestRulesWithoutExactSizesAreRefusedAtConstruction;
    procedure TestWebPkiVerifierChainOutsideModule;
    procedure TestInstanceVerifierIsCustomNotChainOutside;
    procedure TestInstanceVerifierRefusedInRelaxed;
    procedure TestBuiltInVerifierIsPlatformOnlyInRelaxed;
    procedure TestOsVerifierSourceHasNoVerifierFinding;
    procedure TestHostSourceIsCustom;
    procedure TestHostSourceRefusedInRelaxed;
    procedure TestRequiredPskClientIgnoresCustomVerifier;
    procedure TestSystemVerifierSourceAdmitted;
    procedure TestStapleRequestedRefused;
    procedure TestStapleRequestedByRequiredPskClientIsNotAFinding;
    procedure TestMtlsServerWebPkiClientVerifierRefused;
    procedure TestMtlsServerOsVerifierSourceAdmits;
    procedure TestMtlsServerInstanceVerifierIsCustom;
    procedure TestMtlsServerInstanceVerifierRefusedInRelaxed;
    procedure TestMtlsServerBuiltInVerifierIsPlatformOnlyInRelaxed;
    procedure TestMtlsServerHostSourceIsCustom;
    procedure TestServerWithoutClientAuthNeedsNoClientVerifier;
    procedure TestRevocationOffDisclosed;
    procedure TestServerWithoutClientAuthHasNoPeerDisclosure;
    procedure TestMtlsServerDisclosesRevocationOff;
    procedure TestMtlsServerDisclosesRsaPeerChainRange;
    procedure TestClientDisclosesRsaPeerChainRange;
    procedure TestPlainServerHasNoDisclosure;
    procedure TestWeakSniEntryIsBelowRules;
    procedure TestHostListedResolverIsUnchecked;
    procedure TestSniResolverIsEnumerated;
    procedure TestHostClassClaimingCheckedMarkerIsUnchecked;
    procedure TestCheckedWrapperOverHostListedResolverIsNotUnchecked;
    procedure TestDefaultSharedWithAnSniEntryIsReportedOnce;
    procedure TestTwoCredentialsAreReportedEach;
    procedure TestSameKeyWithAnotherChainIsAnotherCredential;
    procedure TestWrapperOfAnotherPolicyAroundTheSniResolverIsUnchecked;
    procedure TestWrapperOfThisPolicyAroundTheSniResolverIsChecked;
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
    procedure TestEvaluateCredentialWithoutKeyIsMissing;
    procedure TestIntermediateKeyBelowTheFloorsIsAFinding;
    procedure TestUnreadableIntermediateIsUndetermined;
    procedure TestChainSignatureHashOutsideTheRulesIsAFinding;
    procedure TestChainSignatureHashInsideTheRulesIsNoFinding;
    procedure TestSelfSignedLastCertificateSignatureIsNotChecked;
    procedure TestSelfIssuedLinkBeforeTheLastCertificateIsChecked;
    procedure TestLoneSelfSignedCertificateSignatureIsNotChecked;
    procedure TestSelfIssuedLastCertificateSignedByAnotherKeyIsChecked;
    procedure TestSelfIssuedLastCertificateSignedByItsOwnKeyIsNotChecked;
    procedure TestPssSignatureUnderAPssIssuerKeyIsAFinding;
    procedure TestPssSignatureUnderAnRsaIssuerKeyIsNoFinding;
    procedure TestPssSignatureUnderAPssIssuerKeyIsAFindingWhateverTheChainOrder;
    procedure TestRsaSignatureUnderEcdsaOnlyRulesIsAFinding;
    procedure TestEcdsaSignatureUnderEcdsaOnlyRulesIsNoFinding;
    procedure TestKdfOutsideTheModuleIsJudgedByTheConfigSuites;
    procedure TestBuildClientLeavesTheCallersVariableAloneWhenRefused;
    procedure TestBuildServerLeavesTheCallersVariableAloneWhenRefused;
    procedure TestKeyOfAnotherCertificateIsMismatched;
    procedure TestKeyOfTheLeafIsNotMismatched;
    procedure TestKeyThatExposesNoPublicKeyIsUnusableNotMismatched;
    procedure TestKeyInAnotherEncodingOfTheLeafKeyIsNotMismatched;
    procedure TestLeafBarringDigitalSignatureIsUnusable;
    procedure TestRsaKeyOverAnRsaPssLeafIsUnusable;
    procedure TestCheckedResolverRefusesAKeyThatExposesNoPublicKey;
    procedure TestCheckedResolverRefusesALeafBarringDigitalSignature;
    procedure TestCheckedResolverAdmitsALeafPermittingDigitalSignature;
    procedure TestCheckedResolverRefusesAnRsaPssLeaf;
    procedure TestCheckedResolverRefusesAKeyOfAnotherCertificate;
    procedure TestEvaluateCredentialReportsExtraSchemes;
    procedure TestEvaluateCredentialOfAGoodCredentialHasNoFinding;
    procedure TestTicketAeadNotAllowedWhenServerSealsWithoutAes256;
    procedure TestExplicitTicketKeysUnderAes128AreRefused;
    procedure TestStoreWithDefaultTicketKeysUnderAes128IsNotRefused;
    procedure TestStoreWithDefaultTicketKeysUnderTls12Aes128IsRefused;
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

  TTestComplianceResumption = class(TCompliancePolicyTestCase)
  strict private
    function ClientWithCache(const APolicy: ICompliancePolicy): ITlsClientConfigBuilder;
    function NewStore(const APolicy: ICompliancePolicy): ISessionStore;
    function HasPrefixOf(const AScope: TBytes; const APolicy: ICompliancePolicy): Boolean;
    // the scope a host gives every server of a fleet: no policy prefix, so only equality admits it
    function FleetScope: TBytes;
    function NewFleet: IFleetTicketKeyManager;
    // a facade server holding AFleet behind the policy wrapper and AScope as its resumption scope
    function FleetServerBuilder(const APolicy: ICompliancePolicy;
      const AFleet: IFleetTicketKeyManager; const AScope: TBytes): ITlsServerConfigBuilder;
    // a strict policy over a base whose random generator is ARandom
    function PolicyOverRandom(const ARandom: IRandom): ICompliancePolicy;
  published
    procedure TestSessionScopeIs32BytesWithThePolicyPrefix;
    procedure TestSessionScopePrefixIsStableForOnePolicy;
    procedure TestSessionScopeRandomHalfIsFresh;
    procedure TestSessionScopePrefixDiffersBetweenPolicies;
    procedure TestClientCacheWithBuilderDefaultScopeIsUnchecked;
    procedure TestClientCacheWithPolicyScopeIsAdmitted;
    procedure TestClientCacheWithForeignScopeIsUnchecked;
    procedure TestClientCacheWithAnotherPolicysScopeIsUnchecked;
    procedure TestClientCacheWithScopeOneByteShortOfThePrefixIsUnchecked;
    procedure TestClientCacheWithTheBarePrefixIsAdmitted;
    procedure TestClientWithoutCacheHasNoResumptionFinding;
    procedure TestFacadeServerCarriesThePolicyScope;
    procedure TestFacadeServerHoldsThePolicyTicketKeys;
    procedure TestFacadeServerIsAdmitted;
    procedure TestFacadeServerKeysRotateOnTheTicketLifetime;
    procedure TestFacadeServerWithoutAes256HoldsNoTicketState;
    procedure TestMtlsFacadeServerIsAdmitted;
    procedure TestServerStoreWithPolicyScopeIsAdmitted;
    procedure TestServerStoreWithForeignScopeIsUnchecked;
    procedure TestServerStoreWithEmptyScopeIsUnchecked;
    procedure TestServerKeysWithForeignScopeIsUnchecked;
    procedure TestPlainServerDefaultKeysAreUnchecked;
    procedure TestPlainServerWithoutScopeIsUnchecked;
    procedure TestHostStekKeysAreUnchecked;
    procedure TestAnotherPolicysTicketKeysAreUnchecked;
    procedure TestHostClassClaimingTheMarkerIsUnchecked;
    procedure TestPolicyTicketKeysAreAdmitted;
    procedure TestTicketKeysLifetimeMismatchIsDisclosed;
    procedure TestTicketKeysLifetimeMatchIsNotDisclosed;
    procedure TestFleetKeysWithoutWrapperAreUnchecked;
    procedure TestCheckedFleetKeysWithTheFleetScopeAreAdmitted;
    procedure TestCheckedFleetKeysWithAnotherScopeAreUnchecked;
    procedure TestCheckedFleetKeysWithAPolicyScopeAreUnchecked;
    procedure TestCheckedFleetOfAnotherPolicyIsUnchecked;
    procedure TestCheckedFleetKeysAreDisclosed;
    procedure TestCheckedFleetScopeIsDisclosed;
    procedure TestKeysBesideAStoreAreNotChecked;
    procedure TestKeysBesideAStoreUnderTls12AreChecked;
    procedure TestFleetBesideAStoreIsNotDisclosed;
    procedure TestIdleCheckedFleetBesideAStoreAcceptsTheFleetScope;
    procedure TestIdleCheckedFleetBesideAStoreAcceptsThePolicyScope;
    procedure TestIdleCheckedFleetBesideAStoreRefusesAnotherScope;
    procedure TestFleetBesideAStoreUnderTls12IsDisclosed;
    procedure TestCheckedFleetBesideAStoreUnderTls12KeepsTheFleetScope;
    procedure TestCheckedFleetBesideAStoreUnderTls12RefusesThePolicyScope;
    procedure TestTicketKeysAreMintedFromThePolicyRandom;
    procedure TestTicketKeysRotateForwards;
    procedure TestCheckedFleetInstallKeyForwards;
    procedure TestTicketKeysRejectNilClock;
    procedure TestTicketKeysRejectZeroLifetime;
    procedure TestTicketKeysRefusedWithoutAes256;
    procedure TestCheckedTicketKeysRejectNilFleet;
    procedure TestCheckedTicketKeysRejectEmptyScope;
    procedure TestCheckedTicketKeysAcceptTheLongestScope;
    procedure TestCheckedTicketKeysRejectAScopeOneByteTooLong;
    procedure TestTicketKeysWrapperRejectsNilPolicy;
    procedure TestTicketKeysWrapperRejectsNilClock;
    procedure TestTicketKeysWrapperRejectsZeroLifetime;
    procedure TestFleetWrapperRejectsNilPolicy;
    procedure TestFleetWrapperRejectsNilInner;
    procedure TestWithoutResumptionTurnsResumptionOff;
    procedure TestWithResumptionFalseAloneStillRaises;
    procedure TestWithoutResumptionRejectsNilBuilder;
  end;

  TTestComplianceRoots = class(TCompliancePolicyTestCase)
  strict private
    // builds the Roots client; skips and returns False where the platform has no OS verifier
    function ConfigOrSkip(const APolicy: ICompliancePolicy; const ARoots: TSystemTrustRoots;
      out AConfig: ITlsClientConfig): Boolean;
    function SourceOf(const AConfig: ITlsClientConfig): TOSVerifierSource;
  published
    procedure TestHostRootsClientKeepsChainInModuleAndFloors;
    procedure TestHostRootsSourceCarriesTheRootsAlone;
    procedure TestOsAndHostRootsSourceCarriesExtraAnchors;
    procedure TestOsRootsSourceCarriesNeither;
    procedure TestRootsClientRejectsNilPolicy;
    procedure TestBuildClientRejectsNilBuilder;
    procedure TestBuildServerRejectsNilBuilder;
  end;

  TTestComplianceMtls = class(TCompliancePolicyTestCase)
  strict private
    // the fake-OS client verification over the test root
    function FakeClientVerification: IClientVerificationBuilder;
    // a verification whose own minimum strength is looser than the rules
    function LooseClientVerification: IClientVerificationBuilder;
    // a store holding a root of the RSA-2048 vector chain
    function WeakClientCa: ITrustAnchorStore;
    // the client-CA builder; skips and returns False without an OS verifier
    function ClientCaOrSkip(const APolicy: ICompliancePolicy; const AClientCa: ITrustAnchorStore;
      out ABuilder: ITlsServerConfigBuilder): Boolean;
    // the live builder; skips and returns False without OS live revocation
    function LiveOrSkip(APosture: TRevocationPosture;
      out ABuilder: ITlsServerConfigBuilder): Boolean;
  published
    procedure TestVerificationOverloadReplacesALooseMinimumStrength;
    procedure TestVerificationOverloadLeavesNoStrengthFinding;
    procedure TestVerificationOverloadCarriesRequired;
    procedure TestVerificationOverloadCarriesRequested;
    procedure TestVerificationOverloadStrictBuildServerAdmits;
    procedure TestVerificationOverloadRejectsModeNone;
    procedure TestVerificationOverloadRejectsNilPolicy;
    procedure TestVerificationOverloadRejectsNilBuilder;
    procedure TestVerificationOverloadRejectsNilVerification;
    procedure TestClientCaOverloadUsesTheOsVerifierSource;
    procedure TestClientCaOverloadKeepsTheChainInModule;
    procedure TestClientCaOverloadLeavesNoStrengthFinding;
    procedure TestClientCaOverloadRejectsNilStore;
    procedure TestClientCaOverloadRejectsEmptyStore;
    procedure TestClientCaOverloadRefusesAWeakCaAtBuild;
    procedure TestClientCaOverloadRaisesWithoutAnOsDelegate;
    procedure TestLiveOverloadDefersToLiveRevocation;
    procedure TestLiveOverloadKeepsThePosture;
    procedure TestLiveOverloadDisclosesTheHostResolver;
    procedure TestLiveOverloadBuildsUnderHard;
    procedure TestLiveOverloadRejectsEmptyStore;
    procedure TestClientCaOverloadRejectsNilPolicyBeforeTheOsSource;
    procedure TestClientCaOverloadRejectsNilBuilderBeforeTheOsSource;
    procedure TestClientCaOverloadRejectsModeNoneBeforeTheOsSource;
    procedure TestLiveOverloadRejectsNilPolicyBeforeTheOsSource;
    procedure TestLiveOverloadRejectsNilBuilderBeforeTheOsSource;
    procedure TestLiveOverloadRejectsModeNoneBeforeTheOsSource;
    procedure TestVerificationOverloadChangesTheCallersBuilderInPlace;
    procedure TestClientCaOverloadSourceNeedsNoLiveVerdict;
    procedure TestLiveOverloadSourceRefusesWithoutTheLiveVerdict;
    procedure TestLiveOverloadSourceAcceptsTheLiveVerdict;
  end;

  TTestComplianceAnchorFloors = class(TCompliancePolicyTestCase)
  strict private
    // whether the OS delegate accepts a path of ALeaf and ARoot under the strength policy of a
    // facade client of APolicy; AFlag replaces the anchor flag when AOverride
    function AcceptsAnchor(const APolicy: ICompliancePolicy; const ALeaf, ARoot: TBytes;
      AOverride, AFlag: Boolean; out AAlert: TTlsAlertDescription): Boolean;
    // Fips140_3 narrowed to the secp384r1 curve alone
    function P384Policy: ICompliancePolicy;
  published
    procedure TestFacadeClientCarriesTheAnchorFlagIntoTheConfig;
    procedure TestFacadeMtlsServerClientVerificationCarriesTheAnchorFlag;
    procedure TestClientWhoseAnchorsAreExemptIsBelowTheRules;
    procedure TestRsa2048AnchorIsRefusedUnderARulesFloorOf3072;
    procedure TestRsa2048AnchorPassesWhenTheFlagIsCleared;
    procedure TestFips140_3AcceptsAnRsa2048Anchor;
    procedure TestAnchorOnACurveOutsideTheListIsRefused;
    procedure TestAnchorOnACurveOutsideTheListPassesWhenTheFlagIsCleared;
    procedure TestFips140_3AcceptsAP256Anchor;
  end;

  /// <summary>The facts the Windows module suites share; it has no tests and is not
  /// registered.</summary>
  TWindowsModuleTestBase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    // facts of a native x64 process on UEFI firmware on a listed release with the system copy
    // of the module
    function ValidFacts(ABuild: UInt32; AProductType: Byte): TWindowsModuleFacts;
    // whether some entry of ADisclosures holds AFragment
    function Lists(const ADisclosures: TArray<string>; const AFragment: string): Boolean;
  end;

  TTestWindowsModuleDecision = class(TWindowsModuleTestBase)
  published
    procedure TestDecide22621WorkstationValidated;
    procedure TestDecide20348ServerValidated;
    procedure TestDecide20348DomainControllerValidated;
    procedure TestDecide22621ServerNotValidated;
    procedure TestDecide22621DomainControllerNotValidated;
    procedure TestDecide20348WorkstationNotValidated;
    procedure TestDecideEmulatedProcessNotValidated;
    procedure TestDecideProcessUnderWow64OnX64NotValidated;
    procedure TestDecide32BitProcessNotValidated;
    procedure TestDecide32BitProcessOnWow64NotValidated;
    procedure TestDecide32BitProcessBeatsUnreadableOs;
    procedure TestDecideNativeArm64NotValidated;
    procedure TestDecideBiosFirmwareNotValidated;
    procedure TestDecideUnreadableFirmwareIsUnknown;
    procedure TestDecideModuleBuildMismatchNotValidated;
    procedure TestDecideModuleMajorMismatchNotValidated;
    procedure TestDecideModuleMinorMismatchNotValidated;
    procedure TestDecideModuleNotSystemCopyNotValidated;
    procedure TestDecideBcryptNotSystemCopyNotValidated;
    procedure TestDecideNcryptNotSystemCopyNotValidated;
    procedure TestDecideUnreadableImportsIsUnknown;
    procedure TestDecideUnreadableNcryptAloneIsUnknown;
    procedure TestDecideOtherBcryptWithUnreadableNcryptIsNotValidated;
    procedure TestDecideOtherNcryptWithUnreadableBcryptIsNotValidated;
    procedure TestDecideWrongMajorNotValidated;
    procedure TestDecideWrongMinorNotValidated;
    procedure TestDecideWrongPlatformNotValidated;
    procedure TestDecide26100NotValidated;
    procedure TestDecide22631NotValidated;
    procedure TestDecideUnlistedBuildNotValidated;
    procedure TestDecideUnreadableOsIsUnknown;
    procedure TestDecideUnreadableMachinesIsUnknown;
    procedure TestDecideUnreadableSystemDirectoryIsUnknown;
    procedure TestDecideUnreadablePathIsUnknown;
    procedure TestDecideUnreadableVersionIsUnknown;
    procedure TestDecideOnTheSunsetDayIsStillValidated;
    procedure TestDecideAfterTheSunsetDayIsHistorical;
    procedure TestDecideUnreadableDateIsUnknown;
    procedure TestDecideSunsetDoesNotOutweighAMismatch;
    procedure TestDecideMismatchBeatsUnreadable;
    procedure TestDecideModuleRevisionDoesNotDecide;
    procedure TestDecideEditionDoesNotDecide;
    procedure TestDecideReasonsAreDistinct;
    procedure TestFirmwareNames;
    procedure TestEditionCoverageOfTheListedWorkstationEditions;
    procedure TestEditionCoverageOfTheListedServerEditions;
    procedure TestEditionCoverageOfAnUnlistedEditionIsUntested;
    procedure TestEditionCoverageOfAnUnreadEditionIsUnread;
    procedure TestEditionCoverageOfAReleaseWithNoListHasNoTestedList;
    procedure TestEditionCoverageIsPerRelease;
    procedure TestEditionCoverageDoesNotMatchAcrossTwoEditions;
    procedure TestDisclosuresOfAValidatedStatusNameTheHardware;
    procedure TestDisclosuresOfAnotherStatusAreEmpty;
    procedure TestDisclosuresOfATestedEditionNameNoEdition;
    procedure TestDisclosuresNameAnEditionOutsideTheTestedList;
    procedure TestDisclosuresNameTheAzureEditionsByTheirOsNames;
    procedure TestDisclosuresNameAnUnreadEdition;
    procedure TestDisclosuresOfAReleaseWithNoListNameNoEdition;
    procedure TestTableValidated22621And20348;
    procedure TestTableNotValidated26100_22631_19045;
    procedure TestValidatedRowsCarryTheirStandardLevelAndDates;
    procedure TestNotValidatedRowsHaveNoCertificate;
    procedure TestLookupMissesUnlistedBuild;
  end;

{$IFDEF TLSLIB_MSWINDOWS}
  TTestWindowsModuleAttestation = class(TWindowsModuleTestBase)
  published
    procedure TestDescribePrintsTheReason;
    procedure TestDescribeOfUnreadableOsIsTheReason;
    procedure TestDescribeOfValidatedFacts;
    procedure TestIdentityCarriesTheFacts;
    procedure TestIdentityOfUnreadableOsKeepsTheOtherFacts;
    procedure TestIdentityOfUnreadVersionHasNoFileVersion;
    procedure TestIdentityOfNotValidatedRowHasNoListedVersion;
    procedure TestIdentityNamesTheCertificateOnlyWhenValidated;
    procedure TestHistoricalModuleCitesNoCertificate;
    procedure TestAttestedIdentityIsMarkedAttested;
    procedure TestGatheredDateIsToday;
    procedure TestCoversTheOsCompositionOnly;
    procedure TestGatheredFactsDescribeThisProcess;
    procedure TestParseFileVersionReadsTheLeadingNumbers;
    procedure TestParseFileVersionRefusesOtherText;
    procedure TestGatheredModuleIsTheSystemCopy;
    procedure TestGatheredImportsAreTheSystemCopies;
    procedure TestGatheredEditionAndFirmware;
    procedure TestRealProcessFactsDecideByProcess;
    procedure TestReadsBuildAndModuleVersion;
    procedure TestDescribeNamesNoStandardWhenNotValidated;
    procedure TestStatusFollowsTheTable;
    procedure TestDescribeNamesTheOutcome;
    procedure TestAttestedDisclosuresFollowTheStatus;
    procedure TestCreatedAttestationDisclosesWhenItIsValidated;
  end;

  TTestWindowsCompliance = class(TCompliancePolicyTestCase)
  strict private
    // whether the build is validated; otherwise skips, or fails where the leg must validate
    function ValidatedAttestationOrSkip(out AAttestation: IModuleAttestation): Boolean;
  published
    procedure TestStrictPassesOnValidatedBuild;
    procedure TestStrictTls12OnlyRulesAreCompliantOnValidatedBuild;
    procedure TestStrictRaisesNotValidatedOnOtherBuilds;
    procedure TestRelaxedReportsNotValidatedOnOtherBuilds;
    procedure TestOsVerifierClientKeepsStrengthFloors;
    procedure TestLiveClientKeepsStrengthFloors;
    procedure TestLiveClientCarriesTheHostRootsAlone;
    procedure TestLiveClientCarriesNoHostRootsForOsRoots;
    procedure TestHostKeyListingTheMarkerIsOutsideTheModule;
    procedure TestOsImportedKeyIsInsideTheModule;
  end;
{$ENDIF TLSLIB_MSWINDOWS}

implementation

type
  // a host class that lists the ticket-keys marker and names a policy, without checking
  TClaimingTicketKeys = class sealed(TInterfacedObject, ISessionTicketKeyManager,
    IComplianceTicketKeys)
  strict private
  var
    FPolicy: ICompliancePolicy;
  public
    constructor Create(const APolicy: ICompliancePolicy);
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyNameLength: Int32;
    function Policy: ICompliancePolicy;
    function LifetimeSeconds: UInt32;
    function FleetScope: TBytes;
  end;

  // a host attestation that is validated on the first read and not validated after it, and counts
  // what it is asked
  TFlippingAttestation = class sealed(TInterfacedObject, IModuleAttestation)
  strict private
  var
    FIdentityReads: Int32;
    FStatusReads: Int32;
    FDescribeReads: Int32;
    FDisclosureReads: Int32;
  public
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
    function Covers(const ACrypto: ICryptoProvider): Boolean;
    function Disclosures: TArray<string>;
    property IdentityReads: Int32 read FIdentityReads;
    property StatusReads: Int32 read FStatusReads;
    property DescribeReads: Int32 read FDescribeReads;
    property DisclosureReads: Int32 read FDisclosureReads;
  end;

  // a host class that lists the checked-resolver marker and names a policy, without checking
  TClaimingResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver,
    IComplianceCredentialResolver)
  strict private
  var
    FPolicy: ICompliancePolicy;
    FInner: ITlsServerCredentialResolver;
  public
    constructor Create(const APolicy: ICompliancePolicy;
      const AInner: ITlsServerCredentialResolver);
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
    function Policy: ICompliancePolicy;
    function Inner: ITlsServerCredentialResolver;
  end;

resourcestring
  SBranchNotValidated = 'build %d is not validated; the validated branch does not apply';
  SBranchValidated = 'build %d is validated; the not-validated branch does not apply';
  SExpectedValidated = 'build %d is not validated but this leg must run the validated path';

{ TFlippingAttestation }

function TFlippingAttestation.Identity: TModuleIdentity;
begin
  Inc(FIdentityReads);
  Result := Default(TModuleIdentity);
  Result.OsVersion := '10.0.1';
end;

function TFlippingAttestation.Status(AStandard: TModuleStandard): TModuleStatus;
begin
  Inc(FStatusReads);
  if FStatusReads = 1 then
    Result := TModuleStatus.Validated
  else
    Result := TModuleStatus.NotValidated;
end;

function TFlippingAttestation.Describe: string;
begin
  Inc(FDescribeReads);
  Result := 'flipping attestation';
end;

function TFlippingAttestation.Covers(const ACrypto: ICryptoProvider): Boolean;
begin
  Result := True;
end;

function TFlippingAttestation.Disclosures: TArray<string>;
begin
  Inc(FDisclosureReads);
  Result := nil;
end;

{ TClaimingTicketKeys }

constructor TClaimingTicketKeys.Create(const APolicy: ICompliancePolicy);
begin
  inherited Create;
  FPolicy := APolicy;
end;

function TClaimingTicketKeys.CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
begin
  AKeyName := nil;
  AKey := nil;
  Result := False;
end;

function TClaimingTicketKeys.KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
begin
  AKey := nil;
  Result := False;
end;

function TClaimingTicketKeys.KeyNameLength: Int32;
begin
  Result := 16;
end;

function TClaimingTicketKeys.Policy: ICompliancePolicy;
begin
  Result := FPolicy;
end;

function TClaimingTicketKeys.LifetimeSeconds: UInt32;
begin
  Result := 7200;
end;

function TClaimingTicketKeys.FleetScope: TBytes;
begin
  Result := nil;
end;

{ TClaimingResolver }

constructor TClaimingResolver.Create(const APolicy: ICompliancePolicy;
  const AInner: ITlsServerCredentialResolver);
begin
  inherited Create;
  FPolicy := APolicy;
  FInner := AInner;
end;

function TClaimingResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  ACredential := Default(TTlsCredential);
  Result := False;
end;

function TClaimingResolver.Policy: ICompliancePolicy;
begin
  Result := FPolicy;
end;

function TClaimingResolver.Inner: ITlsServerCredentialResolver;
begin
  Result := FInner;
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

function TCompliancePolicyTestCase.SystemBaseWithKey: ICryptoProvider;
var
  LKey: ISigningKey;
  LReport: TFakeBackendReport;
begin
  // the key must expose the public key of the leaf it signs for
  LKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256), Pkix.Certificates.Parse(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert')).PublicKeyInfo)
    as ISigningKey;
  // the module serves the TLS 1.2 PRF, as the Windows module does
  LReport := TFakeBackendReport.Create([]);
  LReport.NativePrf := True;
  Result := TComplianceFakes.FakeSystemBase(LReport as ICryptoBackendReport,
    TFakeSigningCrypto.Create(LKey, True) as ISigningCrypto, nil);
end;

function TCompliancePolicyTestCase.Tls12OnlyRules: TComplianceRules;
begin
  Result := TCompliancePresets.Fips140_3;
  Result.Versions := TArray<UInt16>.Create(TlsWireVersionTls12);
  Result.CipherSuites := TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes256GcmSha384, TCipherSuites12.EcdheRsaAes128GcmSha256,
    TCipherSuites12.EcdheRsaAes256GcmSha384);
end;

function TCompliancePolicyTestCase.Attestation(AStatus: TModuleStatus): IModuleAttestation;
begin
  Result := TFakeModuleAttestation.Create(AStatus, Identity) as IModuleAttestation;
end;

function TCompliancePolicyTestCase.UncoveredAttestation: IModuleAttestation;
var
  LFake: TFakeModuleAttestation;
begin
  LFake := TFakeModuleAttestation.Create(TModuleStatus.Validated, Identity);
  LFake.Covered := False;
  Result := LFake as IModuleAttestation;
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

function TCompliancePolicyTestCase.Tls13Profile: TTlsConfigProfile;
begin
  Result := TTlsConfigProfile.Default;
  Result.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  Result.SignatureSchemes := TSignatureSchemeRegistry.CreateDefault;
  Result.NamedGroups := TNamedGroups.CreateDefaultRegistry(Crypto);
  Result.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
  Result.PreferredGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
end;

function TCompliancePolicyTestCase.RawServer(
  const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
begin
  Result := TTlsConfigBuilder.CreateFromProfile(APolicy.Crypto, APolicy.Pkix,
    Tls13Profile).Server;
end;

function TCompliancePolicyTestCase.MtlsServerBuilder(const APolicy: ICompliancePolicy;
  APosture: TRevocationPosture): ITlsServerConfigBuilder;
begin
  Result := TComplianceTls.WithPeerAuth(APolicy, ServerBuilder(APolicy),
    TClientAuthMode.Required, TClientVerification.VerifierSource(
    TFakeOsVerifierSources.Client,
    TTlsLibTestCertificates.EcP256RootStore).WithRevocation(APosture));
end;

function TCompliancePolicyTestCase.Disclosed(const AReport: IComplianceReport;
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

function TCompliancePolicyTestCase.Aes128Policy: ICompliancePolicy;
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

function TCompliancePolicyTestCase.ClientBuilder(
  const APolicy: ICompliancePolicy): ITlsClientConfigBuilder;
begin
  Result := TComplianceTls.Client(APolicy, TServerVerification.VerifierSource(
    TFakeOsVerifierSources.Server));
end;

function TCompliancePolicyTestCase.ServerBuilder(
  const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
begin
  Result := TComplianceTls.Server(APolicy, ServerCredential(APolicy.Crypto));
end;

function TCompliancePolicyTestCase.Tls13OnlyServerBuilder(
  const APolicy: ICompliancePolicy): ITlsServerConfigBuilder;
begin
  Result := ServerBuilder(APolicy);
  Result.Tls12.WithExtendedMasterSecret(False);
  Result.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
end;

function TCompliancePolicyTestCase.MarkedKeyCredential(const ACrypto: ICryptoProvider;
  const ASchemes: TArray<TSignatureScheme>): TTlsCredential;
begin
  Result := ServerCredential(ACrypto);
  Result.PrivateKey := TFakeSystemSigningKey.Create(ASchemes,
    Result.PrivateKey.PublicKeyInfo) as ISigningKey;
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
    NewPolicy(ARules, TComplianceFakes.SystemOver([]), TModuleStatus.Validated, AEnforcement);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestCompliancePolicy.DisclosesRevision(AStatus: TModuleStatus;
  const AFileVersion, AListedVersion: string): Boolean;
var
  LIdentity: TModuleIdentity;
  LPolicy: ICompliancePolicy;
begin
  LIdentity := Identity;
  LIdentity.ModuleFileVersion := AFileVersion;
  LIdentity.ListedModuleVersion := AListedVersion;
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TComplianceFakes.SystemOver([]), Pkix,
    TFakeModuleAttestation.Create(AStatus, LIdentity) as IModuleAttestation,
    TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  Result := Disclosed(LPolicy.PlatformReport, AFileVersion + ' differs from the ' +
    AListedVersion);
end;

procedure TTestCompliancePolicy.TestListedModuleVersionDifferingIsDisclosed;
begin
  CheckTrue(DisclosesRevision(TModuleStatus.Validated, '10.0.20348.2000', '10.0.20348.30000'),
    'the revision is disclosed');
end;

procedure TTestCompliancePolicy.TestListedModuleVersionMatchingIsNotDisclosed;
begin
  CheckFalse(DisclosesRevision(TModuleStatus.Validated, '10.0.20348.30000',
    '10.0.20348.30000'), 'nothing to disclose');
end;

procedure TTestCompliancePolicy.TestNoListedModuleVersionIsNotDisclosed;
begin
  CheckFalse(DisclosesRevision(TModuleStatus.Validated, '10.0.20348.2000', ''),
    'a module with no listed version has nothing to differ from');
end;

procedure TTestCompliancePolicy.TestNotValidatedModuleVersionIsNotDisclosed;
begin
  CheckFalse(DisclosesRevision(TModuleStatus.NotValidated, '10.0.20348.2000',
    '10.0.20348.30000'), 'the finding says it; a disclosure would be noise');
end;

procedure TTestCompliancePolicy.TestCnsa1DisclosesTheInternalSha256;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Cnsa1, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Strict);
  CheckTrue(Disclosed(LPolicy.PlatformReport, 'SHA-256 runs in the module'),
    'the rules hold SHA-384 only, so the engine''s own SHA-256 is stated');
  CheckTrue(Disclosed(LPolicy.PlatformReport, 'HelloRetryRequest cookie'), 'with its uses');
end;

procedure TTestCompliancePolicy.TestFips140_3DoesNotDiscloseTheInternalSha256;
begin
  CheckFalse(Disclosed(StrictPolicy.PlatformReport, 'SHA-256 runs in the module'),
    'the rules already hold SHA-256');
end;

procedure TTestCompliancePolicy.TestStrictCnsa1Sha256OutsideTheModuleRaises;
var
  LReport: TFakeBackendReport;
  LFindings: TArray<TComplianceFinding>;
begin
  LReport := TFakeBackendReport.Create([]);
  LReport.PortableHashes := [THashAlgorithm.SHA_256];
  CheckTrue(Construct(TCompliancePresets.Cnsa1, TComplianceFakes.FakeSystemBase(
    LReport as ICryptoBackendReport, nil, nil), TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings),
    'the rules never name SHA-256, but the engine uses it');
  CheckEquals('hash SHA_256', FindingOfKind(LFindings,
    TComplianceFindingKind.AlgorithmOutsideModule).Subject, 'which one');
end;

procedure TTestCompliancePolicy.TestStrictCnsa1Sha256HmacOutsideTheModuleRaises;
var
  LReport: TFakeBackendReport;
  LFindings: TArray<TComplianceFinding>;
begin
  LReport := TFakeBackendReport.Create([]);
  LReport.PortableHmacs := [THashAlgorithm.SHA_256];
  CheckTrue(Construct(TCompliancePresets.Cnsa1, TComplianceFakes.FakeSystemBase(
    LReport as ICryptoBackendReport, nil, nil), TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'the cookie MAC is an HMAC');
  CheckEquals('HMAC SHA_256', FindingOfKind(LFindings,
    TComplianceFindingKind.AlgorithmOutsideModule).Subject, 'which one');
end;

procedure TTestCompliancePolicy.TestStrictCnsa1IgnoresSha512OutsideTheModule;
var
  LReport: TFakeBackendReport;
  LFindings: TArray<TComplianceFinding>;
begin
  LReport := TFakeBackendReport.Create([]);
  LReport.PortableHashes := [THashAlgorithm.SHA_512];
  CheckFalse(Construct(TCompliancePresets.Cnsa1, TComplianceFakes.FakeSystemBase(
    LReport as ICryptoBackendReport, nil, nil), TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'no listed scheme or suite digests with SHA-512');
end;

function TTestCompliancePolicy.DisclosingPolicy(AStatus: TModuleStatus;
  const ADisclosures: TArray<string>; AEnforcement: TComplianceEnforcement): ICompliancePolicy;
var
  LFake: TFakeModuleAttestation;
begin
  LFake := TFakeModuleAttestation.Create(AStatus, Identity);
  LFake.Disclosed := ADisclosures;
  Result := TCompliancePolicy.Create(TCompliancePresets.Fips140_3, SystemBaseWithKey, Pkix,
    LFake as IModuleAttestation, AEnforcement) as ICompliancePolicy;
end;

function TTestCompliancePolicy.PortableHmacPolicy(const ARules: TComplianceRules;
  ANativePrf: Boolean): ICompliancePolicy;
var
  LReport: TFakeBackendReport;
begin
  LReport := TFakeBackendReport.Create([]);
  LReport.PortableHmacs := [Low(THashAlgorithm) .. High(THashAlgorithm)];
  LReport.NativePrf := ANativePrf;
  Result := NewPolicy(ARules, TComplianceFakes.FakeSystemBase(LReport as ICryptoBackendReport,
    nil, nil), TModuleStatus.Validated, TComplianceEnforcement.Relaxed);
end;

function TTestCompliancePolicy.ModuleReportPolicy(const ARules: TComplianceRules;
  AEnforcement: TComplianceEnforcement): ICompliancePolicy;
begin
  Result := NewPolicy(ARules, TComplianceFakes.FakeSystemBase(
    TFakeVerifierReport.Create(True) as ICryptoBackendReport, nil, nil), TModuleStatus.Validated,
    AEnforcement);
end;

procedure TTestCompliancePolicy.TestRelaxedPolicyDisclosesThatPortableCodeIsNotRefused;
begin
  CheckTrue(Disclosed(RelaxedPolicy.PlatformReport,
    'relaxed mode reports platform facts but does not refuse portable code'),
    'the relaxed verdict says what it does not see');
  CheckTrue(Disclosed(RelaxedPolicy.PlatformReport,
    'per-connection fallbacks to portable code are not reflected in the verdict'),
    'including the fallbacks');
end;

procedure TTestCompliancePolicy.TestStrictPolicyDoesNotDiscloseThePortableCodeLimit;
begin
  CheckFalse(Disclosed(StrictPolicy.PlatformReport, 'does not refuse portable code'),
    'strict refuses portable code, so there is nothing to bound');
end;

procedure TTestCompliancePolicy.TestRelaxedDisclosureReachesAConfigReport;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Build),
    'does not refuse portable code'), 'a client report');
  CheckTrue(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build),
    'does not refuse portable code'), 'a server report');
end;

procedure TTestCompliancePolicy.TestGcmRulesDiscloseTheIvConstruction;
begin
  CheckTrue(Disclosed(NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Strict).PlatformReport,
    'GCM IV fixed field and counter'), 'Fips140_3, strict');
  CheckTrue(Disclosed(NewPolicy(TCompliancePresets.Cnsa1, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Strict).PlatformReport,
    'GCM IV fixed field and counter'), 'Cnsa1, strict');
  CheckTrue(Disclosed(NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Relaxed).PlatformReport,
    'GCM IV fixed field and counter'), 'relaxed');
  CheckTrue(Disclosed(NewPolicy(Tls12OnlyRules, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Strict).PlatformReport,
    'GCM IV fixed field and counter'), 'TLS 1.2 rules');
end;

procedure TTestCompliancePolicy.TestIvDisclosureNamesTheCounterAndTheStandards;
var
  LReport: IComplianceReport;
begin
  LReport := StrictPolicy.PlatformReport;
  CheckTrue(Disclosed(LReport, 'TLS 1.2 nonce_explicit = record sequence number'), 'TLS 1.2');
  CheckTrue(Disclosed(LReport, 'TLS 1.3 write_iv XOR sequence number'), 'TLS 1.3');
  CheckTrue(Disclosed(LReport, 'RFC 5288 / RFC 8446 section 5.3'), 'the RFCs');
  CheckTrue(Disclosed(LReport, 'IG C.H scenario 1(a), SP section 2.7.1'), 'the module documents');
  CheckTrue(Disclosed(LReport, 'counter exhaustion forces a key update or close, and keys are ' +
    'ephemeral per session'), 'exhaustion');
end;

procedure TTestCompliancePolicy.TestGcmDisclosureCitesScenario1aAfterTheConstruction;
var
  LDisclosures: TArray<string>;
  LI: Int32;
  LText: string;
begin
  LDisclosures := StrictPolicy.PlatformReport.Disclosures;
  LText := '';
  for LI := 0 to System.Length(LDisclosures) - 1 do
    if Pos('GCM IV fixed field and counter', LDisclosures[LI]) > 0 then
      LText := LDisclosures[LI];
  CheckTrue(LText <> '', 'not vacuous: the disclosure is present');
  CheckTrue(Pos('RFC 8446 section 5.3 (IG C.H scenario 1(a), SP section 2.7.1); the module ' +
    'offers no interface to generate or check the counter', LText) > 0,
    'the cite follows the construction sentence');
  CheckTrue(LText[System.Length(LText)] <> '.', 'no closing period');
  CheckTrue((LText[1] >= 'a') and (LText[1] <= 'z'), 'no initial capital');
end;

procedure TTestCompliancePolicy.TestIvDisclosureReachesAConfigReport;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Build),
    'GCM IV fixed field and counter'), 'a client report');
  CheckTrue(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build),
    'GCM IV fixed field and counter'), 'a server report');
  CheckTrue(Disclosed(LPolicy.EvaluateCredential(ServerCredential(LPolicy.Crypto)),
    'GCM IV fixed field and counter'), 'a credential report');
end;

procedure TTestCompliancePolicy.TestIvDisclosureLeavesTheVerdictAlone;
var
  LReport: IComplianceReport;
begin
  LReport := NewPolicy(Tls12OnlyRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport;
  CheckTrue(Disclosed(LReport, 'GCM IV fixed field and counter'), 'disclosed');
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'and still Compliant');
end;

procedure TTestCompliancePolicy.TestPolicyAppendsTheAttestationDisclosures;
var
  LReport: IComplianceReport;
begin
  LReport := DisclosingPolicy(TModuleStatus.Validated, TArray<string>.Create('first fact',
    'second fact'), TComplianceEnforcement.Strict).PlatformReport;
  CheckTrue(Disclosed(LReport, 'first fact'), 'the first');
  CheckTrue(Disclosed(LReport, 'second fact'), 'the second');
end;

procedure TTestCompliancePolicy.TestPolicyAppendsTheAttestationDisclosuresWhateverTheStatus;
begin
  CheckTrue(Disclosed(DisclosingPolicy(TModuleStatus.NotValidated,
    TArray<string>.Create('host fact'), TComplianceEnforcement.Relaxed).PlatformReport,
    'host fact'), 'the policy does not judge which disclosures an attestation gives');
end;

procedure TTestCompliancePolicy.TestAttestationDisclosuresReachAConfigReport;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := DisclosingPolicy(TModuleStatus.Validated, TArray<string>.Create('host fact'),
    TComplianceEnforcement.Strict);
  CheckTrue(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Build), 'host fact'),
    'a client report');
  CheckTrue(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build), 'host fact'),
    'a server report');
  CheckTrue(Disclosed(LPolicy.EvaluateCredential(ServerCredential(LPolicy.Crypto)), 'host fact'),
    'a credential report');
end;

procedure TTestCompliancePolicy.TestAttestationWithoutDisclosuresAddsNone;
var
  LReport: IComplianceReport;
begin
  LReport := StrictPolicy.PlatformReport;
  CheckFalse(Disclosed(LReport, 'hypervisor'), 'no hardware disclosure of its own');
  CheckFalse(Disclosed(LReport, 'edition'), 'no edition disclosure of its own');
  CheckFalse(Disclosed(LReport, 'vendor-affirmed'), 'no vendor affirmation of its own');
end;

procedure TTestCompliancePolicy.TestAttestationDisclosuresNeverRefuseAStrictPolicy;
begin
  CheckEquals(Ord(TModuleStatus.Validated), Ord(DisclosingPolicy(TModuleStatus.Validated,
    TArray<string>.Create('host fact'), TComplianceEnforcement.Strict).PlatformReport.ModuleStatus),
    'a disclosure never decides');
end;

procedure TTestCompliancePolicy.TestExporterDisclosureIsOnAPlatformReportOfferingTls12;
begin
  CheckTrue(Disclosed(StrictPolicy.PlatformReport, 'TLS 1.2 exporter derivations (RFC 5705) ' +
    'are composed over the module HMAC; only the key-schedule derivations are module services'),
    'both versions');
  CheckTrue(Disclosed(NewPolicy(Tls12OnlyRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport, 'TLS 1.2 exporter derivations'),
    'TLS 1.2 alone');
end;

procedure TTestCompliancePolicy.TestExporterDisclosureIsOnAConfigReportOfferingTls12;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(ClientBuilder(LPolicy).Build),
    'TLS 1.2 exporter derivations'), 'a client report');
  CheckTrue(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build),
    'TLS 1.2 exporter derivations'), 'a server report');
end;

procedure TTestCompliancePolicy.TestExporterDisclosureIsOnACredentialReport;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.EvaluateCredential(ServerCredential(LPolicy.Crypto)),
    'TLS 1.2 exporter derivations'), 'judged by the versions of the rules');
end;

procedure TTestCompliancePolicy.TestExporterDisclosureIsAbsentWhenTls12IsNotOffered;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsClientConfigBuilder;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  CheckFalse(Disclosed(NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport, 'TLS 1.2 exporter derivations'),
    'rules that offer TLS 1.3 alone');
  LPolicy := StrictPolicy;
  LBuilder := ClientBuilder(LPolicy);
  // the facade's TLS 1.2 setting is taken back, as the builder refuses it without TLS 1.2
  LBuilder.Tls12.WithExtendedMasterSecret(False);
  CheckFalse(Disclosed(LPolicy.Evaluate(LBuilder.WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls13)).Build), 'TLS 1.2 exporter derivations'),
    'a config that offers TLS 1.3 alone, under rules that offer both');
  CheckFalse(Disclosed(LPolicy.Evaluate(Tls13OnlyServerBuilder(LPolicy).Build),
    'TLS 1.2 exporter derivations'), 'and a server config');
end;

procedure TTestCompliancePolicy.TestExporterDisclosureLeavesTheVerdictAlone;
var
  LReport: IComplianceReport;
begin
  LReport := NewPolicy(Tls12OnlyRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport;
  CheckTrue(Disclosed(LReport, 'TLS 1.2 exporter derivations'), 'disclosed');
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'and still Compliant');
  CheckTrue(LReport.KeyDerivationInModule, 'and the key-schedule derivations are in the module');
end;

procedure TTestCompliancePolicy.TestExporterIsDisclosedRefusedUnderStrictRequireModule;
var
  LRules: TComplianceRules;
begin
  LRules := Tls12OnlyRules;
  LRules.Kdf := TKdfRule.RequireModule;
  CheckTrue(Disclosed(NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport, 'TLS 1.2 exporter derivations (RFC 5705) ' +
    'are refused: the rules require every key derivation to be a module service'),
    'the exporter is refused, and the report says so');
end;

procedure TTestCompliancePolicy.TestExporterIsNotDisclosedComposedUnderStrictRequireModule;
var
  LRules: TComplianceRules;
begin
  LRules := Tls12OnlyRules;
  LRules.Kdf := TKdfRule.RequireModule;
  CheckFalse(Disclosed(NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport, 'are composed over the module HMAC'),
    'a refused exporter is not composed');
end;

procedure TTestCompliancePolicy.TestExporterIsDisclosedComposedUnderRelaxedRequireModule;
var
  LRules: TComplianceRules;
begin
  LRules := Tls12OnlyRules;
  LRules.Kdf := TKdfRule.RequireModule;
  CheckTrue(Disclosed(NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed).PlatformReport, 'are composed over the module HMAC'),
    'relaxed mode refuses no exporter');
end;

procedure TTestCompliancePolicy.TestExporterIsDisclosedComposedUnderStrictAllowComposed;
var
  LRules: TComplianceRules;
  LReport: IComplianceReport;
begin
  LRules := Tls12OnlyRules;
  LRules.Kdf := TKdfRule.AllowComposed;
  LReport := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport;
  CheckTrue(Disclosed(LReport, 'are composed over the module HMAC'), 'composed');
  CheckFalse(Disclosed(LReport, 'are refused'), 'and not refused');
end;

procedure TTestCompliancePolicy.
  TestExporterDisclosureIsAbsentUnderRelaxedRequireModuleWithoutTls12;
var
  LRules: TComplianceRules;
  LReport: IComplianceReport;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  LRules.Kdf := TKdfRule.RequireModule;
  LReport := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed).PlatformReport;
  CheckFalse(Disclosed(LReport, 'are composed over the module HMAC'), 'not composed');
  CheckFalse(Disclosed(LReport, 'are refused'), 'and not refused');
end;

procedure TTestCompliancePolicy.TestPortableKdfIsNotAModuleService;
var
  LReport: IComplianceReport;
begin
  LReport := PortableHmacPolicy(Tls12OnlyRules, False).PlatformReport;
  CheckFalse(LReport.KeyDerivationInModule, 'the PRF runs in portable code');
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict),
    'and its backend is a finding');
end;

procedure TTestCompliancePolicy.TestModulePrfBesidePortableHmacIsAModuleService;
begin
  CheckTrue(PortableHmacPolicy(Tls12OnlyRules, True).PlatformReport.KeyDerivationInModule,
    'a PRF the report places in the module counts whatever the HMAC is');
end;

procedure TTestCompliancePolicy.TestHkdfIsOutsideTheModuleWhateverTheReportNames;
var
  LReport: IComplianceReport;
begin
  LReport := ModuleReportPolicy(TCompliancePresets.Fips140_3,
    TComplianceEnforcement.Strict).PlatformReport;
  CheckFalse(LReport.KeyDerivationInModule, 'the policy assembles HKDF over its own HMAC');
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LReport.Verdict), 'verdict');
end;

procedure TTestCompliancePolicy.TestHkdfOutsideTheModuleStillLeavesTls12OnlyRulesCompliant;
begin
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(ModuleReportPolicy(Tls12OnlyRules,
    TComplianceEnforcement.Strict).PlatformReport.Verdict), 'no HKDF runs');
end;

procedure TTestCompliancePolicy.TestRequireModuleRefusesHkdfWhateverTheReportNames;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
  LRaised: Boolean;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Kdf := TKdfRule.RequireModule;
  LRaised := False;
  LFindings := nil;
  try
    ModuleReportPolicy(LRules, TComplianceEnforcement.Strict);
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      LFindings := E.Findings;
    end;
  end;
  CheckTrue(LRaised, 'strict refuses it');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.KdfOutsideModule), 'as a derivation');
end;

procedure TTestCompliancePolicy.TestRsaRangeWithMinAboveMaxRaisesArgumentInBothModes;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.Strength.MinRsaModulusBits := 4096;
  LRules.Strength.MaxRsaModulusBits := 3072;
  LRules.RsaModulusBits := TArray<UInt32>.Create(3072);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'strict');
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Relaxed), 'relaxed');
end;

procedure TTestCompliancePolicy.TestRsaSizesOutsideTheRangeRaiseArgumentInBothModes;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.Strength.MaxRsaModulusBits := 3072;
  LRules.RsaModulusBits := TArray<UInt32>.Create(4096);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'strict');
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Relaxed), 'relaxed');
  LRules.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
  CheckFalse(ArgumentRefused(LRules, TComplianceEnforcement.Strict),
    'a listed size inside the range keeps the rules runnable');
end;

procedure TTestCompliancePolicy.TestRsaRangeMessageNeedsAtLeastOneListedSize;
var
  LRules: TComplianceRules;
  LMessage: string;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.Strength.MaxRsaModulusBits := 3072;
  LRules.RsaModulusBits := TArray<UInt32>.Create(4096);
  LMessage := '';
  try
    NewPolicy(LRules, TComplianceFakes.SystemOver([]), TModuleStatus.Validated,
      TComplianceEnforcement.Strict);
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals('the rules must hold a non-empty RSA modulus range that contains at least one ' +
    'exact size they list', LMessage, 'the sizes are met by one, not by all');
end;

procedure TTestCompliancePolicy.TestNotValidatedModuleKeepsNoCertificate;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.NotValidated, TComplianceEnforcement.Relaxed);
  CheckEquals('', LPolicy.PlatformReport.Module.Certificate,
    'a certificate means something only while the module is validated');
end;

procedure TTestCompliancePolicy.TestNotValidatedReportPrintsNoCertificate;
var
  LReport: IComplianceReport;
begin
  LReport := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.NotValidated, TComplianceEnforcement.Relaxed).PlatformReport;
  CheckEquals(0, Pos('5410', LReport.Describe), 'not in the description either');
end;

procedure TTestCompliancePolicy.TestValidatedReportPrintsTheCertificate;
begin
  CheckTrue(Pos('certificate 5410', StrictPolicy.PlatformReport.Describe) > 0,
    'a validated module names its certificate');
  CheckEquals('5410', StrictPolicy.PlatformReport.Module.Certificate, 'and keeps it');
end;

procedure TTestCompliancePolicy.TestStrictFakeValidatedSystemConstructs;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LPolicy.PlatformReport.Verdict),
    'TLS 1.3 key derivation is composed outside the module');
  CheckEquals('Fips140_3', LPolicy.PlatformReport.Preset, 'the rules name their preset');
end;

procedure TTestCompliancePolicy.TestCnsa1NamesItsPreset;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Cnsa1, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Strict);
  CheckEquals('Cnsa1', LPolicy.PlatformReport.Preset, 'the tightest preset');
end;

procedure TTestCompliancePolicy.TestStrictNotValidatedRaises;
var
  LFindings: TArray<TComplianceFinding>;
begin
  CheckTrue(Construct(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.NotValidated, TComplianceEnforcement.Strict, LFindings), 'strict refuses');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ModuleNotValidated), 'names the module');
end;

procedure TTestCompliancePolicy.TestRelaxedNotValidatedReports;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.NotValidated, TComplianceEnforcement.Relaxed);
  CheckTrue(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.ModuleNotValidated),
    'the finding is reported');
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LPolicy.PlatformReport.Verdict),
    'and is never silent');
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(LPolicy.PlatformReport.ModuleStatus),
    'the status is carried');
end;

procedure TTestCompliancePolicy.TestRelaxedUncoveredCryptoReportsItAndEverythingOutside;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TComplianceFakes.SystemOver([]), Pkix,
    UncoveredAttestation, TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  LReport := LPolicy.PlatformReport;
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CryptoNotCovered), 'the kind');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.NoBackendReport),
    'the base does report');
  CheckEquals('random generator', FindingOfKind(LReport.Findings,
    TComplianceFindingKind.AlgorithmOutsideModule).Subject,
    'the base report is not believed, so one portable report decides');
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict), 'verdict');
end;

procedure TTestCompliancePolicy.TestStrictUncoveredCryptoRaises;
var
  LFindings: TArray<TComplianceFinding>;
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LRaised := False;
  LFindings := nil;
  try
    LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
      TComplianceFakes.SystemOver([]), Pkix, UncoveredAttestation,
      TComplianceEnforcement.Strict) as ICompliancePolicy;
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      LFindings := E.Findings;
    end;
  end;
  CheckTrue(LRaised, 'strict refuses a provider the module does not serve');
  CheckEquals(Ord(TComplianceFindingCategory.Platform), Ord(FindingOfKind(LFindings,
    TComplianceFindingKind.CryptoNotCovered).Category), 'it is a platform finding');
end;

procedure TTestCompliancePolicy.TestCoveredCryptoHasNoCoverageFinding;
begin
  CheckFalse(ReportHasKind(StrictPolicy.PlatformReport, TComplianceFindingKind.CryptoNotCovered),
    'a covered provider');
end;

procedure TTestCompliancePolicy.TestHostAttestationIsDisclosedAndNotAttested;
var
  LIdentity: TModuleIdentity;
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LIdentity := Identity;
  LIdentity.Attested := True;
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TComplianceFakes.SystemOver([]), Pkix,
    TFakeModuleAttestation.Create(TModuleStatus.Validated, LIdentity) as IModuleAttestation,
    TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  LReport := LPolicy.PlatformReport;
  CheckTrue(Disclosed(LReport, 'attestation is supplied by the host'), 'disclosed');
  CheckFalse(LReport.Module.Attested, 'the host cannot claim the library attested it');
end;

procedure TTestCompliancePolicy.TestPlatformAttestationIsNotDisclosedAsHost;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TComplianceFakes.SystemOver([]), Pkix,
    TOSModuleAttestation.Current, TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  CheckFalse(Disclosed(LPolicy.PlatformReport, 'supplied by the host'),
    'the library''s own class');
end;

procedure TTestCompliancePolicy.TestIsPlatformIsAClassCheck;
begin
  CheckTrue(TOSModuleAttestation.IsPlatform(TOSModuleAttestation.Current), 'the platform class');
  CheckFalse(TOSModuleAttestation.IsPlatform(Attestation(TModuleStatus.Validated)),
    'a host class, whatever it claims');
  CheckFalse(TOSModuleAttestation.IsPlatform(nil), 'nothing');
end;

procedure TTestCompliancePolicy.TestUnattestedModuleAttestsNothing;
var
  LAttestation: IModuleAttestation;
begin
  LAttestation := TUnattestedModule.Create as IModuleAttestation;
  CheckEquals(Ord(TModuleStatus.Unknown),
    Ord(LAttestation.Status(TModuleStandard.Fips140_3)), 'no status');
  CheckEquals('', LAttestation.Identity.Describe, 'no identity');
  CheckTrue(LAttestation.Describe <> '', 'the reason is given');
  CheckFalse(LAttestation.Covers(TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable)),
    'no provider is covered');
  CheckEquals(0, System.Length(LAttestation.Disclosures), 'nothing to disclose');
end;

procedure TTestCompliancePolicy.TestOsAttestationAttestsOnlyWhereATableShips;
var
  LAttestation: IModuleAttestation;
begin
  LAttestation := TOSModuleAttestation.Current;
{$IFDEF TLSLIB_MSWINDOWS}
  CheckTrue(LAttestation.Identity.Attested, 'the Windows table is shipped');
{$ELSE}
  CheckFalse(LAttestation.Identity.Attested, 'no table is shipped');
  CheckFalse(LAttestation.Covers(TComplianceFakes.SystemOver([])), 'so it covers no provider');
{$ENDIF}
end;

procedure TTestCompliancePolicy.TestPolicyReadsTheAttestationOnce;
var
  LAttestation: TFlippingAttestation;
  LRef: IModuleAttestation;
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LAttestation := TFlippingAttestation.Create;
  LRef := LAttestation;
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3, SystemBaseWithKey, Pkix,
    LRef, TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  LReport := LPolicy.Evaluate(ClientBuilder(LPolicy).Build);
  LPolicy.Evaluate(ServerBuilder(LPolicy).Build);
  LPolicy.EvaluateCredential(ServerCredential(LPolicy.Crypto));
  CheckEquals(1, LAttestation.IdentityReads, 'the identity is read at construction');
  CheckEquals(1, LAttestation.StatusReads, 'and so is the status');
  CheckEquals(1, LAttestation.DescribeReads, 'and the description');
  CheckEquals(1, LAttestation.DisclosureReads, 'and the disclosures');
  CheckEquals(Ord(TModuleStatus.Validated), Ord(LReport.ModuleStatus),
    'a later answer of the attestation does not reach a report');
end;

procedure TTestCompliancePolicy.TestStrictHistoricalModuleRaises;
var
  LFindings: TArray<TComplianceFinding>;
begin
  CheckTrue(Construct(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.Historical, TComplianceEnforcement.Strict, LFindings),
    'a module past its sunset date is refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ModuleNotValidated), 'names the module');
end;

procedure TTestCompliancePolicy.TestRelaxedHistoricalModuleReports;
var
  LReport: IComplianceReport;
begin
  LReport := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.Historical, TComplianceEnforcement.Relaxed).PlatformReport;
  CheckEquals(Ord(TModuleStatus.Historical), Ord(LReport.ModuleStatus), 'the status is carried');
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict), 'never compliant');
  CheckTrue(HasKind(LReport.Findings, TComplianceFindingKind.ModuleNotValidated), 'reported');
end;

procedure TTestCompliancePolicy.TestStrictUnknownStatusRaises;
var
  LFindings: TArray<TComplianceFinding>;
begin
  CheckTrue(Construct(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.Unknown, TComplianceEnforcement.Strict, LFindings),
    'an unknown module is not a validated one');
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
  LBase := TComplianceFakes.SystemOver([TAeadAlgorithm.AES_128_GCM]);
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
  LBase := TComplianceFakes.SystemOver([TAeadAlgorithm.AES_128_GCM]);
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, LBase, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  CheckTrue(ReportHasKind(LPolicy.PlatformReport, TComplianceFindingKind.AlgorithmOutsideModule),
    'reported');
end;

procedure TTestCompliancePolicy.TestStrictHandBuiltEd25519RaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  Include(LRules.SignatureSchemes, TSignatureScheme.ED25519);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict),
    'rules outside every preset are not runnable');
end;

procedure TTestCompliancePolicy.TestRelaxedHandBuiltEd25519RaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  Include(LRules.SignatureSchemes, TSignatureScheme.ED25519);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Relaxed),
    'relaxed never relaxes what the rules allow');
end;

procedure TTestCompliancePolicy.TestRulesWiderThanAPresetRaiseArgumentInBothModes;
var
  LRules: TComplianceRules;
  LMode: TComplianceEnforcement;
begin
  for LMode := Low(TComplianceEnforcement) to High(TComplianceEnforcement) do
  begin
    LRules := TCompliancePresets.Fips140_3;
    LRules.Strength.AllowEdDsa := True;
    CheckTrue(ArgumentRefused(LRules, LMode), 'EdDSA certificates');
    LRules := TCompliancePresets.Fips140_3;
    LRules.Strength.MinRsaModulusBits := 1024;
    CheckTrue(ArgumentRefused(LRules, LMode), 'a lower RSA floor');
    LRules := TCompliancePresets.Fips140_3;
    LRules.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
    CheckTrue(ArgumentRefused(LRules, LMode), 'a deprecated hash');
    LRules := TCompliancePresets.Fips140_3;
    LRules.Strength.AnchorKeyFloors := False;
    CheckTrue(ArgumentRefused(LRules, LMode), 'anchors left out of the key floors');
    LRules := TCompliancePresets.Fips140_3;
    LRules.Aeads := LRules.Aeads + [TAeadAlgorithm.CHACHA20_POLY1305];
    CheckTrue(ArgumentRefused(LRules, LMode), 'ChaCha');
  end;
end;

procedure TTestCompliancePolicy.TestDroppedRequirementRaisesArgumentInBothModes;
var
  LRules: TComplianceRules;
  LMode: TComplianceEnforcement;
  LRequirement: TComplianceRequirement;
begin
  for LMode := Low(TComplianceEnforcement) to High(TComplianceEnforcement) do
    for LRequirement := Low(TComplianceRequirement) to High(TComplianceRequirement) do
    begin
      LRules := TCompliancePresets.Fips140_3;
      Exclude(LRules.Requirements, LRequirement);
      CheckTrue(ArgumentRefused(LRules, LMode),
        TEnumUtilities.GetName<TComplianceRequirement>(LRequirement));
    end;
end;

procedure TTestCompliancePolicy.TestNarrowerRulesAreAcceptedInBothModes;
var
  LRules: TComplianceRules;
  LMode: TComplianceEnforcement;
begin
  for LMode := Low(TComplianceEnforcement) to High(TComplianceEnforcement) do
  begin
    LRules := TCompliancePresets.Fips140_3;
    LRules.Strength.MinRsaModulusBits := 3072;
    LRules.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
    CheckFalse(ArgumentRefused(LRules, LMode), 'a higher RSA floor narrows');
    CheckFalse(ArgumentRefused(Tls12OnlyRules, LMode), 'TLS 1.2 alone narrows');
  end;
end;

procedure TTestCompliancePolicy.TestPolicyOverNarrowerRulesNamesThePreset;
begin
  CheckEquals('within Fips140_3', NewPolicy(Tls12OnlyRules, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Strict).PlatformReport.Preset,
    'narrower than Fips140_3');
  CheckEquals('Fips140_3', StrictPolicy.PlatformReport.Preset, 'equal to Fips140_3');
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

procedure TTestCompliancePolicy.TestDuplicateSuiteRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites13.Aes256GcmSha384, TCipherSuites13.Aes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'a suite listed twice');
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Relaxed), 'in relaxed mode too');
end;

procedure TTestCompliancePolicy.TestDuplicateGroupRaisesArgument;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1, TNamedGroupCatalog.Secp256r1);
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Strict), 'a group listed twice');
  CheckTrue(ArgumentRefused(LRules, TComplianceEnforcement.Relaxed), 'in relaxed mode too');
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
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3, nil, Pkix,
      Attestation(TModuleStatus.Validated), TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil crypto');
end;

procedure TTestCompliancePolicy.TestNilBasePkixRaisesArgument;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
      TComplianceFakes.SystemOver([]), nil, Attestation(TModuleStatus.Validated),
      TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil PKIX');
end;

procedure TTestCompliancePolicy.TestNilAttestationRaisesArgument;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
      TComplianceFakes.SystemOver([]), Pkix, nil,
      TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil attestation');
end;

procedure TTestCompliancePolicy.TestComposedKdfCapsTheVerdictAtPrimitivesInModule;
var
  LReport: IComplianceReport;
begin
  LReport := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.SystemOver([]),
    TModuleStatus.Validated, TComplianceEnforcement.Strict).PlatformReport;
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LReport.Verdict), 'verdict');
  CheckFalse(LReport.KeyDerivationInModule, 'a derivation runs outside the module');
  CheckEquals(0, System.Length(LReport.Findings), 'a composed derivation is no finding');
  CheckTrue(Disclosed(LReport, 'TLS 1.3 key schedule (HKDF)'), 'the derivation is named');
  CheckTrue(Disclosed(LReport, 'TLS 1.2 key schedule (PRF)'), 'both versions are offered');
end;

procedure TTestCompliancePolicy.TestTls12OnlyRulesWithTheModulePrfAreCompliant;
var
  LReport: IComplianceReport;
begin
  LReport := NewPolicy(Tls12OnlyRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport;
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'verdict');
  CheckTrue(LReport.KeyDerivationInModule, 'the PRF is a module service');
  CheckFalse(Disclosed(LReport, 'key schedule'), 'nothing runs outside the module');
end;

procedure TTestCompliancePolicy.TestTls12OnlyRulesWithAComposedPrfArePrimitivesInModule;
var
  LReport: IComplianceReport;
begin
  LReport := NewPolicy(Tls12OnlyRules, TComplianceFakes.SystemOver([]), TModuleStatus.Validated,
    TComplianceEnforcement.Strict).PlatformReport;
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LReport.Verdict), 'verdict');
  CheckTrue(Disclosed(LReport, 'TLS 1.2 key schedule (PRF)'), 'the derivation is named');
  CheckFalse(Disclosed(LReport, 'TLS 1.3 key schedule (HKDF)'), 'TLS 1.3 is not offered');
end;

procedure TTestCompliancePolicy.TestTls13OnlyRulesAreCappedWhateverThePrfIs;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(NewPolicy(LRules, SystemBaseWithKey,
    TModuleStatus.Validated, TComplianceEnforcement.Strict).PlatformReport.Verdict),
    'HKDF is composed on every module');
end;

procedure TTestCompliancePolicy.TestRequireModuleAcceptsTls12OnlyRulesWithTheModulePrf;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := Tls12OnlyRules;
  LRules.Kdf := TKdfRule.RequireModule;
  CheckFalse(Construct(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'the PRF is already a module service');
end;

procedure TTestCompliancePolicy.TestRequireModuleRefusesTls12OnlyRulesWithAComposedPrf;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := Tls12OnlyRules;
  LRules.Kdf := TKdfRule.RequireModule;
  CheckTrue(Construct(LRules, TComplianceFakes.SystemOver([]), TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'strict refuses');
  CheckEquals('TLS 1.2 PRF SHA_256', FindingOfKind(LFindings,
    TComplianceFindingKind.KdfOutsideModule).Subject, 'the PRF is named');
end;

procedure TTestCompliancePolicy.TestRequireModuleIgnoresTheTls13SuitesOfRulesThatOfferNoTls13;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  // the TLS 1.3 suites stay listed, but no offered version runs the HKDF they name
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LRules.Kdf := TKdfRule.RequireModule;
  CheckFalse(Construct(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'the module serves the only derivation that runs');
end;

procedure TTestCompliancePolicy.TestRequireModuleIgnoresTheTls12SuitesOfRulesThatOfferNoTls12;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  LRules.Kdf := TKdfRule.RequireModule;
  CheckTrue(Construct(LRules, TComplianceFakes.SystemOver([]), TModuleStatus.Validated,
    TComplianceEnforcement.Strict, LFindings), 'the HKDF of TLS 1.3 is composed');
  CheckTrue(CountOfKind(LFindings, TComplianceFindingKind.KdfOutsideModule) > 0, 'not vacuous');
  for LI := 0 to System.Length(LFindings) - 1 do
    CheckEquals(0, Pos('TLS 1.2 PRF', LFindings[LI].Subject), 'the PRF is not named');
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

procedure TTestCompliancePolicy.TestForeignHpkeIsNotAFindingWhenRulesForbidEch;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.FakeSystemBase(
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil, TFakeHpke.Create as IHpkeCrypto),
    TModuleStatus.Validated, TComplianceEnforcement.Strict);
  CheckEquals(0, System.Length(LPolicy.PlatformReport.Findings), 'nothing uses HPKE');
end;

procedure TTestCompliancePolicy.TestKdfRequireModuleRaisesStrictOnComposed;
var
  LRules: TComplianceRules;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Kdf := TKdfRule.RequireModule;
  CheckTrue(Construct(LRules, TComplianceFakes.SystemOver([]), TModuleStatus.Validated,
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
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TComplianceFakes.SystemOver([]), Pkix,
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
  LBase := TComplianceFakes.SystemOver([TAeadAlgorithm.AES_128_GCM]);
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
begin
  Result := TTlsConfigBuilder.CreateFromProfile(ACrypto, APkix, Tls13Profile).Client
    .WithServerVerification(TServerVerification.VerifierSource(
    TFakeOsVerifierSources.Server).Build).Build;
end;

function TTestComplianceAdmit.Psk: TExternalPsk;
begin
  Result.Identity := TBytes.Create($61, $62);
  Result.Secret := TSecretBuffer.From(TBytes.Create($00, $11, $22, $33, $44, $55, $66, $77,
    $88, $99, $AA, $BB, $CC, $DD, $EE, $FF));
  Result.Context := nil;
  Result.Hash := THashAlgorithm.SHA_256;
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
    TInMemorySessionCache.Create as ISessionCache).WithResumptionScope(APolicy.SessionScope);
  Result.Tls13.WithEarlyData(True);
end;

function TTestComplianceAdmit.RawResolverConfig(const APolicy: ICompliancePolicy;
  const AResolver: ITlsServerCredentialResolver): ITlsServerConfig;
begin
  Result := RawServer(APolicy).WithResumption(False).WithCredentialResolver(AResolver).Build;
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

procedure TTestComplianceAdmit.TestBaselineClientAdmitsStrict;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Admit(ClientBuilder(LPolicy).Build);
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LReport.Verdict),
    'the config can run TLS 1.3 key derivation');
  CheckEquals(0, System.Length(LReport.Findings), 'no finding');
end;

procedure TTestComplianceAdmit.TestBaselineServerAdmitsStrict;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Admit(ServerBuilder(LPolicy).Build);
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LReport.Verdict),
    'the config can run TLS 1.3 key derivation');
  CheckEquals(0, System.Length(LReport.Findings), 'no finding');
end;

procedure TTestComplianceAdmit.TestTls12OnlyClientIsCompliantWhenTheModuleServesThePrf;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Admit(ClientBuilder(LPolicy).WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls12)).Build);
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'verdict');
  CheckTrue(LReport.KeyDerivationInModule, 'the PRF is the only derivation');
end;

procedure TTestComplianceAdmit.TestTls12OnlyServerIsCompliantWhenTheModuleServesThePrf;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Admit(ServerBuilder(LPolicy).WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls12)).Build);
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'verdict');
end;

procedure TTestComplianceAdmit.TestTls13OnlyClientIsCappedWhenTheModuleServesThePrf;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsClientConfigBuilder;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LBuilder := ClientBuilder(LPolicy);
  // the facade's TLS 1.2 setting is taken back, as the builder refuses it without TLS 1.2
  LBuilder.Tls12.WithExtendedMasterSecret(False);
  LReport := LPolicy.Admit(LBuilder.WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls13)).Build);
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LReport.Verdict), 'verdict');
  CheckFalse(LReport.KeyDerivationInModule, 'HKDF runs outside the module');
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

procedure TTestComplianceAdmit.TestListedAndPreferredDisallowedGroupIsReportedOnce;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(
    TNamedGroups.CreateRegistry(TArray<INamedGroup>.Create(
    TFakeNamedGroup.Create(TNamedGroupCatalog.X25519) as INamedGroup)))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519)).Build,
    LFindings), 'refused');
  CheckEquals(1, CountOfKind(LFindings, TComplianceFindingKind.NamedGroupNotAllowed),
    'X25519 is both listed and preferred but found once');
end;

procedure TTestComplianceAdmit.TestNamedGroupNotAllowedRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(
    TNamedGroups.CreateDefaultRegistry(Crypto)).WithPreferredGroups(
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519)).Build, LFindings), 'refused');
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
  // the registry holds the policy's own P-256 and a P-384 the rules do not list; both are preferred
  LBuilder := LPolicy.NamedGroups.ToBuilder;
  LBuilder.Add(TFakeNamedGroup.Create(TNamedGroupCatalog.Secp384r1) as INamedGroup);
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(LBuilder.Build)
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
  CheckEquals(3, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'each of the 3 groups is found once, though it is listed and preferred');
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
  CheckEquals(3, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'the identity is the objects, not the provider, and each group is found once');
end;

procedure TTestComplianceAdmit.TestListedForeignGroupNoPreferenceNamesIsAdmitted;
var
  LPolicy: ICompliancePolicy;
  LBuilder: INamedGroupRegistryBuilder;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  // the preference list names the policy's own P-256 only, so the foreign P-384 is never offered
  LBuilder := LPolicy.NamedGroups.ToBuilder;
  LBuilder.Prune(TNamedGroupCatalog.Secp384r1);
  LBuilder.Add(TNamedGroups.CreateNistEcdh(LPolicy.Crypto, 'secp384r1'));
  CheckFalse(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithNamedGroups(LBuilder.Build)
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1)).Build,
    LFindings), 'admitted');
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

function TTestComplianceAdmit.CatalogSuite: TTlsCipherSuite;
begin
  CheckTrue(TCipherSuiteCatalog.TryGet(TCipherSuites12.EcdheEcdsaAes256GcmSha384, Result),
    'catalog');
end;

procedure TTestComplianceAdmit.SuiteSets(const APolicy: ICompliancePolicy;
  const ASuite: TTlsCipherSuite; out AClean, AAltered: TArray<TTlsCipherSuite>);
var
  LRules: TComplianceRules;
  LSuite: TTlsCipherSuite;
  LI: Int32;
begin
  LRules := APolicy.Rules;
  System.SetLength(AClean, System.Length(LRules.CipherSuites));
  System.SetLength(AAltered, System.Length(LRules.CipherSuites));
  for LI := 0 to System.Length(LRules.CipherSuites) - 1 do
  begin
    CheckTrue(TCipherSuiteCatalog.TryGet(LRules.CipherSuites[LI], LSuite), 'catalog');
    AClean[LI] := LSuite;
    if LSuite.Common.Code = ASuite.Common.Code then
      AAltered[LI] := ASuite
    else
      AAltered[LI] := LSuite;
  end;
end;

function TTestComplianceAdmit.SuiteAdmit(const ASuite: TTlsCipherSuite;
  out AFindings: TArray<TComplianceFinding>): Boolean;
var
  LPolicy: ICompliancePolicy;
  LHeld: TFakeSuiteRegistry;
  LRegistry: ICipherSuiteRegistry;
  LConfig: ITlsClientConfig;
  LClean, LAltered: TArray<TTlsCipherSuite>;
begin
  LPolicy := StrictPolicy;
  SuiteSets(LPolicy, ASuite, LClean, LAltered);
  // the core builder refuses a non-catalog record, so a host registry swaps it in after Build
  LHeld := TFakeSuiteRegistry.Create(LClean);
  LRegistry := LHeld;
  LConfig := ClientBuilder(LPolicy).WithCipherSuites(LRegistry).Build;
  LHeld.Replace(LAltered);
  Result := ClientAdmit(LPolicy, LConfig, AFindings);
end;

function TTestComplianceAdmit.ServerSuiteAdmit(const ASuite: TTlsCipherSuite;
  out AFindings: TArray<TComplianceFinding>): Boolean;
var
  LPolicy: ICompliancePolicy;
  LHeld: TFakeSuiteRegistry;
  LRegistry: ICipherSuiteRegistry;
  LConfig: ITlsServerConfig;
  LClean, LAltered: TArray<TTlsCipherSuite>;
begin
  LPolicy := StrictPolicy;
  SuiteSets(LPolicy, ASuite, LClean, LAltered);
  LHeld := TFakeSuiteRegistry.Create(LClean);
  LRegistry := LHeld;
  LConfig := ServerBuilder(LPolicy).WithCipherSuites(LRegistry).Build;
  LHeld.Replace(LAltered);
  Result := ServerAdmit(LPolicy, LConfig, AFindings);
end;

procedure TTestComplianceAdmit.CheckDiffersFromCatalog(
  const AFindings: TArray<TComplianceFinding>);
var
  LFinding: TComplianceFinding;
begin
  LFinding := FindingOfKind(AFindings, TComplianceFindingKind.CipherSuiteDiffersFromCatalog);
  CheckEquals(TCipherSuiteCatalog.Name(CatalogSuite.Common.Code), LFinding.Subject,
    'names the suite');
  CheckTrue(Pos('catalog', LFinding.Message) > 0, 'says it differs from the catalog');
  CheckFalse(HasKind(AFindings, TComplianceFindingKind.CipherSuiteNotAllowed),
    'the code itself is allowed');
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
  CheckDiffersFromCatalog(LFindings);
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredPrfRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Prf := THashAlgorithm.SHA_256;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckDiffersFromCatalog(LFindings);
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredKeyLengthRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Common.KeyLength := 16;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckDiffersFromCatalog(LFindings);
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredAeadRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Common.Aead := TAeadAlgorithm.AES_128_GCM;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckDiffersFromCatalog(LFindings);
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredProtocolRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Protocol := TSuiteProtocol.Tls13;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckDiffersFromCatalog(LFindings);
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredKeyExchangeRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.KeyExchange := TKeyExchangeMethod.Decoupled;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckDiffersFromCatalog(LFindings);
end;

procedure TTestComplianceAdmit.TestSuiteWithAlteredAuthRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Auth := TAuthMethod.Rsa;
  CheckTrue(SuiteAdmit(LSuite, LFindings), 'refused');
  CheckDiffersFromCatalog(LFindings);
end;

procedure TTestComplianceAdmit.TestServerSuiteWithAlteredHashRefused;
var
  LSuite: TTlsCipherSuite;
  LFindings: TArray<TComplianceFinding>;
begin
  LSuite := CatalogSuite;
  LSuite.Common.Hash := THashAlgorithm.SHA_256;
  CheckTrue(ServerSuiteAdmit(LSuite, LFindings), 'refused');
  CheckDiffersFromCatalog(LFindings);
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
  CheckEquals(3, CountOfKind(LFindings, TComplianceFindingKind.ForeignNamedGroup),
    'each of the 3 groups is found once, though it is listed and preferred');
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
    .VerifierSource(TFakeOsVerifierSources.Server))
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

function TTestComplianceAdmit.EchKeyStore(const APolicy: ICompliancePolicy): IEchServerKeyStore;
var
  LGen: TEchKeyGenResult;
begin
  LGen := TEchKeyGenerator.Generate(APolicy.Crypto, 'public.example', 'origin.example', $AA,
    THpkeKem.DHKEM_P256_HKDF_SHA256, THpkeKdf.HKDF_SHA256, THpkeAead.AES_256_GCM, 0);
  Result := TInMemoryEchKeyStore.FromPem(LGen.Pem, APolicy.Crypto);
end;

procedure TTestComplianceAdmit.TestKeyedEchServerIsEchConfigured;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).Tls13.WithEchKeyStore(
    EchKeyStore(LPolicy)).Build), TComplianceFindingKind.EchConfigured),
    'the presets refuse ECH outright, keys and all');
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
  LSpy: TVerifyCallbackSpy;
begin
  LPolicy := StrictPolicy;
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  CheckFalse(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithCertificateVerifyCallback(
    LSpy.Callback).Build, LFindings), 'a callback can only add rejections');
end;

procedure TTestComplianceAdmit.TestStrengthBelowRulesRefused;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.VerifierSource(TFakeOsVerifierSources.Server).WithMinimumStrength(
    TCertificateStrengthPolicy.Defaults).Build).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.StrengthBelowRules), 'names the floors');
end;

procedure TTestComplianceAdmit.TestEd25519CredentialKeyBelowRules;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ServerAdmit(LPolicy, TComplianceTls.Server(LPolicy, ServerCredentialEd25519).Build,
    LFindings), 'a configuration finding refuses even in relaxed mode');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules), 'names the key');
end;

procedure TTestComplianceAdmit.TestEd25519CredentialSchemesNotAllowed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ServerAdmit(LPolicy, TComplianceTls.Server(LPolicy, ServerCredentialEd25519).Build,
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
  LReport := LPolicy.Evaluate(TComplianceTls.Server(LPolicy, ServerCredentialEd25519).Build);
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
  LConfig := TComplianceTls.Server(RelaxedPolicy, ServerCredential(Crypto)).Build;
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
  LBase := TComplianceFakes.SystemOver([]);
  LPolicy := NewPolicy(TCompliancePresets.Fips140_3, LBase, TModuleStatus.Validated,
    TComplianceEnforcement.Relaxed);
  LConfig := TComplianceTls.Server(LPolicy, ServerCredential(LPolicy.Crypto)).Build;
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
  LReport := LPolicy.Evaluate(TComplianceTls.Server(LPolicy, Rsa2048Credential).Build);
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
  LReport := LPolicy.Evaluate(TComplianceTls.Server(LPolicy, Rsa2048Credential).Build);
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    '2048 is inside the range but not an exact size');
end;

procedure TTestComplianceAdmit.TestRulesWithoutExactSizesAreRefusedAtConstruction;
var
  LRules: TComplianceRules;
  LRaised: Boolean;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.RsaModulusBits := nil;
  LRaised := False;
  try
    NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated, TComplianceEnforcement.Relaxed);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a range alone is looser than the exact sizes of the presets');
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

procedure TTestComplianceAdmit.TestInstanceVerifierIsCustomNotChainOutside;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.Custom(TFixedVerdictVerifier.CreateAccepting(False)
    as IServerCertificateVerifier)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'where a custom verifier runs cannot be seen');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'and it is not the built-in portable check');
end;

procedure TTestComplianceAdmit.TestInstanceVerifierRefusedInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.Custom(TFixedVerdictVerifier.CreateAccepting(False)
    as IServerCertificateVerifier)).Build, LFindings), 'a configuration finding is never relaxed');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured), 'which');
end;

procedure TTestComplianceAdmit.TestBuiltInVerifierIsPlatformOnlyInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckFalse(ClientAdmit(LPolicy, TComplianceTls.Client(LPolicy, TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore)).Build, LFindings), 'relaxed does not raise');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the portable check is a platform fact');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'and the built-in source is not host-supplied');
end;

procedure TTestComplianceAdmit.TestOsVerifierSourceHasNoVerifierFinding;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.VerifierSource(TFakeOsVerifierSources.Server)
    .WithMinimumStrength(LPolicy.Rules.Strength).Build).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CustomVerifierConfigured),
    'the OS source is not custom');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'and is in the module');
end;

procedure TTestComplianceAdmit.TestHostSourceIsCustom;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.VerifierSource(TFakeHostVerifierSource.Create
    as IServerCertificateVerifierSource).Build).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'a host source is not the OS source, so it is not in the module');
end;

procedure TTestComplianceAdmit.TestHostSourceRefusedInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ClientAdmit(LPolicy, ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.VerifierSource(TFakeHostVerifierSource.Create
    as IServerCertificateVerifierSource).Build).Build, LFindings),
    'a configuration finding is never relaxed');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'and the raised findings name the verifier');
end;

procedure TTestComplianceAdmit.TestRequiredPskClientIgnoresCustomVerifier;
var
  LPolicy: ICompliancePolicy;
  LCustom: IServerVerification;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls13));
  LCustom := TServerVerification.Custom(TFixedVerdictVerifier.CreateAccepting(False)
    as IServerCertificateVerifier);
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    LCustom).Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(Psk)).Build),
    TComplianceFindingKind.CustomVerifierConfigured),
    'a client that verifies no chain runs no verifier');
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    LCustom).Build), TComplianceFindingKind.CustomVerifierConfigured),
    'control: the same verifier without the PSK is found');
end;

procedure TTestComplianceAdmit.TestSystemVerifierSourceAdmitted;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(ClientBuilder(LPolicy).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the library OS verifier source, judged by its class, is in the module');
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

procedure TTestComplianceAdmit.TestStapleRequestedByRequiredPskClientIsNotAFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := VersionPolicy(TArray<UInt16>.Create(TlsWireVersionTls13));
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).WithOcspStaplingRequest(True)
    .Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(Psk)).Build),
    TComplianceFindingKind.StapleVerifiedOutsideModule),
    'a client that verifies no chain checks no staple');
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).WithOcspStaplingRequest(True)
    .Build), TComplianceFindingKind.StapleVerifiedOutsideModule),
    'control: the same request without the PSK is found');
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

procedure TTestComplianceAdmit.TestMtlsServerOsVerifierSourceAdmits;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ServerAdmit(LPolicy, TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy),
    TClientAuthMode.Required, TClientVerification.VerifierSource(
    TFakeOsVerifierSources.Client, TTlsLibTestCertificates.EcP256RootStore)).Build,
    LFindings), 'admitted');
end;

procedure TTestComplianceAdmit.TestMtlsServerInstanceVerifierIsCustom;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.Custom(TFixedVerdictVerifier.CreateAccepting(
    False) as IClientCertificateVerifier)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'a custom client verifier is host-supplied');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'and is not the built-in portable check');
end;

procedure TTestComplianceAdmit.TestMtlsServerInstanceVerifierRefusedInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.Custom(TFixedVerdictVerifier.CreateAccepting(
    False) as IClientCertificateVerifier)).Build, LFindings),
    'a configuration finding is never relaxed');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'and the raised findings name the verifier');
end;

procedure TTestComplianceAdmit.TestMtlsServerBuiltInVerifierIsPlatformOnlyInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckFalse(ServerAdmit(LPolicy, ServerBuilder(LPolicy).WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore)
    .WithMinimumStrength(LPolicy.Rules.Strength).Build).Build, LFindings),
    'relaxed does not raise');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.ChainVerifiedOutsideModule),
    'the portable check is a platform fact');
  CheckFalse(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'and the built-in source is not host-supplied');
end;

procedure TTestComplianceAdmit.TestMtlsServerHostSourceIsCustom;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ServerAdmit(LPolicy, TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy),
    TClientAuthMode.Required, TClientVerification.VerifierSource(
    TFakeHostVerifierSource.Create as IClientCertificateVerifierSource,
    TTlsLibTestCertificates.EcP256RootStore)).Build, LFindings), 'refused');
  CheckTrue(HasKind(LFindings, TComplianceFindingKind.CustomVerifierConfigured),
    'a host source is not the OS source, so it is not in the module');
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
    TServerVerification.VerifierSource(TFakeOsVerifierSources.Server)
    .WithMinimumStrength(LPolicy.Rules.Strength).WithRevocation(TRevocationPosture.Off)
    .Build).Build);
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
    ServerCredentialEd25519).Build).Findings;
  CheckEquals('credential 2 (CN=localhost)',
    FindingOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules).Subject,
    'the SNI credential is checked too, named by its place in the set and its common name');
end;

procedure TTestComplianceAdmit.TestHostListedResolverIsUnchecked;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
  LReport := LPolicy.Evaluate(RawResolverConfig(LPolicy, TListedCredentialResolver.Create(
    TArray<TTlsCredential>.Create(ServerCredential(LPolicy.Crypto), ServerCredentialEd25519))
    as ITlsServerCredentialResolver));
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialResolverUnchecked),
    'a host list can name credentials it never serves, so it is not trusted');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    'and its entries are not read');
end;

procedure TTestComplianceAdmit.TestSniResolverIsEnumerated;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
  LReport := LPolicy.Evaluate(RawResolverConfig(LPolicy,
    TSniCredentialResolver.ForCredential(ServerCredentialEd25519)));
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    'the library resolver is immutable, so its entries are checked');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialResolverUnchecked),
    'and it is not reported as uninspectable');
end;

procedure TTestComplianceAdmit.TestHostClassClaimingCheckedMarkerIsUnchecked;
var
  LPolicy: ICompliancePolicy;
  LInner: ITlsServerCredentialResolver;
begin
  LPolicy := StrictPolicy;
  LInner := TFixedCredentialResolver.Create(ServerCredential(LPolicy.Crypto), True)
    as ITlsServerCredentialResolver;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(RawResolverConfig(LPolicy,
    TClaimingResolver.Create(LPolicy, LInner) as ITlsServerCredentialResolver)),
    TComplianceFindingKind.CredentialResolverUnchecked),
    'a host class that lists the checked marker and names this policy is not the wrapper');
end;

procedure TTestComplianceAdmit.TestCheckedWrapperOverHostListedResolverIsNotUnchecked;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LReport := LPolicy.Evaluate(RawResolverConfig(LPolicy,
    LPolicy.CheckedCredentialResolver(TListedCredentialResolver.Create(
    TArray<TTlsCredential>.Create(ServerCredential(LPolicy.Crypto), ServerCredentialEd25519))
    as ITlsServerCredentialResolver)));
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialResolverUnchecked),
    'the handshake-time check of the policy wrapper is the enforcement');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyBelowRules),
    'and the entries of a host list behind it are not read at build');
end;

procedure TTestComplianceAdmit.TestDefaultSharedWithAnSniEntryIsReportedOnce;
var
  LPolicy: ICompliancePolicy;
  LWeak: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  LWeak := ServerCredentialEd25519;
  LFindings := LPolicy.Evaluate(RawServer(LPolicy).WithCredential(LWeak)
    .WithSniCredential('localhost', LWeak).Build).Findings;
  CheckEquals(1, CountOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules),
    'the credential the default shares with an entry is one credential');
end;

procedure TTestComplianceAdmit.TestTwoCredentialsAreReportedEach;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  LFindings := LPolicy.Evaluate(RawServer(LPolicy).WithCredential(ServerCredentialEd25519)
    .WithSniCredential('localhost', ServerCredentialEd25519).Build).Findings;
  CheckEquals(2, CountOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules),
    'two key objects are two credentials, whatever their material');
end;

procedure TTestComplianceAdmit.TestSameKeyWithAnotherChainIsAnotherCredential;
var
  LPolicy: ICompliancePolicy;
  LWeak, LOther: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  LWeak := ServerCredentialEd25519;
  LOther := LWeak;
  LOther.CertificateChain := TArray<TBytes>.Create(LWeak.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/Ed25519Chain.txt', 'root_cert'));
  LFindings := LPolicy.Evaluate(RawServer(LPolicy).WithCredential(LWeak)
    .WithSniCredential('localhost', LOther).Build).Findings;
  CheckTrue(CountOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules) >= 2,
    'a chain that differs is a credential that differs');
end;

procedure TTestComplianceAdmit.TestRawCustomResolverIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(RawResolverConfig(LPolicy,
    TFixedCredentialResolver.Create(ServerCredential(LPolicy.Crypto), True)
    as ITlsServerCredentialResolver)), TComplianceFindingKind.CredentialResolverUnchecked),
    'a resolver the policy cannot see into is reported');
end;

procedure TTestComplianceAdmit.TestRawCustomResolverIsRefusedEvenInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(ServerAdmit(LPolicy, RawResolverConfig(LPolicy, TFixedCredentialResolver.Create(
    ServerCredential(LPolicy.Crypto), True) as ITlsServerCredentialResolver), LFindings),
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
    TFixedCredentialResolver.Create(ServerCredential(LPolicy.Crypto), True)
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
    LOwner.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    ServerCredential(LOwner.Crypto), True) as ITlsServerCredentialResolver))),
    TComplianceFindingKind.CredentialResolverUnchecked),
    'a wrapper bound to a different policy instance is not trusted');
end;

procedure TTestComplianceAdmit.TestPskOnlyServerHasNoResolverFinding;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := RelaxedPolicy;
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
  LGiven := ServerCredential(LPolicy.Crypto);
  CheckTrue(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved), 'admitted');
  CheckTrue(TArrayUtilities.AreEqual(LGiven.CertificateChain[0], LResolved.CertificateChain[0]),
    'with its own chain');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesRsaOffTheExactSizes;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := LargeRsaPolicy;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    Rsa2048Credential, True) as ITlsServerCredentialResolver).TryResolve(
    Default(TTlsClientHelloInfo), LResolved), 'a 2048-bit key is not one of 3072 and 4096');
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
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    ServerCredential(LPolicy.Crypto), True) as ITlsServerCredentialResolver).TryResolve(
    Default(TTlsClientHelloInfo), LResolved), 'a P-256 key is outside the allowed curves');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAPortableKeyInStrict;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    ServerCredential(Crypto), True) as ITlsServerCredentialResolver).TryResolve(
    Default(TTlsClientHelloInfo), LResolved), 'strict refuses a key the module does not serve');
end;

procedure TTestComplianceAdmit.TestCheckedResolverAdmitsAPortableKeyInRelaxed;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := RelaxedPolicy;
  CheckTrue(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    ServerCredential(Crypto), True) as ITlsServerCredentialResolver).TryResolve(
    Default(TTlsClientHelloInfo), LResolved),
    'relaxed reports a platform finding and still admits');
end;

procedure TTestComplianceAdmit.TestCheckedResolverAnswersFalseWhenTheInnerDoes;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    ServerCredential(LPolicy.Crypto), False) as ITlsServerCredentialResolver).TryResolve(
    Default(TTlsClientHelloInfo), LResolved), 'an inner refusal stands');
  CheckEquals(0, System.Length(LResolved.CertificateChain), 'and nothing is handed out');
end;

procedure TTestComplianceAdmit.TestCheckedResolverNarrowsTheKey;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := MarkedKeyCredential(LPolicy.Crypto, TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256));
  CheckTrue(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved), 'admitted once narrowed');
  CheckEquals(1, System.Length(LResolved.PrivateKey.CapableSchemes), 'only the allowed scheme');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAnEmptyChain;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    Default(TTlsCredential), True) as ITlsServerCredentialResolver).TryResolve(
    Default(TTlsClientHelloInfo), LResolved),
    'an inner answer that holds no certificate is refused');
  CheckEquals(0, System.Length(LResolved.CertificateChain), 'and nothing is handed out');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAKeyWithNoAllowedScheme;
var
  LPolicy: ICompliancePolicy;
  LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(
    MarkedKeyCredential(LPolicy.Crypto, TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519)), True) as ITlsServerCredentialResolver)
    .TryResolve(Default(TTlsClientHelloInfo), LResolved),
    'a key whose schemes miss the rules is refused once narrowed');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAChainWithNoKey;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := ServerCredential(LPolicy.Crypto);
  LGiven.PrivateKey := nil;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved), 'a certificate with no private key can sign nothing');
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
    LPolicy.CheckedCredentialResolver(TFailingCredentialResolver.Create
      as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo), LResolved);
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
  LInner := TFixedCredentialResolver.Create(ServerCredential(LPolicy.Crypto), True)
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
    TFixedCredentialResolver.Create(ServerCredential(LPolicy.Crypto), True)
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
      TSniCredentialResolver.ForCredential(ServerCredentialEd25519)));
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
  LGiven := MarkedKeyCredential(LPolicy.Crypto, TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256));
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
  LFindings := LPolicy.Evaluate(TComplianceTls.Server(LPolicy, ServerCredentialEd25519).Build)
    .Findings;
  CheckEquals('credential 1 (CN=localhost)',
    FindingOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules).Subject,
    'the facade credential is the first of the set');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialUnreadableCertificateIsUndetermined;
var
  LCredential: TTlsCredential;
begin
  LCredential := ServerCredential(StrictPolicy.Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(TBytes.Create(1, 2, 3));
  CheckTrue(ReportHasKind(StrictPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyUndetermined), 'reported, not raised');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialWithoutChainIsUndetermined;
var
  LCredential: TTlsCredential;
begin
  LCredential := ServerCredential(StrictPolicy.Crypto);
  LCredential.CertificateChain := nil;
  CheckTrue(ReportHasKind(StrictPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyUndetermined), 'a credential with no certificate');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialWithoutKeyIsMissing;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  LCredential.PrivateKey := nil;
  LReport := LPolicy.EvaluateCredential(LCredential);
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyMissing),
    'a certificate with no private key');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyUndetermined),
    'which is not an unreadable key');
end;

procedure TTestComplianceAdmit.TestIntermediateKeyBelowTheFloorsIsAFinding;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.MinRsaModulusBits := 3072;
  LRules.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LCredential := ServerCredential(LPolicy.Crypto);
  // the P-256 leaf is inside the rules; the RSA-2048 certificate after it is not
  LCredential.CertificateChain := TArray<TBytes>.Create(LCredential.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_cert'));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckEquals(1, CountOfKind(LFindings, TComplianceFindingKind.CredentialKeyBelowRules),
    'only the second certificate');
  CheckTrue(Pos('certificate 2', FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialKeyBelowRules).Message) > 0, 'and it is named');
end;

procedure TTestComplianceAdmit.TestUnreadableIntermediateIsUndetermined;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(LCredential.CertificateChain[0],
    TBytes.Create(1, 2, 3));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('certificate 2', FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialKeyUndetermined).Message) > 0, 'the second certificate');
end;

procedure TTestComplianceAdmit.TestChainSignatureHashOutsideTheRulesIsAFinding;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFacts: TCertSignatureFacts;
  LFindings: TArray<TComplianceFinding>;
begin
  LCredential := ServerCredential(Crypto);
  CheckTrue(Pkix.Certificates.Parse(LCredential.CertificateChain[0]).SignatureFacts(LFacts),
    'the fixture signature is readable');
  CheckEquals(Ord(TCertSignatureHash.Sha256), Ord(LFacts.Hash), 'and is made with SHA-256');
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384];
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('certificate 1', FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialSchemesNotAllowed).Message) > 0,
    'a SHA-256 signature where only SHA-384 schemes are allowed');
end;

procedure TTestComplianceAdmit.TestChainSignatureHashInsideTheRulesIsNoFinding;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LFindings := LPolicy.EvaluateCredential(ServerCredential(LPolicy.Crypto)).Findings;
  CheckEquals(0, CountOfKind(LFindings, TComplianceFindingKind.CredentialSchemesNotAllowed),
    'SHA-256 is inside the Fips140_3 schemes');
end;

procedure TTestComplianceAdmit.TestSelfSignedLastCertificateSignatureIsNotChecked;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384];
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LCredential := ServerCredential(Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(LCredential.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('certificate 1', FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialSchemesNotAllowed).Message) > 0,
    'not vacuous: the leaf signature is reported');
  for LI := 0 to System.Length(LFindings) - 1 do
    CheckEquals(0, Pos('certificate 2', LFindings[LI].Message),
      'the self-signed root signature is not judged');
end;

procedure TTestComplianceAdmit.TestSelfIssuedLinkBeforeTheLastCertificateIsChecked;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
  LI, LSignatures: Int32;
  LSecond: Boolean;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384];
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LCredential := ServerCredential(Crypto);
  // the self-issued root sits mid-chain, as a key-rollover link does, with a certificate after it
  LCredential.CertificateChain := TArray<TBytes>.Create(LCredential.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'),
    LCredential.CertificateChain[0]);
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  LSecond := False;
  LSignatures := 0;
  for LI := 0 to System.Length(LFindings) - 1 do
    if Pos('is signed with an algorithm the rules do not allow', LFindings[LI].Message) > 0 then
    begin
      Inc(LSignatures);
      if Pos('certificate 2', LFindings[LI].Message) > 0 then
        LSecond := True;
    end;
  CheckTrue(LSecond, 'a self-issued certificate that is not last is judged');
  CheckEquals(3, LSignatures, 'all three SHA-256 signatures');
end;

procedure TTestComplianceAdmit.TestLoneSelfSignedCertificateSignatureIsNotChecked;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384];
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LCredential := ServerCredential(Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(System.Length(LFindings) > 0, 'not vacuous: the key still draws findings');
  for LI := 0 to System.Length(LFindings) - 1 do
    CheckEquals(0, Pos('is signed with an algorithm', LFindings[LI].Message),
      'a certificate that is both first and last, and self-issued, ends its chain');
end;

procedure TTestComplianceAdmit.TestSelfIssuedLastCertificateSignedByAnotherKeyIsChecked;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
  LSecond: Boolean;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384];
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LCredential := ServerCredential(Crypto);
  // a key rollover: the subject and the issuer name are one, and the old key signed it
  LCredential.CertificateChain := TArray<TBytes>.Create(LCredential.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/RolloverRoot.txt', 'rollover_new_root_cert'));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  LSecond := False;
  for LI := 0 to System.Length(LFindings) - 1 do
    if Pos('certificate 2 of the credential is signed with an algorithm',
      LFindings[LI].Message) > 0 then
      LSecond := True;
  CheckTrue(LSecond, 'a last certificate that is only self-issued is judged');
end;

procedure TTestComplianceAdmit.TestSelfIssuedLastCertificateSignedByItsOwnKeyIsNotChecked;
var
  LRules: TComplianceRules;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384];
  LPolicy := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
  LCredential := ServerCredential(Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(LCredential.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/RolloverRoot.txt', 'rollover_old_root_cert'));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('certificate 1', FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialSchemesNotAllowed).Message) > 0,
    'not vacuous: the leaf signature is reported');
  for LI := 0 to System.Length(LFindings) - 1 do
    CheckEquals(0, Pos('certificate 2', LFindings[LI].Message),
      'the root that verifies under its own key ends the chain');
end;

procedure TTestComplianceAdmit.TestPssSignatureUnderAPssIssuerKeyIsAFinding;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFacts: TCertSignatureFacts;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/PssIssuerKeyChain.txt', 'pss_signed_leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/PssIssuerKeyChain.txt', 'pss_key_root_cert'));
  CheckTrue(Pkix.Certificates.Parse(LCredential.CertificateChain[0]).SignatureFacts(LFacts),
    'the fixture signature is readable');
  CheckEquals(Ord(TCertSignatureFamily.RsaPss), Ord(LFacts.Family), 'it is RSA-PSS');
  CheckTrue(LFacts.PssCanonical, 'with canonical parameters, which the rules allow as rsae');
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('certificate 1 of the credential is signed under an RSASSA-PSS key',
    FindingOfKind(LFindings, TComplianceFindingKind.CredentialSchemesNotAllowed).Message) > 0,
    'no scheme of the rules covers the issuer key');
end;

procedure TTestComplianceAdmit.TestPssSignatureUnderAnRsaIssuerKeyIsNoFinding;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/PssIssuerKeyChain.txt', 'pss_signed_leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/PssIssuerKeyChain.txt', 'rsa_key_root_cert'));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(System.Length(LFindings) > 0, 'not vacuous: the key of the credential draws findings');
  for LI := 0 to System.Length(LFindings) - 1 do
    CheckEquals(0, Pos('certificate 1 of the credential is signed', LFindings[LI].Message),
      'the control: the same signature beside an rsaEncryption issuer key');
end;

procedure TTestComplianceAdmit.
  TestPssSignatureUnderAPssIssuerKeyIsAFindingWhateverTheChainOrder;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  // the issuer of certificate 1 is listed last, behind a certificate that does not issue it
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/PssIssuerKeyChain.txt', 'pss_signed_leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/PssIssuerKeyChain.txt', 'rsa_key_root_cert'),
    TTlsLibTestCertificates.Field('Certs/PssIssuerKeyChain.txt', 'pss_key_root_cert'));
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('certificate 1 of the credential is signed under an RSASSA-PSS key',
    FindingOfKind(LFindings, TComplianceFindingKind.CredentialSchemesNotAllowed).Message) > 0,
    'the issuer is found by name, not by position');
end;

function TTestComplianceAdmit.EcdsaOnlyPolicy: ICompliancePolicy;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP256R1_SHA256,
    TSignatureScheme.ECDSA_SECP384R1_SHA384, TSignatureScheme.ECDSA_SECP521R1_SHA512];
  Result := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
end;

procedure TTestComplianceAdmit.TestRsaSignatureUnderEcdsaOnlyRulesIsAFinding;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFacts: TCertSignatureFacts;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := EcdsaOnlyPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  // an RSA PKCS#1 SHA-256 signature, a hash the ECDSA schemes of the rules also use
  LCredential.CertificateChain := TArray<TBytes>.Create(LCredential.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_cert'));
  CheckTrue(Pkix.Certificates.Parse(LCredential.CertificateChain[1]).SignatureFacts(LFacts),
    'the fixture signature is readable');
  CheckEquals(Ord(TCertSignatureFamily.RsaPkcs1), Ord(LFacts.Family), 'it is RSA PKCS#1');
  CheckEquals(Ord(TCertSignatureHash.Sha256), Ord(LFacts.Hash), 'with SHA-256');
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckTrue(Pos('certificate 2', FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialSchemesNotAllowed).Message) > 0,
    'the family is not one the rules allow');
end;

procedure TTestComplianceAdmit.TestEcdsaSignatureUnderEcdsaOnlyRulesIsNoFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := EcdsaOnlyPolicy;
  CheckEquals(0, CountOfKind(LPolicy.EvaluateCredential(ServerCredential(LPolicy.Crypto)).Findings,
    TComplianceFindingKind.CredentialSchemesNotAllowed), 'the control: an ECDSA signature');
end;

function TTestComplianceAdmit.Sha256PrfComposedPolicy: ICompliancePolicy;
var
  LFake: TFakeBackendReport;
begin
  LFake := TFakeBackendReport.Create([]);
  LFake.NativePrf := True;
  LFake.ComposedPrfHashes := [THashAlgorithm.SHA_256];
  Result := NewPolicy(TCompliancePresets.Fips140_3, TComplianceFakes.FakeSystemBase(
    LFake as ICryptoBackendReport, nil, nil), TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
end;

function TTestComplianceAdmit.Tls12Client(const APolicy: ICompliancePolicy;
  const ACodes: array of UInt16): ITlsClientConfig;
var
  LSuites: ICipherSuiteRegistryBuilder;
  LSuite: TTlsCipherSuite;
  LI: Int32;
begin
  LSuites := TCipherSuiteRegistryBuilder.Create as ICipherSuiteRegistryBuilder;
  for LI := Low(ACodes) to High(ACodes) do
  begin
    CheckTrue(TCipherSuiteCatalog.TryGet(ACodes[LI], LSuite), 'catalog');
    LSuites.Add(LSuite);
  end;
  Result := ClientBuilder(APolicy).WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls12)).WithCipherSuites(LSuites.Build).Build;
end;

procedure TTestComplianceAdmit.TestKdfOutsideTheModuleIsJudgedByTheConfigSuites;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := Sha256PrfComposedPolicy;
  CheckFalse(LPolicy.PlatformReport.KeyDerivationInModule,
    'the rules list SHA-256 suites, whose PRF is composed');
  LReport := LPolicy.Evaluate(Tls12Client(LPolicy,
    [TCipherSuites12.EcdheEcdsaAes256GcmSha384, TCipherSuites12.EcdheRsaAes256GcmSha384]));
  CheckTrue(LReport.KeyDerivationInModule, 'a config of SHA-384 suites runs the module PRF');
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'verdict');
  LReport := LPolicy.Evaluate(Tls12Client(LPolicy,
    [TCipherSuites12.EcdheEcdsaAes128GcmSha256]));
  CheckFalse(LReport.KeyDerivationInModule, 'a config of a SHA-256 suite runs the composed one');
end;

procedure TTestComplianceAdmit.TestKeyOfAnotherCertificateIsMismatched;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  LCredential.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256), Pkix.Certificates.Parse(
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_cert')).PublicKeyInfo)
    as ISigningKey;
  LFindings := LPolicy.EvaluateCredential(LCredential).Findings;
  CheckEquals(Ord(TComplianceFindingCategory.Configuration), Ord(FindingOfKind(LFindings,
    TComplianceFindingKind.CredentialKeyMismatch).Category), 'a configuration finding');
end;

procedure TTestComplianceAdmit.TestKeyOfTheLeafIsNotMismatched;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ReportHasKind(LPolicy.EvaluateCredential(ServerCredential(LPolicy.Crypto)),
    TComplianceFindingKind.CredentialKeyMismatch), 'the leaf''s own key');
end;

procedure TTestComplianceAdmit.TestKeyThatExposesNoPublicKeyIsUnusableNotMismatched;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LReport: IComplianceReport;
begin
  // the builder refuses a key that cannot be matched to its leaf, so it is not admitted
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  LCredential.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256)) as ISigningKey;
  LReport := LPolicy.EvaluateCredential(LCredential);
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyUnusable),
    'a key with no public half cannot be matched to its leaf');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.CredentialKeyMismatch),
    'and is not reported as a mismatch');
end;

procedure TTestComplianceAdmit.TestKeyInAnotherEncodingOfTheLeafKeyIsNotMismatched;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LSpki: TBytes;
begin
  // the builder compares keys by value, so a re-encoding of the leaf's own key is the leaf's
  LPolicy := StrictPolicy;
  LCredential := Rsa2048Credential;
  LSpki := LCredential.PrivateKey.PublicKeyInfo;
  LCredential.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.RSA_PSS_RSAE_SHA256),
    TTlsLibTestCertificates.RsaSpkiWithoutNullParameters(LSpki)) as ISigningKey;
  CheckFalse(TArrayUtilities.AreEqual(LSpki, LCredential.PrivateKey.PublicKeyInfo),
    'the encodings differ in bytes');
  CheckFalse(ReportHasKind(LPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyMismatch), 'the same key in another encoding');
end;

procedure TTestComplianceAdmit.TestLeafBarringDigitalSignatureIsUnusable;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LCredential := ServerCredential(LPolicy.Crypto);
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'ku_keyenc_cert'));
  CheckTrue(ReportHasKind(LPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyUnusable), 'a leaf that cannot sign a handshake');
end;

procedure TTestComplianceAdmit.TestRsaKeyOverAnRsaPssLeafIsUnusable;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LCredential := Rsa2048Credential;
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'rsapss_cert'));
  LCredential.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.RSA_PSS_RSAE_SHA256), Pkix.Certificates.PublicKeyInfo(
    LCredential.CertificateChain[0])) as ISigningKey;
  CheckTrue(ReportHasKind(LPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyUnusable),
    'an RSA key over an id-RSASSA-PSS leaf, though the key matches it');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAKeyThatExposesNoPublicKey;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := ServerCredential(LPolicy.Crypto);
  LGiven.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256)) as ISigningKey;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved), 'a key that cannot be matched');
end;

function TTestComplianceAdmit.KeyUsageCredential(const APolicy: ICompliancePolicy;
  const ACertField: string): TTlsCredential;
begin
  // the key is the leaf's own, so keyUsage is the only thing that can set the credential apart
  Result := ServerCredential(APolicy.Crypto);
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', ACertField));
  Result.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256), Pkix.Certificates.PublicKeyInfo(
    Result.CertificateChain[0])) as ISigningKey;
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesALeafBarringDigitalSignature;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := KeyUsageCredential(LPolicy, 'ku_keyenc_cert');
  CheckTrue(ReportHasKind(LPolicy.EvaluateCredential(LGiven),
    TComplianceFindingKind.CredentialKeyUnusable), 'the leaf is what is wrong');
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved), 'a leaf that cannot sign');
end;

procedure TTestComplianceAdmit.TestCheckedResolverAdmitsALeafPermittingDigitalSignature;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := KeyUsageCredential(LPolicy, 'ku_digsig_cert');
  CheckFalse(ReportHasKind(LPolicy.EvaluateCredential(LGiven),
    TComplianceFindingKind.CredentialKeyUnusable), 'control: nothing unusable');
  CheckTrue(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved), 'control: the same shape is handed out');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAnRsaPssLeaf;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := Rsa2048Credential;
  LGiven.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'rsapss_cert'));
  LGiven.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.RSA_PSS_RSAE_SHA256), Pkix.Certificates.PublicKeyInfo(
    LGiven.CertificateChain[0])) as ISigningKey;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved), 'an RSA key over an RSA-PSS leaf');
end;

procedure TTestComplianceAdmit.TestCheckedResolverRefusesAKeyOfAnotherCertificate;
var
  LPolicy: ICompliancePolicy;
  LGiven, LResolved: TTlsCredential;
begin
  LPolicy := StrictPolicy;
  LGiven := ServerCredential(LPolicy.Crypto);
  LGiven.PrivateKey := TFakeSystemSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256), Pkix.Certificates.Parse(
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_cert')).PublicKeyInfo)
    as ISigningKey;
  CheckFalse(LPolicy.CheckedCredentialResolver(TFixedCredentialResolver.Create(LGiven,
    True) as ITlsServerCredentialResolver).TryResolve(Default(TTlsClientHelloInfo),
    LResolved),
    'a resolver cannot hand a handshake a key for a certificate it was never judged with');
end;

procedure TTestComplianceAdmit.TestWrapperOfAnotherPolicyAroundTheSniResolverIsUnchecked;
var
  LOwner, LPolicy: ICompliancePolicy;
  LInner: ITlsServerCredentialResolver;
begin
  LOwner := StrictPolicy;
  LPolicy := StrictPolicy;
  LInner := TSniCredentialResolver.ForCredential(ServerCredential(LOwner.Crypto));
  CheckTrue(ReportHasKind(LPolicy.Evaluate(RawResolverConfig(LPolicy,
    LOwner.CheckedCredentialResolver(LInner))), TComplianceFindingKind.CredentialResolverUnchecked),
    'the other policy''s rules, not these, judge each handshake');
end;

procedure TTestComplianceAdmit.TestWrapperOfThisPolicyAroundTheSniResolverIsChecked;
var
  LPolicy: ICompliancePolicy;
  LInner: ITlsServerCredentialResolver;
begin
  LPolicy := StrictPolicy;
  LInner := TSniCredentialResolver.ForCredential(ServerCredential(LPolicy.Crypto));
  CheckFalse(ReportHasKind(LPolicy.Evaluate(RawResolverConfig(LPolicy,
    LPolicy.CheckedCredentialResolver(LInner))),
    TComplianceFindingKind.CredentialResolverUnchecked), 'control: its own wrapper is');
end;

procedure TTestComplianceAdmit.TestEvaluateCredentialReportsExtraSchemes;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LCredential := MarkedKeyCredential(LPolicy.Crypto, TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256));
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
  CheckEquals(0, System.Length(LPolicy.EvaluateCredential(
    ServerCredential(LPolicy.Crypto)).Findings), 'none');
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

procedure TTestComplianceAdmit.TestStoreWithDefaultTicketKeysUnderAes128IsNotRefused;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
begin
  LPolicy := Aes128Policy;
  LBuilder := Tls13OnlyServerBuilder(LPolicy).WithResumption(True).WithSessionStore(
    TInMemorySessionStore.Create(LPolicy.Crypto.Primitives.GetRandom) as ISessionStore)
    .WithDefaultSessionTicketKeys;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(LBuilder.Build),
    TComplianceFindingKind.TicketAeadNotAllowed),
    'TLS 1.3 seals with the store alone, so the keys beside it are idle');
end;

procedure TTestComplianceAdmit.TestStoreWithDefaultTicketKeysUnderTls12Aes128IsRefused;
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
    'TLS 1.2 seals with the keys even beside a store');
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
  LLoose := TServerVerification.VerifierSource(TFakeOsVerifierSources.Server).WithMinimumStrength(
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
    .VerifierSource(TFakeOsVerifierSources.Server))
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
    TFakeOsVerifierSources.Server));
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

procedure TTestComplianceAdmit.TestBuildClientLeavesTheCallersVariableAloneWhenRefused;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsClientConfigBuilder;
  LConfig: ITlsClientConfig;
  LRaised: Boolean;
begin
  // guards that a refused config never reaches the caller's variable
  LPolicy := StrictPolicy;
  LBuilder := EarlyDataClientBuilder(LPolicy, TServerVerification.VerifierSource(
    TFakeOsVerifierSources.Server));
  LConfig := nil;
  LRaised := False;
  try
    LConfig := TComplianceTls.BuildClient(LPolicy, LBuilder);
  except
    on EComplianceUnmetTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the policy refused it');
  CheckTrue(LConfig = nil, 'and the refused config never reached the caller''s variable');
end;

procedure TTestComplianceAdmit.TestBuildServerLeavesTheCallersVariableAloneWhenRefused;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
  LConfig: ITlsServerConfig;
  LRaised: Boolean;
begin
  // guards that a refused config never reaches the caller's variable
  LPolicy := StrictPolicy;
  LBuilder := ServerBuilder(LPolicy);
  LBuilder.Tls13.WithEarlyData(1024).WithAntiReplay(
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  LConfig := nil;
  LRaised := False;
  try
    LConfig := TComplianceTls.BuildServer(LPolicy, LBuilder);
  except
    on EComplianceUnmetTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the policy refused it');
  CheckTrue(LConfig = nil, 'and the refused config never reached the caller''s variable');
end;

procedure TTestComplianceAdmit.TestFacadeServerNarrowsKeySchemes;
var
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
  LSchemes: TArray<TSignatureScheme>;
begin
  LPolicy := StrictPolicy;
  LCredential := MarkedKeyCredential(LPolicy.Crypto, TArray<TSignatureScheme>.Create(
    TSignatureScheme.ED25519, TSignatureScheme.ECDSA_SECP256R1_SHA256));
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
      TFakeOsVerifierSources.Server));
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
    TComplianceTls.Server(LNone, ServerCredential(Crypto));
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

{ TTestComplianceResumption }

function TTestComplianceResumption.ClientWithCache(
  const APolicy: ICompliancePolicy): ITlsClientConfigBuilder;
begin
  Result := ClientBuilder(APolicy).WithSessionCache(
    TInMemorySessionCache.Create as ISessionCache);
end;

function TTestComplianceResumption.NewStore(const APolicy: ICompliancePolicy): ISessionStore;
begin
  Result := TInMemorySessionStore.Create(APolicy.Crypto.Primitives.GetRandom) as ISessionStore;
end;

function TTestComplianceResumption.HasPrefixOf(const AScope: TBytes;
  const APolicy: ICompliancePolicy): Boolean;
begin
  Result := (System.Length(AScope) >= 16) and
    AreEqual(System.Copy(AScope, 0, 16), System.Copy(APolicy.SessionScope, 0, 16));
end;

function TTestComplianceResumption.FleetScope: TBytes;
begin
  Result := Crypto.Primitives.GetRandom.GenerateBytes(32);
end;

function TTestComplianceResumption.NewFleet: IFleetTicketKeyManager;
begin
  Result := TFleetTicketKeyManager.Create as IFleetTicketKeyManager;
end;

function TTestComplianceResumption.FleetServerBuilder(const APolicy: ICompliancePolicy;
  const AFleet: IFleetTicketKeyManager; const AScope: TBytes): ITlsServerConfigBuilder;
begin
  Result := ServerBuilder(APolicy).WithResumptionScope(AScope).WithSessionTicketKeys(
    APolicy.CheckedTicketKeys(AFleet, AScope));
end;

function TTestComplianceResumption.PolicyOverRandom(const ARandom: IRandom): ICompliancePolicy;
var
  LBase: ICryptoProvider;
begin
  LBase := TOverlayCryptoProvider.Create(TMockCryptoProvider.Create(ARandom)
    as ICryptoProvider, nil, nil,
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil);
  Result := NewPolicy(TCompliancePresets.Fips140_3, LBase, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
end;

procedure TTestComplianceResumption.TestSessionScopeIs32BytesWithThePolicyPrefix;
var
  LPolicy: ICompliancePolicy;
  LScope: TBytes;
begin
  LPolicy := StrictPolicy;
  LScope := LPolicy.SessionScope;
  CheckEquals(32, System.Length(LScope), 'the prefix and 16 random bytes');
  CheckTrue(HasPrefixOf(LScope, LPolicy), 'it starts with the prefix of every scope of the policy');
end;

procedure TTestComplianceResumption.TestSessionScopePrefixIsStableForOnePolicy;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(HasPrefixOf(LPolicy.SessionScope, LPolicy), 'two scopes share the prefix');
end;

procedure TTestComplianceResumption.TestSessionScopeRandomHalfIsFresh;
var
  LPolicy: ICompliancePolicy;
  LFirst, LSecond: TBytes;
begin
  LPolicy := StrictPolicy;
  LFirst := LPolicy.SessionScope;
  LSecond := LPolicy.SessionScope;
  CheckFalse(AreEqual(System.Copy(LFirst, 16, 16), System.Copy(LSecond, 16, 16)),
    'each scope has its own random half');
end;

procedure TTestComplianceResumption.TestSessionScopePrefixDiffersBetweenPolicies;
var
  LFirst, LSecond: ICompliancePolicy;
begin
  LFirst := StrictPolicy;
  LSecond := StrictPolicy;
  CheckFalse(HasPrefixOf(LFirst.SessionScope, LSecond), 'each policy has its own prefix');
end;

procedure TTestComplianceResumption.TestClientCacheWithBuilderDefaultScopeIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientWithCache(LPolicy).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'a fresh random scope is not the policy');
end;

procedure TTestComplianceResumption.TestClientCacheWithPolicyScopeIsAdmitted;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ClientWithCache(LPolicy).WithResumptionScope(
    LPolicy.SessionScope).Build), TComplianceFindingKind.ResumptionStateUnchecked),
    'the policy scope');
end;

procedure TTestComplianceResumption.TestClientCacheWithForeignScopeIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientWithCache(LPolicy).WithResumptionScope(
    Crypto.Primitives.GetRandom.GenerateBytes(32)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'a scope the host made up');
end;

procedure TTestComplianceResumption.TestClientCacheWithAnotherPolicysScopeIsUnchecked;
var
  LPolicy, LOther: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  LOther := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientWithCache(LPolicy).WithResumptionScope(
    LOther.SessionScope).Build), TComplianceFindingKind.ResumptionStateUnchecked),
    'the scope of another policy instance');
end;

procedure TTestComplianceResumption.TestClientCacheWithScopeOneByteShortOfThePrefixIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientWithCache(LPolicy).WithResumptionScope(
    System.Copy(LPolicy.SessionScope, 0, 15)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'only 15 of the 16 prefix bytes');
end;

procedure TTestComplianceResumption.TestClientCacheWithTheBarePrefixIsAdmitted;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ClientWithCache(LPolicy).WithResumptionScope(
    System.Copy(LPolicy.SessionScope, 0, 16)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'exactly the 16 prefix bytes');
end;

procedure TTestComplianceResumption.TestClientWithoutCacheHasNoResumptionFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'a client with no cache keeps no sessions');
end;

procedure TTestComplianceResumption.TestFacadeServerCarriesThePolicyScope;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
begin
  LPolicy := StrictPolicy;
  LConfig := ServerBuilder(LPolicy).Build;
  CheckEquals(32, System.Length(LConfig.ResumptionScope), 'a full scope');
  CheckTrue(HasPrefixOf(LConfig.ResumptionScope, LPolicy), 'the policy prefix');
end;

procedure TTestComplianceResumption.TestFacadeServerHoldsThePolicyTicketKeys;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ServerBuilder(LPolicy).Build.SessionTicketKeys is TComplianceTicketKeys,
    'the keys the policy minted');
end;

procedure TTestComplianceResumption.TestFacadeServerIsAdmitted;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ServerAdmit(LPolicy, ServerBuilder(LPolicy).Build, LFindings), 'admitted');
  CheckEquals(0, System.Length(LFindings), 'with no finding');
end;

procedure TTestComplianceResumption.TestFacadeServerKeysRotateOnTheTicketLifetime;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
  LKeys: IComplianceTicketKeys;
begin
  LPolicy := StrictPolicy;
  LConfig := ServerBuilder(LPolicy).Build;
  CheckTrue(Supports(LConfig.SessionTicketKeys, IComplianceTicketKeys, LKeys), 'policy keys');
  CheckEquals(LConfig.TicketLifetimeSeconds, LKeys.LifetimeSeconds, 'the lifetime of the tickets');
  CheckFalse(Disclosed(LPolicy.Evaluate(LConfig), 'ticket lifetime'), 'so nothing is disclosed');
end;

procedure TTestComplianceResumption.TestFacadeServerWithoutAes256HoldsNoTicketState;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ServerBuilder(Aes128Policy).Build;
  CheckTrue(LConfig.SessionTicketKeys = nil, 'no keys');
  CheckEquals(0, System.Length(LConfig.ResumptionScope), 'no scope');
end;

procedure TTestComplianceResumption.TestWithoutResumptionTurnsResumptionOff;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  LConfig := TComplianceTls.WithoutResumption(ServerBuilder(LPolicy)).Build;
  CheckFalse(LConfig.Resumption, 'resumption is off');
  CheckTrue(LConfig.SessionTicketKeys = nil, 'the facade ticket keys are cleared');
  CheckEquals(0, System.Length(LConfig.ResumptionScope), 'and so is the scope');
  CheckFalse(ServerAdmit(LPolicy, LConfig, LFindings), 'and the config is admitted');
  CheckEquals(0, System.Length(LFindings), 'with no finding');
end;

procedure TTestComplianceResumption.TestWithResumptionFalseAloneStillRaises;
var
  LRaised: Boolean;
begin
  // the builder refuses ticket settings while resumption is off, and the facade set both
  LRaised := False;
  try
    ServerBuilder(StrictPolicy).WithResumption(False).Build;
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the facade ticket keys and scope remain');
end;

procedure TTestComplianceResumption.TestWithoutResumptionRejectsNilBuilder;
var
  LRaised: Boolean;
  LNone: ITlsServerConfigBuilder;
begin
  LRaised := False;
  LNone := nil;
  try
    TComplianceTls.WithoutResumption(LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil builder');
end;

procedure TTestComplianceResumption.TestMtlsFacadeServerIsAdmitted;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
begin
  LPolicy := StrictPolicy;
  // the build refuses explicit ticket keys without a scope under client authentication
  LConfig := MtlsServerBuilder(LPolicy, TRevocationPosture.Soft).Build;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(LConfig),
    TComplianceFindingKind.ResumptionStateUnchecked), 'the scope is the policy scope');
end;

procedure TTestComplianceResumption.TestServerStoreWithPolicyScopeIsAdmitted;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(nil)
    .WithSessionStore(NewStore(LPolicy)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'a store under the policy scope');
end;

procedure TTestComplianceResumption.TestServerStoreWithForeignScopeIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(nil)
    .WithSessionStore(NewStore(LPolicy)).WithResumptionScope(
    Crypto.Primitives.GetRandom.GenerateBytes(32)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'a store under a scope of the host');
end;

procedure TTestComplianceResumption.TestServerStoreWithEmptyScopeIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(nil)
    .WithSessionStore(NewStore(LPolicy)).WithResumptionScope(nil).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'an empty scope shares the store');
end;

procedure TTestComplianceResumption.TestServerKeysWithForeignScopeIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithResumptionScope(
    Crypto.Primitives.GetRandom.GenerateBytes(32)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'keys under a scope of the host');
end;

procedure TTestComplianceResumption.TestPlainServerDefaultKeysAreUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(RawServer(LPolicy).WithCredential(
    ServerCredential(LPolicy.Crypto)).Build), TComplianceFindingKind.TicketKeysUnchecked),
    'the default keys are the builder''s own');
end;

procedure TTestComplianceResumption.TestPlainServerWithoutScopeIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(RawServer(LPolicy).WithCredential(
    ServerCredential(LPolicy.Crypto)).Build), TComplianceFindingKind.ResumptionStateUnchecked),
    'the default keys have no scope');
end;

procedure TTestComplianceResumption.TestHostStekKeysAreUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .Build), TComplianceFindingKind.TicketKeysUnchecked), 'keys over the portable random');
end;

procedure TTestComplianceResumption.TestAnotherPolicysTicketKeysAreUnchecked;
var
  LPolicy, LOther: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  LOther := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    LOther.TicketKeys(TSystemClock.Create as ITlsClock, 7200)).Build),
    TComplianceFindingKind.TicketKeysUnchecked), 'keys another policy minted');
end;

procedure TTestComplianceResumption.TestHostClassClaimingTheMarkerIsUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    TClaimingTicketKeys.Create(LPolicy) as ISessionTicketKeyManager).Build),
    TComplianceFindingKind.TicketKeysUnchecked), 'a class that only lists the marker');
end;

procedure TTestComplianceResumption.TestPolicyTicketKeysAreAdmitted;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    LPolicy.TicketKeys(TSystemClock.Create as ITlsClock, 7200)).Build),
    TComplianceFindingKind.TicketKeysUnchecked), 'keys the policy minted');
end;

procedure TTestComplianceResumption.TestTicketKeysLifetimeMismatchIsDisclosed;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    LPolicy.TicketKeys(TSystemClock.Create as ITlsClock, 3600)).Build), 'ticket lifetime'),
    'keys for 3600 seconds beside the default 7200');
end;

procedure TTestComplianceResumption.TestTicketKeysLifetimeMatchIsNotDisclosed;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).WithTicketLifetime(3600)
    .WithSessionTicketKeys(LPolicy.TicketKeys(TSystemClock.Create as ITlsClock, 3600)).Build),
    'ticket lifetime'), 'keys and tickets both for 3600 seconds');
end;

procedure TTestComplianceResumption.TestFleetKeysWithoutWrapperAreUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    TFleetTicketKeyManager.Create as IFleetTicketKeyManager).Build),
    TComplianceFindingKind.TicketKeysUnchecked), 'a fleet the policy never checked');
end;

procedure TTestComplianceResumption.TestCheckedFleetKeysWithTheFleetScopeAreAdmitted;
var
  LPolicy: ICompliancePolicy;
  LFindings: TArray<TComplianceFinding>;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ServerAdmit(LPolicy, FleetServerBuilder(LPolicy, NewFleet, FleetScope).Build,
    LFindings), 'a fleet behind the policy wrapper, under the scope the host gave it');
  CheckEquals(0, System.Length(LFindings), 'with no finding');
end;

procedure TTestComplianceResumption.TestCheckedFleetKeysWithAnotherScopeAreUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithResumptionScope(FleetScope)
    .WithSessionTicketKeys(LPolicy.CheckedTicketKeys(NewFleet, FleetScope)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'a scope other than the fleet scope');
end;

procedure TTestComplianceResumption.TestCheckedFleetKeysWithAPolicyScopeAreUnchecked;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    LPolicy.CheckedTicketKeys(NewFleet, FleetScope)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked),
    'the policy prefix does not stand for the fleet scope');
end;

procedure TTestComplianceResumption.TestCheckedFleetOfAnotherPolicyIsUnchecked;
var
  LPolicy, LOther: ICompliancePolicy;
  LScope: TBytes;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LOther := StrictPolicy;
  LScope := FleetScope;
  LReport := LPolicy.Evaluate(ServerBuilder(LPolicy).WithResumptionScope(LScope)
    .WithSessionTicketKeys(LOther.CheckedTicketKeys(NewFleet, LScope)).Build);
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.TicketKeysUnchecked),
    'a fleet another policy wrapped');
  CheckTrue(ReportHasKind(LReport, TComplianceFindingKind.ResumptionStateUnchecked),
    'and its scope is not the policy''s either');
end;

procedure TTestComplianceResumption.TestCheckedFleetKeysAreDisclosed;
var
  LPolicy: ICompliancePolicy;
  LScope: TBytes;
begin
  LPolicy := StrictPolicy;
  LScope := FleetScope;
  CheckTrue(Disclosed(LPolicy.Evaluate(FleetServerBuilder(LPolicy, NewFleet, LScope).Build),
    'keys are entered by the host'), 'the host still chose the keys');
end;

procedure TTestComplianceResumption.TestCheckedFleetScopeIsDisclosed;
var
  LPolicy: ICompliancePolicy;
  LScope: TBytes;
begin
  LPolicy := StrictPolicy;
  LScope := FleetScope;
  CheckTrue(Disclosed(LPolicy.Evaluate(FleetServerBuilder(LPolicy, NewFleet, LScope).Build),
    'the fleet scope is entered by the host'), 'and so did the scope');
  CheckFalse(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).Build), 'fleet scope'),
    'control: the policy keys disclose no scope');
end;

procedure TTestComplianceResumption.TestKeysBesideAStoreAreNotChecked;
var
  LPolicy: ICompliancePolicy;
  LHostKeys: ISessionTicketKeyManager;
  LReport: IComplianceReport;
begin
  LPolicy := StrictPolicy;
  LHostKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager;
  LReport := LPolicy.Evaluate(Tls13OnlyServerBuilder(LPolicy).WithSessionTicketKeys(LHostKeys)
    .WithSessionStore(NewStore(LPolicy)).Build);
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.TicketKeysUnchecked),
    'TLS 1.3 seals with the store alone, so the keys beside it are idle');
  CheckFalse(ReportHasKind(LReport, TComplianceFindingKind.ResumptionStateUnchecked),
    'and the store runs under the policy scope');
end;

procedure TTestComplianceResumption.TestKeysBesideAStoreUnderTls12AreChecked;
var
  LPolicy: ICompliancePolicy;
  LHostKeys: ISessionTicketKeyManager;
begin
  LPolicy := StrictPolicy;
  LHostKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(LHostKeys)
    .WithSessionStore(NewStore(LPolicy)).Build), TComplianceFindingKind.TicketKeysUnchecked),
    'TLS 1.2 seals with the keys even beside a store');
end;

procedure TTestComplianceResumption.TestFleetBesideAStoreIsNotDisclosed;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(Disclosed(LPolicy.Evaluate(Tls13OnlyServerBuilder(LPolicy)
    .WithSessionTicketKeys(NewFleet).WithSessionStore(NewStore(LPolicy)).Build),
    'entered by the host'),
    'keys the TLS 1.3 engine never uses are not the host''s choice');
end;

procedure TTestComplianceResumption.TestIdleCheckedFleetBesideAStoreAcceptsTheFleetScope;
var
  LPolicy: ICompliancePolicy;
  LScope: TBytes;
begin
  LPolicy := StrictPolicy;
  LScope := FleetScope;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(Tls13OnlyServerBuilder(LPolicy)
    .WithResumptionScope(LScope).WithSessionTicketKeys(LPolicy.CheckedTicketKeys(NewFleet,
    LScope)).WithSessionStore(NewStore(LPolicy)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked),
    'the store runs under the scope the host gave the fleet');
end;

procedure TTestComplianceResumption.TestIdleCheckedFleetBesideAStoreAcceptsThePolicyScope;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(Tls13OnlyServerBuilder(LPolicy)
    .WithSessionTicketKeys(LPolicy.CheckedTicketKeys(NewFleet, FleetScope))
    .WithSessionStore(NewStore(LPolicy)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked),
    'the store is as well kept apart by the policy scope');
end;

procedure TTestComplianceResumption.TestIdleCheckedFleetBesideAStoreRefusesAnotherScope;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(Tls13OnlyServerBuilder(LPolicy)
    .WithResumptionScope(Filled($42, 32)).WithSessionTicketKeys(LPolicy.CheckedTicketKeys(
    NewFleet, FleetScope)).WithSessionStore(NewStore(LPolicy)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'neither the fleet scope nor the policy''s');
end;

procedure TTestComplianceResumption.TestFleetBesideAStoreUnderTls12IsDisclosed;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(Disclosed(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(NewFleet)
    .WithSessionStore(NewStore(LPolicy)).Build), 'entered by the host'),
    'the TLS 1.2 engine seals with the fleet keys');
end;

procedure TTestComplianceResumption.TestCheckedFleetBesideAStoreUnderTls12KeepsTheFleetScope;
var
  LPolicy: ICompliancePolicy;
  LScope: TBytes;
begin
  LPolicy := StrictPolicy;
  LScope := FleetScope;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(FleetServerBuilder(LPolicy, NewFleet, LScope)
    .WithSessionStore(NewStore(LPolicy)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked), 'the fleet scope is the one that fits');
end;

procedure TTestComplianceResumption.TestCheckedFleetBesideAStoreUnderTls12RefusesThePolicyScope;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy).WithSessionTicketKeys(
    LPolicy.CheckedTicketKeys(NewFleet, FleetScope)).WithSessionStore(NewStore(LPolicy)).Build),
    TComplianceFindingKind.ResumptionStateUnchecked),
    'the policy scope does not stand for the fleet keys');
end;

procedure TTestComplianceResumption.TestTicketKeysAreMintedFromThePolicyRandom;
var
  LRandom: TFilledRandom;
  LKeys: ISessionTicketKeyManager;
  LName: TBytes;
  LKey, LFound: ISecretBuffer;
  LBefore: Int32;
  LHold: IRandom;
  LPolicy: ICompliancePolicy;
begin
  LRandom := TFilledRandom.Create($5A);
  LHold := LRandom as IRandom;
  LPolicy := PolicyOverRandom(LHold);
  LBefore := LRandom.Drawn;
  LKeys := LPolicy.TicketKeys(TSystemClock.Create as ITlsClock, 7200);
  CheckTrue(LKeys.CurrentKey(LName, LKey), 'a current key');
  CheckEquals(LBefore + 48, LRandom.Drawn, 'a name and a key came out of the policy random');
  CheckEqualBytes('its name comes from the policy random', Filled($5A, 16), LName);
  CheckEqualBytes('and so does the key', Filled($5A, 32), LKey.ToBytes);
  CheckEquals(16, LKeys.KeyNameLength, 'the name length');
  CheckTrue(LKeys.KeyByName(LName, LFound), 'found by name');
end;

procedure TTestComplianceResumption.TestTicketKeysRotateForwards;
var
  LKeys: IRotatingTicketKeyManager;
  LBefore, LAfter: TBytes;
  LKey: ISecretBuffer;
begin
  LKeys := StrictPolicy.TicketKeys(TSystemClock.Create as ITlsClock, 7200);
  LKeys.CurrentKey(LBefore, LKey);
  LKeys.Rotate;
  LKeys.CurrentKey(LAfter, LKey);
  CheckFalse(AreEqual(LBefore, LAfter), 'a fresh current key');
end;

procedure TTestComplianceResumption.TestCheckedFleetInstallKeyForwards;
var
  LPolicy: ICompliancePolicy;
  LFleet: IFleetTicketKeyManager;
  LName, LCurrent: TBytes;
  LKey: ISecretBuffer;
begin
  LPolicy := StrictPolicy;
  LFleet := NewFleet;
  LName := Crypto.Primitives.GetRandom.GenerateBytes(16);
  (LPolicy.CheckedTicketKeys(LFleet, FleetScope) as IFleetTicketKeyManager).InstallKey(LName,
    TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32)));
  CheckTrue(LFleet.CurrentKey(LCurrent, LKey), 'the fleet holds the key');
  CheckTrue(AreEqual(LName, LCurrent), 'under the installed name');
end;

procedure TTestComplianceResumption.TestTicketKeysRejectNilClock;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    StrictPolicy.TicketKeys(nil, 7200);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil clock');
end;

procedure TTestComplianceResumption.TestTicketKeysRejectZeroLifetime;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    StrictPolicy.TicketKeys(TSystemClock.Create as ITlsClock, 0);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a zero lifetime would rotate on a fallback the keys do not record');
end;

procedure TTestComplianceResumption.TestTicketKeysRefusedWithoutAes256;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Aes128Policy.TicketKeys(TSystemClock.Create as ITlsClock, 7200);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the keys seal with AES-256-GCM');
end;

procedure TTestComplianceResumption.TestCheckedTicketKeysRejectNilFleet;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    StrictPolicy.CheckedTicketKeys(nil, FleetScope);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil fleet');
end;

procedure TTestComplianceResumption.TestCheckedTicketKeysRejectEmptyScope;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    StrictPolicy.CheckedTicketKeys(NewFleet, nil);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty scope partitions nothing');
end;

procedure TTestComplianceResumption.TestCheckedTicketKeysAcceptTheLongestScope;
begin
  CheckTrue(StrictPolicy.CheckedTicketKeys(NewFleet, Filled($01, 32)) <> nil,
    'the builder accepts 32 bytes');
end;

procedure TTestComplianceResumption.TestCheckedTicketKeysRejectAScopeOneByteTooLong;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    StrictPolicy.CheckedTicketKeys(NewFleet, Filled($01, 33));
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the builder would refuse 33 bytes');
end;

procedure TTestComplianceResumption.TestTicketKeysWrapperRejectsNilPolicy;
var
  LKeys: IComplianceTicketKeys;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    LKeys := TComplianceTicketKeys.Create(nil, TSystemClock.Create as ITlsClock, 7200)
      as IComplianceTicketKeys;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil policy');
end;

procedure TTestComplianceResumption.TestTicketKeysWrapperRejectsNilClock;
var
  LKeys: IComplianceTicketKeys;
  LRaised: Boolean;
  LNone: ITlsClock;
begin
  LRaised := False;
  LNone := nil;
  try
    LKeys := TComplianceTicketKeys.Create(StrictPolicy, LNone, 7200) as IComplianceTicketKeys;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil clock');
end;

procedure TTestComplianceResumption.TestTicketKeysWrapperRejectsZeroLifetime;
var
  LKeys: IComplianceTicketKeys;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    LKeys := TComplianceTicketKeys.Create(StrictPolicy, TSystemClock.Create as ITlsClock, 0)
      as IComplianceTicketKeys;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'zero lifetime');
end;

procedure TTestComplianceResumption.TestFleetWrapperRejectsNilPolicy;
var
  LKeys: IComplianceTicketKeys;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    LKeys := TComplianceFleetTicketKeys.Create(nil, NewFleet, FleetScope)
      as IComplianceTicketKeys;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil policy');
end;

procedure TTestComplianceResumption.TestFleetWrapperRejectsNilInner;
var
  LKeys: IComplianceTicketKeys;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    LKeys := TComplianceFleetTicketKeys.Create(StrictPolicy, nil, FleetScope)
      as IComplianceTicketKeys;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil inner fleet');
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

function TTestComplianceRoots.SourceOf(const AConfig: ITlsClientConfig): TOSVerifierSource;
begin
  Result := nil;
  CheckTrue(AConfig.ServerVerifierSource is TOSVerifierSource, 'the verification is the OS source');
  Result := AConfig.ServerVerifierSource as TOSVerifierSource;
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
  LSource: TOSVerifierSource;
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
  LSource: TOSVerifierSource;
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
  LSource: TOSVerifierSource;
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

{ TTestComplianceMtls }

function TTestComplianceMtls.FakeClientVerification: IClientVerificationBuilder;
begin
  Result := TClientVerification.VerifierSource(TFakeOsVerifierSources.Client,
    TTlsLibTestCertificates.EcP256RootStore);
end;

function TTestComplianceMtls.LooseClientVerification: IClientVerificationBuilder;
var
  LStrength: TCertificateStrengthPolicy;
begin
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.AnchorKeyFloors := False;
  Result := FakeClientVerification.WithMinimumStrength(LStrength);
end;

function TTestComplianceMtls.WeakClientCa: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert'))) as ITrustAnchorStore;
end;

function TTestComplianceMtls.ClientCaOrSkip(const APolicy: ICompliancePolicy;
  const AClientCa: ITrustAnchorStore; out ABuilder: ITlsServerConfigBuilder): Boolean;
begin
  ABuilder := nil;
  Result := TOSSystemTrust.Supports(TSystemTrustMode.Delegate);
  if not Result then
  begin
    SkipTest('this platform has no OS verifier');
    Exit;
  end;
  ABuilder := TComplianceTls.WithPeerAuth(APolicy, ServerBuilder(APolicy),
    TClientAuthMode.Required, AClientCa);
end;

function TTestComplianceMtls.LiveOrSkip(APosture: TRevocationPosture;
  out ABuilder: ITlsServerConfigBuilder): Boolean;
var
  LPolicy: ICompliancePolicy;
begin
  ABuilder := nil;
  Result := TOSSystemTrust.Supports(TSystemTrustMode.Delegate);
  if not Result then
  begin
    SkipTest('this platform has no OS verifier');
    Exit;
  end;
  LPolicy := StrictPolicy;
  try
    ABuilder := TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy),
      TClientAuthMode.Required, TTlsLibTestCertificates.EcP256RootStore, APosture, 1000);
  except
    on ESystemTrustUnsupportedTlsLibException do
    begin
      Result := False;
      SkipTest('this platform has no OS live revocation');
    end;
  end;
end;

procedure TTestComplianceMtls.TestVerificationOverloadReplacesALooseMinimumStrength;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
begin
  LPolicy := Rsa3072Policy;
  LConfig := TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy),
    TClientAuthMode.Required, LooseClientVerification).Build;
  CheckEquals(Int32(LPolicy.Rules.Strength.MinRsaModulusBits),
    Int32(LConfig.CertificateStrengthPolicy.MinRsaModulusBits),
    'the config strength is the rules, not the looser one set first');
  CheckTrue(LConfig.CertificateStrengthPolicy.AnchorKeyFloors, 'and the anchors are held to it');
end;

procedure TTestComplianceMtls.TestVerificationOverloadLeavesNoStrengthFinding;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ServerBuilder(LPolicy)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(LooseClientVerification.Build).Build),
    TComplianceFindingKind.StrengthBelowRules), 'control: hand-wired with the loose strength');
  CheckFalse(ReportHasKind(LPolicy.Evaluate(TComplianceTls.WithPeerAuth(LPolicy,
    ServerBuilder(LPolicy), TClientAuthMode.Required, LooseClientVerification).Build),
    TComplianceFindingKind.StrengthBelowRules), 'the floors are the rules');
end;

procedure TTestComplianceMtls.TestVerificationOverloadCarriesRequired;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckEquals(Ord(TClientAuthMode.Required), Ord(TComplianceTls.WithPeerAuth(LPolicy,
    ServerBuilder(LPolicy), TClientAuthMode.Required, FakeClientVerification).Build.ClientAuth),
    'the mode');
end;

procedure TTestComplianceMtls.TestVerificationOverloadCarriesRequested;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckEquals(Ord(TClientAuthMode.Requested), Ord(TComplianceTls.WithPeerAuth(LPolicy,
    ServerBuilder(LPolicy), TClientAuthMode.Requested, FakeClientVerification).Build.ClientAuth),
    'the mode');
end;

procedure TTestComplianceMtls.TestVerificationOverloadStrictBuildServerAdmits;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(TComplianceTls.BuildServer(LPolicy, TComplianceTls.WithPeerAuth(LPolicy,
    ServerBuilder(LPolicy), TClientAuthMode.Required, FakeClientVerification)) <> nil,
    'admitted');
end;

procedure TTestComplianceMtls.TestVerificationOverloadRejectsModeNone;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.None,
      FakeClientVerification);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'no client certificate is not mutual TLS');
end;

procedure TTestComplianceMtls.TestVerificationOverloadRejectsNilPolicy;
var
  LNone: ICompliancePolicy;
  LRaised: Boolean;
begin
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LNone, ServerBuilder(StrictPolicy), TClientAuthMode.Required,
      FakeClientVerification);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil policy');
end;

procedure TTestComplianceMtls.TestVerificationOverloadRejectsNilBuilder;
var
  LNone: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(StrictPolicy, LNone, TClientAuthMode.Required,
      FakeClientVerification);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil builder');
end;

procedure TTestComplianceMtls.TestVerificationOverloadRejectsNilVerification;
var
  LPolicy: ICompliancePolicy;
  LNone: IClientVerificationBuilder;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.Required,
      LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil verification');
end;

procedure TTestComplianceMtls.TestClientCaOverloadUsesTheOsVerifierSource;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  if not ClientCaOrSkip(StrictPolicy, TTlsLibTestCertificates.EcP256RootStore, LBuilder) then
    Exit;
  CheckTrue(LBuilder.Build.ClientVerifierSource is TOSVerifierSource,
    'the client chain is verified by the OS source');
end;

procedure TTestComplianceMtls.TestClientCaOverloadKeepsTheChainInModule;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
begin
  LPolicy := StrictPolicy;
  if not ClientCaOrSkip(LPolicy, TTlsLibTestCertificates.EcP256RootStore, LBuilder) then
    Exit;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(LBuilder.Build),
    TComplianceFindingKind.ChainVerifiedOutsideModule), 'the OS verifier decides');
end;

procedure TTestComplianceMtls.TestClientCaOverloadLeavesNoStrengthFinding;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
begin
  LPolicy := StrictPolicy;
  if not ClientCaOrSkip(LPolicy, TTlsLibTestCertificates.EcP256RootStore, LBuilder) then
    Exit;
  CheckFalse(ReportHasKind(LPolicy.Evaluate(LBuilder.Build),
    TComplianceFindingKind.StrengthBelowRules), 'the floors are the rules');
end;

procedure TTestComplianceMtls.TestClientCaOverloadRejectsNilStore;
var
  LPolicy: ICompliancePolicy;
  LNone: ITrustAnchorStore;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.Required, LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil client CA');
end;

procedure TTestComplianceMtls.TestClientCaOverloadRejectsEmptyStore;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.Required,
      TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client CA with no roots');
end;

procedure TTestComplianceMtls.TestClientCaOverloadRefusesAWeakCaAtBuild;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LPolicy := Rsa3072Policy;
  if not ClientCaOrSkip(LPolicy, TTlsLibTestCertificates.EcP256RootStore, LBuilder) then
    Exit;
  CheckTrue(LBuilder.Build <> nil, 'control: a strong CA builds');
  if not ClientCaOrSkip(LPolicy, WeakClientCa, LBuilder) then
    Exit;
  LRaised := False;
  try
    TComplianceTls.BuildServer(LPolicy, LBuilder);
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an RSA-2048 client CA is below a 3072-bit floor');
end;

procedure TTestComplianceMtls.TestClientCaOverloadRaisesWithoutAnOsDelegate;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
  begin
    SkipTest('this platform has an OS verifier');
    Exit;
  end;
  LPolicy := StrictPolicy;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.Required,
      TTlsLibTestCertificates.EcP256RootStore);
  except
    on ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'no fallback to the built-in verifier');
end;

procedure TTestComplianceMtls.TestLiveOverloadDefersToLiveRevocation;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  if not LiveOrSkip(TRevocationPosture.Soft, LBuilder) then
    Exit;
  CheckEquals(Ord(TVerdictDeferral.LiveRevocation),
    Ord(LBuilder.Build.AsyncCertificateVerdict.Deferral), 'the deferral');
end;

procedure TTestComplianceMtls.TestLiveOverloadKeepsThePosture;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  if not LiveOrSkip(TRevocationPosture.Hard, LBuilder) then
    Exit;
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LBuilder.Build.RevocationPosture), 'the posture');
end;

procedure TTestComplianceMtls.TestLiveOverloadDisclosesTheHostResolver;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  if not LiveOrSkip(TRevocationPosture.Soft, LBuilder) then
    Exit;
  CheckTrue(Disclosed(StrictPolicy.Evaluate(LBuilder.Build), 'host-owned'),
    'the resolver of the host cannot be inspected');
end;

procedure TTestComplianceMtls.TestLiveOverloadBuildsUnderHard;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  if not LiveOrSkip(TRevocationPosture.Hard, LBuilder) then
    Exit;
  CheckTrue(LBuilder.Build <> nil, 'Hard needs the live verdict, which the overload sets');
end;

procedure TTestComplianceMtls.TestLiveOverloadRejectsEmptyStore;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.Required,
      TTrustAnchorStore.Create(nil) as ITrustAnchorStore, TRevocationPosture.Soft, 1000);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client CA with no roots');
end;

procedure TTestComplianceMtls.TestClientCaOverloadRejectsNilPolicyBeforeTheOsSource;
var
  LNone: ICompliancePolicy;
  LRaised: Boolean;
begin
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LNone, ServerBuilder(StrictPolicy), TClientAuthMode.Required,
      TTlsLibTestCertificates.EcP256RootStore);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an argument error on every platform');
end;

procedure TTestComplianceMtls.TestClientCaOverloadRejectsNilBuilderBeforeTheOsSource;
var
  LNone: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(StrictPolicy, LNone, TClientAuthMode.Required,
      TTlsLibTestCertificates.EcP256RootStore);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an argument error on every platform');
end;

procedure TTestComplianceMtls.TestClientCaOverloadRejectsModeNoneBeforeTheOsSource;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.None,
      TTlsLibTestCertificates.EcP256RootStore);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an argument error on every platform');
end;

procedure TTestComplianceMtls.TestLiveOverloadRejectsNilPolicyBeforeTheOsSource;
var
  LNone: ICompliancePolicy;
  LRaised: Boolean;
begin
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LNone, ServerBuilder(StrictPolicy), TClientAuthMode.Required,
      TTlsLibTestCertificates.EcP256RootStore, TRevocationPosture.Soft, 1000);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an argument error on every platform');
end;

procedure TTestComplianceMtls.TestLiveOverloadRejectsNilBuilderBeforeTheOsSource;
var
  LNone: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LNone := nil;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(StrictPolicy, LNone, TClientAuthMode.Required,
      TTlsLibTestCertificates.EcP256RootStore, TRevocationPosture.Soft, 1000);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an argument error on every platform');
end;

procedure TTestComplianceMtls.TestLiveOverloadRejectsModeNoneBeforeTheOsSource;
var
  LPolicy: ICompliancePolicy;
  LRaised: Boolean;
begin
  LPolicy := StrictPolicy;
  LRaised := False;
  try
    TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.None,
      TTlsLibTestCertificates.EcP256RootStore, TRevocationPosture.Soft, 1000);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an argument error on every platform');
end;

procedure TTestComplianceMtls.TestVerificationOverloadChangesTheCallersBuilderInPlace;
var
  LPolicy: ICompliancePolicy;
  LVerification: IClientVerificationBuilder;
begin
  LPolicy := Rsa3072Policy;
  LVerification := LooseClientVerification;
  CheckEquals(2048, Int32(LVerification.Build.StrengthPolicy.MinRsaModulusBits),
    'control: the builder starts looser than the rules');
  TComplianceTls.WithPeerAuth(LPolicy, ServerBuilder(LPolicy), TClientAuthMode.Required,
    LVerification);
  CheckEquals(Int32(LPolicy.Rules.Strength.MinRsaModulusBits),
    Int32(LVerification.Build.StrengthPolicy.MinRsaModulusBits),
    'the caller''s builder now carries the floors of the rules');
end;

procedure TTestComplianceMtls.TestClientCaOverloadSourceNeedsNoLiveVerdict;
var
  LBuilder: ITlsServerConfigBuilder;
  LContext: TClientTrustContext;
begin
  if not ClientCaOrSkip(StrictPolicy, TTlsLibTestCertificates.EcP256RootStore, LBuilder) then
    Exit;
  LContext := Default(TClientTrustContext);
  LContext.Deferral := TVerdictDeferral.None;
  CheckTrue(LBuilder.Build.ClientVerifierSource.CreateClientVerifier(LContext) <> nil,
    'a cache-only source builds its verifier without the live verdict');
end;

procedure TTestComplianceMtls.TestLiveOverloadSourceRefusesWithoutTheLiveVerdict;
var
  LBuilder: ITlsServerConfigBuilder;
  LContext: TClientTrustContext;
  LRaised: Boolean;
begin
  if not LiveOrSkip(TRevocationPosture.Soft, LBuilder) then
    Exit;
  LContext := Default(TClientTrustContext);
  LContext.Deferral := TVerdictDeferral.None;
  LRaised := False;
  try
    LBuilder.Build.ClientVerifierSource.CreateClientVerifier(LContext);
  except
    on ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a live source refuses a context that defers nothing to the live verdict');
end;

procedure TTestComplianceMtls.TestLiveOverloadSourceAcceptsTheLiveVerdict;
var
  LBuilder: ITlsServerConfigBuilder;
  LContext: TClientTrustContext;
begin
  if not LiveOrSkip(TRevocationPosture.Soft, LBuilder) then
    Exit;
  LContext := Default(TClientTrustContext);
  LContext.Deferral := TVerdictDeferral.LiveRevocation;
  CheckTrue(LBuilder.Build.ClientVerifierSource.CreateClientVerifier(LContext) <> nil,
    'control: the same source builds once the live verdict is deferred to');
end;

{ TTestComplianceAnchorFloors }

function TTestComplianceAnchorFloors.AcceptsAnchor(const APolicy: ICompliancePolicy;
  const ALeaf, ARoot: TBytes; AOverride, AFlag: Boolean;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LConfig: ITlsClientConfig;
  LResult: TPlatformChainResult;
  LEngine: IPlatformChainEngine;
  LDelegate: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LConfig := ClientBuilder(APolicy).Build;
  LResult := Default(TPlatformChainResult);
  LResult.Outcome := TLiveRevocationOutcome.Good;
  LResult.Path := TArray<TBytes>.Create(ALeaf, ARoot);
  LResult.PolicyExempt := TArray<TBytes>.Create(ARoot);
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True, LResult, TTlsAlertDescription.BadCertificate);
  LDelegate := TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  if AOverride then
    LDelegate.StrengthPolicy.AnchorKeyFloors := AFlag;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LDelegate) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(TArray<TBytes>.Create(ALeaf),
    TServerName.DnsName('localhost'), nil, LVerified, AAlert);
end;

function TCompliancePolicyTestCase.Rsa3072Policy: ICompliancePolicy;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.MinRsaModulusBits := 3072;
  LRules.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
  Result := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
end;

function TTestComplianceAnchorFloors.P384Policy: ICompliancePolicy;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  Result := NewPolicy(LRules, SystemBaseWithKey, TModuleStatus.Validated,
    TComplianceEnforcement.Strict);
end;

procedure TTestComplianceAnchorFloors.TestFacadeClientCarriesTheAnchorFlagIntoTheConfig;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(ClientBuilder(LPolicy).Build.CertificateStrengthPolicy.AnchorKeyFloors,
    'the verifier policy holds anchors to the floors');
end;

procedure TTestComplianceAnchorFloors.TestFacadeMtlsServerClientVerificationCarriesTheAnchorFlag;
var
  LPolicy: ICompliancePolicy;
begin
  LPolicy := StrictPolicy;
  CheckTrue(MtlsServerBuilder(LPolicy, TRevocationPosture.Soft).Build
    .CertificateStrengthPolicy.AnchorKeyFloors, 'the client-certificate verifier does too');
end;

procedure TTestComplianceAnchorFloors.TestClientWhoseAnchorsAreExemptIsBelowTheRules;
var
  LPolicy: ICompliancePolicy;
  LBuilder: ITlsClientConfigBuilder;
  LStrength: TCertificateStrengthPolicy;
begin
  LPolicy := StrictPolicy;
  LStrength := LPolicy.Rules.Strength;
  LStrength.AnchorKeyFloors := False;
  LBuilder := ClientBuilder(LPolicy);
  LBuilder.WithServerVerification(TServerVerification.VerifierSource(
    TFakeOsVerifierSources.Server).WithMinimumStrength(LStrength).Build);
  CheckTrue(ReportHasKind(LPolicy.Evaluate(LBuilder.Build),
    TComplianceFindingKind.StrengthBelowRules), 'the flag is the only difference');
end;

procedure TTestComplianceAnchorFloors.TestRsa2048AnchorIsRefusedUnderARulesFloorOf3072;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(AcceptsAnchor(Rsa3072Policy, TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt',
    'leaf_cert'), TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert'), False,
    False, LAlert), 'the anchor key is below the floor');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert), 'the alert');
end;

procedure TTestComplianceAnchorFloors.TestRsa2048AnchorPassesWhenTheFlagIsCleared;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(AcceptsAnchor(Rsa3072Policy, TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt',
    'leaf_cert'), TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert'), True,
    False, LAlert), 'control: the same path with anchors exempt');
end;

procedure TTestComplianceAnchorFloors.TestFips140_3AcceptsAnRsa2048Anchor;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(AcceptsAnchor(StrictPolicy, TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt',
    'leaf_cert'), TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert'), False,
    False, LAlert), '2048 bits is inside the Fips140_3 range');
end;

procedure TTestComplianceAnchorFloors.TestAnchorOnACurveOutsideTheListIsRefused;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(AcceptsAnchor(P384Policy, TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt',
    'leaf_cert'), TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'), False,
    False, LAlert), 'a P-256 anchor where only P-384 is listed');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert), 'the alert');
end;

procedure TTestComplianceAnchorFloors.TestAnchorOnACurveOutsideTheListPassesWhenTheFlagIsCleared;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(AcceptsAnchor(P384Policy, TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt',
    'leaf_cert'), TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'), True,
    False, LAlert), 'control: the same path with anchors exempt');
end;

procedure TTestComplianceAnchorFloors.TestFips140_3AcceptsAP256Anchor;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(AcceptsAnchor(StrictPolicy, TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt',
    'leaf_cert'), TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'), False,
    False, LAlert), 'P-256 is in the Fips140_3 list');
end;

{ TWindowsModuleTestBase }

const
  ProductWorkstation = 1;
  ProductDomainController = 2;
  ProductServer = 3;
  MachineI386 = $014C;
  MachineAmd64 = $8664;
  MachineArm64 = $AA64;
  FirmwareBios = 1;
  FirmwareUefi = 2;

function TWindowsModuleTestBase.ValidFacts(ABuild: UInt32;
  AProductType: Byte): TWindowsModuleFacts;
begin
  Result := Default(TWindowsModuleFacts);
  Result.OsRead := True;
  Result.Major := 10;
  Result.Minor := 0;
  Result.Build := ABuild;
  Result.PlatformId := 2;
  Result.Revision := 3;
  Result.ProductType := AProductType;
  Result.Edition := 'Professional';
  Result.Process64Bit := True;
  Result.MachineRead := True;
  Result.ProcessMachine := 0;
  Result.NativeMachine := MachineAmd64;
  Result.FirmwareRead := True;
  Result.FirmwareType := FirmwareUefi;
  Result.PathRead := True;
  Result.ModulePath := 'C:\Windows\System32\bcryptprimitives.dll';
  Result.SystemModulePath := 'C:\Windows\System32\bcryptprimitives.dll';
  Result.SystemCopy := True;
  Result.BcryptRead := True;
  Result.BcryptSystemCopy := True;
  Result.NcryptRead := True;
  Result.NcryptSystemCopy := True;
  Result.VersionRead := True;
  Result.ModuleMajor := 10;
  Result.ModuleMinor := 0;
  Result.ModuleBuild := UInt16(ABuild);
  Result.ModuleRevision := 30001;
  Result.Today := 20270615;
  Result.LegacyFipsPolicy := TLegacyFipsPolicy.Disabled;
end;

function TWindowsModuleTestBase.Lists(const ADisclosures: TArray<string>;
  const AFragment: string): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to System.Length(ADisclosures) - 1 do
    if Pos(AFragment, ADisclosures[LI]) > 0 then
      Result := True;
end;

{ TTestWindowsModuleDecision }

procedure TTestWindowsModuleDecision.TestDecide22621WorkstationValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.Validated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(22621, ProductWorkstation), TModuleStandard.Fips140_3, LReason)),
    '22621 workstation, native x64');
  CheckEquals('', LReason, 'no reason when validated');
end;

procedure TTestWindowsModuleDecision.TestDecide20348ServerValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.Validated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(20348, ProductServer), TModuleStandard.Fips140_3, LReason)),
    '20348 server, native x64');
end;

procedure TTestWindowsModuleDecision.TestDecide20348DomainControllerValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.Validated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(20348, ProductDomainController), TModuleStandard.Fips140_3, LReason)),
    '20348 domain controller');
end;

procedure TTestWindowsModuleDecision.TestDecide22621ServerNotValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(22621, ProductServer), TModuleStandard.Fips140_3, LReason)),
    '22621 is the workstation release');
  CheckTrue(Pos('product type 3', LReason) > 0, 'the reason names the product type');
end;

procedure TTestWindowsModuleDecision.TestDecide22621DomainControllerNotValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(22621, ProductDomainController), TModuleStandard.Fips140_3, LReason)),
    '22621 is the workstation release');
end;

procedure TTestWindowsModuleDecision.TestDecide20348WorkstationNotValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(20348, ProductWorkstation), TModuleStandard.Fips140_3, LReason)),
    '20348 is the server release');
  CheckTrue(Pos('product type 1', LReason) > 0, 'the reason names the product type');
end;

procedure TTestWindowsModuleDecision.TestDecideEmulatedProcessNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.ProcessMachine := MachineAmd64;
  LFacts.NativeMachine := MachineArm64;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'an x64 process emulated on ARM64');
  CheckTrue(Pos('not x64', LReason) > 0, 'the machine it runs on is the reason');
end;

procedure TTestWindowsModuleDecision.TestDecideProcessUnderWow64OnX64NotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.ProcessMachine := MachineI386;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a process with an emulated machine on x64');
  CheckTrue(Pos('WOW64', LReason) > 0, 'the reason names the emulation layer');
  CheckEquals(0, Pos('x64 emulation', LReason), 'and no x64 emulation');
end;

procedure TTestWindowsModuleDecision.TestDecide32BitProcessOnWow64NotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Process64Bit := False;
  LFacts.ProcessMachine := MachineI386;
  LFacts.ModulePath := 'C:\Windows\SysWOW64\bcryptprimitives.dll';
  LFacts.SystemModulePath := 'C:\Windows\SysWOW64\bcryptprimitives.dll';
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a 32-bit process on 64-bit Windows');
  CheckTrue(Pos('32-bit', LReason) > 0, 'the bitness is the reason, not the 32-bit module path');
end;

procedure TTestWindowsModuleDecision.TestDecide32BitProcessBeatsUnreadableOs;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Process64Bit := False;
  LFacts.OsRead := False;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the bitness is known whatever the OS reports');
  CheckTrue(Pos('32-bit', LReason) > 0, 'the reason names the bitness');
end;

procedure TTestWindowsModuleDecision.TestDecideBiosFirmwareNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.FirmwareType := FirmwareBios;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'BIOS firmware');
  CheckTrue(Pos('firmware is BIOS, not UEFI', LReason) > 0, 'the reason names the firmware');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableFirmwareIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.FirmwareRead := False;
  LFacts.FirmwareType := 0;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'no firmware query');
  CheckTrue(Pos('firmware kind', LReason) > 0, 'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecide32BitProcessNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Process64Bit := False;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a process that is not 64-bit');
  CheckTrue(Pos('32-bit', LReason) > 0, 'the reason names the bitness');
  CheckTrue(Pos('the policy covers the 64-bit module only, and the tested environments are ' +
    '64-bit', LReason) > 0, 'and what the policy covers');
end;

procedure TTestWindowsModuleDecision.TestDecideNativeArm64NotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.NativeMachine := MachineArm64;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a native ARM64 process');
  CheckTrue(Pos('not x64', LReason) > 0, 'the reason names the machine');
end;

procedure TTestWindowsModuleDecision.TestDecideModuleBuildMismatchNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.ModuleBuild := 19041;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the module is another build');
  CheckTrue(Pos('file version is 10.0.19041.30001, not 10.0.22621', LReason) > 0,
    'the reason names both versions');
end;

procedure TTestWindowsModuleDecision.TestDecideModuleMajorMismatchNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.ModuleMajor := 6;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the module major version');
end;

procedure TTestWindowsModuleDecision.TestDecideModuleMinorMismatchNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.ModuleMinor := 1;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the module minor version');
end;

procedure TTestWindowsModuleDecision.TestDecideModuleNotSystemCopyNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.ModulePath := 'C:\Tools\bcryptprimitives.dll';
  LFacts.SystemCopy := False;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a module from another directory');
  CheckTrue(Pos('C:\Tools', LReason) > 0, 'the reason names the loaded path');
  CheckTrue(Pos('system copy C:\Windows\System32', LReason) > 0, 'and the system copy');
end;

procedure TTestWindowsModuleDecision.TestDecideBcryptNotSystemCopyNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.BcryptSystemCopy := False;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a bcrypt.dll from another directory');
  CheckTrue(Pos('bcrypt.dll', LReason) > 0, 'the reason names it');
  CheckEquals(0, Pos('ncrypt.dll', LReason), 'and not the other');
end;

procedure TTestWindowsModuleDecision.TestDecideNcryptNotSystemCopyNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.NcryptSystemCopy := False;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'an ncrypt.dll from another directory');
  CheckTrue(Pos('ncrypt.dll', LReason) > 0, 'the reason names it');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableImportsIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.BcryptRead := False;
  LFacts.BcryptSystemCopy := False;
  LFacts.NcryptRead := False;
  LFacts.NcryptSystemCopy := False;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the loaded copies could not be identified');
  CheckTrue(Pos('bcrypt.dll and ncrypt.dll', LReason) > 0, 'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableNcryptAloneIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.NcryptRead := False;
  LFacts.NcryptSystemCopy := False;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'bcrypt.dll is the system copy, ncrypt.dll is unread');
  CheckTrue(Pos('ncrypt.dll', LReason) > 0, 'the reason names the unread file');
  CheckFalse(Pos('bcrypt.dll', LReason) > 0, 'and not the one that was read');
end;

procedure TTestWindowsModuleDecision.TestDecideOtherBcryptWithUnreadableNcryptIsNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.BcryptSystemCopy := False;
  LFacts.NcryptRead := False;
  LFacts.NcryptSystemCopy := False;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a bcrypt.dll known not to be the system copy');
  CheckTrue(Pos('bcrypt.dll', LReason) > 0, 'the reason names it');
end;

procedure TTestWindowsModuleDecision.TestDecideOtherNcryptWithUnreadableBcryptIsNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.BcryptRead := False;
  LFacts.BcryptSystemCopy := False;
  LFacts.NcryptSystemCopy := False;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'an ncrypt.dll known not to be the system copy');
  CheckTrue(Pos('ncrypt.dll', LReason) > 0, 'the reason names it');
end;

procedure TTestWindowsModuleDecision.TestDecideWrongMajorNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Major := 6;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the OS major version');
  CheckTrue(Pos('NT 10.0', LReason) > 0, 'the reason names the release family');
end;

procedure TTestWindowsModuleDecision.TestDecideWrongMinorNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Minor := 1;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the OS minor version');
end;

procedure TTestWindowsModuleDecision.TestDecideWrongPlatformNotValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.PlatformId := 1;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the platform id');
end;

procedure TTestWindowsModuleDecision.TestDecide26100NotValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(26100, ProductWorkstation), TModuleStandard.Fips140_3, LReason)),
    '26100 is not validated');
  CheckTrue(Pos('no validated module', LReason) > 0, 'the table says so');
end;

procedure TTestWindowsModuleDecision.TestDecide22631NotValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(22631, ProductWorkstation), TModuleStandard.Fips140_3, LReason)),
    '22631 is not validated');
  CheckTrue(Pos('no validated module', LReason) > 0, 'the table says so');
end;

procedure TTestWindowsModuleDecision.TestDecideUnlistedBuildNotValidated;
var
  LReason: string;
begin
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(
    ValidFacts(12345, ProductWorkstation), TModuleStandard.Fips140_3, LReason)),
    'a build the table does not list');
  CheckTrue(Pos('no validated module', LReason) > 0, 'the table says so');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableOsIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.OsRead := False;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'an OS that could not be read');
  CheckTrue(Pos('OS build', LReason) > 0, 'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableMachinesIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.MachineRead := False;
  LFacts.NativeMachine := 0;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'no architecture query');
  CheckTrue(Pos('architectures', LReason) > 0, 'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableSystemDirectoryIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.SystemModulePath := '';
  LFacts.SystemCopy := False;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'no system directory to compare with');
  CheckTrue(Pos('system directory', LReason) > 0, 'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadablePathIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.PathRead := False;
  LFacts.ModulePath := '';
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'no module path');
  CheckTrue(Pos('path of the loaded module', LReason) > 0, 'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableVersionIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.VersionRead := False;
  LFacts.ModuleMajor := 0;
  LFacts.ModuleMinor := 0;
  LFacts.ModuleBuild := 0;
  LFacts.ModuleRevision := 0;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'no module file version');
  CheckTrue(Pos('file version of the loaded module', LReason) > 0,
    'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecideOnTheSunsetDayIsStillValidated;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Today := 20310830;
  CheckEquals(Ord(TModuleStatus.Validated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the sunset date itself is inside the certificate');
end;

procedure TTestWindowsModuleDecision.TestDecideAfterTheSunsetDayIsHistorical;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Today := 20310831;
  CheckEquals(Ord(TModuleStatus.Historical), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the day after the sunset date');
  CheckTrue(Pos('2031-08-30', LReason) > 0, 'the reason names the sunset date');
  CheckTrue(Pos('certificate 5410', LReason) > 0, 'and the certificate');
end;

procedure TTestWindowsModuleDecision.TestDecideUnreadableDateIsUnknown;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Today := 0;
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'no clock to compare with the sunset date');
  CheckTrue(Pos('current date', LReason) > 0, 'the reason says what was unread');
end;

procedure TTestWindowsModuleDecision.TestDecideSunsetDoesNotOutweighAMismatch;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Today := 20400101;
  LFacts.NativeMachine := MachineArm64;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a module that never applied is not historical');
end;

procedure TTestWindowsModuleDecision.TestDecideMismatchBeatsUnreadable;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.VersionRead := False;
  LFacts.NativeMachine := MachineArm64;
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'a fact that contradicts outweighs one unread');
end;

procedure TTestWindowsModuleDecision.TestDecideModuleRevisionDoesNotDecide;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.ModuleRevision := 5;
  LFacts.Revision := 9999;
  CheckEquals(Ord(TModuleStatus.Validated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the revisions are reported, not gated');
end;

procedure TTestWindowsModuleDecision.TestDecideEditionDoesNotDecide;
var
  LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Edition := 'ServerAzureStackHCICor';
  CheckEquals(Ord(TModuleStatus.Validated), Ord(TWindowsModuleDecision.Decide(LFacts,
    TModuleStandard.Fips140_3, LReason)), 'the edition is reported, not gated');
end;

procedure TTestWindowsModuleDecision.TestDecideReasonsAreDistinct;
const
  CaseCount = 20;
var
  LCases: array [0 .. CaseCount - 1] of TWindowsModuleFacts;
  LReasons: array [0 .. CaseCount - 1] of string;
  LI, LJ: Int32;
begin
  for LI := 0 to CaseCount - 1 do
    LCases[LI] := ValidFacts(22621, ProductWorkstation);
  LCases[0].Major := 6;
  LCases[1].Build := 26100;
  LCases[2].ProductType := ProductServer;
  LCases[3].Process64Bit := False;
  LCases[4].ProcessMachine := MachineAmd64;
  LCases[5].NativeMachine := MachineArm64;
  LCases[6].SystemCopy := False;
  LCases[7].ModuleBuild := 19041;
  LCases[8].MachineRead := False;
  LCases[9].PathRead := False;
  LCases[10].VersionRead := False;
  LCases[11].FirmwareType := FirmwareBios;
  LCases[12].FirmwareRead := False;
  LCases[13].SystemModulePath := '';
  LCases[14].OsRead := False;
  LCases[15].Today := 0;
  LCases[16].Today := 20310831;
  LCases[17].BcryptSystemCopy := False;
  LCases[18].NcryptSystemCopy := False;
  LCases[19].BcryptRead := False;
  LCases[19].NcryptRead := False;
  for LI := 0 to CaseCount - 1 do
  begin
    TWindowsModuleDecision.Decide(LCases[LI], TModuleStandard.Fips140_3, LReasons[LI]);
    CheckTrue(LReasons[LI] <> '', 'a reason for case ' + IntToStr(LI));
    for LJ := 0 to LI - 1 do
      CheckTrue(LReasons[LI] <> LReasons[LJ], Format('cases %d and %d differ', [LJ, LI]));
  end;
end;

procedure TTestWindowsModuleDecision.TestFirmwareNames;
begin
  CheckEquals('BIOS', TWindowsModuleDecision.FirmwareName(FirmwareBios), 'BIOS');
  CheckEquals('UEFI', TWindowsModuleDecision.FirmwareName(FirmwareUefi), 'UEFI');
  CheckEquals('type 3', TWindowsModuleDecision.FirmwareName(3), 'any other kind is numbered');
end;

procedure TTestWindowsModuleDecision.TestEditionCoverageOfTheListedWorkstationEditions;
const
  Listed: array [0 .. 4] of string = ('Core', 'Professional', 'Enterprise', 'IoTEnterprise',
    'Education');
var
  LI: Int32;
begin
  for LI := Low(Listed) to High(Listed) do
    CheckEquals(Ord(TEditionCoverage.Tested), Ord(TWindowsModuleDecision.EditionCoverage(22621,
      Listed[LI])), Listed[LI]);
end;

procedure TTestWindowsModuleDecision.TestEditionCoverageOfTheListedServerEditions;
begin
  CheckEquals(Ord(TEditionCoverage.Tested), Ord(TWindowsModuleDecision.EditionCoverage(20348,
    'ServerStandard')), 'Standard');
  CheckEquals(Ord(TEditionCoverage.Tested), Ord(TWindowsModuleDecision.EditionCoverage(20348,
    'ServerDatacenter')), 'Datacenter');
end;

procedure TTestWindowsModuleDecision.TestEditionCoverageOfAnUnlistedEditionIsUntested;
begin
  CheckEquals(Ord(TEditionCoverage.Untested), Ord(TWindowsModuleDecision.EditionCoverage(22621,
    'CloudEdition')), 'Windows 11 SE');
  CheckEquals(Ord(TEditionCoverage.Untested), Ord(TWindowsModuleDecision.EditionCoverage(20348,
    'ServerTurbine')), 'Server 2022 Azure Edition');
  CheckEquals(Ord(TEditionCoverage.Untested), Ord(TWindowsModuleDecision.EditionCoverage(20348,
    'ServerAzureStackHCICor')), 'Azure Stack HCI');
  CheckEquals(Ord(TEditionCoverage.Untested), Ord(TWindowsModuleDecision.EditionCoverage(22621,
    'core')), 'the OS spelling is exact');
end;

procedure TTestWindowsModuleDecision.TestEditionCoverageOfAnUnreadEditionIsUnread;
begin
  CheckEquals(Ord(TEditionCoverage.Unread), Ord(TWindowsModuleDecision.EditionCoverage(22621,
    '')), 'workstation');
  CheckEquals(Ord(TEditionCoverage.Unread), Ord(TWindowsModuleDecision.EditionCoverage(20348,
    '')), 'server');
end;

procedure TTestWindowsModuleDecision.TestEditionCoverageOfAReleaseWithNoListHasNoTestedList;
begin
  CheckEquals(Ord(TEditionCoverage.NoTestedList), Ord(TWindowsModuleDecision.EditionCoverage(
    19045, 'Professional')), 'a release the table lists as not validated');
  CheckEquals(Ord(TEditionCoverage.NoTestedList), Ord(TWindowsModuleDecision.EditionCoverage(
    12345, 'Professional')), 'a release the table does not list');
end;

procedure TTestWindowsModuleDecision.TestEditionCoverageIsPerRelease;
begin
  CheckEquals(Ord(TEditionCoverage.Untested), Ord(TWindowsModuleDecision.EditionCoverage(22621,
    'ServerStandard')), 'a server edition on the workstation release');
  CheckEquals(Ord(TEditionCoverage.Untested), Ord(TWindowsModuleDecision.EditionCoverage(20348,
    'Professional')), 'a workstation edition on the server release');
end;

procedure TTestWindowsModuleDecision.TestEditionCoverageDoesNotMatchAcrossTwoEditions;
begin
  CheckEquals(Ord(TEditionCoverage.Untested), Ord(TWindowsModuleDecision.EditionCoverage(22621,
    'Core|Professional')), 'a name that spans two listed editions');
end;

procedure TTestWindowsModuleDecision.TestDisclosuresOfAValidatedStatusNameTheHardware;
var
  LDisclosures: TArray<string>;
begin
  LDisclosures := TWindowsModuleDecision.Disclosures(22621, 'Professional',
    TModuleStatus.Validated);
  CheckTrue(Lists(LDisclosures, 'the hardware and any hypervisor are not checked against the ' +
    'tested platforms'), 'the platforms');
  CheckTrue(Lists(LDisclosures, 'on any other platform coverage is vendor-affirmed, with no ' +
    'assurance of the minimum strength of generated keys'), 'and what the vendor affirms');
end;

procedure TTestWindowsModuleDecision.TestDisclosuresOfAnotherStatusAreEmpty;
begin
  CheckEquals(0, System.Length(TWindowsModuleDecision.Disclosures(22621, 'CloudEdition',
    TModuleStatus.NotValidated)), 'not validated');
  CheckEquals(0, System.Length(TWindowsModuleDecision.Disclosures(22621, 'Professional',
    TModuleStatus.Unknown)), 'unknown');
  CheckEquals(0, System.Length(TWindowsModuleDecision.Disclosures(22621, 'Professional',
    TModuleStatus.Historical)), 'historical');
end;

procedure TTestWindowsModuleDecision.TestDisclosuresOfATestedEditionNameNoEdition;
begin
  CheckFalse(Lists(TWindowsModuleDecision.Disclosures(22621, 'Professional',
    TModuleStatus.Validated), 'edition'), 'a workstation edition the Security Policy lists');
  CheckFalse(Lists(TWindowsModuleDecision.Disclosures(20348, 'ServerDatacenter',
    TModuleStatus.Validated), 'edition'), 'a server edition the Security Policy lists');
end;

procedure TTestWindowsModuleDecision.TestDisclosuresNameAnEditionOutsideTheTestedList;
begin
  CheckTrue(Lists(TWindowsModuleDecision.Disclosures(22621, 'CloudEdition',
    TModuleStatus.Validated),
    'edition CloudEdition is outside the tested list; coverage is vendor-affirmed'),
    'Windows 11 SE');
end;

procedure TTestWindowsModuleDecision.TestDisclosuresNameTheAzureEditionsByTheirOsNames;
begin
  CheckTrue(Lists(TWindowsModuleDecision.Disclosures(20348, 'ServerTurbine',
    TModuleStatus.Validated), 'edition ServerTurbine is outside the tested list'),
    'Server 2022 Azure Edition');
  CheckTrue(Lists(TWindowsModuleDecision.Disclosures(20348, 'ServerAzureStackHCICor',
    TModuleStatus.Validated), 'edition ServerAzureStackHCICor is outside the tested list'),
    'Azure Stack HCI');
end;

procedure TTestWindowsModuleDecision.TestDisclosuresNameAnUnreadEdition;
begin
  CheckTrue(Lists(TWindowsModuleDecision.Disclosures(22621, '', TModuleStatus.Validated),
    'the edition could not be read'), 'an edition the OS did not give');
end;

procedure TTestWindowsModuleDecision.TestDisclosuresOfAReleaseWithNoListNameNoEdition;
begin
  CheckFalse(Lists(TWindowsModuleDecision.Disclosures(12345, 'CloudEdition',
    TModuleStatus.Validated), 'edition'), 'a build the table has no edition list for');
end;

procedure TTestWindowsModuleDecision.TestTableValidated22621And20348;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckTrue(TWindowsModuleDecision.Lookup(22621, LEntry), '22621 listed');
  CheckTrue(LEntry.Validated, '22621 validated');
  CheckEquals('5410', LEntry.Certificate, '22621 certificate');
  CheckTrue(TWindowsModuleDecision.Lookup(20348, LEntry), '20348 listed');
  CheckTrue(LEntry.Validated, '20348 validated');
  CheckEquals('5410', LEntry.Certificate, '20348 certificate');
end;

procedure TTestWindowsModuleDecision.TestValidatedRowsCarryTheirStandardLevelAndDates;
var
  LEntry: TWindowsModuleEntry;
  LBuilds: array [0 .. 1] of UInt32;
  LI: Int32;
begin
  LBuilds[0] := 22621;
  LBuilds[1] := 20348;
  for LI := 0 to 1 do
  begin
    CheckTrue(TWindowsModuleDecision.Lookup(LBuilds[LI], LEntry), 'listed ' + IntToStr(LI));
    CheckEquals(Ord(TModuleStandard.Fips140_3), Ord(LEntry.Standard), 'standard ' + IntToStr(LI));
    CheckEquals(1, Int32(LEntry.Level), 'level ' + IntToStr(LI));
    CheckEquals('2026-08-31', LEntry.ValidatedOn, 'validated on ' + IntToStr(LI));
    CheckEquals('2031-08-30', LEntry.Sunset, 'sunset ' + IntToStr(LI));
    CheckEquals(20310830, Int32(LEntry.SunsetDay), 'sunset day ' + IntToStr(LI));
  end;
end;

procedure TTestWindowsModuleDecision.TestTableNotValidated26100_22631_19045;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckTrue(TWindowsModuleDecision.Lookup(26100, LEntry), '26100 listed');
  CheckFalse(LEntry.Validated, '26100 not validated');
  CheckTrue(TWindowsModuleDecision.Lookup(22631, LEntry), '22631 listed');
  CheckFalse(LEntry.Validated, '22631 not validated');
  CheckTrue(TWindowsModuleDecision.Lookup(19045, LEntry), '19045 listed');
  CheckFalse(LEntry.Validated, '19045 not validated');
  CheckTrue(TWindowsModuleDecision.Lookup(26200, LEntry), '26200 listed');
  CheckFalse(LEntry.Validated, '26200 not validated');
end;

procedure TTestWindowsModuleDecision.TestNotValidatedRowsHaveNoCertificate;
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
    CheckTrue(TWindowsModuleDecision.Lookup(LBuilds[LI], LEntry), 'listed ' + IntToStr(LI));
    CheckFalse(LEntry.Validated, 'not validated ' + IntToStr(LI));
    CheckEquals('', LEntry.Certificate, 'certificate ' + IntToStr(LI));
    CheckEquals('', LEntry.ValidatedOn, 'no validation date ' + IntToStr(LI));
    CheckEquals('', LEntry.Sunset, 'no sunset ' + IntToStr(LI));
    CheckEquals(0, Int32(LEntry.SunsetDay), 'no sunset day ' + IntToStr(LI));
  end;
end;

procedure TTestWindowsModuleDecision.TestLookupMissesUnlistedBuild;
var
  LEntry: TWindowsModuleEntry;
begin
  CheckFalse(TWindowsModuleDecision.Lookup(12345, LEntry), 'unlisted');
  CheckFalse(LEntry.Validated, 'the out entry is cleared');
  CheckEquals('', LEntry.Product, 'with no product');
end;

{$IFDEF TLSLIB_MSWINDOWS}

{ TTestWindowsModuleAttestation }

procedure TTestWindowsModuleAttestation.TestDescribePrintsTheReason;
var
  LFacts: TWindowsModuleFacts;
  LAttested: TWindowsAttestation;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Process64Bit := False;
  LAttested := TWindowsModuleAttestation.Attest(LFacts);
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(LAttested.Status), 'the status');
  CheckTrue(Pos('the process is 32-bit', LAttested.Description) > 0, 'the reason is printed');
  CheckEquals(0, Pos('FIPS', LAttested.Description), 'no standard is claimed');
end;

procedure TTestWindowsModuleAttestation.TestDescribeOfUnreadableOsIsTheReason;
var
  LFacts: TWindowsModuleFacts;
  LAttested: TWindowsAttestation;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.OsRead := False;
  LAttested := TWindowsModuleAttestation.Attest(LFacts);
  CheckEquals(Ord(TModuleStatus.Unknown), Ord(LAttested.Status), 'the status');
  CheckEquals('the OS build could not be read', LAttested.Description, 'the reason alone');
end;

procedure TTestWindowsModuleAttestation.TestDescribeOfValidatedFacts;
var
  LAttested: TWindowsAttestation;
begin
  LAttested := TWindowsModuleAttestation.Attest(ValidFacts(20348, ProductServer));
  CheckEquals(Ord(TModuleStatus.Validated), Ord(LAttested.Status), 'the status');
  CheckTrue(Pos('CMVP certificate 5410, FIPS 140-3 Level 1', LAttested.Description) > 0,
    'the certificate');
end;

procedure TTestWindowsModuleAttestation.TestIdentityCarriesTheFacts;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := TWindowsModuleAttestation.Attest(ValidFacts(20348, ProductServer)).Identity;
  CheckEquals('10.0.20348.3', LIdentity.OsVersion, 'the OS version with its revision');
  CheckEquals('Professional', LIdentity.Edition, 'the edition');
  CheckEquals('UEFI', LIdentity.Firmware, 'the firmware');
  CheckEquals(ProductServer, Int32(LIdentity.ProductType), 'the product type');
  CheckEquals(0, Int32(LIdentity.ProcessMachine), 'the process machine');
  CheckEquals(MachineAmd64, Int32(LIdentity.NativeMachine), 'the native machine');
  CheckEquals('C:\Windows\System32\bcryptprimitives.dll', LIdentity.ModulePath, 'the path');
  CheckEquals('10.0.20348.30001', LIdentity.ModuleFileVersion, 'the file version');
  CheckEquals('10.0.20348.30000', LIdentity.ListedModuleVersion, 'the listed version');
  CheckEquals(Ord(TLegacyFipsPolicy.Disabled), Ord(LIdentity.LegacyFipsPolicy), 'the legacy flag');
  CheckTrue(Pos('legacy FIPS policy Disabled', LIdentity.Describe) > 0, 'printed');
  CheckTrue(Pos('machine 0x8664', LIdentity.Describe) > 0, 'printed');
end;

procedure TTestWindowsModuleAttestation.TestIdentityOfUnreadableOsKeepsTheOtherFacts;
var
  LFacts: TWindowsModuleFacts;
  LIdentity: TModuleIdentity;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.OsRead := False;
  LIdentity := TWindowsModuleAttestation.Attest(LFacts).Identity;
  CheckEquals(Ord(TLegacyFipsPolicy.Disabled), Ord(LIdentity.LegacyFipsPolicy), 'the flag');
  CheckEquals('', LIdentity.ListedModuleVersion, 'no listed version without a build');
  CheckEquals('', LIdentity.OsVersion, 'no OS version');
  CheckEquals(MachineAmd64, Int32(LIdentity.NativeMachine), 'the native machine');
  CheckEquals('C:\Windows\System32\bcryptprimitives.dll', LIdentity.ModulePath, 'the path');
  CheckEquals('10.0.22621.30001', LIdentity.ModuleFileVersion, 'the file version');
  CheckEquals('UEFI', LIdentity.Firmware, 'the firmware');
end;

procedure TTestWindowsModuleAttestation.TestIdentityOfUnreadVersionHasNoFileVersion;
var
  LFacts: TWindowsModuleFacts;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.VersionRead := False;
  CheckEquals('', TWindowsModuleAttestation.Attest(LFacts).Identity.ModuleFileVersion,
    'no zeroed version is invented');
end;

procedure TTestWindowsModuleAttestation.TestIdentityOfNotValidatedRowHasNoListedVersion;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := TWindowsModuleAttestation.Attest(ValidFacts(22631, ProductWorkstation)).Identity;
  CheckEquals('', LIdentity.ListedModuleVersion, 'the row lists none');
  CheckEquals('', LIdentity.Certificate, 'and no certificate');
end;

procedure TTestWindowsModuleAttestation.TestIdentityNamesTheCertificateOnlyWhenValidated;
var
  LFacts: TWindowsModuleFacts;
  LIdentity: TModuleIdentity;
begin
  CheckEquals('5410', TWindowsModuleAttestation.Attest(ValidFacts(22621,
    ProductWorkstation)).Identity.Certificate, 'a validated module names its certificate');
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Process64Bit := False;
  LIdentity := TWindowsModuleAttestation.Attest(LFacts).Identity;
  CheckEquals('Windows 11 22H2', LIdentity.Product, 'the listed build is still named');
  CheckEquals('', LIdentity.Certificate, 'but a module that is not validated cites no certificate');
end;

procedure TTestWindowsModuleAttestation.TestHistoricalModuleCitesNoCertificate;
var
  LFacts: TWindowsModuleFacts;
  LAttested: TWindowsAttestation;
begin
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Today := 20310831;
  LAttested := TWindowsModuleAttestation.Attest(LFacts);
  CheckEquals(Ord(TModuleStatus.Historical), Ord(LAttested.Status), 'past the sunset date');
  CheckEquals('', LAttested.Identity.Certificate, 'no certificate is cited for it');
  CheckTrue(Pos('sunset date 2031-08-30', LAttested.Description) > 0,
    'and the description says why');
  CheckTrue(Pos('certificate 5410', LAttested.Description) > 0, 'and names the certificate');
end;

procedure TTestWindowsModuleAttestation.TestAttestedIdentityIsMarkedAttested;
begin
  CheckTrue(TWindowsModuleAttestation.Attest(ValidFacts(22621,
    ProductWorkstation)).Identity.Attested, 'the library produced it');
end;

procedure TTestWindowsModuleAttestation.TestGatheredDateIsToday;
var
  LToday: UInt32;
  LGathered: TDateTime;
begin
  LToday := TWindowsModuleAttestation.Gather.Today;
  LGathered := EncodeDate(Word(LToday div 10000), Word((LToday div 100) mod 100),
    Word(LToday mod 100));
  // the local date is within a day of the UTC date at any offset
  CheckTrue(Abs(LGathered - Trunc(Now)) <= 1, 'the date is the RTL date to within a day');
end;

procedure TTestWindowsModuleAttestation.TestCoversTheOsCompositionOnly;
var
  LAttestation: IModuleAttestation;
  LBase, LOs: ICryptoProvider;
begin
  LAttestation := TWindowsModuleAttestation.Create as IModuleAttestation;
  LBase := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
  CheckFalse(LAttestation.Covers(LBase), 'the portable provider is not what was attested');
  CheckFalse(LAttestation.Covers(nil), 'nor is nothing');
  LOs := TOSCryptoProvider.Compose(LBase);
  if not TOSCryptoProvider.IsComposition(LOs) then
  begin
    SkipTest('no OS composition is engaged on this host');
    Exit;
  end;
  CheckTrue(LAttestation.Covers(LOs), 'the OS composition is');
end;

procedure TTestWindowsModuleAttestation.TestGatheredFactsDescribeThisProcess;
var
  LFacts: TWindowsModuleFacts;
begin
  LFacts := TWindowsModuleAttestation.Gather;
  CheckTrue(LFacts.OsRead, 'the OS was read');
  CheckTrue(LFacts.PathRead, 'the module path was read');
  CheckTrue(LFacts.VersionRead, 'the module version was read');
  CheckEquals(SizeOf(Pointer) = 8, LFacts.Process64Bit, 'the process bitness');
  CheckEquals(10, Int32(LFacts.ModuleMajor), 'the module version is not the shimmed 6.2');
  if not LFacts.MachineRead then
  begin
    SkipTest('the system has no architecture query');
    Exit;
  end;
  CheckTrue(LFacts.NativeMachine <> 0, 'the native machine');
  if LFacts.NativeMachine <> MachineAmd64 then
  begin
    SkipTest('this machine is not x64');
    Exit;
  end;
  if LFacts.Process64Bit then
    CheckEquals(0, Int32(LFacts.ProcessMachine), 'a 64-bit process is native')
  else
    CheckEquals(MachineI386, Int32(LFacts.ProcessMachine), 'a 32-bit process is emulated');
end;

procedure TTestWindowsModuleAttestation.TestParseFileVersionReadsTheLeadingNumbers;
var
  LFacts: TWindowsModuleFacts;
begin
  LFacts := Default(TWindowsModuleFacts);
  CheckTrue(TWindowsModuleAttestation.ParseFileVersion(
    '10.0.22621.30001 (WinBuild.160101.0800)', LFacts), 'a Windows file version string');
  CheckEquals(10, Int32(LFacts.ModuleMajor), 'major');
  CheckEquals(0, Int32(LFacts.ModuleMinor), 'minor');
  CheckEquals(22621, Int32(LFacts.ModuleBuild), 'build');
  CheckEquals(30001, Int32(LFacts.ModuleRevision), 'revision');
end;

procedure TTestWindowsModuleAttestation.TestParseFileVersionRefusesOtherText;
const
  Bad: array [0 .. 6] of string = ('', 'abc', '10.0.22621', '10.0.22621.', '10..1.2',
    '10.0.70000.1', '.1.2.3');
var
  LFacts: TWindowsModuleFacts;
  LI: Int32;
begin
  LFacts := Default(TWindowsModuleFacts);
  LFacts.ModuleMajor := 7;
  for LI := 0 to High(Bad) do
    CheckFalse(TWindowsModuleAttestation.ParseFileVersion(Bad[LI], LFacts), 'refuses ' + Bad[LI]);
  CheckEquals(7, Int32(LFacts.ModuleMajor), 'a refused text leaves the facts alone');
end;

procedure TTestWindowsModuleAttestation.TestGatheredModuleIsTheSystemCopy;
var
  LFacts: TWindowsModuleFacts;
begin
  LFacts := TWindowsModuleAttestation.Gather;
  CheckTrue(LFacts.SystemModulePath <> '', 'the system copy was named');
  CheckTrue(LFacts.PathRead, 'the loaded module was named');
  CheckTrue(LFacts.SystemCopy, 'the loaded module is the system copy');
  CheckEquals(LowerCase(string(LFacts.SystemModulePath)), LowerCase(string(LFacts.ModulePath)),
    'the two paths agree up to case');
end;

procedure TTestWindowsModuleAttestation.TestGatheredImportsAreTheSystemCopies;
var
  LFacts: TWindowsModuleFacts;
begin
  LFacts := TWindowsModuleAttestation.Gather;
  CheckTrue(LFacts.BcryptRead and LFacts.NcryptRead, 'the loaded copies were identified');
  CheckTrue(LFacts.BcryptSystemCopy, 'bcrypt.dll is the system copy');
  CheckTrue(LFacts.NcryptSystemCopy, 'ncrypt.dll is the system copy');
end;

procedure TTestWindowsModuleAttestation.TestGatheredEditionAndFirmware;
var
  LFacts: TWindowsModuleFacts;
begin
  LFacts := TWindowsModuleAttestation.Gather;
  CheckTrue(LFacts.OsRead, 'the OS was read');
  CheckTrue(LFacts.Edition <> '', 'the edition was read');
  if not LFacts.FirmwareRead then
  begin
    SkipTest('the system has no firmware query');
    Exit;
  end;
  CheckTrue((LFacts.FirmwareType = FirmwareBios) or (LFacts.FirmwareType = FirmwareUefi),
    'the firmware is BIOS or UEFI');
end;

procedure TTestWindowsModuleAttestation.TestRealProcessFactsDecideByProcess;
var
  LReal, LFacts: TWindowsModuleFacts;
  LReason: string;
begin
  LReal := TWindowsModuleAttestation.Gather;
  if not LReal.MachineRead or (LReal.NativeMachine <> MachineAmd64) then
  begin
    SkipTest('no x64 machine to judge');
    Exit;
  end;
  // the OS and module facts of a listed release, the process facts of this process
  LFacts := ValidFacts(22621, ProductWorkstation);
  LFacts.Process64Bit := LReal.Process64Bit;
  LFacts.ProcessMachine := LReal.ProcessMachine;
  if LFacts.Process64Bit then
    CheckEquals(Ord(TModuleStatus.Validated), Ord(TWindowsModuleDecision.Decide(LFacts,
      TModuleStandard.Fips140_3, LReason)), 'a native 64-bit process')
  else
    CheckEquals(Ord(TModuleStatus.NotValidated), Ord(TWindowsModuleDecision.Decide(LFacts,
      TModuleStandard.Fips140_3, LReason)), 'a 32-bit process is outside the certificate');
end;

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

procedure TTestWindowsModuleAttestation.TestStatusFollowsTheTable;
var
  LAttestation: IModuleAttestation;
  LEntry: TWindowsModuleEntry;
begin
  LAttestation := TWindowsModuleAttestation.Create as IModuleAttestation;
  if TWindowsModuleDecision.Lookup(LAttestation.Identity.OsBuild, LEntry) and
    LEntry.Validated and (SizeOf(Pointer) = 8) then
  begin
    SkipTest('a listed release can still fail the firmware, module and machine facts');
    Exit;
  end;
  CheckEquals(Ord(TModuleStatus.NotValidated),
    Ord(LAttestation.Status(TModuleStandard.Fips140_3)),
    'a build outside the table, or a 32-bit process, is never validated');
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
  else if LAttestation.Status(TModuleStandard.Fips140_3) = TModuleStatus.Historical then
    CheckTrue(Pos('passed its sunset date 2031-08-30', LAttestation.Describe) > 0,
      'the sunset date that passed')
  else
    CheckTrue(Pos('the process is 32-bit', LAttestation.Describe) +
      Pos('no validated module', LAttestation.Describe) > 0, 'the outcome');
end;

procedure TTestWindowsModuleAttestation.TestAttestedDisclosuresFollowTheStatus;
var
  LFacts: TWindowsModuleFacts;
begin
  LFacts := ValidFacts(20348, ProductServer);
  CheckTrue(Lists(TWindowsModuleAttestation.Attest(LFacts).Disclosures, 'any hypervisor'),
    'a validated status discloses the hardware');
  LFacts.Edition := 'ServerTurbine';
  CheckTrue(Lists(TWindowsModuleAttestation.Attest(LFacts).Disclosures,
    'edition ServerTurbine is outside the tested list'), 'and an untested edition');
  LFacts.Process64Bit := False;
  CheckEquals(0, System.Length(TWindowsModuleAttestation.Attest(LFacts).Disclosures),
    'another status gives none');
end;

procedure TTestWindowsModuleAttestation.TestCreatedAttestationDisclosesWhenItIsValidated;
var
  LAttestation: IModuleAttestation;
begin
  // a guard, not evidence: the disclosure follows the status the host reports
  LAttestation := TWindowsModuleAttestation.Create as IModuleAttestation;
  CheckEquals(Ord(LAttestation.Status(TModuleStandard.Fips140_3) = TModuleStatus.Validated),
    Ord(Lists(LAttestation.Disclosures, 'any hypervisor')),
    'the hardware is disclosed exactly while the module is validated');
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

function TTestWindowsCompliance.ValidatedAttestationOrSkip(
  out AAttestation: IModuleAttestation): Boolean;
begin
  AAttestation := TOSModuleAttestation.Current;
  Result := AAttestation.Status(TModuleStandard.Fips140_3) = TModuleStatus.Validated;
  if Result then
    Exit;
  if SwitchEnabled('TLSLIB_EXPECT_VALIDATED_MODULE') then
    Fail(Format(SExpectedValidated, [AAttestation.Identity.OsBuild]));
  SkipTest(Format(SBranchNotValidated, [AAttestation.Identity.OsBuild]));
end;

procedure TTestWindowsCompliance.TestStrictPassesOnValidatedBuild;
var
  LAttestation: IModuleAttestation;
  LPolicy: ICompliancePolicy;
begin
  if not ValidatedAttestationOrSkip(LAttestation) then
    Exit;
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
    TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS), Pkix, LAttestation,
    TComplianceEnforcement.Strict) as ICompliancePolicy;
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LPolicy.PlatformReport.Verdict),
    'the validated build runs HKDF outside the module');
end;

procedure TTestWindowsCompliance.TestStrictTls12OnlyRulesAreCompliantOnValidatedBuild;
var
  LAttestation: IModuleAttestation;
  LPolicy: ICompliancePolicy;
begin
  if not ValidatedAttestationOrSkip(LAttestation) then
    Exit;
  LPolicy := TCompliancePolicy.Create(Tls12OnlyRules,
    TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS), Pkix, LAttestation,
    TComplianceEnforcement.Strict) as ICompliancePolicy;
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LPolicy.PlatformReport.Verdict),
    'the module serves the TLS 1.2 PRF');
end;

procedure TTestWindowsCompliance.TestStrictRaisesNotValidatedOnOtherBuilds;
var
  LAttestation: IModuleAttestation;
  LPolicy: ICompliancePolicy;
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
    LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3,
      TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS), Pkix, LAttestation,
      TComplianceEnforcement.Strict) as ICompliancePolicy;
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
  // controls: the same policy does report both when a config earns them
  CheckTrue(ReportHasKind(LPolicy.Evaluate(TComplianceTls.Client(LPolicy,
    TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore)).Build),
    TComplianceFindingKind.ChainVerifiedOutsideModule), 'the built-in verifier is outside');
  CheckTrue(ReportHasKind(LPolicy.Evaluate(ClientBuilder(LPolicy).WithServerVerification(
    TServerVerification.VerifierSource(TFakeOsVerifierSources.Server).WithMinimumStrength(
    TCertificateStrengthPolicy.Defaults).Build).Build),
    TComplianceFindingKind.StrengthBelowRules), 'a looser strength policy is below the rules');
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
  LSource: TOSVerifierSource;
  LReport: IComplianceReport;
  LStore: ITrustAnchorStore;
begin
  LPolicy := RelaxedPolicy;
  LStore := TTlsLibTestCertificates.EcP256RootStore;
  LConfig := TComplianceTls.Client(LPolicy, TSystemTrustRoots.HostRoots(LStore),
    TRevocationPosture.Soft, 1000).Build;
  CheckTrue(LConfig.ServerVerifierSource is TOSVerifierSource, 'the live source is the OS source');
  LSource := LConfig.ServerVerifierSource as TOSVerifierSource;
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
  LSource: TOSVerifierSource;
begin
  LConfig := TComplianceTls.Client(RelaxedPolicy, TSystemTrustRoots.OsRoots,
    TRevocationPosture.Soft, 1000).Build;
  CheckTrue(LConfig.ServerVerifierSource is TOSVerifierSource, 'the live source is the OS source');
  LSource := LConfig.ServerVerifierSource as TOSVerifierSource;
  CheckEquals(0, System.Length(LSource.Anchors) + System.Length(LSource.ExtraAnchors),
    'no host root');
end;

procedure TTestWindowsCompliance.TestHostKeyListingTheMarkerIsOutsideTheModule;
var
  LOs: ICryptoProvider;
  LPolicy: ICompliancePolicy;
  LCredential: TTlsCredential;
begin
  LOs := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS);
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3, LOs, Pkix,
    TOSModuleAttestation.Current, TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  LCredential := MarkedKeyCredential(LOs, TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256));
  CheckTrue(Supports(LCredential.PrivateKey, ISystemSigningKey), 'the host key lists the marker');
  CheckTrue(ReportHasKind(LPolicy.EvaluateCredential(LCredential),
    TComplianceFindingKind.CredentialKeyOutsideModule),
    'the real Windows report judges the class, not the marker');
end;

procedure TTestWindowsCompliance.TestOsImportedKeyIsInsideTheModule;
var
  LOs: ICryptoProvider;
  LPolicy: ICompliancePolicy;
begin
  LOs := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.OS);
  LPolicy := TCompliancePolicy.Create(TCompliancePresets.Fips140_3, LOs, Pkix,
    TOSModuleAttestation.Current, TComplianceEnforcement.Relaxed) as ICompliancePolicy;
  CheckFalse(ReportHasKind(LPolicy.EvaluateCredential(ServerCredential(LOs)),
    TComplianceFindingKind.CredentialKeyOutsideModule), 'a key the OS module imported');
  // control: a key imported by the portable provider is outside, under the same policy
  CheckTrue(ReportHasKind(LPolicy.EvaluateCredential(ServerCredential(Crypto)),
    TComplianceFindingKind.CredentialKeyOutsideModule), 'a key the portable code imported');
end;

{$ENDIF TLSLIB_MSWINDOWS}

initialization

{$IFDEF FPC}
  RegisterTest(TTestCompliancePolicy);
  RegisterTest(TTestComplianceAdmit);
  RegisterTest(TTestComplianceResumption);
  RegisterTest(TTestComplianceRoots);
  RegisterTest(TTestComplianceMtls);
  RegisterTest(TTestComplianceAnchorFloors);
  RegisterTest(TTestWindowsModuleDecision);
{$ELSE}
  RegisterTest(TTestCompliancePolicy.Suite);
  RegisterTest(TTestComplianceAdmit.Suite);
  RegisterTest(TTestComplianceResumption.Suite);
  RegisterTest(TTestComplianceRoots.Suite);
  RegisterTest(TTestComplianceMtls.Suite);
  RegisterTest(TTestComplianceAnchorFloors.Suite);
  RegisterTest(TTestWindowsModuleDecision.Suite);
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
