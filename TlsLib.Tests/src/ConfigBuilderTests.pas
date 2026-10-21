{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ConfigBuilderTests;

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
  TlpTlsLibExceptions,
  TlpIClock,
  MockClock,
  TlpTlsVersion,
  TlpAlpnProtocols,
  TlpArrayUtilities,
  TlpSecretBuffer,
  TlpISession,
  TlpSession,
  TlpInMemorySessionCache,
  TlpClientSessionPolicy,
  TlpSystemTimeUtilities,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlpInMemorySessionStore,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpICertificateVerifierSource,
  TlpCertificateVerifierSource,
  TlpTrustTypes,
  TlpTlsAlert,
  TlpINegotiation,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  MockNamedGroups,
  TlpNegotiationPolicy,
  TlpSignatureSchemeRegistry,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpClientPskPath,
  TlpITlsConfig,
  TlpITlsServerCredentialSet,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpInMemoryCertificateCompressionCache,
  TlpZlibCertificateCompression,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpISecretBuffer,
  TlpCryptoDomainTypes,
  TlpEchConfig,
  TlpIEch,
  TlpEchClient,
  TlpInMemoryEchKeyStore,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpITlsConfigBuilder,
  TlpCredentialResolvers,
  TlpTlsPresets,
  TlpTlsConfigBuilder,
  TlpTlsEngineFactory,
  TlpServerName,
  TlpExtensionVector,
  TlpCoreExtensions,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpCertificateCompression,
  TlpGrease,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlsLibTestHandshakeDecoder,
  TlpTlsLib,
  MockCryptoProvider,
  TlsLibTestProviders,
  MockCertificateCompression,
  MockCertificateVerifiers,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  /// <summary>The shapes of client the external-PSK budget is checked against.</summary>
  TOfferKind = (Plain, LargestAlpn, CachedTicket, Ech);

  TTestConfigBuilder = class(TTlsLibHandshakeTestCase)
  private
    FCerts: TStringList;
    // the endpoint views hold a raw back-reference to their owner, so a helper that hands back a
    // view keeps the owning builder alive here for the test's duration
    FBuilders: TArray<ITlsConfigBuilder>;
    // the EcP256 leaf paired with a foreign private key from ImportKeys.txt (never its own key),
    // so the key does not own the leaf
    function CredentialWithForeignKey(const AKeyField: string): TTlsCredential;
    // the dual-version suites with the first one's hash altered, held by a host registry
    function NonCatalogSuiteRegistry: ICipherSuiteRegistry;
    function BuildEchConfigList(AConfigId: Byte; const APublicName: string;
      out APrivateKey: ISecretBuffer): TBytes; overload;
    function BuildEchConfigList(AConfigId: Byte; const APublicName: string;
      const AAeadIds: TArray<UInt16>; out APrivateKey: ISecretBuffer): TBytes; overload;
    /// <summary>Whether giving a server builder over a provider without AES-128-GCM an ECH store
    /// whose one config advertises AAeadIds is refused.</summary>
    function EchKeyStoreRefused(const AAeadIds: TArray<UInt16>): Boolean;
    function BuildClientConfig(const ACryptoProvider: ICryptoProvider): ITlsClientConfig;
    function BuildServerConfig(const ACryptoProvider: ICryptoProvider): ITlsServerConfig;
    function DefaultProfile: TTlsConfigProfile;
    function ChainLimitsAccepted(AMaxCert, AMaxTotal: Int32): Boolean;
    function SameOrder(const AA, AB: TArray<UInt16>): Boolean;
    function ServerBuildIsRefused(const ABuilder: ITlsServerConfigBuilder): Boolean;
    function AuthorityName(ALength: Int32): TBytes;
    function ClientAuthServerBuilder: ITlsServerConfigBuilder;
    // the most framed name bytes a TLS 1.3 CertificateRequest can carry for this default config
    function CertificateRequestRoom: Int32;
    // the message of the EArgumentTlsLibException the call raises, '' when it raises none
    function ClientAuthoritiesRefusal(const ABuilder: ITlsServerConfigBuilder;
      const ANames: TArray<TBytes>): string;
    function HardWebPkiServer: IServerVerification;
    function HardWebPkiClient: IClientVerification;
    // the message of the Build refusal for a server with these client-CA anchors, '' when it builds
    function ClientAnchorBuildMessage(AUseSource, AFloors: Boolean;
      const AStore: ITrustAnchorStore): string;
    function WeakClientAnchor: TBytes;
    function ClientBuildNeedsTls13(const AFacet: ITls13ClientConfigFacet): Boolean;
    function ServerBuildNeedsTls13(const AFacet: ITls13ServerConfigFacet): Boolean;
    /// <summary>Whether Build is refused as invalid operation with AReason in its message.</summary>
    function BuildRefused(const ABuilder: ITlsClientConfigBuilder;
      const AReason: string): Boolean; overload;
    function BuildRefused(const ABuilder: ITlsServerConfigBuilder;
      const AReason: string): Boolean; overload;
    function BuildRefused(const AFacet: ITls13ClientConfigFacet;
      const AReason: string): Boolean; overload;
    function BuildRefused(const AFacet: ITls12ClientConfigFacet;
      const AReason: string): Boolean; overload;
    function BuildRefused(const AFacet: ITls13ServerConfigFacet;
      const AReason: string): Boolean; overload;
    function BuildRefused(const AFacet: ITls12ServerConfigFacet;
      const AReason: string): Boolean; overload;
    function HelloSuites(const AWire: TBytes): TArray<UInt16>;
    function NewTls12OnlyClient(AGrease: Boolean): ITlsEngine;
    function GreaseCount(const AValues: TArray<UInt16>): Int32;
    // overwrites the named_curve (ACurve) or the signature scheme (not ACurve) in the first
    // plaintext ServerKeyExchange of a server flight with AValue
    procedure PatchServerKeyExchange(var AWire: TBytes; ACurve: Boolean; AValue: UInt16);
    procedure CheckGreaseInServerKeyExchangeIsRefused(ACurve: Boolean);
    function NewBareClientBuilder: ITlsClientConfigBuilder;
    function NewClientBuilder: ITlsClientConfigBuilder;
    function NewServerBuilder: ITlsServerConfigBuilder;
    /// <summary>A server builder holding no certificate credential, for the PSK-only shape.</summary>
    function NewPskOnlyServerBuilder: ITlsServerConfigBuilder;
    function MakePskSpec: TExternalPsk;
    function MakePskSpecs(ACount: Int32): TArray<TExternalPsk>;
    /// <summary>The bytes of the ClientHello a client built from AFacet sends first.</summary>
    function HelloLength(const AFacet: ITls13ClientConfigFacet): Int32;
    /// <summary>Whether the ClientHello a client built from AFacet sends is accepted and decoded by
    /// our own handshake reader.</summary>
    function HelloDecodes(const AFacet: ITls13ClientConfigFacet): Boolean;
    /// <summary>Whether Build of AFacet refuses with an invalid-operation error.</summary>
    function OfferRefused(const AFacet: ITls13ClientConfigFacet): Boolean;
    function LargestAlpnBuilder: ITlsClientConfigBuilder;
    /// <summary>A client whose cache holds a ticket at the size cap for localhost.</summary>
    function CachedTicketBuilder: ITlsClientConfigBuilder;
    /// <summary>A TLS 1.3 client with ECH on and ACount external PSKs.</summary>
    function EchFacet(ACount: Int32): ITls13ClientConfigFacet;
    /// <summary>A client of the given shape holding ACount external PSKs.</summary>
    function OfferFacet(AKind: TOfferKind; ACount: Int32): ITls13ClientConfigFacet;
    function LargestAcceptedCount(AKind: TOfferKind): Int32;
    procedure CheckExternalPskRefused(const APsks: TArray<TExternalPsk>; const AMessage: string);
    procedure RunEchThroughBuilder(AMode: TServerNameIndication);
    /// <summary>A name-check-off client offering a config for APublicName to a server whose store
    /// holds a different config (an ECH reject); returns the aborted client and the server's
    /// retry_configs.</summary>
    function RunEchRejectWithNameCheckOff(const APublicName: string;
      out ARetryConfigs: TBytes): ITlsEngine;
    function OmitSniClient(const AVersions: TArray<UInt16>): ITlsClientConfig;
    function RejectEveryChain(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEchThroughServerBuilder;
    procedure TestEchBackendThenKeyStoreRejected;
    procedure TestEchKeyStoreThenBackendRejected;
    procedure TestEchPolicyAbsentWithoutEch;
    procedure TestEchBackendPolicyFrozen;
    procedure TestEchKeyStoreTrialDecryptRecordedOnPolicy;
    procedure TestEchKeyStoreCalledAgainReplacesThePolicy;
    procedure TestEchNilKeyStoreRejected;
    procedure TestEchEmptyKeyStoreRejected;
    procedure TestEchKeyStoreRetryConfigsMustBeAValidList;
    procedure TestEchKeyStoreEntryTheProviderCannotServeRefused;
    procedure TestEchKeyStoreEveryAdvertisedSuiteMustBeServable;
    procedure TestEchKeyStoreEntryTheProviderCanServeBuilds;
    procedure TestEmptyEchConfigListWithoutGreaseRejectedAtBuild;
    procedure TestEchGreaseOnlyBuildsWithoutConfig;
    procedure TestEchEnableRefusedUnderDangerousSkip;
    procedure TestEchRetryRefusedUnderDangerousSkip;
    procedure TestEchGreaseBuildsUnderDangerousSkip;
    procedure TestEchBuildsWithTheNameCheckDisabled;
    procedure TestEchMalformedConfigListIsAnArgumentError;
    procedure TestEchRejectIsAuthenticatedAgainstPublicNameWithTheNameCheckOff;
    procedure TestEchRejectOfATrustedPublicNameSurfacesRetryConfigs;
    procedure TestEchAcceptedWithTheNameCheckOffIgnoresTheHostName;
    procedure TestEnabledEchRefusesTls12Offer;
    procedure TestNilEchModeIsRefused;
    procedure TestEmptySupportedVersionsIsRefused;
    procedure TestNonNegotiableVersionIsRefused;
    procedure TestDuplicateVersionIsRefused;
    procedure TestAlpnEmptyNameIsRefused;
    procedure TestAlpnNonAsciiNameIsRefused;
    procedure TestAlpnOverlongNameIsRefused;
    procedure TestAlpnDuplicateNameIsRefused;
    procedure TestAlpnEmptyListMeansNoAlpn;
    procedure TestCertificateCompressionSetsAreValidated;
    procedure TestMoreThan127DistinctDecompressorsAreRefusedForTheCount;
    procedure Test127DistinctDecompressorsAreAccepted;
    procedure TestClientCertificateCompressionCacheIsConfigurable;
    procedure TestAlpnRejectionWithProtocolsIsRefused;
    procedure TestResumptionSettingsAreRefusedWhenResumptionIsOff;
    procedure TestSingleVersionHelloAdvertisesOnlyThatVersionsSuites;
    procedure TestTls12OnlyHelloCarriesGrease;
    procedure TestGreaseOffSendsNone;
    procedure TestTls12OnlyClientCompletesWithGrease;
    procedure TestTls12ClientRefusesAGreaseSuiteTheServerSelects;
    procedure TestTls12ClientRefusesAGreaseCurveInServerKeyExchange;
    procedure TestTls12ClientRefusesAGreaseSchemeInServerKeyExchange;
    procedure TestAlpnSetterCopiesCallerArray;
    procedure TestRecordSizeLimitDefaultsToUnset;
    procedure TestExternalPskInnerBytesAreCopied;
    procedure TestNilClockIsRefused;
    procedure TestNilMonotonicClockIsRefused;
    procedure TestMonotonicClockDefaultsToTheSystemSourceAndIsInjectable;
    procedure TestAlpnListBeyondWireLimitIsRefused;
    procedure TestLargestAlpnListStillEncodesInTheClientHello;
    procedure TestServerExternalPskNeedsTls13;
    procedure TestExternalPskEmptyIdentityIsRefused;
    procedure TestExternalPskOversizeIdentityIsRefused;
    procedure TestExternalPskNilSecretIsRefused;
    procedure TestExternalPskEmptySecretIsRefused;
    procedure TestExternalPskDuplicateIdentityIsRefused;
    procedure TestExternalPskSameIdentityDifferentContextIsAccepted;
    procedure TestExternalPskSha512ProvisionedHashIsAccepted;
    procedure TestExternalPskOversizeContextIsRefused;
    procedure TestExternalPskImportedIdentityAtTheWireLimitIsAccepted;
    procedure TestExternalPskImportedIdentityBeyondTheWireLimitIsRefused;
    procedure TestExternalPskOfferAtTheBudgetIsAccepted;
    procedure TestExternalPskOfferBeyondTheBudgetIsRefused;
    procedure TestExternalPskOfferAtTheBudgetEncodesInTheClientHello;
    procedure TestExternalPskOfferWithTheLargestAlpnListEncodes;
    procedure TestExternalPskOfferBeyondTheBudgetWithTheLargestAlpnListIsRefused;
    procedure TestExternalPskOfferWithACachedTicketEncodes;
    procedure TestExternalPskOfferBeyondTheBudgetWithACachedTicketIsRefused;
    procedure TestExternalPskOfferAtTheBudgetIsDecodedByTheReader;
    procedure TestExternalPskOfferWithTheLargestAlpnListIsDecodedByTheReader;
    procedure TestExternalPskOfferWithACachedTicketIsDecodedByTheReader;
    procedure TestExternalPskOfferWithEchIsDecodedByTheReader;
    procedure TestExternalPskOfferWithEchEncodes;
    procedure TestExternalPskOfferBeyondTheBudgetWithEchIsRefused;
    procedure TestServerMayHoldMoreExternalPsksThanAClientMayOffer;
    procedure TestServerWithCertificateAndBadExternalPskIsRefused;
    procedure TestPskOnlyServerMustOfferTls13Only;
    procedure TestTls12NeedsAClassicalEcdheGroup;
    procedure TestOneBuilderConfiguresOneEndpoint;
    procedure TestPreferredGroupsWithNoRegisteredGroupIsRefused;
    procedure TestDuplicatePreferredGroupIsRefused;
    procedure TestEmptyPreferredGroupsIsRefusedAtBuild;
    procedure TestNilRegistryIsRefusedAtBuild;
    procedure TestCipherSuiteListNarrowsAndOrdersPerProtocol;
    procedure TestCipherSuiteListLeavesAnUnnamedProtocolIntact;
    procedure TestFailedBuildLeavesTheCipherSuiteListInForce;
    procedure TestCipherSuiteListOutsideTheConfiguredSetIsRefused;
    procedure TestCipherSuiteListIsIndependentOfCallOrder;
    procedure TestEmptyCipherSuiteListIsRefused;
    procedure TestInjectedVerifierRefusesSettingsItIgnores;
    procedure TestTls13SettingsAreRefusedWhenTls13IsNotOffered;
    procedure TestWebPkiPolicyCarriesItsSettingsIntoTheConfig;
    procedure TestSkipAndCustomPoliciesNeedNoAnchors;
    procedure TestVerificationFactoriesRefuseUnusableInput;
    procedure TestInertSettingsAreRefusedAtBuild;
    procedure TestRevertedFacetSettingsAndTicketCountZeroAreNotInert;
    procedure TestOfferedVersionWithoutASuiteIsRefused;
    procedure TestServerCipherSuiteListOrderDecidesTheNegotiatedSuite;
    procedure TestClientCipherSuiteListIsTheOnlyOfferedSuite;
    procedure TestRecordSizeLimitRoundTrips;
    procedure TestRecordSizeLimitRejectsOutOfRange;
    procedure TestRecordSizeLimitCapsRecordsThroughFactory;
    procedure TestPreferredGroupsSetterCopiesCallerArray;
    procedure TestCertificateCompressorsSetterCopiesCallerArray;
    procedure TestCertificateDecompressorsSetterCopiesCallerArray;
    procedure TestRawBuilderWithoutVersionsIsRefusedAtBuild;
    procedure TestBuilderRejectsMutationAfterBuild;
    procedure TestSecondBuildIsRejected;
    procedure TestReturnedPinsArrayCannotMutateConfig;
    procedure TestWithCertificatePinningRejectsWrongLengthPin;
    procedure TestClientConfigRequiresTrustStore;
    procedure TestPskOnlyClientOfferingTls12IsRefused;
    procedure TestPskOnlyClientWithPskOptionalIsRefused;
    procedure TestPskOnlyTls13ClientBuilds;
    procedure TestRequiresPskNeedsAKeyAndTheFlag;
    procedure TestCertificatePathTls13OnlyFollowsTheExternalKeys;
    procedure TestCertificatePathTls12OnlyFollowsTheTls12Keys;
    procedure TestCertificatePathBothVersionsNeedBothKeysRequired;
    procedure TestCertificatePathNoVersionOffered;
    procedure TestServerConfigRequiresCredential;
    procedure TestServerClientAuthRequiresTrustStore;
    // an empty trust store is not a trust source: it must be refused (with a distinct message),
    // an explicit skip-verify builds without one, and the union with a real root still builds
    procedure TestClientEmptyTrustStoreIsRefused;
    procedure TestClientUnionOfEmptyStoresIsRefused;
    procedure TestClientEmptyStoreUnionedWithRealRootBuilds;
    procedure TestClientInsecureSkipVerifyBuildsWithoutTrustStore;
    procedure TestPskClientWithEmptyStoreIsSteeredAsPskOnly;
    procedure TestServerClientAuthEmptyTrustStoreIsRefused;
    procedure TestServerClientAuthInsecureSkipVerifyBuildsWithoutTrustStore;
    // a client verifier source consumes the client-CA anchors, so an empty store is refused at Build
    procedure TestServerClientAuthVerifierSourceWithEmptyStoreIsRefused;
    procedure TestServerClientAuthVerifierSourceWithAnchorsBuilds;
    procedure TestServerClientAuthVerifierSourceWithEmptyStoreAndRealRootBuilds;
    procedure TestServerWebPkiRefusesAWeakClientAnchorWithFloorsOn;
    procedure TestServerVerifierSourceRefusesAWeakClientAnchorWithFloorsOn;
    procedure TestServerBuildsAWeakClientAnchorWithFloorsOff;
    procedure TestServerBuildsAStrongClientAnchorWithFloorsOn;
    procedure TestServerBuildsWhenTheWeakClientAnchorIsDistrustedBesideAStrongOne;
    procedure TestServerRefusesAClientAnchorWithAnUndescribableKey;
    procedure TestServerMalformedClientAnchorIsReportedBeforeTheFloors;
    procedure TestClientBuildsWithAWeakRootWhenFloorsAreOn;
    procedure TestServerVerifierSourceWithoutPeerAuthIsRefused;
    procedure TestServerTrustInputsWithoutPeerAuthAreRefused;
    procedure TestMtlsServerWithSuppliedTicketKeysRequiresScope;
    procedure TestEarlyDataWithSuppliedTicketKeysNeedsSharedReplayProtection;
    procedure TestServerEarlyDataBudgetIsCappedAtOneMebibyte;
    procedure TestMtlsServerWithSuppliedKeysAndScopeBuilds;
    procedure TestMtlsServerWithDefaultTicketKeysBuildsWithoutScope;
    procedure TestFacadeDrivesLoopback;
    procedure TestCustomProviderThreadedThroughRawBuilder;
    procedure TestDefaultCertificateChainLimitsAreConservative;
    procedure TestCertificateChainLimitsAreConfigurable;
    procedure TestInvalidCertificateChainLimitsRejected;
    procedure TestInvalidChainEntryCapRejected;
    procedure TestContradictoryStrengthFloorsRejected;
    procedure TestTls13CompressorOverrideLandsInFrozenConfig;
    procedure TestClientBuilderChainBuildsClient;
    procedure TestServerBuilderChainBuildsServer;
    procedure TestVersionFacetForUnofferedVersionIsRefused;
    procedure TestNonEmsResumptionReachesFrozenConfig;
    procedure TestNonEmsResumptionOnTls13OnlyIsRefused;
    procedure TestRequiredEmsWithNonEmsResumeIsRefused;
    procedure TestDefaultRevocationPostureIsSoft;
    procedure TestWithRevocationSetsHardPosture;
    // server-side Hard client-certificate revocation: satisfiable only by a live resolver, so
    // Build fails fast without one, builds with one, and is inert when client auth is off
    procedure TestServerHardClientRevocationWithoutResolverIsRefused;
    procedure TestServerHardClientRevocationWithResolverBuilds;
    procedure TestServerHardClientRevocationHostDecisionIsRefused;
    procedure TestServerHardRevocationWithoutClientAuthIsRefused;
    procedure TestClientHardHostDecisionWithoutStapleIsRefused;
    procedure TestClientHardLiveRevocationBuilds;
    procedure TestAsyncVerdictMapsToHostDecision;
    procedure TestWithCertificatePinningLandsInFrozenConfig;
    procedure TestServerWithOcspStapleLandsInFrozenConfig;
    procedure TestLoadedCredentialReplacesPriorStaple;
    // a credential built by TTlsCredential.Load passes Build's key<->leaf consistency
    procedure TestLoadedCredentialBuildsServer;
    // the credential key/leaf guard: a private key that does not own CertificateChain[0] (wrong
    // key, wrong key family, or a mis-ordered chain) is refused at Build, not left to fail as a
    // rejected CertificateVerify mid-handshake
    procedure TestServerCredentialWithMismatchedKeyRejected;
    procedure TestServerCredentialWithWrongKeyFamilyRejected;
    procedure TestIncompleteCredentialsAreRefusedAtBuild;
    procedure TestMalformedLeafCredentialIsRefusedAtBuild;
    // a host registry skips the default registry's own catalog check, so Build repeats it
    procedure TestServerCustomSuiteRegistryWithNonCatalogRecordRefused;
    procedure TestClientCustomSuiteRegistryWithNonCatalogRecordRefused;
    procedure TestClientCustomSuiteRegistryOfCatalogRecordsBuilds;
    procedure TestCustomSuiteRegistryWithNonCatalogRecordInListRefused;
    procedure TestCustomSuiteRegistryWithNonCatalogRecordBesideTls12PskRefused;
    procedure TestCustomSuiteRegistryOfCatalogRecordsBuilds;
    procedure TestMalformedTrustAnchorIsRefusedAtBuild;
    procedure TestSniCredentialWithMismatchedKeyNamesHost;
    procedure TestClientCredentialWithMismatchedKeyRejected;
    procedure TestMatchingCredentialBuildsServer;
    // RFC 9846 4.7.1: a server MUST NOT advertise a ticket lifetime over 604800 seconds
    procedure TestTicketLifetimeAboveCapIsRejected;
    procedure TestTicketLifetimeAtCapIsAccepted;
    procedure TestPublishedLimitsKeepTheirValues;
    procedure TestServerConfigCarriesTheDefaultTicketLifetime;
    procedure TestResumptionScopeAboveCapIsRejected;
    procedure TestResumptionScopeAtCapIsAccepted;
    procedure TestClientResumptionScopeAboveCapIsRejected;
    procedure TestClientResumptionScopeAtCapRoundTrips;
    procedure TestClientResumptionScopeIsOrderInsensitive;
    procedure TestTicketCountAboveCapIsRejected;
    procedure TestTicketCountNegativeIsRejected;
    procedure TestTicketCountAtCapIsAccepted;
    // RFC 9846 8: a server authorizing 0-RTT gets one anti-replay register per config (shared
    // across connections), so a replay across connections is detectable without WithAntiReplay
    procedure TestServerEarlyDataMintsSharedAntiReplayDefault;
    procedure TestServerRejectsPublicSuffixSniWildcard;
    procedure TestServerSniWildcardUnderRegistrableDomainPassesTheWildcardGate;
    // a restricted (classical-only) registry composes with a preset whose preferred order still
    // names the pruned hybrid: the engine drops it from the offer instead of failing to build,
    // and the handshake negotiates a classical group
    procedure TestClassicalRegistryOverPresetNegotiatesClassical;
    // the asymmetric case: a classical-registry client against a default, post-quantum-preferring
    // server - the client advertises no hybrid, so the server cannot retry it onto a pruned group
    procedure TestClassicalRegistryClientAgainstDefaultServer;
    // a 1.3 server whose registry holds none of its preferred groups is refused at creation, not
    // left to fault on the first ClientHello
    procedure TestServerWithEmptyGroupIntersectionFailsFast;
    // the accessors relocated onto the role configs read their builder defaults
    procedure TestRoleConfigDefaultsForMovedAccessors;
    procedure TestTls13ReportsExtendedMasterSecret;
    procedure TestVerifyCallbackRunsOverInstanceVerifier;
    procedure TestServerNameIndicationOmitReachesConfig;
    procedure TestOmittedSniSendsNoServerNameAndStillVerifiesHost;
    procedure TestOmittedSniStillRejectsWrongHost;
    procedure TestOmittedSniTls12SendsNoServerName;
    procedure TestOmittedSniHrrRetryKeepsServerNameAbsent;
    procedure TestOmittedSniKeepsSessionsApart;
    procedure TestEchWithOmittedSniAcceptsAndVerifiesHost;
    // dead and ignored combinations are refused at Build (or at the second of two setters sharing a
    // slot); each refusal has a test, and the neighbouring combination that works builds
    procedure TestReverifyUnderHardNeedsALiveVerdict;
    procedure TestReverifyUnderHardBuildsWithALiveVerdict;
    procedure TestReverifyWithEarlyDataAndHostDecisionIsRefused;
    procedure TestReverifyWithEarlyDataAndLiveVerdictIsRefused;
    procedure TestReverifyWithEarlyDataBuildsWithoutAnAsyncVerdict;
    procedure TestHardWithReuseOriginalBuildsWithACache;
    procedure TestPskOnlyClientRefusesPins;
    procedure TestPskOnlyClientRefusesAVerifyCallback;
    procedure TestPskOnlyClientRefusesAVerdictDeferral;
    procedure TestPskOnlyClientRefusesChangedChainLimits;
    procedure TestPskOnlyClientRefusesAChangedStapleRequest;
    procedure TestPskOnlyClientRefusesACredential;
    procedure TestPskOnlyClientRefusesDecompressors;
    procedure TestPskOnlyClientRefusesReverify;
    procedure TestPskOnlyClientRefusesDisabledServerNameCheck;
    procedure TestPskOnlyClientChecksNoServerName;
    procedure TestPskOnlyClientEngineNeedsNoHost;
    procedure TestClientAuthoritiesNilSignatureSchemesIsATypedRefusal;
    procedure TestClientAuthoritiesEmptyNameIsRefused;
    procedure TestClientAuthoritiesFramedTotalAtLimitIsAccepted;
    procedure TestClientAuthoritiesFramedTotalOverLimitIsRefused;
    procedure TestClientAuthoritiesRunningTotalAtLimitIsAccepted;
    procedure TestClientAuthoritiesRunningTotalOverLimitIsRefused;
    procedure TestClientAuthoritiesRefusalLeavesBuilderUsable;
    procedure TestClientAuthoritiesAtCertificateRequestRoomBuildAndEncode;
    procedure TestClientAuthoritiesOverCertificateRequestRoomIsRefused;
    procedure TestClientAuthoritiesOverRoomBuildOnTls12Only;
    procedure TestClientCompressionCacheBesideEmptyCompressorsIsRefused;
    procedure TestServerCompressionCacheBesideEmptyCompressorsIsRefused;
    procedure TestEmptyCompressorsWithoutCacheBuild;
    procedure TestPskOnlyStrictClientBuildsWithItsSeededSettings;
    procedure TestClientCompressorsNeedACredential;
    procedure TestClientCompressionCacheNeedsACredential;
    procedure TestClientDecompressorsBuildWithoutACredential;
    procedure TestAsyncVerdictThenLiveVerdictRaises;
    procedure TestLiveVerdictThenAsyncVerdictRaises;
    procedure TestRepeatingOneVerdictSetterIsAccepted;
    procedure TestCipherSuiteListOfAnUnofferedVersionIsRefused;
    procedure TestMixedCipherSuiteListBuilds;
    procedure TestTicketCountZeroRefusesEarlyDataWithNothingToResume;
    procedure TestTicketCountZeroKeepsEarlyDataWithASessionStore;
    procedure TestTicketCountZeroOnTls13OnlyRefusesDefaultKeys;
    procedure TestTicketCountZeroOnTls13OnlyRefusesATicketLifetime;
    procedure TestTicketCountZeroKeepsDefaultKeysWhenTls12IsOffered;
    procedure TestServerDecompressorsNeedPeerAuth;
    procedure TestServerDecompressorsBuildWithPeerAuth;
    procedure TestPskOnlyServerRefusesCompressors;
    procedure TestPskOnlyServerRefusesCompressionCache;
    procedure TestServerChainLimitsNeedPeerAuth;
    procedure TestServerChainLimitsBuildWithPeerAuth;
    procedure TestServerNarrowedSchemesNeedPeerAuth;
    procedure TestServerReorderedSchemesNeedPeerAuth;
    procedure TestHardenedServerNarrowedSchemesNeedPeerAuth;
    procedure TestServerNarrowedSchemesBuildWithPeerAuth;
    procedure TestServerEqualContentSchemesBuildWithoutPeerAuth;
    procedure TestRawServerBuilderWithDefaultSchemesBuilds;
    procedure TestStrictServerBuildsWithItsSeededChainLimits;
    procedure TestPskOnlyServerRefusesPeerAuth;
    procedure TestTicketLifetimeZeroIsRefusedWithResumptionOn;
    procedure TestDefaultKeysThenExplicitKeysRaise;
    procedure TestExplicitKeysThenDefaultKeysRaise;
    procedure TestDefaultKeysBesideASessionStoreBuild;
    procedure TestEmptyDecompressorsBuildOnAServerWithoutPeerAuth;
    procedure TestEmptyCompressorsBuildOnAPskOnlyServer;
    procedure TestTicketCountZeroKeepsEarlyDataWithExplicitTicketKeys;
    procedure TestTicketLifetimeZeroWithResumptionOffIsRefusedAsInert;
    procedure TestServerCompressorsBuildWithOnlyAnSniCredential;
    procedure TestServerCompressorsBuildWithOnlyACredentialResolver;
    procedure TestTicketCountZeroOnTls13OnlyWithNothingSharedStillBuilds;
    procedure TestComposedCredentialResolverListsDefaultAndSniCredentials;
  end;

implementation

type
  // a key store that serves another store's entries but advertises the given retry configs
  TRetryOverrideKeyStore = class(TInterfacedObject, IEchServerKeyStore)
  strict private
    FInner: IEchServerKeyStore;
    FRetryConfigs: TBytes;
  public
    constructor Create(const AInner: IEchServerKeyStore; const ARetryConfigs: TBytes);
    function Entries: TArray<TEchKeyEntry>;
    function RetryConfigs: TBytes;
  end;

{ TTestConfigBuilder }

procedure TTestConfigBuilder.SetUp;
begin
  inherited SetUp;
  FCerts := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
end;

procedure TTestConfigBuilder.TearDown;
begin
  FBuilders := nil;
  inherited TearDown;
end;

function TTestConfigBuilder.CredentialWithForeignKey(
  const AKeyField: string): TTlsCredential;
var
  LKeys: TStringList;
begin
  Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  LKeys := LoadVectorFields('Certs/ImportKeys.txt');
  try
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LKeys.Values[AKeyField]), nil);
  finally
    LKeys.Free;
  end;
end;

function TTestConfigBuilder.BuildClientConfig(
  const ACryptoProvider: ICryptoProvider): ITlsClientConfig;
var
  LBuilder: ITlsConfigBuilder;
begin
  // assemble a client config straight from the raw builder with the given provider
  LBuilder := TTlsConfigBuilder.CreateFromProfile(ACryptoProvider, Pkix, TTlsConfigProfile.Default);
  Result := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(ACryptoProvider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(ACryptoProvider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Build;
end;

function TTestConfigBuilder.BuildServerConfig(
  const ACryptoProvider: ICryptoProvider): ITlsServerConfig;
var
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(ACryptoProvider, Pkix, TTlsConfigProfile.Default);
  Result := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(ACryptoProvider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(ACryptoProvider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(ServerCredential)
    .Build;
end;

function TTestConfigBuilder.BuildEchConfigList(AConfigId: Byte;
  const APublicName: string; out APrivateKey: ISecretBuffer): TBytes;
begin
  Result := BuildEchConfigList(AConfigId, APublicName,
    TArray<UInt16>.Create(THpkeAead.AES_128_GCM), APrivateKey);
end;

function TTestConfigBuilder.BuildEchConfigList(AConfigId: Byte;
  const APublicName: string; const AAeadIds: TArray<UInt16>;
  out APrivateKey: ISecretBuffer): TBytes;
var
  LPublicKey: TBytes;
  LConfig: TEchConfig;
  LSuites: TArray<TEchCipherSuite>;
  LI: Int32;
begin
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey,
    APrivateKey);
  SetLength(LSuites, System.Length(AAeadIds));
  for LI := 0 to System.High(AAeadIds) do
  begin
    LSuites[LI].KdfId := THpkeKdf.HKDF_SHA256;
    LSuites[LI].AeadId := AAeadIds[LI];
  end;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, AConfigId,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey, LSuites, 0,
    TEncoding.ASCII.GetBytes(APublicName), nil);
  Result := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));
end;

procedure TTestConfigBuilder.TestEchBackendThenKeyStoreRejected;
var
  LSk: ISecretBuffer;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  // the split-mode backend role holds no ECH keys; pairing WithEchBackend with WithEchKeyStore is a
  // contradictory deployment and is refused (RFC 9849 sec. 7), whichever is called second
  LConfigList := BuildEchConfigList($E1, 'cover.example', LSk);
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchBackend.WithEchKeyStore(
      TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Crypto));
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an ECH key store after a split-mode backend is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreThenBackendRejected;
var
  LSk: ISecretBuffer;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  LConfigList := BuildEchConfigList($E1, 'cover.example', LSk);
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchKeyStore(
      TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Crypto)).WithEchBackend;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a split-mode backend after an ECH key store is refused');
end;

procedure TTestConfigBuilder.TestEchPolicyAbsentWithoutEch;
begin
  CheckTrue(NewServerBuilder.Build.EncryptedClientHello = nil,
    'a server with no ECH configuration has no ECH policy');
end;

procedure TTestConfigBuilder.TestEchBackendPolicyFrozen;
var
  LPolicy: IEchServerPolicy;
begin
  LPolicy := NewServerBuilder.Tls13.WithEchBackend.Build.EncryptedClientHello;
  CheckTrue(LPolicy <> nil, 'a backend server has an ECH policy');
  CheckTrue(LPolicy.Role = TEchServerRole.Backend, 'whose role is Backend');
  CheckTrue(LPolicy.KeyStore = nil, 'and which holds no key store');
  CheckFalse(LPolicy.TrialDecrypt, 'and does not trial-decrypt');
end;

procedure TTestConfigBuilder.TestEchKeyStoreTrialDecryptRecordedOnPolicy;
var
  LSk: ISecretBuffer;
  LStore: IEchServerKeyStore;
  LPolicy: IEchServerPolicy;
begin
  LStore := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E3, 'cover.example', LSk), LSk,
    Crypto);
  LPolicy := NewServerBuilder.Tls13.WithEchKeyStore(LStore).Build.EncryptedClientHello;
  CheckTrue(LPolicy.Role = TEchServerRole.Keyed, 'a key store makes the server Keyed');
  CheckFalse(LPolicy.TrialDecrypt, 'trial decryption is off by default');
  LPolicy := NewServerBuilder.Tls13.WithEchKeyStore(LStore, True).Build.EncryptedClientHello;
  CheckTrue(LPolicy.TrialDecrypt, 'the overload turns trial decryption on');
  CheckTrue(LPolicy.KeyStore = LStore, 'and the policy carries the store');
end;

procedure TTestConfigBuilder.TestEchKeyStoreCalledAgainReplacesThePolicy;
var
  LSk: ISecretBuffer;
  LFirst, LSecond: IEchServerKeyStore;
  LFacet: ITls13ServerConfigFacet;
  LPolicy: IEchServerPolicy;
begin
  LFirst := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E4, 'cover.example', LSk), LSk,
    Crypto);
  LSecond := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E5, 'cover.example', LSk), LSk,
    Crypto);
  LFacet := NewServerBuilder.Tls13.WithEchKeyStore(LFirst);
  LPolicy := LFacet.WithEchKeyStore(LSecond, True).Build.EncryptedClientHello;
  CheckTrue(LPolicy.KeyStore = LSecond, 'the second store replaces the first');
  CheckTrue(LPolicy.TrialDecrypt, 'along with its trial-decrypt setting');
end;

constructor TRetryOverrideKeyStore.Create(const AInner: IEchServerKeyStore;
  const ARetryConfigs: TBytes);
begin
  inherited Create;
  FInner := AInner;
  FRetryConfigs := ARetryConfigs;
end;

function TRetryOverrideKeyStore.Entries: TArray<TEchKeyEntry>;
begin
  Result := FInner.Entries;
end;

function TRetryOverrideKeyStore.RetryConfigs: TBytes;
begin
  Result := FRetryConfigs;
end;

procedure TTestConfigBuilder.TestEchEmptyKeyStoreRejected;
var
  LRaised: Boolean;
begin
  // with no entries a keyed server would reject every ECH offer and advertise no retry configs
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchKeyStore(
      TInMemoryEchKeyStore.Create(nil) as IEchServerKeyStore);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an ECH key store with no entries is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreRetryConfigsMustBeAValidList;
var
  LSk: ISecretBuffer;
  LReal: IEchServerKeyStore;
  LForeignSk: ISecretBuffer;
  LForeign: TBytes;
  LCase: Int32;
  LRaised: Boolean;
begin
  // the retry configs go on the wire as they are: an empty, malformed or foreign list is refused
  // up front, while the store's own list passes
  LReal := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E6, 'cover.example', LSk), LSk,
    Crypto);
  LForeign := BuildEchConfigList($E7, 'cover.example', LForeignSk);
  for LCase := 0 to 3 do
  begin
    LRaised := False;
    try
      case LCase of
        0: NewServerBuilder.Tls13.WithEchKeyStore(
             TRetryOverrideKeyStore.Create(LReal, nil) as IEchServerKeyStore);
        1: NewServerBuilder.Tls13.WithEchKeyStore(
             TRetryOverrideKeyStore.Create(LReal, DecodeHex('00ff0102')) as IEchServerKeyStore);
        2: NewServerBuilder.Tls13.WithEchKeyStore(
             TRetryOverrideKeyStore.Create(LReal, LReal.RetryConfigs) as IEchServerKeyStore);
        3: NewServerBuilder.Tls13.WithEchKeyStore(
             TRetryOverrideKeyStore.Create(LReal, LForeign) as IEchServerKeyStore);
      end;
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckEquals(LCase <> 2, LRaised, Format('retry configs case %d', [LCase]));
  end;
end;

procedure TTestConfigBuilder.TestEchNilKeyStoreRejected;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchKeyStore(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil ECH key store is refused');
end;

function TTestConfigBuilder.EchKeyStoreRefused(const AAeadIds: TArray<UInt16>): Boolean;
var
  LSk: ISecretBuffer;
  LStore: IEchServerKeyStore;
  LServing: ICryptoProvider;
  LOwner: ITlsConfigBuilder;
begin
  // the store is built with a full provider, but the one that serves the handshakes lacks AES-128-GCM
  LStore := TInMemoryEchKeyStore.FromConfig(
    BuildEchConfigList($E2, 'cover.example', AAeadIds, LSk), LSk, Crypto);
  LServing := TMissingAeadProvider.Create(Crypto, TAeadAlgorithm.AES_128_GCM) as ICryptoProvider;
  LOwner := TTlsConfigBuilder.CreateFromProfile(LServing, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  Result := False;
  try
    LOwner.Server.WithCredential(ServerCredential).Tls13.WithEchKeyStore(LStore);
  except
    on E: EArgumentTlsLibException do
      Result := True;
  end;
end;

procedure TTestConfigBuilder.TestEchKeyStoreEntryTheProviderCannotServeRefused;
begin
  CheckTrue(EchKeyStoreRefused(TArray<UInt16>.Create(THpkeAead.AES_128_GCM)),
    'an ECH entry whose only suite the serving provider cannot build is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreEveryAdvertisedSuiteMustBeServable;
begin
  // a client may pick any HPKE suite the config lists, so one the provider cannot build would make
  // the server decline ECH for every client that picks it even though another suite works
  CheckTrue(EchKeyStoreRefused(TArray<UInt16>.Create(THpkeAead.AES_128_GCM, THpkeAead.AES_256_GCM)),
    'an entry advertising one unservable suite among servable ones is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreEntryTheProviderCanServeBuilds;
begin
  // the control: the same limited provider builds when every advertised suite is available, so the
  // refusals above are about the suite and nothing else in the setup
  CheckFalse(EchKeyStoreRefused(TArray<UInt16>.Create(THpkeAead.AES_256_GCM)),
    'an entry whose suites the serving provider can all build is accepted');
end;

procedure TTestConfigBuilder.TestEchThroughServerBuilder;
begin
  RunEchThroughBuilder(TServerNameIndication.Send);
end;

procedure TTestConfigBuilder.TestEchWithOmittedSniAcceptsAndVerifiesHost;
begin
  // the outer hello still carries the public_name and the inner none; the leaf matches only
  // localhost, so acceptance proves the host check ran against the host, not the public_name
  RunEchThroughBuilder(TServerNameIndication.Omit);
end;

procedure TTestConfigBuilder.RunEchThroughBuilder(AMode: TServerNameIndication);
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LClientBuilder, LServerBuilder: ITlsConfigBuilder;
  LConfigList: TBytes;
  LSk: ISecretBuffer;
  LMsg, LOuter: TBytes;
begin
  // ECH configured end to end through the public builder: the client offers the config list
  // (Tls13.WithEch) and the server is keyed with the matching config store
  // (Tls13.WithEchKeyStore + TInMemoryEchKeyStore.FromConfig). The store lands on the frozen
  // config, the factory wires it into the server params, and the handshake accepts. The client
  // offers a full (GREASE-bearing) extension set, so this also covers ECH acceptance with
  // GREASE in the inner ClientHello.
  LConfigList := BuildEchConfigList($D4, 'cover.example', LSk);
  LClientBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LClientConfig := LClientBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithServerNameIndication(AMode)
    .Tls13.WithEch(TEchClientModes.Enable(LConfigList)).Build;
  LServerBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LServerConfig := LServerBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(ServerCredential)
    .Tls13.WithEchKeyStore(TInMemoryEchKeyStore.FromConfig(LConfigList, LSk,
    Crypto)).Build;

  CheckTrue(LServerConfig.EncryptedClientHello <> nil,
    'the builder froze an ECH policy onto the server config');

  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient.StartHandshake;
  LOuter := Drain(LClient);
  // the real name never rides the outer hello, whichever mode: it carries the public_name only
  CheckTrue(ContainsAscii(LOuter, 'cover.example'),
    'the outer hello carries the public_name');
  CheckFalse(ContainsAscii(LOuter, 'localhost'),
    'the outer hello does not carry the real host');
  Feed(LServer, LOuter);
  ExchangeFlights(LClient, LServer);

  // completion proves ECH was accepted: the leaf matches only the inner SNI (localhost), never
  // the public_name, so a reject would abort the client on the certificate check
  CheckFalse(LClient.IsHandshaking, 'the ECH client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the ECH server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the ECH client did not abort');
  CheckFalse(LServer.IsTerminal, 'the ECH server did not abort');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted,
    'the builder-configured connection surfaced ECH Accepted');
  // the server reads the name from the decrypted inner hello
  if AMode = TServerNameIndication.Omit then
    CheckEquals('', LServer.ConnectionInfo.ServerName, 'the inner hello carries no SNI')
  else
    CheckEquals('localhost', LServer.ConnectionInfo.ServerName, 'the inner hello carries the host');
  LMsg := DecodeHex('6563682d6f6b'); // "ech-ok"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('app data flows over the builder-configured ECH connection', LMsg,
    ReadAllApp(LServer));
end;

function TTestConfigBuilder.RunEchRejectWithNameCheckOff(const APublicName: string;
  out ARetryConfigs: TBytes): ITlsEngine;
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LServer: ITlsEngine;
  LClientList: TBytes;
  LClientSk, LServerSk: ISecretBuffer;
begin
  // the server's store holds a different config id, so it cannot decrypt the offer and rejects
  LClientList := BuildEchConfigList($D1, APublicName, LClientSk);
  ARetryConfigs := BuildEchConfigList($D2, APublicName, LServerSk);
  LClientConfig := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithDangerousDisableServerNameCheck
    .Tls13.WithEch(TEchClientModes.Enable(LClientList)).Build;
  LServerConfig := NewServerBuilder.Tls13.WithEchKeyStore(
    TInMemoryEchKeyStore.FromConfig(ARetryConfigs, LServerSk, Crypto)).Build;
  Result := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  Result.StartHandshake;
  ExchangeFlights(Result, LServer);
end;

procedure TTestConfigBuilder.TestEchRejectIsAuthenticatedAgainstPublicNameWithTheNameCheckOff;
var
  LClient: ITlsEngine;
  LRetry: TBytes;
begin
  // the server's leaf is valid for localhost only: with the origin name check off the reject must
  // still fail against the cover.example public_name, and its retry_configs must not surface
  LClient := RunEchRejectWithNameCheckOff('cover.example', LRetry);
  CheckTrue(LClient.IsTerminal, 'the client aborted');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(LClient.LastError.Alert.Description), 'the public_name check failed the certificate');
  CheckEquals(0, System.Length(LClient.ConnectionInfo.EchRetryConfigs),
    'unauthenticated retry_configs are not surfaced');
end;

procedure TTestConfigBuilder.TestEchRejectOfATrustedPublicNameSurfacesRetryConfigs;
var
  LClient: ITlsEngine;
  LRetry: TBytes;
begin
  // control: the public_name is one the leaf is valid for, so the reject authenticates, aborts with
  // ech_required and surfaces the retry_configs
  LClient := RunEchRejectWithNameCheckOff('localhost', LRetry);
  CheckEquals(Ord(TTlsAlertDescription.EchRequired),
    Ord(LClient.LastError.Alert.Description), 'the authenticated reject aborts with ech_required');
  CheckEqualBytes('the authenticated reject surfaces the server retry_configs', LRetry,
    LClient.ConnectionInfo.EchRetryConfigs);
end;

procedure TTestConfigBuilder.TestEchAcceptedWithTheNameCheckOffIgnoresTheHostName;
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LConfigList: TBytes;
  LSk: ISecretBuffer;
begin
  // the public_name check belongs to a reject only: on an accepted ECH the origin name check stays
  // off, so a host the leaf (valid for localhost) does not carry still completes as Accepted
  LConfigList := BuildEchConfigList($D3, 'cover.example', LSk);
  LClientConfig := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithDangerousDisableServerNameCheck
    .Tls13.WithEch(TEchClientModes.Enable(LConfigList)).Build;
  LServerConfig := NewServerBuilder.Tls13.WithEchKeyStore(
    TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Crypto)).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'other.example');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient.StartHandshake;
  ExchangeFlights(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client did not abort: ' + LClient.LastError.Message);
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'ECH was accepted');
end;

procedure TTestConfigBuilder.TestEchEnableRefusedUnderDangerousSkip;
var
  LConfigList: TBytes;
  LSk: ISecretBuffer;
  LMsg: string;
begin
  LConfigList := BuildEchConfigList($D7, 'cover.example', LSk);
  LMsg := '';
  try
    NewBareClientBuilder.WithServerVerification(TServerVerification.DangerousSkip)
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .Tls13.WithEch(TEchClientModes.Enable(LConfigList)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue((Pos('DangerousSkip', LMsg) > 0) and (Pos('public_name', LMsg) > 0),
    'a real ECH offer is refused for lack of server verification; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestEchRetryRefusedUnderDangerousSkip;
var
  LConfigList: TBytes;
  LSk: ISecretBuffer;
  LMsg: string;
begin
  LConfigList := BuildEchConfigList($D7, 'cover.example', LSk);
  LMsg := '';
  try
    NewBareClientBuilder.WithServerVerification(TServerVerification.DangerousSkip)
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .Tls13.WithEch(TEchClientModes.Retry(LConfigList)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue((Pos('DangerousSkip', LMsg) > 0) and (Pos('public_name', LMsg) > 0),
    'a retry ECH offer is refused for lack of server verification; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestEchGreaseBuildsUnderDangerousSkip;
begin
  // a decoy offers no real ECH, so there is no reject to authenticate
  CheckTrue(NewBareClientBuilder.WithServerVerification(TServerVerification.DangerousSkip)
    .Tls13.WithEch(TEchClientModes.Grease).Build.EncryptedClientHello.GreaseEnabled,
    'GREASE builds under DangerousSkip');
end;

procedure TTestConfigBuilder.TestEchBuildsWithTheNameCheckDisabled;
var
  LConfigList: TBytes;
  LSk: ISecretBuffer;
begin
  // the origin name check is separate from the reject's public_name check: it does not refuse ECH
  LConfigList := BuildEchConfigList($D7, 'cover.example', LSk);
  CheckTrue(NewClientBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithDangerousDisableServerNameCheck
    .Tls13.WithEch(TEchClientModes.Enable(LConfigList)).Build.EncryptedClientHello.Usable,
    'a real ECH offer builds with the origin name check off');
end;

procedure TTestConfigBuilder.TestEchMalformedConfigListIsAnArgumentError;
var
  LRaised: Boolean;
begin
  // a configuration fault is not a peer-wire alert: an app falling back to GREASE catches this type
  LRaised := False;
  try
    NewClientBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .Tls13.WithEch(TEchClientModes.Enable(TBytes.Create($00, $05, $01))).Build;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a malformed ECHConfigList raises the configuration error type');
end;

procedure TTestConfigBuilder.TestEmptyEchConfigListWithoutGreaseRejectedAtBuild;
var
  LRaised: Boolean;
begin
  // an empty ECHConfigList with GREASE off would send the true SNI in the clear: reject at Build
  LRaised := False;
  try
    NewClientBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .Tls13.WithEch(TEchClientModes.Enable(nil)).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ECHConfigList with GREASE off is rejected at Build');
end;

procedure TTestConfigBuilder.TestEchGreaseOnlyBuildsWithoutConfig;
var
  LConfig: ITlsClientConfig;
begin
  // GREASE with no config list is the explicit GREASE-only mode; it builds
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Tls13.WithEch(TEchClientModes.Grease).Build;
  CheckTrue(LConfig.EncryptedClientHello <> nil, 'GREASE-only ECH is configured');
  CheckTrue(LConfig.EncryptedClientHello.GreaseEnabled, 'the policy is GREASE-enabled');
  CheckFalse(LConfig.EncryptedClientHello.Usable,
    'GREASE-only resolved no usable config');
  CheckEquals(2, System.Length(LConfig.SupportedVersions),
    'GREASE leaves the dual-version offer alone');
end;

procedure TTestConfigBuilder.TestEnabledEchRefusesTls12Offer;
var
  LConfigList: TBytes;
  LSk: ISecretBuffer;
  LMsg: string;
begin
  // the inner hello never offers TLS 1.2 (RFC 9849 6.1), so a real ECH offer on a dual-version
  // client is refused rather than silently narrowed
  LConfigList := BuildEchConfigList($D5, 'cover.example', LSk);
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(
        TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .Tls13.WithEch(TEchClientModes.Enable(LConfigList)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('TLS 1.3-only', LMsg) > 0, 'Enable on a dual-version client is refused; got: ' + LMsg);
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(
        TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .Tls13.WithEch(TEchClientModes.Retry(LConfigList)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('TLS 1.3-only', LMsg) > 0, 'Retry on a dual-version client is refused; got: ' + LMsg);
  // control: the same list builds once the client is pinned to TLS 1.3
  CheckTrue(NewClientBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .Tls13.WithEch(TEchClientModes.Enable(LConfigList)).Build.EncryptedClientHello.Usable,
    'control: a TLS 1.3-only client resolves the config');
end;

procedure TTestConfigBuilder.TestNilEchModeIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.Tls13.WithEch(nil);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil ECH mode is refused');
end;

procedure TTestConfigBuilder.TestEmptySupportedVersionsIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
  LNone: TArray<UInt16>;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LNone := nil;
  LRaised := False;
  try
    LBuilder.Client.WithSupportedVersions(LNone);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty supported-versions set is refused');
end;

procedure TTestConfigBuilder.TestNonNegotiableVersionIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    // TLS 1.0 is not a version the engine can build
    LBuilder.Client.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls10));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-negotiable version is refused');
end;

procedure TTestConfigBuilder.TestDuplicateVersionIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithSupportedVersions(
      TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls13));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a duplicate version is refused');
end;

procedure TTestConfigBuilder.TestAlpnEmptyNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, nil));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ALPN protocol name is refused');
end;

procedure TTestConfigBuilder.TestAlpnNonAsciiNameIsRefused;
var
  LRaised: Boolean;
  LText: string;
begin
  LRaised := False;
  try
    TAlpnProtocols.FromText('h2' + #$00E9);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-ASCII character has no ASCII octets and is refused');
  // an octet above 127 is a legal name on the wire but has no text form
  CheckFalse(TAlpnProtocols.TryToText(TBytes.Create($68, $B2), LText),
    'a name with an octet above 127 has no text form');
  CheckTrue(TAlpnProtocols.TryToText(TAlpnProtocols.H2, LText) and (LText = 'h2'),
    'an ASCII name round-trips through text');
end;

procedure TTestConfigBuilder.TestAlpnOverlongNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised, LAtCapRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(
      TAlpnProtocols.FromText(TArray<string>.Create(StringOfChar('a', 256))));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a 256-byte ALPN protocol name is refused');
  // the 255-byte boundary is legal
  LAtCapRaised := False;
  try
    NewClientBuilder.WithAlpnProtocols(
      TAlpnProtocols.FromText(TArray<string>.Create(StringOfChar('a', 255))));
  except
    on E: EArgumentTlsLibException do
      LAtCapRaised := True;
  end;
  CheckFalse(LAtCapRaised, 'a 255-byte ALPN protocol name is accepted');
end;

procedure TTestConfigBuilder.TestAlpnDuplicateNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(
      TAlpnProtocols.FromText(TArray<string>.Create('h2', 'http/1.1', 'h2')));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a duplicate ALPN protocol name is refused');
end;

procedure TTestConfigBuilder.TestAlpnEmptyListMeansNoAlpn;
var
  LConfig: ITlsClientConfig;
  LNone: TArray<TBytes>;
begin
  LNone := nil;
  LConfig := NewClientBuilder.WithAlpnProtocols(LNone).Build;
  CheckEquals(0, System.Length(LConfig.AlpnProtocols), 'an empty list configures no ALPN');
end;

procedure TTestConfigBuilder.TestAlpnSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<TBytes>;
begin
  LList := TArray<TBytes>.Create(TAlpnProtocols.H2);
  LConfig := NewClientBuilder.WithAlpnProtocols(LList).Build;
  // neither replacing a name nor changing an octet of the caller's arrays may reach the config
  LList[0][0] := Ord('x');
  LList[0] := nil;
  CheckEquals(1, System.Length(LConfig.AlpnProtocols), 'the ALPN list is preserved');
  CheckEqualBytes('the ALPN list is a snapshot of the caller array', TAlpnProtocols.H2,
    LConfig.AlpnProtocols[0]);
end;

procedure TTestConfigBuilder.TestRecordSizeLimitDefaultsToUnset;
begin
  CheckEquals(0, NewClientBuilder.Build.RecordSizeLimit,
    'a client offers no record_size_limit by default');
  CheckEquals(0, NewServerBuilder.Build.RecordSizeLimit,
    'a server offers no record_size_limit by default');
end;

procedure TTestConfigBuilder.TestExternalPskInnerBytesAreCopied;
var
  LPsks, LOut: TArray<TExternalPsk>;
  LConfig: ITlsClientConfig;
begin
  // the frozen config must not alias the caller's identity/context buffers
  LPsks := TArray<TExternalPsk>.Create(MakePskSpec);
  LConfig := NewClientBuilder.Tls13.WithExternalPreSharedKeys(LPsks).Build;
  LPsks[0].Identity[0] := $FF;
  LOut := LConfig.ExternalPsks;
  CheckEquals($61, LOut[0].Identity[0],
    'a caller mutating its identity bytes after Build does not change the config');
  LOut[0].Identity[0] := $EE;
  LOut := LConfig.ExternalPsks;
  CheckEquals($61, LOut[0].Identity[0], 'the accessor returns a copy');
end;

procedure TTestConfigBuilder.TestNilClockIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithClock(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil clock is a typed error, not a silent default');
end;

procedure TTestConfigBuilder.TestNilMonotonicClockIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithMonotonicClock(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil monotonic clock is a typed error on a client builder');
  LRaised := False;
  try
    NewServerBuilder.WithMonotonicClock(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil monotonic clock is a typed error on a server builder');
end;

procedure TTestConfigBuilder.TestMonotonicClockDefaultsToTheSystemSourceAndIsInjectable;
var
  LClock: ITlsMonotonicClock;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
begin
  CheckTrue(NewClientBuilder.Build.MonotonicClock <> nil, 'a client defaults to a clock');
  CheckTrue(NewServerBuilder.Build.MonotonicClock <> nil, 'a server defaults to a clock');
  LClock := TMockMonotonicClock.Create(42) as ITlsMonotonicClock;
  LClientConfig := NewClientBuilder.WithMonotonicClock(LClock).Build;
  CheckTrue(LClientConfig.MonotonicClock = LClock, 'the client config carries the injected clock');
  LServerConfig := NewServerBuilder.WithMonotonicClock(LClock).Build;
  CheckTrue(LServerConfig.MonotonicClock = LClock, 'the server config carries the injected clock');
end;

procedure TTestConfigBuilder.TestAlpnListBeyondWireLimitIsRefused;
var
  LNames: TArray<string>;
  LI: Int32;
  LRaised: Boolean;
begin
  // 64 names of 255 bytes is exactly 16384 wire bytes, the most the list may take
  SetLength(LNames, 64);
  for LI := 0 to 63 do
    LNames[LI] := Format('%.3d', [LI]) + StringOfChar('a', 252);
  NewClientBuilder.WithAlpnProtocols(TAlpnProtocols.FromText(LNames)).Build;
  // one byte more no longer fits
  LNames[63] := LNames[63] + 'a';
  LRaised := False;
  try
    NewClientBuilder.WithAlpnProtocols(TAlpnProtocols.FromText(LNames));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an ALPN list beyond the cap is refused');
end;

procedure TTestConfigBuilder.TestLargestAlpnListStillEncodesInTheClientHello;
var
  LNames: TArray<string>;
  LClient: ITlsEngine;
  LI: Int32;
begin
  // the cap exists so that every list Build accepts also fits the ClientHello's extensions block
  SetLength(LNames, 64);
  for LI := 0 to 63 do
    LNames[LI] := Format('%.3d', [LI]) + StringOfChar('a', 252);
  LClient := TTlsEngineFactory.CreateClientEngine(
    NewClientBuilder.WithAlpnProtocols(TAlpnProtocols.FromText(LNames)).Build, 'localhost');
  LClient.StartHandshake;
  CheckTrue(System.Length(Drain(LClient)) > 16384, 'the ClientHello carries the whole list');
end;

procedure TTestConfigBuilder.TestServerExternalPskNeedsTls13;
var
  LPsks: TArray<TExternalPsk>;
  LRaised: Boolean;
begin
  LPsks := TArray<TExternalPsk>.Create(MakePskSpec);
  NewServerBuilder.Tls13.WithExternalPreSharedKeys(LPsks).Build;
  LRaised := False;
  try
    NewServerBuilder
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
      .Tls13.WithExternalPreSharedKeys(LPsks).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a TLS 1.2-only server cannot honour external PSKs');
end;

procedure TTestConfigBuilder.CheckExternalPskRefused(const APsks: TArray<TExternalPsk>;
  const AMessage: string);
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.Tls13.WithExternalPreSharedKeys(APsks).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, AMessage);
end;

procedure TTestConfigBuilder.TestExternalPskEmptyIdentityIsRefused;
var
  LPsk: TExternalPsk;
begin
  LPsk := MakePskSpec;
  LPsk.Identity := nil;
  CheckExternalPskRefused(TArray<TExternalPsk>.Create(LPsk), 'an empty external PSK identity');
end;

procedure TTestConfigBuilder.TestExternalPskOversizeIdentityIsRefused;
var
  LPsk: TExternalPsk;
begin
  LPsk := MakePskSpec;
  System.SetLength(LPsk.Identity, 65536);
  CheckExternalPskRefused(TArray<TExternalPsk>.Create(LPsk),
    'an external PSK identity beyond 65535 bytes');
end;

procedure TTestConfigBuilder.TestExternalPskNilSecretIsRefused;
var
  LPsk: TExternalPsk;
begin
  LPsk := MakePskSpec;
  LPsk.Secret := nil;
  CheckExternalPskRefused(TArray<TExternalPsk>.Create(LPsk), 'a nil external PSK secret');
end;

procedure TTestConfigBuilder.TestExternalPskEmptySecretIsRefused;
var
  LPsk: TExternalPsk;
begin
  LPsk := MakePskSpec;
  LPsk.Secret := TSecretBuffer.From(nil);
  CheckExternalPskRefused(TArray<TExternalPsk>.Create(LPsk), 'an empty external PSK secret');
end;

procedure TTestConfigBuilder.TestExternalPskDuplicateIdentityIsRefused;
var
  LPsk: TExternalPsk;
begin
  LPsk := MakePskSpec;
  CheckExternalPskRefused(TArray<TExternalPsk>.Create(LPsk, LPsk),
    'two external PSKs with one identity and context');
end;

procedure TTestConfigBuilder.TestExternalPskSameIdentityDifferentContextIsAccepted;
var
  LFirst, LSecond: TExternalPsk;
  LConfig: ITlsClientConfig;
begin
  LFirst := MakePskSpec;
  LSecond := MakePskSpec;
  LSecond.Context := TBytes.Create($01);
  LConfig := NewClientBuilder.Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(LFirst, LSecond)).Build;
  CheckEquals(2, System.Length(LConfig.ExternalPsks),
    'RFC 9258 imported identities differ by context, so the pair is not a duplicate');
end;

procedure TTestConfigBuilder.TestExternalPskSha512ProvisionedHashIsAccepted;
var
  LPsk: TExternalPsk;
  LConfig: ITlsClientConfig;
begin
  // RFC 9258 3 leaves an EPSK's provisioned hash open; only the target KDF is SHA-256 or SHA-384
  LPsk := MakePskSpec;
  LPsk.Hash := THashAlgorithm.SHA_512;
  LConfig := NewClientBuilder.Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(LPsk)).Build;
  CheckEquals(1, System.Length(LConfig.ExternalPsks), 'the SHA-512 PSK is kept');
end;

procedure TTestConfigBuilder.TestExternalPskOversizeContextIsRefused;
var
  LPsk: TExternalPsk;
begin
  LPsk := MakePskSpec;
  System.SetLength(LPsk.Context, 65536);
  CheckExternalPskRefused(TArray<TExternalPsk>.Create(LPsk),
    'a context beyond 2^16-1 bytes cannot be encoded');
end;

procedure TTestConfigBuilder.TestExternalPskImportedIdentityAtTheWireLimitIsAccepted;
var
  LPsk: TExternalPsk;
  LConfig: ITlsServerConfig;
begin
  // a 2-byte identity and a 65525-byte context make a 65535-byte imported identity
  LPsk := MakePskSpec;
  System.SetLength(LPsk.Context, 65525);
  LConfig := NewServerBuilder.Tls13.WithExternalPreSharedKeys(
    TArray<TExternalPsk>.Create(LPsk)).Build;
  CheckEquals(1, System.Length(LConfig.ExternalPsks), 'the largest encodable imported identity');
end;

procedure TTestConfigBuilder.TestExternalPskImportedIdentityBeyondTheWireLimitIsRefused;
var
  LPsk: TExternalPsk;
begin
  LPsk := MakePskSpec;
  System.SetLength(LPsk.Context, 65526);
  CheckExternalPskRefused(TArray<TExternalPsk>.Create(LPsk),
    'an imported identity one byte beyond 2^16-1');
end;

function TTestConfigBuilder.HelloLength(const AFacet: ITls13ClientConfigFacet): Int32;
var
  LClient: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(AFacet.Build, 'localhost');
  LClient.StartHandshake;
  Result := System.Length(Drain(LClient));
end;

function TTestConfigBuilder.HelloDecodes(const AFacet: ITls13ClientConfigFacet): Boolean;
var
  LClient: ITlsEngine;
  LWire, LPayloads: TBytes;
  LReader: THandshakeMessageReader;
  LMessage: TTlsHandshakeMessage;
  LPos, LLength: Int32;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(AFacet.Build, 'localhost');
  LClient.StartHandshake;
  LWire := Drain(LClient);
  // the plaintext handshake records, joined back into the message our own reader would see
  LPayloads := nil;
  LPos := 0;
  while LPos + 5 <= System.Length(LWire) do
  begin
    LLength := (LWire[LPos + 3] shl 8) or LWire[LPos + 4];
    LPayloads := ConcatBytes(LPayloads, System.Copy(LWire, LPos + 5, LLength));
    System.Inc(LPos, 5 + LLength);
  end;
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LPayloads, 0, System.Length(LPayloads));
    Result := LReader.NextMessage(LMessage) and
      (System.Length(THandshakeMessages.DecodeClientHello(LMessage.Body).Extensions) > 0);
  finally
    LReader.Free;
  end;
end;

function TTestConfigBuilder.OfferRefused(const AFacet: ITls13ClientConfigFacet): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := True;
  end;
end;

function TTestConfigBuilder.LargestAlpnBuilder: ITlsClientConfigBuilder;
var
  LNames: TArray<string>;
  LI: Int32;
begin
  System.SetLength(LNames, 64);
  for LI := 0 to 63 do
    LNames[LI] := Format('%.3d', [LI]) + StringOfChar('a', 252);
  Result := NewClientBuilder.WithAlpnProtocols(TAlpnProtocols.FromText(LNames));
end;

function TTestConfigBuilder.CachedTicketBuilder: ITlsClientConfigBuilder;
var
  LCache: ISessionCache;
  LTicket, LScope: TBytes;
begin
  LScope := TBytes.Create($5C);
  // a ticket at the size cap, as a STEK server seals one
  System.SetLength(LTicket, TSessionTicketLimits.MaxCachedTicketBytes);
  LCache := TInMemorySessionCache.Create;
  LCache.Store(TClientSessionPolicy.CacheIdentity('localhost', 'localhost', LScope),
    'localhost',
    TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256, THashAlgorithm.SHA_256,
    TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32)), nil, 'localhost', LTicket,
    3600, 1,
    UInt64(TSystemTimeUtilities.UtcUnixMs), 0, nil, nil) as IResumableSession);
  Result := NewClientBuilder.WithSessionCache(LCache).WithResumptionScope(LScope);
end;

function TTestConfigBuilder.EchFacet(ACount: Int32): ITls13ClientConfigFacet;
var
  LSk: ISecretBuffer;
begin
  Result := NewClientBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .Tls13.WithEch(TEchClientModes.Enable(BuildEchConfigList($D4, 'cover.example', LSk)))
    .WithExternalPreSharedKeys(MakePskSpecs(ACount));
end;

procedure TTestConfigBuilder.TestExternalPskOfferAtTheBudgetIsAccepted;
var
  LConfig: ITlsClientConfig;
begin
  // each 2-byte-identity PSK costs 114 bytes in the extension (two variants); 538 fill the budget
  LConfig := NewClientBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(538)).Build;
  CheckEquals(538, System.Length(LConfig.ExternalPsks), 'the largest offer the budget holds');
end;

procedure TTestConfigBuilder.TestExternalPskOfferBeyondTheBudgetIsRefused;
begin
  CheckTrue(OfferRefused(NewClientBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(539))),
    'one PSK more exceeds the ClientHello extensions budget');
end;

procedure TTestConfigBuilder.TestExternalPskOfferAtTheBudgetEncodesInTheClientHello;
begin
  CheckTrue(HelloLength(NewClientBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(538))) >
    538 * 100, 'the ClientHello carries every variant');
end;

procedure TTestConfigBuilder.TestExternalPskOfferWithTheLargestAlpnListEncodes;
begin
  CheckTrue(HelloLength(LargestAlpnBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(395))) >
    16384 + 395 * 100, 'the largest ALPN list and the PSKs fit one ClientHello');
end;

procedure TTestConfigBuilder.TestExternalPskOfferBeyondTheBudgetWithTheLargestAlpnListIsRefused;
begin
  CheckTrue(OfferRefused(LargestAlpnBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(396))),
    'one PSK more than the largest ALPN list leaves room for');
end;

procedure TTestConfigBuilder.TestExternalPskOfferWithACachedTicketEncodes;
begin
  CheckTrue(HelloLength(CachedTicketBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(394))) >
    16384 + 394 * 100, 'the cached ticket is offered beside the PSKs in one ClientHello');
end;

procedure TTestConfigBuilder.TestExternalPskOfferBeyondTheBudgetWithACachedTicketIsRefused;
begin
  CheckTrue(OfferRefused(CachedTicketBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(395))),
    'one PSK more than a cached ticket leaves room for');
end;

function TTestConfigBuilder.OfferFacet(AKind: TOfferKind;
  ACount: Int32): ITls13ClientConfigFacet;
begin
  case AKind of
    TOfferKind.Plain:
      Result := NewClientBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(ACount));
    TOfferKind.LargestAlpn:
      Result := LargestAlpnBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(ACount));
    TOfferKind.CachedTicket:
      Result := CachedTicketBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(ACount));
  else
    Result := EchFacet(ACount);
  end;
end;

function TTestConfigBuilder.LargestAcceptedCount(AKind: TOfferKind): Int32;
var
  LLow, LHigh, LMid: Int32;
begin
  // the largest PSK count Build accepts for this shape
  LLow := 1;
  LHigh := 800;
  while LLow < LHigh do
  begin
    LMid := (LLow + LHigh + 1) div 2;
    if OfferRefused(OfferFacet(AKind, LMid)) then
      LHigh := LMid - 1
    else
      LLow := LMid;
  end;
  Result := LLow;
end;

procedure TTestConfigBuilder.TestExternalPskOfferAtTheBudgetIsDecodedByTheReader;
begin
  CheckTrue(HelloDecodes(OfferFacet(TOfferKind.Plain, LargestAcceptedCount(TOfferKind.Plain))),
    'our own reader accepts the largest default offer Build accepts');
end;

procedure TTestConfigBuilder.TestExternalPskOfferWithTheLargestAlpnListIsDecodedByTheReader;
begin
  CheckTrue(HelloDecodes(OfferFacet(TOfferKind.LargestAlpn,
    LargestAcceptedCount(TOfferKind.LargestAlpn))),
    'our own reader accepts the largest offer Build accepts beside the largest ALPN list');
end;

procedure TTestConfigBuilder.TestExternalPskOfferWithACachedTicketIsDecodedByTheReader;
begin
  // the ticket allowance is deliberately the offered size, so this one is tight by design
  CheckTrue(HelloDecodes(OfferFacet(TOfferKind.CachedTicket,
    LargestAcceptedCount(TOfferKind.CachedTicket))),
    'our own reader accepts the largest offer Build accepts beside a cached ticket');
end;

procedure TTestConfigBuilder.TestExternalPskOfferWithEchIsDecodedByTheReader;
begin
  // the ECH factor of two over-counts the inner, which compresses shared extensions, so it has headroom
  CheckTrue(HelloDecodes(OfferFacet(TOfferKind.Ech, LargestAcceptedCount(TOfferKind.Ech))),
    'our own reader accepts the largest ECH offer Build accepts');
end;

procedure TTestConfigBuilder.TestExternalPskOfferWithEchEncodes;
begin
  CheckTrue(HelloLength(EchFacet(246)) > 246 * 100, 'the inner and outer hellos fit the ECH payload');
end;

procedure TTestConfigBuilder.TestExternalPskOfferBeyondTheBudgetWithEchIsRefused;
begin
  CheckTrue(OfferRefused(EchFacet(247)), 'one PSK more than an ECH offer leaves room for');
end;

procedure TTestConfigBuilder.TestServerMayHoldMoreExternalPsksThanAClientMayOffer;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := NewServerBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(600)).Build;
  CheckEquals(600, System.Length(LConfig.ExternalPsks), 'a server only matches one offered PSK');
end;

procedure TTestConfigBuilder.TestServerWithCertificateAndBadExternalPskIsRefused;
var
  LPsk: TExternalPsk;
  LRaised: Boolean;
begin
  LPsk := MakePskSpec;
  LPsk.Identity := nil;
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(LPsk)).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a certificate server with a malformed external PSK does not build');
end;

procedure TTestConfigBuilder.TestPskOnlyServerMustOfferTls13Only;
var
  LPsks: TArray<TExternalPsk>;
  LOwner: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LPsks := TArray<TExternalPsk>.Create(MakePskSpec);
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LOwner.Server.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .Tls13.WithExternalPreSharedKeys(LPsks).Build;
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LOwner.Server
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13))
      .Tls13.WithExternalPreSharedKeys(LPsks).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a certificate-less PSK server offering TLS 1.2 is refused');
end;

procedure TTestConfigBuilder.TestTls12NeedsAClassicalEcdheGroup;

  function Accepted(const AGroups, AVersions: TArray<UInt16>): Boolean;
  begin
    Result := True;
    try
      NewClientBuilder.WithSupportedVersions(AVersions).WithPreferredGroups(AGroups).Build;
    except
      on E: EArgumentTlsLibException do
        Result := False;
    end;
  end;

var
  LRaised: Boolean;
begin
  CheckTrue(Accepted(TArray<UInt16>.Create(TNamedGroupCatalog.X25519),
    TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13)),
    'a classical group serves TLS 1.2');
  CheckTrue(Accepted(TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768),
    TArray<UInt16>.Create(TlsWireVersionTls13)), 'a hybrid group serves TLS 1.3 alone');
  CheckFalse(Accepted(TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768),
    TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13)),
    'a hybrid-only preference cannot serve the TLS 1.2 it offers');
  LRaised := False;
  try
    NewServerBuilder.WithSupportedVersions(
      TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13))
      .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768)).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the same refusal applies to a server');
end;

procedure TTestConfigBuilder.TestOneBuilderConfiguresOneEndpoint;
var
  LOwner: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LOwner.Client;
  LRaised := False;
  try
    LOwner.Server;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the server view after the client view is refused');
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LOwner.Server;
  LRaised := False;
  try
    LOwner.Client;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the client view after the server view is refused');
  LOwner.Server;
end;

procedure TTestConfigBuilder.TestPreferredGroupsWithNoRegisteredGroupIsRefused;
var
  LRaised: Boolean;
begin
  NewClientBuilder.WithPreferredGroups(
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519)).Build;
  LRaised := False;
  try
    NewClientBuilder.WithPreferredGroups(TArray<UInt16>.Create($FEFE)).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'preferred groups that are all unregistered are refused at Build');
end;

procedure TTestConfigBuilder.TestDuplicatePreferredGroupIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithPreferredGroups(TArray<UInt16>.Create(
      TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.X25519)).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a duplicate preferred group is refused (RFC 9846 4.3.7)');
end;

procedure TTestConfigBuilder.TestEmptyPreferredGroupsIsRefusedAtBuild;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithPreferredGroups(nil).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty preferred-group list is a typed error at Build');
end;

procedure TTestConfigBuilder.TestNilRegistryIsRefusedAtBuild;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithCipherSuites(nil).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil cipher-suite registry is a typed error at Build');
end;

procedure TTestConfigBuilder.TestCipherSuiteListNarrowsAndOrdersPerProtocol;
var
  LConfig: ITlsClientConfig;
  L12, L13: TArray<UInt16>;
begin
  LConfig := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes256GcmSha384,
      TCipherSuites12.EcdheEcdsaAes128GcmSha256, TCipherSuites13.Aes256GcmSha384))
    .Build;
  L12 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls12);
  L13 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls13);
  CheckEquals(2, System.Length(L12), 'only the listed 1.2 suites remain');
  CheckEquals(TCipherSuites12.EcdheEcdsaAes256GcmSha384, L12[0], 'list order is kept');
  CheckEquals(TCipherSuites12.EcdheEcdsaAes128GcmSha256, L12[1], 'list order is kept');
  CheckEquals(1, System.Length(L13), 'only the listed 1.3 suite remains');
  CheckEquals(TCipherSuites13.Aes256GcmSha384, L13[0], 'the listed 1.3 suite');
end;

procedure TTestConfigBuilder.TestFailedBuildLeavesTheCipherSuiteListInForce;
var
  LBuilder: ITlsClientConfigBuilder;
  LConfig: ITlsClientConfig;
  LRaised: Boolean;
  L13: TArray<UInt16>;
begin
  // a Build refused for another reason must not consume the list: a retry that also swaps in a
  // wider registry still narrows, instead of silently carrying the full set
  LBuilder := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384))
    .WithPreferredGroups(TArray<UInt16>.Create($FFFE));
  LRaised := False;
  try
    LBuilder.Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a preferred group nothing registers is refused');
  LConfig := LBuilder.WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519)).Build;
  L13 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls13);
  CheckEquals(1, System.Length(L13), 'the list is still in force after the failed Build');
  CheckEquals(TCipherSuites13.Aes256GcmSha384, L13[0], 'the listed suite');
end;

procedure TTestConfigBuilder.TestCipherSuiteListLeavesAnUnnamedProtocolIntact;
var
  LConfig: ITlsClientConfig;
  L12, L13: TArray<UInt16>;
begin
  // a list naming only 1.2 suites narrows 1.2 and leaves the 1.3 set as configured
  LConfig := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256))
    .Build;
  L12 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls12);
  L13 := TNegotiationPolicy.SuiteOrder(DefaultProfile.CipherSuites, TSuiteProtocol.Tls13);
  CheckEquals(1, System.Length(L12), 'the named protocol is narrowed');
  CheckEquals(TCipherSuites12.EcdheEcdsaAes128GcmSha256, L12[0], 'the listed 1.2 suite');
  CheckTrue(SameOrder(L13,
    TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls13)),
    'the unnamed protocol keeps its configured suites and order');
end;

procedure TTestConfigBuilder.TestCipherSuiteListOutsideTheConfiguredSetIsRefused;
var
  LRaised: Boolean;
begin
  // the list narrows and reorders; it never admits a suite the configured set does not hold
  LRaised := False;
  try
    NewClientBuilder
      .WithCipherSuiteList(TArray<UInt16>.Create(UInt16($002F)))
      .Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a suite outside the configured set is refused at Build');
end;

procedure TTestConfigBuilder.TestCipherSuiteListIsIndependentOfCallOrder;
var
  LBefore, LAfter: ITlsClientConfig;
  LList: TArray<UInt16>;
begin
  LList := TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes256GcmSha384,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  LBefore := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCipherSuiteList(LList)
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .Build;
  LAfter := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .WithCipherSuiteList(LList)
    .Build;
  CheckTrue(SameOrder(
    TNegotiationPolicy.SuiteOrder(LBefore.CipherSuites, TSuiteProtocol.Tls12),
    TNegotiationPolicy.SuiteOrder(LAfter.CipherSuites, TSuiteProtocol.Tls12)),
    'the list applies at Build, whichever order the setters ran in');
end;

procedure TTestConfigBuilder.TestInjectedVerifierRefusesSettingsItIgnores;
  function ClientRefused(const ABuilder: ITlsClientConfigBuilder): Boolean;
  begin
    Result := False;
    try
      ABuilder.Build;
    except
      on E: EInvalidOperationTlsLibException do
        Result := Pos('injected verifier', E.Message) > 0;
    end;
  end;

  function ServerRefused(const ABuilder: ITlsServerConfigBuilder): Boolean;
  begin
    Result := False;
    try
      ABuilder.Build;
    except
      on E: EInvalidOperationTlsLibException do
        Result := Pos('injected verifier', E.Message) > 0;
    end;
  end;

  function NewVerifierServer(APosture: TRevocationPosture): ITlsServerConfigBuilder;
  begin
    Result := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required).WithClientVerification(TClientVerification.Custom(
      TFixedVerdictVerifier.CreateAccepting(False) as IClientCertificateVerifier, APosture));
  end;

  function NewVerifierClient(APosture: TRevocationPosture): ITlsClientConfigBuilder;
  begin
    Result := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
      TServerVerification.Custom(TFixedVerdictVerifier.CreateAccepting(False)
      as IServerCertificateVerifier, APosture));
  end;

begin
  // a whole-verifier replaces the built-in verification: it has no intermediates, floors or skip
  // to ignore, and Hard needs the live verdict because the verifier does not apply the posture
  CheckTrue(ClientRefused(NewVerifierClient(TRevocationPosture.Hard)),
    'Hard revocation beside a verifier instance without a live verdict');
  CheckTrue(ClientRefused(NewVerifierClient(TRevocationPosture.Hard).WithOcspStaplingRequest(True)),
    'stapling does not rescue Hard beside a verifier instance');
  CheckTrue(ServerRefused(NewVerifierServer(TRevocationPosture.Hard)),
    'Hard revocation beside a client-certificate verifier instance');
  // controls: the verifier alone builds, and Hard builds when a live verdict applies it
  CheckTrue(NewVerifierServer(TRevocationPosture.Soft).Build <> nil,
    'control: the client-certificate verifier alone builds');
  CheckTrue(NewVerifierClient(TRevocationPosture.Soft).Build <> nil,
    'control: the verifier alone builds');
  CheckTrue(NewVerifierClient(TRevocationPosture.Hard)
    .WithLiveRevocationVerdict(1000).Build <> nil, 'control: Hard with a live verdict builds');
end;

function TTestConfigBuilder.ClientBuildNeedsTls13(const AFacet: ITls13ClientConfigFacet): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    // the reason is checked too, so a case cannot pass on some unrelated refusal
    on E: EInvalidOperationTlsLibException do
      Result := Pos('TLS 1.3 settings', E.Message) > 0;
  end;
end;

function TTestConfigBuilder.ServerBuildNeedsTls13(const AFacet: ITls13ServerConfigFacet): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos('TLS 1.3 settings', E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const ABuilder: ITlsClientConfigBuilder;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    ABuilder.Build;
  except
    // the reason is checked too, so a case cannot pass on some unrelated refusal
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const ABuilder: ITlsServerConfigBuilder;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    ABuilder.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const AFacet: ITls13ClientConfigFacet;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const AFacet: ITls12ClientConfigFacet;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const AFacet: ITls13ServerConfigFacet;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const AFacet: ITls12ServerConfigFacet;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

procedure TTestConfigBuilder.TestTls13SettingsAreRefusedWhenTls13IsNotOffered;
var
  LOnly12: TArray<UInt16>;
begin
  // the ticket count and the PSK settings are read only by the TLS 1.3 machines; set on a
  // TLS 1.2-only config they would silently do nothing, so the Tls13 facet refuses them at Build
  LOnly12 := TArray<UInt16>.Create(TlsWireVersionTls12);
  CheckTrue(ClientBuildNeedsTls13(NewClientBuilder.WithSupportedVersions(LOnly12)
    .Tls13.WithExternalPskRequired(False)),
    'the PSK-required switch alone, with no PSKs, on a TLS 1.2-only client');
  CheckTrue(ServerBuildNeedsTls13(NewServerBuilder.WithSupportedVersions(LOnly12)
    .Tls13.WithTicketCount(3)), 'a ticket count on a TLS 1.2-only server');
  // restating a default is not a setting: the facet counts as configured only by a non-default value
  CheckTrue(NewClientBuilder.WithSupportedVersions(LOnly12).WithGrease(False).Build <> nil,
    'GREASE applies to a TLS 1.2-only hello too, so turning it off is not refused');
  CheckTrue(NewServerBuilder.WithSupportedVersions(LOnly12).Tls13.WithTicketCount(2).Build <> nil,
    'restating the default ticket count on a TLS 1.2-only server is not refused');
  CheckTrue(ClientBuildNeedsTls13(NewClientBuilder.WithSupportedVersions(LOnly12)
    .Tls13.WithEch(TEchClientModes.Grease)), 'ECH GREASE on a TLS 1.2-only client');
  // controls: the same client and server build once TLS 1.3 is offered, or when no Tls13 setting
  // was touched
  CheckTrue(NewClientBuilder.WithSupportedVersions(LOnly12).Build <> nil,
    'control: a TLS 1.2-only client without Tls13 settings builds');
  CheckTrue(NewServerBuilder.WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls13)).Tls13.WithTicketCount(2).Build.TicketCount = 2,
    'control: the ticket count builds with TLS 1.3');
end;

procedure TTestConfigBuilder.TestEmptyCipherSuiteListIsRefused;
var
  LRaised: Boolean;
begin
  // an empty list must not read as "no list", which would leave the preset's full set in force
  LRaised := False;
  try
    NewClientBuilder.WithCipherSuiteList(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty cipher-suite list is a typed error');
end;

procedure TTestConfigBuilder.TestOfferedVersionWithoutASuiteIsRefused;
var
  LRaised: Boolean;
begin
  // a 1.3-only registry cannot back an offered TLS 1.2
  LRaised := False;
  try
    NewClientBuilder
      .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
      .Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an offered version with no cipher suite is refused at Build');
end;

procedure TTestConfigBuilder.TestCertificateCompressionSetsAreValidated;
var
  LNilEntry: TArray<ICertificateCompressor>;
  LTwice: TArray<ICertificateDecompressor>;
  LNilRefused, LTwiceRefused: Boolean;
begin
  // nil and a repeated codepoint are refused where they are set
  SetLength(LNilEntry, 1);
  LNilEntry[0] := nil;
  LNilRefused := False;
  try
    NewClientBuilder.Tls13.WithCertificateCompressors(LNilEntry);
  except
    on E: EArgumentTlsLibException do
      LNilRefused := True;
  end;
  CheckTrue(LNilRefused, 'a nil compressor');
  LTwice := TArray<ICertificateDecompressor>.Create(
    TZlibCertificateCompression.DefaultDecompressors[0],
    TZlibCertificateCompression.DefaultDecompressors[0]);
  LTwiceRefused := False;
  try
    NewServerBuilder.Tls13.WithCertificateDecompressors(LTwice);
  except
    on E: EArgumentTlsLibException do
      LTwiceRefused := True;
  end;
  CheckTrue(LTwiceRefused, 'a repeated decompressor codepoint');
  // empty or nil turns a direction off and is valid
  CheckTrue(NewClientBuilder.Tls13.WithCertificateCompressors(nil)
    .WithCertificateDecompressors(nil).Build <> nil, 'an empty set builds');
end;

procedure TTestConfigBuilder.TestMoreThan127DistinctDecompressorsAreRefusedForTheCount;
var
  LMany: TArray<ICertificateDecompressor>;
  LI: Int32;
  LMsg: string;
begin
  // 128 distinct codepoints, so only the RFC 8879 3 count cap can refuse the set
  SetLength(LMany, 128);
  for LI := 0 to 127 do
    LMany[LI] := TMockCertificateDecompressor.Create(1 + LI,
      TMockDecompressorMode.Fails) as ICertificateDecompressor;
  LMsg := '';
  try
    NewClientBuilder.Tls13.WithCertificateDecompressors(LMany);
  except
    on E: EArgumentTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('at most 127', LMsg) > 0,
    'more than 127 distinct decompressors are refused for the count; got: ' + LMsg);
end;

procedure TTestConfigBuilder.Test127DistinctDecompressorsAreAccepted;
var
  LSet: TArray<ICertificateDecompressor>;
  LConfig: ITlsClientConfig;
  LI: Int32;
begin
  SetLength(LSet, 127);
  for LI := 0 to 126 do
    LSet[LI] := TMockCertificateDecompressor.Create(1 + LI,
      TMockDecompressorMode.Fails) as ICertificateDecompressor;
  LConfig := NewClientBuilder.Tls13.WithCertificateDecompressors(LSet).Build;
  CheckEquals(127, System.Length(LConfig.CertificateDecompressors),
    'the boundary count (127) is accepted and kept');
end;

procedure TTestConfigBuilder.TestClientCertificateCompressionCacheIsConfigurable;
var
  LCache: ICertificateCompressionCache;
begin
  LCache := TInMemoryCertificateCompressionCache.Create;
  CheckTrue(NewClientBuilder.Build.CertificateCompressionCache = nil, 'a client defaults to no cache');
  CheckTrue(NewServerBuilder.Build.CertificateCompressionCache = nil, 'a server defaults to no cache');
  CheckTrue(NewClientBuilder.WithCredential(ServerCredential).Tls13
    .WithCertificateCompressionCache(LCache).Build.CertificateCompressionCache = LCache,
    'a client can memoize its own compression');
end;

function TTestConfigBuilder.HelloSuites(const AWire: TBytes): TArray<UInt16>;
var
  LPos, LCount, LI: Int32;
begin
  // record header 5, handshake header 4, legacy_version 2, random 32, session id, cipher_suites
  LPos := 5 + 4 + 2 + 32;
  LPos := LPos + 1 + AWire[LPos];
  LCount := ((AWire[LPos] shl 8) or AWire[LPos + 1]) div 2;
  Inc(LPos, 2);
  SetLength(Result, LCount);
  for LI := 0 to LCount - 1 do
    Result[LI] := UInt16((AWire[LPos + 2 * LI] shl 8) or AWire[LPos + 2 * LI + 1]);
end;

function TTestConfigBuilder.NewTls12OnlyClient(AGrease: Boolean): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithGrease(AGrease).Build, 'localhost');
end;

function TTestConfigBuilder.GreaseCount(const AValues: TArray<UInt16>): Int32;
var
  LValue: UInt16;
begin
  Result := 0;
  for LValue in AValues do
    if TGrease.IsGrease(LValue) then
      Inc(Result);
end;

procedure TTestConfigBuilder.TestTls12OnlyHelloCarriesGrease;
var
  LClient: ITlsEngine;
  LHello: TTlsClientHello;
  LVector: TExtensionVector;
  LTypes: TArray<UInt16>;
  LEntry: TExtensionEntry;
  LGreaseTypes: Int32;
  LType: UInt16;
  LBodies: array[0..1] of Int32;
begin
  // RFC 8701 3.1 covers every ClientHello, not just a TLS 1.3 one
  LClient := NewTls12OnlyClient(True);
  LClient.StartHandshake;
  LHello := TTlsLibTestHandshakeDecoder.ClientHello(Drain(LClient));
  CheckEquals(1, GreaseCount(LHello.CipherSuites), 'one GREASE cipher suite');
  LVector := TExtensionVector.Parse(LHello.Extensions);
  CheckTrue(LVector.TryFind(TExtensionTypes.SupportedGroups, LEntry), 'supported_groups is sent');
  CheckTrue(TGrease.IsGrease(UInt16((LEntry.Data[2] shl 8) or LEntry.Data[3])),
    'a GREASE group leads supported_groups');
  CheckTrue(LVector.TryFind(TExtensionTypes.SignatureAlgorithms, LEntry),
    'signature_algorithms is sent');
  CheckTrue(TGrease.IsGrease(UInt16((LEntry.Data[2] shl 8) or LEntry.Data[3])),
    'a GREASE scheme leads signature_algorithms');
  CheckTrue(LVector.TryFind(TExtensionTypes.SupportedVersions, LEntry),
    'supported_versions is sent');
  CheckTrue(TGrease.IsGrease(UInt16((LEntry.Data[1] shl 8) or LEntry.Data[2])),
    'a GREASE version leads supported_versions');
  LTypes := LVector.Types;
  LGreaseTypes := 0;
  LBodies[0] := -1;
  LBodies[1] := -1;
  for LType in LTypes do
    if TGrease.IsGrease(LType) then
    begin
      LVector.TryFind(LType, LEntry);
      LBodies[LGreaseTypes] := System.Length(LEntry.Data);
      Inc(LGreaseTypes);
    end;
  CheckEquals(2, LGreaseTypes, 'two GREASE extensions');
  CheckEquals(0, LBodies[0] + LBodies[1] - 1, 'one empty and one one-byte, so the hello varies');
end;

procedure TTestConfigBuilder.TestGreaseOffSendsNone;
var
  LClient: ITlsEngine;
  LHello: TTlsClientHello;
  LVector: TExtensionVector;
  LType: UInt16;
begin
  LClient := NewTls12OnlyClient(False);
  LClient.StartHandshake;
  LHello := TTlsLibTestHandshakeDecoder.ClientHello(Drain(LClient));
  CheckEquals(0, GreaseCount(LHello.CipherSuites), 'no GREASE suite');
  LVector := TExtensionVector.Parse(LHello.Extensions);
  for LType in LVector.Types do
    CheckFalse(TGrease.IsGrease(LType), 'no GREASE extension');
end;

procedure TTestConfigBuilder.TestTls12OnlyClientCompletesWithGrease;
var
  LClient, LServer: ITlsEngine;
begin
  // a conformant server ignores the GREASE values (RFC 8701 3.2)
  LClient := NewTls12OnlyClient(True);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEquals(Int64(TlsWireVersionTls12), Int64(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
    'over TLS 1.2');
end;

procedure TTestConfigBuilder.TestTls12ClientRefusesAGreaseSuiteTheServerSelects;
var
  LClient: ITlsEngine;
  LHello: TTlsClientHello;
  LMsg: TTlsServerHello;
  LFramed, LRecord: TBytes;
  LI, LGreaseSuite: Int32;
begin
  // the client must reject a GREASE value the server selects (RFC 8701 3.1): the check runs
  // against the configured suites, which never hold one
  LClient := NewTls12OnlyClient(True);
  LClient.StartHandshake;
  LHello := TTlsLibTestHandshakeDecoder.ClientHello(Drain(LClient));
  LGreaseSuite := -1;
  for LI := 0 to System.High(LHello.CipherSuites) do
    if TGrease.IsGrease(LHello.CipherSuites[LI]) then
      LGreaseSuite := LHello.CipherSuites[LI];
  CheckTrue(LGreaseSuite >= 0, 'the hello offered a GREASE suite');
  LMsg.LegacyVersion := TlsWireVersionTls12;
  LMsg.Random := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LMsg.LegacySessionIdEcho := LHello.LegacySessionId;
  LMsg.CipherSuite := UInt16(LGreaseSuite);
  LMsg.Extensions := TBytes.Create(0, 0);
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LMsg));
  LRecord := ConcatBytes(TBytes.Create($16, $03, $03, Byte(System.Length(LFramed) shr 8),
    Byte(System.Length(LFramed))), LFramed);
  Feed(LClient, LRecord);
  CheckTrue(LClient.IsTerminal, 'the client aborted');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'with illegal_parameter');
end;

procedure TTestConfigBuilder.PatchServerKeyExchange(var AWire: TBytes; ACurve: Boolean;
  AValue: UInt16);
var
  LRecordPos, LMsgPos, LMsgLen, LBody, LOffset: Int32;
begin
  if not TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(AWire,
    Ord(TTlsHandshakeType.ServerKeyExchange), LRecordPos, LMsgPos, LMsgLen) then
    Fail('the flight carries no plaintext ServerKeyExchange');
  // curve_type(1) named_curve(2) point_len(1) point, then the scheme(2)
  LBody := LMsgPos + 4;
  if ACurve then
    LOffset := LBody + 1
  else
    LOffset := LBody + 4 + AWire[LBody + 3];
  AWire[LOffset] := Byte(AValue shr 8);
  AWire[LOffset + 1] := Byte(AValue);
end;

procedure TTestConfigBuilder.CheckGreaseInServerKeyExchangeIsRefused(ACurve: Boolean);
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
begin
  // RFC 8701 3.1: a client MUST reject a GREASE value the server negotiates, including the TLS 1.2
  // ServerKeyExchange named curve and signature algorithm; patch one into a real server flight
  LClient := NewTls12OnlyClient(True);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  LClient.StartHandshake;
  Pump(LClient, LServer);
  LFlight := Drain(LServer);
  PatchServerKeyExchange(LFlight, ACurve, TGrease.ValueAt(5));
  Feed(LClient, LFlight);
  CheckTrue(LClient.IsTerminal, 'the client aborted');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'with illegal_parameter');
end;

procedure TTestConfigBuilder.TestTls12ClientRefusesAGreaseCurveInServerKeyExchange;
begin
  CheckGreaseInServerKeyExchangeIsRefused(True);
end;

procedure TTestConfigBuilder.TestTls12ClientRefusesAGreaseSchemeInServerKeyExchange;
begin
  CheckGreaseInServerKeyExchangeIsRefused(False);
end;

procedure TTestConfigBuilder.TestSingleVersionHelloAdvertisesOnlyThatVersionsSuites;
var
  LSuites: TArray<UInt16>;
  LI: Int32;
  LHas13, LHas12: Boolean;
  LClient: ITlsEngine;
begin
  // a dual-version registry offered to a TLS 1.3-only client: no TLS 1.2 suite goes on the wire
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13)).Build, 'localhost');
  LClient.StartHandshake;
  LSuites := HelloSuites(Drain(LClient));
  LHas13 := False;
  LHas12 := False;
  for LI := 0 to System.High(LSuites) do
    if (LSuites[LI] shr 8) = $13 then
      LHas13 := True
    // a GREASE value and the signalling suite values (RFC 8701, RFC 5746, RFC 7507) are not suites
    else if ((LSuites[LI] and $0F0F) <> $0A0A) and (LSuites[LI] <> $00FF) and
      (LSuites[LI] <> $5600) then
      LHas12 := True;
  CheckTrue(LHas13, 'a TLS 1.3 suite is advertised');
  CheckFalse(LHas12, 'no TLS 1.2 suite is advertised to a TLS 1.3-only client');

  // and the reverse: a TLS 1.2-only client advertises no TLS 1.3 suite
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12)).Build, 'localhost');
  LClient.StartHandshake;
  LSuites := HelloSuites(Drain(LClient));
  LHas13 := False;
  for LI := 0 to System.High(LSuites) do
    if (LSuites[LI] shr 8) = $13 then
      LHas13 := True;
  CheckFalse(LHas13, 'no TLS 1.3 suite is advertised to a TLS 1.2-only client');
  CheckTrue(System.Length(LSuites) > 0, 'a TLS 1.2 hello still lists suites');
end;

procedure TTestConfigBuilder.TestWebPkiPolicyCarriesItsSettingsIntoTheConfig;
var
  LStrength: TCertificateStrengthPolicy;
  LConfig: ITlsClientConfig;
  LChain: TStringList;
begin
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 3072;
  LChain := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
  LConfig := NewBareClientBuilder.WithOcspStaplingRequest(True)
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.EcP256RootStore)
    .WithMinimumStrength(LStrength).WithRevocation(TRevocationPosture.Hard)
    .WithIntermediateCertificates(DecodeHex(LChain.Values['root_cert'])).Build).Build;
  CheckTrue(LConfig.TrustStore.AnchorCount > 0, 'the policy anchors reach the config');
  CheckEquals(3072, LConfig.CertificateStrengthPolicy.MinRsaModulusBits, 'the strength floor');
  CheckTrue(LConfig.RevocationPosture = TRevocationPosture.Hard, 'the revocation posture');
  CheckEquals(1, System.Length(LConfig.IntermediateCertificates), 'the intermediates');
  CheckFalse(LConfig.DangerousTrust.InsecureSkipVerify, 'not a skip');
end;

procedure TTestConfigBuilder.TestSkipAndCustomPoliciesNeedNoAnchors;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := NewBareClientBuilder.WithServerVerification(TServerVerification.DangerousSkip).Build;
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify, 'skip sets the dangerous flag');
  CheckNull(LConfig.TrustStore, 'and holds no anchors');
  LConfig := NewBareClientBuilder.WithServerVerification(
    TServerVerification.Custom(TFixedVerdictVerifier.CreateAccepting(False)
    as IServerCertificateVerifier)).Build;
  CheckNull(LConfig.TrustStore, 'a whole verifier holds no anchors');
  // an injected verifier does not apply the posture, so Hard needs the live verdict
  CheckTrue(BuildRefused(NewBareClientBuilder.WithOcspStaplingRequest(True)
    .WithServerVerification(TServerVerification.Custom(
    TFixedVerdictVerifier.CreateAccepting(False) as IServerCertificateVerifier,
    TRevocationPosture.Hard)),
    'WithLiveRevocationVerdict'), 'Hard over an injected verifier without a live verdict');
  CheckNotNull(NewBareClientBuilder.WithLiveRevocationVerdict(1000)
    .WithServerVerification(TServerVerification.Custom(
    TFixedVerdictVerifier.CreateAccepting(False) as IServerCertificateVerifier,
    TRevocationPosture.Hard)).Build,
    'and builds with one');
end;

procedure TTestConfigBuilder.TestVerificationFactoriesRefuseUnusableInput;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TServerVerification.WebPki(nil, nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a WebPki policy with no anchors is refused');
  LRaised := False;
  try
    TServerVerification.Custom(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil verifier is refused');
  LRaised := False;
  try
    TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).WithMinimumStrength(
      Default(TCertificateStrengthPolicy));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'invalid strength floors are refused at the call');
end;

procedure TTestConfigBuilder.TestInertSettingsAreRefusedAtBuild;
begin
  CheckTrue(BuildRefused(NewClientBuilder
    .WithResumptionScope(Crypto.Primitives.GetRandom.GenerateBytes(8)),
    'without a session cache'), 'a client scope with resumption on but no cache');
  CheckTrue(BuildRefused(NewClientBuilder.Tls13.WithExternalPskRequired(False),
    'marked optional'), 'optional external PSKs without any');
  CheckTrue(BuildRefused(NewClientBuilder
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .Tls12.WithPreSharedKeyRequired(False), 'marked optional'),
    'an optional TLS 1.2 PSK without one');
  CheckTrue(BuildRefused(NewServerBuilder
    .Tls13.WithAntiReplay(TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy),
    'early-data budget'), 'an anti-replay strategy with no early-data budget');
end;

procedure TTestConfigBuilder.TestRevertedFacetSettingsAndTicketCountZeroAreNotInert;
begin
  // a Tls13 setting put back to its default no longer counts, so a TLS 1.2-only server builds
  CheckNotNull(NewServerBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .Tls13.WithTicketCount(3).WithTicketCount(2).Build, 'a reverted ticket count');
  // "no tickets" agrees with resumption off
  CheckNotNull(NewServerBuilder.WithResumption(False).Tls13.WithTicketCount(0).Build,
    'ticket count 0 with resumption off');
end;

procedure TTestConfigBuilder.TestResumptionSettingsAreRefusedWhenResumptionIsOff;
begin
  // a setting that only matters when resuming is refused with resumption off, in either order
  CheckTrue(BuildRefused(NewClientBuilder.WithResumption(False)
    .WithSessionCache(TInMemorySessionCache.Create), 'resumption is off'), 'a session cache');
  CheckTrue(BuildRefused(NewClientBuilder.WithSessionCache(TInMemorySessionCache.Create)
    .WithResumption(False), 'resumption is off'),
    'a session cache set before resumption was turned off');
  CheckTrue(BuildRefused(NewClientBuilder.WithResumption(False)
    .WithResumptionScope(Crypto.Primitives.GetRandom.GenerateBytes(8)), 'resumption is off'),
    'a client scope');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False)
    .WithSessionStore(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom)),
    'resumption is off'), 'a session store');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False).WithTicketLifetime(600),
    'resumption is off'), 'a ticket lifetime');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False).Tls13.WithTicketCount(1),
    'resumption is off'), 'a ticket count');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False)
    .WithResumptionScope(Crypto.Primitives.GetRandom.GenerateBytes(8)), 'resumption is off'),
    'a server scope');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False).WithDefaultSessionTicketKeys,
    'resumption is off'), 'default ticket keys');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False)
    .Tls12.WithNonEmsResumption(TNonEmsResumption.Resume), 'resumption is off'),
    'a non-EMS resumption mode');
  // restating a default is not a setting
  CheckTrue(NewServerBuilder.WithResumption(False)
    .WithTicketLifetime(TTlsConfigBuilder.DefaultTicketLifetimeSeconds)
    .Tls13.WithTicketCount(2).Build <> nil, 'the default ticket settings build with resumption off');
  // controls: nothing supplied builds, and the same settings build with resumption on
  CheckTrue(NewClientBuilder.WithResumption(False).Build <> nil,
    'resumption off alone builds for a client');
  CheckTrue(NewServerBuilder.WithResumption(False).Build <> nil,
    'resumption off alone builds for a server');
  CheckTrue(NewServerBuilder.WithTicketLifetime(600).Tls13.WithTicketCount(1).Build <> nil,
    'ticket settings build with resumption on');
end;

procedure TTestConfigBuilder.TestAlpnRejectionWithProtocolsIsRefused;
begin
  // rejecting every ALPN offer contradicts a list of protocols to select from
  CheckTrue(BuildRefused(NewServerBuilder.WithAlpnRejection(True)
    .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2)), 'ALPN rejection'),
    'rejection with a list');
  CheckTrue(NewServerBuilder.WithAlpnRejection(True).Build <> nil,
    'rejection alone builds');
  CheckTrue(NewServerBuilder.WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2)).Build <> nil,
    'a list alone builds');
end;

procedure TTestConfigBuilder.TestServerCipherSuiteListOrderDecidesTheNegotiatedSuite;
var
  LClient, LServer: ITlsEngine;
begin
  // the host's order is the server's preference whatever the hardware would otherwise favour
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder.Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites13.ChaCha20Poly1305Sha256,
      TCipherSuites13.Aes128GcmSha256)).Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the handshake completed');
  CheckEquals(TCipherSuites13.ChaCha20Poly1305Sha256, LServer.ConnectionInfo.CipherSuite,
    'the first listed suite is negotiated');
end;

procedure TTestConfigBuilder.TestClientCipherSuiteListIsTheOnlyOfferedSuite;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384)).Build,
    'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the handshake completed');
  CheckEquals(TCipherSuites13.Aes256GcmSha384, LServer.ConnectionInfo.CipherSuite,
    'the one listed suite is negotiated');
end;

procedure TTestConfigBuilder.TestRecordSizeLimitRoundTrips;
begin
  CheckEquals(512, NewClientBuilder.WithRecordSizeLimit(512).Build.RecordSizeLimit,
    'the client record_size_limit reaches the frozen config');
  CheckEquals(512, NewServerBuilder.WithRecordSizeLimit(512).Build.RecordSizeLimit,
    'the server record_size_limit reaches the frozen config');
end;

procedure TTestConfigBuilder.TestRecordSizeLimitRejectsOutOfRange;

  function Refused(ALimit: Int32): Boolean;
  begin
    Result := False;
    try
      NewClientBuilder.WithRecordSizeLimit(ALimit);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  // RFC 8449 4: 64 is the minimum; 16384 is the library's cap, legal under both 1.2 (2^14) and
  // 1.3 (2^14+1); 0 opts out
  CheckTrue(Refused(63), 'a record_size_limit below 64 is refused');
  CheckTrue(Refused(16385), 'a record_size_limit above 16384 is refused');
  CheckFalse(Refused(0), 'a record_size_limit of 0 (opt out) is accepted');
  CheckFalse(Refused(64), 'the 64-byte minimum is accepted');
  CheckFalse(Refused(16384), 'the 16384-byte maximum is accepted');
end;

procedure TTestConfigBuilder.TestRecordSizeLimitCapsRecordsThroughFactory;
var
  LClient, LServer: ITlsEngine;
  LPayload, LWire, LReceived: TBytes;
  LI, LPos, LLen, LMax, LCount: Int32;
begin
  // the builder's record_size_limit must reach the record layer through the factory: both peers
  // advertise 512, so a 2000-byte write fragments into several records none past the plaintext cap
  LClient := TTlsEngineFactory.CreateClientEngine(
    NewClientBuilder.WithRecordSizeLimit(512).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(
    NewServerBuilder.WithRecordSizeLimit(512).Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');

  LPayload := nil;
  SetLength(LPayload, 2000);
  for LI := 0 to System.Length(LPayload) - 1 do
    LPayload[LI] := Byte(LI and $FF);
  LClient.Write(LPayload, 0, System.Length(LPayload));
  LWire := Drain(LClient);

  // walk the TLSCiphertext records (5-byte header + length) the write produced
  LMax := 0;
  LCount := 0;
  LPos := 0;
  while LPos + 5 <= System.Length(LWire) do
  begin
    LLen := (LWire[LPos + 3] shl 8) or LWire[LPos + 4];
    Inc(LCount);
    if LLen > LMax then
      LMax := LLen;
    Inc(LPos, 5 + LLen);
  end;
  // a 512-byte plaintext cap => ciphertext <= 511 content + 1 type + 16 tag = 528
  CheckTrue(LMax <= 528, 'no record exceeds the negotiated cap when set through the builder');
  CheckTrue(LCount > 1, 'the oversize write fragmented into several records');

  Feed(LServer, LWire);
  LReceived := ReadAllApp(LServer);
  CheckEqualBytes('the server reassembles the fragmented payload', LPayload, LReceived);
end;

procedure TTestConfigBuilder.TestPreferredGroupsSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<UInt16>;
begin
  LList := TArray<UInt16>.Create(TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1);
  LConfig := NewClientBuilder.WithPreferredGroups(LList).Build;
  LList[0] := TNamedGroupCatalog.Secp384r1; // mutating the caller's array must not reach the config
  CheckEquals(2, System.Length(LConfig.PreferredGroups), 'the preferred-group list is preserved');
  CheckEquals(TNamedGroupCatalog.X25519, LConfig.PreferredGroups[0],
    'the preferred-group list is a snapshot of the caller array');
end;

procedure TTestConfigBuilder.TestCertificateCompressorsSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<ICertificateCompressor>;
begin
  LList := TZlibCertificateCompression.DefaultCompressors;
  CheckTrue(System.Length(LList) > 0, 'there is at least one default compressor to snapshot');
  LConfig := NewClientBuilder.WithCredential(ServerCredential).Tls13
    .WithCertificateCompressors(LList).Build;
  LList[0] := nil; // mutating the caller's array must not reach the config
  CheckTrue(LConfig.CertificateCompressors[0] <> nil,
    'the compressor list is a snapshot of the caller array');
end;

procedure TTestConfigBuilder.TestCertificateDecompressorsSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<ICertificateDecompressor>;
begin
  LList := TZlibCertificateCompression.DefaultDecompressors;
  CheckTrue(System.Length(LList) > 0, 'there is at least one default decompressor to snapshot');
  LConfig := NewClientBuilder.Tls13.WithCertificateDecompressors(LList).Build;
  LList[0] := nil; // mutating the caller's array must not reach the config
  CheckTrue(LConfig.CertificateDecompressors[0] <> nil,
    'the decompressor list is a snapshot of the caller array');
end;

procedure TTestConfigBuilder.TestRawBuilderWithoutVersionsIsRefusedAtBuild;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
  LMsg: string;
begin
  // a builder that never called WithSupportedVersions cannot build a machine
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  LMsg := '';
  try
    LBuilder.Server
      .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
      .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
      .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
      .WithCredential(ServerCredential)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
    begin
      LRaised := True;
      LMsg := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'a build with no offered versions is refused');
  CheckTrue(Pos('must be offered', LMsg) > 0,
    'the message names the missing offered versions');
end;

procedure TTestConfigBuilder.TestBuilderRejectsMutationAfterBuild;
var
  LClient: ITlsClientConfigBuilder;
  LRaised: Boolean;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LClient.WithServerVerification(
    TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build);
  LClient.Build;
  LRaised := False;
  try
    LClient.WithDangerousDisableServerNameCheck;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a built configuration rejects further mutation');
end;

procedure TTestConfigBuilder.TestSecondBuildIsRejected;
var
  LClient: ITlsClientConfigBuilder;
  LRaised: Boolean;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LClient.WithServerVerification(
    TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build);
  LClient.Build;
  LRaised := False;
  try
    LClient.Build; // a builder is single-use
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a second Build on the same builder is rejected');
end;

procedure TTestConfigBuilder.TestReturnedPinsArrayCannotMutateConfig;
var
  LConfig: ITlsClientConfig;
  LPin, LOther: TBytes;
  LPins: TArray<TBytes>;
begin
  LPin := DecodeHex(
    '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  LOther := DecodeHex(
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithCertificatePinning(TArray<TBytes>.Create(LPin))
    .Build;
  // neither reassigning an element nor mutating an inner byte of the returned array
  // may reach the frozen field (the getter deep-copies)
  LPins := LConfig.CertificatePins;
  LPins[0][0] := LPins[0][0] xor $FF;
  LPins[0] := LOther;
  CheckEqualBytes('the frozen config keeps its pin after the returned array is mutated',
    LPin, LConfig.CertificatePins[0]);
end;

procedure TTestConfigBuilder.TestWithCertificatePinningRejectsWrongLengthPin;
var
  LRaised: Boolean;
begin
  // a pin that is not a 32-byte SHA-256 SubjectPublicKeyInfo digest can never match; the builder
  // refuses it rather than let it silently fail every handshake
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithCertificatePinning(TArray<TBytes>.Create(DecodeHex('00112233')));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-32-byte certificate pin is refused at configuration time');
end;

procedure TTestConfigBuilder.TestClientConfigRequiresTrustStore;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Client.Build; // no trust source set
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client config without a trust source is refused');
end;

function TTestConfigBuilder.MakePskSpec: TExternalPsk;
begin
  Result.Identity := TBytes.Create($61, $62);
  Result.Secret := TSecretBuffer.From(TBytes.Create($00, $11, $22, $33, $44, $55, $66, $77,
    $88, $99, $AA, $BB, $CC, $DD, $EE, $FF));
  Result.Context := nil;
  Result.Hash := THashAlgorithm.SHA_256;
end;

function TTestConfigBuilder.MakePskSpecs(ACount: Int32): TArray<TExternalPsk>;
var
  LI: Int32;
begin
  System.SetLength(Result, ACount);
  for LI := 0 to ACount - 1 do
  begin
    Result[LI] := MakePskSpec;
    Result[LI].Identity := TBytes.Create(Byte(LI shr 8), Byte(LI));
  end;
end;

procedure TTestConfigBuilder.TestPskOnlyClientOfferingTls12IsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // a PSK-only client (no trust source) that still offers TLS 1.2 could be selected onto the
  // certificate path with nothing to verify against - refused at Build
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Client.Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a PSK-only client offering TLS 1.2 is refused');
end;

procedure TTestConfigBuilder.TestPskOnlyClientWithPskOptionalIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // PSK optional + no trust source means a non-PSK ServerHello falls through to the certificate
  // path with nothing to verify - refused at Build
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Client.Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec))
      .WithExternalPskRequired(False).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a PSK-optional client without a trust source is refused');
end;

procedure TTestConfigBuilder.TestPskOnlyTls13ClientBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // a required-PSK, TLS 1.3-only client with no trust source is the legitimate PSK-only case
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
  CheckTrue(LConfig <> nil, 'a required-PSK TLS 1.3-only client builds without a trust source');
end;

procedure TTestConfigBuilder.TestServerConfigRequiresCredential;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Server.Build; // no credential set
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a server config without a credential is refused');
end;

procedure TTestConfigBuilder.TestServerClientAuthRequiresTrustStore;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // requesting client certificates needs a trust source to verify the chain against;
  // absent one, building must fail fast rather than only failing closed at handshake
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .Build; // client auth on, but no trust source set
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client-auth server without a trust source is refused');
end;

procedure TTestConfigBuilder.TestClientEmptyTrustStoreIsRefused;
var
  LMsg: string;
begin
  // a store object is not a trust source; a store with no roots would "verify" against nothing
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(TServerVerification.WebPki(
        TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('no root certificates', LMsg) > 0,
    'an empty trust store is refused as not-a-source; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestClientUnionOfEmptyStoresIsRefused;
var
  LUnion: ITrustAnchorStore;
  LMsg: string;
begin
  // a single union store whose children are all empty still yields zero roots: refused, not hidden
  LUnion := TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore,
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore));
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(TServerVerification.WebPki(LUnion).Build).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('no root certificates', LMsg) > 0,
    'a union of empty stores has no roots and is refused; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestClientEmptyStoreUnionedWithRealRootBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // an empty store adds no roots, but a real root alongside it still satisfies the gate
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(TArray<ITrustAnchorStore>.Create(
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore,
    TTlsLibTestCertificates.EcP256RootStore), nil).Build).Build;
  CheckEquals(1, System.Length(LConfig.TrustStore.RootCertificates),
    'the union carries the one real root; the empty store contributes none');
end;

procedure TTestConfigBuilder.TestClientInsecureSkipVerifyBuildsWithoutTrustStore;
var
  LConfig: ITlsClientConfig;
begin
  // Compatible offers 1.3+1.2 and no PSK, so this also proves PSK-only steering does not misfire
  // for a skip-verify client (its certificate path exists and deliberately verifies nothing)
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.DangerousSkip).Build;
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify, 'the loud skip flag is set');
  CheckNull(LConfig.TrustStore, 'skip-verify composes no anchor store');
end;

procedure TTestConfigBuilder.TestPskClientWithEmptyStoreIsSteeredAsPskOnly;
var
  LRaised: Boolean;
begin
  // an empty store yields no roots, so a PSK client with no real trust is steered PSK-only and
  // refused for offering 1.2 - not left to reach the certificate path with nothing to verify
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(TServerVerification.WebPki(
        TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build)
      .Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a PSK client whose only "trust" is an empty store is steered PSK-only');
end;

procedure TTestConfigBuilder.TestServerClientAuthEmptyTrustStoreIsRefused;
var
  LMsg: string;
begin
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(TClientVerification.WebPki(
        TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('no root certificates', LMsg) > 0,
    'a client-auth server with an empty trust store is refused; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestServerClientAuthInsecureSkipVerifyBuildsWithoutTrustStore;
var
  LConfig: ITlsServerConfig;
begin
  // explicit skip-verify satisfies the client-auth trust-source requirement on its own
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.DangerousSkip).Build;
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify,
    'a client-auth server with skip-verify builds without a trust store');
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithEmptyStoreIsRefused;
var
  LMsg: string;
begin
  // an empty store gives the source nothing to consume: the source message wins over SEmptyTrustStore
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(TClientVerification.VerifierSource(
        TAcceptingClientVerifierSource.Create as IClientCertificateVerifierSource,
        TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('TClientVerification.VerifierSource', LMsg) > 0,
    'a source with an empty store is refused with the source message; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithAnchorsBuilds;
var
  LConfig: ITlsServerConfig;
  LSource: IClientCertificateVerifierSource;
begin
  // the composition promise: a source alongside real anchors builds, and the anchors survive
  LSource := TAcceptingClientVerifierSource.Create as IClientCertificateVerifierSource;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.VerifierSource(LSource,
      TTlsLibTestCertificates.EcP256RootStore).Build)
    .Build;
  CheckTrue(LConfig.ClientVerifierSource = LSource, 'the custom source is installed');
  CheckEquals(1, System.Length(LConfig.TrustStore.RootCertificates),
    'the client-CA anchors survive alongside the source');
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithEmptyStoreAndRealRootBuilds;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.VerifierSource(
      TAcceptingClientVerifierSource.Create as IClientCertificateVerifierSource,
      TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(
        TTrustAnchorStore.Create(nil) as ITrustAnchorStore,
        TTlsLibTestCertificates.EcP256RootStore))).Build).Build;
  CheckEquals(1, System.Length(LConfig.TrustStore.RootCertificates),
    'the union carries the one real root; the empty store contributes none');
end;

function TTestConfigBuilder.WeakClientAnchor: TBytes;
begin
  Result := TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert');
end;

function TTestConfigBuilder.ClientAnchorBuildMessage(AUseSource, AFloors: Boolean;
  const AStore: ITrustAnchorStore): string;
var
  LStrength: TCertificateStrengthPolicy;
  LVerification: IClientVerification;
begin
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 3072;
  LStrength.AnchorKeyFloors := AFloors;
  if AUseSource then
    LVerification := TClientVerification.VerifierSource(
      TAcceptingClientVerifierSource.Create as IClientCertificateVerifierSource, AStore)
      .WithMinimumStrength(LStrength).Build
  else
    LVerification := TClientVerification.WebPki(AStore).WithMinimumStrength(LStrength).Build;
  Result := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(LVerification).Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := E.Message;
  end;
end;

procedure TTestConfigBuilder.TestServerWebPkiRefusesAWeakClientAnchorWithFloorsOn;
begin
  CheckTrue(Pos('AnchorKeyFloors', ClientAnchorBuildMessage(False, True,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(WeakClientAnchor)) as ITrustAnchorStore)) > 0,
    'an RSA-2048 client-CA anchor is below a 3072-bit floor');
end;

procedure TTestConfigBuilder.TestServerVerifierSourceRefusesAWeakClientAnchorWithFloorsOn;
begin
  CheckTrue(Pos('AnchorKeyFloors', ClientAnchorBuildMessage(True, True,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(WeakClientAnchor)) as ITrustAnchorStore)) > 0,
    'the source consumes the same anchors, so it is refused the same way');
end;

procedure TTestConfigBuilder.TestServerBuildsAWeakClientAnchorWithFloorsOff;
begin
  CheckEquals('', ClientAnchorBuildMessage(False, False,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(WeakClientAnchor)) as ITrustAnchorStore),
    'the anchor is exempt while the flag is off');
end;

procedure TTestConfigBuilder.TestServerBuildsAStrongClientAnchorWithFloorsOn;
begin
  CheckEquals('', ClientAnchorBuildMessage(False, True, TTlsLibTestCertificates.EcP256RootStore),
    'a P-256 anchor meets the floors');
end;

procedure TTestConfigBuilder.TestServerBuildsWhenTheWeakClientAnchorIsDistrustedBesideAStrongOne;
var
  LStore: ITrustAnchorStore;
begin
  LStore := TTrustAnchorStore.Create(TArray<TBytes>.Create(WeakClientAnchor,
    TTlsLibTestCertificates.EcP256RootStore.RootCertificates[0]),
    TArray<TBytes>.Create(WeakClientAnchor)) as ITrustAnchorStore;
  CheckEquals('', ClientAnchorBuildMessage(False, True, LStore),
    'a distrusted root is not an anchor, so the floors do not see it');
end;

procedure TTestConfigBuilder.TestServerRefusesAClientAnchorWithAnUndescribableKey;
begin
  CheckTrue(Pos('AnchorKeyFloors', ClientAnchorBuildMessage(False, True,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TTlsLibTestCertificates.Field(
    'Certs/DsaRoot.txt', 'root_cert'))) as ITrustAnchorStore)) > 0,
    'a DSA anchor key has no floor to meet');
end;

procedure TTestConfigBuilder.TestServerMalformedClientAnchorIsReportedBeforeTheFloors;
var
  LMessage: string;
begin
  LMessage := ClientAnchorBuildMessage(False, True, TTrustAnchorStore.Create(
    TArray<TBytes>.Create(TBytes.Create(1, 2, 3))) as ITrustAnchorStore);
  CheckTrue(Pos('anchor 0 of trust store 0', LMessage) > 0,
    'an unparseable anchor gets the malformed-anchor error; got: ' + LMessage);
end;

procedure TTestConfigBuilder.TestClientBuildsWithAWeakRootWhenFloorsAreOn;
var
  LStrength: TCertificateStrengthPolicy;
begin
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 3072;
  LStrength.AnchorKeyFloors := True;
  CheckTrue(TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.WebPki(TTrustAnchorStore.Create(TArray<TBytes>.Create(WeakClientAnchor))
    as ITrustAnchorStore).WithMinimumStrength(LStrength).Build).Build <> nil,
    'a client holds each path to the floors at the handshake, not its roots at Build');
end;

function TTestConfigBuilder.HardWebPkiServer: IServerVerification;
begin
  Result := TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore)
    .WithRevocation(TRevocationPosture.Hard).Build;
end;

function TTestConfigBuilder.HardWebPkiClient: IClientVerification;
begin
  Result := TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore)
    .WithRevocation(TRevocationPosture.Hard).Build;
end;

function TTestConfigBuilder.ServerBuildIsRefused(const ABuilder: ITlsServerConfigBuilder): Boolean;
begin
  Result := False;
  try
    ABuilder.Build;
  except
    // the reason is checked too, so a case cannot pass on some earlier, unrelated refusal
    on E: EInvalidOperationTlsLibException do
      Result := Pos('WithPeerAuth', E.Message) > 0;
  end;
end;

procedure TTestConfigBuilder.TestServerVerifierSourceWithoutPeerAuthIsRefused;
begin
  // client auth is off, so the source would be ignored and clients admitted unauthenticated
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithClientVerification(TClientVerification.VerifierSource(
      TAcceptingClientVerifierSource.Create as IClientCertificateVerifierSource,
      TTlsLibTestCertificates.EcP256RootStore).Build)),
    'a client verifier source without WithPeerAuth is refused');
end;

procedure TTestConfigBuilder.TestServerTrustInputsWithoutPeerAuthAreRefused;
begin
  // each client-certificate trust input is inert on a server that requests no client certificate,
  // so it is refused rather than accepted and ignored
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)),
    'a trust store');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithCertificatePinning(TArray<TBytes>.Create(Crypto.Primitives.GetRandom.GenerateBytes(32)))),
    'a certificate pin');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithCertificateVerifyCallback(RejectEveryChain)),
    'a verify callback');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithClientVerification(TClientVerification.DangerousSkip)),
    'skip-verify on its own');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithClientCertificateAuthorities(
      TArray<TBytes>.Create(Crypto.Primitives.GetRandom.GenerateBytes(16)))),
    'a client-CA list');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithLiveRevocationVerdict(1000)), 'a live verdict');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithAsyncCertificateVerdict(1000)), 'an async verdict');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)),
    'trust anchors given as a certificate');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore)
      .WithIntermediateCertificates(
        TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)),
    'intermediate certificates');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithClientVerification(TClientVerification.Custom(
      TFixedVerdictVerifier.CreateAccepting(False) as IClientCertificateVerifier))),
    'a verifier instance');
  // control: the same trust store builds once the server requests client certificates
  CheckTrue(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithPeerAuth(TClientAuthMode.Requested).Build <> nil, 'control: with WithPeerAuth');
end;

procedure TTestConfigBuilder.TestMtlsServerWithSuppliedTicketKeysRequiresScope;
var
  LRaised: Boolean;
begin
  // a supplied ticket-key manager can be shared across configurations; on a client-auth server
  // that would let a ticket minted under another config's client-CA trust resume here, so a scope
  // is required to partition the tickets
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(
        TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .WithSessionTicketKeys(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client-auth server with supplied ticket keys and no scope is refused');
end;

procedure TTestConfigBuilder.TestEarlyDataWithSuppliedTicketKeysNeedsSharedReplayProtection;
var
  LRaised: Boolean;
  LConfig: ITlsServerConfig;
begin
  // an explicit ticket-key manager can be shared across instances, but the default strike
  // register is per configuration, so a replay against another instance would be accepted
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithSessionTicketKeys(TStekTicketKeyManager.Create(
        Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
      .Tls13.WithEarlyData(16384)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('anti-replay', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'early data on supplied ticket keys with no store or anti-replay is refused');
  // naming the anti-replay strategy explicitly takes responsibility for it
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithSessionTicketKeys(TStekTicketKeyManager.Create(
      Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .Tls13.WithEarlyData(16384)
    .WithAntiReplay(TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy)
    .Build;
  CheckTrue(LConfig <> nil, 'an explicit anti-replay strategy builds');
  // a session store makes tickets single-use, so it is the other safe shape
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithSessionTicketKeys(TStekTicketKeyManager.Create(
      Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .WithSessionStore(TInMemorySessionStore.Create(
      Crypto.Primitives.GetRandom) as ISessionStore)
    .Tls13.WithEarlyData(16384)
    .Build;
  CheckTrue(LConfig <> nil, 'a session store makes explicit ticket keys safe for early data');
end;

procedure TTestConfigBuilder.TestServerEarlyDataBudgetIsCappedAtOneMebibyte;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .Tls13.WithEarlyData(1 shl 20);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  // a full allowance of exactly 1 MiB would fill the engine's app-read buffer and stall the
  // handshake before EndOfEarlyData, so the bound is strict
  CheckTrue(LRaised, 'an early-data budget of 1 MiB or more is refused');
  CheckTrue(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Tls13.WithEarlyData((1 shl 20) - 1).Build <> nil, 'just under 1 MiB builds');
end;

procedure TTestConfigBuilder.TestMtlsServerWithSuppliedKeysAndScopeBuilds;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithSessionTicketKeys(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .WithResumptionScope(TBytes.Create($73, $63, $6F, $70, $65))
    .Build;
  CheckTrue(LConfig <> nil, 'a client-auth server with supplied keys and an explicit scope builds');
end;

procedure TTestConfigBuilder.TestMtlsServerWithDefaultTicketKeysBuildsWithoutScope;
var
  LConfig: ITlsServerConfig;
begin
  // the per-config default STEK is never shared, so an mTLS server that supplies neither a store
  // nor a key manager needs no scope
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Build;
  CheckTrue(LConfig <> nil, 'an mTLS server on the default STEK builds without a scope');
end;

procedure TTestConfigBuilder.TestServerHardClientRevocationWithoutResolverIsRefused;
var
  LRaised: Boolean;
  LMsg: string;
begin
  // a client cannot be asked to staple, so Hard client-cert revocation with no live verdict
  // resolver would reject every client - fail fast at Build
  LRaised := False;
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(HardWebPkiClient)
      .Build; // Hard client-cert revocation, but no async resolver
  except
    on E: EInvalidOperationTlsLibException do
    begin
      LRaised := True;
      LMsg := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'a Hard client-cert-revocation server without a resolver is refused');
  CheckTrue(Pos('resolver', LMsg) > 0,
    'the message names the fix (a live verdict resolver)');
end;

procedure TTestConfigBuilder.TestServerHardClientRevocationWithResolverBuilds;
begin
  // with a live-revocation verdict resolver, Hard client-cert revocation is satisfiable - Build
  // succeeds (a host-decision park would not: it does not defer the revocation gate)
  TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(HardWebPkiClient)
    .WithLiveRevocationVerdict(0)
    .Build;
  Check(True, 'a Hard client-cert-revocation server with a resolver builds');
end;

procedure TTestConfigBuilder.TestServerHardClientRevocationHostDecisionIsRefused;
var
  LRaised: Boolean;
begin
  // a host-decision park does not defer the revocation gate, so it does not satisfy Hard mTLS
  // (only a live-revocation resolver does) - Build must still refuse
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(HardWebPkiClient)
      .WithAsyncCertificateVerdict(0)
      .Build;
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a host-decision park does not satisfy Hard client-cert revocation');
end;

procedure TTestConfigBuilder.TestServerHardRevocationWithoutClientAuthIsRefused;
begin
  // with no client authentication there is no client certificate to check, so a Hard posture
  // would be ignored
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithClientVerification(HardWebPkiClient)),
    'Hard revocation without WithPeerAuth is refused');
end;

procedure TTestConfigBuilder.TestClientHardHostDecisionWithoutStapleIsRefused;
var
  LRaised: Boolean;
begin
  // a Hard client with neither a staple request nor a live-revocation resolver always-rejects;
  // a host-decision park does not defer the revocation gate, so it does not rescue this
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(HardWebPkiServer)
      .WithAsyncCertificateVerdict(0)
      .Build;
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a Hard client with only a host-decision park is refused');
end;

procedure TTestConfigBuilder.TestClientHardLiveRevocationBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // a live-revocation resolver satisfies a Hard client with no staple request, and the frozen
  // config carries the LiveRevocation deferral
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(HardWebPkiServer)
    .WithLiveRevocationVerdict(0)
    .Build;
  CheckEquals(Ord(TVerdictDeferral.LiveRevocation),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'the frozen config carries the live-revocation deferral');
end;

procedure TTestConfigBuilder.TestAsyncVerdictMapsToHostDecision;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithAsyncCertificateVerdict(0)
    .Build;
  CheckEquals(Ord(TVerdictDeferral.HostDecision),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'WithAsyncCertificateVerdict enables the host-decision deferral');
end;

procedure TTestConfigBuilder.TestFacadeDrivesLoopback;
var
  LClient, LServer: ITlsEngine;
  LFromClient: TBytes;
begin
  // build the config once via the facade, then create an engine per connection through the factory
  // the facade is fixed to the portable provider, so the credential's key must come from that provider
  // whatever provider the suite runs under
  LClient := TTlsEngineFactory.CreateClientEngine(
    TTlsLib.NewClientConfig(TTlsLibTestCertificates.EcP256RootStore), 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsLib.NewServerConfig(
    ServerCredential(TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable))));
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the facade client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the facade server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');

  LFromClient := DecodeHex('66616361646520617070206461746121'); // "facade app data!"
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('application data flows over the facade-built connection',
    LFromClient, ReadAllApp(LServer));
end;

procedure TTestConfigBuilder.TestCustomProviderThreadedThroughRawBuilder;
var
  LCustom: ICryptoProvider;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a caller-supplied provider (a distinct ICryptoProvider wrapping the default),
  // the escape hatch the facade points to: pass your own provider to the builder
  LCustom := TFixedAesProvider.Create(Crypto, True) as ICryptoProvider;
  LClientConfig := BuildClientConfig(LCustom);
  LServerConfig := BuildServerConfig(LCustom);

  // the builder threads the exact provider instance into the frozen configs
  CheckTrue(LClientConfig.Crypto = LCustom,
    'the client config carries the caller''s provider');
  CheckTrue(LServerConfig.Crypto = LCustom,
    'the server config carries the caller''s provider');

  // and engines built from those configs complete a handshake end to end
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the custom-provider client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the custom-provider server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
end;

procedure TTestConfigBuilder.TestDefaultCertificateChainLimitsAreConservative;
var
  LConfig: ITlsClientConfig;
  LLimits: TCertificateChainLimits;
begin
  // an untuned client config carries the conservative web-PKI defaults
  LConfig := BuildClientConfig(Crypto);
  LLimits := LConfig.CertificateChainLimits;
  CheckEquals(1 shl 16, LLimits.MaxCertificateLength, 'default max certificate length');
  CheckEquals(1 shl 16, LLimits.MaxTotalChainLength, 'default max certificate message length');
end;

procedure TTestConfigBuilder.TestCertificateChainLimitsAreConfigurable;
var
  LBuilder: ITlsConfigBuilder;
  LConfig: ITlsClientConfig;
  LCustom, LFrozen: TCertificateChainLimits;
begin
  // a caller can tune the caps; the frozen config carries the tuned values
  LCustom := TCertificateChainLimits.Defaults;
  LCustom.MaxCertificateLength := 1 shl 17;
  LCustom.MaxTotalChainLength := 1 shl 20;
  LCustom.MaxChainCertificates := 32;
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithCertificateChainLimits(LCustom)
    .Build;
  LFrozen := LConfig.CertificateChainLimits;
  CheckEquals(1 shl 17, LFrozen.MaxCertificateLength, 'the tuned certificate length');
  CheckEquals(1 shl 20, LFrozen.MaxTotalChainLength, 'the tuned total chain length');
  CheckEquals(32, LFrozen.MaxChainCertificates, 'the tuned chain entry count');
end;

function TTestConfigBuilder.ChainLimitsAccepted(AMaxCert,
  AMaxTotal: Int32): Boolean;
var
  LLimits: TCertificateChainLimits;
  LBuilder: ITlsConfigBuilder;
begin
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxCertificateLength := AMaxCert;
  LLimits.MaxTotalChainLength := AMaxTotal;
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  Result := True;
  try
    LBuilder.Client.WithCertificateChainLimits(LLimits);
  except
    on E: EArgumentTlsLibException do
      Result := False;
  end;
end;

procedure TTestConfigBuilder.TestInvalidChainEntryCapRejected;

  function Accepted(ACap: Int32): Boolean;
  var
    LLimits: TCertificateChainLimits;
  begin
    LLimits := TCertificateChainLimits.Defaults;
    LLimits.MaxChainCertificates := ACap;
    Result := True;
    try
      TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default)
        .Client.WithCertificateChainLimits(LLimits);
    except
      on E: EArgumentTlsLibException do
        Result := False;
    end;
  end;

begin
  CheckTrue(Accepted(16), 'the default entry cap is accepted');
  CheckTrue(Accepted(1), 'a single-entry cap is accepted');
  CheckTrue(Accepted(255), 'the largest entry cap is accepted');
  CheckFalse(Accepted(0), 'a zero entry cap is rejected');
  CheckFalse(Accepted(256), 'an entry cap above 255 is rejected');
end;

procedure TTestConfigBuilder.TestContradictoryStrengthFloorsRejected;

  function Accepted(AMin, AMax: Int32): Boolean;
  var
    LPolicy: TCertificateStrengthPolicy;
  begin
    LPolicy := TCertificateStrengthPolicy.Defaults;
    LPolicy.MinRsaModulusBits := AMin;
    LPolicy.MaxRsaModulusBits := AMax;
    Result := True;
    try
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore)
        .WithMinimumStrength(LPolicy);
    except
      on E: EArgumentTlsLibException do
        Result := False;
    end;
  end;

begin
  CheckTrue(Accepted(2048, 8192), 'the default floors are accepted');
  CheckTrue(Accepted(3072, 0), 'no maximum is accepted');
  CheckTrue(Accepted(4096, 4096), 'equal floors are accepted');
  CheckFalse(Accepted(0, 8192), 'a non-positive minimum is rejected');
  CheckFalse(Accepted(4096, 2048), 'a maximum below the minimum is rejected');
end;

procedure TTestConfigBuilder.TestInvalidCertificateChainLimitsRejected;
begin
  // a byte budget is validated at build time: broken limits are a misconfiguration
  CheckTrue(ChainLimitsAccepted(1 shl 15, 1 shl 16), 'valid limits are accepted');
  CheckFalse(ChainLimitsAccepted(0, 1 shl 16), 'a non-positive per-certificate cap is rejected');
  CheckFalse(ChainLimitsAccepted(1 shl 15, 0), 'a non-positive message cap is rejected');
  CheckFalse(ChainLimitsAccepted(1 shl 17, 1 shl 16),
    'a per-certificate cap above the message cap is rejected');
  CheckFalse(ChainLimitsAccepted($1000000, $1000000),
    'a message cap past the 16 MiB handshake ceiling is rejected');
end;

function TTestConfigBuilder.DefaultProfile: TTlsConfigProfile;
begin
  Result := TTlsConfigProfile.Default;
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  Result.SignatureSchemes := TSignatureSchemeRegistry.CreateDefault;
  Result.NamedGroups := TNamedGroups.CreateDefaultRegistry(Crypto);
  Result.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
  Result.PreferredGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
end;

function TTestConfigBuilder.SameOrder(const AA, AB: TArray<UInt16>): Boolean;
var
  LI: Int32;
begin
  Result := System.Length(AA) = System.Length(AB);
  if Result then
    for LI := 0 to System.High(AA) do
      if AA[LI] <> AB[LI] then
        Exit(False);
end;

function TTestConfigBuilder.NewBareClientBuilder: ITlsClientConfigBuilder;
var
  LOwner: ITlsConfigBuilder;
begin
  // a chooser seeded with the shared defaults, narrowed to the client view
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  Result := LOwner.Client;
end;

function TTestConfigBuilder.NewClientBuilder: ITlsClientConfigBuilder;
begin
  Result := NewBareClientBuilder
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build);
end;

function TTestConfigBuilder.NewServerBuilder: ITlsServerConfigBuilder;
var
  LOwner: ITlsConfigBuilder;
begin
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  Result := LOwner.Server.WithCredential(ServerCredential);
end;

procedure TTestConfigBuilder.TestTls13CompressorOverrideLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
  LEmptyComp: TArray<ICertificateCompressor>;
  LEmptyDecomp: TArray<ICertificateDecompressor>;
begin
  // the default carries a compressor; clearing the 1.3 knobs must empty the read side
  LConfig := BuildClientConfig(Crypto);
  CheckTrue(System.Length(LConfig.CertificateCompressors) > 0,
    'the default config carries a compressor');
  CheckTrue(System.Length(LConfig.CertificateDecompressors) > 0,
    'the default config carries a decompressor');

  LEmptyComp := nil;
  LEmptyDecomp := nil;
  LConfig := NewClientBuilder.Tls13
    .WithCertificateCompressors(LEmptyComp)
    .WithCertificateDecompressors(LEmptyDecomp)
    .Build;
  CheckEquals(0, System.Length(LConfig.CertificateCompressors),
    'the .Tls13 compressor override lands in the frozen config');
  CheckEquals(0, System.Length(LConfig.CertificateDecompressors),
    'the .Tls13 decompressor override lands in the frozen config');
end;

procedure TTestConfigBuilder.TestClientBuilderChainBuildsClient;
var
  LConfig: ITlsClientConfig;
begin
  // the client builder chained into the .Tls13 facet, built off the facet
  LConfig := NewClientBuilder.WithCredential(ServerCredential).Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors)
    .WithCertificateDecompressors(TZlibCertificateCompression.DefaultDecompressors)
    .Build;
  CheckTrue(LConfig <> nil, 'the client chain builds a client config');
  CheckEquals(TlsWireVersionTls13, LConfig.SupportedVersions[0],
    'the client is TLS 1.3');
  CheckTrue(System.Length(LConfig.CertificateCompressors) > 0,
    'the chained compressors reach the frozen config');
end;

procedure TTestConfigBuilder.TestServerBuilderChainBuildsServer;
var
  LConfig: ITlsServerConfig;
begin
  // both versions offered, then cross from the .Tls13 facet into .Tls12 and build
  LConfig := NewServerBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12))
    .Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors)
    .Tls12
    .WithExtendedMasterSecret(True)
    .Build;
  CheckTrue(LConfig <> nil, 'the cross-version chain builds a server config');
  CheckEquals(TlsWireVersionTls13, LConfig.SupportedVersions[0],
    'the server offers TLS 1.3 first');
  CheckTrue(LConfig.RequireExtendedMasterSecret,
    'the .Tls12 knob reaches the frozen config');
end;

procedure TTestConfigBuilder.TestVersionFacetForUnofferedVersionIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // configuring a TLS 1.2-only setting on a config that does not offer TLS 1.2 must be
  // refused at build rather than silently ignored - the setting could never apply
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Server
      .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
      .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
      .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
      .WithCredential(ServerCredential)
      .Tls12.WithExtendedMasterSecret(True)
      .Build; // TLS 1.2 configured but only TLS 1.3 offered
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a version facet for an unoffered version is refused at build');
end;

procedure TTestConfigBuilder.TestNonEmsResumptionReachesFrozenConfig;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := NewServerBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .Tls12.WithNonEmsResumption(TNonEmsResumption.Resume).Build;
  CheckEquals(Ord(TNonEmsResumption.Resume), Ord(LConfig.NonEmsResumption),
    'the .Tls12 policy reaches the frozen config');
end;

procedure TTestConfigBuilder.TestNonEmsResumptionOnTls13OnlyIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewServerBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .Tls12.WithNonEmsResumption(TNonEmsResumption.Abort).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a TLS 1.2 resumption policy on a TLS 1.3-only server is refused at build');
end;

procedure TTestConfigBuilder.TestRequiredEmsWithNonEmsResumeIsRefused;

  function Builds(AMode: TNonEmsResumption): Boolean;
  begin
    Result := True;
    try
      NewServerBuilder.WithSupportedVersions(
        TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
        .Tls12.WithExtendedMasterSecret(True).WithNonEmsResumption(AMode).Build;
    except
      on E: EInvalidOperationTlsLibException do
        Result := False;
    end;
  end;

begin
  // requiring EMS rejects every non-EMS client, so no non-EMS resumption mode other than the
  // default could ever apply
  CheckFalse(Builds(TNonEmsResumption.Resume), 'required EMS with legacy resumption contradicts itself');
  CheckFalse(Builds(TNonEmsResumption.Abort), 'required EMS with Abort contradicts itself');
  CheckTrue(Builds(TNonEmsResumption.Decline), 'required EMS with Decline builds');
end;

procedure TTestConfigBuilder.TestDefaultRevocationPostureIsSoft;
begin
  CheckEquals(Ord(TRevocationPosture.Soft),
    Ord(BuildClientConfig(Crypto).RevocationPosture),
    'the default revocation posture is soft-fail');
end;

procedure TTestConfigBuilder.TestWithRevocationSetsHardPosture;
var
  LConfig: ITlsClientConfig;
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithServerVerification(HardWebPkiServer)
    // Hard requires a way to obtain revocation status, else Build rejects it as always-rejecting;
    // pairing it with a stapling request is the minimal usable configuration
    .WithOcspStaplingRequest(True)
    .Build;
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LConfig.RevocationPosture),
    'WithRevocation sets the frozen posture');
end;

procedure TTestConfigBuilder.TestWithCertificatePinningLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
  LBuilder: ITlsConfigBuilder;
  LPin: TBytes;
begin
  LPin := DecodeHex(
    '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithCertificatePinning(TArray<TBytes>.Create(LPin))
    .Build;
  CheckEquals(1, System.Length(LConfig.CertificatePins), 'one pin is stored');
  CheckEqualBytes('the pin round-trips into the frozen config', LPin,
    LConfig.CertificatePins[0]);
end;

procedure TTestConfigBuilder.TestServerWithOcspStapleLandsInFrozenConfig;
var
  LConfig: ITlsServerConfig;
  LBuilder: ITlsConfigBuilder;
  LCredential: TTlsCredential;
  LStaple: TBytes;
begin
  // a staple set on the credential rides through the builder into the frozen config
  LStaple := TBytes.Create($30, $03, $0A, $01, $00);
  LCredential := ServerCredential;
  LCredential.OcspStaple := LStaple;
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(LCredential)
    .Build;
  CheckEqualBytes('the staple round-trips into the frozen config credential', LStaple,
    LConfig.Credential.OcspStaple);
end;

procedure TTestConfigBuilder.TestLoadedCredentialReplacesPriorStaple;
var
  LConfig: ITlsServerConfig;
  LBuilder: ITlsConfigBuilder;
  LStapled: TTlsCredential;
begin
  // a later WithCredential replaces the whole credential (last call wins), and a credential from
  // TTlsCredential.Load is staple-free - so a prior WithCredential's staple cannot bleed through
  LStapled := ServerCredential;
  LStapled.OcspStaple := TBytes.Create($30, $03, $0A, $01, $00);
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(LStapled)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
    DecodeHex(FCerts.Values['leaf_cert']), DecodeHex(FCerts.Values['leaf_key'])))
    .Build;
  CheckEquals(0, System.Length(LConfig.Credential.OcspStaple),
    'the loaded credential cleared the prior staple');
end;

procedure TTestConfigBuilder.TestLoadedCredentialBuildsServer;
var
  LConfig: ITlsServerConfig;
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LConfig := LBuilder.Server.WithCredential(TTlsCredential.Load(Crypto, Pkix,
    DecodeHex(FCerts.Values['leaf_cert']), DecodeHex(FCerts.Values['leaf_key']))).Build;
  CheckEquals(1, System.Length(LConfig.Credential.CertificateChain),
    'the loaded credential freezes its leaf into the config');
end;

procedure TTestConfigBuilder.TestServerCredentialWithMismatchedKeyRejected;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // same key family (EC P-256), different key: the leaf does not belong to the private key
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(CredentialWithForeignKey('ec256_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a credential whose key does not own its leaf is refused at Build');
end;

procedure TTestConfigBuilder.TestServerCredentialWithWrongKeyFamilyRejected;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // an RSA key against an EC leaf: the key-family mismatch surfaces as a wrong-leaf refusal
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(CredentialWithForeignKey('rsa_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a credential whose key family differs from its leaf is refused at Build');
end;

procedure TTestConfigBuilder.TestIncompleteCredentialsAreRefusedAtBuild;
var
  LBuilder: ITlsConfigBuilder;
  LNoChain, LNoKey: TTlsCredential;
  LRaised: Boolean;
begin
  LNoChain := ServerCredential;
  LNoChain.CertificateChain := nil;
  LNoKey := ServerCredential;
  LNoKey.PrivateKey := nil;

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(LNoChain).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('leaf certificate', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a server credential with an empty chain is refused for its chain');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(LNoKey).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('private key', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a server credential without a key is refused for its key');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithSniCredential('localhost', LNoKey).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an SNI-mapped credential without a key is refused');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .WithCredential(LNoKey).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('private key', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a client chain without its key is refused');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .WithCredential(LNoChain).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('leaf certificate', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a client credential with a key but no chain is refused');
end;

procedure TTestConfigBuilder.TestMalformedLeafCredentialIsRefusedAtBuild;
var
  LCredential: TTlsCredential;
  LBuilder: ITlsConfigBuilder;
  LMessage: string;
begin
  LCredential := ServerCredential;
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TArray<Byte>.Create($30, $03, $01, $01, $00));
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LMessage := '';
  try
    LBuilder.Server.WithCredential(LCredential).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMessage := E.Message;
  end;
  CheckTrue(Pos('cannot be parsed', LMessage) > 0, 'a leaf that does not parse is named as such');
end;

function TTestConfigBuilder.NonCatalogSuiteRegistry: ICipherSuiteRegistry;
var
  LSuites: TArray<TTlsCipherSuite>;
begin
  LSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto).Items;
  LSuites[0].Common.Hash := THashAlgorithm.SHA_384;
  Result := TFakeSuiteRegistry.Create(LSuites) as ICipherSuiteRegistry;
end;

procedure TTestConfigBuilder.TestServerCustomSuiteRegistryWithNonCatalogRecordRefused;
var
  LRegistry: ICipherSuiteRegistry;
  LMessage: string;
begin
  LRegistry := NonCatalogSuiteRegistry;
  LMessage := '';
  try
    NewServerBuilder.WithCipherSuites(LRegistry).Build;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckTrue(Pos('differs from the catalog', LMessage) > 0,
    'a host registry holding a record the catalog defines otherwise is refused');
  CheckTrue(Pos('0x' + IntToHex(LRegistry.Items[0].Common.Code, 4), LMessage) > 0,
    'the refusal names the record');
end;

procedure TTestConfigBuilder.TestClientCustomSuiteRegistryWithNonCatalogRecordRefused;
var
  LRegistry: ICipherSuiteRegistry;
  LMessage: string;
begin
  LRegistry := NonCatalogSuiteRegistry;
  LMessage := '';
  try
    NewClientBuilder.WithCipherSuites(LRegistry).Build;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckTrue(Pos('differs from the catalog', LMessage) > 0,
    'a host registry holding a record the catalog defines otherwise is refused');
  CheckTrue(Pos('0x' + IntToHex(LRegistry.Items[0].Common.Code, 4), LMessage) > 0,
    'the refusal names the record');
end;

procedure TTestConfigBuilder.TestClientCustomSuiteRegistryOfCatalogRecordsBuilds;
begin
  CheckNotNull(NewClientBuilder.WithCipherSuites(TFakeSuiteRegistry.Create(
    TCipherSuiteRegistry.CreateDualVersion(Crypto).Items) as ICipherSuiteRegistry).Build,
    'the refusal case''s suites with the record as the catalog defines it build');
end;

procedure TTestConfigBuilder.TestCustomSuiteRegistryWithNonCatalogRecordInListRefused;
var
  LRegistry: ICipherSuiteRegistry;
  LMessage: string;
begin
  LRegistry := NonCatalogSuiteRegistry;
  LMessage := '';
  try
    NewServerBuilder.WithCipherSuites(LRegistry).WithCipherSuiteList(
      TArray<UInt16>.Create(LRegistry.Items[0].Common.Code)).Build;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckTrue(Pos('differs from the catalog', LMessage) > 0,
    'a list over a host registry holding such a record is refused');
end;

procedure TTestConfigBuilder.TestCustomSuiteRegistryWithNonCatalogRecordBesideTls12PskRefused;
var
  LPsk: TTls12Psk;
  LMessage: string;
begin
  LPsk.Identity := TBytes.Create($61, $62);
  LPsk.Secret := TSecretBuffer.From(TBytes.Create($00, $11, $22, $33, $44, $55, $66, $77,
    $88, $99, $AA, $BB, $CC, $DD, $EE, $FF));
  LMessage := '';
  try
    NewServerBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
      .WithCipherSuites(NonCatalogSuiteRegistry).Tls12.WithPreSharedKeys(
      TArray<TTls12Psk>.Create(LPsk)).Build;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckTrue(Pos('differs from the catalog', LMessage) > 0,
    'the suites joined for a TLS 1.2 PSK are checked too');
end;

procedure TTestConfigBuilder.TestCustomSuiteRegistryOfCatalogRecordsBuilds;
var
  LSuites: TArray<TTlsCipherSuite>;
  LUnknown: TTlsCipherSuite;
  LConfig: ITlsServerConfig;
begin
  LSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto).Items;
  LUnknown := LSuites[0];
  LUnknown.Common.Code := $C013;
  TArrayUtilities.Append<TTlsCipherSuite>(LSuites, LUnknown);
  LConfig := NewServerBuilder.WithCipherSuites(
    TFakeSuiteRegistry.Create(LSuites) as ICipherSuiteRegistry).Build;
  CheckEquals(System.Length(LSuites), System.Length(LConfig.CipherSuites.Items),
    'catalog records and a code the catalog does not know pass through');
end;

procedure TTestConfigBuilder.TestMalformedTrustAnchorIsRefusedAtBuild;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // one junk entry in an otherwise valid store would fail every verification against it
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithServerVerification(TServerVerification.WebPki(TTrustAnchorStore.Create(
      TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']), TBytes.Create(1, 2, 3)))
      as ITrustAnchorStore).Build).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('anchor 1 of trust store 0', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a store with an unparsable root is refused, naming it');
  // control: the same store without the junk entry builds
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  CheckTrue(LBuilder.Client.WithServerVerification(
    TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build <> nil,
    'a valid store builds');
end;

procedure TTestConfigBuilder.TestSniCredentialWithMismatchedKeyNamesHost;
var
  LBuilder: ITlsConfigBuilder;
  LMsg: string;
begin
  // the leaf covers "localhost" (SAN), so coverage passes and the key/leaf guard is what trips;
  // the error must name the offending host
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LMsg := '';
  try
    LBuilder.Server.WithSniCredential('localhost',
      CredentialWithForeignKey('ec256_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('localhost', LMsg) > 0,
    'an inconsistent SNI credential is refused and the error names its host');
end;

procedure TTestConfigBuilder.TestClientCredentialWithMismatchedKeyRejected;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // a client-authentication credential is guarded on the client build path too
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .WithCredential(CredentialWithForeignKey('ec256_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client credential whose key does not own its leaf is refused at Build');
end;

procedure TTestConfigBuilder.TestMatchingCredentialBuildsServer;
var
  LConfig: ITlsServerConfig;
begin
  // the guard does not false-positive: a genuine leaf+key pair builds
  LConfig := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile)
    .Server.WithCredential(ServerCredential).Build;
  CheckTrue(LConfig <> nil, 'a consistent credential builds');
end;

procedure TTestConfigBuilder.TestTicketLifetimeAboveCapIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LRaised := False;
  try
    LServer.WithTicketLifetime(604801); // one second over the RFC 9846 4.7.1 ceiling
  except
    on E: EArgumentTlsLibException do
      LRaised := Pos('604800', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a ticket lifetime above 604800 seconds is an argument error');
end;

procedure TTestConfigBuilder.TestTicketLifetimeAtCapIsAccepted;
var
  LConfig: ITlsServerConfig;
begin
  // the boundary value is legal; only a strictly-greater lifetime is refused
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithTicketLifetime(604800)
    .Build;
  CheckNotNull(LConfig, 'the boundary ticket lifetime (604800) is accepted');
end;

procedure TTestConfigBuilder.TestPublishedLimitsKeepTheirValues;
begin
  CheckEquals(7200, Integer(TTlsConfigBuilder.DefaultTicketLifetimeSeconds),
    'default ticket lifetime');
  CheckEquals(32, Integer(TTlsConfigBuilder.MaxResumptionScopeLength), 'longest scope');
end;

procedure TTestConfigBuilder.TestServerConfigCarriesTheDefaultTicketLifetime;
begin
  CheckEquals(TTlsConfigBuilder.DefaultTicketLifetimeSeconds,
    TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(ServerCredential).Build
    .TicketLifetimeSeconds, 'a server config that never set a lifetime carries the default');
end;

procedure TTestConfigBuilder.TestResumptionScopeAboveCapIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LScope: TBytes;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LScope := nil;
  SetLength(LScope, TTlsConfigBuilder.MaxResumptionScopeLength + 1);
  LRaised := False;
  try
    LServer.WithResumptionScope(LScope);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a resumption scope above 32 bytes is rejected');
end;

procedure TTestConfigBuilder.TestResumptionScopeAtCapIsAccepted;
var
  LConfig: ITlsServerConfig;
  LScope: TBytes;
begin
  LScope := nil;
  SetLength(LScope, TTlsConfigBuilder.MaxResumptionScopeLength);
  FillChar(LScope[0], System.Length(LScope), $5C);
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithResumptionScope(LScope)
    .Build;
  CheckEqualBytes('the boundary resumption scope (32 bytes) round-trips', LScope,
    LConfig.ResumptionScope);
end;

procedure TTestConfigBuilder.TestClientResumptionScopeAboveCapIsRejected;
var
  LClient: ITlsClientConfigBuilder;
  LScope: TBytes;
  LRaised: Boolean;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LScope := nil;
  SetLength(LScope, TTlsConfigBuilder.MaxResumptionScopeLength + 1);
  LRaised := False;
  try
    LClient.WithResumptionScope(LScope);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client resumption scope above 32 bytes is rejected');
end;

procedure TTestConfigBuilder.TestClientResumptionScopeAtCapRoundTrips;
var
  LConfig: ITlsClientConfig;
  LScope: TBytes;
begin
  LScope := nil;
  SetLength(LScope, TTlsConfigBuilder.MaxResumptionScopeLength);
  FillChar(LScope[0], System.Length(LScope), $5C);
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumptionScope(LScope)
    .Build;
  CheckEqualBytes('the boundary client resumption scope (32 bytes) round-trips', LScope,
    LConfig.SessionScope);
end;

procedure TTestConfigBuilder.TestClientResumptionScopeIsOrderInsensitive;
var
  LConfig: ITlsClientConfig;
  LScope: TBytes;
begin
  LScope := nil;
  SetLength(LScope, 8);
  FillChar(LScope[0], 8, $2A);
  // set the scope BEFORE the cache: the two setters are order-insensitive, so the pinned scope
  // survives (the cache setter leaves it alone)
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumptionScope(LScope)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .Build;
  CheckEqualBytes('the pinned scope survives a later WithSessionCache', LScope,
    LConfig.SessionScope);
end;

procedure TTestConfigBuilder.TestTicketCountAboveCapIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LRaised := False;
  try
    LServer.Tls13.WithTicketCount(9); // one over the cap
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a ticket count above 8 is rejected');
end;

procedure TTestConfigBuilder.TestTicketCountNegativeIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LRaised := False;
  try
    LServer.Tls13.WithTicketCount(-1);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a negative ticket count is rejected');
end;

procedure TTestConfigBuilder.TestTicketCountAtCapIsAccepted;
var
  LConfig: ITlsServerConfig;
begin
  // the boundary value is legal; only a strictly-greater count is refused
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Tls13.WithTicketCount(8)
    .Build;
  CheckEquals(8, LConfig.TicketCount, 'the boundary ticket count (8) round-trips');
end;

procedure TTestConfigBuilder.TestServerEarlyDataMintsSharedAntiReplayDefault;
var
  LNoEarly, LWithEarly: ITlsServerConfig;
begin
  LNoEarly := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Build;
  CheckFalse(Assigned(LNoEarly.AntiReplay),
    'a server without 0-RTT mints no anti-replay register');
  LWithEarly := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Tls13.WithEarlyData(16384)
    .Build;
  CheckTrue(Assigned(LWithEarly.AntiReplay),
    'a server authorizing 0-RTT mints a default anti-replay register at Build');
end;

procedure TTestConfigBuilder.TestServerRejectsPublicSuffixSniWildcard;
var
  LBuilder: ITlsServerConfigBuilder;
  LMsg: string;
begin
  // a public-suffix wildcard (*.com) can never match a host at runtime, so it is rejected as an
  // SNI pattern at configuration - the same rule name verification enforces
  LBuilder := NewServerBuilder.WithSniCredential('*.com', ServerCredential);
  LMsg := '';
  try
    LBuilder.Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('is not a supported wildcard', LMsg) > 0,
    'a *.com SNI wildcard is refused as a malformed wildcard; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestServerSniWildcardUnderRegistrableDomainPassesTheWildcardGate;
var
  LBuilder: ITlsServerConfigBuilder;
  LMsg: string;
begin
  // control: *.example.com clears the wildcard gate and fails only on SAN coverage
  LBuilder := NewServerBuilder.WithSniCredential('*.example.com', ServerCredential);
  LMsg := '';
  try
    LBuilder.Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('does not cover it', LMsg) > 0,
    'a *.example.com SNI wildcard is refused only for SAN coverage; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestClassicalRegistryOverPresetNegotiatesClassical;
var
  LClient, LServer: ITlsEngine;
  LClientInfo, LServerInfo: TTlsConnectionInfo;
begin
  // Hardened prefers X25519MLKEM768 first; installing the classical-only registry prunes it.
  // Before the registry became authoritative this raised at engine creation (preferred group not
  // in the registry); now the hybrid is dropped from the offer and X25519 is negotiated instead.
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Crypto))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Crypto))
    .WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  LClientInfo := LClient.ConnectionInfo;
  LServerInfo := LServer.ConnectionInfo;
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClientInfo.NamedGroup),
    'negotiated classical X25519, not the pruned post-quantum hybrid');
  CheckEquals(Integer(LClientInfo.NamedGroup), Integer(LServerInfo.NamedGroup),
    'client and server agree on the negotiated group');
end;

procedure TTestConfigBuilder.TestClassicalRegistryClientAgainstDefaultServer;
var
  LClient, LServer: ITlsEngine;
begin
  // the client's registry is classical-only, so its supported_groups carries no hybrid; the server
  // keeps the default registry and prefers the hybrid, but cannot select or retry onto a group the
  // client never offered. Both settle on X25519 with no fatal - the case the OfferedGroups filter,
  // not the PreferredGroup fix, protects.
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Crypto))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not fail (no retry into a pruned group)');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClient.ConnectionInfo.NamedGroup),
    'negotiated classical X25519 though the server prefers the hybrid');
end;

procedure TTestConfigBuilder.TestServerWithEmptyGroupIntersectionFailsFast;
var
  LReg: INamedGroupRegistryBuilder;
  LRaised: Boolean;
begin
  // Hardened prefers the hybrid, X25519 and secp256r1; prune the classical registry down to
  // secp384r1 (which Hardened does not prefer), leaving the registry-vs-preference intersection
  // empty. The server must refuse at creation rather than build with an empty offer and fault on
  // the first ClientHello.
  LReg := TNamedGroups.CreateClassicalRegistry(Crypto).ToBuilder;
  LReg.Prune(TNamedGroupCatalog.X25519);
  LReg.Prune(TNamedGroupCatalog.Secp256r1);
  LReg.Prune(TNamedGroupCatalog.Secp521r1);
  LRaised := False;
  try
    TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
      .WithNamedGroups(LReg.Build).WithCredential(ServerCredential).Build);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a server with an empty registry-vs-preference intersection is refused');
end;

procedure TTestConfigBuilder.TestRoleConfigDefaultsForMovedAccessors;
var
  LClient: ITlsClientConfig;
  LServer: ITlsServerConfig;
begin
  // the server-name / cipher-order / ALPN-reject knobs live only on the server config now, and
  // GREASE only on the client config; each surfaces its builder default off the role config
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build;
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  CheckTrue(LServer.ServerNameAcknowledgement, 'a server acknowledges SNI by default');
  CheckEquals(Ord(TServerCipherPreference.ServerOrder), Ord(LServer.CipherSuitePreference),
    'a server imposes its own cipher order by default');
  CheckFalse(LServer.AlpnRejectAll, 'a server does not reject ALPN unconditionally by default');
  CheckEquals(Ord(TNonEmsResumption.Decline), Ord(LServer.NonEmsResumption),
    'a TLS 1.2 server declines non-EMS resumption by default');
  CheckTrue(LClient.Grease, 'a client greases by default');
  CheckEquals(Ord(TServerNameIndication.Send), Ord(LClient.ServerNameIndication),
    'a client sends SNI by default');
end;

function TTestConfigBuilder.OmitSniClient(const AVersions: TArray<UInt16>): ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(AVersions)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithServerNameIndication(TServerNameIndication.Omit).Build;
end;

function TTestConfigBuilder.RejectEveryChain(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := False;
end;

procedure TTestConfigBuilder.TestTls13ReportsExtendedMasterSecret;
var
  LClient, LServer: ITlsEngine;
begin
  // TLS 1.3 binds every secret to the full transcript (RFC 9846 7.1), so the library reports EMS
  // as in use, including a dual-version client that settles on 1.3
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder.Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the handshake completed');
  CheckTrue(LClient.ConnectionInfo.ExtendedMasterSecret, 'the TLS 1.3 client reports EMS');
  CheckTrue(LServer.ConnectionInfo.ExtendedMasterSecret, 'and the server');
end;

procedure TTestConfigBuilder.TestVerifyCallbackRunsOverInstanceVerifier;
var
  LClient, LServer: ITlsEngine;
begin
  // the callback is the host's own reject rule: it must still run when the whole verifier is a
  // caller-supplied instance that accepts everything
  LClient := TTlsEngineFactory.CreateClientEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithServerVerification(TServerVerification.Custom(
      TFixedVerdictVerifier.CreateAccepting(False) as IServerCertificateVerifier))
    .WithCertificateVerifyCallback(RejectEveryChain).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the callback rejected a chain the instance accepted');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown),
    Ord(LClient.LastError.Alert.Description), 'the alert is certificate_unknown');
end;

procedure TTestConfigBuilder.TestServerNameIndicationOmitReachesConfig;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls13));
  CheckEquals(Ord(TServerNameIndication.Omit), Ord(LConfig.ServerNameIndication),
    'the builder choice reaches the frozen config');
  CheckTrue(LConfig.CheckServerName, 'omitting SNI leaves the name check on');
end;

procedure TTestConfigBuilder.TestOmittedSniSendsNoServerNameAndStillVerifiesHost;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
  LMsg: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(
    OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls13)), 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  LClient.StartHandshake;
  LFlight := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
  CheckTrue(LExts.Count > 0, 'the flight carries a ClientHello');
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry), 'no server_name extension');
  CheckFalse(ContainsAscii(LFlight, 'localhost'),
    'the host does not appear on the wire');
  Feed(LServer, LFlight);
  ExchangeFlights(LClient, LServer);
  // completion proves the leaf was still checked against the host: it matches only localhost
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not abort');
  CheckFalse(LServer.IsTerminal, 'the server did not abort');
  CheckEquals('', LServer.ConnectionInfo.ServerName, 'the server saw no SNI');
  LMsg := DecodeHex('736e692d6f6d6974'); // "sni-omit"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('app data flows without SNI', LMsg, ReadAllApp(LServer));
end;

procedure TTestConfigBuilder.TestOmittedSniStillRejectsWrongHost;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(
    OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls13)), 'wrong.example');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  LClient.StartHandshake;
  LFlight := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry), 'no server_name extension');
  Feed(LServer, LFlight);
  ExchangeFlights(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'omitting SNI is not a name-check bypass: the client aborts');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(LClient.LastError.Alert.Description), 'the alert is bad_certificate');
end;

procedure TTestConfigBuilder.TestOmittedSniTls12SendsNoServerName;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(
    OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls12)), 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  LClient.StartHandshake;
  LFlight := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
  CheckTrue(LExts.Count > 0, 'the flight carries a ClientHello');
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry), 'no server_name in the 1.2 hello');
  Feed(LServer, LFlight);
  ExchangeFlights(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the TLS 1.2 handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not abort: ' + LClient.LastError.Message);
  CheckEquals(Integer(TlsWireVersionTls12), Integer(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
    'TLS 1.2 was negotiated');
end;

procedure TTestConfigBuilder.TestOmittedSniHrrRetryKeepsServerNameAbsent;
var
  LClient, LServer: ITlsEngine;
  LCh1, LCh2: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  // the server prefers a group the client did not send a key share for, forcing a HelloRetryRequest
  LClient := TTlsEngineFactory.CreateClientEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithServerNameIndication(TServerNameIndication.Omit).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1))
    .WithCredential(ServerCredential).Build);
  LClient.StartHandshake;
  LCh1 := Drain(LClient);
  Feed(LServer, LCh1);
  Pump(LServer, LClient);
  LCh2 := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LCh2);
  CheckTrue(LExts.Count > 0, 'the retry flight carries a ClientHello');
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry),
    'the second ClientHello still has no server_name');
  Feed(LServer, LCh2);
  ExchangeFlights(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server accepted the retry ClientHello');
  CheckFalse(LClient.IsTerminal, 'the client did not abort');
  CheckEquals(Integer(TNamedGroupCatalog.Secp256r1), Integer(LClient.ConnectionInfo.NamedGroup),
    'the retry moved the handshake onto the server''s group');
end;

procedure TTestConfigBuilder.TestOmittedSniKeepsSessionsApart;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LOffered: Boolean;

  function Resumes(AMode: TServerNameIndication): Boolean;
  var
    LClient, LServer: ITlsEngine;
    LFlight: TBytes;
    LExts: TExtensionVector;
    LEntry: TExtensionEntry;
  begin
    LClient := TTlsEngineFactory.CreateClientEngine(
      TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .WithServerVerification(
        TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .WithSessionCache(LCache).WithResumptionScope(LScope)
      .WithServerNameIndication(AMode).Build, 'localhost');
    LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
    LClient.StartHandshake;
    LFlight := Drain(LClient);
    // whether the client offered a cached session, apart from the server accepting it
    LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
    LOffered := LExts.TryFind(TExtensionTypes.PreSharedKey, LEntry);
    Feed(LServer, LFlight);
    ExchangeFlights(LClient, LServer);
    // let the post-handshake ticket reach the client's cache
    Pump(LServer, LClient);
    Result := LClient.ConnectionInfo.Resumed;
  end;

begin
  LCache := TInMemorySessionCache.Create as ISessionCache;
  LScope := TBytes.Create($53, $4E, $49);
  LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithResumptionScope(LScope).Build;
  CheckFalse(Resumes(TServerNameIndication.Send), 'the first handshake is a full one');
  CheckFalse(LOffered, 'nothing cached yet, so no session is offered');
  CheckTrue(Resumes(TServerNameIndication.Send), 'a repeat with SNI resumes');
  CheckTrue(LOffered, 'the cached session is offered');
  // the client's own cache key keeps the two apart: it offers no session, rather than the server
  // declining one
  CheckFalse(Resumes(TServerNameIndication.Omit),
    'a client that omits SNI does not resume a session made with it');
  CheckFalse(LOffered, 'a client that omits SNI does not offer a session made with it');
  CheckTrue(Resumes(TServerNameIndication.Omit), 'a repeat without SNI resumes its own session');
  CheckTrue(LOffered, 'it offers its own cached session');
end;

function TTestConfigBuilder.NewPskOnlyServerBuilder: ITlsServerConfigBuilder;
var
  LOwner: ITlsConfigBuilder;
begin
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  Result := LOwner.Server;
end;

procedure TTestConfigBuilder.TestReverifyUnderHardNeedsALiveVerdict;
begin
  // a reverified resume carries no staple, so Hard with only a staple request could never resume
  CheckTrue(BuildRefused(NewBareClientBuilder.WithOcspStaplingRequest(True)
    .WithServerVerification(HardWebPkiServer)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumeVerification(TResumeVerification.Reverify), 'WithResumeVerification(Reverify)'),
    'Reverify under Hard with no live verdict');
end;

procedure TTestConfigBuilder.TestReverifyUnderHardBuildsWithALiveVerdict;
begin
  CheckNotNull(NewBareClientBuilder.WithServerVerification(HardWebPkiServer)
    .WithLiveRevocationVerdict(0)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumeVerification(TResumeVerification.Reverify).Build,
    'Reverify under Hard with a live verdict');
end;

procedure TTestConfigBuilder.TestReverifyWithEarlyDataAndHostDecisionIsRefused;
begin
  // the verdict resolves after the server flight, so no early data could precede it
  CheckTrue(BuildRefused(NewClientBuilder.WithAsyncCertificateVerdict(0)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumeVerification(TResumeVerification.Reverify)
    .Tls13.WithEarlyData(True), 'asynchronous certificate verdict'),
    'early data with Reverify and a host-decision verdict');
end;

procedure TTestConfigBuilder.TestReverifyWithEarlyDataAndLiveVerdictIsRefused;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder.WithServerVerification(HardWebPkiServer)
    .WithLiveRevocationVerdict(0)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumeVerification(TResumeVerification.Reverify)
    .Tls13.WithEarlyData(True), 'asynchronous certificate verdict'),
    'early data with Reverify and a live-revocation verdict');
end;

procedure TTestConfigBuilder.TestReverifyWithEarlyDataBuildsWithoutAnAsyncVerdict;
begin
  CheckNotNull(NewClientBuilder
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumeVerification(TResumeVerification.Reverify)
    .Tls13.WithEarlyData(True).Build, 'early data with Reverify and no deferral');
end;

procedure TTestConfigBuilder.TestHardWithReuseOriginalBuildsWithACache;
begin
  CheckNotNull(NewBareClientBuilder.WithOcspStaplingRequest(True)
    .WithServerVerification(HardWebPkiServer)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache).Build,
    'Hard with the default reuse mode');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesPins;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder
    .WithCertificatePinning(TArray<TBytes>.Create(Crypto.Primitives.GetRandom.GenerateBytes(32)))
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithCertificatePinning'),
    'pins on a client that verifies no certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesAVerifyCallback;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder.WithCertificateVerifyCallback(RejectEveryChain)
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithCertificateVerifyCallback'),
    'a verify callback on a client that verifies no certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesAVerdictDeferral;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder.WithAsyncCertificateVerdict(0)
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithLiveRevocationVerdict'),
    'a verdict deferral on a client that verifies no certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesChangedChainLimits;
var
  LLimits: TCertificateChainLimits;
begin
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxChainCertificates := 8;
  CheckTrue(BuildRefused(NewBareClientBuilder.WithCertificateChainLimits(LLimits)
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithCertificateChainLimits'),
    'chain limits changed on a client that verifies no certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesAChangedStapleRequest;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder.WithOcspStaplingRequest(True)
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithOcspStaplingRequest'),
    'a staple request added on a client that verifies no certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesACredential;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder.WithCredential(ServerCredential)
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithCredential'),
    'a credential on a client whose server never requests one');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesDecompressors;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder.Tls13
    .WithCertificateDecompressors(TZlibCertificateCompression.DefaultDecompressors)
    .WithExternalPreSharedKeys(MakePskSpecs(1)), 'Tls13.WithCertificateDecompressors'),
    'decompressors on a client that receives no certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesReverify;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumeVerification(TResumeVerification.Reverify)
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithResumeVerification(Reverify)'),
    'Reverify on a client that has no certificate to re-verify');
end;

procedure TTestConfigBuilder.TestPskOnlyClientRefusesDisabledServerNameCheck;
begin
  CheckTrue(BuildRefused(NewBareClientBuilder.WithDangerousDisableServerNameCheck
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'WithDangerousDisableServerNameCheck'),
    'a disabled name check on a client that verifies no certificate');
end;

function TTestConfigBuilder.AuthorityName(ALength: Int32): TBytes;
begin
  SetLength(Result, ALength);
  if ALength > 0 then
    FillChar(Result[0], ALength, $30);
end;

function TTestConfigBuilder.ClientAuthoritiesRefusal(const ABuilder: ITlsServerConfigBuilder;
  const ANames: TArray<TBytes>): string;
begin
  Result := '';
  try
    ABuilder.WithClientCertificateAuthorities(ANames);
  except
    on E: EArgumentTlsLibException do
      Result := E.Message;
  end;
end;

procedure TTestConfigBuilder.TestPskOnlyClientChecksNoServerName;
begin
  CheckFalse(NewBareClientBuilder.Tls13.WithExternalPreSharedKeys(MakePskSpecs(1))
    .Build.CheckServerName, 'a PSK-only client has no name to check');
  CheckTrue(NewClientBuilder.Build.CheckServerName, 'a client with trust still checks the name');
end;

procedure TTestConfigBuilder.TestPskOnlyClientEngineNeedsNoHost;
var
  LClient: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(NewBareClientBuilder.Tls13
    .WithExternalPreSharedKeys(MakePskSpecs(1)).Build, '');
  CheckNotNull(LClient, 'a PSK-only client engine is created without a host');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesNilSignatureSchemesIsATypedRefusal;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    ClientAuthServerBuilder.WithSignatureSchemes(nil)
      .WithClientCertificateAuthorities(TArray<TBytes>.Create(AuthorityName(16))).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := Pos('registries are required', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a nil signature-scheme registry is refused by name, not dereferenced');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesEmptyNameIsRefused;
begin
  CheckTrue(Pos('must not be empty', ClientAuthoritiesRefusal(NewServerBuilder,
    TArray<TBytes>.Create(AuthorityName(8), nil))) > 0, 'a nil name');
  CheckTrue(Pos('must not be empty', ClientAuthoritiesRefusal(NewServerBuilder,
    TArray<TBytes>.Create(AuthorityName(0)))) > 0, 'a zero-length name');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesFramedTotalAtLimitIsAccepted;
begin
  // one name of 65533 bytes plus its 2-byte prefix fills the 65535-byte list
  CheckEquals('', ClientAuthoritiesRefusal(NewServerBuilder,
    TArray<TBytes>.Create(AuthorityName(65533))), 'a name filling the list exactly');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesFramedTotalOverLimitIsRefused;
begin
  CheckTrue(Pos('must not exceed 65535', ClientAuthoritiesRefusal(NewServerBuilder,
    TArray<TBytes>.Create(AuthorityName(65534)))) > 0, 'a name one byte over');
  CheckTrue(Pos('must not exceed 65535', ClientAuthoritiesRefusal(NewServerBuilder,
    TArray<TBytes>.Create(AuthorityName(65536)))) > 0, 'a name of 65536 bytes');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesRunningTotalAtLimitIsAccepted;
begin
  CheckEquals('', ClientAuthoritiesRefusal(NewServerBuilder,
    TArray<TBytes>.Create(AuthorityName(32766), AuthorityName(32765))),
    'two names framing to exactly 65535');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesRunningTotalOverLimitIsRefused;
begin
  CheckTrue(Pos('must not exceed 65535', ClientAuthoritiesRefusal(NewServerBuilder,
    TArray<TBytes>.Create(AuthorityName(32766), AuthorityName(32766)))) > 0,
    'two names framing to one byte over');
end;

function TTestConfigBuilder.ClientAuthServerBuilder: ITlsServerConfigBuilder;
begin
  Result := NewServerBuilder.WithClientVerification(
    TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithPeerAuth(TClientAuthMode.Requested);
end;

function TTestConfigBuilder.CertificateRequestRoom: Int32;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ClientAuthServerBuilder.Build;
  Result := 65535 - (4 + 2 + 2 * System.Length(LConfig.SignatureSchemes.Items)) - (4 + 2);
  if System.Length(LConfig.CertificateDecompressors) > 0 then
    Dec(Result, 4 + 1 + 2 * System.Length(LConfig.CertificateDecompressors));
end;

procedure TTestConfigBuilder.TestClientAuthoritiesAtCertificateRequestRoomBuildAndEncode;
var
  LConfig: ITlsServerConfig;
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LBlock: TBytes;
begin
  LConfig := ClientAuthServerBuilder.WithClientCertificateAuthorities(
    TArray<TBytes>.Create(AuthorityName(CertificateRequestRoom - 2))).Build;
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    LContext.SignatureSchemes := TSignatureSchemeCodes.FromRegistry(LConfig.SignatureSchemes);
    LContext.CertificateAuthorities := LConfig.ClientCertificateAuthorities;
    LContext.CertCompressionAlgorithms :=
      TCertificateCompression.Algorithms(LConfig.CertificateDecompressors);
    LBlock := LCodec.ProduceBlock(LContext, TTlsExtensionContextKind.CertificateRequest);
  finally
    LContext.Free;
  end;
  CheckEquals(2 + 65535, System.Length(LBlock), 'the block is exactly full');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesOverCertificateRequestRoomIsRefused;
begin
  CheckTrue(BuildRefused(ClientAuthServerBuilder.WithClientCertificateAuthorities(
    TArray<TBytes>.Create(AuthorityName(CertificateRequestRoom - 1))),
    'room for ' + IntToStr(CertificateRequestRoom)), 'one byte over the room');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesOverRoomBuildOnTls12Only;
begin
  // TLS 1.2 frames the names in a list of their own, so only 1.3 shares the block with other extensions
  CheckNotNull(ClientAuthServerBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithClientCertificateAuthorities(TArray<TBytes>.Create(
    AuthorityName(CertificateRequestRoom - 1))).Build, 'a list over the 1.3 room on a 1.2-only server');
end;

procedure TTestConfigBuilder.TestClientAuthoritiesRefusalLeavesBuilderUsable;
var
  LBuilder: ITlsServerConfigBuilder;
  LKept: TBytes;
  LConfig: ITlsServerConfig;
begin
  LKept := AuthorityName(16);
  LBuilder := ClientAuthServerBuilder.WithClientCertificateAuthorities(
    TArray<TBytes>.Create(LKept));
  CheckTrue(Pos('must not be empty', ClientAuthoritiesRefusal(LBuilder,
    TArray<TBytes>.Create(AuthorityName(1), nil))) > 0, 'the refused call raised');
  LConfig := LBuilder.Build;
  CheckEquals(1, System.Length(LConfig.ClientCertificateAuthorities), 'the earlier list survived');
  CheckEquals(16, System.Length(LConfig.ClientCertificateAuthorities[0]),
    'the earlier name survived');
end;

procedure TTestConfigBuilder.TestClientCompressionCacheBesideEmptyCompressorsIsRefused;
var
  LEmptyComp: TArray<ICertificateCompressor>;
begin
  LEmptyComp := nil;
  CheckTrue(BuildRefused(NewClientBuilder.WithCredential(ServerCredential).Tls13
    .WithCertificateCompressors(LEmptyComp)
    .WithCertificateCompressionCache(
      TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache),
    'needs at least one compressor'), 'a cache beside an empty compressor list on a client');
end;

procedure TTestConfigBuilder.TestServerCompressionCacheBesideEmptyCompressorsIsRefused;
var
  LEmptyComp: TArray<ICertificateCompressor>;
begin
  LEmptyComp := nil;
  CheckTrue(BuildRefused(NewServerBuilder.Tls13
    .WithCertificateCompressors(LEmptyComp)
    .WithCertificateCompressionCache(
      TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache),
    'needs at least one compressor'), 'a cache beside an empty compressor list on a server');
end;

procedure TTestConfigBuilder.TestEmptyCompressorsWithoutCacheBuild;
var
  LEmptyComp: TArray<ICertificateCompressor>;
begin
  LEmptyComp := nil;
  CheckNotNull(NewClientBuilder.WithCredential(ServerCredential).Tls13
    .WithCertificateCompressors(LEmptyComp).Build,
    'an empty compressor list alone on a client');
  CheckNotNull(NewServerBuilder.Tls13
    .WithCertificateCompressors(LEmptyComp).Build,
    'an empty compressor list alone on a server');
end;

procedure TTestConfigBuilder.TestPskOnlyStrictClientBuildsWithItsSeededSettings;
begin
  // Strict seeds chain limits and a staple request; seeded values are the starting point, not a change
  CheckNotNull(TTlsPresets.Strict(Crypto, Pkix).Client
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)).Build, 'a PSK-only Strict client');
end;

procedure TTestConfigBuilder.TestClientCompressorsNeedACredential;
begin
  CheckTrue(BuildRefused(NewClientBuilder.Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors),
    'certificate compressors'), 'compressors on a client with no credential');
end;

procedure TTestConfigBuilder.TestClientCompressionCacheNeedsACredential;
begin
  CheckTrue(BuildRefused(NewClientBuilder.Tls13.WithCertificateCompressionCache(
    TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache),
    'certificate compressors'), 'a compression cache on a client with no credential');
end;

procedure TTestConfigBuilder.TestClientDecompressorsBuildWithoutACredential;
begin
  // the client decompresses the server's certificate whether or not it holds a credential
  CheckNotNull(NewClientBuilder.Tls13
    .WithCertificateDecompressors(TZlibCertificateCompression.DefaultDecompressors).Build,
    'decompressors on a client with no credential');
end;

procedure TTestConfigBuilder.TestAsyncVerdictThenLiveVerdictRaises;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithAsyncCertificateVerdict(0).WithLiveRevocationVerdict(0);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('verdict slot', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'the live verdict after a host-decision verdict');
end;

procedure TTestConfigBuilder.TestLiveVerdictThenAsyncVerdictRaises;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithLiveRevocationVerdict(0).WithAsyncCertificateVerdict(0);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('verdict slot', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'the host-decision verdict after a live verdict');
end;

procedure TTestConfigBuilder.TestRepeatingOneVerdictSetterIsAccepted;
begin
  CheckNotNull(NewClientBuilder.WithLiveRevocationVerdict(0).WithLiveRevocationVerdict(500).Build,
    'a repeated live verdict call');
end;

procedure TTestConfigBuilder.TestCipherSuiteListOfAnUnofferedVersionIsRefused;
var
  LRefused: Boolean;
begin
  // the default profile offers TLS 1.3 only, so a list of TLS 1.2 suites alone would change nothing
  LRefused := False;
  try
    NewClientBuilder.WithCipherSuiteList(
      TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256)).Build;
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a TLS 1.2 list beside a TLS 1.3-only client');
end;

procedure TTestConfigBuilder.TestMixedCipherSuiteListBuilds;
begin
  // a host's shared list may name suites of a version this config does not offer
  CheckNotNull(NewClientBuilder.WithCipherSuiteList(TArray<UInt16>.Create(
    TCipherSuites13.Aes128GcmSha256, TCipherSuites12.EcdheEcdsaAes128GcmSha256)).Build,
    'a mixed list beside a TLS 1.3-only client');
end;

procedure TTestConfigBuilder.TestTicketCountZeroRefusesEarlyDataWithNothingToResume;
begin
  CheckTrue(BuildRefused(NewServerBuilder.Tls13.WithTicketCount(0).WithEarlyData(1000),
    'WithTicketCount(0)'), 'an early-data limit on a server that issues no tickets');
end;

procedure TTestConfigBuilder.TestTicketCountZeroKeepsEarlyDataWithASessionStore;
begin
  // a shared store can still resume the tickets another server issued
  CheckNotNull(NewServerBuilder
    .WithSessionStore(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore)
    .Tls13.WithTicketCount(0).WithEarlyData(1000).Build,
    'an early-data limit beside a session store');
end;

procedure TTestConfigBuilder.TestTicketCountZeroOnTls13OnlyRefusesDefaultKeys;
begin
  CheckTrue(BuildRefused(NewServerBuilder.WithDefaultSessionTicketKeys.Tls13.WithTicketCount(0),
    'WithTicketCount(0)'), 'default ticket keys on a TLS 1.3-only server that issues no tickets');
end;

procedure TTestConfigBuilder.TestTicketCountZeroOnTls13OnlyRefusesATicketLifetime;
begin
  CheckTrue(BuildRefused(NewServerBuilder.WithTicketLifetime(600).Tls13.WithTicketCount(0),
    'WithTicketCount(0)'), 'a ticket lifetime on a TLS 1.3-only server that issues no tickets');
end;

procedure TTestConfigBuilder.TestTicketCountZeroKeepsDefaultKeysWhenTls12IsOffered;
begin
  // the TLS 1.2 side of the server still issues tickets under these
  CheckNotNull(NewServerBuilder.WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .WithDefaultSessionTicketKeys.WithTicketLifetime(600).Tls13.WithTicketCount(0).Build,
    'default keys and a lifetime on a dual-version server');
end;

procedure TTestConfigBuilder.TestServerDecompressorsNeedPeerAuth;
begin
  CheckTrue(BuildRefused(NewServerBuilder.Tls13
    .WithCertificateDecompressors(TZlibCertificateCompression.DefaultDecompressors),
    'certificate decompressors'), 'decompressors on a server that requests no client certificate');
end;

procedure TTestConfigBuilder.TestServerDecompressorsBuildWithPeerAuth;
begin
  CheckNotNull(NewServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Tls13
    .WithCertificateDecompressors(TZlibCertificateCompression.DefaultDecompressors).Build,
    'decompressors on a server that requests client certificates');
end;

procedure TTestConfigBuilder.TestPskOnlyServerRefusesCompressors;
begin
  CheckTrue(BuildRefused(NewPskOnlyServerBuilder.Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors)
    .WithExternalPreSharedKeys(MakePskSpecs(1)), 'certificate compressors'),
    'compressors on a server that sends no certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyServerRefusesCompressionCache;
begin
  CheckTrue(BuildRefused(NewPskOnlyServerBuilder.Tls13.WithCertificateCompressionCache(
    TInMemoryCertificateCompressionCache.Create as ICertificateCompressionCache)
    .WithExternalPreSharedKeys(MakePskSpecs(1)), 'certificate compressors'),
    'a compression cache on a server that sends no certificate');
end;

procedure TTestConfigBuilder.TestServerChainLimitsNeedPeerAuth;
var
  LLimits: TCertificateChainLimits;
begin
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxChainCertificates := 8;
  CheckTrue(BuildRefused(NewServerBuilder.WithCertificateChainLimits(LLimits),
    'certificate-chain limits'), 'chain limits changed on a server that requests no client certificate');
end;

procedure TTestConfigBuilder.TestServerChainLimitsBuildWithPeerAuth;
var
  LLimits: TCertificateChainLimits;
begin
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxChainCertificates := 8;
  CheckNotNull(NewServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithCertificateChainLimits(LLimits).Build,
    'chain limits on a server that requests client certificates');
end;

procedure TTestConfigBuilder.TestServerNarrowedSchemesNeedPeerAuth;
var
  LSchemes: ISignatureSchemeRegistryBuilder;
begin
  LSchemes := TSignatureSchemeRegistry.CreateDefault.ToBuilder;
  LSchemes.Prune(TSignatureSchemes.Ed25519);
  CheckTrue(BuildRefused(NewServerBuilder.WithSignatureSchemes(LSchemes.Build),
    'signature-scheme registry'), 'a narrowed registry on a server that requests no client certificate');
end;

procedure TTestConfigBuilder.TestServerReorderedSchemesNeedPeerAuth;
var
  LSchemes: ISignatureSchemeRegistryBuilder;
begin
  LSchemes := TSignatureSchemeRegistry.CreateDefault.ToBuilder;
  LSchemes.Prune(TSignatureSchemes.Ed25519);
  LSchemes.Add(TSignatureScheme.ED25519);
  CheckTrue(BuildRefused(NewServerBuilder.WithSignatureSchemes(LSchemes.Build),
    'signature-scheme registry'), 'a same-set reordered registry on a server that requests no client certificate');
end;

procedure TTestConfigBuilder.TestHardenedServerNarrowedSchemesNeedPeerAuth;
var
  LSchemes: ISignatureSchemeRegistryBuilder;
begin
  LSchemes := TSignatureSchemeRegistry.CreateDefault.ToBuilder;
  LSchemes.Prune(TSignatureSchemes.Ed25519);
  CheckTrue(BuildRefused(TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .WithSignatureSchemes(LSchemes.Build), 'signature-scheme registry'),
    'a narrowed registry on a Hardened server that requests no client certificate');
end;

procedure TTestConfigBuilder.TestServerNarrowedSchemesBuildWithPeerAuth;
var
  LSchemes: ISignatureSchemeRegistryBuilder;
begin
  LSchemes := TSignatureSchemeRegistry.CreateDefault.ToBuilder;
  LSchemes.Prune(TSignatureSchemes.Ed25519);
  CheckNotNull(NewServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithSignatureSchemes(LSchemes.Build).Build,
    'a narrowed registry on a server that requests client certificates');
end;

procedure TTestConfigBuilder.TestServerEqualContentSchemesBuildWithoutPeerAuth;
begin
  CheckNotNull(NewServerBuilder.WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault).Build,
    'a registry equal in content to the preset''s, held by a different instance');
end;

procedure TTestConfigBuilder.TestRawServerBuilderWithDefaultSchemesBuilds;
var
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  CheckNotNull(LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(ServerCredential).Build,
    'a raw server builder carries no baseline registry, so its own registry is never refused');
end;

procedure TTestConfigBuilder.TestStrictServerBuildsWithItsSeededChainLimits;
begin
  CheckNotNull(TTlsPresets.Strict(Crypto, Pkix).Server.WithCredential(ServerCredential).Build,
    'a Strict server that requests no client certificate');
end;

procedure TTestConfigBuilder.TestPskOnlyServerRefusesPeerAuth;
begin
  CheckTrue(BuildRefused(NewPskOnlyServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .Tls13.WithExternalPreSharedKeys(MakePskSpecs(1)), 'never sends a CertificateRequest'),
    'client authentication on a server that sends no certificate');
end;

procedure TTestConfigBuilder.TestTicketLifetimeZeroIsRefusedWithResumptionOn;
begin
  CheckTrue(BuildRefused(NewServerBuilder.WithTicketLifetime(0), 'lifetime of 0'),
    'a lifetime of 0 while resumption is on');
end;

procedure TTestConfigBuilder.TestDefaultKeysThenExplicitKeysRaise;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewServerBuilder.WithDefaultSessionTicketKeys.WithSessionTicketKeys(
      TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('WithDefaultSessionTicketKeys', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'explicit keys after the default request');
end;

procedure TTestConfigBuilder.TestExplicitKeysThenDefaultKeysRaise;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewServerBuilder.WithSessionTicketKeys(
      TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
      .WithDefaultSessionTicketKeys;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('WithDefaultSessionTicketKeys', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'the default request after explicit keys');
end;

procedure TTestConfigBuilder.TestDefaultKeysBesideASessionStoreBuild;
begin
  // the store and the default keys are both consulted (stateless tickets alongside the store)
  CheckNotNull(NewServerBuilder.WithDefaultSessionTicketKeys
    .WithSessionStore(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore).Build,
    'default keys beside a session store');
end;

procedure TTestConfigBuilder.TestEmptyDecompressorsBuildOnAServerWithoutPeerAuth;
begin
  // an empty list is the documented off switch, legal wherever the direction is unused
  CheckNotNull(NewServerBuilder.Tls13.WithCertificateDecompressors(nil).Build,
    'an empty decompressor list on a server that requests no client certificate');
end;

procedure TTestConfigBuilder.TestEmptyCompressorsBuildOnAPskOnlyServer;
begin
  CheckNotNull(NewPskOnlyServerBuilder.Tls13.WithCertificateCompressors(nil)
    .WithExternalPreSharedKeys(MakePskSpecs(1)).Build,
    'an empty compressor list on a server that sends no certificate');
end;

procedure TTestConfigBuilder.TestTicketCountZeroKeepsEarlyDataWithExplicitTicketKeys;
begin
  // explicit keys can resume tickets another server issued, like a session store
  CheckNotNull(NewServerBuilder.WithSessionTicketKeys(
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .Tls13.WithTicketCount(0).WithEarlyData(1000)
    .WithAntiReplay(TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy).Build,
    'an early-data limit beside explicit ticket keys');
end;

procedure TTestConfigBuilder.TestTicketLifetimeZeroWithResumptionOffIsRefusedAsInert;
begin
  // with resumption off the lifetime is refused as an inert setting, not as a zero lifetime
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False).WithTicketLifetime(0),
    'resumption is off'), 'a lifetime of 0 with resumption off');
end;

procedure TTestConfigBuilder.TestServerCompressorsBuildWithOnlyAnSniCredential;
var
  LOwner: ITlsConfigBuilder;
begin
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  CheckNotNull(LOwner.Server.WithSniCredential('localhost', ServerCredential).Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors).Build,
    'compressors on a server holding only an SNI credential');
end;

procedure TTestConfigBuilder.TestServerCompressorsBuildWithOnlyACredentialResolver;
begin
  CheckNotNull(NewPskOnlyServerBuilder.WithCredentialResolver(
    TSniCredentialResolver.ForCredential(ServerCredential)).Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors).Build,
    'compressors on a server holding only a credential resolver');
end;

procedure TTestConfigBuilder.TestComposedCredentialResolverListsDefaultAndSniCredentials;
var
  LCredential: TTlsCredential;
  LConfig: ITlsServerConfig;
  LSet: ITlsServerCredentialSet;
begin
  LCredential := ServerCredential;
  LConfig := NewPskOnlyServerBuilder.WithCredential(LCredential)
    .WithSniCredential('localhost', LCredential).Tls13.Build;
  CheckTrue(Supports(LConfig.CredentialResolver, ITlsServerCredentialSet, LSet),
    'the composed resolver lists its credentials');
  CheckEquals(2, System.Length(LSet.Credentials),
    'the default and the identical SNI credential are both listed');
end;

procedure TTestConfigBuilder.TestTicketCountZeroOnTls13OnlyWithNothingSharedStillBuilds;
begin
  // documented, not refused: count 0 issues no tickets, so nothing resumes without shared state
  CheckNotNull(NewServerBuilder.Tls13.WithTicketCount(0).Build,
    'count 0 on a TLS 1.3-only server with resumption on and nothing shared');
end;

procedure TTestConfigBuilder.TestRequiresPskNeedsAKeyAndTheFlag;
begin
  CheckTrue(TClientPskPath.RequiresPsk(1, True), 'a key and the flag');
  CheckFalse(TClientPskPath.RequiresPsk(1, False), 'a key, flag clear');
  CheckFalse(TClientPskPath.RequiresPsk(0, True), 'flag with no key');
  CheckFalse(TClientPskPath.RequiresPsk(0, False), 'neither');
end;

procedure TTestConfigBuilder.TestCertificatePathTls13OnlyFollowsTheExternalKeys;
begin
  CheckTrue(TClientPskPath.HasCertificatePath(True, False, 0, False, 0, False), 'no key');
  CheckTrue(TClientPskPath.HasCertificatePath(True, False, 1, False, 0, False), 'optional key');
  CheckTrue(TClientPskPath.HasCertificatePath(True, False, 0, True, 0, False), 'flag, no key');
  CheckFalse(TClientPskPath.HasCertificatePath(True, False, 1, True, 0, False), 'required key');
  CheckTrue(TClientPskPath.HasCertificatePath(True, False, 0, False, 1, True),
    'a required TLS 1.2 key does not bind TLS 1.3');
end;

procedure TTestConfigBuilder.TestCertificatePathTls12OnlyFollowsTheTls12Keys;
begin
  CheckTrue(TClientPskPath.HasCertificatePath(False, True, 0, False, 0, False), 'no key');
  CheckTrue(TClientPskPath.HasCertificatePath(False, True, 0, False, 1, False), 'optional key');
  CheckFalse(TClientPskPath.HasCertificatePath(False, True, 0, False, 1, True), 'required key');
  CheckTrue(TClientPskPath.HasCertificatePath(False, True, 1, True, 0, False),
    'a required external key does not bind TLS 1.2');
end;

procedure TTestConfigBuilder.TestCertificatePathBothVersionsNeedBothKeysRequired;
begin
  CheckTrue(TClientPskPath.HasCertificatePath(True, True, 1, True, 1, False),
    'TLS 1.2 key optional');
  CheckTrue(TClientPskPath.HasCertificatePath(True, True, 1, False, 1, True),
    'external key optional');
  CheckFalse(TClientPskPath.HasCertificatePath(True, True, 1, True, 1, True), 'both required');
end;

procedure TTestConfigBuilder.TestCertificatePathNoVersionOffered;
begin
  CheckFalse(TClientPskPath.HasCertificatePath(False, False, 0, False, 0, False),
    'no version, no path');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestConfigBuilder);
{$ELSE}
  RegisterTest(TTestConfigBuilder.Suite);
{$ENDIF FPC}

end.
