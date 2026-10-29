{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Tests for the optional TlsLib.Trust.System package, in two layers:
///
/// 1. A portable fixture suite that runs on every target: TFileSystemRootSource takes an explicit
///    (env, files, dirs) form, so its harvest/resolution logic runs on any host with throwaway
///    fixture paths, alongside a check that the TOSSystemTrust factory reports a sane capability
///    for the build's platform.
///
/// 2. A real-OS-store contract written once against ITrustAnchorStore
///    (TSystemTrustAnchorContractTestBase) and subclassed per platform to supply the concrete
///    harvester. Each subclass is compile-time guarded to its OS (TLSLIB_MSWINDOWS / TLSLIB_MACOS /
///    TLSLIB_LINUX|BSD|SOLARIS) and registered only there. An empty store is tolerated except on
///    Windows / macOS, which always ship roots and so treat an empty harvest as a failure.</summary>
unit SystemTrustTests;

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
  TlpArrayUtilities,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpCertificateVerifierSource,
  TlpTrustTypes,
  TlpICertificateVerifierSource,
  TlpTrustPolicy,
  TlpCertificateLimits,
  TlpServerName,
  TlpCertificateStrengthPolicy,
  TlpNegotiationTypes,
  TlpSignatureSchemeRegistry,
  TlpTlsAlert,
  TlpIClock,
  TlpClock,
  MockClock,
  TlpSystemTrustExceptions,
  TlpTlsLibExceptions,
  // portable engine - drives the always-on fixtures on every host
  TlpFileSystemTrust,
  // the real per-OS harvesters, each compiled only on its own platform
{$IFDEF TLSLIB_MSWINDOWS}
  TlpWindowsSystemTrust,
{$ENDIF TLSLIB_MSWINDOWS}
{$IFDEF TLSLIB_MACOS}
  TlpAppleSystemTrust,
{$ENDIF TLSLIB_MACOS}
{$IFDEF TLSLIB_ANDROID}
  TlpAndroidSystemTrust,
{$ENDIF TLSLIB_ANDROID}
{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
  TlpUnixSystemTrust,
  TlpPosixPrivilege,
  TlpDynamicLibrary,
{$IFEND}
  TlpOSSystemTrust,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine,
  TlpOSDelegateVerifier,
  TlpOSLiveRevocation,
  TlpSystemTrustFacade,
  TlpITlsConfigBuilder,
  TlpISystemTrustInstaller,
  TlpITlsConfig,
  TlpTlsCredential,
  TlpTlsPresets,
  MockPlatformChainEngine,
  MockVerifyHooks,
  MockCertificateVerifiers,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>Portable suite (always runs): drives TFileSystemRootSource's file/dir resolution
  /// via injected fixtures, and checks the factory reports anchors for this build's platform.</summary>
  TTestSystemTrustFixtures = class(TTlsLibAlgorithmTestCase)
  private
  var
    FDir: string;       // a throwaway fixture directory under the working dir
    FFile: string;      // a fixture bundle file holding the test root
    FMissing: string;   // a path that does not exist
    FCertDir: string;   // a fixture directory holding one root file
    FExtraDir: string;  // a fixture directory holding the second root
    FRootDer: TBytes;   // the test root DER
    FRoot2Der: TBytes;  // a second, distinct root DER
    procedure WriteBytes(const APath: string; const AData: TBytes);
    /// <summary>Builds a filesystem source, freezes it into an immutable snapshot, and
    /// frees the source - the shape every caller uses. Fail-closed harvests raise here.</summary>
    function FileSnapshot(const AEnvFile, AEnvDir: string;
      const AFiles, ADirs: TArray<string>): ITrustAnchorStore;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestInjectedFileHarvestsRoot;
    procedure TestFirstExistingFileCandidateWins;
    procedure TestNoReadableStoreFailsClosed;
    procedure TestDirectoryHarvestReadsCerts;
    procedure TestDuplicateCertsAreDeduplicated;
    procedure TestDistinctCertsAreNotMerged;
    procedure TestSnapshotSurvivesSourceFileDeletion;
    procedure TestEnvDirListHarvestsEveryEntry;
    procedure TestEnvDirListSkipsMissingEntry;
    procedure TestEnvDirListWithNoExistingEntryFailsClosed;
    procedure TestEnvDirListWithNoExistingEntryFailsClosedEvenWithAGoodFile;
    procedure TestMissingEnvFileFailsClosedEvenWithAGoodDir;
    procedure TestEnvDirListIgnoresEmptyEntries;
    procedure TestEnvFileAndEnvDirAreBothHarvested;
    procedure TestEnvFileAndEnvDirSharingACertificateDeduplicate;
    procedure TestEnvDirOverrideReplacesDefaultFiles;
    procedure TestEnvFileOverrideReplacesDefaultDirs;
    procedure TestFactoryAnchorStoreMatchesSupports;
    procedure TestFactoryServerVerifierSourceMatchesSupports;
  end;

  /// <summary>Portable suite (always runs): the host-neutral system-trust installer that bridges
  /// TSystemTrust.ServerVerification into the shared adapter-core seam - the client role installs OS
  /// server trust, and the server role mirrors the facade's client-authentication refusal.</summary>
  TTestSystemTrustInstaller = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestClientInstallComposesLikeFacade;
    procedure TestSharedInstallerIsOneStableInstance;
    procedure TestExplicitOsAnchorsAreTheServerEscapeHatch;
    procedure TestLiveFetchWithoutADeadlineIsRefused;
    procedure TestDefaultResolvesToTheOsEngineWhereThePlatformHasOne;
    procedure TestExplicitAnchorsStillResolveToTheHarvestedStore;
    procedure TestExplicitDelegateIsTheOsEngineOrRefused;
  end;

  /// <summary>Portable suite (always runs): the shared OS-delegate post-checks
  /// (TDelegatePostChecks) - stapled-Revoked-always-wins, IP-literal identity, and the
  /// Hard/Live-need-live-revocation predicates - exercised without touching any real OS store.</summary>
  TTestDelegatePostChecks = class(TTlsLibAlgorithmTestCase)
  private
    FClock: ITlsClock;
    FOcsp: TStringList;      // OcspStapling.txt: a real chain + Good/Revoked/stale staples
    FEc: TStringList;        // EcP256Chain.txt: a DNS-only leaf and an IP-SAN leaf
    function OcspChain: TArray<TBytes>;
    function Ocsp(const AName: string): TBytes;
    function Ec(const AName: string): TBytes;
  protected
    procedure SetUp; override;
  published
    procedure TestRevokedStapleRejectsOverOsPath;
    procedure TestStapleOutcomeMapping;
    procedure TestGoodAndAbsentStapleDoNotFire;
    procedure TestStaleStapleIsNotRevoked;
    procedure TestLeafOnlyPathIsNotRevoked;
    procedure TestNilClockFallsBackToSystemTime;
    procedure TestNilProviderIsNotRevoked;
    procedure TestHardNeedsLiveRevocation;
    procedure TestLiveNeedsLiveRevocation;
    procedure TestOsHostNameStripsIpLiterals;
    procedure TestNameMismatchMatchesDnsLeaf;
    procedure TestNameMismatchMatchesIpLeaf;
    procedure TestNameMismatchRejectsWrongName;
    procedure TestNameMismatchEmptyNameIsNotChecked;
    procedure TestNameMismatchNilProviderFailsClosed;
  end;

  /// <summary>Platform-neutral tests for the OS delegate template over a fake platform engine: the
  /// request shaping, the strength/revocation/identity tail, the source-construction guards and the
  /// live-resolver dispatch.</summary>
  TTestOSDelegateTemplate = class(TTlsLibAlgorithmTestCase)
  strict private
    FClock: ITlsClock;
    FOcsp: TStringList;
    FEngineHold: IPlatformChainEngine;
    FFallbackCalls: Integer;
    function Ocsp(const AName: string): TBytes;
    // a fallback that finds the chain indeterminate and decides at the posture it is handed
    function IndeterminateFallback(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    // a server delegate over an engine that trusts APath, AExempt being the anchors it reports
    function VerifyEnginePath(const AChain, APath, AExempt: TArray<TBytes>;
      const AStrength: TCertificateStrengthPolicy;
      const ACallback: TTlsCertificateVerifyCallback; out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
    // the live re-check form: the engine's Good path is judged by the same strength policy
    function ResolveLiveEnginePath(const AChain, APath, AExempt: TArray<TBytes>;
      const AStrength: TCertificateStrengthPolicy; out AAlert: TTlsAlertDescription): Boolean;
    // the client form: the engine reports no anchor, AAnchors are the configured client-CA roots
    function VerifyClientEnginePath(const AChain, APath, AAnchors: TArray<TBytes>;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
    function OcspChain: TArray<TBytes>;
    function Result_(AOutcome: TLiveRevocationOutcome;
      const APath: TArray<TBytes>): TPlatformChainResult;
    function Policy(APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
      ADeferral: TVerdictDeferral; const AAnchors: TArray<TBytes>): TOSDelegatePolicy;
    function ClientVerify(const AChain, AIntermediates: TArray<TBytes>; AReturns: Boolean;
      AEngineAlert: TTlsAlertDescription; out AFake: TMockPlatformChainEngine;
      out AAlert: TTlsAlertDescription): Boolean;
    function LiveClientResolve(const AChain, AIntermediates: TArray<TBytes>; AReturns: Boolean;
      AEngineAlert: TTlsAlertDescription; out AFake: TMockPlatformChainEngine;
      out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestRequestShapingRevocationLevels;
    procedure TestRequestNetworkNotAllowedInline;
    procedure TestClientRequestCarriesAnchors;
    procedure TestRequestCarriesConfiguredIntermediates;
    procedure TestPolicyFromContextCarriesIntermediates;
    procedure TestClientDistrustedPathIsRefused;
    procedure TestClientDistrustedChainEntryIsWithheldFromTheEngine;
    procedure TestClientDistrustedIntermediateIsWithheldFromTheEngine;
    procedure TestClientWithheldChainEntryWithNoAnchorIsBadCertificate;
    procedure TestClientWithheldIntermediateWithNoAnchorIsBadCertificate;
    procedure TestClientNothingWithheldKeepsTheEngineAlert;
    procedure TestClientWithheldWithAnotherFailureKeepsTheEngineAlert;
    procedure TestLiveClientWithheldChainEntryWithNoAnchorIsBadCertificate;
    procedure TestLiveClientWithheldIntermediateWithNoAnchorIsBadCertificate;
    procedure TestLiveClientNothingWithheldKeepsTheEngineAlert;
    procedure TestLiveClientWithheldWithAnotherFailureKeepsTheEngineAlert;
    procedure TestLiveClientResolverRefusesDistrustedPath;
    procedure TestLiveClientResolverWithholdsDistrustedIntermediate;
    procedure TestEmptyChainIsRefusedBeforeTheEngine;
    procedure TestEngineFailurePassesAlertThrough;
    procedure TestAcceptFillsTrustedPath;
    procedure TestStapledRevokedOverridesUnderOff;
    procedure TestEngineRevokedRejects;
    procedure TestHardIndeterminateRejectsCacheOnly;
    procedure TestHardIndeterminateAcceptsWhenDeferred;
    procedure TestHardIndeterminateAcceptsCacheOnlyWhenLiveVerdictArmed;
    procedure TestNameMismatchRejectsWithoutDnsCapability;
    procedure TestSourceRefusesLiveWithoutLiveFetch;
    procedure TestServerSourceRefusesLiveWithoutVerdict;
    procedure TestServerSourceCarriesExtraAnchorsToTheEngine;
    procedure TestClientSourceRefusesHardWithoutCachedRevocation;
    procedure TestLiveResolverDispatchesToServer;
    procedure TestLiveResolverWrongRoleRefused;
    procedure TestLiveResolverHoldsToTheConfiguredPosture;
    procedure TestLiveResolverOffPostureStillChecksWhenTheConfigurationAsksForMore;
    procedure TestLiveResolverFallbackDecidesAtTheLiftedPosture;
    procedure TestEnginePathStartingAtASubCaIsRefused;
    procedure TestEnginePathOfAPinnedSelfSignedCaIsAccepted;
    procedure TestClientEngineReportingNoAnchorAcceptsAConfiguredSelfSignedCa;
    procedure TestClientEngineReportingNoAnchorRefusesAnUnconfiguredCa;
    procedure TestEnginePathOfAPlainLeafIsAccepted;
    procedure TestEnginePathAnchorKeyBelowTheFloorIsAcceptedWhenNotFlagged;
    procedure TestEnginePathAnchorKeyBelowTheFloorIsRefusedWhenFlagged;
    procedure TestEnginePathAnchorOnAnUnlistedCurveIsRefusedWhenFlagged;
    procedure TestEnginePathAnchorEdDsaKeyIsRefusedWhenFlagged;
    procedure TestEnginePathAnchorWithinTheFloorsIsAcceptedWhenFlagged;
    procedure TestLiveEnginePathAnchorKeyBelowTheFloorIsAcceptedWhenNotFlagged;
    procedure TestLiveEnginePathAnchorKeyBelowTheFloorIsRefusedWhenFlagged;
    procedure TestVerifyCallbackSeesThePresentedChainAndTheEnginePath;
    procedure TestClientRoutesByStapleWithoutCachedRevocation;
    procedure TestStapledRevokedRejectsWithoutCachedRevocation;
    procedure TestVerifyCallbackRejectYieldsCertificateUnknown;
    procedure TestVerifyCallbackNotInvokedWhenEngineRejects;
    procedure TestEmptyServerNameFailsClosedWithoutConsultingEngine;
    procedure TestOverCapChainRefusedWithoutConsultingEngine;
    procedure TestServerSourceCarriesVerifyCallbackFromContext;
    procedure TestClientSourceCarriesVerifyCallbackFromContext;
    procedure TestFilterRootsDeDupsAndDropsMalformed;
    procedure TestSnapshotCarriesDeduplicatedDistrustSet;
    procedure TestReadDistrustedOnlyDeduplicates;
    // RFC 7633 must-staple + TLS Feature well-formedness, enforced by the OS delegate
    procedure TestMustStapleLeafWithoutStapleRejects;
    procedure TestMustStapleLeafWithGoodStapleAccepts;
    procedure TestMustStapleNotBoundWhenNotOfferedOrOnResumption;
    procedure TestMalformedTlsFeatureRejectsBothRoles;
    procedure TestServerSourceEnforcesMustStaple;
    // a DnsIdentity engine's host match does not substitute for the library SAN check
    procedure TestNameMismatchRejectsWithDnsCapability;
  end;

  /// <summary>Platform-neutral tests for OS and host roots over a scripted platform
  /// engine: the retry against the host roots only on a no-trust-anchor failure, the single native
  /// union evaluation, which alert is reported, the OS distrust refusal, and the live resolver
  /// following the same path.</summary>
  TTestDelegateHostRoots = class(TTlsLibAlgorithmTestCase)
  strict private
    FOcsp: TStringList;
    function Ocsp(const AName: string): TBytes;
    function Chain: TArray<TBytes>;
    function HostRoots: TArray<TBytes>;
    function Accepted: TPlatformChainResult;
    function Rejected(AFailure: TPlatformChainFailure): TPlatformChainResult;
    function Policy(const AExtras, ADistrusted: TArray<TBytes>;
      AFetch: TSystemTrustFetch): TOSDelegatePolicy;
    function Verify(const AEngine: IPlatformChainEngine; const AExtras, ADistrusted: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
    function Resolve(const AEngine: IPlatformChainEngine; const ADistrusted: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestOsRootsAcceptanceNeverRetries;
    procedure TestNoTrustAnchorRetriesWithHostRootsAsExclusiveRoot;
    procedure TestOtherFailureIsFinal;
    procedure TestNoHostRootsNeverRetries;
    procedure TestEngineWithoutExclusiveAnchorsNeverRetries;
    procedure TestNativeUnionEvaluatesOnceWithHostRoots;
    procedure TestRetryFailureReportsTheAlertOfTheEvaluationThatReachedAnAnchor;
    procedure TestRetryFindingNoAnchorKeepsTheFirstAlert;
    procedure TestHostRootPathThroughDistrustedCertificateIsRefused;
    procedure TestDistrustAppliesToAnOsRootsAcceptance;
    procedure TestDistrustBindsWithoutHostRoots;
    procedure TestStoreDistrustReachesTheOsSource;
    procedure TestDistrustAppliesUnderNativeUnion;
    procedure TestSourceCarriesDistrustToTheVerifier;
    procedure TestSourceAcceptsHostRootsOverAnExclusiveAnchorEngine;
    procedure TestSourceRefusesHostRootsOverAnEngineWithNeitherCapability;
    procedure TestOsServerSourceIsTheOsSource;
    procedure TestOsClientSourceIsTheOsSource;
    procedure TestBuiltInSourceIsNotTheOsSource;
    procedure TestCustomVerifierSourceIsNotTheOsSource;
    procedure TestLiveResolverRetriesWithHostRoots;
    procedure TestLiveResolverOtherFailureIsFinal;
    procedure TestLiveResolverRefusesDistrustedHostRootPath;
  end;

  /// <summary>Platform-neutral tests for host roots trusted alone (a private PKI) over an engine
  /// that decides by roots: one pass against the host roots, no OS root ever vouching, the OS
  /// distrust still binding, the construction refusals, the guard against an engine that cannot
  /// honour an exclusive server root, and the live re-check built from the client config.</summary>
  TTestDelegateHostRootsAlone = class(TTlsLibAlgorithmTestCase)
  strict private
    FEc: TStringList;
    FOcsp: TStringList;
    FRsa: TStringList;
    function PrivateChain: TArray<TBytes>;
    function PrivateRoot: TArray<TBytes>;
    function PublicChain: TArray<TBytes>;
    function PublicRoot: TArray<TBytes>;
    /// <summary>An EC leaf under an RSA-2048 root: the root's key is what the floors can refuse.</summary>
    function WeakRootChain: TArray<TBytes>;
    function WeakRoot: TArray<TBytes>;
    /// <summary>An engine that accepts the chain but reports no path beyond the leaf and no exempt
    /// anchor, as a platform that reports none does for a client certificate.</summary>
    function NoAnchorEngine: IPlatformChainEngine;
    function ExclusiveCaps: TPlatformChainCapabilities;
    function Context(ADeferral: TVerdictDeferral): TServerTrustContext;
    /// <summary>A client context trusting AAnchors; the RSA floor of 4096 bits refuses WeakRoot, and
    /// AAnchorFloors holds an anchor's key to it.</summary>
    function ClientContext(const AAnchors: TArray<TBytes>;
      AAnchorFloors: Boolean): TClientTrustContext;
    function VerifyClient(const AEngine: IPlatformChainEngine;
      const AAnchors, AChain: TArray<TBytes>; AAnchorFloors: Boolean;
      out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>The live re-check of a client certificate chain over AEngine.</summary>
    function ResolveClient(const AEngine: IPlatformChainEngine;
      const AAnchors, AChain: TArray<TBytes>; AAnchorFloors: Boolean;
      out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>The message of the Build refusal for a server whose client-CA anchors are
    /// AAnchors, or '' when it builds.</summary>
    function ServerBuildMessage(AAnchorFloors: Boolean; const AAnchors: TArray<TBytes>): string;
    function Verify(const AEngine: IPlatformChainEngine; AScope: TSystemTrustRootScope;
      const AHostRoots, ADistrusted, AChain: TArray<TBytes>; const AName: string;
      out AAlert: TTlsAlertDescription): Boolean;
    function ClientConfig(const ASource: IServerCertificateVerifierSource): ITlsClientConfig;
    function WebPkiConfig: ITlsClientConfig;
    /// <summary>Expects the source constructor to raise AExpected; returns its message.</summary>
    function ConstructionMessage(const AEngine: IPlatformChainEngine; AFetch: TSystemTrustFetch;
      AScope: TSystemTrustRootScope; const AHostRoots: TArray<TBytes>;
      AExpected: ExceptClass): string;
    function Resolve(const AConfig: ITlsClientConfig; const AEngine: IPlatformChainEngine;
      const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestHostRootsEvaluatesOnceAgainstTheHostRoots;
    procedure TestHostRootsAcceptsThePrivateChain;
    procedure TestHostRootsRejectsAPublicRootedChain;
    procedure TestOsAndHostRootsStillAcceptsAPublicRootedChain;
    procedure TestOsRootsAloneRejectThePrivateChain;
    procedure TestHostRootsRefusesAPathThroughADistrustedCertificate;
    procedure TestHostRootsStillMatchesTheServerName;
    procedure TestHostRootsWithoutRootsIsRefused;
    procedure TestHostRootsOverAStoreDistrustingItsOnlyRootIsRefused;
    procedure TestHostRootsRawRootAlsoDistrustedLeavesNoRoot;
    procedure TestHostRootsDoNotHandTheEngineADistrustedRoot;
    procedure TestOsAndHostRootsDoNotHandTheEngineADistrustedRoot;
    procedure TestHostRootsRefusesAnEngineWithNoCapabilities;
    procedure TestHostRootsRefusesAnEngineWithOnlyNativeUnion;
    procedure TestConstructionChecksLiveFetchBeforeTheRoots;
    procedure TestConstructionChecksMissingRootsBeforeTheEngineCapability;
    procedure TestHostRootsWithLiveFetchTrustsThePrivateChain;
    procedure TestGuardRefusesAnchorsOnAnEngineWithoutExclusiveRoots;
    procedure TestGuardRefusesAnchorsOnAnEngineWithOnlyNativeUnion;
    procedure TestGuardLeavesAnOsRootsRequestToAnyEngine;
    procedure TestSourceIgnoresLaterMutationOfTheArraysItWasGiven;
    procedure TestSourceGettersReturnCopies;
    procedure TestWebPkiLiveResolverRefusesAnEngineWithoutExclusiveRoots;
    procedure TestLiveResolverFromAWebPkiConfigNeverLetsTheOsRootsVouch;
    procedure TestFromClientConfigCarriesEveryPolicyField;
    procedure TestFromServerConfigCarriesEveryPolicyField;
    procedure TestFromClientConfigWithoutAnOsSourceCarriesTheStoreDistrust;
    procedure TestHostRootsSourceCarriesItsRootsAsAnchors;
    procedure TestOsAndHostRootsSourceCarriesNoAnchors;
    procedure TestFromClientConfigCarriesHostRoots;
    procedure TestFromClientConfigCarriesOsAndHostRoots;
    procedure TestFromClientConfigWithoutAnOsSourceTakesTheTrustStore;
    // a host source is not the OS source, so its roots are not read
    procedure TestFromClientConfigRefusesAHostSource;
    // a host source that decorates the OS one is read through the OS source it is given
    procedure TestFromClientConfigTakesTheAnchorsAndDistrustOfTheRootsSource;
    procedure TestFromClientConfigTakesTheExtraAnchorsOfTheRootsSource;
    procedure TestLiveResolverOverloadRefusesARootsSourceThatIsNotOs;
    procedure TestLiveResolverOverloadRefusesNoRootsSource;
    procedure TestFromServerConfigTakesTheClientCaStore;
    procedure TestLiveResolverAcceptsThePrivateChainUnderHostRoots;
    procedure TestLiveResolverRejectsAPublicRootedChainUnderHostRoots;
    procedure TestLiveResolverOverloadRefusesADifferentOsRootsSource;
    procedure TestLiveResolverOverloadAcceptsTheConfigsOwnOsSource;
    procedure TestFromClientConfigRefusesAConfigWithoutAServerCertificate;
    procedure TestServerBuildRefusesAWeakClientAnchorWithFloorsOn;
    procedure TestServerBuildKeepsAWeakClientAnchorWithFloorsOff;
    procedure TestServerBuildKeepsAClientAnchorThatMeetsTheFloors;
    procedure TestClientDelegateRefusesAWeakAnchorAnEngineReportsAsExempt;
    procedure TestClientDelegateAcceptsAWeakExemptAnchorWithFloorsOff;
    procedure TestClientDelegateRefusesAWeakAnchorWhenTheEngineReportsNone;
    procedure TestClientDelegateAcceptsAWeakUnreportedAnchorWithFloorsOff;
    procedure TestClientDelegateAcceptsAStrongExemptAnchorBesideAWeakOne;
    procedure TestClientDelegateRefusesAnAnchorWithAnUndescribableKey;
    procedure TestClientDelegateReportsAnUnparseableAnchorAsBadCertificate;
    procedure TestLiveResolverRefusesAWeakAnchorWhenTheEngineReportsNone;
    procedure TestLiveResolverAcceptsAWeakAnchorWithFloorsOff;
    procedure TestLiveResolverAcceptsAStrongExemptAnchorBesideAWeakOne;
    procedure TestOsAndHostRootsRefusesANonUnionEngineWhateverTheDistrust;
    procedure TestOsAndHostRootsWithAllHostRootsDistrustedIsOsRootsOnly;
  end;

  /// <summary>Platform-neutral tests for the root-scope value (OsRoots, OsAndHostRoots,
  /// HostRoots) and the facade composition built from it where OS roots are read.</summary>
  TTestSystemTrustRoots = class(TTlsLibAlgorithmTestCase)
  strict private
    function Store: ITrustAnchorStore;
  published
    procedure TestOsRootsHasNoStoreAndTheOsAndHostRootsScope;
    procedure TestDefaultValueIsOsRoots;
    procedure TestOsAndHostRootsOfNilIsOsRoots;
    procedure TestOsAndHostRootsKeepsTheStoreAndScope;
    procedure TestHostRootsKeepsTheStoreIdentityAndScope;
    procedure TestHostRootsOfNilIsRefused;
    procedure TestHostRootsOfAStoreWithoutRootsIsRefused;
    procedure TestHostRootsOfAStoreDistrustingItsOnlyRootIsRefused;
    procedure TestDistrustStoreCarriesNoRoot;
    procedure TestDistrustStoreRefusesANilProvider;
    procedure TestHostRootsTheOsDistrustsAreRefusedByTheDelegateSource;
    procedure TestAnchorStoreRefusesANilProvider;
    procedure TestAnchorsModeHostRootsComposesExactlyTheHostRoots;
    procedure TestAnchorsModeOsAndHostRootsAddsTheHostRootsToTheHarvest;
  end;

  /// <summary>Engine-agnostic contract for a real OS anchor store, written against
  /// ITrustAnchorStore. A concrete per-OS suite supplies only CreateAnchorStore + PlatformName
  /// (and may relax RequiresPopulatedStore); the published tests are inherited and discovered
  /// automatically. Never registered on its own.</summary>
  TSystemTrustAnchorContractTestBase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    // ---- per-OS hooks ----
    function CreateAnchorStore: ITrustAnchorStore; virtual; abstract;
    function PlatformName: string; virtual; abstract;
    /// <summary>Whether an empty harvest is a failure. True where the OS always ships a root
    /// store (Windows, macOS); False where it may legitimately be absent (a bare Unix box).</summary>
    function RequiresPopulatedStore: Boolean; virtual;
    // ---- shared helpers ----
    /// <summary>Harvests the real store; skips and returns False (caller Exits) when a tolerant platform has none.</summary>
    function HarvestOrSkip(out ARoots: TArray<TBytes>): Boolean;
  published
    procedure TestHarvestYieldsRoots;
    procedure TestAllHarvestedRootsWellFormed;
    procedure TestHarvestedRootsAreUnique;
    procedure TestNoHarvestedRootIsDistrusted;
  end;

{$IFDEF TLSLIB_MSWINDOWS}

  /// <summary>Windows (crypt32 ROOT minus Disallowed) instantiation. Registered only on
  /// TLSLIB_MSWINDOWS.</summary>
  TTestWindowsSystemTrust = class(TSystemTrustAnchorContractTestBase)
  strict protected
    function CreateAnchorStore: ITrustAnchorStore; override;
    function PlatformName: string; override;
  published
    procedure TestReadDistrustedMatchesSnapshotDistrust;
  end;

  /// <summary>Behavioural tests for the Windows OS client-certificate delegate against a
  /// self-contained private CA (the exclusive trust root is fully controllable, so unlike the
  /// server delegate these are hermetic). Proves the exclusive-root behaviour, the injected clock,
  /// and the revocation posture over crypt32's real chain engine. Windows-only.</summary>
  TTestWindowsClientDelegate = class(TTlsLibAlgorithmTestCase)
  strict private
    FChain: TStringList;    // ClientAuthChain fields (private CA + dual-EKU leaf)
    FForeign: TStringList;  // an unrelated private root
    function Leaf: TArray<TBytes>;
    function OwnAnchor: TArray<TBytes>;
    function ForeignAnchor: TArray<TBytes>;
    // the full set of advertised schemes a stock config offers (the EC leaf's scheme is in it)
    function Advertised: TArray<UInt16>;
    /// <summary>The connection-scoped policy the delegate template applies around the Windows engine,
    /// assembled the way the trust context would populate it.</summary>
    function MakePolicy(const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      AFetch: TSystemTrustFetch; ADeferral: TVerdictDeferral; const AClock: ITlsClock;
      const AStrength: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>): TOSDelegatePolicy;
    function Verify(const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      const AClock: ITlsClock; out AAlert: TTlsAlertDescription): Boolean;
    function VerifyPolicy(const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      const AClock: ITlsClock; const AStrength: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>Runs the OS-native LIVE client resolver over AAnchors as the exclusive root. Used to
    /// prove exclusivity on the live path: a leaf that does not chain to the anchor fails trust
    /// before any revocation fetch, so this needs no responder.</summary>
    function VerifyLive(const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestAcceptsClientChainToConfiguredAnchor;
    procedure TestRejectsClientChainToForeignAnchor;
    procedure TestInjectedClockRejectsChainOutsideValidity;
    procedure TestHardPostureRejectsUnrevocableChain;
    procedure TestSoftPostureAcceptsUnrevocableChain;
    procedure TestRejectsUnadvertisedLeafScheme;
    procedure TestRejectsLeafOnDisallowedCurve;
    procedure TestLiveFetchDefersUnrevocableChainInline;
    procedure TestLiveEvaluationStaysExclusiveRoot;
    procedure TestWrongRolePeerRefusedWithInternalError;
    procedure TestServerChainResolverRefusesClientParkAtOff;
    procedure TestServerRoleLiveEvaluationHonoursSuppliedAnchors;
    procedure TestConfiguredIntermediateCompletesLeafOnlyClientChain;
  end;

  /// <summary>OS and host roots, and host roots alone, over the real Windows chain engine,
  /// against a private CA that is not in the machine store (which is never touched): the host
  /// roots admit the CA's server chain, the OS roots never vouch when they stand alone, the OS
  /// distrust list still binds, and every other fault stays a refusal. Also the pure mapping from
  /// a chain-policy error to its failure class.</summary>
  TTestWindowsHostRoots = class(TTlsLibAlgorithmTestCase)
  strict private
    FChain: TStringList;    // ClientAuthChain fields (private CA + dual-EKU leaf)
    FForeign: TStringList;  // an unrelated private root
    function Leaf: TArray<TBytes>;
    function CaRoot: TArray<TBytes>;
    function Verify(const ALeaf, AExtras, ADistrusted: TArray<TBytes>; const AClock: ITlsClock;
      out AAlert: TTlsAlertDescription): Boolean;
    function EvaluateStapled(const AStaple: TBytes; ARevocation: TPlatformRevocationCheck;
      out AResult: TPlatformChainResult): Boolean;
    function VerifyThroughSource(const ASource: IServerCertificateVerifierSource;
      out AAlert: TTlsAlertDescription): Boolean;
    // the first OS root the engine accepts offline as a chain of its own, else empty
    function TrustedOsRoot: TBytes;
    function EvaluateChain(const AChain, AAnchors: TArray<TBytes>; ANetworkAllowed: Boolean;
      out AResult: TPlatformChainResult): Boolean;
    function ResolveLive(const ARoots: TSystemTrustRoots;
      out AAlert: TTlsAlertDescription): Boolean;
    procedure CheckMapping(ADwError: Cardinal; AExpectedAlert: TTlsAlertDescription;
      AExpectedFailure: TPlatformChainFailure; const AName: string);
    procedure CheckClassified(ADwError, AErrorStatus: Cardinal;
      AExpectedAlert: TTlsAlertDescription; AExpectedFailure: TPlatformChainFailure;
      const AName: string);
    procedure CheckOutcome(ADwError, AErrorStatus: Cardinal; AExpected: TLiveRevocationOutcome;
      const AName: string);
  protected
    procedure SetUp; override;
  published
    procedure TestHardInlineAcceptsFreshGoodStapleWithoutIntermediateRevocation;
    procedure TestHardInlineRejectsRevokedStaple;
    procedure TestHardInlineWithoutStapleIsIndeterminate;
    procedure TestNoTrustAnchorIsReadFromTheChainBits;
    procedure TestRevocationShapedErrorBesideMissingAnchorIsRetried;
    procedure TestExpiryErrorBesideMissingAnchorIsRetried;
    procedure TestExpiryPolicyErrorBesideMissingAnchorKeepsItsAlert;
    procedure TestNameMismatchBesideMissingAnchorKeepsItsAlert;
    procedure TestDistrustOrBadSignatureIsFinal;
    procedure TestZeroPolicyErrorIsTheOsVerdict;
    procedure TestRevocationOutcomesNeedACleanChain;
    procedure TestPolicyErrorMapping;
    procedure TestRevocationErrorOnDistrustedChainIsNotRevoked;
    procedure TestChainFlagsKeepRootAutoUpdateEnabled;
    procedure TestPrivateCaServerChainRefusedWithoutHostRoots;
    procedure TestPrivateCaServerChainAcceptedWithHostRoots;
    procedure TestForeignHostRootDoesNotVouchForTheChain;
    procedure TestExpiredPrivateChainRefusedWithHostRoots;
    procedure TestCorruptSignatureRefusedWithHostRoots;
    procedure TestDistrustedCaRefusedBesideHostRoots;
    procedure TestLiveResolverTrustsHostRoots;
    procedure TestFactorySourceReadsOsDistrustBesideHostRoots;
    procedure TestFactorySourceRefusesHostRootsWithoutProvider;
    procedure TestFactorySourceIsTheOsSource;
    procedure TestFactoryClientSourceIsTheOsSource;
    procedure TestDefaultModeTrustsHostRootsThroughTheOsEngine;
    procedure TestHostRootsTrustsThePrivateLeaf;
    procedure TestHostRootsRefusesAForeignRoot;
    procedure TestHostRootsRefusesAnOsRootedChainInline;
    procedure TestHostRootsRefusesAnOsRootedChainLive;
    procedure TestLiveResolverHostRootsTrustsThePrivateLeaf;
    procedure TestLiveResolverOsRootsRefusesThePrivateLeaf;
    procedure TestHostRootsSourceCarriesTheHostRootAsTheOnlyAnchor;
    procedure TestHostRootsSourceReadsTheOsDistrustList;
    procedure TestHostRootsRefusesAPathThroughADistrustedCertificate;
    procedure TestDefaultModeHostRootsYieldsASourceWithAnchors;
    procedure TestWithLiveSystemTrustCarriesTheHostRoots;
    procedure TestInstallerTrustsItsExtraAnchorsWithTheOsRoots;
    procedure TestDistrustStoreIsTheDisallowedList;
  end;

{$ENDIF TLSLIB_MSWINDOWS}

{$IFDEF TLSLIB_MACOS}

  /// <summary>macOS (SecTrust settings) instantiation. Registered only on TLSLIB_MACOS - iOS is
  /// delegate-only with no enumerable anchor store, so it is deliberately excluded.</summary>
  TTestMacOSSystemTrust = class(TSystemTrustAnchorContractTestBase)
  strict protected
    function CreateAnchorStore: ITrustAnchorStore; override;
    function PlatformName: string; override;
  end;

  /// <summary>Behavioural tests for the macOS/iOS OS client-certificate delegate against a
  /// self-contained private CA. The exclusive trust root (anchors-only) is fully controllable, so
  /// unlike the server delegate these are hermetic: they prove the exclusive-root restriction, the
  /// injected clock and the revocation posture over Security.framework's real SecTrust engine.
  /// Registered on macOS (the shared macOS/iOS code path; iOS has no CI runner).</summary>
  TTestAppleClientDelegate = class(TTlsLibAlgorithmTestCase)
  strict private
    FChain: TStringList;    // ClientAuthChain fields (private CA + dual-EKU leaf)
    FForeign: TStringList;  // an unrelated private root
    function Leaf: TArray<TBytes>;
    function OwnAnchor: TArray<TBytes>;
    function ForeignAnchor: TArray<TBytes>;
    // the full set of advertised schemes a stock config offers (the EC leaf's scheme is in it)
    function Advertised: TArray<UInt16>;
    function Verify(const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      const AClock: ITlsClock; out AAlert: TTlsAlertDescription): Boolean;
    function VerifyPolicy(const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      const AClock: ITlsClock; const AStrength: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestAcceptsClientChainToConfiguredAnchor;
    procedure TestRejectsClientChainToForeignAnchor;
    procedure TestInjectedClockRejectsChainOutsideValidity;
    procedure TestHardPostureRejectsUnrevocableChain;
    procedure TestSoftPostureAcceptsUnrevocableChain;
    procedure TestRejectsUnadvertisedLeafScheme;
    procedure TestRejectsLeafOnDisallowedCurve;
  end;

  /// <summary>The macOS OS server delegate with host roots trusted alone, against a self-contained
  /// private CA: the engine declares the exclusive server roots, and the chain is judged against
  /// the host root only.</summary>
  TTestAppleHostRoots = class(TTlsLibAlgorithmTestCase)
  strict private
    FChain: TStringList;    // PrivateServerChain fields (private CA + serverAuth-only leaf)
    FForeign: TStringList;  // an unrelated private root
    function VerifyAlone(const ARoot: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestEngineDeclaresExclusiveServerAnchors;
    procedure TestHostRootsTrustsThePrivateLeaf;
    procedure TestHostRootsRefusesAForeignRoot;
  end;

{$ENDIF TLSLIB_MACOS}

{$IFDEF TLSLIB_ANDROID}

  /// <summary>The Java trust-manager rejection classification, from the exception facts alone: only
  /// a path-validation cause at index -1 naming the missing trust anchor is NoTrustAnchor.</summary>
  TTestJavaTrustClassifier = class(TTlsLibAlgorithmTestCase)
  strict private
    function Facts(ACertificateException, ATimeInvalid, APathValidatorCause: Boolean;
      ACauseIndex: Int32; const ACauseMessage: string): TJavaTrustFacts;
    procedure CheckClass(const AFacts: TJavaTrustFacts; AExpectedAlert: TTlsAlertDescription;
      AExpectedFailure: TPlatformChainFailure; const AName: string);
  published
    procedure TestNoTrustAnchorShapeIsNoTrustAnchor;
    procedure TestPathDoesNotChainMessageIsNoTrustAnchor;
    procedure TestInvalidSignatureReasonIsDecryptError;
    procedure TestSignatureCheckFailedMessageIsDecryptError;
    procedure TestOlderPlatformSignatureMessageIsDecryptError;
    procedure TestCriticalExtensionMessageIsCertificateUnknown;
    procedure TestUnrecognizedCriticalExtensionReasonIsCertificateUnknown;
    procedure TestInvalidNameReasonIsCertificateUnknown;
    procedure TestSubtreeCheckMessageIsCertificateUnknown;
    procedure TestNameConstraintsCheckFailedMessageIsCertificateUnknown;
    procedure TestMissingAnchorOutranksASignatureReason;
    procedure TestOtherReasonWithUnrelatedMessageIsOther;
    procedure TestCriticalExtensionWithoutPathValidatorCauseIsOther;
    procedure TestTimeInvalidOutranksInvalidSignature;
    procedure TestPinFailureWithoutCauseIsOther;
    procedure TestPathFailureAtACertificateIndexIsOther;
    procedure TestUnrelatedPathMessageIsOther;
    procedure TestTimeInvalidIsOtherEvenWithAnAnchorCause;
    procedure TestCauseOtherThanPathValidatorIsOther;
    procedure TestDomainScopedNoAnchorIsFinal;
    procedure TestDomainScopedPinFailureIsUnchanged;
    procedure TestNonCertificateExceptionIsInternalError;
  end;

{$ENDIF TLSLIB_ANDROID}

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}

  /// <summary>Desktop/server Unix (real /etc/ssl/certs et al.) instantiation. Registered only on
  /// the filesystem-harvest targets; a bare box with no ca-certificates is tolerated (skips).</summary>
  TTestUnixSystemTrust = class(TSystemTrustAnchorContractTestBase)
  strict protected
    function CreateAnchorStore: ITrustAnchorStore; override;
    function PlatformName: string; override;
    function RequiresPopulatedStore: Boolean; override;
  end;

  /// <summary>An ordinary (non-setuid) process must probe as not-elevated - which also
  /// confirms the runtime identity lookup resolves, since it fails closed to elevated.</summary>
  TTestPosixPrivilege = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestUnprivilegedProcessIsNotElevated;
  end;

  TPosixSetenvFunc = function(AName, AValue: PAnsiChar; AOverwrite: Integer): Integer; cdecl;
  TPosixUnsetenvFunc = function(AName: PAnsiChar): Integer; cdecl;
  TPosixGetenvFunc = function(AName: PAnsiChar): PAnsiChar; cdecl;
  TPosixEnviron = ^PPAnsiChar;

  /// <summary>The Unix harvest with SSL_CERT_FILE / SSL_CERT_DIR naming nothing: the OS roots
  /// cannot be read, so Anchors with the OS roots fails closed, while Anchors over the host
  /// roots alone harvests nothing and builds. The process environment is restored after each
  /// test.</summary>
  TTestUnixAnchorsWithoutABundle = class(TTlsLibAlgorithmTestCase)
  strict private
    FSavedFile, FSavedDir: string;
    FFileWasSet, FDirWasSet: Boolean;
    FRoots: ITrustAnchorStore;
    FLibrary: NativeUInt;
    FSetenv: TPosixSetenvFunc;
    FUnsetenv: TPosixUnsetenvFunc;
    FGetenv: TPosixGetenvFunc;
{$IFDEF FPC}
    FEnviron: TPosixEnviron;
{$ENDIF FPC}
    /// <summary>Sets AName to AValue when AIsSet (an empty value stays set), else unsets it.</summary>
    procedure SetVariable(const AName: string; AIsSet: Boolean; const AValue: string);
    function IsVariableSet(const AName: string): Boolean;
    /// <summary>Points both overrides at nothing; False (the test is skipped) when the process is
    /// elevated, which ignores them.</summary>
    function PointAtNothing: Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestHostRootsBuildsWithoutAReadableBundle;
    procedure TestOsAndHostRootsFailsClosedWithoutAReadableBundle;
    procedure TestOsRootsFailsClosedWithoutAReadableBundle;
  end;

{$IFEND}

implementation

type
  /// <summary>A probe over the abstract root source that drives its shared FilterRoots helper
  /// directly, so the well-formed + de-dup filter both harvesters use is tested once.</summary>
  TFilterRootsProbe = class(TSystemRootSourceBase)
  strict private
  var
    FRoots: TArray<TBytes>;
    FDistrusted: TArray<TBytes>;
    FCollected: TArray<TBytes>;
  strict protected
    function HarvestRoots: TArray<TBytes>; override;
    function HarvestDistrusted: TArray<TBytes>; override;
    function CollectDistrusted: TArray<TBytes>; override;
    function SourceName: string; override;
  public
    function Filter(const ARaw: TArray<TBytes>): TArray<TBytes>;
    /// <summary>What a Snapshot of this probe harvests.</summary>
    procedure Harvests(const ARoots, ADistrusted: TArray<TBytes>);
    /// <summary>What ReadDistrusted of this probe collects before filtering.</summary>
    procedure Collects(const ADistrusted: TArray<TBytes>);
  end;

{ TTestDelegatePostChecks }

procedure TTestDelegatePostChecks.SetUp;
begin
  inherited SetUp;
  FClock := TSystemClock.Create as ITlsClock;
  FOcsp := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
  FEc := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
end;

function TTestDelegatePostChecks.Ocsp(const AName: string): TBytes;
begin
  Result := DecodeHex(FOcsp.Values[AName]);
end;

function TTestDelegatePostChecks.Ec(const AName: string): TBytes;
begin
  Result := DecodeHex(FEc.Values[AName]);
end;

function TTestDelegatePostChecks.OcspChain: TArray<TBytes>;
begin
  // leaf first, then its issuer (needed to authenticate the staple)
  Result := TArray<TBytes>.Create(Ocsp('leaf_cert'), Ocsp('issuer_cert'));
end;

procedure TTestDelegatePostChecks.TestRevokedStapleRejectsOverOsPath;
var
  LAlert: TTlsAlertDescription;
begin
  LAlert := TTlsAlertDescription.BadCertificate;
  CheckTrue(TDelegatePostChecks.RejectStapledRevoked(Pkix, FClock, OcspChain,
    Ocsp('ocsp_revoked'), LAlert), 'a definitive stapled Revoked always rejects');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestDelegatePostChecks.TestStapleOutcomeMapping;
begin
  // the one staple-to-outcome mapping RejectStapledRevoked and the delegate both read
  CheckEquals(Ord(TLiveRevocationOutcome.Good),
    Ord(TDelegatePostChecks.StapleOutcome(Pkix, FClock, OcspChain, Ocsp('ocsp_good'))),
    'a current good staple maps to Good');
  CheckEquals(Ord(TLiveRevocationOutcome.Revoked),
    Ord(TDelegatePostChecks.StapleOutcome(Pkix, FClock, OcspChain, Ocsp('ocsp_revoked'))),
    'a definitive revoked staple maps to Revoked');
  CheckEquals(Ord(TLiveRevocationOutcome.Indeterminate),
    Ord(TDelegatePostChecks.StapleOutcome(Pkix, FClock, OcspChain, Ocsp('ocsp_stale'))),
    'a stale staple is indeterminate');
  CheckEquals(Ord(TLiveRevocationOutcome.Indeterminate),
    Ord(TDelegatePostChecks.StapleOutcome(Pkix, FClock, OcspChain, nil)),
    'an absent staple is indeterminate');
  CheckEquals(Ord(TLiveRevocationOutcome.Indeterminate),
    Ord(TDelegatePostChecks.StapleOutcome(Pkix, FClock,
    TArray<TBytes>.Create(Ocsp('leaf_cert')), Ocsp('ocsp_revoked'))),
    'a leaf-only path cannot render a definitive outcome');
end;

procedure TTestDelegatePostChecks.TestGoodAndAbsentStapleDoNotFire;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(Pkix, FClock, OcspChain,
    Ocsp('ocsp_good'), LAlert), 'a current Good staple does not fire the Revoked post-check');
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(Pkix, FClock, OcspChain,
    nil, LAlert), 'an absent staple does not fire the Revoked post-check');
end;

procedure TTestDelegatePostChecks.TestStaleStapleIsNotRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  // a stale (out-of-window) response is indeterminate, not Revoked - the posture decides it, so
  // this post-check must not fire
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(Pkix, FClock, OcspChain,
    Ocsp('ocsp_stale'), LAlert), 'a stale staple is indeterminate, not Revoked');
end;

procedure TTestDelegatePostChecks.TestLeafOnlyPathIsNotRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  // with no issuer to authenticate the response, the verdict is indeterminate, not Revoked
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(Pkix, FClock,
    TArray<TBytes>.Create(Ocsp('leaf_cert')), Ocsp('ocsp_revoked'), LAlert),
    'a leaf-only path cannot render a definitive Revoked');
end;

procedure TTestDelegatePostChecks.TestNilClockFallsBackToSystemTime;
var
  LAlert: TTlsAlertDescription;
begin
  // a nil clock must not silently skip the check (it would otherwise make every staple
  // indeterminate); it falls back to system time
  CheckTrue(TDelegatePostChecks.RejectStapledRevoked(Pkix, nil, OcspChain,
    Ocsp('ocsp_revoked'), LAlert), 'a nil clock falls back to system time, still catching Revoked');
end;

procedure TTestDelegatePostChecks.TestNilProviderIsNotRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  // a nil provider cannot authenticate a response, so no definitive Revoked is rendered (the
  // delegates fail closed earlier, on the strength policy)
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(nil, FClock, OcspChain,
    Ocsp('ocsp_revoked'), LAlert), 'a nil provider cannot render a Revoked verdict');
end;

procedure TTestDelegatePostChecks.TestHardNeedsLiveRevocation;
begin
  // the delegate gate is the shared predicate: Hard is satisfied only when the live-revocation park runs
  CheckTrue(TRevocationDecision.HardNeedsLiveRevocation(TRevocationPosture.Hard, False),
    'Hard without the live-revocation park needs live revocation');
  CheckFalse(TRevocationDecision.HardNeedsLiveRevocation(TRevocationPosture.Hard, True),
    'Hard with the live-revocation park is satisfied');
  CheckFalse(TRevocationDecision.HardNeedsLiveRevocation(TRevocationPosture.Soft, False),
    'Soft never needs live revocation');
  CheckFalse(TRevocationDecision.HardNeedsLiveRevocation(TRevocationPosture.Off, False),
    'Off never needs live revocation');
end;

procedure TTestDelegatePostChecks.TestLiveNeedsLiveRevocation;
begin
  CheckTrue(TDelegatePostChecks.LiveNeedsLiveRevocation(TSystemTrustFetch.Live,
    TVerdictDeferral.None), 'a Live source with no deferral needs live revocation');
  CheckTrue(TDelegatePostChecks.LiveNeedsLiveRevocation(TSystemTrustFetch.Live,
    TVerdictDeferral.HostDecision), 'a Live source with a host-decision park still needs it');
  CheckFalse(TDelegatePostChecks.LiveNeedsLiveRevocation(TSystemTrustFetch.Live,
    TVerdictDeferral.LiveRevocation), 'a Live source with live revocation is satisfied');
  CheckFalse(TDelegatePostChecks.LiveNeedsLiveRevocation(TSystemTrustFetch.CacheOnly,
    TVerdictDeferral.None), 'a cache-only source never needs it');
end;

procedure TTestDelegatePostChecks.TestOsHostNameStripsIpLiterals;
begin
  CheckEquals('localhost', TDelegatePostChecks.OsHostName('localhost'),
    'a DNS host passes through');
  CheckEquals('', TDelegatePostChecks.OsHostName('127.0.0.1'),
    'an IPv4 literal is stripped');
  CheckEquals('', TDelegatePostChecks.OsHostName('[::1]'),
    'a bracketed IPv6 literal is stripped');
  CheckEquals('', TDelegatePostChecks.OsHostName(''),
    'an empty host passes through as empty');
  CheckEquals('', TDelegatePostChecks.OsHostName('127.0.0.1.'),
    'a trailing-dot IPv4 literal is still stripped');
end;

procedure TTestDelegatePostChecks.TestNameMismatchMatchesDnsLeaf;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  // the EC leaf carries DNS:localhost, so a matching DNS host does not fire
  CheckTrue(TServerName.TryParse('localhost', LName));
  CheckFalse(TDelegatePostChecks.RejectNameMismatch(LName, Pkix,
    TArray<TBytes>.Create(Ec('leaf_cert')), LAlert),
    'a DNS host matching a dNSName SAN is accepted');
end;

procedure TTestDelegatePostChecks.TestNameMismatchMatchesIpLeaf;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  // full RFC 9525 identity here also matches an iPAddress SAN
  CheckTrue(TServerName.TryParse('127.0.0.1', LName));
  CheckFalse(TDelegatePostChecks.RejectNameMismatch(LName, Pkix,
    TArray<TBytes>.Create(Ec('ipsan_leaf_cert')), LAlert),
    'an IP literal matching an iPAddress SAN is accepted');
end;

procedure TTestDelegatePostChecks.TestNameMismatchRejectsWrongName;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TServerName.TryParse('wrong.example', LName));
  CheckTrue(TDelegatePostChecks.RejectNameMismatch(LName, Pkix,
    TArray<TBytes>.Create(Ec('leaf_cert')), LAlert),
    'a host matching no SAN is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestDelegatePostChecks.TestNameMismatchEmptyNameIsNotChecked;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  LName := Default(TServerName);
  CheckFalse(TDelegatePostChecks.RejectNameMismatch(LName, Pkix,
    TArray<TBytes>.Create(Ec('leaf_cert')), LAlert),
    'an empty name never fires');
end;

procedure TTestDelegatePostChecks.TestNameMismatchNilProviderFailsClosed;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  // without a provider to read the SANs a non-empty name cannot be confirmed, so it fails closed
  CheckTrue(TServerName.TryParse('localhost', LName));
  CheckTrue(TDelegatePostChecks.RejectNameMismatch(LName, nil,
    TArray<TBytes>.Create(Ec('leaf_cert')), LAlert),
    'a nil provider fails closed');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the fail-closed alert is bad_certificate');
end;

{ TFilterRootsProbe }

function TFilterRootsProbe.HarvestRoots: TArray<TBytes>;
begin
  Result := FRoots;
end;

function TFilterRootsProbe.HarvestDistrusted: TArray<TBytes>;
begin
  Result := FDistrusted;
end;

function TFilterRootsProbe.CollectDistrusted: TArray<TBytes>;
begin
  Result := FCollected;
end;

procedure TFilterRootsProbe.Harvests(const ARoots, ADistrusted: TArray<TBytes>);
begin
  FRoots := ARoots;
  FDistrusted := ADistrusted;
end;

procedure TFilterRootsProbe.Collects(const ADistrusted: TArray<TBytes>);
begin
  FCollected := ADistrusted;
end;

function TFilterRootsProbe.SourceName: string;
begin
  Result := 'probe';
end;

function TFilterRootsProbe.Filter(const ARaw: TArray<TBytes>): TArray<TBytes>;
begin
  Result := FilterRoots(ARaw);
end;

{ TTestOSDelegateTemplate }

procedure TTestOSDelegateTemplate.SetUp;
begin
  inherited SetUp;
  FClock := TSystemClock.Create as ITlsClock;
  FOcsp := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
end;

function TTestOSDelegateTemplate.Ocsp(const AName: string): TBytes;
begin
  Result := DecodeHex(FOcsp.Values[AName]);
end;

function TTestOSDelegateTemplate.VerifyEnginePath(const AChain, APath,
  AExempt: TArray<TBytes>; const AStrength: TCertificateStrengthPolicy;
  const ACallback: TTlsCertificateVerifyCallback; out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LEngine: IPlatformChainEngine;
  LResult: TPlatformChainResult;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
begin
  LResult := Default(TPlatformChainResult);
  LResult.Outcome := TLiveRevocationOutcome.Good;
  LResult.Path := APath;
  LResult.PolicyExempt := AExempt;
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True, LResult, TTlsAlertDescription.BadCertificate);
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.StrengthPolicy := AStrength;
  LPolicy.Dangerous.VerifyCallback := ACallback;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(AChain, TServerName.DnsName('localhost'), nil,
    AVerified, AAlert);
end;

function TTestOSDelegateTemplate.ResolveLiveEnginePath(const AChain, APath,
  AExempt: TArray<TBytes>; const AStrength: TCertificateStrengthPolicy;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LEngine: IPlatformChainEngine;
  LResult: TPlatformChainResult;
  LPolicy: TOSDelegatePolicy;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
begin
  LResult := Default(TPlatformChainResult);
  LResult.Outcome := TLiveRevocationOutcome.Good;
  LResult.Path := APath;
  LResult.PolicyExempt := AExempt;
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    LResult, TTlsAlertDescription.BadCertificate);
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.Live,
    TVerdictDeferral.LiveRevocation, nil);
  LPolicy.StrengthPolicy := AStrength;
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server, LPolicy, nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := AChain;
    LContext.HostName := 'localhost';
    Result := LResolver.ResolveVerdict(LContext, AAlert);
  finally
    LResolver.Free;
  end;
end;

function TTestOSDelegateTemplate.VerifyClientEnginePath(const AChain, APath,
  AAnchors: TArray<TBytes>; out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LEngine: IPlatformChainEngine;
  LResult: TPlatformChainResult;
  LVerifier: IClientCertificateVerifier;
begin
  LResult := Default(TPlatformChainResult);
  LResult.Outcome := TLiveRevocationOutcome.Indeterminate;
  LResult.Path := APath;
  LEngine := TMockPlatformChainEngine.Create([], True, LResult, TTlsAlertDescription.BadCertificate);
  LVerifier := TOSDelegateClientVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, AAnchors))
    as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(AChain, AVerified, AAlert);
end;

function TTestOSDelegateTemplate.OcspChain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(Ocsp('leaf_cert'), Ocsp('issuer_cert'));
end;

function TTestOSDelegateTemplate.Result_(AOutcome: TLiveRevocationOutcome;
  const APath: TArray<TBytes>): TPlatformChainResult;
begin
  Result := Default(TPlatformChainResult);
  Result.Outcome := AOutcome;
  Result.Path := APath;
  // exempt the whole path so the strength policy is a no-op here; the strength gate itself is
  // covered hermetically by the real-engine delegate tests
  Result.PolicyExempt := APath;
end;

function TTestOSDelegateTemplate.Policy(APosture: TRevocationPosture;
  AFetch: TSystemTrustFetch; ADeferral: TVerdictDeferral;
  const AAnchors: TArray<TBytes>): TOSDelegatePolicy;
begin
  Result := Default(TOSDelegatePolicy);
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.Pkix := Pkix;
  Result.Clock := FClock;
  Result.Posture := APosture;
  Result.Fetch := AFetch;
  Result.Deferral := ADeferral;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  // the leaf is always strength-checked, so advertise the stock scheme set its signature is in
  Result.AdvertisedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
    TSignatureSchemes.EcdsaSecp384r1Sha384, TSignatureSchemes.EcdsaSecp521r1Sha512,
    TSignatureSchemes.RsaPssRsaeSha256, TSignatureSchemes.RsaPssRsaeSha384,
    TSignatureSchemes.RsaPssRsaeSha512, TSignatureSchemes.RsaPkcs1Sha256,
    TSignatureSchemes.RsaPkcs1Sha384, TSignatureSchemes.RsaPkcs1Sha512);
  // these are server-cert templates: the host is matched, as a stock client config does
  Result.CheckHostName := True;
  // the delegate matches the leaf SANs itself (SAN-only) even for a DnsIdentity engine, so the
  // templates use the fixture leaf's real identity (SAN dNSName = localhost)
  Result.Anchors := AAnchors;
end;

procedure TTestOSDelegateTemplate.TestRequestShapingRevocationLevels;

  function Level(APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
    ADeferral: TVerdictDeferral): TPlatformRevocationCheck;
  var
    LFake: TMockPlatformChainEngine;
    LEngine: IPlatformChainEngine;
    LVerifier: IServerCertificateVerifier;
    LVerified: TVerifiedChain;
    LAlert: TTlsAlertDescription;
  begin
    LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
      Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
    LEngine := LFake;
    LVerifier := TOSDelegateServerVerifier.Create(LEngine,
      Policy(APosture, AFetch, ADeferral, nil)) as IServerCertificateVerifier;
    LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
      LVerified, LAlert);
    Result := LFake.Last.Revocation;
  end;

begin
  CheckEquals(Ord(TPlatformRevocationCheck.None),
    Ord(Level(TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None)),
    'Off asks for no revocation processing');
  CheckEquals(Ord(TPlatformRevocationCheck.BestEffort),
    Ord(Level(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None)),
    'Soft asks for best-effort revocation');
  CheckEquals(Ord(TPlatformRevocationCheck.RequirePositive),
    Ord(Level(TRevocationPosture.Hard, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None)),
    'Hard decided inline requires a positive response');
  CheckEquals(Ord(TPlatformRevocationCheck.BestEffort),
    Ord(Level(TRevocationPosture.Hard, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation)),
    'Hard deferred to a live check runs best-effort inline');
  CheckEquals(Ord(TPlatformRevocationCheck.BestEffort),
    Ord(Level(TRevocationPosture.Hard, TSystemTrustFetch.CacheOnly, TVerdictDeferral.LiveRevocation)),
    'Hard with the live verdict armed runs best-effort inline');
end;

procedure TTestOSDelegateTemplate.TestRequestNetworkNotAllowedInline;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert);
  CheckEquals(1, LFake.ServerCalls, 'the engine was consulted exactly once');
  CheckFalse(LFake.Last.NetworkAllowed, 'the inline pass never allows a network fetch');
end;

procedure TTestOSDelegateTemplate.TestClientRequestCarriesAnchors;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateClientVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, OcspChain))
    as IClientCertificateVerifier;
  LVerifier.VerifyClientCertificate(OcspChain, LVerified, LAlert);
  CheckEquals(2, System.Length(LFake.Last.Anchors), 'the client path carries the exclusive anchors');
  CheckTrue(LFake.Last.ServerName.IsEmpty, 'the client path has no server identity');
  CheckEquals(1, LFake.ClientCalls, 'the client engine method ran');
  CheckEquals(0, LFake.ServerCalls, 'the server engine method did not run');
end;

procedure TTestOSDelegateTemplate.TestRequestCarriesConfiguredIntermediates;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LServer: IServerCertificateVerifier;
  LClient: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None,
    OcspChain);
  LPolicy.Intermediates := OcspChain;
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LServer := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  LServer.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil, LVerified,
    LAlert);
  CheckEquals(System.Length(OcspChain), System.Length(LFake.Last.Intermediates),
    'the server request carries the configured intermediates');
  LClient := TOSDelegateClientVerifier.Create(LEngine, LPolicy) as IClientCertificateVerifier;
  LClient.VerifyClientCertificate(OcspChain, LVerified, LAlert);
  CheckEquals(System.Length(OcspChain), System.Length(LFake.Last.Intermediates),
    'the client request carries the configured intermediates');
end;

procedure TTestOSDelegateTemplate.TestPolicyFromContextCarriesIntermediates;
var
  LServer: TServerTrustContext;
  LClient: TClientTrustContext;
begin
  LServer := Default(TServerTrustContext);
  LServer.Intermediates := OcspChain;
  CheckEquals(System.Length(OcspChain), System.Length(
    TOSDelegatePolicy.FromServerContext(LServer, TSystemTrustFetch.CacheOnly).Intermediates),
    'the server policy keeps the configured intermediates');
  LClient := Default(TClientTrustContext);
  LClient.Intermediates := OcspChain;
  CheckEquals(System.Length(OcspChain), System.Length(
    TOSDelegatePolicy.FromClientContext(LClient, TSystemTrustFetch.CacheOnly).Intermediates),
    'the client policy keeps the configured intermediates');
end;

procedure TTestOSDelegateTemplate.TestClientDistrustedPathIsRefused;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LClient: TClientTrustContext;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None,
    OcspChain);
  LPolicy.CheckHostName := False;
  LPolicy.Distrusted := TArray<TBytes>.Create(Ocsp('issuer_cert'));
  LVerifier := TOSDelegateClientVerifier.Create(LEngine, LPolicy) as IClientCertificateVerifier;
  CheckFalse(LVerifier.VerifyClientCertificate(OcspChain, LVerified, LAlert),
    'a client path through a distrusted certificate is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
  LPolicy.Distrusted := TArray<TBytes>.Create(Ocsp('other_ca_cert'));
  LVerifier := TOSDelegateClientVerifier.Create(LEngine, LPolicy) as IClientCertificateVerifier;
  CheckTrue(LVerifier.VerifyClientCertificate(OcspChain, LVerified, LAlert),
    'a distrusted certificate off the path changes nothing');
  LClient := Default(TClientTrustContext);
  LClient.TrustStore := TTrustAnchorStore.Create(nil, TArray<TBytes>.Create(Ocsp('issuer_cert')))
    as ITrustAnchorStore;
  CheckEquals(1, System.Length(
    TOSDelegatePolicy.FromClientContext(LClient, TSystemTrustFetch.CacheOnly).Distrusted),
    'the client policy carries the client-CA store''s distrust list');
end;

function TTestOSDelegateTemplate.ClientVerify(const AChain, AIntermediates: TArray<TBytes>;
  AReturns: Boolean; AEngineAlert: TTlsAlertDescription; out AFake: TMockPlatformChainEngine;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LPolicy: TOSDelegatePolicy;
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  // an engine that reports only the leaf as the path (Android) cannot trip the path post-check
  AFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], AReturns,
    Result_(TLiveRevocationOutcome.Good, TArray<TBytes>.Create(Ocsp('leaf_cert'))), AEngineAlert);
  FEngineHold := AFake;
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None,
    OcspChain);
  LPolicy.CheckHostName := False;
  LPolicy.Intermediates := AIntermediates;
  LPolicy.Distrusted := TArray<TBytes>.Create(Ocsp('issuer_cert'));
  LVerifier := TOSDelegateClientVerifier.Create(FEngineHold, LPolicy) as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(AChain, LVerified, AAlert);
end;

procedure TTestOSDelegateTemplate.TestClientDistrustedChainEntryIsWithheldFromTheEngine;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ClientVerify(OcspChain, nil, True, TTlsAlertDescription.UnknownCa, LFake, LAlert),
    'the leaf alone validates');
  CheckEquals(1, System.Length(LFake.Last.Chain), 'the distrusted chain entry is not presented');
end;

procedure TTestOSDelegateTemplate.TestClientDistrustedIntermediateIsWithheldFromTheEngine;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ClientVerify(TArray<TBytes>.Create(Ocsp('leaf_cert')),
    TArray<TBytes>.Create(Ocsp('issuer_cert')), True, TTlsAlertDescription.UnknownCa, LFake,
    LAlert), 'the leaf alone validates');
  CheckEquals(0, System.Length(LFake.Last.Intermediates), 'the configured candidate is withheld');
end;

procedure TTestOSDelegateTemplate.TestClientWithheldChainEntryWithNoAnchorIsBadCertificate;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ClientVerify(OcspChain, nil, False, TTlsAlertDescription.UnknownCa, LFake, LAlert),
    'the engine finds no path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'built-in parity once a chain entry was withheld');
end;

procedure TTestOSDelegateTemplate.TestClientWithheldIntermediateWithNoAnchorIsBadCertificate;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ClientVerify(TArray<TBytes>.Create(Ocsp('leaf_cert')),
    TArray<TBytes>.Create(Ocsp('issuer_cert')), False, TTlsAlertDescription.UnknownCa, LFake,
    LAlert), 'the engine finds no path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'built-in parity once a configured intermediate was withheld');
end;

procedure TTestOSDelegateTemplate.TestClientNothingWithheldKeepsTheEngineAlert;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ClientVerify(TArray<TBytes>.Create(Ocsp('leaf_cert')), nil, False,
    TTlsAlertDescription.UnknownCa, LFake, LAlert), 'the engine finds no path');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'nothing was withheld, so it is a genuine unknown CA');
end;

procedure TTestOSDelegateTemplate.TestClientWithheldWithAnotherFailureKeepsTheEngineAlert;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ClientVerify(OcspChain, nil, False, TTlsAlertDescription.CertificateExpired, LFake,
    LAlert), 'the engine rejects the leaf');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'an expired leaf stays certificate_expired');
end;

function TTestOSDelegateTemplate.LiveClientResolve(const AChain, AIntermediates: TArray<TBytes>;
  AReturns: Boolean; AEngineAlert: TTlsAlertDescription; out AFake: TMockPlatformChainEngine;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LPolicy: TOSDelegatePolicy;
begin
  AFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], AReturns,
    Result_(TLiveRevocationOutcome.Good, TArray<TBytes>.Create(Ocsp('leaf_cert'))), AEngineAlert);
  FEngineHold := AFake;
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation,
    OcspChain);
  LPolicy.Intermediates := AIntermediates;
  LPolicy.Distrusted := TArray<TBytes>.Create(Ocsp('issuer_cert'));
  LResolver := TOSDelegateLiveResolver.Create(FEngineHold, TPeerRole.Client, LPolicy, nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Client;
    LContext.Chain := AChain;
    Result := LResolver.ResolveVerdict(LContext, AAlert);
  finally
    LResolver.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestLiveClientWithheldChainEntryWithNoAnchorIsBadCertificate;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(LiveClientResolve(OcspChain, nil, False, TTlsAlertDescription.UnknownCa, LFake, LAlert),
    'the engine finds no path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'built-in parity once a chain entry was withheld');
end;

procedure TTestOSDelegateTemplate.TestLiveClientWithheldIntermediateWithNoAnchorIsBadCertificate;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(LiveClientResolve(TArray<TBytes>.Create(Ocsp('leaf_cert')),
    TArray<TBytes>.Create(Ocsp('issuer_cert')), False, TTlsAlertDescription.UnknownCa, LFake,
    LAlert), 'the engine finds no path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'built-in parity once a configured intermediate was withheld');
end;

procedure TTestOSDelegateTemplate.TestLiveClientNothingWithheldKeepsTheEngineAlert;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(LiveClientResolve(TArray<TBytes>.Create(Ocsp('leaf_cert')), nil, False,
    TTlsAlertDescription.UnknownCa, LFake, LAlert), 'the engine finds no path');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'nothing was withheld, so it is a genuine unknown CA');
end;

procedure TTestOSDelegateTemplate.TestLiveClientWithheldWithAnotherFailureKeepsTheEngineAlert;
var
  LFake: TMockPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(LiveClientResolve(OcspChain, nil, False, TTlsAlertDescription.CertificateExpired,
    LFake, LAlert), 'the engine rejects the leaf');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'an expired leaf stays certificate_expired');
end;

procedure TTestOSDelegateTemplate.TestLiveClientResolverRefusesDistrustedPath;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LPolicy: TOSDelegatePolicy;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation,
    OcspChain);
  LPolicy.Distrusted := TArray<TBytes>.Create(Ocsp('issuer_cert'));
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Client, LPolicy, nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Client;
    LContext.Chain := OcspChain;
    CheckFalse(LResolver.ResolveVerdict(LContext, LAlert),
      'the live client pass refuses a path through a distrusted certificate');
    CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
  finally
    LResolver.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestLiveClientResolverWithholdsDistrustedIntermediate;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LPolicy: TOSDelegatePolicy;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    Result_(TLiveRevocationOutcome.Good, TArray<TBytes>.Create(Ocsp('leaf_cert'))),
    TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation,
    OcspChain);
  LPolicy.Intermediates := TArray<TBytes>.Create(Ocsp('issuer_cert'));
  LPolicy.Distrusted := TArray<TBytes>.Create(Ocsp('issuer_cert'));
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Client, LPolicy, nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Client;
    LContext.Chain := OcspChain;
    CheckTrue(LResolver.ResolveVerdict(LContext, LAlert), 'the leaf alone is trusted live');
    CheckEquals(1, System.Length(LFake.Last.Chain), 'the live pass withholds the chain entry');
    CheckEquals(0, System.Length(LFake.Last.Intermediates), 'and the configured candidate');
  finally
    LResolver.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestEmptyChainIsRefusedBeforeTheEngine;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LServer: IServerCertificateVerifier;
  LClient: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // with configured intermediates an empty peer chain must not leave one of them to be judged as
  // the peer's certificate
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None,
    OcspChain);
  LPolicy.Intermediates := OcspChain;
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LServer := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckFalse(LServer.VerifyServerCertificate(nil, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'the server path refuses an empty chain');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'server alert');
  LClient := TOSDelegateClientVerifier.Create(LEngine, LPolicy) as IClientCertificateVerifier;
  CheckFalse(LClient.VerifyClientCertificate(nil, LVerified, LAlert),
    'the client path refuses an empty chain');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'client alert');
  CheckEquals(0, LFake.ServerCalls + LFake.ClientCalls, 'the engine never saw the empty chain');
end;

procedure TTestOSDelegateTemplate.TestEngineFailurePassesAlertThrough;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.DnsIdentity],
    False, Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.UnknownCa);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'an engine rejection rejects');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the engine alert passes through');
  CheckEquals(0, System.Length(LVerified.Path), 'a rejection leaves the verified path empty');
end;

procedure TTestOSDelegateTemplate.TestAcceptFillsTrustedPath;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.DnsIdentity],
    True, Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckTrue(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'a trusted Good path is accepted');
  CheckEquals(2, System.Length(LVerified.Path), 'the built path is returned');
  CheckEquals(Ord(TVerificationOutcome.Trusted), Ord(LVerified.Outcome),
    'the outcome is Trusted (the live park still runs for a delegate)');
end;

procedure TTestOSDelegateTemplate.TestStapledRevokedOverridesUnderOff;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // engine says Good, but a definitive stapled Revoked wins under every posture, including Off
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.DnsIdentity],
    True, Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'),
    Ocsp('ocsp_revoked'), LVerified, LAlert), 'a stapled Revoked overrides an engine Good under Off');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert), 'the alert is certificate_revoked');
end;

procedure TTestOSDelegateTemplate.TestEngineRevokedRejects;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.DnsIdentity],
    True, Result_(TLiveRevocationOutcome.Revoked, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'an engine Revoked outcome rejects');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert), 'the alert is certificate_revoked');
end;

procedure TTestOSDelegateTemplate.TestHardIndeterminateRejectsCacheOnly;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.DnsIdentity],
    True, Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Hard, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'Hard rejects an indeterminate cache-only outcome');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOSDelegateTemplate.TestHardIndeterminateAcceptsWhenDeferred;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // Hard whose indeterminate case defers to the live park accepts inline (effective Soft)
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.DnsIdentity,
    TPlatformChainCapability.LiveFetch],
    True, Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Hard, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation, nil))
    as IServerCertificateVerifier;
  CheckTrue(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'Hard deferred to a live check accepts an indeterminate outcome inline');
end;

procedure TTestOSDelegateTemplate.TestHardIndeterminateAcceptsCacheOnlyWhenLiveVerdictArmed;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // the armed live verdict parks the handshake, so a cache-only indeterminate is not rejected inline
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.DnsIdentity],
    True, Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Hard, TSystemTrustFetch.CacheOnly, TVerdictDeferral.LiveRevocation, nil))
    as IServerCertificateVerifier;
  CheckTrue(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'Hard with the live verdict armed defers a cache-only indeterminate to the park');
end;

procedure TTestOSDelegateTemplate.TestNameMismatchRejectsWithoutDnsCapability;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // no DnsIdentity capability: the library matches the full identity here, so a wrong host rejects
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation],
    True, Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('wrong.example'), nil,
    LVerified, LAlert), 'a wrong host is rejected when the engine matches no identity itself');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestOSDelegateTemplate.TestNameMismatchRejectsWithDnsCapability;
var
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // a DnsIdentity engine matched the host itself, but the library now matches the SANs too (SAN-only,
  // no subject-CN fallback), so a wrong host is rejected here rather than trusted - this is the only
  // test that fails without the S2 change
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('wrong.example'), nil,
    LVerified, LAlert), 'a DnsIdentity engine no longer excuses a SAN mismatch');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestOSDelegateTemplate.TestMustStapleLeafWithoutStapleRejects;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LChain: TArray<TBytes>;
begin
  // a must-staple leaf whose client asked to staple on the initial handshake, but no staple was
  // presented, must be rejected even under Soft (RFC 7633 4.3.3 for the client-asked rule; the
  // initial-handshake and server-certificate scoping is library policy) - the delegate enforces it now
  LChain := TArray<TBytes>.Create(Ocsp('muststaple_leaf_cert'), Ocsp('issuer_cert'));
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True, Result_(TLiveRevocationOutcome.Good, LChain),
    TTlsAlertDescription.BadCertificate);
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.StatusRequestOffered := True;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'a must-staple leaf with no staple is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOSDelegateTemplate.TestMustStapleLeafWithGoodStapleAccepts;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LChain: TArray<TBytes>;
begin
  // the same must-staple leaf with a current Good staple satisfies the requirement and is accepted
  LChain := TArray<TBytes>.Create(Ocsp('muststaple_leaf_cert'), Ocsp('issuer_cert'));
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True, Result_(TLiveRevocationOutcome.Good, LChain),
    TTlsAlertDescription.BadCertificate);
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.StatusRequestOffered := True;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckTrue(LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'),
    Ocsp('ocsp_muststaple_good'), LVerified, LAlert),
    'a must-staple leaf with a Good staple is accepted');
end;

procedure TTestOSDelegateTemplate.TestMustStapleNotBoundWhenNotOfferedOrOnResumption;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LChain: TArray<TBytes>;
begin
  // must-staple binds only when the client offered status_request on the initial handshake: a client
  // that did not offer it, or a resumption, does not demand a staple from a must-staple leaf
  LChain := TArray<TBytes>.Create(Ocsp('muststaple_leaf_cert'), Ocsp('issuer_cert'));
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True, Result_(TLiveRevocationOutcome.Good, LChain),
    TTlsAlertDescription.BadCertificate);
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.StatusRequestOffered := False;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckTrue(LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'must-staple does not bind when the client did not offer status_request');

  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.StatusRequestOffered := True;
  LPolicy.Occasion := TVerificationOccasion.Resumption;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckTrue(LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'must-staple does not bind on a resumption');
end;

procedure TTestOSDelegateTemplate.TestMalformedTlsFeatureRejectsBothRoles;
var
  LServerEngine, LClientEngine: IPlatformChainEngine;
  LServerPolicy, LClientPolicy: TOSDelegatePolicy;
  LServerVerifier: IServerCertificateVerifier;
  LClientVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LChain: TArray<TBytes>;
begin
  // a malformed TLS Feature extension (value not a SEQUENCE OF INTEGER) is a hard bad_certificate for
  // either role, regardless of posture or whether status_request was offered
  LChain := TArray<TBytes>.Create(Ocsp('badfeature_leaf_cert'), Ocsp('issuer_cert'));
  LServerEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True, Result_(TLiveRevocationOutcome.Good, LChain),
    TTlsAlertDescription.BadCertificate);
  LServerPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly,
    TVerdictDeferral.None, nil);
  LServerVerifier := TOSDelegateServerVerifier.Create(LServerEngine, LServerPolicy)
    as IServerCertificateVerifier;
  CheckFalse(LServerVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'a malformed TLS Feature rejects on the server path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');

  LClientEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation],
    True, Result_(TLiveRevocationOutcome.Good, LChain), TTlsAlertDescription.BadCertificate);
  LClientPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly,
    TVerdictDeferral.None, nil);
  LClientPolicy.CheckHostName := False;
  LClientVerifier := TOSDelegateClientVerifier.Create(LClientEngine, LClientPolicy)
    as IClientCertificateVerifier;
  CheckFalse(LClientVerifier.VerifyClientCertificate(LChain, LVerified, LAlert),
    'a malformed TLS Feature rejects on the client path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestOSDelegateTemplate.TestServerSourceEnforcesMustStaple;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LContext: TServerTrustContext;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LChain: TArray<TBytes>;
begin
  // the source copies StatusRequestOffered + Occasion from the context into the delegate policy, so a
  // config that offered stapling enforces must-staple on the OS-delegate path (regression guard)
  LChain := TArray<TBytes>.Create(Ocsp('muststaple_leaf_cert'), Ocsp('issuer_cert'));
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True, Result_(TLiveRevocationOutcome.Good, LChain),
    TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IServerCertificateVerifierSource;
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Clock := FClock;
  LContext.CheckHostName := True;
  LContext.RevocationPosture := TRevocationPosture.Soft;
  LContext.Deferral := TVerdictDeferral.None;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
  LContext.StatusRequestOffered := True;
  LContext.Occasion := TVerificationOccasion.InitialHandshake;
  LVerifier := LSource.CreateServerVerifier(LContext);
  CheckFalse(LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'the source enforces must-staple from the context');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestOSDelegateTemplate.TestSourceRefusesLiveWithoutLiveFetch;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LRaised: Boolean;
begin
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LRaised := False;
  try
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.Live,
      TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IServerCertificateVerifierSource;
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a Live source over an engine without live fetch is refused at construction');
end;

procedure TTestOSDelegateTemplate.TestServerSourceRefusesLiveWithoutVerdict;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LContext: TServerTrustContext;
  LRaised: Boolean;
begin
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.LiveFetch],
    False, Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.Live,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IServerCertificateVerifierSource;
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Deferral := TVerdictDeferral.None;
  LRaised := False;
  try
    LSource.CreateServerVerifier(LContext);
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a Live fetch without the live-revocation verdict is refused at verifier creation');
end;

procedure TTestOSDelegateTemplate.TestServerSourceCarriesExtraAnchorsToTheEngine;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LContext: TServerTrustContext;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LChain: TArray<TBytes>;
begin
  LChain := TArray<TBytes>.Create(Ocsp('muststaple_leaf_cert'), Ocsp('issuer_cert'));
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.NativeAnchorUnion,
    TPlatformChainCapability.DnsIdentity], False, Result_(TLiveRevocationOutcome.Good, LChain),
    TTlsAlertDescription.UnknownCa);
  LEngine := LMock;
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, TArray<TBytes>.Create(Ocsp('issuer_cert')), nil)
    as IServerCertificateVerifierSource;
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Clock := FClock;
  LContext.CheckHostName := True;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LVerifier := LSource.CreateServerVerifier(LContext);
  LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil, LVerified,
    LAlert);
  CheckEquals(1, System.Length((LSource as TOSVerifierSource).ExtraAnchors),
    'the source exposes its extras for the live re-check');
  CheckEquals(1, System.Length(LMock.Last.ExtraAnchors), 'the engine is handed the extra anchor');
  CheckEquals(0, System.Length(LMock.Last.Anchors),
    'the extra anchors do not become the exclusive trust root');
end;

procedure TTestOSDelegateTemplate.TestClientSourceRefusesHardWithoutCachedRevocation;
var
  LEngine: IPlatformChainEngine;
  LSource: IClientCertificateVerifierSource;
  LContext: TClientTrustContext;
  LRaised: Boolean;
begin
  // an engine that renders no cached revocation outcome cannot satisfy a Hard client posture
  LEngine := TMockPlatformChainEngine.Create([], False,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IClientCertificateVerifierSource;
  LContext := Default(TClientTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.RevocationPosture := TRevocationPosture.Hard;
  LContext.Deferral := TVerdictDeferral.None;
  LRaised := False;
  try
    LSource.CreateClientVerifier(LContext);
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a Hard client posture over a no-cached-revocation engine is refused');
end;

procedure TTestOSDelegateTemplate.TestLiveResolverDispatchesToServer;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation, nil), nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := OcspChain;
    LContext.HostName := 'host.example';
    CheckTrue(LResolver.ResolveVerdict(LContext, LAlert),
      'an indeterminate live result accepts under Soft');
    CheckEquals(1, LFake.ServerCalls, 'a server park dispatched to the server engine method');
    CheckEquals(0, LFake.ClientCalls, 'the client engine method did not run');
    CheckTrue(LFake.Last.NetworkAllowed, 'the live re-check allows a network fetch');
    CheckEquals(Ord(TPlatformRevocationCheck.RequirePositive), Ord(LFake.Last.Revocation),
      'the live re-check requires a positive revocation response');
    CheckEquals('host.example', LFake.Last.ServerName.AsDns,
      'the live re-check carries the DNS host');
  finally
    LResolver.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestLiveResolverWrongRoleRefused;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation, nil), nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Client;
    LContext.Chain := OcspChain;
    CheckFalse(LResolver.ResolveVerdict(LContext, LAlert), 'a wrong-role park is refused');
    CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert), 'the alert is internal_error');
    CheckEquals(0, LFake.ServerCalls, 'the engine is not consulted for a wrong-role park');
  finally
    LResolver.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestLiveResolverHoldsToTheConfiguredPosture;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server,
    Policy(TRevocationPosture.Soft, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation, nil), nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := OcspChain;
    LContext.RevocationPosture := TRevocationPosture.Hard;
    CheckFalse(LResolver.ResolveVerdict(LContext, LAlert),
      'an indeterminate live result is refused under a Hard configuration');
    CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
      'the alert is bad_certificate_status_response');
  finally
    LResolver.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestLiveResolverOffPostureStillChecksWhenTheConfigurationAsksForMore;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server,
    Policy(TRevocationPosture.Off, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation, nil), nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := OcspChain;
    LContext.RevocationPosture := TRevocationPosture.Hard;
    CheckTrue(LResolver.ResolveVerdict(LContext, LAlert), 'a Good live result accepts');
    CheckEquals(1, LFake.ServerCalls, 'the engine was consulted despite the resolver''s own Off');
  finally
    LResolver.Free;
  end;
end;

function TTestOSDelegateTemplate.IndeterminateFallback(const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  System.Inc(FFallbackCalls);
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := TRevocationDecision.Decide(TLiveRevocationOutcome.Indeterminate,
    ACtx.RevocationPosture, False, ARejectAlert);
end;

procedure TTestOSDelegateTemplate.TestLiveResolverFallbackDecidesAtTheLiftedPosture;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  FFallbackCalls := 0;
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch], True,
    Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LResolver := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server,
    Policy(TRevocationPosture.Hard, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation, nil),
    IndeterminateFallback);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := OcspChain;
    LContext.RevocationPosture := TRevocationPosture.Soft;
    CheckFalse(LResolver.ResolveVerdict(LContext, LAlert),
      'an indeterminate fallback is refused at the resolver''s stricter Hard posture');
    CheckEquals(1, FFallbackCalls, 'the portable fallback ran');
    CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
      'the alert is bad_certificate_status_response');
  finally
    LResolver.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestEnginePathStartingAtASubCaIsRefused;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LCaLeaf, LRoot: TBytes;
begin
  LCaLeaf := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'caleaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'root_cert');
  CheckFalse(VerifyEnginePath(TArray<TBytes>.Create(LCaLeaf),
    TArray<TBytes>.Create(LCaLeaf, LRoot), TArray<TBytes>.Create(LRoot),
    TCertificateStrengthPolicy.Defaults, nil, LVerified, LAlert),
    'a CA certificate presented as the end-entity is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
  CheckEquals(0, System.Length(LVerified.Path), 'no validated path is reported');
end;

procedure TTestOSDelegateTemplate.TestEnginePathOfAPinnedSelfSignedCaIsAccepted;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSelfCa: TBytes;
begin
  LSelfCa := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'selfca_cert');
  CheckTrue(VerifyEnginePath(TArray<TBytes>.Create(LSelfCa), TArray<TBytes>.Create(LSelfCa),
    TArray<TBytes>.Create(LSelfCa), TCertificateStrengthPolicy.Defaults, nil, LVerified, LAlert),
    'the directly trusted self-signed CA certificate is accepted');
end;

procedure TTestOSDelegateTemplate.TestClientEngineReportingNoAnchorAcceptsAConfiguredSelfSignedCa;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSelfCa: TBytes;
begin
  LSelfCa := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'selfca_cert');
  CheckTrue(VerifyClientEnginePath(TArray<TBytes>.Create(LSelfCa),
    TArray<TBytes>.Create(LSelfCa), TArray<TBytes>.Create(LSelfCa), LVerified, LAlert),
    'a leaf equal to a configured anchor is admitted though the engine named no anchor');
end;

procedure TTestOSDelegateTemplate.TestClientEngineReportingNoAnchorRefusesAnUnconfiguredCa;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSelfCa: TBytes;
begin
  LSelfCa := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'selfca_cert');
  CheckFalse(VerifyClientEnginePath(TArray<TBytes>.Create(LSelfCa),
    TArray<TBytes>.Create(LSelfCa), nil, LVerified, LAlert),
    'the same CA leaf is refused when it is not a configured anchor');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestOSDelegateTemplate.TestEnginePathOfAPlainLeafIsAccepted;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LLeaf, LInter, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'leaf_cert');
  LInter := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt',
    'inter_serverauth_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'root_cert');
  CheckTrue(VerifyEnginePath(TArray<TBytes>.Create(LLeaf, LInter),
    TArray<TBytes>.Create(LLeaf, LInter, LRoot), TArray<TBytes>.Create(LRoot),
    TCertificateStrengthPolicy.Defaults, nil, LVerified, LAlert),
    'an end-entity certificate under a CA is unaffected');
  CheckEquals(3, System.Length(LVerified.Path), 'the engine path is reported');
end;

procedure TTestOSDelegateTemplate.TestEnginePathAnchorKeyBelowTheFloorIsAcceptedWhenNotFlagged;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LStrength: TCertificateStrengthPolicy;
  LLeaf, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert');
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 4096;
  CheckTrue(VerifyEnginePath(TArray<TBytes>.Create(LLeaf), TArray<TBytes>.Create(LLeaf, LRoot),
    TArray<TBytes>.Create(LRoot), LStrength, nil, LVerified, LAlert),
    'an RSA-2048 engine anchor passes a 4096-bit floor while the flag is off');
end;

procedure TTestOSDelegateTemplate.TestEnginePathAnchorKeyBelowTheFloorIsRefusedWhenFlagged;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LStrength: TCertificateStrengthPolicy;
  LLeaf, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert');
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 4096;
  LStrength.AnchorKeyFloors := True;
  CheckFalse(VerifyEnginePath(TArray<TBytes>.Create(LLeaf), TArray<TBytes>.Create(LLeaf, LRoot),
    TArray<TBytes>.Create(LRoot), LStrength, nil, LVerified, LAlert),
    'an RSA-2048 engine anchor is refused under a 4096-bit floor');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a weak anchor key is unsupported_certificate');
  CheckEquals(0, System.Length(LVerified.Path), 'no validated path is reported');
end;

procedure TTestOSDelegateTemplate.TestEnginePathAnchorOnAnUnlistedCurveIsRefusedWhenFlagged;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LStrength: TCertificateStrengthPolicy;
  LLeaf, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert');
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  LStrength.AnchorKeyFloors := True;
  CheckFalse(VerifyEnginePath(TArray<TBytes>.Create(LLeaf), TArray<TBytes>.Create(LLeaf, LRoot),
    TArray<TBytes>.Create(LRoot), LStrength, nil, LVerified, LAlert),
    'a P-256 engine anchor is refused when the list admits only P-384');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a disallowed anchor curve is unsupported_certificate');
end;

procedure TTestOSDelegateTemplate.TestEnginePathAnchorEdDsaKeyIsRefusedWhenFlagged;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LStrength: TCertificateStrengthPolicy;
  LLeaf, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/Ed25519Chain.txt', 'root_cert');
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.AllowEdDsa := False;
  LStrength.AnchorKeyFloors := True;
  CheckFalse(VerifyEnginePath(TArray<TBytes>.Create(LLeaf), TArray<TBytes>.Create(LLeaf, LRoot),
    TArray<TBytes>.Create(LRoot), LStrength, nil, LVerified, LAlert),
    'an Ed25519 engine anchor is refused when EdDSA is disallowed');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a disallowed anchor key type is unsupported_certificate');
end;

procedure TTestOSDelegateTemplate.TestEnginePathAnchorWithinTheFloorsIsAcceptedWhenFlagged;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LStrength: TCertificateStrengthPolicy;
  LLeaf, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert');
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.AnchorKeyFloors := True;
  CheckTrue(VerifyEnginePath(TArray<TBytes>.Create(LLeaf), TArray<TBytes>.Create(LLeaf, LRoot),
    TArray<TBytes>.Create(LRoot), LStrength, nil, LVerified, LAlert),
    'a P-256 engine anchor within the floors is accepted');
end;

procedure TTestOSDelegateTemplate.TestLiveEnginePathAnchorKeyBelowTheFloorIsAcceptedWhenNotFlagged;
var
  LAlert: TTlsAlertDescription;
  LStrength: TCertificateStrengthPolicy;
  LLeaf, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert');
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 4096;
  CheckTrue(ResolveLiveEnginePath(TArray<TBytes>.Create(LLeaf),
    TArray<TBytes>.Create(LLeaf, LRoot), TArray<TBytes>.Create(LRoot), LStrength, LAlert),
    'an RSA-2048 engine anchor passes a 4096-bit floor on the live path while the flag is off');
end;

procedure TTestOSDelegateTemplate.TestLiveEnginePathAnchorKeyBelowTheFloorIsRefusedWhenFlagged;
var
  LAlert: TTlsAlertDescription;
  LStrength: TCertificateStrengthPolicy;
  LLeaf, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'root_cert');
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 4096;
  LStrength.AnchorKeyFloors := True;
  CheckFalse(ResolveLiveEnginePath(TArray<TBytes>.Create(LLeaf),
    TArray<TBytes>.Create(LLeaf, LRoot), TArray<TBytes>.Create(LRoot), LStrength, LAlert),
    'an RSA-2048 engine anchor is refused on the live path under a 4096-bit floor');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a weak anchor key is unsupported_certificate');
end;

procedure TTestOSDelegateTemplate.TestVerifyCallbackSeesThePresentedChainAndTheEnginePath;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
  LLeaf, LInter, LRoot, LExtra: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'leaf_cert');
  LInter := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt',
    'inter_serverauth_cert');
  LRoot := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'root_cert');
  LExtra := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', 'selfca_cert');
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  CheckTrue(VerifyEnginePath(TArray<TBytes>.Create(LLeaf, LInter, LExtra),
    TArray<TBytes>.Create(LLeaf, LInter, LRoot), TArray<TBytes>.Create(LRoot),
    TCertificateStrengthPolicy.Defaults, LSpy.Callback, LVerified, LAlert), 'accepted');
  CheckEquals(3, System.Length(LSpy.Presented), 'the callback sees every presented certificate');
  CheckEquals(3, System.Length(LSpy.Validated), 'and the path the engine built');
  CheckEqualBytes('the validated path ends at the engine''s root', LRoot, LSpy.Validated[2]);
end;

procedure TTestOSDelegateTemplate.TestClientRoutesByStapleWithoutCachedRevocation;

  function VerifyClient(APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
    ADeferral: TVerdictDeferral; out AAlert: TTlsAlertDescription): Boolean;
  var
    LFake: TMockPlatformChainEngine;
    LEngine: IPlatformChainEngine;
    LVerifier: IClientCertificateVerifier;
    LVerified: TVerifiedChain;
  begin
    // no CachedRevocation (Android-shaped): the engine renders no revocation outcome of its own, so
    // an absent client-certificate staple leaves the outcome indeterminate, routed by posture/deferral
    LFake := TMockPlatformChainEngine.Create([], True,
      Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
    LEngine := LFake;
    LVerifier := TOSDelegateClientVerifier.Create(LEngine,
      Policy(APosture, AFetch, ADeferral, OcspChain)) as IClientCertificateVerifier;
    Result := LVerifier.VerifyClientCertificate(OcspChain, LVerified, AAlert);
  end;

var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyClient(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly,
    TVerdictDeferral.None, LAlert), 'Soft accepts an indeterminate no-cached-revocation client');
  CheckFalse(VerifyClient(TRevocationPosture.Hard, TSystemTrustFetch.CacheOnly,
    TVerdictDeferral.None, LAlert), 'Hard rejects it inline');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the inline Hard rejection is bad_certificate_status_response');
  CheckTrue(VerifyClient(TRevocationPosture.Hard, TSystemTrustFetch.CacheOnly,
    TVerdictDeferral.LiveRevocation, LAlert),
    'Hard defers the indeterminate case to the park when the live verdict is armed');
end;

procedure TTestOSDelegateTemplate.TestStapledRevokedRejectsWithoutCachedRevocation;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // no CachedRevocation + a definitive stapled Revoked rejects under Off (the staple is the
  // revocation source here); a matching host keeps the identity check satisfied so revocation decides
  LFake := TMockPlatformChainEngine.Create([], True,
    Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'),
    Ocsp('ocsp_revoked'), LVerified, LAlert),
    'a stapled Revoked rejects a no-cached-revocation server under Off');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestOSDelegateTemplate.TestVerifyCallbackRejectYieldsCertificateUnknown;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  // the augment-only reject hook runs after a trusting engine and turns acceptance into a
  // certificate_unknown rejection with no validated path (built-in verifier parity)
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(False));
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LPolicy := Policy(TRevocationPosture.Soft, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.Dangerous.VerifyCallback := LSpy.Callback;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'the augment callback rejects an otherwise-trusted chain');
  CheckTrue(LSpy.Invoked, 'the augment callback ran');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'a custom rejection is certificate_unknown');
  CheckEquals(0, System.Length(LVerified.Path), 'the validated path is cleared on rejection');
end;

procedure TTestOSDelegateTemplate.TestVerifyCallbackNotInvokedWhenEngineRejects;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  // the hook is augment-only: an engine rejection returns first, so the callback (which could only
  // reject further) never runs and cannot rescue the chain
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LEngine := TMockPlatformChainEngine.Create([], False,
    Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LPolicy := Policy(TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.Dangerous.VerifyCallback := LSpy.Callback;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'an engine rejection stands');
  CheckFalse(LSpy.Invoked, 'the augment callback never ran for a rejected chain');
end;

procedure TTestOSDelegateTemplate.TestEmptyServerNameFailsClosedWithoutConsultingEngine;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // an empty server name under an enabled name check fails closed before the engine runs, rather
  // than trusting a chain whose identity was never matched
  LFake := TMockPlatformChainEngine.Create([], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, Default(TServerName), nil,
    LVerified, LAlert), 'an empty name under an enabled check is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
  CheckEquals(0, LFake.ServerCalls, 'the engine was not consulted');
end;

procedure TTestOSDelegateTemplate.TestOverCapChainRefusedWithoutConsultingEngine;
var
  LFake: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LServer: IServerCertificateVerifier;
  LClient: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // the chain-size caps bind the OS delegates as they bind the built-in verifier: an over-count chain
  // is refused before the platform engine sees it, in both roles
  LFake := TMockPlatformChainEngine.Create([], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.UnknownCa);
  LEngine := LFake;
  LPolicy := Policy(TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil);
  LPolicy.ChainLimits.MaxChainCertificates := 1;
  LServer := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  CheckFalse(LServer.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'an over-count chain is refused for a server certificate');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the server alert is bad_certificate');
  LClient := TOSDelegateClientVerifier.Create(LEngine, LPolicy) as IClientCertificateVerifier;
  CheckFalse(LClient.VerifyClientCertificate(OcspChain, LVerified, LAlert),
    'an over-count chain is refused for a client certificate');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the client alert is bad_certificate');
  CheckEquals(0, LFake.ServerCalls + LFake.ClientCalls, 'the engine was never consulted');
end;

procedure TTestOSDelegateTemplate.TestServerSourceCarriesVerifyCallbackFromContext;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LContext: TServerTrustContext;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  // the source copies the context's augment callback into the delegate policy, so a config-wired
  // reject hook actually runs on the OS-delegate server path (regression guard for the copy)
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(False));
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IServerCertificateVerifierSource;
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Clock := FClock;
  LContext.CheckHostName := True;
  LContext.RevocationPosture := TRevocationPosture.Soft;
  LContext.Deferral := TVerdictDeferral.None;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
  LContext.Dangerous.VerifyCallback := LSpy.Callback;
  LVerifier := LSource.CreateServerVerifier(LContext);
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'the context callback rejects on the server path');
  CheckTrue(LSpy.Invoked, 'the context callback ran');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'a custom rejection is certificate_unknown');
end;

procedure TTestOSDelegateTemplate.TestClientSourceCarriesVerifyCallbackFromContext;
var
  LEngine: IPlatformChainEngine;
  LSource: IClientCertificateVerifierSource;
  LContext: TClientTrustContext;
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  // the client twin: the source copies the callback into the client-delegate policy, and the hook
  // sees an empty host (a client certificate carries no name)
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(False));
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], True,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IClientCertificateVerifierSource;
  LContext := Default(TClientTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Clock := FClock;
  LContext.RevocationPosture := TRevocationPosture.Soft;
  LContext.Deferral := TVerdictDeferral.None;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
  LContext.Dangerous.VerifyCallback := LSpy.Callback;
  LVerifier := LSource.CreateClientVerifier(LContext);
  CheckFalse(LVerifier.VerifyClientCertificate(OcspChain, LVerified, LAlert),
    'the context callback rejects on the client path');
  CheckTrue(LSpy.Invoked, 'the context callback ran');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'a custom rejection is certificate_unknown');
end;

procedure TTestOSDelegateTemplate.TestFilterRootsDeDupsAndDropsMalformed;
var
  LProbe: TFilterRootsProbe;
  LValid: TBytes;
  LResult: TArray<TBytes>;
begin
  // the shared filter both native harvesters use keeps one copy of a well-formed anchor and drops a
  // duplicate and any malformed bytes
  LValid := OcspChain[0];
  LProbe := TFilterRootsProbe.Create(Pkix);
  try
    LResult := LProbe.Filter(TArray<TBytes>.Create(LValid, System.Copy(LValid),
      TBytes.Create(1, 2, 3)));
    CheckEquals(1, System.Length(LResult), 'the duplicate is collapsed and the junk dropped');
    CheckEqualBytes('the survivor is the well-formed anchor', LValid, LResult[0]);
  finally
    LProbe.Free;
  end;
end;

procedure TTestOSDelegateTemplate.TestSnapshotCarriesDeduplicatedDistrustSet;
var
  LProbe: TFilterRootsProbe;
  LStore: ITrustAnchorStore;
  LRoot, LDistrusted: TBytes;
begin
  // the snapshot carries the distrust set with duplicates dropped and an unparseable entry kept
  // (distrust is matched by exact bytes), and a root the source also distrusts is not an anchor
  LRoot := OcspChain[0];
  LDistrusted := OcspChain[1];
  LProbe := TFilterRootsProbe.Create(Pkix);
  try
    LProbe.Harvests(TArray<TBytes>.Create(LRoot, LDistrusted),
      TArray<TBytes>.Create(LDistrusted, System.Copy(LDistrusted), TBytes.Create(1, 2, 3)));
    LStore := LProbe.Snapshot;
  finally
    LProbe.Free;
  end;
  CheckEquals(2, System.Length(LStore.DistrustedCertificates),
    'the duplicate is dropped and the unparseable entry kept');
  CheckTrue(LStore.IsDistrusted(LDistrusted), 'the distrusted certificate matches');
  CheckTrue(LStore.IsDistrusted(TBytes.Create(1, 2, 3)), 'the unparseable entry matches by bytes');
  CheckEquals(1, System.Length(LStore.RootCertificates),
    'a root the source distrusts is not an anchor');
  CheckEqualBytes('the surviving anchor', LRoot, LStore.RootCertificates[0]);
end;

procedure TTestOSDelegateTemplate.TestReadDistrustedOnlyDeduplicates;
var
  LProbe: TFilterRootsProbe;
  LDistrusted: TBytes;
  LResult: TArray<TBytes>;
begin
  // the distrust-only read drops duplicates like the snapshot's set and keeps what it cannot parse
  LDistrusted := OcspChain[1];
  LProbe := TFilterRootsProbe.Create(Pkix);
  try
    LProbe.Collects(TArray<TBytes>.Create(LDistrusted, System.Copy(LDistrusted),
      TBytes.Create(1, 2, 3)));
    LResult := LProbe.ReadDistrusted;
  finally
    LProbe.Free;
  end;
  CheckEquals(2, System.Length(LResult), 'the duplicate is collapsed and nothing else dropped');
  CheckEqualBytes('the certificate comes first', LDistrusted, LResult[0]);
  CheckEqualBytes('the unparseable entry is kept', TBytes.Create(1, 2, 3), LResult[1]);
end;

{ TTestDelegateHostRoots }

procedure TTestDelegateHostRoots.SetUp;
begin
  inherited SetUp;
  FOcsp := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
end;

function TTestDelegateHostRoots.Ocsp(const AName: string): TBytes;
begin
  Result := DecodeHex(FOcsp.Values[AName]);
end;

function TTestDelegateHostRoots.Chain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(Ocsp('leaf_cert'), Ocsp('issuer_cert'));
end;

function TTestDelegateHostRoots.HostRoots: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(Ocsp('issuer_cert'));
end;

function TTestDelegateHostRoots.Accepted: TPlatformChainResult;
begin
  Result := Default(TPlatformChainResult);
  Result.Outcome := TLiveRevocationOutcome.Good;
  Result.Path := Chain;
  Result.PolicyExempt := Chain;
end;

function TTestDelegateHostRoots.Rejected(AFailure: TPlatformChainFailure): TPlatformChainResult;
begin
  Result := Default(TPlatformChainResult);
  Result.Failure := AFailure;
end;

function TTestDelegateHostRoots.Policy(const AExtras, ADistrusted: TArray<TBytes>;
  AFetch: TSystemTrustFetch): TOSDelegatePolicy;
begin
  Result := Default(TOSDelegatePolicy);
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.Pkix := Pkix;
  Result.Clock := TSystemClock.Create as ITlsClock;
  Result.Posture := TRevocationPosture.Soft;
  Result.Fetch := AFetch;
  if AFetch = TSystemTrustFetch.Live then
    Result.Deferral := TVerdictDeferral.LiveRevocation
  else
    Result.Deferral := TVerdictDeferral.None;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.AdvertisedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
    TSignatureSchemes.EcdsaSecp384r1Sha384, TSignatureSchemes.EcdsaSecp521r1Sha512,
    TSignatureSchemes.RsaPssRsaeSha256, TSignatureSchemes.RsaPssRsaeSha384,
    TSignatureSchemes.RsaPssRsaeSha512, TSignatureSchemes.RsaPkcs1Sha256,
    TSignatureSchemes.RsaPkcs1Sha384, TSignatureSchemes.RsaPkcs1Sha512);
  Result.ExtraAnchors := AExtras;
  Result.Distrusted := ADistrusted;
  Result.DeadlineMs := 2000;
end;

function TTestDelegateHostRoots.Verify(const AEngine: IPlatformChainEngine;
  const AExtras, ADistrusted: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TOSDelegateServerVerifier.Create(AEngine,
    Policy(AExtras, ADistrusted, TSystemTrustFetch.CacheOnly)) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(Chain, Default(TServerName), nil, LVerified, AAlert);
end;

function TTestDelegateHostRoots.Resolve(const AEngine: IPlatformChainEngine;
  const ADistrusted: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
var
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
begin
  LResolver := TOSDelegateLiveResolver.Create(AEngine, TPeerRole.Server,
    Policy(HostRoots, ADistrusted, TSystemTrustFetch.Live), nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := Chain;
    LContext.HostName := 'host.example';
    Result := LResolver.ResolveVerdict(LContext, AAlert);
  finally
    LResolver.Free;
  end;
end;

procedure TTestDelegateHostRoots.TestOsRootsAcceptanceNeverRetries;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], True, Accepted,
    TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckTrue(Verify(LEngine, HostRoots, nil, LAlert), 'a chain the OS roots accept is accepted');
  CheckEquals(1, LMock.ServerCalls, 'the host roots are not tried');
  CheckEquals(0, System.Length(LMock.Requests[0].Anchors), 'the evaluation is against the OS roots');
end;

procedure TTestDelegateHostRoots.TestNoTrustAnchorRetriesWithHostRootsAsExclusiveRoot;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckTrue(Verify(LEngine, HostRoots, nil, LAlert),
    'the second evaluation against the host roots decides');
  CheckEquals(2, LMock.ServerCalls, 'one evaluation per root set');
  CheckEquals(0, System.Length(LMock.Requests[0].Anchors), 'the first is against the OS roots');
  CheckEquals(1, System.Length(LMock.Requests[1].Anchors), 'the second has the host roots');
  CheckEqualBytes('the host root is the exclusive root', HostRoots[0], LMock.Requests[1].Anchors[0]);
  CheckEquals(0, System.Length(LMock.Requests[1].ExtraAnchors),
    'the host roots are not also offered as extras');
  CheckEquals(Ord(LMock.Requests[0].Revocation), Ord(LMock.Requests[1].Revocation),
    'both evaluations use the same revocation level');
  CheckEquals(LMock.Requests[0].NetworkAllowed, LMock.Requests[1].NetworkAllowed,
    'both evaluations use the same fetch mode');
end;

procedure TTestDelegateHostRoots.TestOtherFailureIsFinal;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.Other), TTlsAlertDescription.CertificateExpired);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, nil, LAlert), 'an expired, revoked or pinned chain stays refused');
  CheckEquals(1, LMock.ServerCalls, 'the host roots are not tried');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert), 'the alert is the first one');
end;

procedure TTestDelegateHostRoots.TestNoHostRootsNeverRetries;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, nil, nil, LAlert), 'without host roots the OS verdict stands');
  CheckEquals(1, LMock.ServerCalls, 'there is nothing to retry with');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is the first one');
end;

procedure TTestDelegateHostRoots.TestEngineWithoutExclusiveAnchorsNeverRetries;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, nil, LAlert),
    'an engine that cannot take an exclusive server root is never retried');
  CheckEquals(1, LMock.ServerCalls, 'a single evaluation');
end;

procedure TTestDelegateHostRoots.TestNativeUnionEvaluatesOnceWithHostRoots;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.NativeAnchorUnion, TPlatformChainCapability.ExclusiveServerAnchors],
    False, Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, nil, LAlert), 'the single union evaluation is final');
  CheckEquals(1, LMock.ServerCalls, 'one evaluation');
  CheckEquals(1, System.Length(LMock.Requests[0].ExtraAnchors), 'it carries the host roots');
  CheckEquals(0, System.Length(LMock.Requests[0].Anchors), 'they are not the exclusive root');
end;

procedure TTestDelegateHostRoots.TestRetryFailureReportsTheAlertOfTheEvaluationThatReachedAnAnchor;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(False, Rejected(TPlatformChainFailure.Other),
    TTlsAlertDescription.CertificateExpired);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, nil, LAlert), 'a private chain that fails past its anchor is refused');
  CheckEquals(2, LMock.ServerCalls, 'both root sets were tried');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'the alert is the one from the host-root evaluation');
end;

procedure TTestDelegateHostRoots.TestRetryFindingNoAnchorKeepsTheFirstAlert;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(False, Rejected(TPlatformChainFailure.NoTrustAnchor),
    TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, nil, LAlert), 'a chain that reaches neither root set is refused');
  CheckEquals(2, LMock.ServerCalls, 'both root sets were tried');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is the one from the OS-root evaluation');
end;

procedure TTestDelegateHostRoots.TestHostRootPathThroughDistrustedCertificateIsRefused;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, TArray<TBytes>.Create(Ocsp('issuer_cert')), LAlert),
    'a path through an OS-distrusted certificate is refused though the host roots vouch for it');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
  CheckTrue(Verify(LEngine, HostRoots, TArray<TBytes>.Create(Ocsp('root_cert')), LAlert),
    'a distrusted certificate that is not on the path changes nothing');
end;

procedure TTestDelegateHostRoots.TestDistrustAppliesToAnOsRootsAcceptance;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], True, Accepted,
    TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, TArray<TBytes>.Create(Ocsp('issuer_cert')), LAlert),
    'a host distrust entry binds a path the OS roots accepted');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
  CheckEquals(1, LMock.ServerCalls, 'no host-root retry was needed');
  CheckTrue(Length(Ocsp('other_ca_cert')) > 0, 'the off-path entry is a real certificate');
  CheckTrue(Verify(LEngine, HostRoots, TArray<TBytes>.Create(Ocsp('other_ca_cert')), LAlert),
    'a distrusted certificate that is not on the path changes nothing');
end;

procedure TTestDelegateHostRoots.TestDistrustBindsWithoutHostRoots;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], True,
    Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, nil, TArray<TBytes>.Create(Ocsp('issuer_cert')), LAlert),
    'a distrust list alone refuses a path through it');
end;

procedure TTestDelegateHostRoots.TestStoreDistrustReachesTheOsSource;
var
  LStore: ITrustAnchorStore;
  LSource: IServerCertificateVerifierSource;
  LDistrusted: TArray<TBytes>;
  LIndex: Int32;
  LFound: Boolean;
begin
  LStore := TTrustAnchorStore.Create(nil, TArray<TBytes>.Create(Ocsp('issuer_cert')))
    as ITrustAnchorStore;
  CheckEquals(1, System.Length(LStore.DistrustedCertificates), 'the host store carries its entry');
  if not TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
  begin
    SkipTest('this platform has no OS delegate engine');
    Exit;
  end;
  LSource := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.OsAndHostRoots(LStore), Pkix);
  LDistrusted := (LSource as TOSVerifierSource).Distrusted;
  LFound := False;
  for LIndex := 0 to System.High(LDistrusted) do
    if TArrayUtilities.AreEqual(LDistrusted[LIndex], Ocsp('issuer_cert')) then
      LFound := True;
  CheckTrue(LFound, 'the host store''s own distrust entry is carried even without host roots');
end;

procedure TTestDelegateHostRoots.TestDistrustAppliesUnderNativeUnion;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.NativeAnchorUnion], True, Accepted,
    TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Verify(LEngine, HostRoots, TArray<TBytes>.Create(Ocsp('issuer_cert')), LAlert),
    'a union path through an OS-distrusted certificate is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestDelegateHostRoots.TestSourceCarriesDistrustToTheVerifier;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LContext: TServerTrustContext;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, HostRoots, TArray<TBytes>.Create(Ocsp('leaf_cert')))
    as IServerCertificateVerifierSource;
  CheckEquals(1, System.Length((LSource as TOSVerifierSource).Distrusted),
    'the source exposes its distrust set for the live re-check');
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Clock := TSystemClock.Create as ITlsClock;
  LContext.RevocationPosture := TRevocationPosture.Soft;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
  LVerifier := LSource.CreateServerVerifier(LContext);
  CheckFalse(LVerifier.VerifyServerCertificate(Chain, Default(TServerName), nil, LVerified, LAlert),
    'the verifier built by the source refuses a path through a distrusted certificate');
  CheckEquals(2, LMock.ServerCalls, 'after the retry against the host roots');
end;

procedure TTestDelegateHostRoots.TestSourceAcceptsHostRootsOverAnExclusiveAnchorEngine;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
begin
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.ExclusiveServerAnchors],
    False, Rejected(TPlatformChainFailure.None), TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, HostRoots, nil) as IServerCertificateVerifierSource;
  CheckEquals(1, System.Length((LSource as TOSVerifierSource).ExtraAnchors),
    'host roots are accepted at construction');
end;

procedure TTestDelegateHostRoots.TestSourceRefusesHostRootsOverAnEngineWithNeitherCapability;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LRaised: Boolean;
begin
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
    Rejected(TPlatformChainFailure.None), TTlsAlertDescription.BadCertificate);
  LRaised := False;
  try
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
      TSystemTrustRootScope.OsAndHostRoots, HostRoots, nil) as IServerCertificateVerifierSource;
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'host roots over an engine that cannot trust them are refused at construction');
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.NativeAnchorUnion], False,
    Rejected(TPlatformChainFailure.None), TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, HostRoots, nil) as IServerCertificateVerifierSource;
  CheckEquals(1, System.Length((LSource as TOSVerifierSource).ExtraAnchors),
    'a native-union engine accepts host roots');
end;

procedure TTestDelegateHostRoots.TestOsServerSourceIsTheOsSource;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
begin
  LEngine := TMockPlatformChainEngine.Create([], False, Rejected(TPlatformChainFailure.None),
    TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IServerCertificateVerifierSource;
  CheckTrue(LSource is TOSVerifierSource, 'an OS-delegate server source is the OS source');
end;

procedure TTestDelegateHostRoots.TestOsClientSourceIsTheOsSource;
var
  LEngine: IPlatformChainEngine;
  LSource: IClientCertificateVerifierSource;
begin
  LEngine := TMockPlatformChainEngine.Create([], False, Rejected(TPlatformChainFailure.None),
    TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IClientCertificateVerifierSource;
  CheckTrue(LSource is TOSVerifierSource, 'an OS-delegate client source is the OS source');
end;

procedure TTestDelegateHostRoots.TestBuiltInSourceIsNotTheOsSource;
var
  LSource: IServerCertificateVerifierSource;
begin
  LSource := TBuiltInServerVerifierSource.Create as IServerCertificateVerifierSource;
  CheckFalse(LSource is TOSVerifierSource, 'the portable built-in source is not the OS source');
end;

procedure TTestDelegateHostRoots.TestCustomVerifierSourceIsNotTheOsSource;
var
  LVerifier: IServerCertificateVerifier;
  LSource: IServerCertificateVerifierSource;
begin
  LVerifier := TFixedVerdictVerifier.CreateAccepting(False) as IServerCertificateVerifier;
  LSource := TInstanceServerVerifierSource.Create(LVerifier) as IServerCertificateVerifierSource;
  CheckFalse(LSource is TOSVerifierSource, 'a caller-supplied verifier source is not the OS source');
end;

procedure TTestDelegateHostRoots.TestLiveResolverRetriesWithHostRoots;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckTrue(Resolve(LEngine, nil, LAlert), 'the live pass trusts the chain through the host roots');
  CheckEquals(2, LMock.ServerCalls, 'one evaluation per root set');
  CheckEquals(0, System.Length(LMock.Requests[0].Anchors), 'the first is against the OS roots');
  CheckEquals(1, System.Length(LMock.Requests[1].Anchors), 'the second has the host roots');
  CheckTrue(LMock.Requests[1].NetworkAllowed, 'the retry keeps the network fetch');
  CheckEquals(Ord(TPlatformRevocationCheck.RequirePositive), Ord(LMock.Requests[1].Revocation),
    'and the positive revocation requirement');
end;

procedure TTestDelegateHostRoots.TestLiveResolverOtherFailureIsFinal;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.Other), TTlsAlertDescription.CertificateExpired);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Resolve(LEngine, nil, LAlert), 'any other failure rejects the live pass');
  CheckEquals(1, LMock.ServerCalls, 'the host roots are not tried');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert), 'with the first alert');
end;

procedure TTestDelegateHostRoots.TestLiveResolverRefusesDistrustedHostRootPath;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.LiveFetch,
    TPlatformChainCapability.ExclusiveServerAnchors], False,
    Rejected(TPlatformChainFailure.NoTrustAnchor), TTlsAlertDescription.UnknownCa);
  LMock.ThenReturn(True, Accepted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  CheckFalse(Resolve(LEngine, TArray<TBytes>.Create(Ocsp('issuer_cert')), LAlert),
    'the live pass refuses a host-root path through a distrusted certificate');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

{ TTestDelegateHostRootsAlone }

procedure TTestDelegateHostRootsAlone.SetUp;
begin
  inherited SetUp;
  FEc := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
  FOcsp := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
  FRsa := Own<TStringList>(LoadVectorFields('Certs/Rsa2048Chain.txt'));
end;

function TTestDelegateHostRootsAlone.WeakRoot: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FRsa.Values['root_cert']));
end;

function TTestDelegateHostRootsAlone.WeakRootChain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FEc.Values['leaf_cert']), WeakRoot[0]);
end;

function TTestDelegateHostRootsAlone.ClientContext(const AAnchors: TArray<TBytes>;
  AAnchorFloors: Boolean): TClientTrustContext;
begin
  Result := Default(TClientTrustContext);
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.Pkix := Pkix;
  Result.Clock := TSystemClock.Create as ITlsClock;
  Result.TrustStore := TTrustAnchorStore.Create(AAnchors) as ITrustAnchorStore;
  Result.RevocationPosture := TRevocationPosture.Soft;
  Result.Deferral := TVerdictDeferral.None;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.StrengthPolicy.MinRsaModulusBits := 4096;
  Result.StrengthPolicy.AnchorKeyFloors := AAnchorFloors;
  Result.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
end;

function TTestDelegateHostRootsAlone.VerifyClient(const AEngine: IPlatformChainEngine;
  const AAnchors, AChain: TArray<TBytes>; AAnchorFloors: Boolean;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TOSDelegateClientVerifier.Create(AEngine, TOSDelegatePolicy.FromClientContext(
    ClientContext(AAnchors, AAnchorFloors), TSystemTrustFetch.CacheOnly))
    as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(AChain, LVerified, AAlert);
end;

function TTestDelegateHostRootsAlone.ResolveClient(const AEngine: IPlatformChainEngine;
  const AAnchors, AChain: TArray<TBytes>; AAnchorFloors: Boolean;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
begin
  LResolver := TOSDelegateLiveResolver.Create(AEngine, TPeerRole.Client,
    TOSDelegatePolicy.FromClientContext(ClientContext(AAnchors, AAnchorFloors),
    TSystemTrustFetch.Live), nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Client;
    LContext.Chain := AChain;
    Result := LResolver.ResolveVerdict(LContext, AAlert);
  finally
    LResolver.Free;
  end;
end;

function TTestDelegateHostRootsAlone.NoAnchorEngine: IPlatformChainEngine;
var
  LResult: TPlatformChainResult;
begin
  LResult := Default(TPlatformChainResult);
  LResult.Outcome := TLiveRevocationOutcome.Good;
  LResult.Path := TArray<TBytes>.Create(WeakRootChain[0]);
  Result := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.LiveFetch], True, LResult, TTlsAlertDescription.BadCertificate);
end;

function TTestDelegateHostRootsAlone.ServerBuildMessage(AAnchorFloors: Boolean;
  const AAnchors: TArray<TBytes>): string;
var
  LSource: IClientCertificateVerifierSource;
  LStrength: TCertificateStrengthPolicy;
begin
  Result := '';
  LSource := TOSVerifierSource.Create(TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps,
    PublicRoot) as IPlatformChainEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, nil, nil) as IClientCertificateVerifierSource;
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 4096;
  LStrength.AnchorKeyFloors := AAnchorFloors;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(TTlsCredential.Load(Crypto, Pkix, DecodeHex(FEc.Values['leaf_cert']),
      DecodeHex(FEc.Values['leaf_key'])))
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(TClientVerification.VerifierSource(LSource,
      TTrustAnchorStore.Create(AAnchors) as ITrustAnchorStore)
      .WithMinimumStrength(LStrength).Build).Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := E.Message;
  end;
end;

function TTestDelegateHostRootsAlone.PrivateChain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FEc.Values['leaf_cert']), PrivateRoot[0]);
end;

function TTestDelegateHostRootsAlone.PrivateRoot: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FEc.Values['root_cert']));
end;

function TTestDelegateHostRootsAlone.PublicChain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FOcsp.Values['leaf_cert']), PublicRoot[0]);
end;

function TTestDelegateHostRootsAlone.PublicRoot: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FOcsp.Values['issuer_cert']));
end;

function TTestDelegateHostRootsAlone.ExclusiveCaps: TPlatformChainCapabilities;
begin
  Result := [TPlatformChainCapability.CachedRevocation, TPlatformChainCapability.LiveFetch,
    TPlatformChainCapability.ExclusiveServerAnchors];
end;

function TTestDelegateHostRootsAlone.Context(ADeferral: TVerdictDeferral): TServerTrustContext;
begin
  Result := Default(TServerTrustContext);
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.Pkix := Pkix;
  Result.Clock := TSystemClock.Create as ITlsClock;
  Result.CheckHostName := True;
  Result.RevocationPosture := TRevocationPosture.Soft;
  Result.Deferral := ADeferral;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
end;

function TTestDelegateHostRootsAlone.Verify(const AEngine: IPlatformChainEngine;
  AScope: TSystemTrustRootScope; const AHostRoots, ADistrusted, AChain: TArray<TBytes>;
  const AName: string; out AAlert: TTlsAlertDescription): Boolean;
var
  LSource: IServerCertificateVerifierSource;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LSource := TOSVerifierSource.Create(AEngine, TSystemTrustFetch.CacheOnly, AScope, AHostRoots,
    ADistrusted) as IServerCertificateVerifierSource;
  LVerifier := LSource.CreateServerVerifier(Context(TVerdictDeferral.None));
  Result := LVerifier.VerifyServerCertificate(AChain, TServerName.DnsName(AName), nil, LVerified,
    AAlert);
end;

function TTestDelegateHostRootsAlone.WebPkiConfig: ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.WebPki(TTrustAnchorStore.Create(PrivateRoot) as ITrustAnchorStore)
    .Build).Build;
end;

function TTestDelegateHostRootsAlone.ConstructionMessage(const AEngine: IPlatformChainEngine;
  AFetch: TSystemTrustFetch; AScope: TSystemTrustRootScope; const AHostRoots: TArray<TBytes>;
  AExpected: ExceptClass): string;
var
  LSource: IServerCertificateVerifierSource;
begin
  Result := '';
  try
    LSource := TOSVerifierSource.Create(AEngine, AFetch, AScope, AHostRoots, nil)
      as IServerCertificateVerifierSource;
    Fail('the source constructor did not raise');
  except
    on E: Exception do
      if E.ClassType = AExpected then
        Result := E.Message
      else
        raise;
  end;
end;

function TTestDelegateHostRootsAlone.ClientConfig(const ASource: IServerCertificateVerifierSource)
  : ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.VerifierSource(ASource).Build).Build;
end;

function TTestDelegateHostRootsAlone.Resolve(const AConfig: ITlsClientConfig;
  const AEngine: IPlatformChainEngine; const AChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LResolver: TOSDelegateLiveResolver;
  LContext: TCertificateVerdictContext;
begin
  LResolver := TOSDelegateLiveResolver.Create(AEngine, TPeerRole.Server,
    TOSDelegatePolicy.FromClientConfig(AConfig, AConfig.ServerVerifierSource), nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := AChain;
    LContext.HostName := 'localhost';
    Result := LResolver.ResolveVerdict(LContext, AAlert);
  finally
    LResolver.Free;
  end;
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsEvaluatesOnceAgainstTheHostRoots;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  Verify(LEngine, TSystemTrustRootScope.HostRoots, PrivateRoot, nil, PrivateChain, 'localhost',
    LAlert);
  CheckEquals(1, LFake.ServerCalls, 'one pass, no retry');
  CheckEquals(1, System.Length(LFake.Requests[0].Anchors), 'the host roots are the exclusive root');
  CheckEqualBytes('the exclusive root is the host root', PrivateRoot[0],
    LFake.Requests[0].Anchors[0]);
  CheckEquals(0, System.Length(LFake.Requests[0].ExtraAnchors),
    'the host roots are not also offered as extras');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsAcceptsThePrivateChain;
var
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  CheckTrue(Verify(LEngine, TSystemTrustRootScope.HostRoots, PrivateRoot, nil, PrivateChain,
    'localhost', LAlert), 'a chain to the host root is trusted');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsRejectsAPublicRootedChain;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  CheckFalse(Verify(LEngine, TSystemTrustRootScope.HostRoots, PrivateRoot, nil, PublicChain,
    'localhost', LAlert), 'an OS-rooted chain is not trusted when the host roots stand alone');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
  CheckEquals(1, LFake.ServerCalls, 'the OS roots are never tried');
end;

procedure TTestDelegateHostRootsAlone.TestOsAndHostRootsStillAcceptsAPublicRootedChain;
var
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  CheckTrue(Verify(LEngine, TSystemTrustRootScope.OsAndHostRoots, PrivateRoot, nil, PublicChain,
    'localhost', LAlert), 'the same chain is trusted when the host roots sit with the OS roots');
end;

procedure TTestDelegateHostRootsAlone.TestOsRootsAloneRejectThePrivateChain;
var
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  CheckFalse(Verify(LEngine, TSystemTrustRootScope.OsAndHostRoots, nil, nil, PrivateChain,
    'localhost', LAlert), 'the private chain is unknown to the OS roots');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsRefusesAPathThroughADistrustedCertificate;
var
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  CheckFalse(Verify(LEngine, TSystemTrustRootScope.HostRoots, PrivateRoot,
    TArray<TBytes>.Create(PrivateChain[0]), PrivateChain, 'localhost', LAlert),
    'distrust still binds a host-rooted path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsStillMatchesTheServerName;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  CheckFalse(Verify(LEngine, TSystemTrustRootScope.HostRoots, PrivateRoot, nil, PrivateChain,
    'other.example', LAlert), 'a trusted chain for another host is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the identity check reports bad_certificate');
  CheckEquals(1, LFake.ServerCalls, 'the engine trusted the chain before the identity check');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsWithoutRootsIsRefused;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LRaised: Boolean;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LRaised := False;
  try
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
      TSystemTrustRootScope.HostRoots, nil, nil) as IServerCertificateVerifierSource;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'host roots alone need at least one root');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsOverAStoreDistrustingItsOnlyRootIsRefused;
var
  LEngine: IPlatformChainEngine;
  LStore: ITrustAnchorStore;
  LSource: IServerCertificateVerifierSource;
  LRaised: Boolean;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  // the store drops a distrusted root from RootCertificates, so the roots handed over are empty
  LStore := TTrustAnchorStore.Create(PrivateRoot, PrivateRoot) as ITrustAnchorStore;
  LRaised := False;
  try
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
      TSystemTrustRootScope.HostRoots, LStore.RootCertificates, LStore.DistrustedCertificates)
      as IServerCertificateVerifierSource;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a store that distrusts its only root leaves no root to trust alone');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsRefusesAnEngineWithNoCapabilities;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LRaised: Boolean;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create([], PublicRoot);
  LRaised := False;
  try
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
      TSystemTrustRootScope.HostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource;
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an engine without exclusive server roots cannot trust host roots alone');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsRefusesAnEngineWithOnlyNativeUnion;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LRaised: Boolean;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create([TPlatformChainCapability.NativeAnchorUnion],
    PublicRoot);
  LRaised := False;
  try
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
      TSystemTrustRootScope.HostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource;
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a union with the OS roots is not trusting the host roots alone');
end;

procedure TTestDelegateHostRootsAlone.TestGuardRefusesAnchorsOnAnEngineWithoutExclusiveRoots;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LScripted, LResult: TPlatformChainResult;
  LRequest: TPlatformChainRequest;
  LAlert: TTlsAlertDescription;
begin
  LScripted := Default(TPlatformChainResult);
  LScripted.Outcome := TLiveRevocationOutcome.Good;
  LScripted.Path := PrivateChain;
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], True,
    LScripted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  LRequest := Default(TPlatformChainRequest);
  LRequest.Chain := PrivateChain;
  LRequest.Anchors := PrivateRoot;
  CheckFalse(TDelegateEvaluation.EvaluateServer(LEngine, LRequest, nil, LResult, LAlert),
    'an engine that would judge the chain against the OS roots is never asked');
  CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert), 'the alert is internal_error');
  CheckEquals(0, LMock.ServerCalls, 'the engine is not called');
  CheckEquals(0, System.Length(LResult.Path), 'no path is reported');
end;

procedure TTestDelegateHostRootsAlone.TestGuardLeavesAnOsRootsRequestToAnyEngine;
var
  LMock: TMockPlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LScripted, LResult: TPlatformChainResult;
  LRequest: TPlatformChainRequest;
  LAlert: TTlsAlertDescription;
begin
  LScripted := Default(TPlatformChainResult);
  LScripted.Outcome := TLiveRevocationOutcome.Good;
  LScripted.Path := PrivateChain;
  LMock := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], True,
    LScripted, TTlsAlertDescription.BadCertificate);
  LEngine := LMock;
  LRequest := Default(TPlatformChainRequest);
  LRequest.Chain := PrivateChain;
  CheckTrue(TDelegateEvaluation.EvaluateServer(LEngine, LRequest, nil, LResult, LAlert),
    'a request without anchors reaches an engine that takes none');
  CheckEquals(1, LMock.ServerCalls, 'the engine is called once');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsRawRootAlsoDistrustedLeavesNoRoot;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LMessage: string;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LMessage := '';
  try
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
      TSystemTrustRootScope.HostRoots, PrivateRoot, PrivateRoot)
      as IServerCertificateVerifierSource;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SHostRootsNeedRoots, LMessage,
    'a host root the source also distrusts leaves no root to trust alone');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsDoNotHandTheEngineADistrustedRoot;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  CheckTrue(Verify(LEngine, TSystemTrustRootScope.HostRoots,
    TArray<TBytes>.Create(PrivateRoot[0], PublicRoot[0]), PublicRoot, PrivateChain, 'localhost',
    LAlert), 'the usable host root still vouches');
  CheckEquals(1, System.Length(LFake.Requests[0].Anchors),
    'only the host root that is not distrusted is the exclusive root');
  CheckEqualBytes('it is the usable root', PrivateRoot[0], LFake.Requests[0].Anchors[0]);
end;

procedure TTestDelegateHostRootsAlone.TestOsAndHostRootsDoNotHandTheEngineADistrustedRoot;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  CheckFalse(Verify(LEngine, TSystemTrustRootScope.OsAndHostRoots, PrivateRoot, PrivateRoot,
    PrivateChain, 'localhost', LAlert), 'no path is built through the distrusted host root');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the chain has no anchor');
  CheckEquals(1, LFake.ServerCalls, 'there is no host-root pass to retry with');
  CheckEquals(0, System.Length(LFake.Requests[0].ExtraAnchors),
    'the distrusted root is not offered as an extra anchor');
end;

procedure TTestDelegateHostRootsAlone.TestConstructionChecksLiveFetchBeforeTheRoots;
begin
  CheckEquals(SNoLiveRevocation, ConstructionMessage(
    TAnchorAwarePlatformChainEngine.Create([], PublicRoot) as IPlatformChainEngine,
    TSystemTrustFetch.Live,
    TSystemTrustRootScope.HostRoots, nil, ESystemTrustUnsupportedTlsLibException),
    'a live fetch the engine cannot do is reported first');
end;

procedure TTestDelegateHostRootsAlone.TestConstructionChecksMissingRootsBeforeTheEngineCapability;
begin
  CheckEquals(SHostRootsNeedRoots, ConstructionMessage(
    TAnchorAwarePlatformChainEngine.Create([], PublicRoot) as IPlatformChainEngine,
    TSystemTrustFetch.CacheOnly, TSystemTrustRootScope.HostRoots, nil,
    EArgumentTlsLibException),
    'missing roots are reported before the engine capability');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsWithLiveFetchTrustsThePrivateChain;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.Live,
    TSystemTrustRootScope.HostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource;
  LVerifier := LSource.CreateServerVerifier(Context(TVerdictDeferral.LiveRevocation));
  CheckTrue(LVerifier.VerifyServerCertificate(PrivateChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert), 'a live-fetch source trusts the chain through the host roots');
  CheckEquals(1, System.Length(LFake.Requests[0].Anchors), 'the host roots are the exclusive root');
end;

procedure TTestDelegateHostRootsAlone.TestGuardRefusesAnchorsOnAnEngineWithOnlyNativeUnion;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LResult: TPlatformChainResult;
  LRequest: TPlatformChainRequest;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create([TPlatformChainCapability.NativeAnchorUnion],
    PublicRoot);
  LEngine := LFake;
  LRequest := Default(TPlatformChainRequest);
  LRequest.Chain := PublicChain;
  LRequest.Anchors := PrivateRoot;
  CheckFalse(TDelegateEvaluation.EvaluateServer(LEngine, LRequest, nil, LResult, LAlert),
    'a union with the OS roots is not an exclusive root');
  CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert), 'the alert is internal_error');
  CheckEquals(0, LFake.ServerCalls, 'the engine is not called');
end;

procedure TTestDelegateHostRootsAlone.TestSourceIgnoresLaterMutationOfTheArraysItWasGiven;
var
  LEngine: IPlatformChainEngine;
  LRoots, LDistrusted, LExtras: TArray<TBytes>;
  LAlone, LOsAndHost: IServerCertificateVerifierSource;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LRoots := PrivateRoot;
  LDistrusted := PublicRoot;
  LExtras := PrivateRoot;
  LAlone := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.HostRoots, LRoots, LDistrusted) as IServerCertificateVerifierSource;
  LOsAndHost := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, LExtras, nil) as IServerCertificateVerifierSource;
  LRoots[0][0] := LRoots[0][0] xor $FF;
  LDistrusted[0][0] := LDistrusted[0][0] xor $FF;
  LExtras[0][0] := LExtras[0][0] xor $FF;
  CheckEqualBytes('the anchors are unchanged', PrivateRoot[0],
    (LAlone as TOSVerifierSource).Anchors[0]);
  CheckEqualBytes('the distrust set is unchanged', PublicRoot[0],
    (LAlone as TOSVerifierSource).Distrusted[0]);
  CheckEqualBytes('the extra anchors are unchanged', PrivateRoot[0],
    (LOsAndHost as TOSVerifierSource).ExtraAnchors[0]);
end;

procedure TTestDelegateHostRootsAlone.TestSourceGettersReturnCopies;
var
  LEngine: IPlatformChainEngine;
  LAloneHolder, LOsAndHostHolder: IServerCertificateVerifierSource;
  LAlone, LOsAndHost: TOSVerifierSource;
  LGot: TArray<TBytes>;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LAloneHolder := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.HostRoots, PrivateRoot, PublicRoot) as IServerCertificateVerifierSource;
  LOsAndHostHolder := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource;
  LAlone := LAloneHolder as TOSVerifierSource;
  LOsAndHost := LOsAndHostHolder as TOSVerifierSource;
  LGot := LAlone.Anchors;
  LGot[0][0] := LGot[0][0] xor $FF;
  CheckEqualBytes('the anchors are unchanged', PrivateRoot[0], LAlone.Anchors[0]);
  LGot := LAlone.Distrusted;
  LGot[0][0] := LGot[0][0] xor $FF;
  CheckEqualBytes('the distrust set is unchanged', PublicRoot[0], LAlone.Distrusted[0]);
  LGot := LOsAndHost.ExtraAnchors;
  LGot[0][0] := LGot[0][0] xor $FF;
  CheckEqualBytes('the extra anchors are unchanged', PrivateRoot[0], LOsAndHost.ExtraAnchors[0]);
end;

procedure TTestDelegateHostRootsAlone.TestWebPkiLiveResolverRefusesAnEngineWithoutExclusiveRoots;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create([TPlatformChainCapability.LiveFetch,
    TPlatformChainCapability.CachedRevocation], PublicRoot);
  LEngine := LFake;
  CheckFalse(Resolve(WebPkiConfig, LEngine, PrivateChain, LAlert),
    'the store roots cannot be honoured, so the live pass refuses');
  CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert), 'the alert is internal_error');
  CheckEquals(0, LFake.ServerCalls, 'the engine is not called');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverFromAWebPkiConfigNeverLetsTheOsRootsVouch;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  CheckFalse(Resolve(WebPkiConfig, LEngine, PublicChain, LAlert),
    'a chain only the OS roots know is not accepted under a private store');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
  CheckEquals(1, LFake.ServerCalls, 'the engine judged the chain');
  CheckEquals(1, System.Length(LFake.Requests[0].Anchors),
    'the store roots are the exclusive root');
  CheckEqualBytes('the exclusive root is the store root', PrivateRoot[0],
    LFake.Requests[0].Anchors[0]);
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigWithoutAnOsSourceCarriesTheStoreDistrust;
var
  LConfig: ITlsClientConfig;
  LPolicy: TOSDelegatePolicy;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.WebPki(TTrustAnchorStore.Create(PrivateRoot, PublicRoot)
    as ITrustAnchorStore).Build).Build;
  LPolicy := TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  CheckEquals(1, System.Length(LPolicy.Distrusted), 'the store distrust set is carried');
  CheckEqualBytes('it is the store entry', PublicRoot[0], LPolicy.Distrusted[0]);
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigCarriesEveryPolicyField;
var
  LStrength: TCertificateStrengthPolicy;
  LLimits: TCertificateChainLimits;
  LConfig: ITlsClientConfig;
  LPolicy: TOSDelegatePolicy;
begin
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 3072;
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxChainCertificates := 7;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.WebPki(TTrustAnchorStore.Create(PrivateRoot) as ITrustAnchorStore)
    .WithRevocation(TRevocationPosture.Off).WithMinimumStrength(LStrength)
    .WithIntermediateCertificates(DecodeHex(FEc.Values['leaf_cert'])).Build)
    .WithCertificateChainLimits(LLimits).WithClock(TMockClock.Create(1700000000000) as ITlsClock)
    .WithAsyncCertificateVerdict(1234).Build;
  LPolicy := TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  CheckTrue(LPolicy.Pkix = LConfig.Pkix, 'the PKIX provider');
  CheckTrue(LPolicy.Clock = LConfig.Clock, 'the clock');
  CheckEquals(Ord(TRevocationPosture.Off), Ord(LPolicy.Posture), 'the revocation posture');
  CheckEquals(3072, LPolicy.StrengthPolicy.MinRsaModulusBits, 'the strength policy');
  CheckEquals(7, LPolicy.ChainLimits.MaxChainCertificates, 'the chain limits');
  CheckEquals(System.Length(TSignatureSchemeCodes.FromRegistry(LConfig.SignatureSchemes)),
    System.Length(LPolicy.AdvertisedSchemes), 'the advertised schemes');
  CheckTrue(System.Length(LPolicy.AdvertisedSchemes) > 0, 'some schemes are advertised');
  CheckEquals(1234, LPolicy.DeadlineMs, 'the live deadline');
  CheckEquals(1, System.Length(LPolicy.Intermediates), 'the configured intermediates');
  CheckEquals(Ord(TSystemTrustFetch.Live), Ord(LPolicy.Fetch), 'the live pass fetches');
  CheckTrue(LPolicy.CheckHostName, 'the host name is matched');
end;

procedure TTestDelegateHostRootsAlone.TestFromServerConfigCarriesEveryPolicyField;
var
  LStrength: TCertificateStrengthPolicy;
  LLimits: TCertificateChainLimits;
  LConfig: ITlsServerConfig;
  LPolicy: TOSDelegatePolicy;
begin
  LStrength := TCertificateStrengthPolicy.Defaults;
  LStrength.MinRsaModulusBits := 3072;
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxChainCertificates := 7;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix, DecodeHex(FEc.Values['leaf_cert']),
    DecodeHex(FEc.Values['leaf_key'])))
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(
    TTrustAnchorStore.Create(PrivateRoot) as ITrustAnchorStore)
    .WithRevocation(TRevocationPosture.Off).WithMinimumStrength(LStrength)
    .WithIntermediateCertificates(DecodeHex(FEc.Values['leaf_cert'])).Build)
    .WithCertificateChainLimits(LLimits).WithClock(TMockClock.Create(1700000000000) as ITlsClock)
    .WithAsyncCertificateVerdict(1234).Build;
  LPolicy := TOSDelegatePolicy.FromServerConfig(LConfig);
  CheckTrue(LPolicy.Pkix = LConfig.Pkix, 'the PKIX provider');
  CheckTrue(LPolicy.Clock = LConfig.Clock, 'the clock');
  CheckEquals(Ord(TRevocationPosture.Off), Ord(LPolicy.Posture), 'the revocation posture');
  CheckEquals(3072, LPolicy.StrengthPolicy.MinRsaModulusBits, 'the strength policy');
  CheckEquals(7, LPolicy.ChainLimits.MaxChainCertificates, 'the chain limits');
  CheckEquals(System.Length(TSignatureSchemeCodes.FromRegistry(LConfig.SignatureSchemes)),
    System.Length(LPolicy.AdvertisedSchemes), 'the advertised schemes');
  CheckTrue(System.Length(LPolicy.AdvertisedSchemes) > 0, 'some schemes are advertised');
  CheckEquals(1234, LPolicy.DeadlineMs, 'the live deadline');
  CheckEquals(1, System.Length(LPolicy.Intermediates), 'the configured intermediates');
  CheckEquals(Ord(TSystemTrustFetch.Live), Ord(LPolicy.Fetch), 'the live pass fetches');
  CheckFalse(LPolicy.CheckHostName, 'a client certificate has no name to match');
end;

procedure TTestDelegateHostRootsAlone.TestHostRootsSourceCarriesItsRootsAsAnchors;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LOs: TOSVerifierSource;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.HostRoots, PrivateRoot, PublicRoot)
    as IServerCertificateVerifierSource;
  CheckTrue(LSource is TOSVerifierSource, 'the source is the OS source');
  LOs := LSource as TOSVerifierSource;
  CheckEquals(1, System.Length(LOs.Anchors), 'the host roots are the anchors');
  CheckEqualBytes('the anchor is the host root', PrivateRoot[0], LOs.Anchors[0]);
  CheckEquals(0, System.Length(LOs.ExtraAnchors), 'there are no extras');
  CheckEquals(1, System.Length(LOs.Distrusted), 'the distrust set is carried');
end;

procedure TTestDelegateHostRootsAlone.TestOsAndHostRootsSourceCarriesNoAnchors;
var
  LEngine: IPlatformChainEngine;
  LSource: IServerCertificateVerifierSource;
  LOs: TOSVerifierSource;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource;
  CheckTrue(LSource is TOSVerifierSource, 'the source is the OS source');
  LOs := LSource as TOSVerifierSource;
  CheckEquals(0, System.Length(LOs.Anchors), 'the OS roots stay the root');
  CheckEquals(1, System.Length(LOs.ExtraAnchors), 'the host roots are extras');
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigCarriesHostRoots;
var
  LEngine: IPlatformChainEngine;
  LConfig: ITlsClientConfig;
  LPolicy: TOSDelegatePolicy;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LConfig := ClientConfig(TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.HostRoots, PrivateRoot, PublicRoot) as IServerCertificateVerifierSource);
  LPolicy := TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  CheckEquals(1, System.Length(LPolicy.Anchors), 'the live pass builds against the host roots');
  CheckEqualBytes('the anchor is the host root', PrivateRoot[0], LPolicy.Anchors[0]);
  CheckEquals(1, System.Length(LPolicy.Distrusted), 'it applies the same distrust');
  CheckEquals(0, System.Length(LPolicy.ExtraAnchors), 'there are no extras');
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigCarriesOsAndHostRoots;
var
  LEngine: IPlatformChainEngine;
  LConfig: ITlsClientConfig;
  LPolicy: TOSDelegatePolicy;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LConfig := ClientConfig(TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource);
  LPolicy := TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  CheckEquals(0, System.Length(LPolicy.Anchors), 'the OS roots stay the root');
  CheckEquals(1, System.Length(LPolicy.ExtraAnchors), 'the host roots ride with them');
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigWithoutAnOsSourceTakesTheTrustStore;
var
  LConfig: ITlsClientConfig;
  LPolicy: TOSDelegatePolicy;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.WebPki(TTrustAnchorStore.Create(PrivateRoot) as ITrustAnchorStore)
    .Build).Build;
  LPolicy := TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  CheckEquals(1, System.Length(LPolicy.Anchors), 'the store roots are the exclusive root');
  CheckEquals(Ord(TSystemTrustFetch.Live), Ord(LPolicy.Fetch), 'the live pass fetches');
  CheckTrue(LPolicy.CheckHostName, 'the host name is matched as the config asks');
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigRefusesAHostSource;
var
  LConfig: ITlsClientConfig;
  LMessage: string;
begin
  LConfig := ClientConfig(TFakeHostVerifierSource.Create as IServerCertificateVerifierSource);
  LMessage := '';
  try
    TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SLiveNeedsKnownRoots, LMessage,
    'a host source with no trust store hides the roots the live pass must use');
  CheckTrue(Pos('pass the OS source it wraps', LMessage) > 0,
    'the refusal points at the overload for a decorated source');
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigTakesTheAnchorsAndDistrustOfTheRootsSource;
var
  LEngine: IPlatformChainEngine;
  LConfig: ITlsClientConfig;
  LRootsOf: IServerCertificateVerifierSource;
  LPolicy: TOSDelegatePolicy;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LRootsOf := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.HostRoots, PrivateRoot, PublicRoot) as IServerCertificateVerifierSource;
  LConfig := ClientConfig(TFakeHostVerifierSource.Create as IServerCertificateVerifierSource);
  LPolicy := TOSDelegatePolicy.FromClientConfig(LConfig, LRootsOf);
  CheckEquals(1, System.Length(LPolicy.Anchors), 'the decorated source''s anchor is carried');
  CheckEqualBytes('it is the host root', PrivateRoot[0], LPolicy.Anchors[0]);
  CheckEquals(1, System.Length(LPolicy.Distrusted), 'its distrust set is carried');
  CheckEqualBytes('it is the distrusted root', PublicRoot[0], LPolicy.Distrusted[0]);
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigTakesTheExtraAnchorsOfTheRootsSource;
var
  LEngine: IPlatformChainEngine;
  LConfig: ITlsClientConfig;
  LRootsOf: IServerCertificateVerifierSource;
  LPolicy: TOSDelegatePolicy;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LRootsOf := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.OsAndHostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource;
  LConfig := ClientConfig(TFakeHostVerifierSource.Create as IServerCertificateVerifierSource);
  LPolicy := TOSDelegatePolicy.FromClientConfig(LConfig, LRootsOf);
  CheckEquals(0, System.Length(LPolicy.Anchors), 'the OS roots stay the root');
  CheckEquals(1, System.Length(LPolicy.ExtraAnchors), 'the decorated source''s extra is carried');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverOverloadRefusesARootsSourceThatIsNotOs;
var
  LConfig: ITlsClientConfig;
  LMessage: string;
begin
  LConfig := ClientConfig(TFakeHostVerifierSource.Create as IServerCertificateVerifierSource);
  LMessage := '';
  try
    TOSSystemTrust.LiveRevocationResolver(LConfig, TFakeHostVerifierSource.Create
      as IServerCertificateVerifierSource, nil).Free;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SLiveRootsOfNeedsOsSource, LMessage, 'only the OS source supplies roots');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverOverloadRefusesNoRootsSource;
var
  LConfig: ITlsClientConfig;
  LMessage: string;
begin
  LConfig := ClientConfig(TFakeHostVerifierSource.Create as IServerCertificateVerifierSource);
  LMessage := '';
  try
    TOSSystemTrust.LiveRevocationResolver(LConfig, nil, nil).Free;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SLiveRootsOfNeedsOsSource, LMessage, 'a missing roots source is refused too');
end;

procedure TTestDelegateHostRootsAlone.TestFromServerConfigTakesTheClientCaStore;
var
  LConfig: ITlsServerConfig;
  LPolicy: TOSDelegatePolicy;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix, DecodeHex(FEc.Values['leaf_cert']),
    DecodeHex(FEc.Values['leaf_key'])))
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(
    TTrustAnchorStore.Create(PrivateRoot, PublicRoot) as ITrustAnchorStore).Build).Build;
  LPolicy := TOSDelegatePolicy.FromServerConfig(LConfig);
  CheckEquals(1, System.Length(LPolicy.Anchors), 'the client-CA roots are the exclusive root');
  CheckEquals(1, System.Length(LPolicy.Distrusted), 'its distrust set is carried');
  CheckFalse(LPolicy.CheckHostName, 'a client certificate has no name to match');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverAcceptsThePrivateChainUnderHostRoots;
var
  LFake: TAnchorAwarePlatformChainEngine;
  LEngine: IPlatformChainEngine;
  LConfig: ITlsClientConfig;
  LAlert: TTlsAlertDescription;
begin
  LFake := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LEngine := LFake;
  LConfig := ClientConfig(TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.HostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource);
  CheckTrue(Resolve(LConfig, LEngine, PrivateChain, LAlert),
    'the live pass trusts the chain through the host roots');
  CheckEquals(1, LFake.ServerCalls, 'one evaluation');
  CheckTrue(LFake.Requests[0].NetworkAllowed, 'the live pass fetches');
  CheckEquals(Ord(TPlatformRevocationCheck.RequirePositive), Ord(LFake.Requests[0].Revocation),
    'and requires a positive revocation answer');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverRejectsAPublicRootedChainUnderHostRoots;
var
  LEngine: IPlatformChainEngine;
  LConfig: ITlsClientConfig;
  LAlert: TTlsAlertDescription;
begin
  LEngine := TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot);
  LConfig := ClientConfig(TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly,
    TSystemTrustRootScope.HostRoots, PrivateRoot, nil) as IServerCertificateVerifierSource);
  CheckFalse(Resolve(LConfig, LEngine, PublicChain, LAlert),
    'the live pass does not let the OS roots vouch');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverOverloadRefusesADifferentOsRootsSource;
var
  LConfig: ITlsClientConfig;
  LMessage: string;
begin
  LConfig := ClientConfig(TOSVerifierSource.Create(
    TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot) as IPlatformChainEngine,
    TSystemTrustFetch.CacheOnly, TSystemTrustRootScope.HostRoots, PrivateRoot, nil)
    as IServerCertificateVerifierSource);
  LMessage := '';
  try
    TOSSystemTrust.LiveRevocationResolver(LConfig, TOSVerifierSource.Create(
      TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot) as IPlatformChainEngine,
      TSystemTrustFetch.CacheOnly, TSystemTrustRootScope.OsAndHostRoots, nil, nil)
      as IServerCertificateVerifierSource, nil).Free;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SLiveRootsOfSourceDiffers, LMessage,
    'roots read off another OS source would differ from the inline pass');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverOverloadAcceptsTheConfigsOwnOsSource;
var
  LSource: IServerCertificateVerifierSource;
  LConfig: ITlsClientConfig;
  LMessage: string;
begin
  LSource := TOSVerifierSource.Create(
    TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot) as IPlatformChainEngine,
    TSystemTrustFetch.CacheOnly, TSystemTrustRootScope.HostRoots, PrivateRoot, nil)
    as IServerCertificateVerifierSource;
  LConfig := ClientConfig(LSource);
  LMessage := '';
  try
    TOSSystemTrust.LiveRevocationResolver(LConfig, LSource, nil).Free;
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
    // a platform without an engine refuses after the source checks have passed
    on E: ESystemTrustUnsupportedTlsLibException do
      LMessage := '';
  end;
  CheckEquals('', LMessage, 'the config''s own OS source is accepted as the roots source');
end;

procedure TTestDelegateHostRootsAlone.TestFromClientConfigRefusesAConfigWithoutAServerCertificate;
var
  LConfig: ITlsClientConfig;
  LMessage: string;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.DangerousSkip).Build;
  LMessage := '';
  try
    TOSDelegatePolicy.FromClientConfig(LConfig, LConfig.ServerVerifierSource);
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SLiveNeedsServerVerification, LMessage,
    'a skip-verify config has no server certificate to re-check');
end;

procedure TTestDelegateHostRootsAlone.TestServerBuildRefusesAWeakClientAnchorWithFloorsOn;
begin
  CheckTrue(Pos('AnchorKeyFloors', ServerBuildMessage(True, WeakRoot)) > 0,
    'an RSA-2048 client-CA anchor is below a 4096-bit floor');
end;

procedure TTestDelegateHostRootsAlone.TestServerBuildKeepsAWeakClientAnchorWithFloorsOff;
begin
  CheckEquals('', ServerBuildMessage(False, WeakRoot), 'the anchor is exempt from the floors');
end;

procedure TTestDelegateHostRootsAlone.TestServerBuildKeepsAClientAnchorThatMeetsTheFloors;
begin
  CheckEquals('', ServerBuildMessage(True, PrivateRoot), 'a P-256 anchor meets the floors');
end;

procedure TTestDelegateHostRootsAlone.TestClientDelegateRefusesAWeakAnchorAnEngineReportsAsExempt;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyClient(TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot)
    as IPlatformChainEngine, WeakRoot, WeakRootChain, True, LAlert),
    'the walk holds the reported anchor to the floors');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a weak anchor key is unsupported_certificate');
end;

procedure TTestDelegateHostRootsAlone.TestClientDelegateAcceptsAWeakExemptAnchorWithFloorsOff;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyClient(TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot)
    as IPlatformChainEngine, WeakRoot, WeakRootChain, False, LAlert),
    'the anchor is exempt while the flag is off');
end;

procedure TTestDelegateHostRootsAlone.TestClientDelegateRefusesAWeakAnchorWhenTheEngineReportsNone;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyClient(NoAnchorEngine, WeakRoot, WeakRootChain, True, LAlert),
    'the configured anchors are key-checked when the walk never sees one');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a weak anchor key is unsupported_certificate');
end;

procedure TTestDelegateHostRootsAlone.TestClientDelegateAcceptsAWeakUnreportedAnchorWithFloorsOff;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyClient(NoAnchorEngine, WeakRoot, WeakRootChain, False, LAlert),
    'the anchor is exempt while the flag is off');
end;

procedure TTestDelegateHostRootsAlone.TestClientDelegateAcceptsAStrongExemptAnchorBesideAWeakOne;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyClient(TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot)
    as IPlatformChainEngine, TArray<TBytes>.Create(PrivateRoot[0], WeakRoot[0]), PrivateChain,
    True, LAlert), 'a reported exempt anchor means the configured anchors are not key-checked');
end;

procedure TTestDelegateHostRootsAlone.TestClientDelegateRefusesAnAnchorWithAnUndescribableKey;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyClient(NoAnchorEngine, TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/DsaRoot.txt', 'root_cert')), WeakRootChain, True, LAlert),
    'a DSA anchor key has no floor to meet');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'an anchor key that cannot be described is unsupported_certificate');
end;

procedure TTestDelegateHostRootsAlone.TestClientDelegateReportsAnUnparseableAnchorAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyClient(NoAnchorEngine, TArray<TBytes>.Create(TBytes.Create($30, $03, $02, $01,
    $00)), WeakRootChain, True, LAlert), 'an anchor that does not parse fails closed');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'a parse failure stays bad_certificate');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverRefusesAWeakAnchorWhenTheEngineReportsNone;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ResolveClient(NoAnchorEngine, WeakRoot, WeakRootChain, True, LAlert),
    'the live pass key-checks the configured anchors when the walk never sees one');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a weak anchor key is unsupported_certificate');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverAcceptsAWeakAnchorWithFloorsOff;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ResolveClient(NoAnchorEngine, WeakRoot, WeakRootChain, False, LAlert),
    'the anchor is exempt while the flag is off');
end;

procedure TTestDelegateHostRootsAlone.TestLiveResolverAcceptsAStrongExemptAnchorBesideAWeakOne;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ResolveClient(TAnchorAwarePlatformChainEngine.Create(ExclusiveCaps, PublicRoot)
    as IPlatformChainEngine, TArray<TBytes>.Create(PrivateRoot[0], WeakRoot[0]), PrivateChain,
    True, LAlert), 'a reported exempt anchor means the configured anchors are not key-checked');
end;

procedure TTestDelegateHostRootsAlone.TestOsAndHostRootsRefusesANonUnionEngineWhateverTheDistrust;
var
  LMessage: string;
  LSource: IServerCertificateVerifierSource;
begin
  LMessage := '';
  try
    LSource := TOSVerifierSource.Create(TAnchorAwarePlatformChainEngine.Create([], PublicRoot)
      as IPlatformChainEngine, TSystemTrustFetch.CacheOnly, TSystemTrustRootScope.OsAndHostRoots,
      PrivateRoot, PrivateRoot) as IServerCertificateVerifierSource;
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SEngineCannotTrustOsAndHostRoots, LMessage,
    'the refusal does not depend on the distrust set');
  CheckTrue(LSource = nil, 'a refused source is not handed back');
end;

procedure TTestDelegateHostRootsAlone.TestOsAndHostRootsWithAllHostRootsDistrustedIsOsRootsOnly;
var
  LSource: TOSVerifierSource;
  LIntf: IServerCertificateVerifierSource;
begin
  LIntf := TOSVerifierSource.Create(TAnchorAwarePlatformChainEngine.Create(
    [TPlatformChainCapability.NativeAnchorUnion], PublicRoot) as IPlatformChainEngine,
    TSystemTrustFetch.CacheOnly, TSystemTrustRootScope.OsAndHostRoots, PrivateRoot, PrivateRoot)
    as IServerCertificateVerifierSource;
  LSource := LIntf as TOSVerifierSource;
  CheckEquals(0, System.Length(LSource.ExtraAnchors), 'no host root is left to trust');
  CheckEquals(0, System.Length(LSource.Anchors), 'the OS roots stand alone');
end;

{ TTestSystemTrustRoots }

function TTestSystemTrustRoots.Store: ITrustAnchorStore;
var
  LEc: TStringList;
begin
  LEc := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
  Result := TTrustAnchorStore.Create(TArray<TBytes>.Create(DecodeHex(LEc.Values['root_cert'])))
    as ITrustAnchorStore;
end;

procedure TTestSystemTrustRoots.TestOsRootsHasNoStoreAndTheOsAndHostRootsScope;
var
  LRoots: TSystemTrustRoots;
begin
  LRoots := TSystemTrustRoots.OsRoots;
  CheckNull(LRoots.Store, 'no host roots');
  CheckEquals(Ord(TSystemTrustRootScope.OsAndHostRoots), Ord(LRoots.Scope), 'the OS roots stand');
end;

procedure TTestSystemTrustRoots.TestDefaultValueIsOsRoots;
var
  LRoots: TSystemTrustRoots;
begin
  LRoots := Default(TSystemTrustRoots);
  CheckNull(LRoots.Store, 'an unset value has no host roots');
  CheckEquals(Ord(TSystemTrustRootScope.OsAndHostRoots), Ord(LRoots.Scope),
    'an unset value trusts the OS roots');
end;

procedure TTestSystemTrustRoots.TestOsAndHostRootsOfNilIsOsRoots;
var
  LRoots: TSystemTrustRoots;
begin
  LRoots := TSystemTrustRoots.OsAndHostRoots(nil);
  CheckNull(LRoots.Store, 'nil host roots are no host roots');
  CheckEquals(Ord(TSystemTrustRootScope.OsAndHostRoots), Ord(LRoots.Scope),
    'the scope is the OS one');
end;

procedure TTestSystemTrustRoots.TestOsAndHostRootsKeepsTheStoreAndScope;
var
  LStore: ITrustAnchorStore;
  LRoots: TSystemTrustRoots;
begin
  LStore := Store;
  LRoots := TSystemTrustRoots.OsAndHostRoots(LStore);
  CheckTrue(LRoots.Store = LStore, 'the store is carried as given');
  CheckEquals(Ord(TSystemTrustRootScope.OsAndHostRoots), Ord(LRoots.Scope), 'OS and host roots');
end;

procedure TTestSystemTrustRoots.TestHostRootsKeepsTheStoreIdentityAndScope;
var
  LStore: ITrustAnchorStore;
  LRoots: TSystemTrustRoots;
begin
  LStore := Store;
  LRoots := TSystemTrustRoots.HostRoots(LStore);
  CheckTrue(LRoots.Store = LStore, 'the store is carried as given');
  CheckEquals(Ord(TSystemTrustRootScope.HostRoots), Ord(LRoots.Scope),
    'the host roots stand alone');
end;

procedure TTestSystemTrustRoots.TestHostRootsOfNilIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TSystemTrustRoots.HostRoots(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'host roots alone need a store');
end;

procedure TTestSystemTrustRoots.TestHostRootsOfAStoreWithoutRootsIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'host roots alone need at least one root');
end;

procedure TTestSystemTrustRoots.TestHostRootsOfAStoreDistrustingItsOnlyRootIsRefused;
var
  LRoot: TArray<TBytes>;
  LRaised: Boolean;
begin
  LRoot := Store.RootCertificates;
  LRaised := False;
  try
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(LRoot, LRoot) as ITrustAnchorStore);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a store that distrusts its only root leaves nothing to trust alone');
end;

procedure TTestSystemTrustRoots.TestDistrustStoreCarriesNoRoot;
begin
  if not TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
  begin
    SkipTest('this platform cannot read the OS store');
    Exit;
  end;
  CheckEquals(0, TOSSystemTrust.DistrustStore(Pkix).AnchorCount, 'the distrust list holds no root');
end;

procedure TTestSystemTrustRoots.TestDistrustStoreRefusesANilProvider;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TOSSystemTrust.DistrustStore(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'reading the distrust list needs a PKIX provider');
end;

procedure TTestSystemTrustRoots.TestHostRootsTheOsDistrustsAreRefusedByTheDelegateSource;
var
  LDistrusted: TArray<TBytes>;
  LRoots: TSystemTrustRoots;
  LMessage: string;
begin
  if not (TOSSystemTrust.Supports(TSystemTrustMode.Delegate) and
    TOSSystemTrust.Supports(TSystemTrustMode.Anchors)) then
  begin
    SkipTest('this platform has no delegate with a readable OS distrust list');
    Exit;
  end;
  LDistrusted := TOSSystemTrust.DistrustStore(Pkix).DistrustedCertificates;
  if System.Length(LDistrusted) = 0 then
  begin
    SkipTest('the OS distrust list is empty, so there is no distrusted root to hand in');
    Exit;
  end;
  LRoots := TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(
    TArray<TBytes>.Create(LDistrusted[0])) as ITrustAnchorStore);
  LMessage := '';
  try
    TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly, LRoots, Pkix);
  except
    on E: EArgumentTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals(SHostRootsNeedRoots, LMessage,
    'a host root the OS distrusts leaves nothing to trust');
end;

procedure TTestSystemTrustRoots.TestAnchorStoreRefusesANilProvider;
var
  LRaised: Boolean;
begin
  if not TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
  begin
    SkipTest('this platform cannot harvest OS anchors');
    Exit;
  end;
  LRaised := False;
  try
    TOSSystemTrust.AnchorStore(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'harvesting the OS roots needs a PKIX provider, as the distrust list does');
end;

procedure TTestSystemTrustRoots.TestAnchorsModeHostRootsComposesExactlyTheHostRoots;
var
  LStore, LUnion: ITrustAnchorStore;
  LVerification: IServerVerification;
  LRoot: TBytes;
begin
  if not TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
  begin
    SkipTest('this platform cannot harvest OS anchors');
    Exit;
  end;
  LStore := Store;
  LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Anchors,
    TSystemTrustRoots.HostRoots(LStore)).Build;
  CheckEquals(Ord(TVerificationKind.WebPki), Ord(LVerification.Kind), 'our own validator');
  CheckEquals(2, System.Length(LVerification.AnchorStores), 'the host roots and the OS distrust');
  CheckTrue(LVerification.AnchorStores[0] = LStore, 'the host store is the first one');
  CheckEquals(0, LVerification.AnchorStores[1].AnchorCount, 'the OS store holds no root');
  CheckEquals(System.Length(TOSSystemTrust.DistrustStore(Pkix).DistrustedCertificates),
    System.Length(LVerification.AnchorStores[1].DistrustedCertificates),
    'the second store carries the OS distrust list');
  LUnion := TTrustAnchorStore.Union(LVerification.AnchorStores);
  CheckEquals(LStore.AnchorCount, LUnion.AnchorCount, 'no OS root joins the host roots');
  for LRoot in LStore.RootCertificates do
    CheckTrue(LUnion.IsAnchor(LRoot), 'the host root is the anchor');
end;

procedure TTestSystemTrustRoots.TestAnchorsModeOsAndHostRootsAddsTheHostRootsToTheHarvest;
var
  LStore: ITrustAnchorStore;
  LVerification: IServerVerification;
begin
  if not TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
  begin
    SkipTest('this platform cannot harvest OS anchors');
    Exit;
  end;
  LStore := Store;
  LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Anchors,
    TSystemTrustRoots.OsAndHostRoots(LStore)).Build;
  CheckEquals(2, System.Length(LVerification.AnchorStores), 'the harvest and the host roots');
  CheckTrue(LVerification.AnchorStores[1] = LStore, 'the host store is the second one');
end;

{ TTestSystemTrustFixtures }

function TTestSystemTrustFixtures.FileSnapshot(const AEnvFile, AEnvDir: string;
  const AFiles, ADirs: TArray<string>): ITrustAnchorStore;
var
  LSource: TFileSystemRootSource;
begin
  LSource := TFileSystemRootSource.Create(Pkix, AEnvFile, AEnvDir, AFiles, ADirs);
  try
    Result := LSource.Snapshot;
  finally
    LSource.Free;
  end;
end;

procedure TTestSystemTrustFixtures.WriteBytes(const APath: string; const AData: TBytes);
var
  LStream: TFileStream;
begin
  LStream := TFileStream.Create(APath, fmCreate);
  try
    if System.Length(AData) > 0 then
      LStream.WriteBuffer(AData[0], System.Length(AData));
  finally
    LStream.Free;
  end;
end;

procedure TTestSystemTrustFixtures.SetUp;
var
  LDer: TBytes;
  LVectors: TStringList;
begin
  inherited SetUp;
  FDir := TempPath('systrust_fixtures');
  ForceDirectories(FDir);
  FCertDir := IncludeTrailingPathDelimiter(FDir) + 'certsdir';
  ForceDirectories(FCertDir);

  LVectors := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    LDer := DecodeHex(LVectors.Values['root_cert']);
    FRootDer := LDer;
    FRoot2Der := DecodeHex(LVectors.Values['root2_cert']);
  finally
    LVectors.Free;
  end;
  FFile := IncludeTrailingPathDelimiter(FDir) + 'roots.der';
  WriteBytes(FFile, LDer);
  WriteBytes(IncludeTrailingPathDelimiter(FCertDir) + 'root.der', LDer);
  FMissing := IncludeTrailingPathDelimiter(FDir) + 'does-not-exist.der';
  FExtraDir := IncludeTrailingPathDelimiter(FDir) + 'extradir';
  ForceDirectories(FExtraDir);
  WriteBytes(IncludeTrailingPathDelimiter(FExtraDir) + 'root2.der', FRoot2Der);
end;

procedure TTestSystemTrustFixtures.TearDown;
begin
  SysUtils.DeleteFile(IncludeTrailingPathDelimiter(FExtraDir) + 'root2.der');
  SysUtils.RemoveDir(FExtraDir);
  SysUtils.DeleteFile(FFile);
  SysUtils.DeleteFile(IncludeTrailingPathDelimiter(FCertDir) + 'root.der');
  SysUtils.RemoveDir(FCertDir);
  SysUtils.RemoveDir(FDir);
  inherited TearDown;
end;

procedure TTestSystemTrustFixtures.TestInjectedFileHarvestsRoot;
begin
  // a single injected bundle file yields exactly its one root
  CheckEquals(1, System.Length(FileSnapshot('', '',
    TArray<string>.Create(FFile), nil).RootCertificates),
    'the injected bundle file is harvested into one anchor');
end;

procedure TTestSystemTrustFixtures.TestFirstExistingFileCandidateWins;
begin
  // a missing candidate is skipped; the first EXISTING file becomes the authoritative store
  CheckEquals(1, System.Length(FileSnapshot('', '',
    TArray<string>.Create(FMissing, FFile), nil).RootCertificates),
    'the first existing candidate file is used, missing ones skipped');
end;

procedure TTestSystemTrustFixtures.TestNoReadableStoreFailsClosed;
var
  LRaised: Boolean;
begin
  // nothing readable anywhere -> fail closed at build, never a silent empty trust store
  LRaised := False;
  try
    FileSnapshot('', '', TArray<string>.Create(FMissing), TArray<string>.Create(FMissing));
  except
    on E: ESystemTrustUnavailableTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an unreadable/empty system store fails closed');
end;

procedure TTestSystemTrustFixtures.TestDirectoryHarvestReadsCerts;
begin
  // a directory of certificate files is enumerated and harvested
  CheckTrue(System.Length(FileSnapshot('', '', nil,
    TArray<string>.Create(FCertDir)).RootCertificates) >= 1,
    'the certificate directory is enumerated into anchors');
end;

procedure TTestSystemTrustFixtures.TestDuplicateCertsAreDeduplicated;
var
  LDir: string;
begin
  LDir := IncludeTrailingPathDelimiter(FDir) + 'dupdir';
  ForceDirectories(LDir);
  try
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'a.der', FRootDer);
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'b.der', FRootDer);
    CheckEquals(1, System.Length(FileSnapshot('', '', nil,
      TArray<string>.Create(LDir)).RootCertificates),
      'the same certificate under two names is de-duplicated to one anchor');
  finally
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'a.der');
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'b.der');
    SysUtils.RemoveDir(LDir);
  end;
end;

procedure TTestSystemTrustFixtures.TestDistinctCertsAreNotMerged;
var
  LDir: string;
begin
  LDir := IncludeTrailingPathDelimiter(FDir) + 'distinctdir';
  ForceDirectories(LDir);
  try
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'r1.der', FRootDer);
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'r2.der', FRoot2Der);
    CheckEquals(2, System.Length(FileSnapshot('', '', nil,
      TArray<string>.Create(LDir)).RootCertificates),
      'two distinct certificates are harvested as two anchors');
  finally
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'r1.der');
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'r2.der');
    SysUtils.RemoveDir(LDir);
  end;
end;

procedure TTestSystemTrustFixtures.TestSnapshotSurvivesSourceFileDeletion;
var
  LDir, LFile: string;
  LStore: ITrustAnchorStore;
begin
  // the snapshot owns its DER: once built, deleting the underlying bundle does not change it
  LDir := IncludeTrailingPathDelimiter(FDir) + 'snapdir';
  ForceDirectories(LDir);
  LFile := IncludeTrailingPathDelimiter(LDir) + 'snap.der';
  try
    WriteBytes(LFile, FRootDer);
    LStore := FileSnapshot('', '', TArray<string>.Create(LFile), nil);
    CheckEquals(1, System.Length(LStore.RootCertificates),
      'the snapshot harvested the bundle');
    SysUtils.DeleteFile(LFile);
    CheckEquals(1, System.Length(LStore.RootCertificates),
      'the snapshot still returns its roots after the source file is deleted');
  finally
    SysUtils.DeleteFile(LFile);
    SysUtils.RemoveDir(LDir);
  end;
end;

procedure TTestSystemTrustFixtures.TestEnvDirListHarvestsEveryEntry;
begin
  CheckEquals(2, System.Length(FileSnapshot('', FCertDir + PathSep + FExtraDir,
    nil, nil).RootCertificates),
    'every directory in the list is harvested');
end;

procedure TTestSystemTrustFixtures.TestEnvDirListSkipsMissingEntry;
begin
  CheckEquals(1, System.Length(FileSnapshot('', FMissing + PathSep + FCertDir,
    nil, nil).RootCertificates),
    'a missing entry is skipped and the existing one is harvested');
end;

procedure TTestSystemTrustFixtures.TestEnvDirListWithNoExistingEntryFailsClosed;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    FileSnapshot('', FMissing + PathSep + FMissing + 'x', nil, TArray<string>.Create(FCertDir));
  except
    on E: ESystemTrustUnavailableTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a list naming no existing directory fails closed without falling back');
end;

procedure TTestSystemTrustFixtures.TestEnvDirListIgnoresEmptyEntries;
begin
  CheckEquals(2, System.Length(FileSnapshot('',
    PathSep + FCertDir + PathSep + PathSep + FExtraDir + PathSep,
    nil, nil).RootCertificates),
    'leading, doubled and trailing separators add no entry');
end;

procedure TTestSystemTrustFixtures.TestEnvFileAndEnvDirAreBothHarvested;
begin
  CheckEquals(2, System.Length(FileSnapshot(FFile, FExtraDir, nil, nil).RootCertificates),
    'the bundle file and the directory are both harvested');
end;

procedure TTestSystemTrustFixtures.TestEnvFileAndEnvDirSharingACertificateDeduplicate;
begin
  CheckEquals(1, System.Length(FileSnapshot(FFile, FCertDir, nil, nil).RootCertificates),
    'a certificate present in both sources is one anchor');
end;

procedure TTestSystemTrustFixtures.TestEnvDirOverrideReplacesDefaultFiles;
var
  LRoots: TArray<TBytes>;
begin
  LRoots := FileSnapshot('', FExtraDir, TArray<string>.Create(FFile), nil).RootCertificates;
  CheckEquals(1, System.Length(LRoots),
    'the default bundle is not loaded when only the directory is named');
  CheckTrue(TArrayUtilities.AreEqual(LRoots[0], FRoot2Der),
    'the harvested anchor is the named directory''s, not the default bundle''s');
end;

procedure TTestSystemTrustFixtures.TestEnvFileOverrideReplacesDefaultDirs;
var
  LRoots: TArray<TBytes>;
begin
  LRoots := FileSnapshot(FFile, '', nil, TArray<string>.Create(FExtraDir)).RootCertificates;
  CheckEquals(1, System.Length(LRoots),
    'the default directories are not loaded when only the file is named');
  CheckTrue(TArrayUtilities.AreEqual(LRoots[0], FRootDer),
    'the harvested anchor is the named file''s, not the default directory''s');
end;

procedure TTestSystemTrustFixtures.TestEnvDirListWithNoExistingEntryFailsClosedEvenWithAGoodFile;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    FileSnapshot(FFile, FMissing + PathSep + FMissing + 'x', nil, nil);
  except
    on E: ESystemTrustUnavailableTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a directory list naming nothing usable is refused even when the file is good');
end;

procedure TTestSystemTrustFixtures.TestMissingEnvFileFailsClosedEvenWithAGoodDir;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    FileSnapshot(FMissing, FExtraDir, nil, nil);
  except
    on E: ESystemTrustUnavailableTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a missing bundle file is refused even when the directory is good');
end;

procedure TTestSystemTrustFixtures.TestFactoryAnchorStoreMatchesSupports;
var
  LRaised: Boolean;
begin
  // the factory's AnchorStore must AGREE with Supports(Anchors) on every platform: a snapshot
  // where supported (Windows/macOS/Unix), a typed UNSUPPORTED error where not (iOS/Android). On a
  // supported platform AnchorStore harvests eagerly, so a bare box with no readable roots may
  // instead fail closed with UNAVAILABLE - both honor the contract; only UNSUPPORTED would not.
  if TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
  begin
    try
      CheckTrue(TOSSystemTrust.AnchorStore(Pkix) <> nil,
        'a platform that supports Anchors hands back an anchor snapshot');
    except
      on E: ESystemTrustUnavailableTlsLibException do
        ; // acceptable: the platform supports Anchors but this box has no readable roots
    end;
  end
  else
  begin
    LRaised := False;
    try
      TOSSystemTrust.AnchorStore(Pkix);
    except
      on E: ESystemTrustUnsupportedTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised,
      'a platform that does not support Anchors must raise from AnchorStore');
  end;
end;

procedure TTestSystemTrustFixtures.TestFactoryServerVerifierSourceMatchesSupports;
var
  LRaised: Boolean;
begin
  // same contract for the OS delegate source: a source where supported (Windows/macOS/iOS/Android),
  // a typed unsupported error where not (Linux/BSD/Solaris).
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
    CheckTrue(TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
      TSystemTrustRoots.OsRoots, Pkix) <> nil,
      'a platform that supports Delegate must hand back an OS server-verifier source')
  else
  begin
    LRaised := False;
    try
      TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
        TSystemTrustRoots.OsRoots, Pkix);
    except
      on E: ESystemTrustUnsupportedTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised,
      'a platform that does not support Delegate must raise from ServerVerifierSource');
  end;
end;

{ TSystemTrustAnchorContractTestBase }

function TSystemTrustAnchorContractTestBase.RequiresPopulatedStore: Boolean;
begin
  Result := True;
end;

function TSystemTrustAnchorContractTestBase.HarvestOrSkip(
  out ARoots: TArray<TBytes>): Boolean;
begin
  Result := True;
  ARoots := nil;
  try
    ARoots := CreateAnchorStore.RootCertificates;
  except
    on E: ESystemTrustUnavailableTlsLibException do
    begin
      // no readable OS store on this environment (e.g. a bare container without ca-certificates)
      if RequiresPopulatedStore then
        Fail(PlatformName +
          ' OS trust store harvested no roots (expected an always-populated store)');
      Result := False;
      SkipTest(PlatformName + ' has no readable OS trust store here');
    end;
  end;
end;

procedure TSystemTrustAnchorContractTestBase.TestHarvestYieldsRoots;
var
  LRoots: TArray<TBytes>;
begin
  if not HarvestOrSkip(LRoots) then
    Exit;
  CheckTrue(System.Length(LRoots) >= 1,
    PlatformName + ' harvests at least one trust anchor');
end;

procedure TSystemTrustAnchorContractTestBase.TestAllHarvestedRootsWellFormed;
var
  LRoots: TArray<TBytes>;
  LI: Integer;
begin
  if not HarvestOrSkip(LRoots) then
    Exit;
  for LI := 0 to System.Length(LRoots) - 1 do
    CheckTrue(Pkix.Certificates.IsWellFormed(LRoots[LI]),
      Format('%s harvested root #%d is a well-formed certificate', [PlatformName, LI]));
end;

procedure TSystemTrustAnchorContractTestBase.TestHarvestedRootsAreUnique;
var
  LRoots: TArray<TBytes>;
  LI, LJ: Integer;
begin
  if not HarvestOrSkip(LRoots) then
    Exit;
  for LI := 0 to System.Length(LRoots) - 1 do
    for LJ := LI + 1 to System.Length(LRoots) - 1 do
      CheckFalse(AreEqual(LRoots[LI], LRoots[LJ]),
        Format('%s harvested roots %d and %d are duplicates', [PlatformName, LI, LJ]));
end;

procedure TSystemTrustAnchorContractTestBase.TestNoHarvestedRootIsDistrusted;
var
  LRoots: TArray<TBytes>;
  LStore: ITrustAnchorStore;
  LI: Integer;
begin
  if not HarvestOrSkip(LRoots) then
    Exit;
  // a snapshot never lists a distrusted certificate as an anchor
  LStore := CreateAnchorStore;
  for LI := 0 to System.Length(LRoots) - 1 do
    CheckFalse(LStore.IsDistrusted(LRoots[LI]),
      Format('%s harvested root %d is also distrusted', [PlatformName, LI]));
end;

{$IFDEF TLSLIB_MSWINDOWS}

{ TTestWindowsSystemTrust }

function TTestWindowsSystemTrust.CreateAnchorStore: ITrustAnchorStore;
var
  LSource: TWindowsRootSource;
begin
  LSource := TWindowsRootSource.Create(Pkix);
  try
    Result := LSource.Snapshot;
  finally
    LSource.Free;
  end;
end;

function TTestWindowsSystemTrust.PlatformName: string;
begin
  Result := 'Windows';
end;

procedure TTestWindowsSystemTrust.TestReadDistrustedMatchesSnapshotDistrust;
var
  LSource: TWindowsRootSource;
  LRead: TArray<TBytes>;
  LStore: ITrustAnchorStore;
  LI: Int32;
begin
  LSource := TWindowsRootSource.Create(Pkix);
  try
    LRead := LSource.ReadDistrusted;
  finally
    LSource.Free;
  end;
  LStore := CreateAnchorStore;
  CheckEquals(System.Length(LStore.DistrustedCertificates), System.Length(LRead),
    'ReadDistrusted returns the Disallowed store alone');
  for LI := 0 to System.Length(LRead) - 1 do
    CheckTrue(LStore.IsDistrusted(LRead[LI]),
      Format('read distrusted certificate %d is in the snapshot distrust set', [LI]));
end;

{ TTestWindowsClientDelegate }

procedure TTestWindowsClientDelegate.SetUp;
begin
  inherited SetUp;
  FChain := Own<TStringList>(LoadVectorFields('Certs/ClientAuthChain.txt'));
  FForeign := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
end;

function TTestWindowsClientDelegate.Leaf: TArray<TBytes>;
begin
  // the dual-EKU (serverAuth+clientAuth) leaf, presented alone (its issuer is the exclusive root)
  Result := TArray<TBytes>.Create(DecodeHex(FChain.Values['leaf_cert']));
end;

function TTestWindowsClientDelegate.OwnAnchor: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FChain.Values['root_cert']));
end;

function TTestWindowsClientDelegate.ForeignAnchor: TArray<TBytes>;
begin
  // an unrelated private root: the leaf does not chain to it
  Result := TArray<TBytes>.Create(DecodeHex(FForeign.Values['root_cert']));
end;

function TTestWindowsClientDelegate.Advertised: TArray<UInt16>;
begin
  Result := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
    TSignatureSchemes.EcdsaSecp384r1Sha384, TSignatureSchemes.EcdsaSecp521r1Sha512,
    TSignatureSchemes.RsaPssRsaeSha256, TSignatureSchemes.RsaPssRsaeSha384,
    TSignatureSchemes.RsaPssRsaeSha512, TSignatureSchemes.RsaPkcs1Sha256,
    TSignatureSchemes.RsaPkcs1Sha384, TSignatureSchemes.RsaPkcs1Sha512);
end;

function TTestWindowsClientDelegate.MakePolicy(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; AFetch: TSystemTrustFetch; ADeferral: TVerdictDeferral;
  const AClock: ITlsClock; const AStrength: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>): TOSDelegatePolicy;
begin
  Result := Default(TOSDelegatePolicy);
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.Pkix := Pkix;
  Result.Clock := AClock;
  Result.Posture := APosture;
  Result.Fetch := AFetch;
  Result.Deferral := ADeferral;
  Result.StrengthPolicy := AStrength;
  Result.AdvertisedSchemes := AAdvertised;
  Result.Anchors := AAnchors;
  // the inline verifier ignores the deadline; the live resolver honours it
  Result.DeadlineMs := 2000;
end;

function TTestWindowsClientDelegate.VerifyPolicy(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrength: TCertificateStrengthPolicy; const AAdvertised: TArray<UInt16>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TOSDelegateClientVerifier.Create(
    TWindowsChainEngine.Create as IPlatformChainEngine,
    MakePolicy(AAnchors, APosture, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None,
    AClock, AStrength, AAdvertised)) as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(Leaf, LVerified, AAlert);
end;

function TTestWindowsClientDelegate.Verify(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // the existing posture/clock/exclusive-root behaviours, under a permissive policy (default
  // strength + the leaf's scheme advertised) so only the property under test drives the verdict
  Result := VerifyPolicy(AAnchors, APosture, AClock,
    TCertificateStrengthPolicy.Defaults, Advertised, AAlert);
end;

procedure TTestWindowsClientDelegate.TestConfiguredIntermediateCompletesLeafOnlyClientChain;
var
  LVec: TStringList;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LLeaf: TArray<TBytes>;
begin
  LVec := LoadVectorFields('Certs/IntermediateClientAuthChain.txt');
  try
    LLeaf := TArray<TBytes>.Create(DecodeHex(LVec.Values['leaf_cert']));
    LPolicy := MakePolicy(TArray<TBytes>.Create(DecodeHex(LVec.Values['root_cert'])),
      TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None,
      TSystemClock.Create as ITlsClock, TCertificateStrengthPolicy.Defaults, Advertised);
    LVerifier := TOSDelegateClientVerifier.Create(
      TWindowsChainEngine.Create as IPlatformChainEngine, LPolicy) as IClientCertificateVerifier;
    CheckFalse(LVerifier.VerifyClientCertificate(LLeaf, LVerified, LAlert),
      'a leaf-only chain cannot reach the root without the issuer');
    CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
    LPolicy.Intermediates := TArray<TBytes>.Create(DecodeHex(LVec.Values['issuer_cert']));
    LVerifier := TOSDelegateClientVerifier.Create(
      TWindowsChainEngine.Create as IPlatformChainEngine, LPolicy) as IClientCertificateVerifier;
    CheckTrue(LVerifier.VerifyClientCertificate(LLeaf, LVerified, LAlert),
      'the configured issuer completes the path to the exclusive root');
  finally
    LVec.Free;
  end;
end;

procedure TTestWindowsClientDelegate.TestAcceptsClientChainToConfiguredAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  // the leaf chains to the configured exclusive root and carries clientAuth: accepted
  CheckTrue(Verify(OwnAnchor, TRevocationPosture.Off, TSystemClock.Create as ITlsClock,
    LAlert), 'a client cert chaining to the configured anchor is accepted');
end;

procedure TTestWindowsClientDelegate.TestRejectsClientChainToForeignAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  // the anchors are the ONLY trust root, so a client cert that does not chain to them
  // is rejected - never validated against the OS/public roots
  CheckFalse(Verify(ForeignAnchor, TRevocationPosture.Off,
    TSystemClock.Create as ITlsClock, LAlert),
    'a client cert not chaining to the configured anchor is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is unknown_ca');
end;

procedure TTestWindowsClientDelegate.TestInjectedClockRejectsChainOutsideValidity;
var
  LAlert: TTlsAlertDescription;
begin
  // the injected clock supplies the validation time: a far-future instant puts the chain past
  // its validity, so the same chain that TestAccepts... accepts at 'now' is rejected here
  CheckFalse(Verify(OwnAnchor, TRevocationPosture.Off,
    TMockClock.Create(UInt64(10000000000000)) as ITlsClock, LAlert),
    'the delegate honors the injected clock (chain outside validity is rejected)');
end;

procedure TTestWindowsClientDelegate.TestHardPostureRejectsUnrevocableChain;
var
  LAlert: TTlsAlertDescription;
begin
  // the private CA publishes no reachable revocation data, so the status is indeterminate;
  // Hard posture rejects an indeterminate outcome
  CheckFalse(Verify(OwnAnchor, TRevocationPosture.Hard,
    TSystemClock.Create as ITlsClock, LAlert),
    'Hard posture rejects a chain whose revocation status is indeterminate');
  // the OS engine reports the indeterminate outcome over its built path, so the shared pipeline
  // renders the precise revocation alert rather than a generic failure
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the indeterminate rejection alert is bad_certificate_status_response');
end;

procedure TTestWindowsClientDelegate.TestSoftPostureAcceptsUnrevocableChain;
var
  LAlert: TTlsAlertDescription;
begin
  // the same indeterminate outcome is accepted under Soft posture
  CheckTrue(Verify(OwnAnchor, TRevocationPosture.Soft,
    TSystemClock.Create as ITlsClock, LAlert),
    'Soft posture accepts a chain whose revocation status is indeterminate');
end;

procedure TTestWindowsClientDelegate.TestRejectsUnadvertisedLeafScheme;
var
  LAlert: TTlsAlertDescription;
begin
  // the chain-algorithm policy now runs over the OS-built path: the EC leaf's ECDSA scheme is
  // absent from an RSA-only advertised set, so a chain the OS trusts is still rejected
  CheckFalse(VerifyPolicy(OwnAnchor, TRevocationPosture.Off,
    TSystemClock.Create as ITlsClock, TCertificateStrengthPolicy.Defaults,
    TArray<UInt16>.Create(TSignatureSchemes.RsaPkcs1Sha256), LAlert),
    'a leaf signed with an unadvertised scheme is rejected over the OS path');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'an unadvertised algorithm is unsupported_certificate');
end;

procedure TTestWindowsClientDelegate.TestRejectsLeafOnDisallowedCurve;
var
  LPolicy: TCertificateStrengthPolicy;
  LAlert: TTlsAlertDescription;
begin
  // the key-strength floors run over the OS-built path too: an allowlist admitting only P-384
  // rejects the P-256 leaf the OS trusts
  LPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  CheckFalse(VerifyPolicy(OwnAnchor, TRevocationPosture.Off,
    TSystemClock.Create as ITlsClock, LPolicy, Advertised, LAlert),
    'a leaf on a disallowed curve is rejected over the OS path');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a disallowed curve is unsupported_certificate');
end;

procedure TTestWindowsClientDelegate.TestLiveFetchDefersUnrevocableChainInline;
var
  LVerifier: IClientCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // under Live the inline cache-only pass runs effective-Soft: an unrevocable client chain (no cached
  // status) is accepted inline so the handshake parks for the off-thread live check, rather than being
  // rejected inline the way configured-Hard cache-only does (TestHardPostureRejectsUnrevocableChain).
  // A definitive cached Revoked and every trust failure still reject inline.
  LVerifier := TOSDelegateClientVerifier.Create(
    TWindowsChainEngine.Create as IPlatformChainEngine,
    MakePolicy(OwnAnchor, TRevocationPosture.Hard, TSystemTrustFetch.Live,
    TVerdictDeferral.LiveRevocation, TSystemClock.Create as ITlsClock,
    TCertificateStrengthPolicy.Defaults, Advertised)) as IClientCertificateVerifier;
  CheckTrue(LVerifier.VerifyClientCertificate(Leaf, LVerified, LAlert),
    'Live defers an unrevocable client chain inline (effective-Soft) so the handshake can park');
end;

function TTestWindowsClientDelegate.VerifyLive(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; out AAlert: TTlsAlertDescription): Boolean;
var
  LResolver: TOSDelegateLiveResolver;
  LCtx: TCertificateVerdictContext;
begin
  LResolver := TOSDelegateLiveResolver.Create(
    TWindowsChainEngine.Create as IPlatformChainEngine, TPeerRole.Client,
    MakePolicy(AAnchors, APosture, TSystemTrustFetch.Live, TVerdictDeferral.LiveRevocation,
    TSystemClock.Create as ITlsClock, TCertificateStrengthPolicy.Defaults, Advertised), nil);
  try
    LCtx := Default(TCertificateVerdictContext);
    LCtx.PeerRole := TPeerRole.Client; // a client-chain resolver evaluates a client certificate
    LCtx.Chain := Leaf;
    Result := LResolver.ResolveVerdict(LCtx, AAlert);
  finally
    LResolver.Free;
  end;
end;

procedure TTestWindowsClientDelegate.TestLiveEvaluationStaysExclusiveRoot;
var
  LAlert: TTlsAlertDescription;
begin
  // the live re-evaluation stays exclusive-root too: a leaf that does not chain to the configured
  // anchor is rejected, never validated against the OS/public roots. The untrusted-root failure
  // precedes any revocation fetch, so this needs no responder.
  CheckFalse(VerifyLive(ForeignAnchor, TRevocationPosture.Hard, LAlert),
    'a client leaf that does not chain to the configured anchor is rejected on the live path');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'a non-chaining client leaf is unknown_ca on the live path, never accepted against public roots');
end;

procedure TTestWindowsClientDelegate.TestWrongRolePeerRefusedWithInternalError;
var
  LResolver: TOSDelegateLiveResolver;
  LCtx: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  // a client-chain resolver (client-auth EKU) handed a SERVER-role park is a local misconfiguration
  // - a single process-wide resolver wired for the wrong role. It must refuse with internal_error,
  // not run its client-auth engine over a server chain and surface a misleading trust failure.
  LResolver := TOSDelegateLiveResolver.Create(
    TWindowsChainEngine.Create as IPlatformChainEngine, TPeerRole.Client,
    MakePolicy(OwnAnchor, TRevocationPosture.Hard, TSystemTrustFetch.Live,
    TVerdictDeferral.LiveRevocation, TSystemClock.Create as ITlsClock,
    TCertificateStrengthPolicy.Defaults, Advertised), nil);
  try
    LCtx := Default(TCertificateVerdictContext);
    LCtx.PeerRole := TPeerRole.Server; // wrong role for a client-chain resolver
    LCtx.Chain := Leaf;
    CheckFalse(LResolver.ResolveVerdict(LCtx, LAlert),
      'a wrong-role park is refused, not evaluated');
    CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert),
      'a role mismatch surfaces as internal_error (local misconfiguration), not a trust failure');
  finally
    LResolver.Free;
  end;
end;

procedure TTestWindowsClientDelegate.TestServerChainResolverRefusesClientParkAtOff;
var
  LResolver: TOSDelegateLiveResolver;
  LCtx: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  // the dangerous direction: a SERVER-chain resolver (server-auth EKU) wired into a server's
  // mTLS park would evaluate a CLIENT chain against the wrong EKU and reject every client. The
  // role guard must refuse it - and even under the Off posture, because the misconfiguration is
  // posture-independent (Off would otherwise accept without evaluating, hiding the mistake until a
  // later posture change). This pins both the bug direction and the guard-before-Off ordering.
  LResolver := TOSDelegateLiveResolver.Create(
    TWindowsChainEngine.Create as IPlatformChainEngine, TPeerRole.Server,
    MakePolicy(nil, TRevocationPosture.Off, TSystemTrustFetch.Live,
    TVerdictDeferral.LiveRevocation, TSystemClock.Create as ITlsClock,
    TCertificateStrengthPolicy.Defaults, Advertised), nil);
  try
    LCtx := Default(TCertificateVerdictContext);
    LCtx.RevocationPosture := TRevocationPosture.Off; // the zero value (Soft) would lift it out of Off
    LCtx.PeerRole := TPeerRole.Client; // a client chain handed to a server-chain resolver
    LCtx.Chain := Leaf;
    CheckFalse(LResolver.ResolveVerdict(LCtx, LAlert),
      'a server-chain resolver refuses a client park even under Off');
    CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert),
      'the refusal is internal_error, and the guard runs before the Off short-circuit');
  finally
    LResolver.Free;
  end;
end;

procedure TTestWindowsClientDelegate.TestServerRoleLiveEvaluationHonoursSuppliedAnchors;
var
  LAlert: TTlsAlertDescription;

  function ResolveServerRole(const AAnchors: TArray<TBytes>): Boolean;
  var
    LResolver: TOSDelegateLiveResolver;
    LCtx: TCertificateVerdictContext;
  begin
    LResolver := TOSDelegateLiveResolver.Create(
      TWindowsChainEngine.Create as IPlatformChainEngine, TPeerRole.Server,
      MakePolicy(AAnchors, TRevocationPosture.Soft, TSystemTrustFetch.Live,
      TVerdictDeferral.LiveRevocation, TSystemClock.Create as ITlsClock,
      TCertificateStrengthPolicy.Defaults, Advertised), nil);
    try
      LCtx := Default(TCertificateVerdictContext);
      LCtx.PeerRole := TPeerRole.Server;
      LCtx.Chain := Leaf;
      Result := LResolver.ResolveVerdict(LCtx, LAlert);
    finally
      LResolver.Free;
    end;
  end;

begin
  // a private-PKI server chain is trusted only through the config's anchors: with them the live
  // pass builds against that root, without them it uses the OS roots and finds no issuer
  CheckTrue(ResolveServerRole(OwnAnchor),
    'a server chain to the supplied anchor is trusted on the live path');
  CheckFalse(ResolveServerRole(nil), 'with no anchors the private root is not an OS root');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'and the failure is unknown_ca');
  CheckFalse(ResolveServerRole(ForeignAnchor), 'a foreign anchor does not vouch for the chain');
end;

{ TTestWindowsHostRoots }

procedure TTestWindowsHostRoots.SetUp;
begin
  inherited SetUp;
  FChain := Own<TStringList>(LoadVectorFields('Certs/ClientAuthChain.txt'));
  FForeign := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
end;

function TTestWindowsHostRoots.Leaf: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FChain.Values['leaf_cert']));
end;

function TTestWindowsHostRoots.CaRoot: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FChain.Values['root_cert']));
end;

function TTestWindowsHostRoots.Verify(const ALeaf, AExtras, ADistrusted: TArray<TBytes>;
  const AClock: ITlsClock; out AAlert: TTlsAlertDescription): Boolean;
var
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LPolicy := Default(TOSDelegatePolicy);
  LPolicy.ChainLimits := TCertificateChainLimits.Defaults;
  LPolicy.Pkix := Pkix;
  LPolicy.Clock := AClock;
  LPolicy.Posture := TRevocationPosture.Off;
  LPolicy.Fetch := TSystemTrustFetch.CacheOnly;
  LPolicy.Deferral := TVerdictDeferral.None;
  LPolicy.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.AdvertisedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
    TSignatureSchemes.EcdsaSecp384r1Sha384, TSignatureSchemes.EcdsaSecp521r1Sha512);
  LPolicy.ExtraAnchors := AExtras;
  LPolicy.Distrusted := ADistrusted;
  LVerifier := TOSDelegateServerVerifier.Create(
    TWindowsChainEngine.Create as IPlatformChainEngine, LPolicy) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(ALeaf, Default(TServerName), nil, LVerified, AAlert);
end;

function TTestWindowsHostRoots.EvaluateStapled(const AStaple: TBytes;
  ARevocation: TPlatformRevocationCheck; out AResult: TPlatformChainResult): Boolean;
var
  LRequest: TPlatformChainRequest;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  // a private chain in no OS store, so no intermediate has cached revocation data
  LRequest := Default(TPlatformChainRequest);
  LRequest.Chain := TArray<TBytes>.Create(DecodeHex(FForeign.Values['leaf_cert']),
    DecodeHex(FForeign.Values['issuer_cert']));
  LRequest.Anchors := TArray<TBytes>.Create(DecodeHex(FForeign.Values['root_cert']));
  LRequest.OcspStaple := AStaple;
  LRequest.Revocation := ARevocation;
  LRequest.Clock := TSystemClock.Create as ITlsClock;
  LEngine := TWindowsChainEngine.Create as IPlatformChainEngine;
  Result := LEngine.EvaluateServer(LRequest, AResult, LAlert);
end;

procedure TTestWindowsHostRoots.TestHardInlineAcceptsFreshGoodStapleWithoutIntermediateRevocation;
var
  LResult: TPlatformChainResult;
begin
  CheckTrue(EvaluateStapled(DecodeHex(FForeign.Values['ocsp_good']),
    TPlatformRevocationCheck.RequirePositive, LResult),
    'the chain is trusted though the intermediate has no cached revocation status');
  CheckEquals(Ord(TLiveRevocationOutcome.Good), Ord(LResult.Outcome),
    'a fresh Good staple decides the leaf under RequirePositive');
end;

procedure TTestWindowsHostRoots.TestHardInlineRejectsRevokedStaple;
var
  LResult: TPlatformChainResult;
begin
  EvaluateStapled(DecodeHex(FForeign.Values['ocsp_revoked']),
    TPlatformRevocationCheck.RequirePositive, LResult);
  CheckEquals(Ord(TLiveRevocationOutcome.Revoked), Ord(LResult.Outcome),
    'a Revoked staple is still a revocation under RequirePositive');
end;

procedure TTestWindowsHostRoots.TestHardInlineWithoutStapleIsIndeterminate;
var
  LResult: TPlatformChainResult;
begin
  EvaluateStapled(nil, TPlatformRevocationCheck.RequirePositive, LResult);
  CheckEquals(Ord(TLiveRevocationOutcome.Indeterminate), Ord(LResult.Outcome),
    'a leaf with no revocation data at all is still undecided under RequirePositive');
end;

const
  WtsCertEUntrustedRoot = Cardinal($800B0109);
  WtsCertEExpired = Cardinal($800B0101);
  WtsCertECnNoMatch = Cardinal($800B010F);
  WtsCertERevoked = Cardinal($800B010C);
  WtsNoRevocationCheck = Cardinal($80092012);
  WtsNotTimeValid = Cardinal($00000001);
  WtsIsRevoked = Cardinal($00000004);
  WtsNotSignatureValid = Cardinal($00000008);
  WtsUntrustedRoot = Cardinal($00000020);
  WtsRevocationUnknown = Cardinal($00000040);
  WtsPartialChain = Cardinal($00010000);
  WtsExplicitDistrust = Cardinal($04000000);

procedure TTestWindowsHostRoots.CheckMapping(ADwError: Cardinal;
  AExpectedAlert: TTlsAlertDescription; AExpectedFailure: TPlatformChainFailure;
  const AName: string);
var
  LAlert: TTlsAlertDescription;
  LFailure: TPlatformChainFailure;
begin
  TWindowsChainEngine.MapPolicyError(ADwError, LAlert, LFailure);
  CheckEquals(Ord(AExpectedAlert), Ord(LAlert), AName + ': alert');
  CheckEquals(Ord(AExpectedFailure), Ord(LFailure), AName + ': failure class');
end;

// a zero-filled context with only dwErrorStatus: an outcome surfaces as internal_error (no path)
procedure TTestWindowsHostRoots.CheckClassified(ADwError, AErrorStatus: Cardinal;
  AExpectedAlert: TTlsAlertDescription; AExpectedFailure: TPlatformChainFailure;
  const AName: string);
var
  LCtx: TBytes;
  LResult: TPlatformChainResult;
  LAlert: TTlsAlertDescription;
begin
  SetLength(LCtx, 64);
  PCardinal(@LCtx[4])^ := AErrorStatus;
  TWindowsChainEngine.ClassifyPolicyStatus(ADwError, @LCtx[0], LResult, LAlert);
  CheckEquals(Ord(AExpectedAlert), Ord(LAlert), AName + ': alert');
  CheckEquals(Ord(AExpectedFailure), Ord(LResult.Failure), AName + ': failure class');
end;

procedure TTestWindowsHostRoots.CheckOutcome(ADwError, AErrorStatus: Cardinal;
  AExpected: TLiveRevocationOutcome; const AName: string);
var
  LCtx: TBytes;
  LResult: TPlatformChainResult;
  LAlert: TTlsAlertDescription;
begin
  SetLength(LCtx, 64);
  PCardinal(@LCtx[4])^ := AErrorStatus;
  TWindowsChainEngine.ClassifyPolicyStatus(ADwError, @LCtx[0], LResult, LAlert);
  CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert),
    AName + ': a revocation outcome, not a trust rejection');
  CheckEquals(Ord(AExpected), Ord(LResult.Outcome), AName + ': outcome');
end;

procedure TTestWindowsHostRoots.TestNoTrustAnchorIsReadFromTheChainBits;
begin
  CheckClassified(WtsCertEUntrustedRoot, WtsUntrustedRoot, TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.NoTrustAnchor, 'untrusted root alone');
  CheckClassified(WtsCertEUntrustedRoot, WtsUntrustedRoot or WtsPartialChain,
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor, 'untrusted root, partial');
  CheckClassified(WtsCertEUntrustedRoot, WtsUntrustedRoot or WtsRevocationUnknown,
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor,
    'untrusted root, revocation unknown');
end;

procedure TTestWindowsHostRoots.TestRevocationShapedErrorBesideMissingAnchorIsRetried;
begin
  CheckClassified(WtsNoRevocationCheck, WtsUntrustedRoot, TTlsAlertDescription.BadCertificate,
    TPlatformChainFailure.NoTrustAnchor, 'revocation-shaped error on an untrusted chain');
  CheckClassified(WtsNoRevocationCheck, WtsPartialChain, TTlsAlertDescription.BadCertificate,
    TPlatformChainFailure.NoTrustAnchor, 'revocation-shaped error on a partial chain');
end;

procedure TTestWindowsHostRoots.TestExpiryErrorBesideMissingAnchorIsRetried;
begin
  CheckClassified(WtsCertEUntrustedRoot, WtsUntrustedRoot or WtsNotTimeValid,
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor,
    'untrusted root, expired bit');
end;

procedure TTestWindowsHostRoots.TestExpiryPolicyErrorBesideMissingAnchorKeepsItsAlert;
begin
  CheckClassified(WtsCertEExpired, WtsUntrustedRoot or WtsNotTimeValid,
    TTlsAlertDescription.CertificateExpired, TPlatformChainFailure.NoTrustAnchor,
    'expiry error on an untrusted root');
end;

procedure TTestWindowsHostRoots.TestNameMismatchBesideMissingAnchorKeepsItsAlert;
begin
  CheckClassified(WtsCertECnNoMatch, WtsUntrustedRoot, TTlsAlertDescription.BadCertificate,
    TPlatformChainFailure.NoTrustAnchor, 'name mismatch on an untrusted root');
end;

procedure TTestWindowsHostRoots.TestDistrustOrBadSignatureIsFinal;
begin
  CheckClassified(WtsCertEUntrustedRoot, WtsUntrustedRoot or WtsExplicitDistrust,
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other, 'untrusted root, explicit distrust');
  CheckClassified(WtsCertEUntrustedRoot, WtsUntrustedRoot or WtsNotSignatureValid,
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other, 'untrusted root, bad signature');
  CheckClassified(WtsNoRevocationCheck, WtsUntrustedRoot or WtsExplicitDistrust,
    TTlsAlertDescription.BadCertificate, TPlatformChainFailure.Other,
    'revocation-shaped error on a distrusted untrusted chain');
  CheckClassified(WtsCertERevoked, WtsIsRevoked or WtsNotSignatureValid, TTlsAlertDescription.BadCertificate,
    TPlatformChainFailure.Other, 'revoked beside a bad signature');
end;

procedure TTestWindowsHostRoots.TestZeroPolicyErrorIsTheOsVerdict;
begin
  CheckOutcome(0, WtsNotTimeValid, TLiveRevocationOutcome.Good,
    'no policy error is accepted whatever the chain bits');
  CheckOutcome(0, WtsRevocationUnknown, TLiveRevocationOutcome.Indeterminate,
    'suppressed revocation-unknown');
end;

procedure TTestWindowsHostRoots.TestRevocationOutcomesNeedACleanChain;
begin
  CheckOutcome(WtsCertERevoked, WtsIsRevoked, TLiveRevocationOutcome.Revoked, 'revoked alone');
  CheckOutcome(WtsNoRevocationCheck, WtsRevocationUnknown, TLiveRevocationOutcome.Indeterminate,
    'revocation unknown alone');
end;

procedure TTestWindowsHostRoots.TestPolicyErrorMapping;
begin
  CheckMapping($800B0109,TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.NoTrustAnchor, 'CERT_E_UNTRUSTEDROOT');
  CheckMapping($800B010A,TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.NoTrustAnchor, 'CERT_E_CHAINING');
  CheckMapping($800B0112,TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.Other, 'CERT_E_UNTRUSTEDCA');
  CheckMapping($80096004,TTlsAlertDescription.DecryptError,
    TPlatformChainFailure.Other, 'TRUST_E_CERT_SIGNATURE');
  CheckMapping($800B0105,TTlsAlertDescription.CertificateUnknown,
    TPlatformChainFailure.Other, 'CERT_E_CRITICAL');
  CheckMapping($800B0114,TTlsAlertDescription.CertificateUnknown,
    TPlatformChainFailure.Other, 'CERT_E_INVALID_NAME');
  CheckMapping($800B0104,TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.Other, 'CERT_E_PATHLENCONST');
  CheckMapping($80096019,TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.Other, 'TRUST_E_BASIC_CONSTRAINTS');
  CheckMapping($800B0101,TTlsAlertDescription.CertificateExpired,
    TPlatformChainFailure.Other, 'CERT_E_EXPIRED');
  CheckMapping($800B0110,TTlsAlertDescription.UnsupportedCertificate,
    TPlatformChainFailure.Other, 'CERT_E_WRONG_USAGE');
  CheckMapping($800B010F,TTlsAlertDescription.BadCertificate,
    TPlatformChainFailure.Other, 'CERT_E_CN_NO_MATCH');
end;

procedure TTestWindowsHostRoots.TestRevocationErrorOnDistrustedChainIsNotRevoked;
var
  LCtx: TBytes;
  LResult: TPlatformChainResult;
  LAlert: TTlsAlertDescription;
begin
  // zero-filled chain context: dwErrorStatus follows cbSize
  SetLength(LCtx, 64);
  PCardinal(@LCtx[4])^ := WtsExplicitDistrust;
  CheckFalse(TWindowsChainEngine.ClassifyPolicyStatus(WtsCertERevoked, @LCtx[0], LResult, LAlert),
    'an explicitly distrusted chain is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
  CheckEquals(Ord(TPlatformChainFailure.Other), Ord(LResult.Failure), 'the failure class is Other');
  CheckTrue(LResult.Outcome <> TLiveRevocationOutcome.Revoked, 'it is not reported as revoked');
  PCardinal(@LCtx[4])^ := 0;
  TWindowsChainEngine.ClassifyPolicyStatus(WtsCertERevoked, @LCtx[0], LResult, LAlert);
  CheckEquals(Ord(TLiveRevocationOutcome.Revoked), Ord(LResult.Outcome),
    'without the distrust bit the same error is a revocation');
end;

procedure TTestWindowsHostRoots.TestChainFlagsKeepRootAutoUpdateEnabled;
const
  DisableAuthRootAutoUpdate = Cardinal($00000100);
  CacheOnlyUrlRetrieval = Cardinal($00000004);
  EndCert = Cardinal($10000000);
  ExcludeRoot = Cardinal($40000000);
var
  LLevel: TPlatformRevocationCheck;
begin
  for LLevel := Low(TPlatformRevocationCheck) to High(TPlatformRevocationCheck) do
  begin
    CheckEquals(0, TWindowsChainEngine.ChainFlags(LLevel, False) and DisableAuthRootAutoUpdate,
      Format('inline flags leave root auto-update enabled (level %d)', [Ord(LLevel)]));
    CheckEquals(CacheOnlyUrlRetrieval,
      TWindowsChainEngine.ChainFlags(LLevel, False) and CacheOnlyUrlRetrieval,
      Format('inline flags are cache-only (level %d)', [Ord(LLevel)]));
    CheckEquals(0, TWindowsChainEngine.ChainFlags(LLevel, True) and DisableAuthRootAutoUpdate,
      Format('live flags leave root auto-update enabled (level %d)', [Ord(LLevel)]));
    CheckEquals(0, TWindowsChainEngine.ChainFlags(LLevel, True) and CacheOnlyUrlRetrieval,
      Format('live flags are not cache-only (level %d)', [Ord(LLevel)]));
    CheckEquals(ExcludeRoot, TWindowsChainEngine.ChainFlags(LLevel, True) and (ExcludeRoot or EndCert),
      Format('live flags check the whole chain except the root (level %d)', [Ord(LLevel)]));
  end;
  CheckEquals(EndCert, TWindowsChainEngine.ChainFlags(TPlatformRevocationCheck.RequirePositive,
    False) and (ExcludeRoot or EndCert), 'Hard inline is leaf-scoped');
  CheckEquals(ExcludeRoot, TWindowsChainEngine.ChainFlags(TPlatformRevocationCheck.BestEffort,
    False) and (ExcludeRoot or EndCert), 'Soft inline keeps the whole-chain scope');
  CheckEquals(0, TWindowsChainEngine.ChainFlags(TPlatformRevocationCheck.None, False) and
    (ExcludeRoot or EndCert), 'no revocation check, no revocation scope');
end;

procedure TTestWindowsHostRoots.TestPrivateCaServerChainRefusedWithoutHostRoots;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verify(Leaf, nil, nil, TSystemClock.Create as ITlsClock, LAlert),
    'a private CA that is not in the machine store is not trusted');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

procedure TTestWindowsHostRoots.TestPrivateCaServerChainAcceptedWithHostRoots;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(Verify(Leaf, CaRoot, nil, TSystemClock.Create as ITlsClock, LAlert),
    'the host root vouches for the private CA chain with the OS roots');
end;

procedure TTestWindowsHostRoots.TestForeignHostRootDoesNotVouchForTheChain;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verify(Leaf, TArray<TBytes>.Create(DecodeHex(FForeign.Values['root_cert'])), nil,
    TSystemClock.Create as ITlsClock, LAlert), 'a host root the chain does not reach is no help');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is the OS-root one, unknown_ca');
end;

procedure TTestWindowsHostRoots.TestExpiredPrivateChainRefusedWithHostRoots;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verify(Leaf, CaRoot, nil, TMockClock.Create(UInt64(10000000000000)) as ITlsClock,
    LAlert), 'the host roots do not excuse a chain outside its validity');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert), 'the alert is certificate_expired');
end;

procedure TTestWindowsHostRoots.TestCorruptSignatureRefusedWithHostRoots;
var
  LAlert: TTlsAlertDescription;
  LLeaf: TArray<TBytes>;
begin
  LLeaf := Leaf;
  LLeaf[0][High(LLeaf[0])] := LLeaf[0][High(LLeaf[0])] xor $01;
  CheckFalse(Verify(LLeaf, CaRoot, nil, TSystemClock.Create as ITlsClock, LAlert),
    'a leaf whose signature does not verify is refused even with the host roots');
end;

procedure TTestWindowsHostRoots.TestDistrustedCaRefusedBesideHostRoots;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verify(Leaf, CaRoot, CaRoot, TSystemClock.Create as ITlsClock, LAlert),
    'a host root the OS distrusts does not admit the chain');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestWindowsHostRoots.TestLiveResolverTrustsHostRoots;
var
  LAlert: TTlsAlertDescription;

  function ResolveWith(const AExtras: TArray<TBytes>): Boolean;
  var
    LPolicy: TOSDelegatePolicy;
    LResolver: TOSDelegateLiveResolver;
    LContext: TCertificateVerdictContext;
  begin
    LPolicy := Default(TOSDelegatePolicy);
    LPolicy.ChainLimits := TCertificateChainLimits.Defaults;
    LPolicy.Pkix := Pkix;
    LPolicy.Clock := TSystemClock.Create as ITlsClock;
    LPolicy.Posture := TRevocationPosture.Soft;
    LPolicy.Fetch := TSystemTrustFetch.Live;
    LPolicy.Deferral := TVerdictDeferral.LiveRevocation;
    LPolicy.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
    LPolicy.AdvertisedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
      TSignatureSchemes.EcdsaSecp384r1Sha384, TSignatureSchemes.EcdsaSecp521r1Sha512);
    LPolicy.ExtraAnchors := AExtras;
    LPolicy.DeadlineMs := 2000;
    LResolver := TOSDelegateLiveResolver.Create(
      TWindowsChainEngine.Create as IPlatformChainEngine, TPeerRole.Server, LPolicy, nil);
    try
      LContext := Default(TCertificateVerdictContext);
      LContext.PeerRole := TPeerRole.Server;
      LContext.Chain := Leaf;
      Result := LResolver.ResolveVerdict(LContext, LAlert);
    finally
      LResolver.Free;
    end;
  end;

begin
  CheckTrue(ResolveWith(CaRoot), 'the live pass trusts the private CA chain through the host roots');
  CheckFalse(ResolveWith(nil), 'without host roots the live pass finds no anchor');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

procedure TTestWindowsHostRoots.TestFactorySourceReadsOsDistrustBesideHostRoots;
var
  LHostRoots: ITrustAnchorStore;
  LWith, LWithout: IServerCertificateVerifierSource;
  LDisallowed: Int32;
begin
  LHostRoots := TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore;
  LWith := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.OsAndHostRoots(LHostRoots), Pkix);
  LWithout := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.OsRoots, Pkix);
  LDisallowed := System.Length(TOSSystemTrust.AnchorStore(Pkix).DistrustedCertificates);
  CheckEquals(1, System.Length((LWith as TOSVerifierSource).ExtraAnchors),
    'the host roots are carried');
  CheckEquals(LDisallowed, System.Length((LWith as TOSVerifierSource).Distrusted),
    'the OS distrust list is read beside host roots');
  CheckEquals(0, System.Length((LWithout as TOSVerifierSource).Distrusted),
    'it is not read without host roots');
end;

procedure TTestWindowsHostRoots.TestFactorySourceIsTheOsSource;
var
  LSource: IServerCertificateVerifierSource;
begin
  LSource := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.OsRoots, Pkix);
  CheckTrue(LSource is TOSVerifierSource, 'the Windows factory source is the OS source');
end;

procedure TTestWindowsHostRoots.TestFactoryClientSourceIsTheOsSource;
var
  LSource: IClientCertificateVerifierSource;
begin
  LSource := TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.CacheOnly);
  CheckTrue(LSource is TOSVerifierSource, 'the Windows factory client source is the OS source');
end;

procedure TTestWindowsHostRoots.TestFactorySourceRefusesHostRootsWithoutProvider;
var
  LHostRoots: ITrustAnchorStore;
  LRaised: Boolean;
begin
  LHostRoots := TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore;
  LRaised := False;
  try
    TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
      TSystemTrustRoots.OsAndHostRoots(LHostRoots), nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'host roots without a PKIX provider are refused as an argument error');
end;

procedure TTestWindowsHostRoots.TestDefaultModeTrustsHostRootsThroughTheOsEngine;

  function DefaultVerifies(const AHostRoots: ITrustAnchorStore): Boolean;
  var
    LVerification: IServerVerification;
    LContext: TServerTrustContext;
    LVerified: TVerifiedChain;
    LAlert: TTlsAlertDescription;
  begin
    LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default,
      TSystemTrustRoots.OsAndHostRoots(AHostRoots)).WithRevocation(TRevocationPosture.Off).Build;
    CheckTrue(LVerification.Source is TOSVerifierSource,
      'Default on Windows is the OS verifier source');
    LContext := Default(TServerTrustContext);
    LContext.ChainLimits := TCertificateChainLimits.Defaults;
    LContext.Pkix := Pkix;
    LContext.Clock := TSystemClock.Create as ITlsClock;
    LContext.RevocationPosture := TRevocationPosture.Off;
    LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
    LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
      TSignatureSchemes.EcdsaSecp521r1Sha512);
    Result := LVerification.Source.CreateServerVerifier(LContext).VerifyServerCertificate(Leaf,
      Default(TServerName), nil, LVerified, LAlert);
  end;

begin
  CheckTrue(DefaultVerifies(TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore),
    'the host root vouches for the private CA chain under Default');
  CheckFalse(DefaultVerifies(nil), 'without host roots the private CA is not trusted');
end;

function TTestWindowsHostRoots.VerifyThroughSource(const ASource: IServerCertificateVerifierSource;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LContext: TServerTrustContext;
  LVerified: TVerifiedChain;
begin
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Clock := TSystemClock.Create as ITlsClock;
  LContext.RevocationPosture := TRevocationPosture.Off;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
  Result := ASource.CreateServerVerifier(LContext).VerifyServerCertificate(Leaf,
    Default(TServerName), nil, LVerified, AAlert);
end;

function TTestWindowsHostRoots.EvaluateChain(const AChain, AAnchors: TArray<TBytes>;
  ANetworkAllowed: Boolean; out AResult: TPlatformChainResult): Boolean;
var
  LRequest: TPlatformChainRequest;
  LEngine: IPlatformChainEngine;
  LAlert: TTlsAlertDescription;
begin
  LRequest := Default(TPlatformChainRequest);
  LRequest.Chain := AChain;
  LRequest.Anchors := AAnchors;
  LRequest.NetworkAllowed := ANetworkAllowed;
  LRequest.DeadlineMs := 2000;
  if ANetworkAllowed then
    LRequest.Revocation := TPlatformRevocationCheck.BestEffort
  else
    LRequest.Revocation := TPlatformRevocationCheck.None;
  LRequest.Clock := TSystemClock.Create as ITlsClock;
  LEngine := TWindowsChainEngine.Create as IPlatformChainEngine;
  Result := LEngine.EvaluateServer(LRequest, AResult, LAlert);
end;

function TTestWindowsHostRoots.TrustedOsRoot: TBytes;
var
  LRoots: TArray<TBytes>;
  LResult: TPlatformChainResult;
  LI: Int32;
begin
  Result := nil;
  LRoots := TOSSystemTrust.AnchorStore(Pkix).RootCertificates;
  for LI := 0 to System.High(LRoots) do
    if EvaluateChain(TArray<TBytes>.Create(LRoots[LI]), nil, False, LResult) then
      Exit(LRoots[LI]);
end;

function TTestWindowsHostRoots.ResolveLive(const ARoots: TSystemTrustRoots;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LConfig: ITlsClientConfig;
  LResolver: TOSLiveRevocationResolverBase;
  LContext: TCertificateVerdictContext;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    TServerVerification.VerifierSource(TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.Live,
    ARoots, Pkix)).WithRevocation(TRevocationPosture.Soft).Build).WithLiveRevocationVerdict(2000)
    .Build;
  LResolver := TOSSystemTrust.LiveRevocationResolver(LConfig, nil);
  try
    LContext := Default(TCertificateVerdictContext);
    LContext.PeerRole := TPeerRole.Server;
    LContext.Chain := Leaf;
    Result := LResolver.ResolveVerdict(LContext, AAlert);
  finally
    LResolver.Free;
  end;
end;

procedure TTestWindowsHostRoots.TestHostRootsTrustsThePrivateLeaf;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyThroughSource(TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore), Pkix),
    LAlert), 'the host root alone vouches for the private CA chain');
end;

procedure TTestWindowsHostRoots.TestHostRootsRefusesAForeignRoot;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyThroughSource(TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(TArray<TBytes>.Create(
    DecodeHex(FForeign.Values['root_cert']))) as ITrustAnchorStore), Pkix), LAlert),
    'a root the chain does not reach is no help');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

procedure TTestWindowsHostRoots.TestHostRootsRefusesAnOsRootedChainInline;
var
  LRoot: TBytes;
  LResult: TPlatformChainResult;
begin
  LRoot := TrustedOsRoot;
  if System.Length(LRoot) = 0 then
  begin
    SkipTest('no OS root is accepted as a chain of its own, so there is no positive control');
    Exit;
  end;
  CheckFalse(EvaluateChain(TArray<TBytes>.Create(LRoot), CaRoot, False, LResult),
    'an OS-rooted chain is not trusted when the private root stands alone');
  CheckEquals(Ord(TPlatformChainFailure.NoTrustAnchor), Ord(LResult.Failure),
    'the failure is a missing trust anchor');
end;

procedure TTestWindowsHostRoots.TestHostRootsRefusesAnOsRootedChainLive;
var
  LRoot: TBytes;
  LResult: TPlatformChainResult;
begin
  LRoot := TrustedOsRoot;
  if System.Length(LRoot) = 0 then
  begin
    SkipTest('no OS root is accepted as a chain of its own, so there is no positive control');
    Exit;
  end;
  CheckFalse(EvaluateChain(TArray<TBytes>.Create(LRoot), CaRoot, True, LResult),
    'the live pass does not let an OS root vouch either');
  CheckEquals(Ord(TPlatformChainFailure.NoTrustAnchor), Ord(LResult.Failure),
    'the failure is a missing trust anchor');
end;

procedure TTestWindowsHostRoots.TestLiveResolverHostRootsTrustsThePrivateLeaf;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ResolveLive(TSystemTrustRoots.HostRoots(
    TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore), LAlert),
    'the live pass trusts the private CA chain through the host root alone');
end;

procedure TTestWindowsHostRoots.TestLiveResolverOsRootsRefusesThePrivateLeaf;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ResolveLive(TSystemTrustRoots.OsRoots, LAlert),
    'the same config without the host root does not trust the private CA');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

procedure TTestWindowsHostRoots.TestHostRootsSourceCarriesTheHostRootAsTheOnlyAnchor;
var
  LHolder: IServerCertificateVerifierSource;
  LSource: TOSVerifierSource;
begin
  LHolder := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore), Pkix);
  LSource := LHolder as TOSVerifierSource;
  CheckEquals(1, System.Length(LSource.Anchors), 'the host root is the exclusive root');
  CheckEquals(0, System.Length(LSource.ExtraAnchors), 'it is not also an extra');
end;

procedure TTestWindowsHostRoots.TestHostRootsSourceReadsTheOsDistrustList;
var
  LHolder: IServerCertificateVerifierSource;
  LSource: TOSVerifierSource;
  LDisallowed: Int32;
begin
  LHolder := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore), Pkix);
  LSource := LHolder as TOSVerifierSource;
  LDisallowed := System.Length(TOSSystemTrust.AnchorStore(Pkix).DistrustedCertificates);
  if LDisallowed = 0 then
  begin
    SkipTest('the OS distrust list is empty, so reading it cannot be observed');
    Exit;
  end;
  CheckEquals(LDisallowed, System.Length(LSource.Distrusted),
    'the OS distrust list is read with the host roots alone');
end;

procedure TTestWindowsHostRoots.TestHostRootsRefusesAPathThroughADistrustedCertificate;
var
  LSource: IServerCertificateVerifierSource;
  LAlert: TTlsAlertDescription;
begin
  LSource := TOSVerifierSource.Create(TWindowsChainEngine.Create as IPlatformChainEngine,
    TSystemTrustFetch.CacheOnly, TSystemTrustRootScope.HostRoots, CaRoot, Leaf)
    as IServerCertificateVerifierSource;
  CheckFalse(VerifyThroughSource(LSource, LAlert),
    'a distrusted certificate on the path does not admit the chain');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestWindowsHostRoots.TestDefaultModeHostRootsYieldsASourceWithAnchors;
var
  LVerification: IServerVerification;
  LSource: TOSVerifierSource;
begin
  LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default,
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore)).Build;
  CheckTrue(LVerification.Source is TOSVerifierSource,
    'Default on Windows is the OS verifier source');
  LSource := LVerification.Source as TOSVerifierSource;
  CheckEquals(1, System.Length(LSource.Anchors), 'the host root is the exclusive root');
  CheckEquals(0, System.Length(LSource.ExtraAnchors), 'and not an extra');
end;

procedure TTestWindowsHostRoots.TestWithLiveSystemTrustCarriesTheHostRoots;
var
  LConfig: ITlsClientConfig;
  LSource: TOSVerifierSource;
begin
  LConfig := TSystemTrust.WithLiveSystemTrust(TTlsPresets.Compatible(Crypto, Pkix).Client, Pkix,
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore),
    TRevocationPosture.Soft, 2000).Build;
  CheckTrue(LConfig.ServerVerifierSource is TOSVerifierSource,
    'the live source is the OS verifier source');
  LSource := LConfig.ServerVerifierSource as TOSVerifierSource;
  CheckEquals(1, System.Length(LSource.Anchors), 'the host root is the exclusive root');
end;

procedure TTestWindowsHostRoots.TestInstallerTrustsItsExtraAnchorsWithTheOsRoots;
var
  LVerification: IServerVerification;
  LSource: TOSVerifierSource;
begin
  LVerification := TSystemTrustInstaller.Shared.ServerVerification(Pkix,
    TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore);
  CheckTrue(LVerification.Source is TOSVerifierSource,
    'the installed source is the OS verifier source');
  LSource := LVerification.Source as TOSVerifierSource;
  CheckEquals(1, System.Length(LSource.ExtraAnchors), 'the extra anchors sit with the OS roots');
  CheckEquals(0, System.Length(LSource.Anchors), 'they are not the exclusive root');
end;

procedure TTestWindowsHostRoots.TestDistrustStoreIsTheDisallowedList;
var
  LDisallowed: Int32;
begin
  LDisallowed := System.Length(TOSSystemTrust.AnchorStore(Pkix).DistrustedCertificates);
  if LDisallowed = 0 then
  begin
    SkipTest('the OS distrust list is empty');
    Exit;
  end;
  CheckEquals(LDisallowed, System.Length(TOSSystemTrust.DistrustStore(Pkix).DistrustedCertificates),
    'the distrust store holds the whole OS list');
end;

{$ENDIF TLSLIB_MSWINDOWS}

{$IFDEF TLSLIB_MACOS}

{ TTestMacOSSystemTrust }

function TTestMacOSSystemTrust.CreateAnchorStore: ITrustAnchorStore;
var
  LSource: TAppleRootSource;
begin
  LSource := TAppleRootSource.Create(Pkix);
  try
    Result := LSource.Snapshot;
  finally
    LSource.Free;
  end;
end;

function TTestMacOSSystemTrust.PlatformName: string;
begin
  Result := 'macOS';
end;

{ TTestAppleClientDelegate }

procedure TTestAppleClientDelegate.SetUp;
begin
  inherited SetUp;
  FChain := Own<TStringList>(LoadVectorFields('Certs/ClientAuthChain.txt'));
  FForeign := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
end;

function TTestAppleClientDelegate.Leaf: TArray<TBytes>;
begin
  // the dual-EKU (serverAuth+clientAuth) leaf, presented alone (its issuer is the exclusive root)
  Result := TArray<TBytes>.Create(DecodeHex(FChain.Values['leaf_cert']));
end;

function TTestAppleClientDelegate.OwnAnchor: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(DecodeHex(FChain.Values['root_cert']));
end;

function TTestAppleClientDelegate.ForeignAnchor: TArray<TBytes>;
begin
  // an unrelated private root: the leaf does not chain to it
  Result := TArray<TBytes>.Create(DecodeHex(FForeign.Values['root_cert']));
end;

function TTestAppleClientDelegate.Advertised: TArray<UInt16>;
begin
  Result := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
    TSignatureSchemes.EcdsaSecp384r1Sha384, TSignatureSchemes.EcdsaSecp521r1Sha512,
    TSignatureSchemes.RsaPssRsaeSha256, TSignatureSchemes.RsaPssRsaeSha384,
    TSignatureSchemes.RsaPssRsaeSha512, TSignatureSchemes.RsaPkcs1Sha256,
    TSignatureSchemes.RsaPkcs1Sha384, TSignatureSchemes.RsaPkcs1Sha512);
end;

function TTestAppleClientDelegate.VerifyPolicy(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrength: TCertificateStrengthPolicy; const AAdvertised: TArray<UInt16>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LPolicy: TOSDelegatePolicy;
begin
  LPolicy := Default(TOSDelegatePolicy);
  LPolicy.ChainLimits := TCertificateChainLimits.Defaults;
  LPolicy.Pkix := Pkix;
  LPolicy.Clock := AClock;
  LPolicy.Posture := APosture;
  LPolicy.Fetch := TSystemTrustFetch.CacheOnly;
  LPolicy.Deferral := TVerdictDeferral.None;
  LPolicy.StrengthPolicy := AStrength;
  LPolicy.AdvertisedSchemes := AAdvertised;
  LPolicy.Anchors := AAnchors;
  LPolicy.DeadlineMs := 0;
  LVerifier := TOSDelegateClientVerifier.Create(
    TAppleChainEngine.Create as IPlatformChainEngine, LPolicy) as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(Leaf, LVerified, AAlert);
end;

function TTestAppleClientDelegate.Verify(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // the existing posture/clock/anchors-only behaviours, under a permissive policy so only the
  // property under test drives the verdict
  Result := VerifyPolicy(AAnchors, APosture, AClock,
    TCertificateStrengthPolicy.Defaults, Advertised, AAlert);
end;

procedure TTestAppleClientDelegate.TestAcceptsClientChainToConfiguredAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  // the leaf chains to the configured exclusive root and carries clientAuth: accepted
  CheckTrue(Verify(OwnAnchor, TRevocationPosture.Off, TSystemClock.Create as ITlsClock,
    LAlert), 'a client cert chaining to the configured anchor is accepted');
end;

procedure TTestAppleClientDelegate.TestRejectsClientChainToForeignAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  // the anchors are the ONLY trust root (anchors-only), so a client cert that does not chain to
  // them is rejected - never validated against the OS/public roots
  CheckFalse(Verify(ForeignAnchor, TRevocationPosture.Off,
    TSystemClock.Create as ITlsClock, LAlert),
    'a client cert not chaining to the configured anchor is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is unknown_ca');
end;

procedure TTestAppleClientDelegate.TestInjectedClockRejectsChainOutsideValidity;
var
  LAlert: TTlsAlertDescription;
begin
  // the injected clock supplies the validation time (SecTrustSetVerifyDate): a far-future instant
  // puts the chain past its validity, so the chain accepted at 'now' is rejected here
  CheckFalse(Verify(OwnAnchor, TRevocationPosture.Off,
    TMockClock.Create(UInt64(10000000000000)) as ITlsClock, LAlert),
    'the delegate honors the injected clock (chain outside validity is rejected)');
end;

procedure TTestAppleClientDelegate.TestHardPostureRejectsUnrevocableChain;
var
  LAlert: TTlsAlertDescription;
begin
  // the private CA publishes no reachable revocation data and network fetch is disabled, so the
  // status is indeterminate; a Hard posture (require-positive) rejects an indeterminate outcome
  CheckFalse(Verify(OwnAnchor, TRevocationPosture.Hard,
    TSystemClock.Create as ITlsClock, LAlert),
    'Hard posture rejects a chain whose revocation status is indeterminate');
  // the OS engine reports the indeterminate outcome over its built path, so the shared pipeline
  // renders the precise revocation alert rather than a generic failure
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the indeterminate rejection alert is bad_certificate_status_response');
end;

procedure TTestAppleClientDelegate.TestSoftPostureAcceptsUnrevocableChain;
var
  LAlert: TTlsAlertDescription;
begin
  // the same indeterminate outcome is accepted under Soft posture
  CheckTrue(Verify(OwnAnchor, TRevocationPosture.Soft,
    TSystemClock.Create as ITlsClock, LAlert),
    'Soft posture accepts a chain whose revocation status is indeterminate');
end;

procedure TTestAppleClientDelegate.TestRejectsUnadvertisedLeafScheme;
var
  LAlert: TTlsAlertDescription;
begin
  // the chain-algorithm policy now runs over the OS-built path: the EC leaf's ECDSA scheme is
  // absent from an RSA-only advertised set, so a chain the OS trusts is still rejected
  CheckFalse(VerifyPolicy(OwnAnchor, TRevocationPosture.Off,
    TSystemClock.Create as ITlsClock, TCertificateStrengthPolicy.Defaults,
    TArray<UInt16>.Create(TSignatureSchemes.RsaPkcs1Sha256), LAlert),
    'a leaf signed with an unadvertised scheme is rejected over the OS path');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'an unadvertised algorithm is unsupported_certificate');
end;

procedure TTestAppleClientDelegate.TestRejectsLeafOnDisallowedCurve;
var
  LPolicy: TCertificateStrengthPolicy;
  LAlert: TTlsAlertDescription;
begin
  // the key-strength floors run over the OS-built path too: an allowlist admitting only P-384
  // rejects the P-256 leaf the OS trusts
  LPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  CheckFalse(VerifyPolicy(OwnAnchor, TRevocationPosture.Off,
    TSystemClock.Create as ITlsClock, LPolicy, Advertised, LAlert),
    'a leaf on a disallowed curve is rejected over the OS path');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'a disallowed curve is unsupported_certificate');
end;

{ TTestAppleHostRoots }

procedure TTestAppleHostRoots.SetUp;
begin
  inherited SetUp;
  // the leaf is valid for 790 days: the server rules cap validity at 825 days, private roots too
  FChain := Own<TStringList>(LoadVectorFields('Certs/PrivateServerChain.txt'));
  FForeign := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
end;

function TTestAppleHostRoots.VerifyAlone(const ARoot: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LSource: IServerCertificateVerifierSource;
  LContext: TServerTrustContext;
  LVerified: TVerifiedChain;
begin
  LSource := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly,
    TSystemTrustRoots.HostRoots(TTrustAnchorStore.Create(ARoot) as ITrustAnchorStore), Pkix);
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  // 2021-01-01, inside the fixture leaf's validity
  LContext.Clock := TMockClock.Create(1609459200000) as ITlsClock;
  LContext.RevocationPosture := TRevocationPosture.Off;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureSchemes.EcdsaSecp521r1Sha512);
  Result := LSource.CreateServerVerifier(LContext).VerifyServerCertificate(
    TArray<TBytes>.Create(DecodeHex(FChain.Values['leaf_cert'])), Default(TServerName), nil,
    LVerified, AAlert);
end;

procedure TTestAppleHostRoots.TestEngineDeclaresExclusiveServerAnchors;
var
  LEngine: IPlatformChainEngine;
begin
  LEngine := TAppleChainEngine.Create as IPlatformChainEngine;
  CheckTrue(TPlatformChainCapability.ExclusiveServerAnchors in LEngine.Capabilities,
    'the engine honours an exclusive server root');
end;

procedure TTestAppleHostRoots.TestHostRootsTrustsThePrivateLeaf;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifyAlone(TArray<TBytes>.Create(DecodeHex(FChain.Values['root_cert'])), LAlert),
    'the host root alone vouches for the private CA chain');
end;

procedure TTestAppleHostRoots.TestHostRootsRefusesAForeignRoot;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifyAlone(TArray<TBytes>.Create(DecodeHex(FForeign.Values['root_cert'])), LAlert),
    'a root the chain does not reach is no help');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

{$ENDIF TLSLIB_MACOS}

{$IFDEF TLSLIB_ANDROID}

{ TTestJavaTrustClassifier }

function TTestJavaTrustClassifier.Facts(ACertificateException, ATimeInvalid,
  APathValidatorCause: Boolean; ACauseIndex: Int32; const ACauseMessage: string): TJavaTrustFacts;
begin
  Result := Default(TJavaTrustFacts);
  Result.CertificateException := ACertificateException;
  Result.TimeInvalid := ATimeInvalid;
  Result.PathValidatorCause := APathValidatorCause;
  Result.CauseIndex := ACauseIndex;
  Result.CauseMessage := ACauseMessage;
end;

procedure TTestJavaTrustClassifier.CheckClass(const AFacts: TJavaTrustFacts;
  AExpectedAlert: TTlsAlertDescription; AExpectedFailure: TPlatformChainFailure;
  const AName: string);
var
  LAlert: TTlsAlertDescription;
  LFailure: TPlatformChainFailure;
begin
  TJavaTrustClassifier.Classify(AFacts, LAlert, LFailure);
  CheckEquals(Ord(AExpectedAlert), Ord(LAlert), AName + ': alert');
  CheckEquals(Ord(AExpectedFailure), Ord(LFailure), AName + ': failure class');
end;

procedure TTestJavaTrustClassifier.TestNoTrustAnchorShapeIsNoTrustAnchor;
begin
  CheckClass(Facts(True, False, True, -1, 'Trust anchor for certification path not found.'),
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor, 'anchor not found');
end;

procedure TTestJavaTrustClassifier.TestPathDoesNotChainMessageIsNoTrustAnchor;
begin
  CheckClass(Facts(True, False, True, -1, 'Path does not chain with any of the trust anchors'),
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor, 'does not chain');
end;

procedure TTestJavaTrustClassifier.TestInvalidSignatureReasonIsDecryptError;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, False, True, 0, '');
  LFacts.CauseReason := 'INVALID_SIGNATURE';
  CheckClass(LFacts, TTlsAlertDescription.DecryptError, TPlatformChainFailure.Other,
    'invalid signature');
end;

procedure TTestJavaTrustClassifier.TestSignatureCheckFailedMessageIsDecryptError;
begin
  CheckClass(Facts(True, False, True, 0, 'signature check failed'),
    TTlsAlertDescription.DecryptError, TPlatformChainFailure.Other, 'signature check');
end;

procedure TTestJavaTrustClassifier.TestOlderPlatformSignatureMessageIsDecryptError;
begin
  CheckClass(Facts(True, False, True, 0, 'Could not validate certificate signature.'),
    TTlsAlertDescription.DecryptError, TPlatformChainFailure.Other, 'older platform');
end;

procedure TTestJavaTrustClassifier.TestCriticalExtensionMessageIsCertificateUnknown;
begin
  CheckClass(Facts(True, False, True, 0, 'unrecognized critical extension(s)'),
    TTlsAlertDescription.CertificateUnknown, TPlatformChainFailure.Other, 'critical extension');
end;

procedure TTestJavaTrustClassifier.TestUnrecognizedCriticalExtensionReasonIsCertificateUnknown;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, False, True, 0, '');
  LFacts.CauseReason := 'UNRECOGNIZED_CRIT_EXT';
  CheckClass(LFacts, TTlsAlertDescription.CertificateUnknown, TPlatformChainFailure.Other,
    'critical extension reason');
end;

procedure TTestJavaTrustClassifier.TestInvalidNameReasonIsCertificateUnknown;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, False, True, 0, '');
  LFacts.CauseReason := 'INVALID_NAME';
  CheckClass(LFacts, TTlsAlertDescription.CertificateUnknown, TPlatformChainFailure.Other,
    'name reason');
end;

procedure TTestJavaTrustClassifier.TestSubtreeCheckMessageIsCertificateUnknown;
begin
  CheckClass(Facts(True, False, True, 0, 'Subtree check for certificate subject failed.'),
    TTlsAlertDescription.CertificateUnknown, TPlatformChainFailure.Other, 'name constraints');
end;

procedure TTestJavaTrustClassifier.TestNameConstraintsCheckFailedMessageIsCertificateUnknown;
begin
  CheckClass(Facts(True, False, True, 0, 'name constraints check failed'),
    TTlsAlertDescription.CertificateUnknown, TPlatformChainFailure.Other, 'name constraints');
end;

procedure TTestJavaTrustClassifier.TestMissingAnchorOutranksASignatureReason;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, False, True, -1, 'Trust anchor for certification path not found.');
  LFacts.CauseReason := 'INVALID_SIGNATURE';
  CheckClass(LFacts, TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor,
    'missing anchor first');
end;

procedure TTestJavaTrustClassifier.TestOtherReasonWithUnrelatedMessageIsOther;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, False, True, 0, 'revocation check failed');
  LFacts.CauseReason := 'UNSPECIFIED';
  CheckClass(LFacts, TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other,
    'other reason');
end;

procedure TTestJavaTrustClassifier.TestCriticalExtensionWithoutPathValidatorCauseIsOther;
begin
  CheckClass(Facts(True, False, False, 0, 'unrecognized critical extension(s)'),
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other, 'no path validator cause');
end;

procedure TTestJavaTrustClassifier.TestTimeInvalidOutranksInvalidSignature;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, True, True, 0, '');
  LFacts.CauseReason := 'INVALID_SIGNATURE';
  CheckClass(LFacts, TTlsAlertDescription.CertificateExpired, TPlatformChainFailure.Other,
    'expiry first');
end;

procedure TTestJavaTrustClassifier.TestPinFailureWithoutCauseIsOther;
begin
  CheckClass(Facts(True, False, False, 0, ''), TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.Other, 'pin');
end;

procedure TTestJavaTrustClassifier.TestPathFailureAtACertificateIndexIsOther;
begin
  CheckClass(Facts(True, False, True, 1, 'Trust anchor for certification path not found.'),
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other, 'index 1');
end;

procedure TTestJavaTrustClassifier.TestUnrelatedPathMessageIsOther;
begin
  CheckClass(Facts(True, False, True, -1, 'Certificate has been revoked'),
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other, 'revoked');
  CheckClass(Facts(True, False, True, -1, ''), TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.Other, 'no message');
end;

procedure TTestJavaTrustClassifier.TestTimeInvalidIsOtherEvenWithAnAnchorCause;
begin
  CheckClass(Facts(True, True, False, 0, ''), TTlsAlertDescription.CertificateExpired,
    TPlatformChainFailure.Other, 'expired');
  CheckClass(Facts(True, True, True, -1, 'Trust anchor for certification path not found.'),
    TTlsAlertDescription.CertificateExpired, TPlatformChainFailure.Other, 'expired with cause');
end;

procedure TTestJavaTrustClassifier.TestCauseOtherThanPathValidatorIsOther;
begin
  CheckClass(Facts(True, False, False, -1, 'Trust anchor for certification path not found.'),
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other, 'other cause');
end;

procedure TTestJavaTrustClassifier.TestDomainScopedNoAnchorIsFinal;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, False, True, -1, 'Trust anchor for certification path not found.');
  LFacts.DomainScoped := True;
  CheckClass(LFacts, TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other,
    'a host a domain-config names keeps unknown_ca and is never retried with host roots');
  LFacts.DomainScoped := False;
  CheckClass(LFacts, TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor,
    'a base-config host is still a missing anchor');
end;

procedure TTestJavaTrustClassifier.TestDomainScopedPinFailureIsUnchanged;
var
  LFacts: TJavaTrustFacts;
begin
  LFacts := Facts(True, False, False, 0, '');
  LFacts.DomainScoped := True;
  CheckClass(LFacts, TTlsAlertDescription.UnknownCa, TPlatformChainFailure.Other, 'pin');
end;

procedure TTestJavaTrustClassifier.TestNonCertificateExceptionIsInternalError;
begin
  CheckClass(Facts(False, False, True, -1, 'Trust anchor for certification path not found.'),
    TTlsAlertDescription.InternalError, TPlatformChainFailure.Other, 'not a CertificateException');
end;

{$ENDIF TLSLIB_ANDROID}

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}

{ TTestUnixSystemTrust }

function TTestUnixSystemTrust.CreateAnchorStore: ITrustAnchorStore;
var
  LSource: TUnixRootSource;
begin
  LSource := TUnixRootSource.Create(Pkix);
  try
    Result := LSource.Snapshot;
  finally
    LSource.Free;
  end;
end;

function TTestUnixSystemTrust.PlatformName: string;
begin
  Result := 'Unix';
end;

function TTestUnixSystemTrust.RequiresPopulatedStore: Boolean;
begin
  Result := False; // a minimal box may ship no ca-certificates - tolerate an empty harvest
end;

{ TTestPosixPrivilege }

procedure TTestPosixPrivilege.TestUnprivilegedProcessIsNotElevated;
begin
  CheckFalse(TPosixPrivilege.IsElevated,
    'the unprivileged test process must probe as not elevated');
end;

{ TTestUnixAnchorsWithoutABundle }

function TTestUnixAnchorsWithoutABundle.IsVariableSet(const AName: string): Boolean;
var
  LName: AnsiString;
begin
  LName := AnsiString(AName);
  Result := FGetenv(PAnsiChar(LName)) <> nil;
end;

procedure TTestUnixAnchorsWithoutABundle.SetVariable(const AName: string; AIsSet: Boolean;
  const AValue: string);
var
  LName, LValue: AnsiString;
begin
  LName := AnsiString(AName);
  LValue := AnsiString(AValue);
  if AIsSet then
    FSetenv(PAnsiChar(LName), PAnsiChar(LValue), 1)
  else
    FUnsetenv(PAnsiChar(LName));
{$IFDEF FPC}
  // the RTL reads a copy of the environ pointer taken at startup, which setenv may reallocate
  envp := FEnviron^;
{$ENDIF FPC}
end;

function TTestUnixAnchorsWithoutABundle.PointAtNothing: Boolean;
begin
  Result := not TPosixPrivilege.IsElevated;
  if not Result then
  begin
    SkipTest('an elevated process ignores the SSL_CERT_* overrides');
    Exit;
  end;
  SetVariable('SSL_CERT_FILE', True, TempPath('no-such-bundle.pem'));
  SetVariable('SSL_CERT_DIR', True, TempPath('no-such-bundle-dir'));
end;

procedure TTestUnixAnchorsWithoutABundle.SetUp;
var
  LEc: TStringList;
begin
  inherited SetUp;
  FLibrary := TDynamicLibrary.Open('');
  CheckTrue(FLibrary <> 0, 'the C library is reachable');
  FSetenv := TPosixSetenvFunc(TDynamicLibrary.Resolve(FLibrary, 'setenv'));
  FUnsetenv := TPosixUnsetenvFunc(TDynamicLibrary.Resolve(FLibrary, 'unsetenv'));
  FGetenv := TPosixGetenvFunc(TDynamicLibrary.Resolve(FLibrary, 'getenv'));
  CheckTrue(Assigned(FSetenv) and Assigned(FUnsetenv) and Assigned(FGetenv),
    'the environment accessors resolve');
{$IFDEF FPC}
  FEnviron := TDynamicLibrary.Resolve(FLibrary, 'environ');
  CheckTrue(FEnviron <> nil, 'the environment block resolves');
{$ENDIF FPC}
  FSavedFile := GetEnvironmentVariable('SSL_CERT_FILE');
  FSavedDir := GetEnvironmentVariable('SSL_CERT_DIR');
  FFileWasSet := IsVariableSet('SSL_CERT_FILE');
  FDirWasSet := IsVariableSet('SSL_CERT_DIR');
  LEc := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
  FRoots := TTrustAnchorStore.Create(TArray<TBytes>.Create(DecodeHex(LEc.Values['root_cert'])))
    as ITrustAnchorStore;
end;

procedure TTestUnixAnchorsWithoutABundle.TearDown;
begin
  if FLibrary <> 0 then
  begin
    if Assigned(FSetenv) and Assigned(FUnsetenv) and Assigned(FGetenv) then
    begin
      SetVariable('SSL_CERT_FILE', FFileWasSet, FSavedFile);
      SetVariable('SSL_CERT_DIR', FDirWasSet, FSavedDir);
    end;
    TDynamicLibrary.Close(FLibrary);
    FLibrary := 0;
  end;
  inherited TearDown;
end;

procedure TTestUnixAnchorsWithoutABundle.TestHostRootsBuildsWithoutAReadableBundle;
var
  LVerification: IServerVerification;
begin
  if not PointAtNothing then
    Exit;
  LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Anchors,
    TSystemTrustRoots.HostRoots(FRoots)).Build;
  CheckEquals(2, System.Length(LVerification.AnchorStores), 'the host roots and the distrust list');
end;

procedure TTestUnixAnchorsWithoutABundle.TestOsAndHostRootsFailsClosedWithoutAReadableBundle;
var
  LRaised: Boolean;
begin
  if not PointAtNothing then
    Exit;
  LRaised := False;
  try
    TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Anchors,
      TSystemTrustRoots.OsAndHostRoots(FRoots));
  except
    on E: ESystemTrustUnavailableTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an override naming nothing is never read as an empty trust store');
end;

procedure TTestUnixAnchorsWithoutABundle.TestOsRootsFailsClosedWithoutAReadableBundle;
var
  LRaised: Boolean;
begin
  if not PointAtNothing then
    Exit;
  LRaised := False;
  try
    TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Anchors, TSystemTrustRoots.OsRoots);
  except
    on E: ESystemTrustUnavailableTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the OS roots alone fail closed when nothing is readable');
end;

{$IFEND}

{ TTestSystemTrustInstaller }

procedure TTestSystemTrustInstaller.TestClientInstallComposesLikeFacade;
var
  LInstaller: ISystemTrustInstaller;
  LViaFacade, LViaInstaller: IServerVerification;
begin
  LInstaller := TSystemTrustInstaller.Create;
  LViaFacade := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default,
    TSystemTrustRoots.OsRoots).Build;
  LViaInstaller := LInstaller.ServerVerification(Pkix, nil);
  CheckEquals(Ord(LViaFacade.Kind), Ord(LViaInstaller.Kind),
    'the installer composes the same kind of server verification as the facade');
  CheckEquals(System.Length(LViaFacade.AnchorStores), System.Length(LViaInstaller.AnchorStores),
    'the installer composes the same anchor-store count as the facade');
  CheckEquals(LViaFacade.Source = nil, LViaInstaller.Source = nil,
    'the installer has an OS verifier source exactly when the facade does');
  CheckNotNull(TTlsPresets.Compatible(Crypto, Pkix).Client.WithServerVerification(
    LViaInstaller).Build, 'the installer''s verification builds into a client config');
end;

procedure TTestSystemTrustInstaller.TestLiveFetchWithoutADeadlineIsRefused;
var
  LRefused: Boolean;
begin
  LRefused := False;
  try
    TSystemTrust.WithLiveSystemTrust(TTlsPresets.Compatible(Crypto, Pkix).Client, Pkix,
      TSystemTrustRoots.OsRoots, TRevocationPosture.Soft, 0);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a live fetch with a zero verdict deadline is refused before any build');
end;

procedure TTestSystemTrustInstaller.TestDefaultResolvesToTheOsEngineWhereThePlatformHasOne;
var
  LFacade, LInstalled: IServerVerification;
begin
  LFacade := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default,
    TSystemTrustRoots.OsRoots).Build;
  LInstalled := TSystemTrustInstaller.Shared.ServerVerification(Pkix, nil);
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
  begin
    CheckEquals(Ord(TVerificationKind.VerifierSource), Ord(LFacade.Kind),
      'Default is the OS engine where the platform has one');
    CheckTrue(LFacade.Source is TOSVerifierSource, 'the Default source is the OS verifier source');
    CheckEquals(Ord(TVerificationKind.VerifierSource), Ord(LInstalled.Kind),
      'the installer resolves Default the same way');
  end
  else
  begin
    CheckEquals(Ord(TVerificationKind.WebPki), Ord(LFacade.Kind),
      'Default harvests the OS anchors where the platform has no OS engine');
    CheckEquals(1, System.Length(LFacade.AnchorStores), 'the harvested store is the anchor set');
    CheckEquals(Ord(TVerificationKind.WebPki), Ord(LInstalled.Kind),
      'the installer resolves Default the same way');
  end;
end;

procedure TTestSystemTrustInstaller.TestExplicitAnchorsStillResolveToTheHarvestedStore;
var
  LVerification: IServerVerification;
begin
  if not TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
  begin
    SkipTest('this platform cannot enumerate OS anchors');
    Exit;
  end;
  LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Anchors,
    TSystemTrustRoots.OsRoots).Build;
  CheckEquals(Ord(TVerificationKind.WebPki), Ord(LVerification.Kind),
    'explicit Anchors is our own validator over the harvested roots');
  CheckEquals(1, System.Length(LVerification.AnchorStores), 'the harvested store is the anchor set');
  CheckNull(LVerification.Source, 'no OS verifier source is involved');
end;

procedure TTestSystemTrustInstaller.TestExplicitDelegateIsTheOsEngineOrRefused;
var
  LVerification: IServerVerification;
  LRefused: Boolean;
begin
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
  begin
    LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Delegate,
      TSystemTrustRoots.OsRoots).Build;
    CheckEquals(Ord(TVerificationKind.VerifierSource), Ord(LVerification.Kind),
      'explicit Delegate is the OS engine');
    Exit;
  end;
  LRefused := False;
  try
    TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Delegate, TSystemTrustRoots.OsRoots);
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'explicit Delegate raises where the platform has no OS engine');
end;

procedure TTestSystemTrustInstaller.TestSharedInstallerIsOneStableInstance;
begin
  // the adapters' config memo keys the installer by identity, so it must not change per connection
  CheckTrue(TSystemTrustInstaller.Shared = TSystemTrustInstaller.Shared,
    'the shared installer is one instance');
  CheckNotNull(TSystemTrustInstaller.Shared, 'the shared installer exists');
end;

procedure TTestSystemTrustInstaller.TestExplicitOsAnchorsAreTheServerEscapeHatch;
var
  LStore: ITrustAnchorStore;
  LV: TStringList;
  LConfig: ITlsServerConfig;
begin
  // there is no server form of system trust: OS roots become a client-CA only when written out explicitly
  if not TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
  begin
    SkipTest('this platform cannot enumerate OS anchors');
    Exit;
  end;
  LStore := TOSSystemTrust.AnchorStore(Pkix);
  CheckNotNull(LStore, 'the OS anchor store is reachable for the explicit escape hatch');
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      DecodeHex(LV.Values['leaf_cert']), DecodeHex(LV.Values['leaf_key'])))
      .WithPeerAuth(TClientAuthMode.Required)
      .WithClientVerification(TClientVerification.WebPki(LStore).Build).Build;
  finally
    LV.Free;
  end;
  CheckEquals(Ord(TClientAuthMode.Required), Ord(LConfig.ClientAuth),
    'the explicit OS-anchor escape hatch composes a Required-mode server');
  CheckTrue(System.Length(LConfig.TrustStore.RootCertificates) > 0,
    'the explicitly-named OS anchors are the client-CA');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSystemTrustFixtures);
  RegisterTest(TTestDelegatePostChecks);
  RegisterTest(TTestOSDelegateTemplate);
  RegisterTest(TTestDelegateHostRoots);
  RegisterTest(TTestDelegateHostRootsAlone);
  RegisterTest(TTestSystemTrustRoots);
  RegisterTest(TTestSystemTrustInstaller);
{$ELSE}
  RegisterTest(TTestSystemTrustFixtures.Suite);
  RegisterTest(TTestDelegatePostChecks.Suite);
  RegisterTest(TTestOSDelegateTemplate.Suite);
  RegisterTest(TTestDelegateHostRoots.Suite);
  RegisterTest(TTestDelegateHostRootsAlone.Suite);
  RegisterTest(TTestSystemTrustRoots.Suite);
  RegisterTest(TTestSystemTrustInstaller.Suite);
{$ENDIF FPC}

{$IFDEF TLSLIB_MSWINDOWS}
{$IFDEF FPC}
  RegisterTest(TTestWindowsSystemTrust);
  RegisterTest(TTestWindowsClientDelegate);
  RegisterTest(TTestWindowsHostRoots);
{$ELSE}
  RegisterTest(TTestWindowsSystemTrust.Suite);
  RegisterTest(TTestWindowsClientDelegate.Suite);
  RegisterTest(TTestWindowsHostRoots.Suite);
{$ENDIF FPC}
{$ENDIF TLSLIB_MSWINDOWS}

{$IFDEF TLSLIB_MACOS}
{$IFDEF FPC}
  RegisterTest(TTestMacOSSystemTrust);
  RegisterTest(TTestAppleClientDelegate);
  RegisterTest(TTestAppleHostRoots);
{$ELSE}
  RegisterTest(TTestMacOSSystemTrust.Suite);
  RegisterTest(TTestAppleClientDelegate.Suite);
  RegisterTest(TTestAppleHostRoots.Suite);
{$ENDIF FPC}
{$ENDIF TLSLIB_MACOS}

{$IFDEF TLSLIB_ANDROID}
{$IFDEF FPC}
  RegisterTest(TTestJavaTrustClassifier);
{$ELSE}
  RegisterTest(TTestJavaTrustClassifier.Suite);
{$ENDIF FPC}
{$ENDIF TLSLIB_ANDROID}

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
{$IFDEF FPC}
  RegisterTest(TTestUnixSystemTrust);
  RegisterTest(TTestPosixPrivilege);
  RegisterTest(TTestUnixAnchorsWithoutABundle);
{$ELSE}
  RegisterTest(TTestUnixSystemTrust.Suite);
  RegisterTest(TTestPosixPrivilege.Suite);
  RegisterTest(TTestUnixAnchorsWithoutABundle.Suite);
{$ENDIF FPC}
{$IFEND}

end.
