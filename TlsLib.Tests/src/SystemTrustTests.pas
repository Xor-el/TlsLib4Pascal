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
{$IFEND}
  TlpOSSystemTrust,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine,
  TlpOSDelegateVerifier,
  TlpSystemTrustFacade,
  TlpITlsConfigBuilder,
  TlpISystemTrustInstaller,
  TlpITlsConfig,
  TlpTlsCredential,
  TlpTlsPresets,
  MockPlatformChainEngine,
  MockVerifyHooks,
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
      const ACallback: TTlsCertificateVerifyCallback; out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
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
    procedure TestSnapshotCarriesFilteredDistrustSet;
    // RFC 7633 must-staple + TLS Feature well-formedness, enforced by the OS delegate
    procedure TestMustStapleLeafWithoutStapleRejects;
    procedure TestMustStapleLeafWithGoodStapleAccepts;
    procedure TestMustStapleNotBoundWhenNotOfferedOrOnResumption;
    procedure TestMalformedTlsFeatureRejectsBothRoles;
    procedure TestServerSourceEnforcesMustStaple;
    // a DnsIdentity engine's host match does not substitute for the library SAN check
    procedure TestNameMismatchRejectsWithDnsCapability;
  end;

  /// <summary>Platform-neutral tests for host roots beside the OS roots over a scripted platform
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
    procedure TestLiveResolverRetriesWithHostRoots;
    procedure TestLiveResolverOtherFailureIsFinal;
    procedure TestLiveResolverRefusesDistrustedHostRootPath;
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

  /// <summary>Host roots beside the OS roots over crypt32's real chain engine, against a private CA
  /// that is not in the machine store (which is never touched): the retry against the host roots
  /// admits the CA's server chain, and every other fault stays a refusal. Also the pure mapping from
  /// a chain-policy error to its failure class. Windows-only.</summary>
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
    procedure TestDefaultModeTrustsHostRootsThroughTheOsEngine;
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
  strict protected
    function HarvestRoots: TArray<TBytes>; override;
    function HarvestDistrusted: TArray<TBytes>; override;
    function SourceName: string; override;
  public
    function Filter(const ARaw: TArray<TBytes>): TArray<TBytes>;
    /// <summary>What a Snapshot of this probe harvests.</summary>
    procedure Harvests(const ARoots, ADistrusted: TArray<TBytes>);
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

procedure TFilterRootsProbe.Harvests(const ARoots, ADistrusted: TArray<TBytes>);
begin
  FRoots := ARoots;
  FDistrusted := ADistrusted;
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
  AExempt: TArray<TBytes>; const ACallback: TTlsCertificateVerifyCallback;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
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
  LPolicy.Dangerous.VerifyCallback := ACallback;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine, LPolicy) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(AChain, TServerName.DnsName('localhost'), nil,
    AVerified, AAlert);
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
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
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
  LFake := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], True,
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
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly)
    as IServerCertificateVerifierSource;
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
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.Live)
      as IServerCertificateVerifierSource;
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
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.Live) as IServerCertificateVerifierSource;
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
    TArray<TBytes>.Create(Ocsp('issuer_cert')), nil) as IServerCertificateVerifierSource;
  LContext := Default(TServerTrustContext);
  LContext.ChainLimits := TCertificateChainLimits.Defaults;
  LContext.Pkix := Pkix;
  LContext.Clock := FClock;
  LContext.CheckHostName := True;
  LContext.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LVerifier := LSource.CreateServerVerifier(LContext);
  LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil, LVerified,
    LAlert);
  CheckEquals(1, System.Length((LSource as IOSServerVerifierSource).ExtraAnchors),
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
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly) as IClientCertificateVerifierSource;
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
    TArray<TBytes>.Create(LCaLeaf, LRoot), TArray<TBytes>.Create(LRoot), nil, LVerified, LAlert),
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
    TArray<TBytes>.Create(LSelfCa), nil, LVerified, LAlert),
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
    TArray<TBytes>.Create(LLeaf, LInter, LRoot), TArray<TBytes>.Create(LRoot), nil, LVerified,
    LAlert), 'an end-entity certificate under a CA is unaffected');
  CheckEquals(3, System.Length(LVerified.Path), 'the engine path is reported');
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
    TArray<TBytes>.Create(LLeaf, LInter, LRoot), TArray<TBytes>.Create(LRoot), LSpy.Callback,
    LVerified, LAlert), 'accepted');
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
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly)
    as IServerCertificateVerifierSource;
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
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly)
    as IClientCertificateVerifierSource;
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

procedure TTestOSDelegateTemplate.TestSnapshotCarriesFilteredDistrustSet;
var
  LProbe: TFilterRootsProbe;
  LStore: ITrustAnchorStore;
  LRoot, LDistrusted: TBytes;
begin
  // the snapshot carries the distrust set, filtered like the roots (junk and duplicates dropped),
  // and a root the source also distrusts is not an anchor
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
  CheckEquals(1, System.Length(LStore.DistrustedCertificates),
    'the distrust set is de-duplicated and the junk dropped');
  CheckTrue(LStore.IsDistrusted(LDistrusted), 'the distrusted certificate matches');
  CheckEquals(1, System.Length(LStore.RootCertificates),
    'a root the source distrusts is not an anchor');
  CheckEqualBytes('the surviving anchor', LRoot, LStore.RootCertificates[0]);
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
  LSource := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly, LStore, Pkix);
  LDistrusted := (LSource as IOSServerVerifierSource).Distrusted;
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
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly, HostRoots,
    TArray<TBytes>.Create(Ocsp('issuer_cert'))) as IServerCertificateVerifierSource;
  CheckEquals(1, System.Length((LSource as IOSServerVerifierSource).Distrusted),
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
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly, HostRoots, nil)
    as IServerCertificateVerifierSource;
  CheckEquals(1, System.Length((LSource as IOSServerVerifierSource).ExtraAnchors),
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
    LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly, HostRoots, nil)
      as IServerCertificateVerifierSource;
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'host roots over an engine that cannot trust them are refused at construction');
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.NativeAnchorUnion], False,
    Rejected(TPlatformChainFailure.None), TTlsAlertDescription.BadCertificate);
  LSource := TOSVerifierSource.Create(LEngine, TSystemTrustFetch.CacheOnly, HostRoots, nil)
    as IServerCertificateVerifierSource;
  CheckEquals(1, System.Length((LSource as IOSServerVerifierSource).ExtraAnchors),
    'a native-union engine accepts host roots');
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
    CheckTrue(TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly) <> nil,
      'a platform that supports Delegate must hand back an OS server-verifier source')
  else
  begin
    LRaised := False;
    try
      TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly);
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
  CheckMapping($80096004,TTlsAlertDescription.UnknownCa,
    TPlatformChainFailure.Other, 'TRUST_E_CERT_SIGNATURE');
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
    'the host root vouches for the private CA chain beside the OS roots');
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
  LWith, LWithout: IOSServerVerifierSource;
  LDisallowed: Int32;
begin
  LHostRoots := TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore;
  LWith := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly, LHostRoots, Pkix)
    as IOSServerVerifierSource;
  LWithout := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly, nil, Pkix)
    as IOSServerVerifierSource;
  LDisallowed := System.Length(TOSSystemTrust.AnchorStore(Pkix).DistrustedCertificates);
  CheckEquals(1, System.Length(LWith.ExtraAnchors), 'the host roots are carried');
  CheckEquals(LDisallowed, System.Length(LWith.Distrusted),
    'the OS distrust list is read beside host roots');
  CheckEquals(0, System.Length(LWithout.Distrusted), 'it is not read without host roots');
end;

procedure TTestWindowsHostRoots.TestFactorySourceRefusesHostRootsWithoutProvider;
var
  LHostRoots: ITrustAnchorStore;
  LRaised: Boolean;
begin
  LHostRoots := TTrustAnchorStore.Create(CaRoot) as ITrustAnchorStore;
  LRaised := False;
  try
    TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly, LHostRoots, nil);
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
    LSource: IOSServerVerifierSource;
    LContext: TServerTrustContext;
    LVerified: TVerifiedChain;
    LAlert: TTlsAlertDescription;
  begin
    LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Default,
      AHostRoots).WithRevocation(TRevocationPosture.Off).Build;
    CheckTrue(SysUtils.Supports(LVerification.Source, IOSServerVerifierSource, LSource),
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
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor, 'Conscrypt');
end;

procedure TTestJavaTrustClassifier.TestPathDoesNotChainMessageIsNoTrustAnchor;
begin
  CheckClass(Facts(True, False, True, -1, 'Path does not chain with any of the trust anchors'),
    TTlsAlertDescription.UnknownCa, TPlatformChainFailure.NoTrustAnchor, 'PKIX');
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

{$IFEND}

{ TTestSystemTrustInstaller }

procedure TTestSystemTrustInstaller.TestClientInstallComposesLikeFacade;
var
  LInstaller: ISystemTrustInstaller;
  LViaFacade, LViaInstaller: IServerVerification;
begin
  LInstaller := TSystemTrustInstaller.Create;
  LViaFacade := TSystemTrust.ServerVerification(Pkix).Build;
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
    TSystemTrust.WithLiveSystemTrust(TTlsPresets.Compatible(Crypto, Pkix).Client,
      TRevocationPosture.Soft, 0);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a live fetch with a zero verdict deadline is refused before any build');
end;

procedure TTestSystemTrustInstaller.TestDefaultResolvesToTheOsEngineWhereThePlatformHasOne;
var
  LFacade, LInstalled: IServerVerification;
  LSource: IOSServerVerifierSource;
begin
  LFacade := TSystemTrust.ServerVerification(Pkix).Build;
  LInstalled := TSystemTrustInstaller.Shared.ServerVerification(Pkix, nil);
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
  begin
    CheckEquals(Ord(TVerificationKind.VerifierSource), Ord(LFacade.Kind),
      'Default is the OS engine where the platform has one');
    CheckTrue(SysUtils.Supports(LFacade.Source, IOSServerVerifierSource, LSource),
      'the Default source is the OS verifier source');
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
  LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Anchors, nil).Build;
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
    LVerification := TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Delegate, nil).Build;
    CheckEquals(Ord(TVerificationKind.VerifierSource), Ord(LVerification.Kind),
      'explicit Delegate is the OS engine');
    Exit;
  end;
  LRefused := False;
  try
    TSystemTrust.ServerVerification(Pkix, TSystemTrustMode.Delegate, nil);
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
  RegisterTest(TTestSystemTrustInstaller);
{$ELSE}
  RegisterTest(TTestSystemTrustFixtures.Suite);
  RegisterTest(TTestDelegatePostChecks.Suite);
  RegisterTest(TTestOSDelegateTemplate.Suite);
  RegisterTest(TTestDelegateHostRoots.Suite);
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
{$ELSE}
  RegisterTest(TTestMacOSSystemTrust.Suite);
  RegisterTest(TTestAppleClientDelegate.Suite);
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
{$ELSE}
  RegisterTest(TTestUnixSystemTrust.Suite);
  RegisterTest(TTestPosixPrivilege.Suite);
{$ENDIF FPC}
{$IFEND}

end.
