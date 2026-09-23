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
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpTrustPolicy,
  TlpServerName,
  TlpCertificateStrengthPolicy,
  TlpNegotiationTypes,
  TlpTlsAlert,
  TlpIClock,
  TlpClock,
  MockClock,
  TlpSystemTrustExceptions,
  // portable engine - drives the always-on fixtures on every host
  TlpFileSystemTrust,
  // the real per-OS harvesters, each compiled only on its own platform
{$IFDEF TLSLIB_MSWINDOWS}
  TlpWindowsSystemTrust,
{$ENDIF TLSLIB_MSWINDOWS}
{$IFDEF TLSLIB_MACOS}
  TlpAppleSystemTrust,
{$ENDIF TLSLIB_MACOS}
{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
  TlpUnixSystemTrust,
{$IFEND}
  TlpOSSystemTrust,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine,
  TlpOSDelegateVerifier,
  TlpSystemTrustFacade,
  TlpITlsConfigBuilder,
  TlpITlsConfig,
  TlpTlsPresets,
  MockPlatformChainEngine,
  TlsLibTestBase;

type
  /// <summary>Portable suite (always runs): drives TFileSystemRootSource's file/dir resolution
  /// via injected fixtures, and checks the factory reports anchors for this build's platform.</summary>
  TTestSystemTrustFixtures = class(TTlsLibAlgorithmTestCase)
  private
  var
    FPkix: IPkixProvider;
    FDir: string;       // a throwaway fixture directory under the working dir
    FFile: string;      // a fixture bundle file holding the test root
    FMissing: string;   // a path that does not exist
    FCertDir: string;   // a fixture directory holding one root file
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
    procedure TestFactoryAnchorStoreMatchesSupports;
    procedure TestFactoryServerVerifierSourceMatchesSupports;
  end;

  /// <summary>Portable suite (always runs): the host-neutral system-trust installer that bridges
  /// TSystemTrust.WithSystemTrust into the shared adapter-core seam - the client role installs OS
  /// server trust, and the server role mirrors the facade's client-authentication refusal.</summary>
  TTestSystemTrustInstaller = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestClientInstallComposesLikeFacade;
    procedure TestServerInstallMirrorsFacadeRefusal;
  end;

  /// <summary>Portable suite (always runs): the shared OS-delegate post-checks
  /// (TDelegatePostChecks) - stapled-Revoked-always-wins, IP-literal identity, and the
  /// Hard/Live-need-live-revocation predicates - exercised without touching any real OS store.</summary>
  TTestDelegatePostChecks = class(TTlsLibAlgorithmTestCase)
  private
    FPkix: IPkixProvider;
    FClock: ITlsClock;
    FOcsp: TStringList;      // OcspStapling.txt: a real chain + Good/Revoked/stale staples
    FEc: TStringList;        // EcP256Chain.txt: a DNS-only leaf and an IP-SAN leaf
    function OcspChain: TArray<TBytes>;
    function Ocsp(const AName: string): TBytes;
    function Ec(const AName: string): TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRevokedStapleRejectsOverOsPath;
    procedure TestGoodAndAbsentStapleDoNotFire;
    procedure TestStaleStapleIsNotRevoked;
    procedure TestLeafOnlyPathIsNotRevoked;
    procedure TestNilClockFallsBackToSystemTime;
    procedure TestNilProviderIsNotRevoked;
    procedure TestIpNameMatchesIpSanLeaf;
    procedure TestIpNameAgainstDnsOnlyLeafRejects;
    procedure TestDnsNameIsNotRecheckedHere;
    procedure TestEmptyNameIsNotRechecked;
    procedure TestIpNameNilProviderFailsClosed;
    procedure TestIpNameEmptyPathFailsClosed;
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
    FPkix: IPkixProvider;
    FClock: ITlsClock;
    FOcsp: TStringList;
    function Ocsp(const AName: string): TBytes;
    function OcspChain: TArray<TBytes>;
    function Result_(AOutcome: TLiveRevocationOutcome;
      const APath: TArray<TBytes>): TPlatformChainResult;
    function Policy(APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
      ADeferral: TVerdictDeferral; const AAnchors: TArray<TBytes>): TOSDelegatePolicy;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRequestShapingRevocationLevels;
    procedure TestRequestNetworkNotAllowedInline;
    procedure TestClientRequestCarriesAnchors;
    procedure TestEngineFailurePassesAlertThrough;
    procedure TestAcceptFillsTrustedPath;
    procedure TestStapledRevokedOverridesUnderOff;
    procedure TestEngineRevokedRejects;
    procedure TestHardIndeterminateRejectsCacheOnly;
    procedure TestHardIndeterminateAcceptsWhenDeferred;
    procedure TestNameMismatchRejectsWithoutDnsCapability;
    procedure TestSourceRefusesLiveWithoutLiveFetch;
    procedure TestServerSourceRefusesLiveWithoutVerdict;
    procedure TestClientSourceRefusesHardWithoutCachedRevocation;
    procedure TestLiveResolverDispatchesToServer;
    procedure TestLiveResolverWrongRoleRefused;
    procedure TestClientRoutesByStapleWithoutCachedRevocation;
    procedure TestStapledRevokedRejectsWithoutCachedRevocation;
  end;

  /// <summary>Engine-agnostic contract for a real OS anchor store, written against
  /// ITrustAnchorStore. A concrete per-OS suite supplies only CreateAnchorStore + PlatformName
  /// (and may relax RequiresPopulatedStore); the published tests are inherited and discovered
  /// automatically. Never registered on its own.</summary>
  TSystemTrustAnchorContractTestBase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    FPkix: IPkixProvider;
    // ---- per-OS hooks ----
    function CreateAnchorStore: ITrustAnchorStore; virtual; abstract;
    function PlatformName: string; virtual; abstract;
    /// <summary>Whether an empty harvest is a failure. True where the OS always ships a root
    /// store (Windows, macOS); False where it may legitimately be absent (a bare Unix box).</summary>
    function RequiresPopulatedStore: Boolean; virtual;
    // ---- shared helpers ----
    /// <summary>Harvests the real store. Returns False (no assertion) when the store is absent on
    /// a platform that tolerates it - so the caller should Exit and skip. Fails outright when an
    /// always-populated platform harvests nothing.</summary>
    function HarvestOrSkip(out ARoots: TArray<TBytes>): Boolean;
    procedure SetUp; override;
  published
    procedure TestHarvestYieldsRoots;
    procedure TestAllHarvestedRootsWellFormed;
    procedure TestHarvestedRootsAreUnique;
  end;

{$IFDEF TLSLIB_MSWINDOWS}

  /// <summary>Windows (crypt32 ROOT+CA minus Disallowed) instantiation. Registered only on
  /// TLSLIB_MSWINDOWS.</summary>
  TTestWindowsSystemTrust = class(TSystemTrustAnchorContractTestBase)
  strict protected
    function CreateAnchorStore: ITrustAnchorStore; override;
    function PlatformName: string; override;
  end;

  /// <summary>Behavioural tests for the Windows OS client-certificate delegate against a
  /// self-contained private CA (the exclusive trust root is fully controllable, so unlike the
  /// server delegate these are hermetic). Proves the H3 exclusive-root fix, the injected clock,
  /// and the revocation posture over crypt32's real chain engine. Windows-only.</summary>
  TTestWindowsClientDelegate = class(TTlsLibAlgorithmTestCase)
  strict private
    FPkix: IPkixProvider;
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
    procedure TearDown; override;
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
    FPkix: IPkixProvider;
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
    procedure TearDown; override;
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

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}

  /// <summary>Desktop/server Unix (real /etc/ssl/certs et al.) instantiation. Registered only on
  /// the filesystem-harvest targets; a bare box with no ca-certificates is tolerated (skips).
  /// Android also harvests from the filesystem but is a mobile target with its own store path and
  /// a JNI-delegate future, so it is not grouped here.</summary>
  TTestUnixSystemTrust = class(TSystemTrustAnchorContractTestBase)
  strict protected
    function CreateAnchorStore: ITrustAnchorStore; override;
    function PlatformName: string; override;
    function RequiresPopulatedStore: Boolean; override;
  end;

{$IFEND}

implementation

{ TTestDelegatePostChecks }

procedure TTestDelegatePostChecks.SetUp;
begin
  inherited SetUp;
  FPkix := TDefaultPkixProvider.Create as IPkixProvider;
  FClock := TSystemClock.Create as ITlsClock;
  FOcsp := LoadVectorFields('Certs/OcspStapling.txt');
  FEc := LoadVectorFields('Certs/EcP256Chain.txt');
end;

procedure TTestDelegatePostChecks.TearDown;
begin
  FEc.Free;
  FOcsp.Free;
  inherited TearDown;
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
  CheckTrue(TDelegatePostChecks.RejectStapledRevoked(FPkix, FClock, OcspChain,
    Ocsp('ocsp_revoked'), LAlert), 'a definitive stapled Revoked always rejects');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestDelegatePostChecks.TestGoodAndAbsentStapleDoNotFire;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FPkix, FClock, OcspChain,
    Ocsp('ocsp_good'), LAlert), 'a current Good staple does not fire the Revoked post-check');
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FPkix, FClock, OcspChain,
    nil, LAlert), 'an absent staple does not fire the Revoked post-check');
end;

procedure TTestDelegatePostChecks.TestStaleStapleIsNotRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  // a stale (out-of-window) response is indeterminate, not Revoked - the posture decides it, so
  // this post-check must not fire
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FPkix, FClock, OcspChain,
    Ocsp('ocsp_stale'), LAlert), 'a stale staple is indeterminate, not Revoked');
end;

procedure TTestDelegatePostChecks.TestLeafOnlyPathIsNotRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  // with no issuer to authenticate the response, the verdict is indeterminate, not Revoked
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FPkix, FClock,
    TArray<TBytes>.Create(Ocsp('leaf_cert')), Ocsp('ocsp_revoked'), LAlert),
    'a leaf-only path cannot render a definitive Revoked');
end;

procedure TTestDelegatePostChecks.TestNilClockFallsBackToSystemTime;
var
  LAlert: TTlsAlertDescription;
begin
  // a nil clock must not silently skip the check (it would otherwise make every staple
  // indeterminate); it falls back to system time
  CheckTrue(TDelegatePostChecks.RejectStapledRevoked(FPkix, nil, OcspChain,
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

procedure TTestDelegatePostChecks.TestIpNameMatchesIpSanLeaf;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  // the IP-SAN leaf carries IP:127.0.0.1, so an IP-literal identity matches and does not fire
  CheckTrue(TServerName.TryParse('127.0.0.1', LName));
  CheckFalse(TDelegatePostChecks.RejectIpMismatch(LName, FPkix,
    TArray<TBytes>.Create(Ec('ipsan_leaf_cert')), LAlert),
    'an IP literal matching an iPAddress SAN is accepted');
  CheckTrue(TServerName.TryParse('[::1]', LName));
  CheckFalse(TDelegatePostChecks.RejectIpMismatch(LName, FPkix,
    TArray<TBytes>.Create(Ec('ipsan_leaf_cert')), LAlert),
    'an IPv6 literal matching an iPAddress SAN is accepted');
end;

procedure TTestDelegatePostChecks.TestIpNameAgainstDnsOnlyLeafRejects;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  // the EC leaf has only DNS:localhost, so an IP-literal identity has no iPAddress SAN to match
  CheckTrue(TServerName.TryParse('127.0.0.1', LName));
  CheckTrue(TDelegatePostChecks.RejectIpMismatch(LName, FPkix,
    TArray<TBytes>.Create(Ec('leaf_cert')), LAlert),
    'an IP literal against a DNS-only leaf is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestDelegatePostChecks.TestDnsNameIsNotRecheckedHere;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  // a DNS host was matched by the OS name logic; this post-check leaves it alone (a nil provider
  // would fail closed if it did run)
  CheckTrue(TServerName.TryParse('localhost', LName));
  CheckFalse(TDelegatePostChecks.RejectIpMismatch(LName, nil, nil, LAlert),
    'a DNS host is not re-checked by the IP post-check');
end;

procedure TTestDelegatePostChecks.TestEmptyNameIsNotRechecked;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  LName := Default(TServerName);
  CheckFalse(TDelegatePostChecks.RejectIpMismatch(LName, nil, nil, LAlert),
    'an empty name (name-checking off) is not re-checked');
end;

procedure TTestDelegatePostChecks.TestIpNameNilProviderFailsClosed;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TServerName.TryParse('127.0.0.1', LName));
  CheckTrue(TDelegatePostChecks.RejectIpMismatch(LName, nil,
    TArray<TBytes>.Create(Ec('ipsan_leaf_cert')), LAlert),
    'an IP literal with no provider to read SANs fails closed');
  CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert),
    'the fail-closed alert is internal_error');
end;

procedure TTestDelegatePostChecks.TestIpNameEmptyPathFailsClosed;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  LAlert := TTlsAlertDescription.BadCertificate;
  CheckTrue(TServerName.TryParse('127.0.0.1', LName));
  CheckTrue(TDelegatePostChecks.RejectIpMismatch(LName, FPkix, nil, LAlert),
    'an IP literal with no validated leaf fails closed');
  CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert),
    'the fail-closed alert is internal_error');
end;

procedure TTestDelegatePostChecks.TestHardNeedsLiveRevocation;
begin
  CheckTrue(TDelegatePostChecks.HardNeedsLiveRevocation(TRevocationPosture.Hard,
    TVerdictDeferral.None), 'Hard with no deferral needs live revocation');
  CheckTrue(TDelegatePostChecks.HardNeedsLiveRevocation(TRevocationPosture.Hard,
    TVerdictDeferral.HostDecision), 'Hard with a host-decision park still needs live revocation');
  CheckFalse(TDelegatePostChecks.HardNeedsLiveRevocation(TRevocationPosture.Hard,
    TVerdictDeferral.LiveRevocation), 'Hard with live revocation is satisfied');
  CheckFalse(TDelegatePostChecks.HardNeedsLiveRevocation(TRevocationPosture.Soft,
    TVerdictDeferral.None), 'Soft never needs live revocation');
  CheckFalse(TDelegatePostChecks.HardNeedsLiveRevocation(TRevocationPosture.Off,
    TVerdictDeferral.None), 'Off never needs live revocation');
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
  CheckFalse(TDelegatePostChecks.RejectNameMismatch(LName, FPkix,
    TArray<TBytes>.Create(Ec('leaf_cert')), LAlert),
    'a DNS host matching a dNSName SAN is accepted');
end;

procedure TTestDelegatePostChecks.TestNameMismatchMatchesIpLeaf;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  // full RFC 6125 identity here also matches an iPAddress SAN
  CheckTrue(TServerName.TryParse('127.0.0.1', LName));
  CheckFalse(TDelegatePostChecks.RejectNameMismatch(LName, FPkix,
    TArray<TBytes>.Create(Ec('ipsan_leaf_cert')), LAlert),
    'an IP literal matching an iPAddress SAN is accepted');
end;

procedure TTestDelegatePostChecks.TestNameMismatchRejectsWrongName;
var
  LName: TServerName;
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(TServerName.TryParse('wrong.example', LName));
  CheckTrue(TDelegatePostChecks.RejectNameMismatch(LName, FPkix,
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
  CheckFalse(TDelegatePostChecks.RejectNameMismatch(LName, FPkix,
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

{ TTestOSDelegateTemplate }

procedure TTestOSDelegateTemplate.SetUp;
begin
  inherited SetUp;
  FPkix := TDefaultPkixProvider.Create as IPkixProvider;
  FClock := TSystemClock.Create as ITlsClock;
  FOcsp := LoadVectorFields('Certs/OcspStapling.txt');
end;

procedure TTestOSDelegateTemplate.TearDown;
begin
  FOcsp.Free;
  inherited TearDown;
end;

function TTestOSDelegateTemplate.Ocsp(const AName: string): TBytes;
begin
  Result := DecodeHex(FOcsp.Values[AName]);
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
  Result.Pkix := FPkix;
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
    LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'), nil,
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
  LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert);
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
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'), nil,
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
  CheckTrue(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'), nil,
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
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'),
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
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'), nil,
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
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'), nil,
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
  CheckTrue(LVerifier.VerifyServerCertificate(OcspChain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert), 'Hard deferred to a live check accepts an indeterminate outcome inline');
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

procedure TTestOSDelegateTemplate.TestSourceRefusesLiveWithoutLiveFetch;
var
  LEngine: IPlatformChainEngine;
  LRaised: Boolean;
begin
  LEngine := TMockPlatformChainEngine.Create([TPlatformChainCapability.CachedRevocation], False,
    Result_(TLiveRevocationOutcome.Good, OcspChain), TTlsAlertDescription.BadCertificate);
  LRaised := False;
  try
    TOSVerifierSource.Create(LEngine, TSystemTrustFetch.Live);
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
  LContext.Pkix := FPkix;
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
  LContext.Pkix := FPkix;
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
  // revocation source here); an empty server name keeps the identity check out of the way
  LFake := TMockPlatformChainEngine.Create([], True,
    Result_(TLiveRevocationOutcome.Indeterminate, OcspChain), TTlsAlertDescription.BadCertificate);
  LEngine := LFake;
  LVerifier := TOSDelegateServerVerifier.Create(LEngine,
    Policy(TRevocationPosture.Off, TSystemTrustFetch.CacheOnly, TVerdictDeferral.None, nil))
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(OcspChain, Default(TServerName), Ocsp('ocsp_revoked'),
    LVerified, LAlert), 'a stapled Revoked rejects a no-cached-revocation server under Off');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

{ TTestSystemTrustFixtures }

function TTestSystemTrustFixtures.FileSnapshot(const AEnvFile, AEnvDir: string;
  const AFiles, ADirs: TArray<string>): ITrustAnchorStore;
var
  LSource: TFileSystemRootSource;
begin
  LSource := TFileSystemRootSource.Create(FPkix, AEnvFile, AEnvDir, AFiles, ADirs);
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
  FPkix := TDefaultPkixProvider.Create as IPkixProvider;
  FDir := IncludeTrailingPathDelimiter(GetCurrentDir) + 'systrust_fixtures';
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
end;

procedure TTestSystemTrustFixtures.TearDown;
begin
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
      CheckTrue(TOSSystemTrust.AnchorStore(FPkix) <> nil,
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
      TOSSystemTrust.AnchorStore(FPkix);
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

procedure TSystemTrustAnchorContractTestBase.SetUp;
begin
  inherited SetUp;
  FPkix := TDefaultPkixProvider.Create as IPkixProvider;
end;

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
    CheckTrue(FPkix.Certificates.IsWellFormed(LRoots[LI]),
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

{$IFDEF TLSLIB_MSWINDOWS}

{ TTestWindowsSystemTrust }

function TTestWindowsSystemTrust.CreateAnchorStore: ITrustAnchorStore;
var
  LSource: TWindowsRootSource;
begin
  LSource := TWindowsRootSource.Create(FPkix);
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

{ TTestWindowsClientDelegate }

procedure TTestWindowsClientDelegate.SetUp;
begin
  inherited SetUp;
  FPkix := TDefaultPkixProvider.Create as IPkixProvider;
  FChain := LoadVectorFields('Certs/ClientAuthChain.txt');
  FForeign := LoadVectorFields('Certs/OcspStapling.txt');
end;

procedure TTestWindowsClientDelegate.TearDown;
begin
  FChain.Free;
  FForeign.Free;
  inherited TearDown;
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
  Result.Pkix := FPkix;
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
  // audit H3: the anchors are the ONLY trust root, so a client cert that does not chain to them
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
    LCtx.PeerRole := TPeerRole.Client; // a client-chain resolver evaluates a client certificate
    LCtx.HostName := '';
    LCtx.OcspStaple := nil;
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
    LCtx.PeerRole := TPeerRole.Server; // wrong role for a client-chain resolver
    LCtx.HostName := '';
    LCtx.OcspStaple := nil;
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
  // the exact A-3 bug direction: a SERVER-chain resolver (server-auth EKU) wired into a server's
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
    LCtx.PeerRole := TPeerRole.Client; // a client chain handed to a server-chain resolver
    LCtx.HostName := '';
    LCtx.OcspStaple := nil;
    LCtx.Chain := Leaf;
    CheckFalse(LResolver.ResolveVerdict(LCtx, LAlert),
      'a server-chain resolver refuses a client park even under Off');
    CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LAlert),
      'the refusal is internal_error, and the guard runs before the Off short-circuit');
  finally
    LResolver.Free;
  end;
end;

{$ENDIF TLSLIB_MSWINDOWS}

{$IFDEF TLSLIB_MACOS}

{ TTestMacOSSystemTrust }

function TTestMacOSSystemTrust.CreateAnchorStore: ITrustAnchorStore;
var
  LSource: TAppleRootSource;
begin
  LSource := TAppleRootSource.Create(FPkix);
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
  FPkix := TDefaultPkixProvider.Create as IPkixProvider;
  FChain := LoadVectorFields('Certs/ClientAuthChain.txt');
  FForeign := LoadVectorFields('Certs/OcspStapling.txt');
end;

procedure TTestAppleClientDelegate.TearDown;
begin
  FChain.Free;
  FForeign.Free;
  inherited TearDown;
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
  LPolicy.Pkix := FPkix;
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

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}

{ TTestUnixSystemTrust }

function TTestUnixSystemTrust.CreateAnchorStore: ITrustAnchorStore;
var
  LSource: TUnixRootSource;
begin
  LSource := TUnixRootSource.Create(FPkix);
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

{$IFEND}

{ TTestSystemTrustInstaller }

procedure TTestSystemTrustInstaller.TestClientInstallComposesLikeFacade;
var
  LInstaller: ISystemTrustInstaller;
  LViaFacade, LViaInstaller: ITlsClientConfig;
  LFacadeBuilder, LInstallerBuilder: ITlsClientConfigBuilder;
begin
  // both paths install the OS server-trust source; the installer simply forwards to the facade
  LInstaller := TSystemTrustInstaller.Create;
  LFacadeBuilder := TTlsPresets.Compatible(Crypto, Pkix).Client;
  TSystemTrust.WithSystemTrust(LFacadeBuilder, Pkix);
  LViaFacade := LFacadeBuilder.Build;
  LInstallerBuilder := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LInstaller.InstallClientTrust(LInstallerBuilder, Pkix);
  LViaInstaller := LInstallerBuilder.Build;
  CheckNotNull(LViaFacade, 'the facade installs a usable client trust source');
  CheckNotNull(LViaInstaller, 'the installer installs a usable client trust source');
end;

procedure TTestSystemTrustInstaller.TestServerInstallMirrorsFacadeRefusal;
var
  LInstaller: ISystemTrustInstaller;
  LFacadeRaised, LInstallerRaised: Boolean;
begin
  // the server role never roots client-cert trust at the public OS store: it installs OS-enumerable
  // anchors where it can and raises where only a delegate exists - the installer mirrors that exactly
  LInstaller := TSystemTrustInstaller.Create;
  LFacadeRaised := False;
  try
    TSystemTrust.WithSystemTrust(TTlsPresets.Compatible(Crypto, Pkix).Server, Pkix);
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LFacadeRaised := True;
  end;
  LInstallerRaised := False;
  try
    LInstaller.InstallClientAuthTrust(TTlsPresets.Compatible(Crypto, Pkix).Server, Pkix);
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      LInstallerRaised := True;
  end;
  CheckEquals(LFacadeRaised, LInstallerRaised,
    'the server installer raises exactly where the facade does');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSystemTrustFixtures);
  RegisterTest(TTestDelegatePostChecks);
  RegisterTest(TTestOSDelegateTemplate);
  RegisterTest(TTestSystemTrustInstaller);
{$ELSE}
  RegisterTest(TTestSystemTrustFixtures.Suite);
  RegisterTest(TTestDelegatePostChecks.Suite);
  RegisterTest(TTestOSDelegateTemplate.Suite);
  RegisterTest(TTestSystemTrustInstaller.Suite);
{$ENDIF FPC}

{$IFDEF TLSLIB_MSWINDOWS}
{$IFDEF FPC}
  RegisterTest(TTestWindowsSystemTrust);
  RegisterTest(TTestWindowsClientDelegate);
{$ELSE}
  RegisterTest(TTestWindowsSystemTrust.Suite);
  RegisterTest(TTestWindowsClientDelegate.Suite);
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

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
{$IFDEF FPC}
  RegisterTest(TTestUnixSystemTrust);
{$ELSE}
  RegisterTest(TTestUnixSystemTrust.Suite);
{$ENDIF FPC}
{$IFEND}

end.
