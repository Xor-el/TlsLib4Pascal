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
/// 1. A portable fixture suite (always runs on every target). TFileSystemRootSource is portable
///    and takes an explicit (env, files, dirs) form, so its harvest/resolution logic is exercised
///    on any host by injecting throwaway fixture paths - no real /etc/ssl/certs needed - plus a
///    check that the TOSSystemTrust factory reports a sane capability for the build's platform.
///
/// 2. A real-OS-store contract, written once against ITrustAnchorStore in an abstract base
///    (TSystemTrustAnchorContractTestBase) and instantiated per platform by a thin subclass that
///    supplies the concrete harvester. Each subclass is compile-time guarded to its OS
///    (TLSLIB_MSWINDOWS / TLSLIB_MACOS / TLSLIB_LINUX|BSD|SOLARIS) and registered only there, so it
///    only ever runs on a target that actually owns that store - mirroring the CryptoLib
///    hardware-engine test idiom. A machine with no populated store (e.g. a bare container with no
///    ca-certificates) is tolerated: only the platforms whose OS always ships roots
///    (Windows / macOS) treat an empty harvest as a failure.</summary>
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
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
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
  TlsLibTestBase;

type
  /// <summary>Portable suite (always runs): drives TFileSystemRootSource's file/dir resolution
  /// via injected fixtures, and checks the factory reports anchors for this build's platform.</summary>
  TTestSystemTrustFixtures = class(TTlsLibAlgorithmTestCase)
  private
  var
    FProvider: ICryptoProvider;
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

  /// <summary>Portable suite (always runs): the shared OS-delegate post-checks
  /// (TDelegatePostChecks) - stapled-Revoked-always-wins, IP-literal identity, and the
  /// Hard/Live-need-live-revocation predicates - exercised without touching any real OS store.</summary>
  TTestDelegatePostChecks = class(TTlsLibAlgorithmTestCase)
  private
    FProvider: ICryptoProvider;
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
  end;

  /// <summary>Engine-agnostic contract for a real OS anchor store, written against
  /// ITrustAnchorStore. A concrete per-OS suite supplies only CreateAnchorStore + PlatformName
  /// (and may relax RequiresPopulatedStore); the published tests are inherited and discovered
  /// automatically. Never registered on its own.</summary>
  TSystemTrustAnchorContractTestBase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    FProvider: ICryptoProvider;
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
    FProvider: ICryptoProvider;
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
    FProvider: ICryptoProvider;
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
  FProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
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
  CheckTrue(TDelegatePostChecks.RejectStapledRevoked(FProvider, FClock, OcspChain,
    Ocsp('ocsp_revoked'), LAlert), 'a definitive stapled Revoked always rejects');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestDelegatePostChecks.TestGoodAndAbsentStapleDoNotFire;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FProvider, FClock, OcspChain,
    Ocsp('ocsp_good'), LAlert), 'a current Good staple does not fire the Revoked post-check');
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FProvider, FClock, OcspChain,
    nil, LAlert), 'an absent staple does not fire the Revoked post-check');
end;

procedure TTestDelegatePostChecks.TestStaleStapleIsNotRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  // a stale (out-of-window) response is indeterminate, not Revoked - the posture decides it, so
  // this post-check must not fire
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FProvider, FClock, OcspChain,
    Ocsp('ocsp_stale'), LAlert), 'a stale staple is indeterminate, not Revoked');
end;

procedure TTestDelegatePostChecks.TestLeafOnlyPathIsNotRevoked;
var
  LAlert: TTlsAlertDescription;
begin
  // with no issuer to authenticate the response, the verdict is indeterminate, not Revoked
  CheckFalse(TDelegatePostChecks.RejectStapledRevoked(FProvider, FClock,
    TArray<TBytes>.Create(Ocsp('leaf_cert')), Ocsp('ocsp_revoked'), LAlert),
    'a leaf-only path cannot render a definitive Revoked');
end;

procedure TTestDelegatePostChecks.TestNilClockFallsBackToSystemTime;
var
  LAlert: TTlsAlertDescription;
begin
  // a nil clock must not silently skip the check (it would otherwise make every staple
  // indeterminate); it falls back to system time
  CheckTrue(TDelegatePostChecks.RejectStapledRevoked(FProvider, nil, OcspChain,
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
  CheckFalse(TDelegatePostChecks.RejectIpMismatch(LName, FProvider,
    TArray<TBytes>.Create(Ec('ipsan_leaf_cert')), LAlert),
    'an IP literal matching an iPAddress SAN is accepted');
  CheckTrue(TServerName.TryParse('[::1]', LName));
  CheckFalse(TDelegatePostChecks.RejectIpMismatch(LName, FProvider,
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
  CheckTrue(TDelegatePostChecks.RejectIpMismatch(LName, FProvider,
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
  CheckTrue(TDelegatePostChecks.RejectIpMismatch(LName, FProvider, nil, LAlert),
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

{ TTestSystemTrustFixtures }

function TTestSystemTrustFixtures.FileSnapshot(const AEnvFile, AEnvDir: string;
  const AFiles, ADirs: TArray<string>): ITrustAnchorStore;
var
  LSource: TFileSystemRootSource;
begin
  LSource := TFileSystemRootSource.Create(FProvider, AEnvFile, AEnvDir, AFiles, ADirs);
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
  FProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
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
      CheckTrue(TOSSystemTrust.AnchorStore(FProvider) <> nil,
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
      TOSSystemTrust.AnchorStore(FProvider);
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
    CheckTrue(TOSSystemTrust.ServerVerifierSource(FProvider,
      TSystemTrustFetch.CacheOnly) <> nil,
      'a platform that supports Delegate must hand back an OS server-verifier source')
  else
  begin
    LRaised := False;
    try
      TOSSystemTrust.ServerVerifierSource(FProvider, TSystemTrustFetch.CacheOnly);
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
  FProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
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
    CheckTrue(FProvider.Certificates.IsWellFormed(LRoots[LI]),
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
  LSource := TWindowsRootSource.Create(FProvider);
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
  FProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
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

function TTestWindowsClientDelegate.VerifyPolicy(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrength: TCertificateStrengthPolicy; const AAdvertised: TArray<UInt16>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TWindowsClientDelegateVerifier.Create(FProvider, AAnchors, APosture,
    TSystemTrustFetch.CacheOnly, AClock, AStrength, AAdvertised) as IClientCertificateVerifier;
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
  LVerifier := TWindowsClientDelegateVerifier.Create(FProvider, OwnAnchor,
    TRevocationPosture.Hard, TSystemTrustFetch.Live, TSystemClock.Create as ITlsClock,
    TCertificateStrengthPolicy.Defaults, Advertised) as IClientCertificateVerifier;
  CheckTrue(LVerifier.VerifyClientCertificate(Leaf, LVerified, LAlert),
    'Live defers an unrevocable client chain inline (effective-Soft) so the handshake can park');
end;

function TTestWindowsClientDelegate.VerifyLive(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; out AAlert: TTlsAlertDescription): Boolean;
var
  LResolver: TWindowsClientLiveRevocationResolver;
  LCtx: TCertificateVerdictContext;
begin
  LResolver := TWindowsClientLiveRevocationResolver.Create(FProvider, AAnchors, APosture,
    TSystemClock.Create as ITlsClock, TCertificateStrengthPolicy.Defaults, Advertised, 2000, nil);
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
  LResolver: TWindowsClientLiveRevocationResolver;
  LCtx: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  // a client-chain resolver (client-auth EKU) handed a SERVER-role park is a local misconfiguration
  // - a single process-wide resolver wired for the wrong role. It must refuse with internal_error,
  // not run its client-auth engine over a server chain and surface a misleading trust failure.
  LResolver := TWindowsClientLiveRevocationResolver.Create(FProvider, OwnAnchor,
    TRevocationPosture.Hard, TSystemClock.Create as ITlsClock,
    TCertificateStrengthPolicy.Defaults, Advertised, 2000, nil);
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
  LResolver: TWindowsLiveRevocationResolver;
  LCtx: TCertificateVerdictContext;
  LAlert: TTlsAlertDescription;
begin
  // the exact A-3 bug direction: a SERVER-chain resolver (server-auth EKU) wired into a server's
  // mTLS park would evaluate a CLIENT chain against the wrong EKU and reject every client. The
  // role guard must refuse it - and even under the Off posture, because the misconfiguration is
  // posture-independent (Off would otherwise accept without evaluating, hiding the mistake until a
  // later posture change). This pins both the bug direction and the guard-before-Off ordering.
  LResolver := TWindowsLiveRevocationResolver.Create(FProvider, TRevocationPosture.Off,
    TSystemClock.Create as ITlsClock, TCertificateStrengthPolicy.Defaults, Advertised, 2000, nil);
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
  LSource := TAppleRootSource.Create(FProvider);
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
  FProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
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
begin
  LVerifier := TAppleClientDelegateVerifier.Create(FProvider, AAnchors, APosture,
    TSystemTrustFetch.CacheOnly, AClock, AStrength, AAdvertised) as IClientCertificateVerifier;
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
  LSource := TUnixRootSource.Create(FProvider);
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestSystemTrustFixtures);
  RegisterTest(TTestDelegatePostChecks);
{$ELSE}
  RegisterTest(TTestSystemTrustFixtures.Suite);
  RegisterTest(TTestDelegatePostChecks.Suite);
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
