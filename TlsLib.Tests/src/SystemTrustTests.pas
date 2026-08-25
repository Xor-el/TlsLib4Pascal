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
/// 1. A portable fixture suite (always runs on every target). TFileSystemAnchorStore is portable
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
  TlsLibTestBase;

type
  /// <summary>Portable suite (always runs): drives TFileSystemAnchorStore's file/dir resolution
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
    procedure TestFactoryAnchorStoreMatchesSupports;
    procedure TestFactoryDelegateVerifierMatchesSupports;
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

{$ENDIF TLSLIB_MSWINDOWS}

{$IFDEF TLSLIB_MACOS}

  /// <summary>macOS (SecTrust settings) instantiation. Registered only on TLSLIB_MACOS - iOS is
  /// delegate-only with no enumerable anchor store, so it is deliberately excluded.</summary>
  TTestMacOSSystemTrust = class(TSystemTrustAnchorContractTestBase)
  strict protected
    function CreateAnchorStore: ITrustAnchorStore; override;
    function PlatformName: string; override;
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

{ TTestSystemTrustFixtures }

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
var
  LStore: ITrustAnchorStore;
begin
  // a single injected bundle file yields exactly its one root
  LStore := TFileSystemAnchorStore.Create(FProvider, '', '',
    TArray<string>.Create(FFile), nil) as ITrustAnchorStore;
  CheckEquals(1, System.Length(LStore.RootCertificates),
    'the injected bundle file is harvested into one anchor');
end;

procedure TTestSystemTrustFixtures.TestFirstExistingFileCandidateWins;
var
  LStore: ITrustAnchorStore;
begin
  // a missing candidate is skipped; the first EXISTING file becomes the authoritative store
  LStore := TFileSystemAnchorStore.Create(FProvider, '', '',
    TArray<string>.Create(FMissing, FFile), nil) as ITrustAnchorStore;
  CheckEquals(1, System.Length(LStore.RootCertificates),
    'the first existing candidate file is used, missing ones skipped');
end;

procedure TTestSystemTrustFixtures.TestNoReadableStoreFailsClosed;
var
  LStore: ITrustAnchorStore;
  LRaised: Boolean;
begin
  // nothing readable anywhere -> fail closed, never a silent empty trust store
  LStore := TFileSystemAnchorStore.Create(FProvider, '', '',
    TArray<string>.Create(FMissing), TArray<string>.Create(FMissing)) as ITrustAnchorStore;
  LRaised := False;
  try
    LStore.RootCertificates;
  except
    on E: ESystemTrustUnavailableTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an unreadable/empty system store fails closed');
end;

procedure TTestSystemTrustFixtures.TestDirectoryHarvestReadsCerts;
var
  LStore: ITrustAnchorStore;
begin
  // a directory of certificate files is enumerated and harvested
  LStore := TFileSystemAnchorStore.Create(FProvider, '', '', nil,
    TArray<string>.Create(FCertDir)) as ITrustAnchorStore;
  CheckTrue(System.Length(LStore.RootCertificates) >= 1,
    'the certificate directory is enumerated into anchors');
end;

procedure TTestSystemTrustFixtures.TestDuplicateCertsAreDeduplicated;
var
  LDir: string;
  LStore: ITrustAnchorStore;
begin
  LDir := IncludeTrailingPathDelimiter(FDir) + 'dupdir';
  ForceDirectories(LDir);
  try
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'a.der', FRootDer);
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'b.der', FRootDer);
    LStore := TFileSystemAnchorStore.Create(FProvider, '', '', nil,
      TArray<string>.Create(LDir)) as ITrustAnchorStore;
    CheckEquals(1, System.Length(LStore.RootCertificates),
      'the same certificate under two names is de-duplicated to one anchor');
  finally
    LStore := nil;
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'a.der');
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'b.der');
    SysUtils.RemoveDir(LDir);
  end;
end;

procedure TTestSystemTrustFixtures.TestDistinctCertsAreNotMerged;
var
  LDir: string;
  LStore: ITrustAnchorStore;
begin
  LDir := IncludeTrailingPathDelimiter(FDir) + 'distinctdir';
  ForceDirectories(LDir);
  try
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'r1.der', FRootDer);
    WriteBytes(IncludeTrailingPathDelimiter(LDir) + 'r2.der', FRoot2Der);
    LStore := TFileSystemAnchorStore.Create(FProvider, '', '', nil,
      TArray<string>.Create(LDir)) as ITrustAnchorStore;
    CheckEquals(2, System.Length(LStore.RootCertificates),
      'two distinct certificates are harvested as two anchors');
  finally
    LStore := nil;
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'r1.der');
    SysUtils.DeleteFile(IncludeTrailingPathDelimiter(LDir) + 'r2.der');
    SysUtils.RemoveDir(LDir);
  end;
end;

procedure TTestSystemTrustFixtures.TestFactoryAnchorStoreMatchesSupports;
var
  LRaised: Boolean;
begin
  // the factory's AnchorStore must AGREE with Supports(Anchors) on every platform: a store where
  // supported (Windows/macOS/Unix), a typed unsupported error where not (iOS/Android). This is
  // platform-agnostic - the contract itself is the invariant, no per-OS expected value hardcoded.
  // Construction is lazy (no harvest here), so this is safe on an empty box.
  if TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
    CheckTrue(TOSSystemTrust.AnchorStore(FProvider) <> nil,
      'a platform that supports Anchors must hand back an anchor store')
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

procedure TTestSystemTrustFixtures.TestFactoryDelegateVerifierMatchesSupports;
var
  LRaised: Boolean;
begin
  // same contract for the OS delegate verifier: a verifier where supported (Windows/macOS/iOS/Android),
  // a typed unsupported error where not (Linux/BSD/Solaris).
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
    CheckTrue(TOSSystemTrust.DelegateVerifier(FProvider) <> nil,
      'a platform that supports Delegate must hand back an OS delegate verifier')
  else
  begin
    LRaised := False;
    try
      TOSSystemTrust.DelegateVerifier(FProvider);
    except
      on E: ESystemTrustUnsupportedTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised,
      'a platform that does not support Delegate must raise from DelegateVerifier');
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
begin
  Result := TWindowsAnchorStore.Create(FProvider) as ITrustAnchorStore;
end;

function TTestWindowsSystemTrust.PlatformName: string;
begin
  Result := 'Windows';
end;

{$ENDIF TLSLIB_MSWINDOWS}

{$IFDEF TLSLIB_MACOS}

{ TTestMacOSSystemTrust }

function TTestMacOSSystemTrust.CreateAnchorStore: ITrustAnchorStore;
begin
  Result := TAppleAnchorStore.Create(FProvider) as ITrustAnchorStore;
end;

function TTestMacOSSystemTrust.PlatformName: string;
begin
  Result := 'macOS';
end;

{$ENDIF TLSLIB_MACOS}

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}

{ TTestUnixSystemTrust }

function TTestUnixSystemTrust.CreateAnchorStore: ITrustAnchorStore;
begin
  Result := TUnixAnchorStore.Create(FProvider) as ITrustAnchorStore;
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
{$ELSE}
  RegisterTest(TTestSystemTrustFixtures.Suite);
{$ENDIF FPC}

{$IFDEF TLSLIB_MSWINDOWS}
{$IFDEF FPC}
  RegisterTest(TTestWindowsSystemTrust);
{$ELSE}
  RegisterTest(TTestWindowsSystemTrust.Suite);
{$ENDIF FPC}
{$ENDIF TLSLIB_MSWINDOWS}

{$IFDEF TLSLIB_MACOS}
{$IFDEF FPC}
  RegisterTest(TTestMacOSSystemTrust);
{$ELSE}
  RegisterTest(TTestMacOSSystemTrust.Suite);
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
