{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWindowsModuleAttestation;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IFDEF TLSLIB_MSWINDOWS}

uses
  Windows,
  SysUtils,
  TlpDynamicLibrary,
  TlpComplianceTypes,
  TlpIModuleAttestation;

type
  TRtlOsVersionInfoW = record
    dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId: ULONG;
    szCSDVersion: array [0 .. 127] of WideChar;
    wServicePackMajor, wServicePackMinor, wSuiteMask: Word;
    wProductType, wReserved: Byte;
  end;

  TVsFixedFileInfo = record
    dwSignature, dwStrucVersion, dwFileVersionMS, dwFileVersionLS, dwProductVersionMS,
      dwProductVersionLS, dwFileFlagsMask, dwFileFlags, dwFileOS, dwFileType, dwFileSubtype,
      dwFileDateMS, dwFileDateLS: DWORD;
  end;

  PVsFixedFileInfo = ^TVsFixedFileInfo;

  TRtlGetVersion = function(var AInfo: TRtlOsVersionInfoW): Int32; stdcall;
  TGetFileVersionInfoSizeW = function(AFileName: PWideChar; var AHandle: DWORD): DWORD; stdcall;
  TGetFileVersionInfoW = function(AFileName: PWideChar; AHandle, ALength: DWORD;
    AData: Pointer): BOOL; stdcall;
  TVerQueryValueW = function(ABlock: Pointer; ASubBlock: PWideChar; var ABuffer: Pointer;
    var ALength: UINT): BOOL; stdcall;
  TBCryptGetFipsAlgorithmMode = function(out AEnabled: ByteBool): Int32; stdcall;
  TIsWow64Process2 = function(AProcess: THandle; out AProcessMachine,
    ANativeMachine: Word): BOOL; stdcall;

  /// <summary>One row of the shipped validated-module table. Standard, Level, the dates, the
  /// product types and the listed module version mean something only when Validated.</summary>
  TWindowsModuleEntry = record
    Build: UInt32;
    Product: string;
    Certificate: string;
    Validated: Boolean;
    Standard: TModuleStandard;
    Level: UInt32;
    /// <summary>Validation and sunset dates, ISO 8601.</summary>
    ValidatedOn: string;
    Sunset: string;
    /// <summary>The OS product types the certificate was issued for.</summary>
    ProductTypes: set of Byte;
    /// <summary>The module file version the certificate lists.</summary>
    ListedVersion: string;
  end;

  /// <summary>Everything the decision reads. The Read flags say whether a fact could be
  /// obtained; a fact that was not read decides nothing but Unknown.</summary>
  TWindowsModuleFacts = record
    OsRead: Boolean;
    Major: UInt32;
    Minor: UInt32;
    Build: UInt32;
    PlatformId: UInt32;
    Revision: UInt32;
    ProductType: Byte;
    Process64Bit: Boolean;
    MachineRead: Boolean;
    ProcessMachine: UInt16;
    NativeMachine: UInt16;
    PathRead: Boolean;
    ModulePath: WideString;
    SystemModulePath: WideString;
    VersionRead: Boolean;
    ModuleMajor: UInt16;
    ModuleMinor: UInt16;
    ModuleBuild: UInt16;
    ModuleRevision: UInt16;
    LegacyFipsPolicy: TLegacyFipsPolicy;
  end;

  /// <summary>
  /// Attests the OS cryptographic module. The status is validated only for a listed release
  /// run as a native 64-bit x64 process with the system copy of the module at that release's
  /// build; every other combination is NotValidated and a fact that cannot be read is Unknown.
  /// The update revision and the legacy FIPS switch are reported but never decide the status.
  /// Facts are read once at construction.
  /// </summary>
  TWindowsModuleAttestation = class sealed(TInterfacedObject, IModuleAttestation)
  strict private
  var
    FFacts: TWindowsModuleFacts;
    FIdentity: TModuleIdentity;
    FEntry: TWindowsModuleEntry;
    class function ReadOs(var AFacts: TWindowsModuleFacts): Boolean; static;
    class function ReadRevision: UInt32; static;
    class function ReadMachines(out AProcessMachine, ANativeMachine: Word): Boolean; static;
    class function ReadSystemPath: WideString; static;
    class function ReadLoadedPath(out APath: WideString): Boolean; static;
    class function ReadModuleVersion(const APath: WideString;
      var AFacts: TWindowsModuleFacts): Boolean; static;
    class function ReadLegacyPolicy: TLegacyFipsPolicy; static;
    // the reason of the first fact that contradicts validation, else empty
    class function Mismatch(const AFacts: TWindowsModuleFacts;
      AStandard: TModuleStandard): string; static;
    // the reason of the first fact the decision needs and could not be read, else empty
    class function Unreadable(const AFacts: TWindowsModuleFacts): string; static;
    procedure Apply(const AFacts: TWindowsModuleFacts);
  public
    /// <summary>The shipped validated-module table, matched on the OS build alone.</summary>
    class function Lookup(ABuild: UInt32; out AEntry: TWindowsModuleEntry): Boolean; static;
    /// <summary>Reads the facts of this process and machine.</summary>
    class function Gather: TWindowsModuleFacts; static;
    /// <summary>The status the facts give for AStandard, and the reason when it is not
    /// Validated.</summary>
    class function Decide(const AFacts: TWindowsModuleFacts; AStandard: TModuleStandard;
      out AReason: string): TModuleStatus; static;
    constructor Create;
    /// <summary>Attests the given facts instead of the ones this process reads.</summary>
    constructor CreateFromFacts(const AFacts: TWindowsModuleFacts);
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

resourcestring
  SValidatedModule = '%s %s: %s, CMVP certificate %s, %s Level %d, validated %s, sunset %s';
  SNotValidatedModule = '%s %s: %s';
  SUnreadableBuild = 'the OS build could not be read';
  SNotNtTen = 'the OS is %d.%d (platform %d), not a Windows NT 10.0 release';
  SNoValidatedBuild = 'the shipped table records no validated module for this build';
  SProductTypeNotCovered = 'the OS product type %d is not one the certificate covers for build %d';
  SProcess32Bit = 'the process is 32-bit; the certificate covers the 64-bit module only';
  SProcessEmulated = 'the process runs under emulation (process machine 0x%.4x); the certificate ' +
    'covers a native x64 process';
  SNativeNotX64 = 'the native machine is 0x%.4x, not x64; the certificate covers x64 hardware';
  SModuleNotSystemCopy = 'the loaded module is %s, not the system copy %s';
  SModuleBuildMismatch = 'the module file version is %d.%d.%d.%d, not 10.0.%d';
  SMachineUnreadable = 'the process and machine architectures could not be read';
  SModulePathUnreadable = 'the path of the loaded module could not be read';
  SModuleVersionUnreadable = 'the file version of the loaded module could not be read';

const
  ModuleFileName = 'bcryptprimitives.dll';
  NtMajor = 10;
  NtMinor = 0;
  NtPlatformId = 2;
  MachineAmd64 = $8664;
  ProductWorkstation = 1;
  ProductDomainController = 2;
  ProductServer = 3;
  ValidatedCertificate = '5410';
  CertificateValidatedOn = '2026-08-31';
  CertificateSunset = '2031-08-30';
  VersionKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion';
  RevisionValue = 'UBR';

{ TWindowsModuleAttestation }

class function TWindowsModuleAttestation.Lookup(ABuild: UInt32;
  out AEntry: TWindowsModuleEntry): Boolean;
const
  Table: array [0 .. 8] of TWindowsModuleEntry = (
    (Build: 22621; Product: 'Windows 11 22H2'; Certificate: ValidatedCertificate;
    Validated: True; Standard: TModuleStandard.Fips140_3; Level: 1;
    ValidatedOn: CertificateValidatedOn; Sunset: CertificateSunset;
    ProductTypes: [ProductWorkstation]; ListedVersion: '10.0.22621.30001'),
    (Build: 20348; Product: 'Windows Server 2022'; Certificate: ValidatedCertificate;
    Validated: True; Standard: TModuleStandard.Fips140_3; Level: 1;
    ValidatedOn: CertificateValidatedOn; Sunset: CertificateSunset;
    ProductTypes: [ProductDomainController, ProductServer]; ListedVersion: '10.0.20348.30000'),
    (Build: 22631; Product: 'Windows 11 23H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: '';
    ProductTypes: []; ListedVersion: ''),
    (Build: 26100; Product: 'Windows 11 24H2 / Server 2025'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: '';
    ProductTypes: []; ListedVersion: ''),
    (Build: 26200; Product: 'Windows 11 25H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: '';
    ProductTypes: []; ListedVersion: ''),
    (Build: 19045; Product: 'Windows 10 22H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: '';
    ProductTypes: []; ListedVersion: ''),
    (Build: 19044; Product: 'Windows 10 21H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: '';
    ProductTypes: []; ListedVersion: ''),
    (Build: 17763; Product: 'Windows 10 1809 / Server 2019'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: '';
    ProductTypes: []; ListedVersion: ''),
    (Build: 14393; Product: 'Windows 10 1607 / Server 2016'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: '';
    ProductTypes: []; ListedVersion: ''));
var
  LI: Int32;
begin
  AEntry := Default(TWindowsModuleEntry);
  Result := False;
  for LI := Low(Table) to High(Table) do
    if Table[LI].Build = ABuild then
    begin
      AEntry := Table[LI];
      Exit(True);
    end;
end;

class function TWindowsModuleAttestation.ReadOs(var AFacts: TWindowsModuleFacts): Boolean;
var
  LModule: NativeUInt;
  LGetVersion: TRtlGetVersion;
  LInfo: TRtlOsVersionInfoW;
begin
  Result := False;
  LModule := TDynamicLibrary.Open('ntdll.dll');
  if LModule = 0 then
    Exit;
  try
    // unlike the compatibility-shimmed query, this reports the true build
    LGetVersion := TRtlGetVersion(TDynamicLibrary.Resolve(LModule, 'RtlGetVersion'));
    if not Assigned(LGetVersion) then
      Exit;
    LInfo := Default(TRtlOsVersionInfoW);
    LInfo.dwOSVersionInfoSize := SizeOf(LInfo);
    if LGetVersion(LInfo) <> 0 then
      Exit;
    AFacts.Major := LInfo.dwMajorVersion;
    AFacts.Minor := LInfo.dwMinorVersion;
    AFacts.Build := LInfo.dwBuildNumber;
    AFacts.PlatformId := LInfo.dwPlatformId;
    AFacts.ProductType := LInfo.wProductType;
    Result := True;
  finally
    TDynamicLibrary.Close(LModule);
  end;
end;

class function TWindowsModuleAttestation.ReadMachines(out AProcessMachine,
  ANativeMachine: Word): Boolean;
var
  LModule: NativeUInt;
  LIsWow64Process2: TIsWow64Process2;
begin
  AProcessMachine := 0;
  ANativeMachine := 0;
  Result := False;
  LModule := TDynamicLibrary.Open('kernel32.dll');
  if LModule = 0 then
    Exit;
  try
    // older systems lack it; it also tells emulated processes on other hardware apart
    LIsWow64Process2 := TIsWow64Process2(TDynamicLibrary.Resolve(LModule, 'IsWow64Process2'));
    if not Assigned(LIsWow64Process2) then
      Exit;
    Result := LIsWow64Process2(GetCurrentProcess, AProcessMachine, ANativeMachine);
  finally
    TDynamicLibrary.Close(LModule);
  end;
end;

class function TWindowsModuleAttestation.ReadSystemPath: WideString;
var
  LDirectory: array [0 .. MAX_PATH] of WideChar;
  LLength: UINT;
begin
  Result := '';
  LLength := GetSystemDirectoryW(@LDirectory[0], Length(LDirectory));
  if (LLength > 0) and (LLength < UINT(Length(LDirectory))) then
    Result := WideString(PWideChar(@LDirectory[0])) + '\' + ModuleFileName;
end;

class function TWindowsModuleAttestation.ReadLoadedPath(out APath: WideString): Boolean;
var
  LHandle: NativeUInt;
  LLoaded: Boolean;
  LName: WideString;
  LBuffer: array [0 .. MAX_PATH] of WideChar;
  LLength: DWORD;
begin
  APath := '';
  Result := False;
  LName := ModuleFileName;
  LHandle := NativeUInt(GetModuleHandleW(PWideChar(LName)));
  LLoaded := False;
  if LHandle = 0 then
  begin
    LHandle := TDynamicLibrary.Open(ModuleFileName);
    LLoaded := LHandle <> 0;
  end;
  if LHandle = 0 then
    Exit;
  try
    LLength := GetModuleFileNameW(HMODULE(LHandle), @LBuffer[0], Length(LBuffer));
    if (LLength > 0) and (LLength < DWORD(Length(LBuffer))) then
    begin
      APath := WideString(PWideChar(@LBuffer[0]));
      Result := True;
    end;
  finally
    if LLoaded then
      TDynamicLibrary.Close(LHandle);
  end;
end;

class function TWindowsModuleAttestation.ReadRevision: UInt32;
var
  LKey: HKEY;
  LSubKey, LName: WideString;
  LType, LValue, LSize: DWORD;
begin
  Result := 0;
  LSubKey := VersionKey;
  LName := RevisionValue;
  if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PWideChar(LSubKey), 0,
    KEY_QUERY_VALUE or KEY_WOW64_64KEY, LKey) <> ERROR_SUCCESS then
    Exit;
  try
    LType := 0;
    LValue := 0;
    LSize := SizeOf(LValue);
    if (RegQueryValueExW(LKey, PWideChar(LName), nil, @LType, PByte(@LValue), @LSize) =
      ERROR_SUCCESS) and (LType = REG_DWORD) then
      Result := LValue;
  finally
    RegCloseKey(LKey);
  end;
end;

class function TWindowsModuleAttestation.ReadModuleVersion(const APath: WideString;
  var AFacts: TWindowsModuleFacts): Boolean;
var
  LModule: NativeUInt;
  LGetSize: TGetFileVersionInfoSizeW;
  LGetInfo: TGetFileVersionInfoW;
  LQuery: TVerQueryValueW;
  LHandle, LSize: DWORD;
  LData: TBytes;
  LBuffer: Pointer;
  LLength: UINT;
  LRoot: WideString;
  LInfo: PVsFixedFileInfo;
begin
  Result := False;
  LModule := TDynamicLibrary.Open('version.dll');
  if LModule = 0 then
    Exit;
  try
    LGetSize := TGetFileVersionInfoSizeW(TDynamicLibrary.Resolve(LModule,
      'GetFileVersionInfoSizeW'));
    LGetInfo := TGetFileVersionInfoW(TDynamicLibrary.Resolve(LModule, 'GetFileVersionInfoW'));
    LQuery := TVerQueryValueW(TDynamicLibrary.Resolve(LModule, 'VerQueryValueW'));
    if not (Assigned(LGetSize) and Assigned(LGetInfo) and Assigned(LQuery)) then
      Exit;
    LHandle := 0;
    LSize := LGetSize(PWideChar(APath), LHandle);
    if LSize = 0 then
      Exit;
    SetLength(LData, LSize);
    if not LGetInfo(PWideChar(APath), 0, LSize, @LData[0]) then
      Exit;
    LRoot := '\';
    LBuffer := nil;
    LLength := 0;
    if not LQuery(@LData[0], PWideChar(LRoot), LBuffer, LLength) then
      Exit;
    if (LBuffer = nil) or (LLength < SizeOf(TVsFixedFileInfo)) then
      Exit;
    LInfo := PVsFixedFileInfo(LBuffer);
    AFacts.ModuleMajor := UInt16(LInfo^.dwFileVersionMS shr 16);
    AFacts.ModuleMinor := UInt16(LInfo^.dwFileVersionMS and $FFFF);
    AFacts.ModuleBuild := UInt16(LInfo^.dwFileVersionLS shr 16);
    AFacts.ModuleRevision := UInt16(LInfo^.dwFileVersionLS and $FFFF);
    Result := True;
  finally
    TDynamicLibrary.Close(LModule);
  end;
end;

class function TWindowsModuleAttestation.ReadLegacyPolicy: TLegacyFipsPolicy;
var
  LModule: NativeUInt;
  LGetMode: TBCryptGetFipsAlgorithmMode;
  LEnabled: ByteBool;
begin
  Result := TLegacyFipsPolicy.Unknown;
  LModule := TDynamicLibrary.Open('bcrypt.dll');
  if LModule = 0 then
    Exit;
  try
    LGetMode := TBCryptGetFipsAlgorithmMode(TDynamicLibrary.Resolve(LModule,
      'BCryptGetFipsAlgorithmMode'));
    if not Assigned(LGetMode) then
      Exit;
    LEnabled := False;
    if LGetMode(LEnabled) <> 0 then
      Exit;
    if LEnabled then
      Result := TLegacyFipsPolicy.Enabled
    else
      Result := TLegacyFipsPolicy.Disabled;
  finally
    TDynamicLibrary.Close(LModule);
  end;
end;

class function TWindowsModuleAttestation.Gather: TWindowsModuleFacts;
begin
  Result := Default(TWindowsModuleFacts);
  Result.LegacyFipsPolicy := ReadLegacyPolicy;
  Result.OsRead := ReadOs(Result);
  if Result.OsRead then
    Result.Revision := ReadRevision;
  Result.Process64Bit := SizeOf(Pointer) = 8;
  Result.MachineRead := ReadMachines(Result.ProcessMachine, Result.NativeMachine);
  Result.SystemModulePath := ReadSystemPath;
  Result.PathRead := (Result.SystemModulePath <> '') and
    ReadLoadedPath(Result.ModulePath);
  if Result.PathRead then
    Result.VersionRead := ReadModuleVersion(Result.ModulePath, Result);
end;

class function TWindowsModuleAttestation.Mismatch(const AFacts: TWindowsModuleFacts;
  AStandard: TModuleStandard): string;
var
  LEntry: TWindowsModuleEntry;
  LListed: Boolean;
begin
  Result := '';
  if (AFacts.Major <> NtMajor) or (AFacts.Minor <> NtMinor) or
    (AFacts.PlatformId <> NtPlatformId) then
    Exit(Format(SNotNtTen, [AFacts.Major, AFacts.Minor, AFacts.PlatformId]));
  LListed := Lookup(AFacts.Build, LEntry);
  if not LListed or not LEntry.Validated or (LEntry.Standard <> AStandard) then
    Exit(SNoValidatedBuild);
  if not (AFacts.ProductType in LEntry.ProductTypes) then
    Exit(Format(SProductTypeNotCovered, [AFacts.ProductType, AFacts.Build]));
  if not AFacts.Process64Bit then
    Exit(SProcess32Bit);
  if AFacts.ProcessMachine <> 0 then
    Exit(Format(SProcessEmulated, [AFacts.ProcessMachine]));
  if AFacts.MachineRead and (AFacts.NativeMachine <> MachineAmd64) then
    Exit(Format(SNativeNotX64, [AFacts.NativeMachine]));
  if AFacts.PathRead and not WideSameText(AFacts.ModulePath, AFacts.SystemModulePath) then
    Exit(Format(SModuleNotSystemCopy, [string(AFacts.ModulePath),
      string(AFacts.SystemModulePath)]));
  if AFacts.VersionRead and ((AFacts.ModuleMajor <> NtMajor) or
    (AFacts.ModuleMinor <> NtMinor) or (AFacts.ModuleBuild <> AFacts.Build)) then
    Exit(Format(SModuleBuildMismatch, [AFacts.ModuleMajor, AFacts.ModuleMinor,
      AFacts.ModuleBuild, AFacts.ModuleRevision, AFacts.Build]));
end;

class function TWindowsModuleAttestation.Unreadable(const AFacts: TWindowsModuleFacts): string;
begin
  Result := '';
  if not AFacts.MachineRead then
    Exit(SMachineUnreadable);
  if not AFacts.PathRead then
    Exit(SModulePathUnreadable);
  if not AFacts.VersionRead then
    Exit(SModuleVersionUnreadable);
end;

class function TWindowsModuleAttestation.Decide(const AFacts: TWindowsModuleFacts;
  AStandard: TModuleStandard; out AReason: string): TModuleStatus;
begin
  if not AFacts.OsRead then
  begin
    AReason := SUnreadableBuild;
    Exit(TModuleStatus.Unknown);
  end;
  AReason := Mismatch(AFacts, AStandard);
  if AReason <> '' then
    Exit(TModuleStatus.NotValidated);
  AReason := Unreadable(AFacts);
  if AReason <> '' then
    Exit(TModuleStatus.Unknown);
  Result := TModuleStatus.Validated;
end;

procedure TWindowsModuleAttestation.Apply(const AFacts: TWindowsModuleFacts);
begin
  FFacts := AFacts;
  FEntry := Default(TWindowsModuleEntry);
  FIdentity := Default(TModuleIdentity);
  FIdentity.OsName := 'Windows';
  FIdentity.ModuleName := ModuleFileName;
  FIdentity.LegacyFipsPolicy := AFacts.LegacyFipsPolicy;
  if not AFacts.OsRead then
    Exit;
  FIdentity.OsBuild := AFacts.Build;
  FIdentity.OsRevision := AFacts.Revision;
  FIdentity.OsVersion := Format('%d.%d.%d.%d', [AFacts.Major, AFacts.Minor, AFacts.Build,
    AFacts.Revision]);
  FIdentity.ProductType := AFacts.ProductType;
  FIdentity.ProcessMachine := AFacts.ProcessMachine;
  FIdentity.NativeMachine := AFacts.NativeMachine;
  FIdentity.ModulePath := string(AFacts.ModulePath);
  if AFacts.VersionRead then
    FIdentity.ModuleFileVersion := Format('%d.%d.%d.%d', [AFacts.ModuleMajor,
      AFacts.ModuleMinor, AFacts.ModuleBuild, AFacts.ModuleRevision]);
  if Lookup(AFacts.Build, FEntry) then
  begin
    FIdentity.Product := FEntry.Product;
    FIdentity.Certificate := FEntry.Certificate;
    FIdentity.ListedModuleVersion := FEntry.ListedVersion;
  end;
end;

constructor TWindowsModuleAttestation.Create;
begin
  inherited Create;
  Apply(Gather);
end;

constructor TWindowsModuleAttestation.CreateFromFacts(const AFacts: TWindowsModuleFacts);
begin
  inherited Create;
  Apply(AFacts);
end;

function TWindowsModuleAttestation.Identity: TModuleIdentity;
begin
  Result := FIdentity;
end;

function TWindowsModuleAttestation.Status(AStandard: TModuleStandard): TModuleStatus;
var
  LReason: string;
begin
  Result := Decide(FFacts, AStandard, LReason);
end;

function TWindowsModuleAttestation.Describe: string;
var
  LReason: string;
begin
  if Decide(FFacts, FEntry.Standard, LReason) = TModuleStatus.Validated then
    Result := Format(SValidatedModule, [FIdentity.OsName, FIdentity.OsVersion,
      FIdentity.ModuleName, FIdentity.Certificate,
      TComplianceCatalog.StandardName(FEntry.Standard), FEntry.Level, FEntry.ValidatedOn,
      FEntry.Sunset])
  else if FFacts.OsRead then
    Result := Format(SNotValidatedModule, [FIdentity.OsName, FIdentity.OsVersion, LReason])
  else
    Result := LReason;
end;

{$ENDIF}

end.
