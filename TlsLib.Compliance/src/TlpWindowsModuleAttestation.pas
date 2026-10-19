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

  /// <summary>One row of the shipped validated-module table. A row that is not Validated has no
  /// certificate and carries no standard, level or dates.</summary>
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
  end;

  /// <summary>
  /// Attests the OS cryptographic module from the OS build alone: the build is looked up in a
  /// shipped table of validated releases, so a release the table does not list is NotValidated.
  /// The module file version, the update revision and the legacy FIPS switch are reported but
  /// never decide the status. Facts are read once at construction.
  /// </summary>
  TWindowsModuleAttestation = class sealed(TInterfacedObject, IModuleAttestation)
  strict private
  var
    FIdentity: TModuleIdentity;
    FBuildKnown: Boolean;
    FEntry: TWindowsModuleEntry;
    class function ReadBuild(out ABuild: UInt32; out AVersion: string): Boolean; static;
    class function ReadRevision: UInt32; static;
    class function ReadModuleVersion(const APath: WideString): string; static;
    class function ReadLegacyPolicy: TLegacyFipsPolicy; static;
  public
    /// <summary>The shipped validated-module table, matched on the OS build alone.</summary>
    class function Lookup(ABuild: UInt32; out AEntry: TWindowsModuleEntry): Boolean; static;
    constructor Create;
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

resourcestring
  SValidatedModule = '%s %s: %s, CMVP certificate %s, %s Level %d, validated %s, sunset %s';
  SNotValidatedModule = '%s %s: the shipped table records no validated module for this build';
  SUnreadableBuild = 'the OS build could not be read';

const
  ModuleFileName = 'bcryptprimitives.dll';
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
    ValidatedOn: CertificateValidatedOn; Sunset: CertificateSunset),
    (Build: 20348; Product: 'Windows Server 2022'; Certificate: ValidatedCertificate;
    Validated: True; Standard: TModuleStandard.Fips140_3; Level: 1;
    ValidatedOn: CertificateValidatedOn; Sunset: CertificateSunset),
    (Build: 22631; Product: 'Windows 11 23H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''),
    (Build: 26100; Product: 'Windows 11 24H2 / Server 2025'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''),
    (Build: 26200; Product: 'Windows 11 25H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''),
    (Build: 19045; Product: 'Windows 10 22H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''),
    (Build: 19044; Product: 'Windows 10 21H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''),
    (Build: 17763; Product: 'Windows 10 1809 / Server 2019'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''),
    (Build: 14393; Product: 'Windows 10 1607 / Server 2016'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''));
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

class function TWindowsModuleAttestation.ReadBuild(out ABuild: UInt32;
  out AVersion: string): Boolean;
var
  LModule: NativeUInt;
  LGetVersion: TRtlGetVersion;
  LInfo: TRtlOsVersionInfoW;
begin
  ABuild := 0;
  AVersion := '';
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
    ABuild := LInfo.dwBuildNumber;
    AVersion := Format('%d.%d.%d', [LInfo.dwMajorVersion, LInfo.dwMinorVersion,
      LInfo.dwBuildNumber]);
    Result := True;
  finally
    TDynamicLibrary.Close(LModule);
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

class function TWindowsModuleAttestation.ReadModuleVersion(const APath: WideString): string;
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
  Result := '';
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
    Result := Format('%d.%d.%d.%d', [LInfo^.dwFileVersionMS shr 16,
      LInfo^.dwFileVersionMS and $FFFF, LInfo^.dwFileVersionLS shr 16,
      LInfo^.dwFileVersionLS and $FFFF]);
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

constructor TWindowsModuleAttestation.Create;
var
  LEntry: TWindowsModuleEntry;
  LVersion: string;
  LDirectory: array [0 .. MAX_PATH] of WideChar;
  LLength: UINT;
  LPath: WideString;
begin
  inherited Create;
  FIdentity := Default(TModuleIdentity);
  FEntry := Default(TWindowsModuleEntry);
  FIdentity.OsName := 'Windows';
  FIdentity.ModuleName := ModuleFileName;
  FIdentity.LegacyFipsPolicy := ReadLegacyPolicy;
  FBuildKnown := ReadBuild(FIdentity.OsBuild, LVersion);
  if not FBuildKnown then
    Exit;
  FIdentity.OsRevision := ReadRevision;
  FIdentity.OsVersion := Format('%s.%d', [LVersion, FIdentity.OsRevision]);
  LLength := GetSystemDirectoryW(@LDirectory[0], Length(LDirectory));
  if (LLength > 0) and (LLength < UINT(Length(LDirectory))) then
  begin
    LPath := WideString(PWideChar(@LDirectory[0])) + '\' + ModuleFileName;
    FIdentity.ModuleFileVersion := ReadModuleVersion(LPath);
  end;
  if Lookup(FIdentity.OsBuild, LEntry) then
  begin
    FEntry := LEntry;
    FIdentity.Product := LEntry.Product;
    FIdentity.Certificate := LEntry.Certificate;
  end;
end;

function TWindowsModuleAttestation.Identity: TModuleIdentity;
begin
  Result := FIdentity;
end;

function TWindowsModuleAttestation.Status(AStandard: TModuleStandard): TModuleStatus;
begin
  if not FBuildKnown then
    Result := TModuleStatus.Unknown
  else if FEntry.Validated and (FEntry.Standard = AStandard) then
    Result := TModuleStatus.Validated
  else
    Result := TModuleStatus.NotValidated;
end;

function TWindowsModuleAttestation.Describe: string;
begin
  if not FBuildKnown then
    Result := SUnreadableBuild
  else if FEntry.Validated then
    Result := Format(SValidatedModule, [FIdentity.OsName, FIdentity.OsVersion,
      FIdentity.ModuleName, FIdentity.Certificate,
      TComplianceCatalog.StandardName(FEntry.Standard), FEntry.Level, FEntry.ValidatedOn,
      FEntry.Sunset])
  else
    Result := Format(SNotValidatedModule, [FIdentity.OsName, FIdentity.OsVersion]);
end;

{$ENDIF}

end.
