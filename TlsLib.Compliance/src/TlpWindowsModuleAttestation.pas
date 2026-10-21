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
  TlpICryptoProvider,
  TlpOSCryptoProvider,
  TlpComplianceTypes,
  TlpIModuleAttestation,
  TlpWindowsModuleDecision;

type
  TRtlOsVersionInfoW = record
    dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId: ULONG;
    szCSDVersion: array [0 .. 127] of WideChar;
    wServicePackMajor, wServicePackMinor, wSuiteMask: Word;
    wProductType, wReserved: Byte;
  end;

  TRtlGetVersion = function(var AInfo: TRtlOsVersionInfoW): Int32; stdcall;
  TGetFileVersionInfoSizeW = function(AFileName: PWideChar; var AHandle: DWORD): DWORD; stdcall;
  TGetFileVersionInfoW = function(AFileName: PWideChar; AHandle, ALength: DWORD;
    AData: Pointer): BOOL; stdcall;
  TVerQueryValueW = function(ABlock: Pointer; ASubBlock: PWideChar; var ABuffer: Pointer;
    var ALength: UINT): BOOL; stdcall;
  TBCryptGetFipsAlgorithmMode = function(out AEnabled: ByteBool): Int32; stdcall;
  TIsWow64Process2 = function(AProcess: THandle; out AProcessMachine,
    ANativeMachine: Word): BOOL; stdcall;
  TGetFirmwareType = function(out AType: UInt32): BOOL; stdcall;

  /// <summary>What Attest derives from a set of facts.</summary>
  TWindowsAttestation = record
    Identity: TModuleIdentity;
    Status: TModuleStatus;
    Description: string;
    Disclosures: TArray<string>;
  end;

  /// <summary>
  /// Attests the OS cryptographic module from facts read once at construction: the status is
  /// the decision of TWindowsModuleDecision over them, so a later change to the process, the
  /// machine or the date is not seen. The facts come from the OS version query, the process, the
  /// firmware kind, the clock and the module file on disk, not from the image in memory; code that
  /// alters any of them inside the process is out of scope. The update revision, the edition and
  /// the legacy FIPS switch are reported but never decide the status.
  /// </summary>
  TWindowsModuleAttestation = class sealed(TInterfacedObject, IModuleAttestation)
  strict private
  var
    FFacts: TWindowsModuleFacts;
    FAttested: TWindowsAttestation;
    class function ReadOs(var AFacts: TWindowsModuleFacts): Boolean; static;
    class procedure ReadRegistry(var AFacts: TWindowsModuleFacts); static;
    class function ReadMachines(out AProcessMachine, ANativeMachine: Word): Boolean; static;
    class function ReadFirmware(out AType: UInt32): Boolean; static;
    class function ReadSystemFile(const AFileName: WideString): WideString; static;
    // whether the module the process resolves AFileName to is the system copy; False when it
    // could not be told
    class function ReadSystemCopy(const AFileName: string;
      out ASystemCopy: Boolean): Boolean; static;
    class function ReadLoadedPath(var AFacts: TWindowsModuleFacts): Boolean; static;
    class function ReadModuleVersion(var AFacts: TWindowsModuleFacts): Boolean; static;
    class function ReadLegacyPolicy: TLegacyFipsPolicy; static;
    class function ReadToday: UInt32; static;
  public
    /// <summary>Reads the four numbers a file version string starts with into the module
    /// version facts; False, leaving them alone, for any other text.</summary>
    class function ParseFileVersion(const AText: WideString;
      var AFacts: TWindowsModuleFacts): Boolean; static;
    /// <summary>Reads the facts of this process and machine.</summary>
    class function Gather: TWindowsModuleFacts; static;
    /// <summary>The identity, status and description the given facts give; reads nothing.</summary>
    class function Attest(const AFacts: TWindowsModuleFacts): TWindowsAttestation; static;
    constructor Create;
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
    /// <summary>Whether ACrypto is the OS composition this attestation describes.</summary>
    function Covers(const ACrypto: ICryptoProvider): Boolean;
    function Disclosures: TArray<string>;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

resourcestring
  SValidatedModule = '%s %s: %s, CMVP certificate %s, %s Level %d, validated %s, sunset %s';
  SNotValidatedModule = '%s %s: %s';

const
  ModuleFileName = 'bcryptprimitives.dll';
  FirmwareUnknown = 0;
  VersionKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion';
  RevisionValue = 'UBR';
  EditionValue = 'EditionID';
  EditionChars = 64;

{ TWindowsModuleAttestation }

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
    // not subject to the manifest-based version shim of the Win32 version query
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

class function TWindowsModuleAttestation.ReadFirmware(out AType: UInt32): Boolean;
var
  LModule: NativeUInt;
  LGetFirmwareType: TGetFirmwareType;
begin
  AType := FirmwareUnknown;
  Result := False;
  LModule := TDynamicLibrary.Open('kernel32.dll');
  if LModule = 0 then
    Exit;
  try
    // Windows 8 and later; the validated releases all have it
    LGetFirmwareType := TGetFirmwareType(TDynamicLibrary.Resolve(LModule, 'GetFirmwareType'));
    if not Assigned(LGetFirmwareType) then
      Exit;
    Result := LGetFirmwareType(AType) and (AType <> FirmwareUnknown);
  finally
    TDynamicLibrary.Close(LModule);
  end;
end;

class function TWindowsModuleAttestation.ReadSystemFile(
  const AFileName: WideString): WideString;
var
  LDirectory: array [0 .. MAX_PATH] of WideChar;
  LLength: UINT;
begin
  Result := '';
  LLength := GetSystemDirectoryW(@LDirectory[0], Length(LDirectory));
  if (LLength > 0) and (LLength < UINT(Length(LDirectory))) then
    Result := WideString(PWideChar(@LDirectory[0])) + '\' + AFileName;
end;

class function TWindowsModuleAttestation.ReadSystemCopy(const AFileName: string;
  out ASystemCopy: Boolean): Boolean;
var
  LHandle: NativeUInt;
  LLoaded: Boolean;
  LName, LSystemFile: WideString;
begin
  ASystemCopy := False;
  Result := False;
  LName := AFileName;
  LSystemFile := ReadSystemFile(LName);
  if LSystemFile = '' then
    Exit;
  LHandle := NativeUInt(GetModuleHandleW(PWideChar(LName)));
  LLoaded := False;
  if LHandle = 0 then
  begin
    LHandle := TDynamicLibrary.Open(AFileName);
    LLoaded := LHandle <> 0;
  end;
  if LHandle = 0 then
    Exit;
  try
    // one handle for the bare name and the full system path is the system copy
    ASystemCopy := NativeUInt(GetModuleHandleW(PWideChar(LSystemFile))) = LHandle;
    Result := True;
  finally
    if LLoaded then
      TDynamicLibrary.Close(LHandle);
  end;
end;

class function TWindowsModuleAttestation.ReadLoadedPath(
  var AFacts: TWindowsModuleFacts): Boolean;
var
  LHandle: NativeUInt;
  LLoaded: Boolean;
  LName: WideString;
  LBuffer: array [0 .. MAX_PATH] of WideChar;
  LLength: DWORD;
begin
  AFacts.ModulePath := '';
  AFacts.SystemCopy := False;
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
      AFacts.ModulePath := WideString(PWideChar(@LBuffer[0]));
      Result := True;
    end;
    // the loader resolves a full path to the module loaded from it, whatever the spelling of
    // case or directory, so one handle for both names is the system copy
    AFacts.SystemCopy := (AFacts.SystemModulePath <> '') and
      (NativeUInt(GetModuleHandleW(PWideChar(AFacts.SystemModulePath))) = LHandle);
  finally
    if LLoaded then
      TDynamicLibrary.Close(LHandle);
  end;
end;

class procedure TWindowsModuleAttestation.ReadRegistry(var AFacts: TWindowsModuleFacts);
var
  LKey: HKEY;
  LSubKey, LName: WideString;
  LType, LValue, LSize: DWORD;
  LEdition: array [0 .. EditionChars] of WideChar;
begin
  LSubKey := VersionKey;
  if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PWideChar(LSubKey), 0,
    KEY_QUERY_VALUE or KEY_WOW64_64KEY, LKey) <> ERROR_SUCCESS then
    Exit;
  try
    LName := RevisionValue;
    LType := 0;
    LValue := 0;
    LSize := SizeOf(LValue);
    if (RegQueryValueExW(LKey, PWideChar(LName), nil, @LType, PByte(@LValue), @LSize) =
      ERROR_SUCCESS) and (LType = REG_DWORD) then
      AFacts.Revision := LValue;
    LName := EditionValue;
    LType := 0;
    FillChar(LEdition, SizeOf(LEdition), 0);
    LSize := EditionChars * SizeOf(WideChar);
    if (RegQueryValueExW(LKey, PWideChar(LName), nil, @LType, PByte(@LEdition[0]), @LSize) =
      ERROR_SUCCESS) and (LType = REG_SZ) then
      AFacts.Edition := WideString(PWideChar(@LEdition[0]));
  finally
    RegCloseKey(LKey);
  end;
end;

class function TWindowsModuleAttestation.ParseFileVersion(const AText: WideString;
  var AFacts: TWindowsModuleFacts): Boolean;
var
  LParts: array [0 .. 3] of UInt32;
  LPart, LI: Int32;
  LDigits: Boolean;
begin
  Result := False;
  LPart := 0;
  LDigits := False;
  LParts[0] := 0;
  for LI := 1 to Length(AText) do
  begin
    if (AText[LI] >= '0') and (AText[LI] <= '9') then
    begin
      LParts[LPart] := LParts[LPart] * 10 + UInt32(Ord(AText[LI]) - Ord('0'));
      if LParts[LPart] > $FFFF then
        Exit;
      LDigits := True;
    end
    else if (AText[LI] = '.') and LDigits and (LPart < 3) then
    begin
      Inc(LPart);
      LParts[LPart] := 0;
      LDigits := False;
    end
    else
      Break;
  end;
  if (LPart <> 3) or not LDigits then
    Exit;
  AFacts.ModuleMajor := UInt16(LParts[0]);
  AFacts.ModuleMinor := UInt16(LParts[1]);
  AFacts.ModuleBuild := UInt16(LParts[2]);
  AFacts.ModuleRevision := UInt16(LParts[3]);
  Result := True;
end;

class function TWindowsModuleAttestation.ReadModuleVersion(
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
  LSubBlock: WideString;
  LTranslation: PDWORD;
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
    LSize := LGetSize(PWideChar(AFacts.ModulePath), LHandle);
    if LSize = 0 then
      Exit;
    SetLength(LData, LSize);
    if not LGetInfo(PWideChar(AFacts.ModulePath), 0, LSize, @LData[0]) then
      Exit;
    // the fixed numeric version of a system file reads 6.2 to a process without a Windows 10
    // manifest, so the version string, which is not shimmed, is the source
    LSubBlock := '\VarFileInfo\Translation';
    LBuffer := nil;
    LLength := 0;
    if not LQuery(@LData[0], PWideChar(LSubBlock), LBuffer, LLength) then
      Exit;
    if (LBuffer = nil) or (LLength < SizeOf(DWORD)) then
      Exit;
    LTranslation := PDWORD(LBuffer);
    LSubBlock := WideString(Format('\StringFileInfo\%.4x%.4x\FileVersion',
      [LTranslation^ and $FFFF, LTranslation^ shr 16]));
    LBuffer := nil;
    LLength := 0;
    if not LQuery(@LData[0], PWideChar(LSubBlock), LBuffer, LLength) then
      Exit;
    if LBuffer = nil then
      Exit;
    Result := ParseFileVersion(WideString(PWideChar(LBuffer)), AFacts);
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
  LModule := TDynamicLibrary.Open(TWindowsModuleDecision.BcryptName);
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

class function TWindowsModuleAttestation.ReadToday: UInt32;
var
  LTime: TSystemTime;
begin
  GetSystemTime(LTime);
  Result := UInt32(LTime.wYear) * 10000 + UInt32(LTime.wMonth) * 100 + UInt32(LTime.wDay);
end;

class function TWindowsModuleAttestation.Gather: TWindowsModuleFacts;
begin
  Result := Default(TWindowsModuleFacts);
  Result.Today := ReadToday;
  Result.LegacyFipsPolicy := ReadLegacyPolicy;
  Result.OsRead := ReadOs(Result);
  if Result.OsRead then
    ReadRegistry(Result);
  Result.Process64Bit := SizeOf(Pointer) = 8;
  Result.MachineRead := ReadMachines(Result.ProcessMachine, Result.NativeMachine);
  Result.FirmwareRead := ReadFirmware(Result.FirmwareType);
  Result.SystemModulePath := ReadSystemFile(ModuleFileName);
  Result.BcryptRead := ReadSystemCopy(TWindowsModuleDecision.BcryptName,
    Result.BcryptSystemCopy);
  Result.NcryptRead := ReadSystemCopy(TWindowsModuleDecision.NcryptName,
    Result.NcryptSystemCopy);
  Result.PathRead := ReadLoadedPath(Result);
  if Result.PathRead then
    Result.VersionRead := ReadModuleVersion(Result);
end;

class function TWindowsModuleAttestation.Attest(
  const AFacts: TWindowsModuleFacts): TWindowsAttestation;
var
  LEntry: TWindowsModuleEntry;
  LReason: string;
  LListed: Boolean;
begin
  Result := Default(TWindowsAttestation);
  LEntry := Default(TWindowsModuleEntry);
  Result.Identity.Attested := True;
  Result.Identity.OsName := 'Windows';
  Result.Identity.ModuleName := ModuleFileName;
  Result.Identity.LegacyFipsPolicy := AFacts.LegacyFipsPolicy;
  Result.Identity.ProcessMachine := AFacts.ProcessMachine;
  Result.Identity.NativeMachine := AFacts.NativeMachine;
  Result.Identity.ModulePath := string(AFacts.ModulePath);
  if AFacts.FirmwareRead then
    Result.Identity.Firmware := TWindowsModuleDecision.FirmwareName(AFacts.FirmwareType);
  if AFacts.VersionRead then
    Result.Identity.ModuleFileVersion := Format('%d.%d.%d.%d', [AFacts.ModuleMajor,
      AFacts.ModuleMinor, AFacts.ModuleBuild, AFacts.ModuleRevision]);
  if AFacts.OsRead then
  begin
    Result.Identity.OsBuild := AFacts.Build;
    Result.Identity.OsRevision := AFacts.Revision;
    Result.Identity.OsVersion := Format('%d.%d.%d.%d', [AFacts.Major, AFacts.Minor,
      AFacts.Build, AFacts.Revision]);
    Result.Identity.ProductType := AFacts.ProductType;
    Result.Identity.Edition := AFacts.Edition;
    LListed := TWindowsModuleDecision.Lookup(AFacts.Build, LEntry);
    if LListed then
    begin
      Result.Identity.Product := LEntry.Product;
      Result.Identity.ListedModuleVersion := LEntry.ListedVersion;
    end;
  end;
  Result.Status := TWindowsModuleDecision.Decide(AFacts, LEntry.Standard, LReason);
  // a certificate number means something only while the module is validated
  if Result.Status = TModuleStatus.Validated then
  begin
    Result.Identity.Certificate := LEntry.Certificate;
    Result.Description := Format(SValidatedModule, [Result.Identity.OsName,
      Result.Identity.OsVersion, Result.Identity.ModuleName, LEntry.Certificate,
      TComplianceCatalog.StandardName(LEntry.Standard), LEntry.Level, LEntry.ValidatedOn,
      LEntry.Sunset]);
  end
  else if AFacts.OsRead then
    Result.Description := Format(SNotValidatedModule, [Result.Identity.OsName,
      Result.Identity.OsVersion, LReason])
  else
    Result.Description := LReason;
  Result.Disclosures := TWindowsModuleDecision.Disclosures(AFacts.Build, AFacts.Edition,
    Result.Status);
end;

constructor TWindowsModuleAttestation.Create;
begin
  inherited Create;
  FFacts := Gather;
  FAttested := Attest(FFacts);
end;

function TWindowsModuleAttestation.Identity: TModuleIdentity;
begin
  Result := FAttested.Identity;
end;

function TWindowsModuleAttestation.Status(AStandard: TModuleStandard): TModuleStatus;
var
  LReason: string;
begin
  Result := TWindowsModuleDecision.Decide(FFacts, AStandard, LReason);
end;

function TWindowsModuleAttestation.Describe: string;
begin
  Result := FAttested.Description;
end;

function TWindowsModuleAttestation.Covers(const ACrypto: ICryptoProvider): Boolean;
begin
  Result := TOSCryptoProvider.IsComposition(ACrypto);
end;

function TWindowsModuleAttestation.Disclosures: TArray<string>;
begin
  Result := System.Copy(FAttested.Disclosures);
end;

{$ENDIF}

end.
