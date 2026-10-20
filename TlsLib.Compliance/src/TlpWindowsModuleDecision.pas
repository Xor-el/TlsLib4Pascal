{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWindowsModuleDecision;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpComplianceTypes;

type
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
  /// obtained; a fact that was not read decides nothing but Unknown. Edition and Revision are
  /// reported, never decided on.</summary>
  TWindowsModuleFacts = record
    OsRead: Boolean;
    Major: UInt32;
    Minor: UInt32;
    Build: UInt32;
    PlatformId: UInt32;
    Revision: UInt32;
    ProductType: Byte;
    Edition: string;
    Process64Bit: Boolean;
    MachineRead: Boolean;
    ProcessMachine: UInt16;
    NativeMachine: UInt16;
    FirmwareRead: Boolean;
    /// <summary>The firmware kind as the OS numbers it: 1 BIOS, 2 UEFI.</summary>
    FirmwareType: UInt32;
    PathRead: Boolean;
    ModulePath: WideString;
    SystemModulePath: WideString;
    /// <summary>The loaded module is the one at SystemModulePath; the gatherer decides, so the
    /// platform's path equivalence stays with it.</summary>
    SystemCopy: Boolean;
    VersionRead: Boolean;
    ModuleMajor: UInt16;
    ModuleMinor: UInt16;
    ModuleBuild: UInt16;
    ModuleRevision: UInt16;
    LegacyFipsPolicy: TLegacyFipsPolicy;
  end;

  /// <summary>
  /// The shipped table of validated Windows modules and the decision over gathered facts. The
  /// status is validated only for a listed release run as a native 64-bit x64 process on UEFI
  /// firmware with the system copy of the module at that release's build; every other
  /// combination is NotValidated and a fact that cannot be read is Unknown. Pure data and logic,
  /// so every platform runs it.
  /// </summary>
  TWindowsModuleDecision = class sealed(TObject)
  strict private
    // the reason of the first fact that contradicts validation, else empty
    class function Mismatch(const AFacts: TWindowsModuleFacts;
      AStandard: TModuleStandard): string; static;
    // the reason of the first fact the decision needs and could not be read, else empty
    class function Unreadable(const AFacts: TWindowsModuleFacts): string; static;
  public
    /// <summary>The shipped validated-module table, matched on the OS build alone.</summary>
    class function Lookup(ABuild: UInt32; out AEntry: TWindowsModuleEntry): Boolean; static;
    /// <summary>The status the facts give for AStandard, and the reason when it is not
    /// Validated.</summary>
    class function Decide(const AFacts: TWindowsModuleFacts; AStandard: TModuleStandard;
      out AReason: string): TModuleStatus; static;
    /// <summary>The name of a firmware kind as the OS numbers it.</summary>
    class function FirmwareName(AType: UInt32): string; static;
  end;

implementation

resourcestring
  SUnreadableBuild = 'the OS build could not be read';
  SNotNtTen = 'the OS is %d.%d (platform %d), not a Windows NT 10.0 release';
  SNoValidatedBuild = 'the shipped table records no validated module for this build';
  SProductTypeNotCovered = 'the OS product type %d is not one the certificate covers for build %d';
  SProcess32Bit = 'the process is 32-bit; the certificate covers the 64-bit module only';
  SProcessEmulated = 'the process runs under WOW64 or x64 emulation (process machine 0x%.4x); ' +
    'the certificate covers a native x64 process';
  SNativeNotX64 = 'the native machine is 0x%.4x, not x64; the certificate covers x64 hardware';
  SFirmwareNotUefi = 'the firmware is %s, not UEFI; the certificate covers UEFI-based x64 ' +
    'computers';
  SModuleNotSystemCopy = 'the loaded module is %s, not the system copy %s';
  SModuleBuildMismatch = 'the module file version is %d.%d.%d.%d, not 10.0.%d';
  SMachineUnreadable = 'the process and machine architectures could not be read';
  SFirmwareUnreadable = 'the firmware kind could not be read';
  SSystemDirectoryUnreadable = 'the system directory could not be read';
  SModulePathUnreadable = 'the path of the loaded module could not be read';
  SModuleVersionUnreadable = 'the file version of the loaded module could not be read';
  SFirmwareBios = 'BIOS';
  SFirmwareUefi = 'UEFI';
  SFirmwareOther = 'type %d';

const
  NtMajor = 10;
  NtMinor = 0;
  NtPlatformId = 2;
  MachineAmd64 = $8664;
  ProductWorkstation = 1;
  ProductDomainController = 2;
  ProductServer = 3;
  FirmwareBios = 1;
  FirmwareUefi = 2;
  ValidatedCertificate = '5410';
  CertificateValidatedOn = '2026-08-31';
  CertificateSunset = '2031-08-30';

{ TWindowsModuleDecision }

class function TWindowsModuleDecision.Lookup(ABuild: UInt32;
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

class function TWindowsModuleDecision.Mismatch(const AFacts: TWindowsModuleFacts;
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
  if AFacts.ProcessMachine <> 0 then
    Exit(Format(SProcessEmulated, [AFacts.ProcessMachine]));
  if AFacts.MachineRead and (AFacts.NativeMachine <> MachineAmd64) then
    Exit(Format(SNativeNotX64, [AFacts.NativeMachine]));
  if AFacts.FirmwareRead and (AFacts.FirmwareType <> FirmwareUefi) then
    Exit(Format(SFirmwareNotUefi, [FirmwareName(AFacts.FirmwareType)]));
  if AFacts.PathRead and (AFacts.SystemModulePath <> '') and not AFacts.SystemCopy then
    Exit(Format(SModuleNotSystemCopy, [string(AFacts.ModulePath),
      string(AFacts.SystemModulePath)]));
  if AFacts.VersionRead and ((AFacts.ModuleMajor <> NtMajor) or
    (AFacts.ModuleMinor <> NtMinor) or (AFacts.ModuleBuild <> AFacts.Build)) then
    Exit(Format(SModuleBuildMismatch, [AFacts.ModuleMajor, AFacts.ModuleMinor,
      AFacts.ModuleBuild, AFacts.ModuleRevision, AFacts.Build]));
end;

class function TWindowsModuleDecision.Unreadable(const AFacts: TWindowsModuleFacts): string;
begin
  Result := '';
  if not AFacts.MachineRead then
    Exit(SMachineUnreadable);
  if not AFacts.FirmwareRead then
    Exit(SFirmwareUnreadable);
  if AFacts.SystemModulePath = '' then
    Exit(SSystemDirectoryUnreadable);
  if not AFacts.PathRead then
    Exit(SModulePathUnreadable);
  if not AFacts.VersionRead then
    Exit(SModuleVersionUnreadable);
end;

class function TWindowsModuleDecision.Decide(const AFacts: TWindowsModuleFacts;
  AStandard: TModuleStandard; out AReason: string): TModuleStatus;
begin
  // a 32-bit process loads the 32-bit module whatever else is known
  if not AFacts.Process64Bit then
  begin
    AReason := SProcess32Bit;
    Exit(TModuleStatus.NotValidated);
  end;
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

class function TWindowsModuleDecision.FirmwareName(AType: UInt32): string;
begin
  case AType of
    FirmwareBios:
      Result := SFirmwareBios;
    FirmwareUefi:
      Result := SFirmwareUefi;
  else
    Result := Format(SFirmwareOther, [AType]);
  end;
end;

end.
