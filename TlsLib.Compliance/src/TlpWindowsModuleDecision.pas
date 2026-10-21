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
  TlpArrayUtilities,
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
    /// <summary>The sunset date as yyyymmdd (0 when none); Historical after it.</summary>
    SunsetDay: UInt32;
    /// <summary>The OS product types the certificate was issued for.</summary>
    ProductTypes: set of Byte;
    /// <summary>The module file version the certificate lists.</summary>
    ListedVersion: string;
    /// <summary>The OS editions the Security Policy lists for the release, as the OS names them
    /// (EditionID), each between bars; empty when none is listed.</summary>
    Editions: string;
  end;

  /// <summary>How an OS edition stands against the editions the Security Policy lists for its
  /// release.</summary>
  TEditionCoverage = (NoTestedList, Tested, Untested, Unread);

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
    /// <summary>Whether the loaded bcrypt.dll was identified, and whether it is the system
    /// copy.</summary>
    BcryptRead: Boolean;
    BcryptSystemCopy: Boolean;
    /// <summary>The same for the loaded ncrypt.dll.</summary>
    NcryptRead: Boolean;
    NcryptSystemCopy: Boolean;
    VersionRead: Boolean;
    ModuleMajor: UInt16;
    ModuleMinor: UInt16;
    ModuleBuild: UInt16;
    ModuleRevision: UInt16;
    /// <summary>The current UTC date as yyyymmdd; 0 when it could not be read.</summary>
    Today: UInt32;
    LegacyFipsPolicy: TLegacyFipsPolicy;
  end;

  /// <summary>
  /// The shipped table of validated Windows modules and the decision over gathered facts. The
  /// status is validated only for a listed release run as a native 64-bit x64 process on UEFI
  /// firmware with the system copy of the module at that release's build, on or before the
  /// sunset date of the certificate and Historical after it; every other combination is
  /// NotValidated and a fact that cannot be read is Unknown. Pure data and logic, so every
  /// platform runs it.
  /// </summary>
  TWindowsModuleDecision = class sealed(TObject)
  public
  const
    BcryptName = 'bcrypt.dll';
    NcryptName = 'ncrypt.dll';
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
    /// <summary>Whether AEdition, as the OS names it, is one the Security Policy lists for
    /// ABuild's release; Unread for an empty AEdition and NoTestedList where the release lists
    /// none. Never decides the status.</summary>
    class function EditionCoverage(ABuild: UInt32; const AEdition: string): TEditionCoverage;
      static;
    /// <summary>What a Validated status leaves to the vendor: an edition outside the tested
    /// list and hardware the Security Policy did not test. None for any other status.</summary>
    class function Disclosures(ABuild: UInt32; const AEdition: string;
      AStatus: TModuleStatus): TArray<string>; static;
  end;

implementation

resourcestring
  SUnreadableBuild = 'the OS build could not be read';
  SNotNtTen = 'the OS is %d.%d (platform %d), not a Windows NT 10.0 release';
  SNoValidatedBuild = 'the shipped table records no validated module for this build';
  SProductTypeNotCovered = 'the OS product type %d is not one the certificate covers for build %d';
  SProcess32Bit = 'the process is 32-bit; the policy covers the 64-bit module only, and the ' +
    'tested environments are 64-bit';
  SProcessEmulated = 'the process runs under WOW64 (process machine 0x%.4x); ' +
    'the certificate covers a native x64 process';
  SImportNotSystemCopy = 'the loaded %s is not the system copy';
  SImportsUnreadable = 'the identity of the loaded %s could not be read';
  SBothImports = '%s and %s';
  SNativeNotX64 = 'the native machine is 0x%.4x, not x64; the certificate covers x64 hardware';
  SFirmwareNotUefi = 'the firmware is %s, not UEFI; the certificate covers UEFI-based x64 ' +
    'computers';
  SModuleNotSystemCopy = 'the loaded module is %s, not the system copy %s';
  SModuleBuildMismatch = 'the module file version is %d.%d.%d.%d, not 10.0.%d';
  SMachineUnreadable = 'the process and machine architectures could not be read';
  SFirmwareUnreadable = 'the firmware kind could not be read';
  SSystemDirectoryUnreadable = 'the system directory could not be read';
  SModulePathUnreadable = 'the path of the loaded module could not be read';
  SDateUnreadable = 'the current date could not be read';
  SSunsetPassed = 'certificate %s passed its sunset date %s and is historical';
  SModuleVersionUnreadable = 'the file version of the loaded module could not be read';
  SFirmwareBios = 'BIOS';
  SFirmwareUefi = 'UEFI';
  SFirmwareOther = 'type %d';
  SHardwareVendorAffirmed = 'the hardware and any hypervisor are not checked against the ' +
    'tested platforms; on any other platform coverage is vendor-affirmed, with no assurance of ' +
    'the minimum strength of generated keys';
  SEditionUntested = 'edition %s is outside the tested list; coverage is vendor-affirmed';
  SEditionUnread = 'the edition could not be read; coverage is vendor-affirmed for any edition ' +
    'outside the tested list';

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
  EditionSeparator = '|';
  ValidatedCertificate = '5410';
  CertificateValidatedOn = '2026-08-31';
  CertificateSunset = '2031-08-30';
  CertificateSunsetDay = UInt32(20310830);

{ TWindowsModuleDecision }

class function TWindowsModuleDecision.Lookup(ABuild: UInt32;
  out AEntry: TWindowsModuleEntry): Boolean;
const
  Table: array [0 .. 8] of TWindowsModuleEntry = (
    (Build: 22621; Product: 'Windows 11 22H2'; Certificate: ValidatedCertificate;
    Validated: True; Standard: TModuleStandard.Fips140_3; Level: 1;
    ValidatedOn: CertificateValidatedOn; Sunset: CertificateSunset;
    SunsetDay: CertificateSunsetDay;
    ProductTypes: [ProductWorkstation]; ListedVersion: '10.0.22621.30001';
    Editions: '|Core|Professional|Enterprise|IoTEnterprise|Education|'),
    (Build: 20348; Product: 'Windows Server 2022'; Certificate: ValidatedCertificate;
    Validated: True; Standard: TModuleStandard.Fips140_3; Level: 1;
    ValidatedOn: CertificateValidatedOn; Sunset: CertificateSunset;
    SunsetDay: CertificateSunsetDay;
    ProductTypes: [ProductDomainController, ProductServer]; ListedVersion: '10.0.20348.30000';
    Editions: '|ServerStandard|ServerDatacenter|'),
    (Build: 22631; Product: 'Windows 11 23H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''; SunsetDay: 0;
    ProductTypes: []; ListedVersion: ''; Editions: ''),
    (Build: 26100; Product: 'Windows 11 24H2 / Server 2025'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''; SunsetDay: 0;
    ProductTypes: []; ListedVersion: ''; Editions: ''),
    (Build: 26200; Product: 'Windows 11 25H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''; SunsetDay: 0;
    ProductTypes: []; ListedVersion: ''; Editions: ''),
    (Build: 19045; Product: 'Windows 10 22H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''; SunsetDay: 0;
    ProductTypes: []; ListedVersion: ''; Editions: ''),
    (Build: 19044; Product: 'Windows 10 21H2'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''; SunsetDay: 0;
    ProductTypes: []; ListedVersion: ''; Editions: ''),
    (Build: 17763; Product: 'Windows 10 1809 / Server 2019'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''; SunsetDay: 0;
    ProductTypes: []; ListedVersion: ''; Editions: ''),
    (Build: 14393; Product: 'Windows 10 1607 / Server 2016'; Certificate: ''; Validated: False;
    Standard: TModuleStandard.Fips140_3; Level: 0; ValidatedOn: ''; Sunset: ''; SunsetDay: 0;
    ProductTypes: []; ListedVersion: ''; Editions: ''));
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
  // the native machine is named first, whatever the process reports
  if AFacts.MachineRead and (AFacts.NativeMachine <> MachineAmd64) then
    Exit(Format(SNativeNotX64, [AFacts.NativeMachine]));
  if AFacts.ProcessMachine <> 0 then
    Exit(Format(SProcessEmulated, [AFacts.ProcessMachine]));
  if AFacts.FirmwareRead and (AFacts.FirmwareType <> FirmwareUefi) then
    Exit(Format(SFirmwareNotUefi, [FirmwareName(AFacts.FirmwareType)]));
  if AFacts.PathRead and (AFacts.SystemModulePath <> '') and not AFacts.SystemCopy then
    Exit(Format(SModuleNotSystemCopy, [string(AFacts.ModulePath),
      string(AFacts.SystemModulePath)]));
  if AFacts.BcryptRead and not AFacts.BcryptSystemCopy then
    Exit(Format(SImportNotSystemCopy, [BcryptName]));
  if AFacts.NcryptRead and not AFacts.NcryptSystemCopy then
    Exit(Format(SImportNotSystemCopy, [NcryptName]));
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
  if not AFacts.BcryptRead and not AFacts.NcryptRead then
    Exit(Format(SImportsUnreadable, [Format(SBothImports, [BcryptName, NcryptName])]));
  if not AFacts.BcryptRead then
    Exit(Format(SImportsUnreadable, [BcryptName]));
  if not AFacts.NcryptRead then
    Exit(Format(SImportsUnreadable, [NcryptName]));
  if AFacts.Today = 0 then
    Exit(SDateUnreadable);
end;

class function TWindowsModuleDecision.Decide(const AFacts: TWindowsModuleFacts;
  AStandard: TModuleStandard; out AReason: string): TModuleStatus;
var
  LEntry: TWindowsModuleEntry;
  LListed: Boolean;
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
  LListed := Lookup(AFacts.Build, LEntry);
  if LListed and (LEntry.SunsetDay <> 0) and (AFacts.Today > LEntry.SunsetDay) then
  begin
    AReason := Format(SSunsetPassed, [LEntry.Certificate, LEntry.Sunset]);
    Exit(TModuleStatus.Historical);
  end;
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

class function TWindowsModuleDecision.EditionCoverage(ABuild: UInt32;
  const AEdition: string): TEditionCoverage;
var
  LEntry: TWindowsModuleEntry;
  LListed: Boolean;
begin
  LListed := Lookup(ABuild, LEntry);
  if not LListed or (LEntry.Editions = '') then
    Exit(TEditionCoverage.NoTestedList);
  if AEdition = '' then
    Exit(TEditionCoverage.Unread);
  // a name holding the separator could match across two listed editions
  if (Pos(EditionSeparator, AEdition) = 0) and
    (Pos(EditionSeparator + AEdition + EditionSeparator, LEntry.Editions) > 0) then
    Result := TEditionCoverage.Tested
  else
    Result := TEditionCoverage.Untested;
end;

class function TWindowsModuleDecision.Disclosures(ABuild: UInt32; const AEdition: string;
  AStatus: TModuleStatus): TArray<string>;
begin
  Result := nil;
  if AStatus <> TModuleStatus.Validated then
    Exit;
  // the edition never decides, but coverage beyond the tested list rests on the vendor
  case EditionCoverage(ABuild, AEdition) of
    TEditionCoverage.Untested:
      TArrayUtilities.Append<string>(Result, Format(SEditionUntested, [AEdition]));
    TEditionCoverage.Unread:
      TArrayUtilities.Append<string>(Result, SEditionUnread);
  end;
  TArrayUtilities.Append<string>(Result, SHardwareVendorAffirmed);
end;

end.
