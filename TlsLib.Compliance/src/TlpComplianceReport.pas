{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceReport;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpComplianceTypes,
  TlpIComplianceReport,
  TlpEnumUtilities;

type
  /// <summary>The immutable report: Compliant only when a named preset contains the rules, the
  /// module is validated and nothing was found.</summary>
  TComplianceReport = class sealed(TInterfacedObject, IComplianceReport)
  strict private
  var
    FEnforcement: TComplianceEnforcement;
    FPreset: string;
    FModule: TModuleIdentity;
    FModuleStatus: TModuleStatus;
    FFindings: TArray<TComplianceFinding>;
    FDisclosures: TArray<string>;
  public
    constructor Create(AEnforcement: TComplianceEnforcement; const APreset: string;
      const AModule: TModuleIdentity; AModuleStatus: TModuleStatus;
      const AFindings: TArray<TComplianceFinding>; const ADisclosures: TArray<string>);
    function Verdict: TComplianceVerdict;
    function Enforcement: TComplianceEnforcement;
    function Preset: string;
    function Module: TModuleIdentity;
    function ModuleStatus: TModuleStatus;
    function Findings: TArray<TComplianceFinding>;
    function Disclosures: TArray<string>;
    function Describe: string;
  end;

implementation

resourcestring
  SVerdictLine = 'Verdict: %s (%s)';
  SPresetLine = 'Preset: %s';
  SNoPreset = 'none';
  SFindingPrefix = 'Finding: ';
  SDisclosurePrefix = 'Disclosure: ';
  SUnknownModule = 'unknown module';
  SModulePrefix = 'Module: ';
  SCertificatePart = ', certificate %s';
  SStatusPart = ', status %s';

{ TComplianceReport }

constructor TComplianceReport.Create(AEnforcement: TComplianceEnforcement;
  const APreset: string; const AModule: TModuleIdentity; AModuleStatus: TModuleStatus;
  const AFindings: TArray<TComplianceFinding>; const ADisclosures: TArray<string>);
begin
  inherited Create;
  FEnforcement := AEnforcement;
  FPreset := APreset;
  FModule := AModule;
  FModuleStatus := AModuleStatus;
  FFindings := System.Copy(AFindings);
  FDisclosures := System.Copy(ADisclosures);
end;

function TComplianceReport.Verdict: TComplianceVerdict;
begin
  if (FPreset <> '') and (FModuleStatus = TModuleStatus.Validated) and
    (System.Length(FFindings) = 0) then
    Result := TComplianceVerdict.Compliant
  else
    Result := TComplianceVerdict.NotCompliant;
end;

function TComplianceReport.Enforcement: TComplianceEnforcement;
begin
  Result := FEnforcement;
end;

function TComplianceReport.Preset: string;
begin
  Result := FPreset;
end;

function TComplianceReport.Module: TModuleIdentity;
begin
  Result := FModule;
end;

function TComplianceReport.ModuleStatus: TModuleStatus;
begin
  Result := FModuleStatus;
end;

function TComplianceReport.Findings: TArray<TComplianceFinding>;
begin
  Result := System.Copy(FFindings);
end;

function TComplianceReport.Disclosures: TArray<string>;
begin
  Result := System.Copy(FDisclosures);
end;

function TComplianceReport.Describe: string;
var
  LI: Int32;
  LModule: string;
begin
  Result := Format(SVerdictLine, [TEnumUtilities.GetName<TComplianceVerdict>(Verdict),
    TEnumUtilities.GetName<TComplianceEnforcement>(FEnforcement)]) + sLineBreak;
  if FPreset = '' then
    Result := Result + Format(SPresetLine, [SNoPreset]) + sLineBreak
  else
    Result := Result + Format(SPresetLine, [FPreset]) + sLineBreak;
  LModule := FModule.Describe;
  if LModule = '' then
    LModule := SUnknownModule;
  Result := Result + SModulePrefix + LModule;
  if FModule.Certificate <> '' then
    Result := Result + Format(SCertificatePart, [FModule.Certificate]);
  Result := Result + Format(SStatusPart,
    [TEnumUtilities.GetName<TModuleStatus>(FModuleStatus)]);
  for LI := 0 to System.Length(FFindings) - 1 do
    Result := Result + sLineBreak + SFindingPrefix + FFindings[LI].Describe;
  for LI := 0 to System.Length(FDisclosures) - 1 do
    Result := Result + sLineBreak + SDisclosurePrefix + FDisclosures[LI];
end;

end.
