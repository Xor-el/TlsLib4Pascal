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
  /// <summary>The immutable report: Compliant only when a named preset contains the rules and
  /// nothing was found.</summary>
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
  if (FPreset <> '') and (System.Length(FFindings) = 0) then
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
begin
  Result := Format('Verdict: %s (%s)', [TEnumUtilities.GetName<TComplianceVerdict>(Verdict),
    TEnumUtilities.GetName<TComplianceEnforcement>(FEnforcement)]) + sLineBreak;
  if FPreset = '' then
    Result := Result + 'Preset: none' + sLineBreak
  else
    Result := Result + 'Preset: ' + FPreset + sLineBreak;
  Result := Result + Format('Module: %s %s %s %s %s, certificate %s, status %s',
    [FModule.OsName, FModule.OsVersion, FModule.Product, FModule.ModuleName,
    FModule.ModuleFileVersion, FModule.Certificate,
    TEnumUtilities.GetName<TModuleStatus>(FModuleStatus)]);
  for LI := 0 to System.Length(FFindings) - 1 do
    Result := Result + sLineBreak + 'Finding: ' + FFindings[LI].Describe;
  for LI := 0 to System.Length(FDisclosures) - 1 do
    Result := Result + sLineBreak + 'Disclosure: ' + FDisclosures[LI];
end;

end.
