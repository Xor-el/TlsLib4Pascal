{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIComplianceReport;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpComplianceTypes;

type
  /// <summary>The immutable outcome of a compliance evaluation.</summary>
  IComplianceReport = interface(IInterface)
    ['{E3BA3D8A-845F-43B9-B429-11B28973E7D2}']
    /// <summary>Compliant only for a named preset, a validated module and no finding.</summary>
    function Verdict: TComplianceVerdict;
    function Enforcement: TComplianceEnforcement;
    /// <summary>The tightest named preset the rules fit, or empty when none does.</summary>
    function Preset: string;
    function Module: TModuleIdentity;
    function ModuleStatus: TModuleStatus;
    function Findings: TArray<TComplianceFinding>;
    /// <summary>Facts that do not change the verdict but bound the claim.</summary>
    function Disclosures: TArray<string>;
    function Describe: string;
  end;

implementation

end.
