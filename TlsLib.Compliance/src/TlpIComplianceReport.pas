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
    ['{E91099AD-1417-4A32-A8F9-141015BF4C89}']
    /// <summary>NotCompliant unless rules within a named preset, a validated module and no
    /// finding hold; then PrimitivesInModule while a key-schedule derivation runs outside the
    /// module, else Compliant.</summary>
    function Verdict: TComplianceVerdict;
    function Enforcement: TComplianceEnforcement;
    /// <summary>The named preset the rules equal, or 'within' and the tightest one they fit;
    /// empty when none does.</summary>
    function Preset: string;
    /// <summary>Whether every key-schedule derivation the evaluated rules or config can run is a
    /// module service. A TLS 1.2 exporter derivation is not one; it is disclosed.</summary>
    function KeyDerivationInModule: Boolean;
    function Module: TModuleIdentity;
    function ModuleStatus: TModuleStatus;
    function Findings: TArray<TComplianceFinding>;
    /// <summary>Facts that do not change the verdict but bound the claim.</summary>
    function Disclosures: TArray<string>;
    function Describe: string;
  end;

implementation

end.
