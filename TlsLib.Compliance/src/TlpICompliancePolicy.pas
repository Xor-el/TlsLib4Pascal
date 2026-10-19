{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpICompliancePolicy;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpComplianceTypes,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpITlsConfig,
  TlpIComplianceReport,
  TlpIModuleAttestation;

type
  /// <summary>
  /// An immutable compliance policy: the rules, the refusing providers every admitted config must
  /// hold, and the verdicts over a platform and a config. Evaluate reports; Admit reports and then
  /// raises for what the enforcement mode does not tolerate.
  /// </summary>
  ICompliancePolicy = interface(IInterface)
    ['{7F7447FD-5BBF-4BAA-8E89-2B2456AAFAB4}']
    /// <summary>A copy of the rules; the policy itself never changes.</summary>
    function Rules: TComplianceRules;
    function Enforcement: TComplianceEnforcement;
    /// <summary>The refusing crypto provider every admitted config must hold.</summary>
    function Crypto: ICryptoProvider;
    /// <summary>The refusing PKIX provider every admitted config must hold.</summary>
    function Pkix: IPkixProvider;
    function Attestation: IModuleAttestation;
    /// <summary>The platform findings alone: the module, the backends and the rules.</summary>
    function PlatformReport: IComplianceReport;
    /// <summary>The platform findings plus those of AConfig; never raises for a finding.</summary>
    function Evaluate(const AConfig: ITlsClientConfig): IComplianceReport; overload;
    function Evaluate(const AConfig: ITlsServerConfig): IComplianceReport; overload;
    /// <summary>Evaluates AConfig and raises EComplianceUnmetTlsLibException for any finding in
    /// strict mode, or for a configuration finding in relaxed mode; otherwise returns the
    /// report.</summary>
    function Admit(const AConfig: ITlsClientConfig): IComplianceReport; overload;
    function Admit(const AConfig: ITlsServerConfig): IComplianceReport; overload;
  end;

implementation

end.
