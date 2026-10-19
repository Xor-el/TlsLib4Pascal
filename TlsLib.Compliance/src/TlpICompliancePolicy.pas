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
  TlpITlsCredentialResolver,
  TlpTlsCredential,
  TlpIComplianceReport,
  TlpIModuleAttestation;

type
  /// <summary>
  /// An immutable compliance policy: the rules, the refusing providers every admitted config must
  /// hold, and the verdicts over a platform and a config. Evaluate reports; Admit reports and then
  /// raises for what the enforcement mode does not tolerate.
  /// </summary>
  ICompliancePolicy = interface(IInterface)
    ['{371DAE23-8791-4A91-978B-24F7E0AFA042}']
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
    /// <summary>The platform findings plus those of one credential as given: its key against the
    /// strength floors and exact RSA sizes, its schemes against the rules, and its key's backend.
    /// The checked resolver judges a credential after narrowing its key to the schemes of the
    /// rules, so a key with extra schemes is a finding here and admitted there. Never raises; a
    /// certificate that cannot be read is reported as a finding.</summary>
    function EvaluateCredential(const ACredential: TTlsCredential): IComplianceReport;
    /// <summary>A resolver that asks AInner and then refuses, by returning False, every credential
    /// the enforcement mode does not tolerate (as Admit does), narrowing the key it admits to the
    /// schemes of the rules. A server config holding it needs no CredentialResolverUnchecked
    /// finding. It reads the chosen credential's certificate on every handshake, so it is for a
    /// host that picks credentials at run time. A refusal reaches the client as unrecognized_name
    /// (SNI) or handshake_failure and the host gets no reason: run EvaluateCredential over the
    /// credentials at startup. Raises EArgumentTlsLibException for a nil AInner.</summary>
    function CheckedCredentialResolver(
      const AInner: ITlsServerCredentialResolver): ITlsServerCredentialResolver;
  end;

implementation

end.
