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
  SysUtils,
  TlpIClock,
  TlpISession,
  TlpComplianceTypes,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpINamedGroup,
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
    ['{97F7D0DE-23CC-4FA4-BAC2-C795048A2492}']
    /// <summary>A copy of the rules; the policy itself never changes.</summary>
    function Rules: TComplianceRules;
    function Enforcement: TComplianceEnforcement;
    /// <summary>The refusing crypto provider every admitted config must hold.</summary>
    function Crypto: ICryptoProvider;
    /// <summary>The refusing PKIX provider every admitted config must hold.</summary>
    function Pkix: IPkixProvider;
    function Attestation: IModuleAttestation;
    /// <summary>The groups of the rules, built over Crypto. A config is admitted only with these
    /// group objects; derive a changed set with ToBuilder.</summary>
    function NamedGroups: INamedGroupRegistry;
    /// <summary>The platform findings alone: the module, the backends and the rules.</summary>
    function PlatformReport: IComplianceReport;
    /// <summary>The platform findings plus those of AConfig; never raises for a finding. A
    /// verifier source is judged by its class: the OS source is in the module, the built-in one is
    /// a platform finding, and any other is a configuration finding.</summary>
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
    /// <summary>A fresh 32-byte session scope: the policy's 16-byte prefix and 16 random bytes.
    /// Give it to WithResumptionScope on a server, or on a client that holds a session cache; a
    /// config whose scope lacks the prefix is a ResumptionStateUnchecked finding. A store, cache
    /// or ticket key shared with a config that has another scope never resumes across the two.
    /// Use one value per config, or one shared value for configs that trust identically.</summary>
    function SessionScope: TBytes;
    /// <summary>Default session-ticket keys minted from the policy crypto provider's random
    /// generator, rotating on ALifetimeSeconds, for WithSessionTicketKeys. Only keys the policy
    /// issued, or wrapped with CheckedTicketKeys, are admitted. Raises EArgumentTlsLibException
    /// for a nil AClock.</summary>
    function TicketKeys(const AClock: ITlsClock;
      ALifetimeSeconds: UInt32): ISessionTicketKeyManager;
    /// <summary>AFleet, whose keys the host enters, marked as checked by this policy; the fleet
    /// is still disclosed. Raises EArgumentTlsLibException for a nil AFleet.</summary>
    function CheckedTicketKeys(const AFleet: IFleetTicketKeyManager): ISessionTicketKeyManager;
  end;

implementation

end.
