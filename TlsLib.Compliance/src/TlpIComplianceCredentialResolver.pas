{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIComplianceCredentialResolver;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpITlsCredentialResolver,
  TlpICompliancePolicy;

type
  /// <summary>
  /// Marks a credential resolver that checks every credential it selects against a compliance
  /// policy, so that policy need not report it as unchecked. A resolver of another policy is not
  /// trusted.
  /// </summary>
  IComplianceCredentialResolver = interface(IInterface)
    ['{9FB03C9D-4BA1-4F21-AF5F-8D95B0CE5DB7}']
    /// <summary>The policy the resolver checks against.</summary>
    function Policy: ICompliancePolicy;
    /// <summary>The resolver being checked, so a policy can list its credentials.</summary>
    function Inner: ITlsServerCredentialResolver;
  end;

implementation

end.
