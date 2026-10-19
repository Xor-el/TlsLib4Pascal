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
  TlpICompliancePolicy;

type
  /// <summary>
  /// Marks a credential resolver that checks every credential it selects against a compliance
  /// policy, so that policy need not report it as unchecked. A resolver of another policy is not
  /// trusted.
  /// </summary>
  IComplianceCredentialResolver = interface(IInterface)
    ['{2B3587AF-0705-4395-B8B4-D9A747CA8F22}']
    /// <summary>The policy the resolver checks against.</summary>
    function Policy: ICompliancePolicy;
  end;

implementation

end.
