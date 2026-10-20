{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIComplianceTicketKeys;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpICompliancePolicy;

type
  /// <summary>
  /// Marks session-ticket keys issued or checked by a compliance policy. The policy trusts only
  /// its own wrapper classes, not this interface, which any class can list, so keys of another
  /// policy or of the host are reported as unchecked.
  /// </summary>
  IComplianceTicketKeys = interface(IInterface)
    ['{C06E45CC-C73F-4589-ABB9-2B88AD030CFB}']
    /// <summary>The policy that issued or checked the keys.</summary>
    function Policy: ICompliancePolicy;
    /// <summary>The rotation lifetime the keys were minted for; 0 for host-entered keys.</summary>
    function LifetimeSeconds: UInt32;
    /// <summary>The resumption scope the host entered for a fleet; empty for keys the policy
    /// minted.</summary>
    function FleetScope: TBytes;
  end;

implementation

end.
