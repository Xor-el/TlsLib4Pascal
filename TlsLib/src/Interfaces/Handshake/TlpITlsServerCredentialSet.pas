{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsServerCredentialSet;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpTlsCredential;

type
  /// <summary>
  /// A server credential resolver that can enumerate what it may select. A resolver that cannot
  /// list its credentials (one that builds them per handshake) does not implement this.
  /// </summary>
  ITlsServerCredentialSet = interface(IInterface)
    ['{CF098290-4B3D-43D7-ABEA-978523360FAB}']
    /// <summary>Every credential the resolver can return, default first.</summary>
    function Credentials: TArray<TTlsCredential>;
  end;

implementation

end.
