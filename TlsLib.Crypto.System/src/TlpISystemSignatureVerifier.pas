{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISystemSignatureVerifier;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

type
  /// <summary>Marks a signature verifier whose operations run on the OS module. A platform's
  /// verifier class lists it, so a caller can tell a native verifier from the portable one the
  /// facet falls back to for a key the module cannot import, without naming the platform. Any
  /// class can list it, so it is not authoritative on its own: a platform report confirms the
  /// verifier's class.
  /// </summary>
  ISystemSignatureVerifier = interface(IInterface)
    ['{B7A3C1D4-6E52-4F08-9A1B-3D84E0F2C617}']
  end;

implementation

end.
