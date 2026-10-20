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
  /// <summary>Informational: marks a signature verifier whose operations run on the OS module. A
  /// platform's verifier class lists it. Any class can list it, so nothing decides on it: a
  /// backend report judges the verifier's class instead.
  /// </summary>
  ISystemSignatureVerifier = interface(IInterface)
    ['{D6258B91-347C-454D-9CF6-1831CB44C90D}']
  end;

implementation

end.
