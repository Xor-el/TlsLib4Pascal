{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISystemVerifierSource;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

type
  /// <summary>Marks a certificate verifier source that validates chains through the OS delegate
  /// rather than the portable verifier. The source class lists it, so a config check can tell the
  /// two apart without naming the platform.</summary>
  ISystemVerifierSource = interface(IInterface)
    ['{D2F6A8B1-3C47-4E95-8B0A-61E9C7A4F358}']
  end;

implementation

end.
