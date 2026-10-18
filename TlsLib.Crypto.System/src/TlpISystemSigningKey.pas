{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISystemSigningKey;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

type
  /// <summary>Marks a signing key whose operations run on the OS module. A platform's key
  /// class lists it beside its own marker, so a backend report can tell native keys from
  /// portable ones without naming the platform.</summary>
  ISystemSigningKey = interface(IInterface)
    ['{5E03E459-EF8C-45B9-908F-2C31631E7BA8}']
  end;

implementation

end.
