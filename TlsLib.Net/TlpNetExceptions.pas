{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpNetExceptions;

{$I ..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsLibExceptions;

type
  /// <summary>A TCP socket operation failed.</summary>
  ENetSocketError = class(EBaseTlsLibException);

  /// <summary>A connection could not be made: the name did not resolve, the peer refused, or the
  /// connect timeout elapsed.</summary>
  ENetConnectError = class(ENetSocketError);

  /// <summary>A bounded receive saw no byte within its timeout.</summary>
  ENetReceiveTimeout = class(ENetSocketError);

implementation

end.
