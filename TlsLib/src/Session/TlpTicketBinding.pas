{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTicketBinding;

{$I ..\Include\TlsLib.inc}

interface

type
  /// <summary>
  /// Which kind of engine minted a TLS 1.3 session. A ticket resumes only on the kind that minted
  /// it, so settings one kind attaches to a ticket never reach another. HandshakeEngine is an
  /// engine whose host owns record protection.
  /// </summary>
  TTicketBinding = (RecordEngine, HandshakeEngine);

implementation

end.
