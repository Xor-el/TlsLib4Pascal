{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeStage;

{$I ..\Include\TlsLib.inc}

interface

type
  /// <summary>
  /// The coarse, role- and version-neutral stage of a handshake machine, distinct from each
  /// machine's fine-grained private phase. Handshaking is the default running state;
  /// ParkedForVerdict means the machine is suspended awaiting an out-of-band peer-certificate
  /// verdict (the async-verdict seam) and must not advance keying material or the exporter;
  /// Connected means the handshake has established (its HandshakeEstablished was emitted).
  /// The engine and conductor read this instead of scanning effects or proxy flags.
  /// </summary>
  THandshakeStage = (Handshaking, ParkedForVerdict, Connected);

implementation

end.
