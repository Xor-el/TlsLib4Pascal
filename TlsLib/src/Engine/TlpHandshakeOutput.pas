{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeOutput;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpIKeySchedule;

type
  /// <summary>What a handshake-only engine hands its host next: handshake bytes to send at a
  /// level, a traffic secret to install for reading or for writing at a level, or the end of
  /// the handshake.</summary>
  THandshakeOutputKind = (HandshakeData, ReadSecret, WriteSecret, HandshakeComplete);

  /// <summary>
  /// One item of a handshake-only engine's output queue. Level names the encryption level the
  /// item belongs to; Data carries the bytes of a HandshakeData item, Secret the secret of a
  /// ReadSecret or WriteSecret item (the host owns it from the moment it takes it).
  /// </summary>
  THandshakeOutput = record
    Kind: THandshakeOutputKind;
    Level: TTlsEpoch;
    Data: TBytes;
    Secret: ITrafficSecret;
  end;

implementation

end.
