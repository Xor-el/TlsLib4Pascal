{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls13HandshakeOutput;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpIKeySchedule;

type
  /// <summary>What a TLS 1.3 handshake-only engine hands its host next: handshake bytes to send at a
  /// level, a traffic secret to install for reading or for writing at a level, or the end of
  /// the handshake.</summary>
  TTls13HandshakeOutputKind = (HandshakeData, ReadSecret, WriteSecret, HandshakeComplete);

  /// <summary>
  /// One item of a TLS 1.3 handshake-only engine's output queue. Level names the encryption level the
  /// item belongs to; Data carries the bytes of a HandshakeData item, Secret the secret of a
  /// ReadSecret or WriteSecret item (the host owns it from the moment it takes it).
  /// </summary>
  TTls13HandshakeOutput = record
    Kind: TTls13HandshakeOutputKind;
    Level: TTlsEpoch;
    Data: TBytes;
    Secret: ITrafficSecret;
  end;

implementation

end.
