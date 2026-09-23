{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsTransport;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// The minimal blocking raw-byte conduit the stream pump drives the sans-IO
  /// engine over: it moves ciphertext (and the handshake flights) to and from the peer.
  /// A generic Read + Write transport - each host integration adapts its own socket to this
  /// seam, and the pump stays transport-agnostic.
  /// Blocking: Read waits for at least one byte; there is no non-blocking / poll variant on
  /// this seam.
  /// </summary>
  ITlsTransport = interface(IInterface)
    ['{1B7E9C42-3D06-4A58-9F21-6C0E5B4D82A7}']
    /// <summary>Reads up to AMaxLength bytes into ABuffer at AOffset, blocking until at
    /// least one byte is available. Returns the count read, or 0 on an orderly peer close
    /// (transport EOF). Raises on a transport error.</summary>
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    /// <summary>Writes ALength bytes from ABuffer at AOffset, blocking until all have been
    /// handed to the transport. Raises on a transport error.</summary>
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

implementation

end.
