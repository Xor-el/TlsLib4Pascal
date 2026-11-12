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
  SysUtils,
  TlpIClock;

type
  /// <summary>
  /// The minimal blocking raw-byte conduit the stream pump drives the sans-IO
  /// engine over: it moves ciphertext (and the handshake flights) to and from the peer.
  /// A generic Read + Write transport - each host integration adapts its own socket to this
  /// seam, and the pump stays transport-agnostic.
  /// Blocking: Read waits for at least one byte; there is no non-blocking / poll variant on
  /// this seam. One Read may run concurrently with one Write, so the two must not share
  /// unsynchronised state. A transport that is not an ITlsTimedTransport cannot bound a send, so a
  /// closing send on it can wait for ever on a peer that does not read.
  /// </summary>
  ITlsTransport = interface(IInterface)
    ['{1B7E9C42-3D06-4A58-9F21-6C0E5B4D82A7}']
    /// <summary>Reads up to AMaxLength bytes into ABuffer at AOffset, blocking until at
    /// least one byte is available. Returns the count read, or 0 on an orderly peer close
    /// (transport EOF). Raises on a transport error.</summary>
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    /// <summary>Writes ALength bytes from ABuffer at AOffset, blocking until all have been
    /// handed to the transport, or raises. A raise may follow a partial write, so the connection
    /// is unusable afterwards: the caller must not retry.</summary>
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>
  /// An ITlsTransport whose reads and writes a connection can bound: it arms a deadline for the
  /// handshake, for one application read, or for a send, and an operation past it raises instead of
  /// blocking.
  /// </summary>
  ITlsTimedTransport = interface(ITlsTransport)
    ['{86703A08-58FD-482B-80FC-2E596B4E4162}']
    /// <summary>Measures the deadlines on AClock (required; nil raises). Call it before
    /// SetReadTimeout or SetWriteTimeout: it clears any armed cap or deadline.</summary>
    procedure UseClock(const AClock: ITlsMonotonicClock);
    /// <summary>Bounds the reads that follow to AMs ms in total, as a deadline from this call
    /// (0 = block); a read past it raises ETlsHandshakeTimeout.</summary>
    procedure SetReadTimeout(AMs: Int32);
    /// <summary>As SetReadTimeout, for an application read: a read past the deadline raises the
    /// retryable ETlsReadTimeout.</summary>
    procedure SetApplicationReadTimeout(AMs: Int32);
    /// <summary>Bounds the writes that follow to AMs ms in total, as a deadline from this call
    /// (AMs &lt;= 0 clears it, the default); a write past it raises ETlsWriteTimeout, possibly
    /// after part of the data was sent, so the connection is unusable afterwards. Not
    /// thread-safe: call it only while holding the send side, and clear it before releasing it.</summary>
    procedure SetWriteTimeout(AMs: Int32);
  end;

implementation

end.
