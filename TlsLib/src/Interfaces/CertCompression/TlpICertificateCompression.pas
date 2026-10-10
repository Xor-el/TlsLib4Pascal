{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpICertificateCompression;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// A certificate-compression algorithm's compress direction (RFC 8879): one
  /// injectable unit per algorithm (zlib ships built in; brotli/zstd or a custom
  /// backend drop in the same way). An endpoint compresses its own Certificate message
  /// body with this, in either role; its input is trusted, so it is not on the
  /// security-sensitive path.
  /// </summary>
  ICertificateCompressor = interface(IInterface)
    ['{B688328F-A66C-4AD6-83C5-642935C4B0E8}']
    /// <summary>The RFC 8879 algorithm codepoint this compresses for.</summary>
    function Algorithm: UInt16;
    /// <summary>Compresses a Certificate message body. False sends it uncompressed: the
    /// algorithm declined it, or the backend failed in a way the implementation caught. A
    /// raised exception is not caught and aborts the handshake. True must yield a non-empty
    /// result. One instance serves every connection of a config, so it is called
    /// concurrently.</summary>
    function TryCompress(const AData: TBytes; out ACompressed: TBytes): Boolean;
  end;

  /// <summary>
  /// A certificate-compression algorithm's decompress direction (RFC 8879), used by
  /// either role. This is the security-sensitive direction, as its input is the
  /// peer's: the implementation bounds output to AMaxLength and returns False rather
  /// than allocate past it, so a decompression bomb cannot exhaust memory. The
  /// declared-length ceiling and ratio guard are applied by the caller before
  /// dispatch, so every algorithm - built in or injected - inherits the same bomb
  /// defense, and the caller maps a False or an exception to the RFC's alert, so an
  /// implementation need know nothing about TLS.
  /// </summary>
  ICertificateDecompressor = interface(IInterface)
    ['{5C23BEBC-EA90-401A-9878-8074CF3ECF58}']
    /// <summary>The RFC 8879 algorithm codepoint this decompresses.</summary>
    function Algorithm: UInt16;
    /// <summary>Decompresses to at most AMaxLength bytes. False when the input cannot be
    /// decompressed: malformed, truncated, followed by trailing bytes, or longer than
    /// AMaxLength once inflated. Called concurrently, like the compressor.</summary>
    function TryDecompress(const ACompressed: TBytes; AMaxLength: Int32;
      out ADecompressed: TBytes): Boolean;
  end;

implementation

end.
