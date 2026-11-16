{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpZlibCertificateCompression;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  paszlib,
{$ELSE}
  System.ZLib,
{$ENDIF FPC}
  TlpCertificateCompression,
  TlpICertificateCompression;

type
  /// <summary>The built-in zlib (RFC 1950) compressor, over the runtime's deflate.</summary>
  TZlibCertificateCompressor = class sealed(TInterfacedObject, ICertificateCompressor)
  public
    function Algorithm: UInt16;
    function TryCompress(const AData: TBytes; out ACompressed: TBytes): Boolean;
  end;

  /// <summary>
  /// The built-in zlib decompressor: inflates bounded to AMaxLength and refuses to
  /// produce more, so a bomb cannot exhaust memory here (the declared-length ceiling
  /// and ratio guard are applied by TCertificateCompression before dispatch).
  /// </summary>
  TZlibCertificateDecompressor = class sealed(TInterfacedObject, ICertificateDecompressor)
  public
    function Algorithm: UInt16;
    function TryDecompress(const ACompressed: TBytes; AMaxLength: Int32;
      out ADecompressed: TBytes): Boolean;
  end;

  /// <summary>
  /// The built-in zlib backend, packaged as the ready-made compressor/decompressor
  /// sets an endpoint uses out of the box. An application that wants another algorithm
  /// implements ICertificateCompressor/ICertificateDecompressor and registers it with
  /// the config builder, optionally alongside these (see WithCertificateCompressors).
  /// </summary>
  TZlibCertificateCompression = class sealed(TObject)
  public
    /// <summary>The zlib compressor set, for a sender.</summary>
    class function DefaultCompressors: TArray<ICertificateCompressor>; static;
    /// <summary>The zlib decompressor set, for a receiver.</summary>
    class function DefaultDecompressors: TArray<ICertificateDecompressor>; static;
  end;

implementation

type
  TZlibStream = {$IFDEF FPC}TZStream{$ELSE}z_stream{$ENDIF};

{ TZlibCertificateCompressor }

function TZlibCertificateCompressor.Algorithm: UInt16;
begin
  Result := TCertificateCompressionAlgorithms.Zlib;
end;

function TZlibCertificateCompressor.TryCompress(const AData: TBytes;
  out ACompressed: TBytes): Boolean;
const
  ChunkBytes = Int32(4096);
var
  LStrm: TZlibStream;
  LStatus, LProduced: Int32;
begin
  ACompressed := nil;
  Result := False;
  FillChar(LStrm, SizeOf(LStrm), 0);
  if deflateInit(LStrm, Z_DEFAULT_COMPRESSION) <> Z_OK then
    Exit;
  try
    if System.Length(AData) > 0 then
      LStrm.next_in := @AData[0];
    LStrm.avail_in := System.Length(AData);
    LProduced := 0;
    repeat
      SetLength(ACompressed, LProduced + ChunkBytes);
      LStrm.next_out := @ACompressed[LProduced];
      LStrm.avail_out := ChunkBytes;
      LStatus := deflate(LStrm, Z_FINISH);
      // Z_OK asks for more room; anything but that or the stream end is a failed compression
      if (LStatus <> Z_OK) and (LStatus <> Z_STREAM_END) then
      begin
        ACompressed := nil;
        Exit;
      end;
      Inc(LProduced, ChunkBytes - Int32(LStrm.avail_out));
    until LStatus = Z_STREAM_END;
    SetLength(ACompressed, LProduced);
    Result := True;
  finally
    deflateEnd(LStrm);
  end;
end;

{ TZlibCertificateDecompressor }

function TZlibCertificateDecompressor.Algorithm: UInt16;
begin
  Result := TCertificateCompressionAlgorithms.Zlib;
end;

function TZlibCertificateDecompressor.TryDecompress(const ACompressed: TBytes;
  AMaxLength: Int32; out ADecompressed: TBytes): Boolean;
var
  LStrm: TZlibStream;
  LChunk: TBytes;
  LStatus, LProduced, LOut: Int32;
begin
  // raw inflate rather than the stream wrapper: the wrapper buffers ahead and never notices
  // input past the deflate stream, but a CompressedCertificate body is exactly one zlib stream
  // (RFC 8879), so trailing bytes must be rejected - the leftover avail_in below catches them
  ADecompressed := nil;
  Result := False;
  if (System.Length(ACompressed) = 0) or (AMaxLength <= 0) then
    Exit;
  FillChar(LStrm, SizeOf(LStrm), 0);
  if inflateInit(LStrm) <> Z_OK then
    Exit;
  try
    SetLength(ADecompressed, AMaxLength);
    SetLength(LChunk, 4096);
    LStrm.next_in := @ACompressed[0];
    LStrm.avail_in := System.Length(ACompressed);
    LProduced := 0;
    repeat
      LStrm.next_out := @LChunk[0];
      LStrm.avail_out := System.Length(LChunk);
      LStatus := inflate(LStrm, Z_NO_FLUSH);
      // Z_BUF_ERROR (truncated input) and every hard error are a failed decompression
      if (LStatus <> Z_OK) and (LStatus <> Z_STREAM_END) then
      begin
        ADecompressed := nil;
        Exit;
      end;
      LOut := System.Length(LChunk) - Int32(LStrm.avail_out);
      if LOut > 0 then
      begin
        // never let the inflated output pass the bound (bomb guard)
        if LProduced + LOut > AMaxLength then
        begin
          ADecompressed := nil;
          Exit;
        end;
        Move(LChunk[0], ADecompressed[LProduced], LOut);
        Inc(LProduced, LOut);
      end;
    until LStatus = Z_STREAM_END;
    // input past the single zlib stream is malformed
    if LStrm.avail_in <> 0 then
    begin
      ADecompressed := nil;
      Exit;
    end;
    SetLength(ADecompressed, LProduced);
    Result := True;
  finally
    inflateEnd(LStrm);
  end;
end;

{ TZlibCertificateCompression }

class function TZlibCertificateCompression.DefaultCompressors: TArray<ICertificateCompressor>;
begin
  Result := TArray<ICertificateCompressor>.Create(
    TZlibCertificateCompressor.Create as ICertificateCompressor);
end;

class function TZlibCertificateCompression.DefaultDecompressors: TArray<ICertificateDecompressor>;
begin
  Result := TArray<ICertificateDecompressor>.Create(
    TZlibCertificateDecompressor.Create as ICertificateDecompressor);
end;

end.
