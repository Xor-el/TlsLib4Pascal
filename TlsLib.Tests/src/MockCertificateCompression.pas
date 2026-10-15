{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockCertificateCompression;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpZlibCertificateCompression;

type
  /// <summary>How a mock compressor answers: zlib, or a scripted breach of the contract.</summary>
  TMockCompressorMode = (Normal, Decline, EmptySuccess, Throws, Oversize);

  /// <summary>How a mock decompressor answers: zlib, or a scripted breach of the contract.</summary>
  TMockDecompressorMode = (Works, Fails, Raises, WrongLength);

  /// <summary>Raised by a mock backend scripted to throw.</summary>
  EMockCompressionBackend = class(Exception);

  /// <summary>A compressor under AAlgorithm that tallies its calls and answers per Mode.</summary>
  TMockCertificateCompressor = class sealed(TInterfacedObject, ICertificateCompressor)
  strict private
    FAlgorithm: UInt16;
    FMode: TMockCompressorMode;
    FCount: Int32;
  public
    constructor Create(AAlgorithm: UInt16; AMode: TMockCompressorMode);
    function Algorithm: UInt16;
    function TryCompress(const AData: TBytes; out ACompressed: TBytes): Boolean;
    property Mode: TMockCompressorMode read FMode write FMode;
    property Count: Int32 read FCount;
  end;

  /// <summary>A decompressor under AAlgorithm that tallies its calls and answers per its mode.</summary>
  TMockCertificateDecompressor = class sealed(TInterfacedObject, ICertificateDecompressor)
  strict private
    FAlgorithm: UInt16;
    FMode: TMockDecompressorMode;
    FCount: Int32;
  public
    constructor Create(AAlgorithm: UInt16; AMode: TMockDecompressorMode);
    function Algorithm: UInt16;
    function TryDecompress(const ACompressed: TBytes; AMaxLength: Int32;
      out ADecompressed: TBytes): Boolean;
    property Count: Int32 read FCount;
  end;

implementation

{ TMockCertificateCompressor }

constructor TMockCertificateCompressor.Create(AAlgorithm: UInt16; AMode: TMockCompressorMode);
begin
  inherited Create;
  FAlgorithm := AAlgorithm;
  FMode := AMode;
end;

function TMockCertificateCompressor.Algorithm: UInt16;
begin
  Result := FAlgorithm;
end;

function TMockCertificateCompressor.TryCompress(const AData: TBytes;
  out ACompressed: TBytes): Boolean;
begin
  Inc(FCount);
  ACompressed := nil;
  case FMode of
    TMockCompressorMode.Decline:
      Result := False;
    TMockCompressorMode.EmptySuccess:
      Result := True;
    TMockCompressorMode.Throws:
      raise EMockCompressionBackend.Create('the backend failed');
    TMockCompressorMode.Oversize:
      begin
        // one byte past the 2^24-1 compressed_certificate_message ceiling
        SetLength(ACompressed, TCertificateCompression.MaxCompressedLength + 1);
        Result := True;
      end;
  else
    Result := TZlibCertificateCompression.DefaultCompressors[0].TryCompress(AData, ACompressed);
  end;
end;

{ TMockCertificateDecompressor }

constructor TMockCertificateDecompressor.Create(AAlgorithm: UInt16;
  AMode: TMockDecompressorMode);
begin
  inherited Create;
  FAlgorithm := AAlgorithm;
  FMode := AMode;
end;

function TMockCertificateDecompressor.Algorithm: UInt16;
begin
  Result := FAlgorithm;
end;

function TMockCertificateDecompressor.TryDecompress(const ACompressed: TBytes;
  AMaxLength: Int32; out ADecompressed: TBytes): Boolean;
begin
  Inc(FCount);
  ADecompressed := nil;
  case FMode of
    TMockDecompressorMode.Fails:
      Result := False;
    TMockDecompressorMode.Raises:
      raise EMockCompressionBackend.Create('the backend failed');
    TMockDecompressorMode.WrongLength:
      begin
        // a short result that is not the declared length
        Result := TZlibCertificateCompression.DefaultDecompressors[0].TryDecompress(
          ACompressed, AMaxLength, ADecompressed);
        if Result and (System.Length(ADecompressed) > 0) then
          SetLength(ADecompressed, System.Length(ADecompressed) - 1);
      end;
  else
    Result := TZlibCertificateCompression.DefaultDecompressors[0].TryDecompress(
      ACompressed, AMaxLength, ADecompressed);
  end;
end;

end.
