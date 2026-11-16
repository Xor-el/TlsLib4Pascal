{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CertificateCompressionTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpZlibCertificateCompression,
  TlsLibTestBase;

type
  TTestCertificateCompression = class(TTlsLibAlgorithmTestCase)
  private
    function JunkCert(ALength: Int32): TBytes;
    function ZlibCompress(const AData: TBytes): TBytes;
    function DecompressAlert(AAlgorithm: UInt16; const ACompressed: TBytes;
      ADeclaredLength, AMaxLength: Int32; out AAlert: TTlsAlertDescription): Boolean;
  published
    procedure TestDecompressionHonoursConfiguredCeiling;
    procedure TestCertificateDecompressionDeclaredAtCeilingPassesCapCheck;
    procedure TestCertificateDecompressionZeroDeclaredLengthRejected;
    procedure TestCertificateDecompressionRatioBombRejected;
    procedure TestCertificateDecompressionAtRatioLimitPassesGuard;
    procedure TestCertificateDecompressionJustOverRatioLimitRejected;
    procedure TestCertificateDecompressionLengthMismatchRejected;
    procedure TestCertificateDecompressionTrailingBytesRejected;
    procedure TestCertificateDecompressionUnsupportedAlgorithmRejected;
  end;

  TTestZlibCertificateCompression = class(TTlsLibAlgorithmTestCase)
  private
    function Compress(const AData: TBytes): TBytes;
    function Inflate(const ACompressed: TBytes; AMaxLength: Int32): TBytes;
  published
    procedure TestCertificateDecompressionRoundTrip;
    procedure TestZlibCompressionRoundTrips;
    procedure TestZlibCompressionSpansSeveralOutputChunks;
    procedure TestZlibCompressionOfNothingIsAnEmptyStream;
  end;

implementation

{ TTestCertificateCompression }

function TTestCertificateCompression.JunkCert(ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  if ALength > 0 then
    FillChar(Result[0], ALength, $41);
end;

// compresses/decompresses through the built-in zlib seam under the shared bomb
// defense (test helpers exercising TCertificateCompression's centralized policy)
function TTestCertificateCompression.ZlibCompress(const AData: TBytes): TBytes;
var
  LCompressors: TArray<ICertificateCompressor>;
begin
  LCompressors := TZlibCertificateCompression.DefaultCompressors;
  CheckTrue(LCompressors[0].TryCompress(AData, Result), 'zlib compressed the body');
end;

// True when Decompress refused the input with a fatal alert, which AAlert carries
function TTestCertificateCompression.DecompressAlert(AAlgorithm: UInt16;
  const ACompressed: TBytes; ADeclaredLength, AMaxLength: Int32;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := False;
  AAlert := TTlsAlertDescription.CloseNotify;
  try
    TCertificateCompression.Decompress(
      TZlibCertificateCompression.DefaultDecompressors, AAlgorithm, ACompressed,
      ADeclaredLength, AMaxLength);
  except
    on E: EFatalAlertTlsLibException do
    begin
      AAlert := E.AlertDescription;
      Result := True;
    end;
  end;
end;

procedure TTestCertificateCompression.TestDecompressionHonoursConfiguredCeiling;
var
  LAlert: TTlsAlertDescription;
begin
  // 100 bytes allow 10000 under the ratio guard, so only the 4096 ceiling can refuse 4097
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(100), 4097, 4096,
    LAlert), 'a declared length one over the ceiling is refused');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an over-ceiling declared length is illegal_parameter');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionDeclaredAtCeilingPassesCapCheck;
var
  LAlert: TTlsAlertDescription;
begin
  // control: exactly the ceiling clears the cap, then the junk input fails to inflate
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(100), 4096, 4096,
    LAlert), 'the junk input is refused');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'a declared length at the ceiling reaches the decompressor');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionZeroDeclaredLengthRejected;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(100), 0, 4096,
    LAlert), 'a zero declared length is refused');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a zero declared length is illegal_parameter');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionRatioBombRejected;
var
  LZeros, LCompressed: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // 60000 zeros stay under the ceiling, so only the ratio guard can refuse the declared length
  LZeros := nil;
  SetLength(LZeros, 60000);
  FillChar(LZeros[0], 60000, 0);
  LCompressed := ZlibCompress(LZeros);
  CheckTrue(System.Length(LCompressed) * TCertificateCompression.MaxExpansionRatio < 60000,
    'the body compresses past the ratio limit');
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, LCompressed, 60000,
    1 shl 18, LAlert), 'the bomb is refused');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a decompression bomb is illegal_parameter');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionAtRatioLimitPassesGuard;
var
  LAlert: TTlsAlertDescription;
begin
  // control: 10 bytes allow exactly 1000, so the guard passes and the junk fails to inflate
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(10), 1000,
    1 shl 18, LAlert), 'the junk input is refused');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'a declared length at the ratio limit reaches the decompressor');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionJustOverRatioLimitRejected;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(10), 1001,
    1 shl 18, LAlert), 'a declared length one over the ratio limit is refused');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an over-ratio declared length is illegal_parameter');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionLengthMismatchRejected;
var
  LOriginal, LCompressed: TBytes;
  LI: Int32;
  LAlert: TTlsAlertDescription;
begin
  // the produced length must equal the declared length exactly. Use a moderately-compressible
  // payload and declare one byte over the true size so the ratio guard is not tripped first: only
  // the produced/declared mismatch fires, which is bad_certificate (not a malformed wire field)
  LOriginal := nil;
  SetLength(LOriginal, 5000);
  for LI := 0 to System.Length(LOriginal) - 1 do
    LOriginal[LI] := Byte((LI * 7) and $FF);
  LCompressed := ZlibCompress(LOriginal);
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, LCompressed, 5001, 8192,
    LAlert), 'a declared/produced length mismatch is rejected');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'a length mismatch is bad_certificate');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionTrailingBytesRejected;
var
  LOriginal, LCompressed, LWithTrailer: TBytes;
  LI: Int32;
  LAlert: TTlsAlertDescription;
begin
  // a CompressedCertificate body is exactly one zlib stream; a byte appended after it is
  // malformed and must be rejected, not silently ignored
  LOriginal := nil;
  SetLength(LOriginal, 5000);
  for LI := 0 to System.Length(LOriginal) - 1 do
    LOriginal[LI] := Byte((LI * 7) and $FF);
  LCompressed := ZlibCompress(LOriginal);
  LWithTrailer := System.Copy(LCompressed);
  SetLength(LWithTrailer, System.Length(LWithTrailer) + 1);
  LWithTrailer[System.Length(LWithTrailer) - 1] := $2A;
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, LWithTrailer,
    System.Length(LOriginal), 8192, LAlert), 'a byte after the zlib stream is rejected');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'a trailing byte is bad_certificate');
end;

procedure TTestCertificateCompression.TestCertificateDecompressionUnsupportedAlgorithmRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // brotli (2) is not advertised; 100 is within the ceiling and ratio, so only the lookup refuses
  CheckTrue(DecompressAlert(2, JunkCert(64), 100, 8192, LAlert),
    'an unsupported compression algorithm is rejected');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an unsupported algorithm is illegal_parameter');
end;

{ TTestZlibCertificateCompression }

function TTestZlibCertificateCompression.Compress(const AData: TBytes): TBytes;
var
  LCompressors: TArray<ICertificateCompressor>;
begin
  LCompressors := TZlibCertificateCompression.DefaultCompressors;
  CheckTrue(LCompressors[0].TryCompress(AData, Result), 'zlib compressed the body');
end;

// through the decompressor, an independent code path from the compressor under test
function TTestZlibCertificateCompression.Inflate(const ACompressed: TBytes;
  AMaxLength: Int32): TBytes;
var
  LDecompressors: TArray<ICertificateDecompressor>;
begin
  LDecompressors := TZlibCertificateCompression.DefaultDecompressors;
  CheckTrue(LDecompressors[0].TryDecompress(ACompressed, AMaxLength, Result),
    'the compressed body inflates');
end;

procedure TTestZlibCertificateCompression.TestCertificateDecompressionRoundTrip;
var
  LOriginal, LCompressed, LRestored: TBytes;
  LI: Int32;
begin
  // a real (non-trivially-sized) payload compresses and decompresses byte-identically
  LOriginal := nil;
  SetLength(LOriginal, 5000);
  for LI := 0 to System.Length(LOriginal) - 1 do
    LOriginal[LI] := Byte((LI * 7) and $FF);
  LCompressed := Compress(LOriginal);
  LRestored := TCertificateCompression.Decompress(
    TZlibCertificateCompression.DefaultDecompressors,
    TCertificateCompressionAlgorithms.Zlib, LCompressed, System.Length(LOriginal), 8192);
  CheckEqualBytes('the payload round-trips through zlib', LOriginal, LRestored);
end;

procedure TTestZlibCertificateCompression.TestZlibCompressionRoundTrips;
var
  LOriginal, LCompressed: TBytes;
  LI: Int32;
begin
  LOriginal := nil;
  SetLength(LOriginal, 2048);
  for LI := 0 to System.Length(LOriginal) - 1 do
    LOriginal[LI] := Byte((LI * LI) shr 3);
  LCompressed := Compress(LOriginal);
  CheckEquals($78, LCompressed[0], 'the stream starts with the zlib header');
  CheckEqualBytes('the body inflates back byte for byte', LOriginal,
    Inflate(LCompressed, 4096));
end;

procedure TTestZlibCertificateCompression.TestZlibCompressionSpansSeveralOutputChunks;
var
  LOriginal, LCompressed: TBytes;
  LState: UInt64;
  LI: Int32;
begin
  // pseudo-random bytes do not compress, so the output needs several rounds of deflate
  LOriginal := nil;
  SetLength(LOriginal, 10000);
  LState := 12345;
  for LI := 0 to System.Length(LOriginal) - 1 do
  begin
    LState := (LState * 1664525 + 1013904223) and $FFFFFFFF;
    LOriginal[LI] := Byte(LState shr 24);
  end;
  LCompressed := Compress(LOriginal);
  CheckTrue(System.Length(LCompressed) > 4096, 'the output is longer than one chunk');
  CheckEqualBytes('the body inflates back byte for byte', LOriginal,
    Inflate(LCompressed, 16384));
end;

procedure TTestZlibCertificateCompression.TestZlibCompressionOfNothingIsAnEmptyStream;
var
  LCompressed: TBytes;
begin
  LCompressed := Compress(nil);
  CheckTrue(System.Length(LCompressed) > 0, 'an empty body still yields a zlib stream');
  CheckEquals(0, System.Length(Inflate(LCompressed, 16)), 'the stream inflates to nothing');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateCompression);
  RegisterTest(TTestZlibCertificateCompression);
{$ELSE}
  RegisterTest(TTestCertificateCompression.Suite);
  RegisterTest(TTestZlibCertificateCompression.Suite);
{$ENDIF FPC}

end.
