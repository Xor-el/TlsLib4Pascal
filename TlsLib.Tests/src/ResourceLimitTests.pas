{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ResourceLimitTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter,
  TlpHandshakeMessage,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpCoreExtensions,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpZlibCertificateCompression,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpServerName,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  TTestResourceLimit = class(TTlsLibAlgorithmTestCase)
  private
    function ExtensionBlock(const ATypes: TArray<UInt16>): TBytes;
    function ConsumeAlert(const ABlock: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
    function JunkCert(ALength: Int32): TBytes;
    function VerifyChain(const AChain: TArray<TBytes>; const ALimits: TCertificateChainLimits;
      out AAlert: TTlsAlertDescription): Boolean;
    function ZlibCompress(const AData: TBytes): TBytes;
    function DecompressAlert(AAlgorithm: UInt16; const ACompressed: TBytes;
      ADeclaredLength, AMaxLength: Int32; out AAlert: TTlsAlertDescription): Boolean;
  published
    procedure TestOverLengthHandshakeMessageRejected;
    procedure TestHandshakeReassemblyOverflowRejected;
    procedure TestDuplicateExtensionRejected;
    procedure TestExtensionCountFloodRejected;
    procedure TestCertificateOverPerCertificateCapRejected;
    procedure TestCertificateAtPerCertificateCapAccepted;
    procedure TestChainOverTotalCapRejected;
    procedure TestChainAtTotalCapAccepted;
    procedure TestDecompressionHonoursConfiguredCeiling;
    procedure TestCertificateDecompressionDeclaredAtCeilingPassesCapCheck;
    procedure TestCertificateDecompressionZeroDeclaredLengthRejected;
    procedure TestCertificateDecompressionRoundTrip;
    procedure TestCertificateDecompressionRatioBombRejected;
    procedure TestCertificateDecompressionAtRatioLimitPassesGuard;
    procedure TestCertificateDecompressionJustOverRatioLimitRejected;
    procedure TestCertificateDecompressionLengthMismatchRejected;
    procedure TestCertificateDecompressionTrailingBytesRejected;
    procedure TestCertificateDecompressionUnsupportedAlgorithmRejected;
  end;

implementation

{ TTestResourceLimit }

// compresses/decompresses through the built-in zlib seam under the shared bomb
// defense (test helpers exercising TCertificateCompression's centralized policy)
function TTestResourceLimit.ZlibCompress(const AData: TBytes): TBytes;
var
  LCompressors: TArray<ICertificateCompressor>;
begin
  LCompressors := TZlibCertificateCompression.DefaultCompressors;
  CheckTrue(LCompressors[0].TryCompress(AData, Result), 'zlib compressed the body');
end;

// True when Decompress refused the input with a fatal alert, which AAlert carries
function TTestResourceLimit.DecompressAlert(AAlgorithm: UInt16;
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

function TTestResourceLimit.ExtensionBlock(
  const ATypes: TArray<UInt16>): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LType: UInt16;
begin
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  for LType in ATypes do
  begin
    LWriter.WriteUInt16(LType);
    LWriter.WriteUInt16(0); // empty extension_data
  end;
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

function TTestResourceLimit.ConsumeAlert(const ABlock: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
begin
  Result := False;
  AAlert := TTlsAlertDescription.CloseNotify;
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    try
      LCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ClientHello, ABlock);
    except
      on E: EDecodeErrorTlsLibException do
      begin
        AAlert := TTlsAlertDescription.DecodeError;
        Result := True;
      end;
      on E: EFatalAlertTlsLibException do
      begin
        AAlert := E.AlertDescription;
        Result := True;
      end;
    end;
  finally
    LContext.Free;
  end;
end;

function TTestResourceLimit.JunkCert(ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  if ALength > 0 then
    FillChar(Result[0], ALength, $41);
end;

// a real chain under the real root, so only a cap in ALimits can refuse it
function TTestResourceLimit.VerifyChain(const AChain: TArray<TBytes>;
  const ALimits: TCertificateChainLimits; out AAlert: TTlsAlertDescription): Boolean;
var
  LOptions: TCertificateVerifierOptions;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LOptions.ChainLimits := ALimits;
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True, LOptions) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(AChain,
    TServerName.DnsName('localhost'), nil, LVerified, AAlert);
end;

procedure TTestResourceLimit.TestOverLengthHandshakeMessageRejected;
var
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LHeader: TBytes;
  LRaised: Boolean;
begin
  // a handshake header declaring a body above the per-message cap is decode_error
  // before the body is buffered: type 11, uint24 length 0x020000 (> 2^16)
  LReader := THandshakeMessageReader.Create;
  try
    LHeader := DecodeHex('0B020000');
    LReader.Append(LHeader, 0, System.Length(LHeader));
    LRaised := False;
    try
      LReader.NextMessage(LMsg);
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'an over-length handshake message is rejected');
  finally
    LReader.Free;
  end;
end;

procedure TTestResourceLimit.TestHandshakeReassemblyOverflowRejected;
var
  LReader: THandshakeMessageReader;
  LChunk: TBytes;
  LRaised: Boolean;
  LI: Int32;
begin
  // a flood that never completes a message cannot grow the reassembly buffer without
  // bound: appending past the total cap is decode_error
  LReader := THandshakeMessageReader.Create;
  try
    LReader.MaxTotalLength := 4096;
    LChunk := JunkCert(1024);
    LRaised := False;
    try
      for LI := 0 to 7 do
        LReader.Append(LChunk, 0, System.Length(LChunk));
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'the reassembly buffer is bounded');
  finally
    LReader.Free;
  end;
end;

procedure TTestResourceLimit.TestDuplicateExtensionRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // two extensions of the same (unknown) type in one block (RFC 9846 4.3): a repeated type is
  // rejected structurally with illegal_parameter
  CheckTrue(ConsumeAlert(ExtensionBlock(TArray<UInt16>.Create($FF00, $FF00)), LAlert),
    'a duplicate extension aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a duplicate extension is illegal_parameter');
end;

procedure TTestResourceLimit.TestExtensionCountFloodRejected;
var
  LTypes: TArray<UInt16>;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  // 65 distinct (unknown) extensions exceed the per-block cap
  LTypes := nil;
  SetLength(LTypes, 65);
  for LI := 0 to 64 do
    LTypes[LI] := UInt16($FF00 + LI);
  CheckTrue(ConsumeAlert(ExtensionBlock(LTypes), LAlert),
    'an extension-count flood aborts');
  CheckTrue(LAlert = TTlsAlertDescription.DecodeError,
    'an extension-count flood is decode_error');
end;

procedure TTestResourceLimit.TestCertificateOverPerCertificateCapRejected;
var
  LLeaf: TBytes;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  // only this cap is tightened, so it alone refuses an otherwise valid certificate
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxCertificateLength := System.Length(LLeaf) - 1;
  CheckFalse(VerifyChain(TArray<TBytes>.Create(LLeaf), LLimits, LAlert),
    'a certificate one byte over the cap aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'an over-cap certificate is bad_certificate');
end;

procedure TTestResourceLimit.TestCertificateAtPerCertificateCapAccepted;
var
  LLeaf: TBytes;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  // the control for the cap test above: the same leaf at exactly the cap verifies
  LLeaf := TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxCertificateLength := System.Length(LLeaf);
  CheckTrue(VerifyChain(TArray<TBytes>.Create(LLeaf), LLimits, LAlert),
    'a certificate exactly at the cap verifies');
end;

procedure TTestResourceLimit.TestChainOverTotalCapRejected;
var
  LChain: TArray<TBytes>;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  // each certificate is under the per-certificate cap, so only the summed total can refuse it
  LChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'));
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxTotalChainLength := System.Length(LChain[0]) + System.Length(LChain[1]) - 1;
  CheckFalse(VerifyChain(LChain, LLimits, LAlert), 'a chain one byte over the total cap aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'an over-total chain is bad_certificate');
end;

procedure TTestResourceLimit.TestChainAtTotalCapAccepted;
var
  LChain: TArray<TBytes>;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  LChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'));
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxTotalChainLength := System.Length(LChain[0]) + System.Length(LChain[1]);
  CheckTrue(VerifyChain(LChain, LLimits, LAlert), 'a chain exactly at the total cap verifies');
end;

procedure TTestResourceLimit.TestDecompressionHonoursConfiguredCeiling;
var
  LAlert: TTlsAlertDescription;
begin
  // 100 bytes allow 10000 under the ratio guard, so only the 4096 ceiling can refuse 4097
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(100), 4097, 4096,
    LAlert), 'a declared length one over the ceiling is refused');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an over-ceiling declared length is illegal_parameter');
end;

procedure TTestResourceLimit.TestCertificateDecompressionDeclaredAtCeilingPassesCapCheck;
var
  LAlert: TTlsAlertDescription;
begin
  // control: exactly the ceiling clears the cap, then the junk input fails to inflate
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(100), 4096, 4096,
    LAlert), 'the junk input is refused');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'a declared length at the ceiling reaches the decompressor');
end;

procedure TTestResourceLimit.TestCertificateDecompressionZeroDeclaredLengthRejected;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(100), 0, 4096,
    LAlert), 'a zero declared length is refused');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a zero declared length is illegal_parameter');
end;

procedure TTestResourceLimit.TestCertificateDecompressionRoundTrip;
var
  LOriginal, LCompressed, LRestored: TBytes;
  LI: Int32;
begin
  // a real (non-trivially-sized) payload compresses and decompresses byte-identically
  LOriginal := nil;
  SetLength(LOriginal, 5000);
  for LI := 0 to System.Length(LOriginal) - 1 do
    LOriginal[LI] := Byte((LI * 7) and $FF);
  LCompressed := ZlibCompress(LOriginal);
  LRestored := TCertificateCompression.Decompress(
    TZlibCertificateCompression.DefaultDecompressors,
    TCertificateCompressionAlgorithms.Zlib, LCompressed, System.Length(LOriginal), 8192);
  CheckEqualBytes('the payload round-trips through zlib', LOriginal, LRestored);
end;

procedure TTestResourceLimit.TestCertificateDecompressionRatioBombRejected;
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

procedure TTestResourceLimit.TestCertificateDecompressionAtRatioLimitPassesGuard;
var
  LAlert: TTlsAlertDescription;
begin
  // control: 10 bytes allow exactly 1000, so the guard passes and the junk fails to inflate
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(10), 1000,
    1 shl 18, LAlert), 'the junk input is refused');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'a declared length at the ratio limit reaches the decompressor');
end;

procedure TTestResourceLimit.TestCertificateDecompressionJustOverRatioLimitRejected;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(DecompressAlert(TCertificateCompressionAlgorithms.Zlib, JunkCert(10), 1001,
    1 shl 18, LAlert), 'a declared length one over the ratio limit is refused');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an over-ratio declared length is illegal_parameter');
end;

procedure TTestResourceLimit.TestCertificateDecompressionLengthMismatchRejected;
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

procedure TTestResourceLimit.TestCertificateDecompressionTrailingBytesRejected;
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

procedure TTestResourceLimit.TestCertificateDecompressionUnsupportedAlgorithmRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // brotli (2) is not advertised; 100 is within the ceiling and ratio, so only the lookup refuses
  CheckTrue(DecompressAlert(2, JunkCert(64), 100, 8192, LAlert),
    'an unsupported compression algorithm is rejected');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an unsupported algorithm is illegal_parameter');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestResourceLimit);
{$ELSE}
  RegisterTest(TTestResourceLimit.Suite);
{$ENDIF FPC}

end.
