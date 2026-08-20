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
  TlpCertificateVerifier,
  TlsLibTestBase;

type
  TTestResourceLimit = class(TTlsLibAlgorithmTestCase)
  private
    function ExtensionBlock(const ATypes: TArray<UInt16>): TBytes;
    function ConsumeAlert(const ABlock: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
    function JunkCert(ALength: Int32): TBytes;
    function VerifyAlert(const AChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
    function ZlibCompress(const AData: TBytes): TBytes;
    function SeamDecompress(AAlgorithm: UInt16; const ACompressed: TBytes;
      ADeclaredLength: Int32): TBytes;
  published
    procedure TestOverLengthHandshakeMessageRejected;
    procedure TestHandshakeReassemblyOverflowRejected;
    procedure TestDuplicateExtensionRejected;
    procedure TestExtensionCountFloodRejected;
    procedure TestOverLongCertificateChainRejected;
    procedure TestOversizeCertificateRejected;
    procedure TestCertificateDecompressionRoundTrip;
    procedure TestCertificateDecompressionRatioBombRejected;
    procedure TestCertificateDecompressionDeclaredTooLargeRejected;
    procedure TestCertificateDecompressionLengthMismatchRejected;
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
  Result := LCompressors[0].Compress(AData);
end;

function TTestResourceLimit.SeamDecompress(AAlgorithm: UInt16;
  const ACompressed: TBytes; ADeclaredLength: Int32): TBytes;
begin
  Result := TCertificateCompression.Decompress(
    TZlibCertificateCompression.DefaultDecompressors, AAlgorithm, ACompressed,
    ADeclaredLength);
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

function TTestResourceLimit.VerifyAlert(const AChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: ICertificateVerifier;
begin
  LVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore, False) as ICertificateVerifier;
  Result := not LVerifier.Verify(AChain, '', nil, AAlert);
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
  // two extensions of the same (unknown) type in one block (RFC 8446 4.2): a repeated type is
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

procedure TTestResourceLimit.TestOverLongCertificateChainRejected;
var
  LChain: TArray<TBytes>;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  // a chain longer than the cap is rejected before any PKIX work
  LChain := nil;
  SetLength(LChain, 11);
  for LI := 0 to 10 do
    LChain[LI] := JunkCert(16);
  CheckTrue(VerifyAlert(LChain, LAlert), 'an over-long chain aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'an over-long chain is bad_certificate');
end;

procedure TTestResourceLimit.TestOversizeCertificateRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // a single certificate above the per-certificate size cap
  CheckTrue(VerifyAlert(TArray<TBytes>.Create(JunkCert((1 shl 16) + 1)), LAlert),
    'an oversize certificate aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'an oversize certificate is bad_certificate');
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
  LRestored := SeamDecompress(TCertificateCompressionAlgorithms.Zlib,
    LCompressed, System.Length(LOriginal));
  CheckEqualBytes('the payload round-trips through zlib', LOriginal, LRestored);
end;

procedure TTestResourceLimit.TestCertificateDecompressionRatioBombRejected;
var
  LZeros, LCompressed: TBytes;
  LRaised: Boolean;
begin
  // a highly compressible blob is the classic bomb: a tiny compressed body declaring a
  // huge expansion must be refused by the ratio guard before it is inflated
  LZeros := JunkCert(0);
  SetLength(LZeros, 60000);
  FillChar(LZeros[0], 60000, 0);
  LCompressed := ZlibCompress(LZeros);
  LRaised := False;
  try
    SeamDecompress(TCertificateCompressionAlgorithms.Zlib, LCompressed, 60000);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := E.AlertDescription = TTlsAlertDescription.BadCertificate;
  end;
  CheckTrue(LRaised, 'a decompression bomb is rejected as bad_certificate');
end;

procedure TTestResourceLimit.TestCertificateDecompressionDeclaredTooLargeRejected;
var
  LRaised: Boolean;
begin
  // a declared uncompressed length above the hard ceiling is refused up front
  LRaised := False;
  try
    SeamDecompress(TCertificateCompressionAlgorithms.Zlib,
      JunkCert(64), (1 shl 18) + 1);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := E.AlertDescription = TTlsAlertDescription.BadCertificate;
  end;
  CheckTrue(LRaised, 'an over-large declared length is rejected');
end;

procedure TTestResourceLimit.TestCertificateDecompressionLengthMismatchRejected;
var
  LOriginal, LCompressed: TBytes;
  LRaised: Boolean;
begin
  // the produced length must equal the declared length exactly
  LOriginal := JunkCert(3000);
  LCompressed := ZlibCompress(LOriginal);
  LRaised := False;
  try
    SeamDecompress(TCertificateCompressionAlgorithms.Zlib, LCompressed, 3200);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := E.AlertDescription = TTlsAlertDescription.BadCertificate;
  end;
  CheckTrue(LRaised, 'a declared/produced length mismatch is rejected');
end;

procedure TTestResourceLimit.TestCertificateDecompressionUnsupportedAlgorithmRejected;
var
  LRaised: Boolean;
begin
  // brotli (2) is not one we advertise or can decompress
  LRaised := False;
  try
    SeamDecompress(2, JunkCert(64), 100);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := E.AlertDescription = TTlsAlertDescription.BadCertificate;
  end;
  CheckTrue(LRaised, 'an unsupported compression algorithm is rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestResourceLimit);
{$ELSE}
  RegisterTest(TTestResourceLimit.Suite);
{$ENDIF FPC}

end.
