{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCertificateCompression;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpBinaryPrimitives,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpICertificateCompression,
  TlpICertificateCompressionCache;

type
  /// <summary>
  /// The certificate-compression algorithm codepoints (RFC 8879). This is an open
  /// IANA registry, not a closed set: a backend the application injects carries its
  /// own UInt16 codepoint, so these are named constants.
  /// </summary>
  TCertificateCompressionAlgorithms = class sealed(TObject)
  public const
    Zlib = UInt16(1);
    Brotli = UInt16(2);
    Zstd = UInt16(3);
  end;

  /// <summary>
  /// The certificate-compression policy layer (RFC 8879), independent of any
  /// algorithm: it selects a compressor against a peer's advertised list and - the
  /// security-critical part - decompresses through an injected decompressor under one
  /// centralized bomb defense (declared-length ceiling, ratio guard, exact-length
  /// match), so a swapped-in algorithm cannot skip the guard. The concrete backends
  /// live behind ICertificateCompressor/ICertificateDecompressor (zlib ships in
  /// TlpZlibCertificateCompression).
  /// </summary>
  TCertificateCompression = class sealed(TObject)
  strict private
    /// <summary>The content-addressed cache key: SHA-256 over be16(algorithm) and ABody.</summary>
    class function DeriveKey(const AProvider: ICryptoProvider; AAlgorithm: UInt16;
      const ABody: TBytes): TBytes; static;
  public const
    /// <summary>The hard ceiling on decompressed certificate-message bytes.</summary>
    MaxDecompressedLength = Int32(1 shl 18);
    /// <summary>The largest declared expansion over the compressed size (bomb guard).</summary>
    MaxExpansionRatio = Int32(100);
  public
    /// <summary>The algorithm codes to advertise for a set of decompressors.</summary>
    class function Algorithms(
      const ADecompressors: TArray<ICertificateDecompressor>): TArray<UInt16>; static;
    /// <summary>The first compressor whose algorithm the peer advertised, or nil.</summary>
    class function SelectCompressor(
      const ACompressors: TArray<ICertificateCompressor>;
      const APeerAlgorithms: TArray<UInt16>): ICertificateCompressor; static;
    /// <summary>
    /// Compresses ABody with ACompressor, memoized through ACache when non-nil (keyed by
    /// a SHA-256 digest of the algorithm codepoint and ABody derived through AProvider).
    /// Because Compress is pure, a hit returns exactly what a fresh Compress(ABody) would,
    /// so the cache never changes the result. ACache = nil compresses directly. The caller
    /// still applies the strictly-smaller check before framing a CompressedCertificate.
    /// </summary>
    class function CompressWithCache(
      const ACache: ICertificateCompressionCache; const AProvider: ICryptoProvider;
      const ACompressor: ICertificateCompressor; const ABody: TBytes): TBytes; static;
    /// <summary>
    /// Decompresses ACompressed under AAlgorithm using ADecompressors, bounded to
    /// ADeclaredLength. Raises a bad_certificate fatal alert on an unsupported
    /// algorithm, a declared length outside its bounds, a ratio that reeks of a bomb,
    /// or an output whose length does not match the declared length.
    /// </summary>
    class function Decompress(
      const ADecompressors: TArray<ICertificateDecompressor>; AAlgorithm: UInt16;
      const ACompressed: TBytes; ADeclaredLength: Int32): TBytes; static;
  end;

implementation

resourcestring
  SUnsupportedAlgorithm = 'unsupported certificate compression algorithm';
  SBadDeclaredLength = 'the declared uncompressed length is out of range';
  SRatioTooHigh = 'the certificate compression ratio exceeds the bomb guard';
  SLengthMismatch = 'decompressed output length does not match the declared length';

{ TCertificateCompression }

class function TCertificateCompression.Algorithms(
  const ADecompressors: TArray<ICertificateDecompressor>): TArray<UInt16>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(ADecompressors));
  for LI := 0 to System.High(ADecompressors) do
    Result[LI] := ADecompressors[LI].Algorithm;
end;

class function TCertificateCompression.SelectCompressor(
  const ACompressors: TArray<ICertificateCompressor>;
  const APeerAlgorithms: TArray<UInt16>): ICertificateCompressor;
var
  LCompressor: ICertificateCompressor;
begin
  Result := nil;
  // server preference: the first configured compressor the peer can decompress
  for LCompressor in ACompressors do
    if TArrayUtilities.Contains<UInt16>(APeerAlgorithms, LCompressor.Algorithm) then
      Exit(LCompressor);
end;

class function TCertificateCompression.DeriveKey(const AProvider: ICryptoProvider;
  AAlgorithm: UInt16; const ABody: TBytes): TBytes;
var
  LHash: IHash;
  LPrefix: TBytes;
begin
  SetLength(LPrefix, SizeOf(UInt16));
  TBinaryPrimitives.WriteUInt16BigEndian(LPrefix, 0, AAlgorithm);
  LHash := AProvider.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LPrefix, 0, System.Length(LPrefix));
  LHash.Update(ABody, 0, System.Length(ABody));
  Result := LHash.DoFinal;
end;

class function TCertificateCompression.CompressWithCache(
  const ACache: ICertificateCompressionCache; const AProvider: ICryptoProvider;
  const ACompressor: ICertificateCompressor; const ABody: TBytes): TBytes;
var
  LKey: TBytes;
begin
  if ACache = nil then
    Exit(ACompressor.Compress(ABody));
  // content-addressed memoization: hashing ABody is far cheaper than deflating it, so a
  // miss still wins; a hit returns the identical bytes a fresh Compress would produce
  LKey := DeriveKey(AProvider, ACompressor.Algorithm, ABody);
  if ACache.TryGet(LKey, Result) then
    Exit;
  Result := ACompressor.Compress(ABody);
  ACache.Put(LKey, Result);
end;

class function TCertificateCompression.Decompress(
  const ADecompressors: TArray<ICertificateDecompressor>; AAlgorithm: UInt16;
  const ACompressed: TBytes; ADeclaredLength: Int32): TBytes;
var
  LDecompressor, LFound: ICertificateDecompressor;
begin
  Result := nil;
  if (ADeclaredLength <= 0) or (ADeclaredLength > MaxDecompressedLength) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadCertificate,
      @SBadDeclaredLength);
  // reject an obvious bomb before allocating: a huge declared expansion over the
  // compressed size cannot be a real certificate chain
  if ADeclaredLength > System.Length(ACompressed) * MaxExpansionRatio then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadCertificate,
      @SRatioTooHigh);
  LFound := nil;
  for LDecompressor in ADecompressors do
    if LDecompressor.Algorithm = AAlgorithm then
    begin
      LFound := LDecompressor;
      Break;
    end;
  if LFound = nil then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadCertificate,
      @SUnsupportedAlgorithm);
  Result := LFound.Decompress(ACompressed, ADeclaredLength);
  if System.Length(Result) <> ADeclaredLength then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadCertificate,
      @SLengthMismatch);
end;

end.
