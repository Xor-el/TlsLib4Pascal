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
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
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
    class function DeriveKey(const ACryptoProvider: ICryptoProvider; AAlgorithm: UInt16;
      const ABody: TBytes): TBytes; static;
  public const
    /// <summary>The hard ceiling on decompressed certificate-message bytes.</summary>
    MaxDecompressedLength = Int32(1 shl 18);
    /// <summary>The largest declared expansion over the compressed size (bomb guard).</summary>
    MaxExpansionRatio = Int32(100);
    /// <summary>The most algorithms one compress_certificate extension can list
    /// (algorithms&lt;2..2^8-2&gt;, two bytes each).</summary>
    MaxAdvertisedAlgorithms = Int32(127);
    /// <summary>The largest compressed_certificate_message a CompressedCertificate can carry
    /// (RFC 8879 4: &lt;1..2^24-1&gt;).</summary>
    MaxCompressedLength = Int32((1 shl 24) - 1);
  public
    /// <summary>Raises EArgumentTlsLibException for a compressor set that is not usable: a nil
    /// entry, the reserved codepoint 0, or a codepoint listed twice. nil or empty is valid
    /// (that direction is off).</summary>
    class procedure ValidateCompressors(
      const ACompressors: TArray<ICertificateCompressor>); static;
    /// <summary>As ValidateCompressors, and also refuses more entries than one
    /// compress_certificate extension can advertise.</summary>
    class procedure ValidateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>); static;
    /// <summary>The algorithm codes to advertise for a set of decompressors.</summary>
    class function Algorithms(
      const ADecompressors: TArray<ICertificateDecompressor>): TArray<UInt16>; static;
    /// <summary>The first compressor, in the sender's order, whose algorithm the peer
    /// advertised, or nil.</summary>
    class function SelectCompressor(
      const ACompressors: TArray<ICertificateCompressor>;
      const APeerAlgorithms: TArray<UInt16>): ICertificateCompressor; static;
    /// <summary>
    /// Compresses ABody with ACompressor, memoized through ACache when non-nil (keyed by
    /// a SHA-256 digest of the algorithm codepoint and ABody derived through ACryptoProvider).
    /// True with the output, or False when the compressor declined (nothing is cached for a
    /// decline, which may be transient). A compressor that reports True with an empty result
    /// breaks its contract and fails the handshake with internal_error. Because TryCompress
    /// is pure, a hit returns exactly what a fresh call would, so the cache never changes the
    /// result. ACache = nil compresses directly.
    /// </summary>
    class function TryCompressWithCache(
      const ACache: ICertificateCompressionCache; const ACryptoProvider: ICryptoProvider;
      const ACompressor: ICertificateCompressor; const ABody: TBytes;
      out ACompressed: TBytes): Boolean; static;
    /// <summary>
    /// The framed Certificate handshake message an endpoint sends for ABody (a Certificate
    /// message body): a CompressedCertificate when the sender holds a compressor the peer
    /// advertised and it produced a result the wire can carry, else a plain Certificate. A
    /// certificate list with no entries (AHasEntries False) is never compressed. Both roles
    /// send through this, so they share one rule.
    /// </summary>
    class function FrameCertificate(
      const ACompressors: TArray<ICertificateCompressor>;
      const APeerAlgorithms: TArray<UInt16>; const ACache: ICertificateCompressionCache;
      const ACryptoProvider: ICryptoProvider; const ABody: TBytes;
      AHasEntries: Boolean): TBytes; static;
    /// <summary>
    /// Decompresses ACompressed under AAlgorithm using ADecompressors, bounded to
    /// ADeclaredLength against the hard MaxDecompressedLength ceiling. Raises a fatal
    /// alert on an unsupported algorithm or a declared length outside its bounds
    /// (illegal_parameter), a ratio that reeks of a bomb (illegal_parameter), a
    /// decompressor that cannot decompress the input or raises (bad_certificate), or an
    /// output whose length does not match the declared length (bad_certificate).
    /// </summary>
    class function Decompress(
      const ADecompressors: TArray<ICertificateDecompressor>; AAlgorithm: UInt16;
      const ACompressed: TBytes; ADeclaredLength: Int32): TBytes; overload; static;
    /// <summary>As above, but with an explicit AMaxLength ceiling so the caller's
    /// configured budget (the certificate-chain limits) bounds the decompressed body
    /// rather than the fixed MaxDecompressedLength - the compressed and uncompressed
    /// paths then honour the same cap.</summary>
    class function Decompress(
      const ADecompressors: TArray<ICertificateDecompressor>; AAlgorithm: UInt16;
      const ACompressed: TBytes; ADeclaredLength, AMaxLength: Int32): TBytes;
      overload; static;
  end;

implementation

resourcestring
  SUnsupportedAlgorithm = 'unsupported certificate compression algorithm';
  SBadDeclaredLength = 'the declared uncompressed length is out of range';
  SRatioTooHigh = 'the certificate compression ratio exceeds the bomb guard';
  SLengthMismatch = 'decompressed output length does not match the declared length';
  SDecompressFailed = 'the certificate could not be decompressed';
  SEmptyCompressorOutput = 'a certificate compressor reported success with an empty result';
  SNilCompressionEntry = 'a certificate compression set holds a nil entry';
  SReservedCompressionAlgorithm = 'certificate compression algorithm 0 is reserved';
  SDuplicateCompressionAlgorithm = 'a certificate compression algorithm is listed twice';
  STooManyCompressionAlgorithms = 'at most 127 certificate decompression algorithms can be ' +
    'advertised';

{ TCertificateCompression }

class procedure TCertificateCompression.ValidateCompressors(
  const ACompressors: TArray<ICertificateCompressor>);
var
  LI, LJ: Int32;
begin
  for LI := 0 to System.High(ACompressors) do
  begin
    if ACompressors[LI] = nil then
      raise EArgumentTlsLibException.CreateRes(@SNilCompressionEntry);
    if ACompressors[LI].Algorithm = 0 then
      raise EArgumentTlsLibException.CreateRes(@SReservedCompressionAlgorithm);
    for LJ := 0 to LI - 1 do
      if ACompressors[LJ].Algorithm = ACompressors[LI].Algorithm then
        raise EArgumentTlsLibException.CreateRes(@SDuplicateCompressionAlgorithm);
  end;
end;

class procedure TCertificateCompression.ValidateDecompressors(
  const ADecompressors: TArray<ICertificateDecompressor>);
var
  LI, LJ: Int32;
begin
  if System.Length(ADecompressors) > MaxAdvertisedAlgorithms then
    raise EArgumentTlsLibException.CreateRes(@STooManyCompressionAlgorithms);
  for LI := 0 to System.High(ADecompressors) do
  begin
    if ADecompressors[LI] = nil then
      raise EArgumentTlsLibException.CreateRes(@SNilCompressionEntry);
    if ADecompressors[LI].Algorithm = 0 then
      raise EArgumentTlsLibException.CreateRes(@SReservedCompressionAlgorithm);
    for LJ := 0 to LI - 1 do
      if ADecompressors[LJ].Algorithm = ADecompressors[LI].Algorithm then
        raise EArgumentTlsLibException.CreateRes(@SDuplicateCompressionAlgorithm);
  end;
end;

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
  // sender preference: the first configured compressor the peer can decompress
  for LCompressor in ACompressors do
    if TArrayUtilities.Contains<UInt16>(APeerAlgorithms, LCompressor.Algorithm) then
      Exit(LCompressor);
end;

class function TCertificateCompression.DeriveKey(const ACryptoProvider: ICryptoProvider;
  AAlgorithm: UInt16; const ABody: TBytes): TBytes;
var
  LHash: IHash;
  LPrefix: TBytes;
begin
  SetLength(LPrefix, SizeOf(UInt16));
  TBinaryPrimitives.WriteUInt16BigEndian(LPrefix, 0, AAlgorithm);
  LHash := ACryptoProvider.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LPrefix, 0, System.Length(LPrefix));
  LHash.Update(ABody, 0, System.Length(ABody));
  Result := LHash.DoFinal;
end;

class function TCertificateCompression.TryCompressWithCache(
  const ACache: ICertificateCompressionCache; const ACryptoProvider: ICryptoProvider;
  const ACompressor: ICertificateCompressor; const ABody: TBytes;
  out ACompressed: TBytes): Boolean;
var
  LKey: TBytes;
begin
  ACompressed := nil;
  LKey := nil;
  // content-addressed memoization: hashing ABody is far cheaper than deflating it, so a
  // miss still wins; a hit returns the identical bytes a fresh TryCompress would produce
  if ACache <> nil then
  begin
    LKey := DeriveKey(ACryptoProvider, ACompressor.Algorithm, ABody);
    if ACache.TryGet(LKey, ACompressed) then
      Exit(True);
  end;
  if not ACompressor.TryCompress(ABody, ACompressed) then
  begin
    ACompressed := nil;
    Exit(False);
  end;
  // a success the wire cannot carry (RFC 8879 4: <1..2^24-1>) is a broken compressor, not a decline
  if System.Length(ACompressed) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.InternalError,
      @SEmptyCompressorOutput);
  if ACache <> nil then
    ACache.Put(LKey, ACompressed);
  Result := True;
end;

class function TCertificateCompression.FrameCertificate(
  const ACompressors: TArray<ICertificateCompressor>;
  const APeerAlgorithms: TArray<UInt16>; const ACache: ICertificateCompressionCache;
  const ACryptoProvider: ICryptoProvider; const ABody: TBytes;
  AHasEntries: Boolean): TBytes;
var
  LCompressor: ICertificateCompressor;
  LCompressed: TBytes;
  LMsg: TTlsCompressedCertificate;
begin
  LCompressor := nil;
  // an empty Certificate carries nothing to shrink
  if AHasEntries then
    LCompressor := SelectCompressor(ACompressors, APeerAlgorithms);
  if (LCompressor <> nil) and
    TryCompressWithCache(ACache, ACryptoProvider, LCompressor, ABody, LCompressed) and
    (System.Length(LCompressed) <= MaxCompressedLength) then
  begin
    LMsg.Algorithm := LCompressor.Algorithm;
    LMsg.UncompressedLength := System.Length(ABody);
    LMsg.Compressed := LCompressed;
    Exit(THandshakeFraming.Frame(TTlsHandshakeType.CompressedCertificate,
      THandshakeMessages.EncodeCompressedCertificate(LMsg)));
  end;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.Certificate, ABody);
end;

class function TCertificateCompression.Decompress(
  const ADecompressors: TArray<ICertificateDecompressor>; AAlgorithm: UInt16;
  const ACompressed: TBytes; ADeclaredLength: Int32): TBytes;
begin
  Result := Decompress(ADecompressors, AAlgorithm, ACompressed, ADeclaredLength,
    MaxDecompressedLength);
end;

class function TCertificateCompression.Decompress(
  const ADecompressors: TArray<ICertificateDecompressor>; AAlgorithm: UInt16;
  const ACompressed: TBytes; ADeclaredLength, AMaxLength: Int32): TBytes;
var
  LDecompressor, LFound: ICertificateDecompressor;
  LDone: Boolean;
begin
  Result := nil;
  // an out-of-range declared length is a malformed wire field, not a bad certificate (the size
  // ceiling is local policy; RFC 8879 4 names bad_certificate for a length mismatch and for a
  // message that cannot be decompressed)
  if (ADeclaredLength <= 0) or (ADeclaredLength > AMaxLength) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.IllegalParameter,
      @SBadDeclaredLength);
  // reject an obvious bomb before allocating: a huge declared expansion over the
  // compressed size cannot be a real certificate chain
  if ADeclaredLength > System.Length(ACompressed) * MaxExpansionRatio then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.IllegalParameter,
      @SRatioTooHigh);
  LFound := nil;
  for LDecompressor in ADecompressors do
    if LDecompressor.Algorithm = AAlgorithm then
    begin
      LFound := LDecompressor;
      Break;
    end;
  // an algorithm the peer did not advertise is illegal_parameter (RFC 8879 4 requires a listed
  // algorithm but names no alert; the alert is local policy)
  if LFound = nil then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.IllegalParameter,
      @SUnsupportedAlgorithm);
  // the input is the peer's, so a decompressor that fails or raises has been handed something it
  // cannot decompress: that is the RFC 8879 4 bad_certificate, whatever its own error type
  try
    LDone := LFound.TryDecompress(ACompressed, ADeclaredLength, Result);
  except
    LDone := False;
  end;
  if not LDone then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadCertificate,
      @SDecompressFailed);
  if System.Length(Result) <> ADeclaredLength then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadCertificate,
      @SLengthMismatch);
end;

end.
