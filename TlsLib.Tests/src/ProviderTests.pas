{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ProviderTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpAeadUtilities,
  TlpDefaultCryptoProvider,
  TlpOSCryptoProvider,
  TlpCryptoDomainTypes,
  TlsLibTestBase;

type
  TTestCryptoProvider = class(TTlsLibAlgorithmTestCase)
  private
    function SecretBytes(const ASecret: ISecretBuffer): TBytes;
    function IsAllZero(const AData: TBytes): Boolean;
    function PatternBytes(ALength, ASeed: Int32): TBytes;
    function CounterNonce(ANonceSize, AIndex: Int32): TBytes;
    // Seals a long, varied stream of records through one reused adapter and asserts
    // each sealed output is byte-identical to a fresh create-per-record reference,
    // and that a fresh opener round-trips every record.
    procedure CheckAeadReuseParity(AAlgorithm: TAeadAlgorithm;
      AKeySize, AMinLength: Int32);
    // the in-place AEAD span behaviours, run against whichever provider is passed so the
    // same guarantees are asserted for the portable adapter and the OS-native overlay
    procedure DoAeadInPlaceRoundTrip(const AProvider: ICryptoProvider);
    procedure DoAeadOpenTamperWipes(const AProvider: ICryptoProvider);
    procedure DoAeadSpanGuards(const AProvider: ICryptoProvider);
    procedure DoAeadNonceReuseRejected(const AProvider: ICryptoProvider);
  published
    procedure TestSha256Kat;
    procedure TestSha384Kat;
    procedure TestHashCloneIsIndependent;
    procedure TestHmacSha256Kat;
    procedure TestHkdfSha256Rfc5869;
    procedure TestHkdfExpandRejectsOverCapAndNegative;
    procedure TestAesGcmKat;
    procedure TestAes256GcmKat;
    procedure TestAesGcmRoundTrip;
    procedure TestChaCha20Poly1305Kat;
    procedure TestAeadOpenAuthFailureRaisesBadRecordMac;
    procedure TestAeadInPlaceRoundTripMatchesAllocating;
    procedure TestAeadInPlaceOpenTamperWipesDestination;
    procedure TestAeadSpanGuardsRejectBadOffsetsAndOverlap;
    procedure TestAeadInPlaceNativeProvider;
    procedure TestAeadReuseParityAes128Gcm;
    procedure TestAeadReuseParityAes256Gcm;
    procedure TestAeadReuseParityChaCha20Poly1305;
    procedure TestAeadLongConnectionRoundTrip;
    procedure TestAeadNonceReuseRejected;
    procedure TestAeadNonceReuseRejectedNativeProvider;
    procedure TestRandomDistinctNonZero;
    procedure TestHasHardwareAesReturnsBoolean;
  end;

implementation

{ TTestCryptoProvider }

function TTestCryptoProvider.SecretBytes(const ASecret: ISecretBuffer): TBytes;
begin
  Result := nil;
  SetLength(Result, ASecret.Len);
  if ASecret.Len > 0 then
    Move(ASecret.DataPtr^, Result[0], ASecret.Len);
end;

function TTestCryptoProvider.IsAllZero(const AData: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := True;
  for LI := 0 to System.Length(AData) - 1 do
    if AData[LI] <> 0 then
      Exit(False);
end;

procedure TTestCryptoProvider.TestSha256Kat;
var
  LVec: TStringList;
  LHash: IHash;
  LMsg: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Digest/Sha2.txt');
  try
    LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
    CheckEquals(32, LHash.HashSize, 'SHA-256 size');
    LMsg := DecodeHex(LVec.Values['sha256_msg']);
    LHash.Update(LMsg, 0, System.Length(LMsg));
    CheckEqualBytes('SHA-256(abc)', DecodeHex(LVec.Values['sha256_digest']),
      LHash.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestSha384Kat;
var
  LVec: TStringList;
  LHash: IHash;
  LMsg: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Digest/Sha2.txt');
  try
    LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_384);
    CheckEquals(48, LHash.HashSize, 'SHA-384 size');
    LMsg := DecodeHex(LVec.Values['sha384_msg']);
    LHash.Update(LMsg, 0, System.Length(LMsg));
    CheckEqualBytes('SHA-384(abc)', DecodeHex(LVec.Values['sha384_digest']),
      LHash.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestHashCloneIsIndependent;
var
  LHash, LClone: IHash;
begin
  // both should finish as SHA-256("abc")
  LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(DecodeHex('61'), 0, 1); // 'a'
  LClone := LHash.Clone;
  LHash.Update(DecodeHex('6263'), 0, 2); // 'bc'
  LClone.Update(DecodeHex('6263'), 0, 2);
  CheckEqualBytes('clone independent', LHash.DoFinal, LClone.DoFinal);
end;

procedure TTestCryptoProvider.TestHmacSha256Kat;
var
  LVec: TStringList;
  LHmac: IHmac;
  LData: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Hmac/HmacSha256.txt');
  try
    LHmac := Crypto.Primitives.CreateHmac(THashAlgorithm.SHA_256);
    LHmac.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LData := DecodeHex(LVec.Values['data']);
    LHmac.Update(LData, 0, System.Length(LData));
    CheckEqualBytes('HMAC-SHA256', DecodeHex(LVec.Values['mac']), LHmac.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestHkdfSha256Rfc5869;
var
  LVec: TStringList;
  LHkdf: IHkdf;
  LPrk, LOkm: ISecretBuffer;
begin
  LVec := LoadVectorFields('Crypto/Hkdf/HkdfSha256.txt');
  try
    LHkdf := Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
    LPrk := LHkdf.Extract(TSecretBuffer.From(DecodeHex(LVec.Values['salt'])),
      TSecretBuffer.From(DecodeHex(LVec.Values['ikm'])));
    CheckEqualBytes('HKDF-Extract PRK', DecodeHex(LVec.Values['prk']),
      SecretBytes(LPrk));
    LOkm := LHkdf.Expand(LPrk, DecodeHex(LVec.Values['info']),
      StrToInt(LVec.Values['length']));
    CheckEqualBytes('HKDF-Expand OKM', DecodeHex(LVec.Values['okm']),
      SecretBytes(LOkm));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestHkdfExpandRejectsOverCapAndNegative;
const
  CHashLen = 32;
var
  LHkdf: IHkdf;
  LPrk, LOkm: ISecretBuffer;
  LInfo: TBytes;
  LRaised: Boolean;
begin
  LHkdf := Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
  LPrk := LHkdf.Extract(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')),
    TSecretBuffer.From(DecodeHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')));
  LInfo := DecodeHex('f0f1f2f3f4f5f6f7f8f9');

  LRaised := False;
  try
    LHkdf.Expand(LPrk, LInfo, 255 * CHashLen + 1);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'Expand beyond 255 * HashLen must raise EArgumentTlsLibException');

  LRaised := False;
  try
    LHkdf.Expand(LPrk, LInfo, -1);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'Expand with a negative length must raise EArgumentTlsLibException');

  LOkm := LHkdf.Expand(LPrk, LInfo, 255 * CHashLen);
  CheckEquals(255 * CHashLen, LOkm.Len, 'Expand at the exact cap must succeed');
end;

procedure TTestCryptoProvider.TestAesGcmKat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Gcm/Aes128Gcm.txt');
  try
    LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('AES-128-GCM seal', LExpected, LSealed);
    CheckEqualBytes('AES-128-GCM open', DecodeHex(LVec.Values['plaintext']),
      TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAes256GcmKat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Gcm/Aes256Gcm.txt');
  try
    LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
    CheckEquals(32, LAead.KeySize, 'AES-256-GCM key size');
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('AES-256-GCM seal', LExpected, LSealed);
    CheckEqualBytes('AES-256-GCM open', DecodeHex(LVec.Values['plaintext']),
      TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAesGcmRoundTrip;
var
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed: TBytes;
begin
  LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := DecodeHex('cafe');
  LPlain := DecodeHex('48656c6c6f2c20544c5321'); // "Hello, TLS!"
  LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, LPlain);
  CheckEquals(System.Length(LPlain) + LAead.TagSize, System.Length(LSealed),
    'sealed length = plaintext + tag');
  CheckEqualBytes('AES-GCM round-trip', LPlain, TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
end;

procedure TTestCryptoProvider.TestChaCha20Poly1305Kat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/ChaCha/ChaCha20Poly1305.txt');
  try
    LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.CHACHA20_POLY1305);
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('ChaCha20-Poly1305 seal', LExpected, LSealed);
    CheckEqualBytes('ChaCha20-Poly1305 open', DecodeHex(LVec.Values['plaintext']),
      TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAeadOpenAuthFailureRaisesBadRecordMac;
var
  LAead: IAead;
  LNonce, LAad, LSealed: TBytes;
  LRaised: Boolean;
begin
  LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := DecodeHex('');
  LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex('deadbeef'));
  // corrupt the last (tag) byte
  LSealed[System.Length(LSealed) - 1] := Byte(LSealed[System.Length(LSealed) - 1] xor $01);
  LRaised := False;
  try
    TAeadUtilities.Open(LAead, LNonce, LAad, LSealed);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'auth failure must raise bad_record_mac');
end;

// (algorithm, key size) for each AEAD suite, so the span tests can loop all three
type
  TAeadSuiteSpec = record
    Algorithm: TAeadAlgorithm;
    KeySize: Int32;
    Name: string;
  end;

const
  AeadSuiteSpecs: array [0 .. 2] of TAeadSuiteSpec = (
    (Algorithm: TAeadAlgorithm.AES_128_GCM; KeySize: 16; Name: 'AES-128-GCM'),
    (Algorithm: TAeadAlgorithm.AES_256_GCM; KeySize: 32; Name: 'AES-256-GCM'),
    (Algorithm: TAeadAlgorithm.CHACHA20_POLY1305; KeySize: 32; Name: 'ChaCha20-Poly1305'));
  AeadSpanSizes: array [0 .. 5] of Int32 = (0, 1, 16, 17, 255, 1400);

procedure TTestCryptoProvider.DoAeadInPlaceRoundTrip(const AProvider: ICryptoProvider);
const
  OFF = 5; // seal at a non-zero offset, as the record layer will
var
  LSi, LZi, LLen, LSealed, LOpened: Int32;
  LKey, LNonce, LAad, LPlain, LRef, LBuf: TBytes;
  LEnc, LDec, LRefAead: IAead;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
    for LZi := System.Low(AeadSpanSizes) to System.High(AeadSpanSizes) do
    begin
      LLen := AeadSpanSizes[LZi];
      LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 1);
      LNonce := PatternBytes(12, LSi + 2);
      LAad := PatternBytes(5, LSi + 3);
      LPlain := PatternBytes(LLen, LSi + 4);
      // allocating reference sealed bytes
      LRefAead := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LRefAead.Init(TSecretBuffer.From(LKey));
      LRef := TAeadUtilities.Seal(LRefAead, LNonce, LAad, LPlain);
      // seal in place into a buffer at OFF, aliasing src = dest
      LBuf := nil;
      SetLength(LBuf, OFF + LLen + 16);
      if LLen > 0 then
        System.Move(LPlain[0], LBuf[OFF], LLen);
      LEnc := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LEnc.Init(TSecretBuffer.From(LKey));
      LSealed := LEnc.Seal(LNonce, LAad, LBuf, OFF, LLen, LBuf, OFF);
      CheckEquals(LLen + 16, LSealed, AeadSuiteSpecs[LSi].Name + ': sealed length');
      CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ': in-place seal matches allocating',
        LRef, System.Copy(LBuf, OFF, LSealed));
      // open in place, aliasing src = dest, and recover the plaintext
      LDec := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LDec.Init(TSecretBuffer.From(LKey));
      LOpened := LDec.Open(LNonce, LAad, LBuf, OFF, LSealed, LBuf, OFF);
      CheckEquals(LLen, LOpened, AeadSuiteSpecs[LSi].Name + ': opened length');
      CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ': in-place open round-trips',
        LPlain, System.Copy(LBuf, OFF, LOpened));
    end;
end;

procedure TTestCryptoProvider.DoAeadOpenTamperWipes(const AProvider: ICryptoProvider);
const
  OFF = 3;
var
  LSi, LI, LSealed: Int32;
  LKey, LNonce, LAad, LPlain, LBuf: TBytes;
  LEnc, LDec: IAead;
  LRaised, LWiped: Boolean;
begin
  // the wipe-on-auth-failure path differs per cipher mode, so assert it for every suite
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 7);
    LNonce := PatternBytes(12, LSi + 8);
    LAad := PatternBytes(5, LSi + 9);
    LPlain := PatternBytes(64, LSi + 10);
    LBuf := nil;
    SetLength(LBuf, OFF + 64 + 16);
    System.Move(LPlain[0], LBuf[OFF], 64);
    LEnc := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LEnc.Init(TSecretBuffer.From(LKey));
    LSealed := LEnc.Seal(LNonce, LAad, LBuf, OFF, 64, LBuf, OFF);
    LBuf[OFF + LSealed - 1] := Byte(LBuf[OFF + LSealed - 1] xor $01); // corrupt the tag
    LDec := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LDec.Init(TSecretBuffer.From(LKey));
    LRaised := False;
    try
      LDec.Open(LNonce, LAad, LBuf, OFF, LSealed, LBuf, OFF);
    except
      on E: EFatalAlertTlsLibException do
        LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
    end;
    CheckTrue(LRaised, AeadSuiteSpecs[LSi].Name + ': a tampered tag raises bad_record_mac');
    LWiped := True;
    for LI := OFF to OFF + 64 - 1 do
      if LBuf[LI] <> 0 then
        LWiped := False;
    CheckTrue(LWiped, AeadSuiteSpecs[LSi].Name +
      ': no unverified plaintext is left in the destination after a failed open');
  end;
end;

procedure TTestCryptoProvider.DoAeadSpanGuards(const AProvider: ICryptoProvider);
  function SealRaises(const AAead: IAead; const ANonce, AAad, ASrc: TBytes;
    ASrcOff, ALen: Int32; const ADest: TBytes; ADestOff: Int32): Boolean;
  begin
    Result := False;
    try
      AAead.Seal(ANonce, AAad, ASrc, ASrcOff, ALen, ADest, ADestOff);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;
  function OpenRaisesArg(const AAead: IAead; const ANonce, AAad, ASrc: TBytes;
    ASrcOff, ALen: Int32; const ADest: TBytes; ADestOff: Int32): Boolean;
  begin
    Result := False;
    try
      AAead.Open(ANonce, AAad, ASrc, ASrcOff, ALen, ADest, ADestOff);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;
var
  LKey, LNonce, LAad, LSrc, LDest, LCt, LOut: TBytes;
  LAead, LSealer: IAead;
  LSealed: Int32;
  LRaised: Boolean;
begin
  LKey := PatternBytes(16, 1);
  LNonce := PatternBytes(12, 2);
  LAad := PatternBytes(5, 3);
  LSrc := PatternBytes(32, 4);
  LDest := nil;
  SetLength(LDest, 32 + 16);
  LAead := AProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(LKey));
  // Seal guards (validated before any keyed work, so one instance serves them all)
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, -1, 32, LDest, 0),
    'seal: a negative source offset is rejected');
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, 0, 40, LDest, 0),
    'seal: a length past the source end is rejected');
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, 0, 32, LDest, 8),
    'seal: a destination too small for ciphertext + tag is rejected');
  // same array, different offsets: only an exact alias is allowed
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, 0, 8, LSrc, 4),
    'seal: a partial overlap (same array, unequal offset) is rejected');
  // Open guards: produce one valid sealed buffer, then probe the Open-side checks
  LSealer := AProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LSealer.Init(TSecretBuffer.From(LKey));
  LCt := TAeadUtilities.Seal(LSealer, LNonce, LAad, LSrc); // 32 + 16 = 48 bytes
  LOut := nil;
  SetLength(LOut, 32);
  CheckTrue(OpenRaisesArg(LAead, LNonce, LAad, LCt, -1, 48, LOut, 0),
    'open: a negative source offset is rejected');
  CheckTrue(OpenRaisesArg(LAead, LNonce, LAad, LCt, 0, 60, LOut, 0),
    'open: a length past the source end is rejected');
  CheckTrue(OpenRaisesArg(LAead, LNonce, LAad, LCt, 0, 48, LOut, 20),
    'open: a destination too small for the plaintext is rejected');
  // a length below the tag size cannot authenticate: bad_record_mac, not an argument error
  LRaised := False;
  try
    LAead.Open(LNonce, LAad, LCt, 0, 8, LOut, 0);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'open: a length shorter than the tag raises bad_record_mac');
end;

procedure TTestCryptoProvider.TestAeadInPlaceRoundTripMatchesAllocating;
begin
  DoAeadInPlaceRoundTrip(Crypto);
end;

procedure TTestCryptoProvider.TestAeadInPlaceOpenTamperWipesDestination;
begin
  DoAeadOpenTamperWipes(Crypto);
end;

procedure TTestCryptoProvider.TestAeadSpanGuardsRejectBadOffsetsAndOverlap;
begin
  DoAeadSpanGuards(Crypto);
end;

procedure TTestCryptoProvider.TestAeadInPlaceNativeProvider;
var
  LProvider: ICryptoProvider;
begin
  // the OS-native overlay has its own span implementation; hold it to the same round-trip,
  // tamper-wipe and guard contract. Where no native overlay applies it falls back to the
  // portable adapter, so this stays a valid, if then redundant, run everywhere.
  LProvider := TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider);
  DoAeadInPlaceRoundTrip(LProvider);
  DoAeadOpenTamperWipes(LProvider);
  DoAeadSpanGuards(LProvider);
end;

function TTestCryptoProvider.PatternBytes(ALength, ASeed: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ALength);
  for LI := 0 to ALength - 1 do
    Result[LI] := Byte((LI * 31 + ASeed * 17 + 7) and $FF);
end;

function TTestCryptoProvider.CounterNonce(ANonceSize, AIndex: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ANonceSize);
  FillChar(Result[0], ANonceSize, 0);
  // a distinct, monotonic nonce per record: the record layer's sequence guarantee
  Result[ANonceSize - 1] := Byte(AIndex and $FF);
  Result[ANonceSize - 2] := Byte((AIndex shr 8) and $FF);
end;

procedure TTestCryptoProvider.CheckAeadReuseParity(AAlgorithm: TAeadAlgorithm;
  AKeySize, AMinLength: Int32);
const
  // varied lengths incl. empty, block boundaries, and off-boundary sizes
  CLengths: array [0 .. 11] of Int32 = (0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1400, 5);
var
  LReused, LFresh, LOpener: IAead;
  LKey: ISecretBuffer;
  LKeyBytes, LNonce, LAad, LPlain, LViaReused, LViaFresh: TBytes;
  LNonceSize, LI, LRecord, LLen: Int32;
begin
  LKeyBytes := PatternBytes(AKeySize, 99);
  LKey := TSecretBuffer.From(LKeyBytes);
  LReused := Crypto.Primitives.CreateAead(AAlgorithm);
  LReused.Init(LKey);
  LNonceSize := LReused.NonceSize;
  // a long stream: cycle the length matrix many times so the reused cipher is
  // re-Init'd across hundreds of records
  for LRecord := 0 to 299 do
  begin
    LI := LRecord mod System.Length(CLengths);
    // AES-GCM tolerates an empty record; ChaCha20-Poly1305 requires >= 1 byte,
    // which matches TLS (inner plaintext always carries a content-type byte)
    LLen := CLengths[LI];
    if LLen < AMinLength then
      LLen := AMinLength;
    LPlain := PatternBytes(LLen, LRecord);
    // alternate absent / present associated data
    if (LRecord and 1) = 0 then
      LAad := nil
    else
      LAad := PatternBytes(5 + (LRecord mod 11), LRecord + 3);
    LNonce := CounterNonce(LNonceSize, LRecord);
    // reference: a fresh adapter per record reproduces the old create-per-record path
    LFresh := Crypto.Primitives.CreateAead(AAlgorithm);
    LFresh.Init(LKey);
    LViaFresh := TAeadUtilities.Seal(LFresh, LNonce, LAad, LPlain);
    LViaReused := TAeadUtilities.Seal(LReused, LNonce, LAad, LPlain);
    CheckEqualBytes('reused seal == fresh seal', LViaFresh, LViaReused);
    // a fresh opener must round-trip the reused adapter's output
    LOpener := Crypto.Primitives.CreateAead(AAlgorithm);
    LOpener.Init(LKey);
    CheckEqualBytes('open round-trips reused seal', LPlain,
      TAeadUtilities.Open(LOpener, LNonce, LAad, LViaReused));
  end;
end;

procedure TTestCryptoProvider.TestAeadReuseParityAes128Gcm;
begin
  CheckAeadReuseParity(TAeadAlgorithm.AES_128_GCM, 16, 0);
end;

procedure TTestCryptoProvider.TestAeadReuseParityAes256Gcm;
begin
  CheckAeadReuseParity(TAeadAlgorithm.AES_256_GCM, 32, 0);
end;

procedure TTestCryptoProvider.TestAeadReuseParityChaCha20Poly1305;
begin
  CheckAeadReuseParity(TAeadAlgorithm.CHACHA20_POLY1305, 32, 1);
end;

procedure TTestCryptoProvider.TestAeadLongConnectionRoundTrip;
var
  LSender, LReceiver: IAead;
  LKey: ISecretBuffer;
  LNonce, LAad, LPlain, LSealed: TBytes;
  LEpoch, LRecord: Int32;
begin
  // two epochs (a KeyUpdate boundary): each is a fresh sender/receiver pair, and
  // each pair streams many sequential records with monotonic nonces
  for LEpoch := 0 to 1 do
  begin
    LKey := TSecretBuffer.From(PatternBytes(16, 40 + LEpoch));
    LSender := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LSender.Init(LKey);
    LReceiver := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LReceiver.Init(LKey);
    for LRecord := 0 to 255 do
    begin
      LPlain := PatternBytes(1 + (LRecord mod 200), LRecord + LEpoch);
      LAad := PatternBytes(5, LRecord);
      LNonce := CounterNonce(LSender.NonceSize, LRecord);
      LSealed := TAeadUtilities.Seal(LSender, LNonce, LAad, LPlain);
      CheckEqualBytes('long-connection record round-trips', LPlain,
        TAeadUtilities.Open(LReceiver, LNonce, LAad, LSealed));
    end;
  end;
end;

procedure TTestCryptoProvider.DoAeadNonceReuseRejected(const AProvider: ICryptoProvider);
var
  LAead: IAead;
  LNonce, LOtherNonce, LAad: TBytes;
  LRaised: Boolean;
begin
  // the reused live cipher lets the provider's encrypt-side guard catch a forced
  // (key, nonce) repeat - a net the old create-per-record adapter never had
  LAead := AProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := nil;
  TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex('deadbeef'));
  LRaised := False;
  try
    TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex('cafebabe'));
  except
    on E: Exception do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'reusing a (key, nonce) for seal must be rejected');
  // no false positive: a different nonce under the same key still seals
  LOtherNonce := DecodeHex('101112131415161718191a1c');
  CheckEquals(4 + LAead.TagSize,
    System.Length(TAeadUtilities.Seal(LAead, LOtherNonce, LAad, DecodeHex('cafebabe'))),
    'a fresh nonce under the same key seals');
  // the guard tracks the current key: re-keying opens a fresh nonce space
  LAead.Init(TSecretBuffer.From(DecodeHex('0f0e0d0c0b0a09080706050403020100')));
  CheckEquals(4 + LAead.TagSize,
    System.Length(TAeadUtilities.Seal(LAead, LOtherNonce, LAad, DecodeHex('cafebabe'))),
    'the last nonce is forgotten on re-Init');
end;

procedure TTestCryptoProvider.TestAeadNonceReuseRejected;
begin
  DoAeadNonceReuseRejected(Crypto);
end;

procedure TTestCryptoProvider.TestAeadNonceReuseRejectedNativeProvider;
begin
  // the OS-native overlay owns its own Seal; hold it to the same encrypt-side guard (where
  // no overlay applies this is a second run against the portable adapter)
  DoAeadNonceReuseRejected(
    TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider));
end;

procedure TTestCryptoProvider.TestRandomDistinctNonZero;
var
  LRandom: IRandom;
  LA, LB: TBytes;
begin
  LRandom := Crypto.Primitives.GetRandom;
  LA := LRandom.GenerateBytes(32);
  LB := LRandom.GenerateBytes(32);
  CheckEquals(32, System.Length(LA), 'length');
  CheckFalse(IsAllZero(LA), 'draw must not be all zero');
  CheckFalse(AreEqual(LA, LB), 'two draws must differ');
end;

procedure TTestCryptoProvider.TestHasHardwareAesReturnsBoolean;
var
  LValue: Boolean;
begin
  // the contract is only that it returns a Boolean without throwing
  LValue := Crypto.Primitives.HasHardwareAes;
  CheckTrue((LValue = True) or (LValue = False), 'HasHardwareAes is a Boolean');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCryptoProvider);
{$ELSE}
  RegisterTest(TTestCryptoProvider.Suite);
{$ENDIF FPC}

end.
