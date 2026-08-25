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
  TlpCryptoAlgorithms,
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
  published
    procedure TestSha256Kat;
    procedure TestSha384Kat;
    procedure TestHashCloneIsIndependent;
    procedure TestHmacSha256Kat;
    procedure TestHkdfSha256Rfc5869;
    procedure TestAesGcmKat;
    procedure TestAes256GcmKat;
    procedure TestAesGcmRoundTrip;
    procedure TestChaCha20Poly1305Kat;
    procedure TestAeadOpenAuthFailureRaisesBadRecordMac;
    procedure TestAeadReuseParityAes128Gcm;
    procedure TestAeadReuseParityAes256Gcm;
    procedure TestAeadReuseParityChaCha20Poly1305;
    procedure TestAeadLongConnectionRoundTrip;
    procedure TestAeadNonceReuseRejected;
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
    LHash := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256);
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
    LHash := Provider.Primitives.CreateHash(THashAlgorithm.SHA_384);
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
  LHash := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256);
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
    LHmac := Provider.Primitives.CreateHmac(THashAlgorithm.SHA_256);
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
    LHkdf := Provider.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
    LPrk := LHkdf.Extract(DecodeHex(LVec.Values['salt']),
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

procedure TTestCryptoProvider.TestAesGcmKat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Gcm/Aes128Gcm.txt');
  try
    LAead := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := LAead.Seal(LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('AES-128-GCM seal', LExpected, LSealed);
    CheckEqualBytes('AES-128-GCM open', DecodeHex(LVec.Values['plaintext']),
      LAead.Open(LNonce, LAad, LSealed));
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
    LAead := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
    CheckEquals(32, LAead.KeySize, 'AES-256-GCM key size');
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := LAead.Seal(LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('AES-256-GCM seal', LExpected, LSealed);
    CheckEqualBytes('AES-256-GCM open', DecodeHex(LVec.Values['plaintext']),
      LAead.Open(LNonce, LAad, LSealed));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAesGcmRoundTrip;
var
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed: TBytes;
begin
  LAead := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := DecodeHex('cafe');
  LPlain := DecodeHex('48656c6c6f2c20544c5321'); // "Hello, TLS!"
  LSealed := LAead.Seal(LNonce, LAad, LPlain);
  CheckEquals(System.Length(LPlain) + LAead.Overhead, System.Length(LSealed),
    'sealed length = plaintext + overhead');
  CheckEqualBytes('AES-GCM round-trip', LPlain, LAead.Open(LNonce, LAad, LSealed));
end;

procedure TTestCryptoProvider.TestChaCha20Poly1305Kat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/ChaCha/ChaCha20Poly1305.txt');
  try
    LAead := Provider.Primitives.CreateAead(TAeadAlgorithm.CHACHA20_POLY1305);
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := LAead.Seal(LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('ChaCha20-Poly1305 seal', LExpected, LSealed);
    CheckEqualBytes('ChaCha20-Poly1305 open', DecodeHex(LVec.Values['plaintext']),
      LAead.Open(LNonce, LAad, LSealed));
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
  LAead := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := DecodeHex('');
  LSealed := LAead.Seal(LNonce, LAad, DecodeHex('deadbeef'));
  // corrupt the last (tag) byte
  LSealed[System.Length(LSealed) - 1] := Byte(LSealed[System.Length(LSealed) - 1] xor $01);
  LRaised := False;
  try
    LAead.Open(LNonce, LAad, LSealed);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'auth failure must raise bad_record_mac');
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
  LReused := Provider.Primitives.CreateAead(AAlgorithm);
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
    LFresh := Provider.Primitives.CreateAead(AAlgorithm);
    LFresh.Init(LKey);
    LViaFresh := LFresh.Seal(LNonce, LAad, LPlain);
    LViaReused := LReused.Seal(LNonce, LAad, LPlain);
    CheckEqualBytes('reused seal == fresh seal', LViaFresh, LViaReused);
    // a fresh opener must round-trip the reused adapter's output
    LOpener := Provider.Primitives.CreateAead(AAlgorithm);
    LOpener.Init(LKey);
    CheckEqualBytes('open round-trips reused seal', LPlain,
      LOpener.Open(LNonce, LAad, LViaReused));
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
    LSender := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LSender.Init(LKey);
    LReceiver := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LReceiver.Init(LKey);
    for LRecord := 0 to 255 do
    begin
      LPlain := PatternBytes(1 + (LRecord mod 200), LRecord + LEpoch);
      LAad := PatternBytes(5, LRecord);
      LNonce := CounterNonce(LSender.NonceSize, LRecord);
      LSealed := LSender.Seal(LNonce, LAad, LPlain);
      CheckEqualBytes('long-connection record round-trips', LPlain,
        LReceiver.Open(LNonce, LAad, LSealed));
    end;
  end;
end;

procedure TTestCryptoProvider.TestAeadNonceReuseRejected;
var
  LAead: IAead;
  LNonce, LAad: TBytes;
  LRaised: Boolean;
begin
  // the reused live cipher lets CL4P's encrypt-side guard catch a forced
  // (key, nonce) repeat - a net the old create-per-record adapter never had
  LAead := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := nil;
  LAead.Seal(LNonce, LAad, DecodeHex('deadbeef'));
  LRaised := False;
  try
    LAead.Seal(LNonce, LAad, DecodeHex('cafebabe'));
  except
    on E: Exception do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'reusing a (key, nonce) for seal must be rejected');
end;

procedure TTestCryptoProvider.TestRandomDistinctNonZero;
var
  LRandom: IRandom;
  LA, LB: TBytes;
begin
  LRandom := Provider.Primitives.GetRandom;
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
  LValue := Provider.Primitives.HasHardwareAes;
  CheckTrue((LValue = True) or (LValue = False), 'HasHardwareAes is a Boolean');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCryptoProvider);
{$ELSE}
  RegisterTest(TTestCryptoProvider.Suite);
{$ENDIF FPC}

end.
