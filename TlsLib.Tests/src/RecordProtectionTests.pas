{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit RecordProtectionTests;

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
  TlpTlsContentType,
  TlpTlsVersion,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpWireWriter,
  TlsLibTestBase;

type
  TTestRecordProtection = class(TTlsLibAlgorithmTestCase)
  private
    function MakeTls13(const AKey, AIv: TBytes; AAlgorithm: TAeadAlgorithm): IRecordProtection;
    function MakeTls12(const AKey, ASalt: TBytes;
      AAlgorithm: TAeadAlgorithm): IRecordProtection;
    function BigEndian8(AValue: UInt64): TBytes;
  published
    procedure TestTls13RecordKatRfc8448;
    procedure TestNonceDerivation;
    procedure TestTls13RoundTripAcrossLengths;
    procedure TestTls13Aes256RoundTrip;
    procedure TestTls13TamperedTagRaisesBadRecordMac;
    procedure TestTls13SequenceCouplesNonce;
    procedure TestSequenceExhaustionRaises;
    procedure TestNeedsKeyUpdateAtUsageLimit;
    procedure TestProtectFailsAtUsageLimit;
    procedure TestNullRecordProtectionFrames;
    procedure TestTls12Aes128GcmRecord;
    procedure TestTls12ChaCha20RecordRfc7905;
    procedure TestTls12TamperedRaisesBadRecordMac;
  end;

implementation

{ TTestRecordProtection }

function TTestRecordProtection.MakeTls13(const AKey, AIv: TBytes;
  AAlgorithm: TAeadAlgorithm): IRecordProtection;
begin
  Result := TTls13RecordProtection.Create(TSecretBuffer.From(AKey),
    TSecretBuffer.From(AIv), Provider.Primitives.CreateAead(AAlgorithm));
end;

function TTestRecordProtection.MakeTls12(const AKey, ASalt: TBytes;
  AAlgorithm: TAeadAlgorithm): IRecordProtection;
begin
  Result := TTls12RecordProtection.Create(TSecretBuffer.From(AKey),
    TSecretBuffer.From(ASalt), Provider.Primitives.CreateAead(AAlgorithm));
end;

function TTestRecordProtection.BigEndian8(AValue: UInt64): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, 8);
  for LI := 0 to 7 do
    Result[7 - LI] := Byte(AValue shr (8 * LI));
end;

procedure TTestRecordProtection.TestTls13RecordKatRfc8448;
var
  LVec: TStringList;
  LKey, LIv, LPlain, LRecord, LProduced, LRecovered: TBytes;
  LProt: IRecordProtection;
  LType: TTlsContentType;
begin
  LVec := LoadVectorFields('Rfc8448/Tls13RecordFinished.txt');
  try
    LKey := DecodeHex(LVec.Values['key']);
    LIv := DecodeHex(LVec.Values['iv']);
    LPlain := DecodeHex(LVec.Values['plaintext']);
    LRecord := DecodeHex(LVec.Values['record']);

    LProt := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
    LProduced := LProt.Protect(TTlsContentType.Handshake, LPlain, 0,
      System.Length(LPlain));
    CheckEqualBytes('RFC 8448 1.3 record', LRecord, LProduced);

    LProt := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
    LRecovered := LProt.Unprotect(LRecord, 0, System.Length(LRecord), LType);
    CheckEqualBytes('RFC 8448 recovered plaintext', LPlain, LRecovered);
    CheckEquals(Ord(TTlsContentType.Handshake), Ord(LType), 'recovered inner type');
  finally
    LVec.Free;
  end;
end;

procedure TTestRecordProtection.TestNonceDerivation;
var
  LIv, LN0, LN1, LNSeq: TBytes;
begin
  LIv := DecodeHex('5b78923dee08579033e523d9');
  // seq 0 leaves the IV unchanged
  LN0 := TRecordProtectionBase.DeriveNonce(LIv, 0);
  CheckEqualBytes('nonce at seq 0', LIv, LN0);
  // seq 1 flips only the last byte
  LN1 := TRecordProtectionBase.DeriveNonce(LIv, 1);
  CheckEqualBytes('nonce at seq 1',
    DecodeHex('5b78923dee08579033e523d8'), LN1);
  // a multi-byte sequence XORs into the low 8 bytes, big-endian
  LNSeq := TRecordProtectionBase.DeriveNonce(LIv, $0102030405060708);
  CheckEqualBytes('nonce at seq 0x0102030405060708',
    DecodeHex('5b78923def0a549436e324d1'), LNSeq);
end;

procedure TTestRecordProtection.TestTls13RoundTripAcrossLengths;
var
  LKey, LIv, LPlain, LRecord, LBack: TBytes;
  LSend, LRecv: IRecordProtection;
  LType: TTlsContentType;
  LLen: Int32;
  LLengths: array of Int32;
  LK: Int32;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LIv := DecodeHex('101112131415161718191a1b');
  LLengths := [0, 1, 16, 17, 255, 1024];
  for LK := 0 to System.Length(LLengths) - 1 do
  begin
    LLen := LLengths[LK];
    LPlain := DecodeHex(StringOfChar('a', LLen * 2));
    LSend := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
    LRecv := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
    LRecord := LSend.Protect(TTlsContentType.ApplicationData, LPlain, 0, LLen);
    LBack := LRecv.Unprotect(LRecord, 0, System.Length(LRecord), LType);
    CheckEqualBytes(Format('round-trip len %d', [LLen]), LPlain, LBack);
    CheckEquals(Ord(TTlsContentType.ApplicationData), Ord(LType),
      'round-trip inner type');
  end;
end;

procedure TTestRecordProtection.TestTls13Aes256RoundTrip;
var
  LKey, LIv, LPlain, LRecord, LBack: TBytes;
  LSend, LRecv: IRecordProtection;
  LType: TTlsContentType;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f'
    + '101112131415161718191a1b1c1d1e1f');
  LIv := DecodeHex('202122232425262728292a2b');
  LPlain := DecodeHex('48656c6c6f2c20544c5320312e3321'); // "Hello, TLS 1.3!"
  LSend := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_256_GCM);
  LRecv := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_256_GCM);
  LRecord := LSend.Protect(TTlsContentType.Handshake, LPlain, 0, System.Length(LPlain));
  LBack := LRecv.Unprotect(LRecord, 0, System.Length(LRecord), LType);
  CheckEqualBytes('AES-256-GCM 1.3 round-trip', LPlain, LBack);
  CheckEquals(Ord(TTlsContentType.Handshake), Ord(LType), 'inner type');
end;

procedure TTestRecordProtection.TestTls13TamperedTagRaisesBadRecordMac;
var
  LKey, LIv, LPlain, LRecord: TBytes;
  LProt: IRecordProtection;
  LType: TTlsContentType;
  LRaised: Boolean;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LIv := DecodeHex('101112131415161718191a1b');
  LPlain := DecodeHex('deadbeef');
  LProt := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
  LRecord := LProt.Protect(TTlsContentType.ApplicationData, LPlain, 0,
    System.Length(LPlain));
  LRecord[System.Length(LRecord) - 1] :=
    Byte(LRecord[System.Length(LRecord) - 1] xor $01);
  LProt := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
  LRaised := False;
  try
    LProt.Unprotect(LRecord, 0, System.Length(LRecord), LType);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'tampered tag must raise bad_record_mac');
end;

procedure TTestRecordProtection.TestTls13SequenceCouplesNonce;
var
  LKey, LIv, LPlain, LR0, LR1: TBytes;
  LSend, LRecv: IRecordProtection;
  LType: TTlsContentType;
  LRaised: Boolean;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LIv := DecodeHex('101112131415161718191a1b');
  LPlain := DecodeHex('cafe');
  LSend := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
  CheckEquals(0, Int32(LSend.SequenceNumber), 'sequence starts at 0');
  LR0 := LSend.Protect(TTlsContentType.ApplicationData, LPlain, 0, 2);
  LR1 := LSend.Protect(TTlsContentType.ApplicationData, LPlain, 0, 2);
  CheckEquals(2, Int32(LSend.SequenceNumber), 'sequence advanced twice');
  CheckFalse(AreEqual(LR0, LR1), 'same plaintext at different seq differs');

  // in-order decrypt succeeds
  LRecv := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
  LRecv.Unprotect(LR0, 0, System.Length(LR0), LType);
  LRecv.Unprotect(LR1, 0, System.Length(LR1), LType);

  // the seq-1 record cannot be opened at seq 0 (nonce mismatch -> auth fail)
  LRecv := MakeTls13(LKey, LIv, TAeadAlgorithm.AES_128_GCM);
  LRaised := False;
  try
    LRecv.Unprotect(LR1, 0, System.Length(LR1), LType);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'out-of-sequence record must fail authentication');
end;

procedure TTestRecordProtection.TestSequenceExhaustionRaises;
var
  LProt: IRecordProtection;
  LHook: IRecordProtectionTestHook;
  LRaised: Boolean;
begin
  LProt := MakeTls13(DecodeHex('000102030405060708090a0b0c0d0e0f'),
    DecodeHex('101112131415161718191a1b'), TAeadAlgorithm.AES_128_GCM);
  CheckTrue(Supports(LProt, IRecordProtectionTestHook, LHook), 'test hook present');
  LHook.SetSequenceNumber(High(UInt64));
  LRaised := False;
  try
    LProt.Protect(TTlsContentType.ApplicationData, DecodeHex('00'), 0, 1);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'exhausted sequence must raise before reuse');
end;

procedure TTestRecordProtection.TestNeedsKeyUpdateAtUsageLimit;
var
  LProt: IRecordProtection;
  LHook: IRecordProtectionTestHook;
begin
  // AES-GCM usage limit is ~2^24.5 records
  LProt := MakeTls13(DecodeHex('000102030405060708090a0b0c0d0e0f'),
    DecodeHex('101112131415161718191a1b'), TAeadAlgorithm.AES_128_GCM);
  Supports(LProt, IRecordProtectionTestHook, LHook);
  LHook.SetSequenceNumber(UInt64(23726565));
  CheckFalse(LProt.NeedsKeyUpdate, 'below the limit: no key update');
  LHook.SetSequenceNumber(UInt64(23726566));
  CheckTrue(LProt.NeedsKeyUpdate, 'at the limit: key update due');
end;

procedure TTestRecordProtection.TestProtectFailsAtUsageLimit;
var
  LProt: IRecordProtection;
  LHook: IRecordProtectionTestHook;
  LRaised: Boolean;
begin
  // at the AES-GCM usage limit, with no key update wired, Protect must fail loudly
  // rather than seal a record past the safety bound (the sequence is not exhausted)
  LProt := MakeTls13(DecodeHex('000102030405060708090a0b0c0d0e0f'),
    DecodeHex('101112131415161718191a1b'), TAeadAlgorithm.AES_128_GCM);
  CheckTrue(Supports(LProt, IRecordProtectionTestHook, LHook), 'test hook present');
  LHook.SetSequenceNumber(UInt64(23726566));
  LRaised := False;
  try
    LProt.Protect(TTlsContentType.ApplicationData, DecodeHex('00'), 0, 1);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'Protect at the usage limit must fail loudly');
end;

procedure TTestRecordProtection.TestNullRecordProtectionFrames;
var
  LProt: IRecordProtection;
  LPlain, LRecord, LBack: TBytes;
  LType: TTlsContentType;
begin
  LProt := TNullRecordProtection.Create;
  LPlain := DecodeHex('0102030405');
  LRecord := LProt.Protect(TTlsContentType.Handshake, LPlain, 0, 5);
  // header is type(22) version(0303) length(0005) then the body verbatim
  CheckEqualBytes('null-framed record', DecodeHex('16030300050102030405'), LRecord);
  LBack := LProt.Unprotect(LRecord, 0, System.Length(LRecord), LType);
  CheckEqualBytes('null recovered', LPlain, LBack);
  CheckEquals(Ord(TTlsContentType.Handshake), Ord(LType), 'null content type');
end;

procedure TTestRecordProtection.TestTls12Aes128GcmRecord;
var
  LVec: TStringList;
  LKey, LSalt, LPlain: TBytes;
  LExplicitNonce, LGcmNonce, LAad, LCipher, LBody, LExpected, LProduced,
    LRecovered: TBytes;
  LAeadRef: IAead;
  LHeaderWriter, LAadWriter: TWireWriter;
  LProt: IRecordProtection;
  LType: TTlsContentType;
begin
  LVec := LoadVectorFields('Tls12Aead/Tls12Aes128GcmRecord.txt');
  try
    LKey := DecodeHex(LVec.Values['key']);
    LSalt := DecodeHex(LVec.Values['salt']);
    LPlain := DecodeHex(LVec.Values['plaintext']);

    // Independent reference framing over the KAT-verified AEAD.
    LExplicitNonce := BigEndian8(0);
    LGcmNonce := ConcatBytes(LSalt, LExplicitNonce);
    LAadWriter := TWireWriter.Create;
    try
      LAadWriter.WriteBytes(BigEndian8(0));
      LAadWriter.WriteUInt8(23);
      LAadWriter.WriteUInt16(TlsWireVersionTls12);
      LAadWriter.WriteUInt16(UInt16(System.Length(LPlain)));
      LAad := LAadWriter.ToBytes;
    finally
      LAadWriter.Free;
    end;
    LAeadRef := Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LAeadRef.Init(TSecretBuffer.From(LKey));
    LCipher := LAeadRef.Seal(LGcmNonce, LAad, LPlain);
    LBody := ConcatBytes(LExplicitNonce, LCipher);
    LHeaderWriter := TWireWriter.Create;
    try
      LHeaderWriter.WriteUInt8(23);
      LHeaderWriter.WriteUInt16(TlsWireVersionTls12);
      LHeaderWriter.WriteUInt16(UInt16(System.Length(LBody)));
      LExpected := ConcatBytes(LHeaderWriter.ToBytes, LBody);
    finally
      LHeaderWriter.Free;
    end;

    LProt := MakeTls12(LKey, LSalt, TAeadAlgorithm.AES_128_GCM);
    LProduced := LProt.Protect(TTlsContentType.ApplicationData, LPlain, 0,
      System.Length(LPlain));
    CheckEqualBytes('TLS 1.2 AES-128-GCM record', LExpected, LProduced);

    LProt := MakeTls12(LKey, LSalt, TAeadAlgorithm.AES_128_GCM);
    LRecovered := LProt.Unprotect(LProduced, 0, System.Length(LProduced), LType);
    CheckEqualBytes('TLS 1.2 recovered plaintext', LPlain, LRecovered);
    CheckEquals(Ord(TTlsContentType.ApplicationData), Ord(LType), '1.2 content type');
  finally
    LVec.Free;
  end;
end;

procedure TTestRecordProtection.TestTls12ChaCha20RecordRfc7905;
var
  LKey, LIv, LPlain, LNonce, LAad, LCipher, LBody, LExpected, LProduced,
    LRecovered: TBytes;
  LAeadRef: IAead;
  LAadWriter, LHeaderWriter: TWireWriter;
  LProt: IRecordProtection;
  LType: TTlsContentType;
  LI: Int32;
begin
  // RFC 7905: TLS 1.2 ChaCha20-Poly1305 uses the 12-byte write IV XORed with the sequence
  // number as the nonce, with NO explicit nonce on the wire - unlike AES-GCM (RFC 5288).
  // The framing is verified against an independent reference over the (KAT-checked) AEAD, so
  // the explicit-nonce construction (correct only for GCM) would fail here.
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f'
    + '101112131415161718191a1b1c1d1e1f');
  LIv := DecodeHex('202122232425262728292a2b');
  // a large (2^14) record - the size at which the 1.2-ChaCha framing bug surfaced
  SetLength(LPlain, 16384);
  for LI := 0 to System.Length(LPlain) - 1 do
    LPlain[LI] := Byte(LI and $FF);

  // independent reference framing at sequence 0
  LNonce := TRecordProtectionBase.DeriveNonce(LIv, 0);
  LAadWriter := TWireWriter.Create;
  try
    LAadWriter.WriteBytes(BigEndian8(0));
    LAadWriter.WriteUInt8(23);
    LAadWriter.WriteUInt16(TlsWireVersionTls12);
    LAadWriter.WriteUInt16(UInt16(System.Length(LPlain)));
    LAad := LAadWriter.ToBytes;
  finally
    LAadWriter.Free;
  end;
  LAeadRef := Provider.Primitives.CreateAead(TAeadAlgorithm.CHACHA20_POLY1305);
  LAeadRef.Init(TSecretBuffer.From(LKey));
  LCipher := LAeadRef.Seal(LNonce, LAad, LPlain);
  // no explicit nonce: the record body is exactly the ciphertext
  LBody := LCipher;
  LHeaderWriter := TWireWriter.Create;
  try
    LHeaderWriter.WriteUInt8(23);
    LHeaderWriter.WriteUInt16(TlsWireVersionTls12);
    LHeaderWriter.WriteUInt16(UInt16(System.Length(LBody)));
    LExpected := ConcatBytes(LHeaderWriter.ToBytes, LBody);
  finally
    LHeaderWriter.Free;
  end;

  LProt := MakeTls12(LKey, LIv, TAeadAlgorithm.CHACHA20_POLY1305);
  LProduced := LProt.Protect(TTlsContentType.ApplicationData, LPlain, 0,
    System.Length(LPlain));
  CheckEqualBytes('TLS 1.2 ChaCha20-Poly1305 record (RFC 7905)', LExpected, LProduced);
  // the body carries no explicit nonce: 5-byte header + ciphertext + 16-byte tag only
  CheckEquals(5 + System.Length(LPlain) + 16,
    System.Length(LProduced), '1.2 ChaCha record has no explicit nonce');

  LProt := MakeTls12(LKey, LIv, TAeadAlgorithm.CHACHA20_POLY1305);
  LRecovered := LProt.Unprotect(LProduced, 0, System.Length(LProduced), LType);
  CheckEqualBytes('TLS 1.2 ChaCha recovered plaintext', LPlain, LRecovered);
  CheckEquals(Ord(TTlsContentType.ApplicationData), Ord(LType), '1.2 ChaCha content type');
end;

procedure TTestRecordProtection.TestTls12TamperedRaisesBadRecordMac;
var
  LKey, LSalt, LPlain, LRecord: TBytes;
  LProt: IRecordProtection;
  LType: TTlsContentType;
  LRaised: Boolean;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LSalt := DecodeHex('cafebabe');
  LPlain := DecodeHex('54616d706572'); // "Tamper"
  LProt := MakeTls12(LKey, LSalt, TAeadAlgorithm.AES_128_GCM);
  LRecord := LProt.Protect(TTlsContentType.ApplicationData, LPlain, 0,
    System.Length(LPlain));
  LRecord[System.Length(LRecord) - 1] :=
    Byte(LRecord[System.Length(LRecord) - 1] xor $01);
  LProt := MakeTls12(LKey, LSalt, TAeadAlgorithm.AES_128_GCM);
  LRaised := False;
  try
    LProt.Unprotect(LRecord, 0, System.Length(LRecord), LType);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'tampered 1.2 record must raise bad_record_mac');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRecordProtection);
{$ELSE}
  RegisterTest(TTestRecordProtection.Suite);
{$ENDIF FPC}

end.
