{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SecretTests;

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
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlsLibTestBase;

type
  TTestSecretBuffer = class(TTlsLibAlgorithmTestCase)
  private
    function ReadBack(const ASecret: ISecretBuffer): TBytes;
    function SignOf(AValue: Int32): Int32;
    procedure CheckOrder(const AName: string; const AA, AB: TBytes; AExpectedSign: Int32);
    procedure CheckCompareMatchesVariableTime(const AName: string; const AA, AB: TBytes);
  published
    procedure TestFromHoldsBytes;
    procedure TestToBytesCopiesSecret;
    procedure TestAllocateIsZeroed;
    procedure TestNegativeAllocateRaises;
    procedure TestEmptyBuffer;
    procedure TestWipePrimitiveZeroes;
    procedure TestConstantTimeAreEqual;
    procedure TestWipeOnLastRelease;
    procedure TestConstantTimeIsAllZeroMatchesVariableTime;
    procedure TestConstantTimeCompareEqualArraysAreZero;
    procedure TestConstantTimeCompareDifferingFirstByteDecides;
    procedure TestConstantTimeCompareDifferingLastByteDecides;
    procedure TestConstantTimeCompareFirstDifferenceBeatsLaterOnes;
    procedure TestConstantTimeCompareBytesAreUnsigned;
    procedure TestConstantTimeComparePrefixSortsFirst;
    procedure TestConstantTimeCompareDifferenceBeatsLength;
    procedure TestConstantTimeCompareEmptyAndNil;
    procedure TestConstantTimeCompareMatchesVariableTimeExhaustively;
    procedure TestConstantTimeCompareMatchesVariableTimeOnRandomEqualLengths;
    procedure TestConstantTimeCompareMatchesVariableTimeOnRandomUnequalLengths;
    procedure TestFromStringHoldsUtf8;
    procedure TestFromStringNonAsciiIsUtf8;
    procedure TestFromStringEmptyIsZeroLength;
    procedure TestSliceCopiesTheRange;
    procedure TestSliceRefusesOutOfRange;
  end;

implementation

{ TTestSecretBuffer }

function TTestSecretBuffer.ReadBack(const ASecret: ISecretBuffer): TBytes;
begin
  Result := nil;
  SetLength(Result, ASecret.Len);
  if ASecret.Len > 0 then
    Move(ASecret.DataPtr^, Result[0], ASecret.Len);
end;

procedure TTestSecretBuffer.TestFromHoldsBytes;
var
  LIn: TBytes;
  LSecret: ISecretBuffer;
begin
  LIn := DecodeHex('00112233445566778899AABBCCDDEEFF');
  LSecret := TSecretBuffer.From(LIn);
  CheckEquals(System.Length(LIn), LSecret.Len, 'Len');
  CheckEqualBytes('From/DataPtr', LIn, ReadBack(LSecret));
end;

procedure TTestSecretBuffer.TestToBytesCopiesSecret;
var
  LIn, LOut: TBytes;
  LSecret: ISecretBuffer;
begin
  LIn := DecodeHex('00112233445566778899AABBCCDDEEFF');
  LSecret := TSecretBuffer.From(LIn);
  LOut := LSecret.ToBytes;
  CheckEqualBytes('ToBytes copy', LIn, LOut);
  // the copy is independent: mutating it must not affect the secret
  LOut[0] := Byte(LOut[0] xor $FF);
  CheckEqualBytes('secret unchanged by copy mutation', LIn, ReadBack(LSecret));
end;

procedure TTestSecretBuffer.TestAllocateIsZeroed;
var
  LSecret: ISecretBuffer;
  LZeros: TBytes;
begin
  LSecret := TSecretBuffer.Allocate(16);
  CheckEquals(16, LSecret.Len, 'Len');
  LZeros := nil;
  SetLength(LZeros, 16);
  CheckEqualBytes('Allocate zero-filled', LZeros, ReadBack(LSecret));
end;

procedure TTestSecretBuffer.TestNegativeAllocateRaises;
var
  LRaised: Boolean;
  LSecret: ISecretBuffer;
begin
  LRaised := False;
  try
    LSecret := TSecretBuffer.Allocate(-1);
    Fail('negative allocation should have raised');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'negative allocation must raise EArgumentTlsLibException');
end;

procedure TTestSecretBuffer.TestEmptyBuffer;
var
  LSecret: ISecretBuffer;
begin
  LSecret := TSecretBuffer.From(nil);
  CheckEquals(0, LSecret.Len, 'empty Len');
  CheckTrue(LSecret.DataPtr = nil, 'empty DataPtr must be nil');
end;

procedure TTestSecretBuffer.TestWipePrimitiveZeroes;
var
  LBuf: PByte;
  LI: Int32;
  LAllZero: Boolean;
begin
  // Deterministic: the buffer is live (not freed) when read back, so this
  // directly asserts the zeroization primitive with no read-after-free.
  GetMem(LBuf, 64);
  try
    FillChar(LBuf^, 64, $FF);
    TSecureMemory.Wipe(LBuf, 64);
    LAllZero := True;
    for LI := 0 to 63 do
      if LBuf[LI] <> 0 then
        LAllZero := False;
    CheckTrue(LAllZero, 'Wipe must zero every byte');
  finally
    FreeMem(LBuf);
  end;
end;

procedure TTestSecretBuffer.TestConstantTimeAreEqual;
var
  LA, LB, LC, LShort: ISecretBuffer;
begin
  LA := TSecretBuffer.From(DecodeHex('00112233445566778899AABBCCDDEEFF'));
  LB := TSecretBuffer.From(DecodeHex('00112233445566778899AABBCCDDEEFF'));
  LC := TSecretBuffer.From(DecodeHex('00112233445566778899AABBCCDDEE00'));
  LShort := TSecretBuffer.From(DecodeHex('0011'));
  CheckTrue(LA.ConstantTimeAreEqual(LB), 'equal secrets compare equal');
  CheckFalse(LA.ConstantTimeAreEqual(LC), 'differing last byte compares unequal');
  CheckFalse(LA.ConstantTimeAreEqual(LShort), 'different lengths compare unequal');
  CheckTrue(TSecretBuffer.From(nil).ConstantTimeAreEqual(TSecretBuffer.From(nil)),
    'two empty secrets compare equal');
end;

procedure TTestSecretBuffer.TestWipeOnLastRelease;
const
  // Bytes the heap manager may reuse at the head of a freed block for its
  // free-list bookkeeping; the wiped tail beyond this must be zero.
  HeaderSlack = 32;
var
  LSecret: ISecretBuffer;
  LSecretBytes, LAfter: TBytes;
  LPtr: PByte;
  LLen, LI, LZeroCount: Int32;
begin
  LSecretBytes := nil;
  SetLength(LSecretBytes, 64);
  for LI := 0 to 63 do
    LSecretBytes[LI] := $A5;
  LSecret := TSecretBuffer.From(LSecretBytes);
  LLen := LSecret.Len;
  // Allocate the read-back buffer before releasing, so it cannot reuse the
  // secret's block; then drop the last reference (the destructor wipes, then
  // frees). Reading the retained pointer afterwards is a controlled
  // read-after-free probe.
  LAfter := nil;
  SetLength(LAfter, LLen);
  LPtr := LSecret.DataPtr;
  LSecret := nil;
  Move(LPtr^, LAfter[0], LLen);
  // The secret must not survive verbatim...
  CheckFalse(AreEqual(LAfter, LSecretBytes),
    'secret must not survive last release');
  // ...and the wiped region must be zero apart from allocator metadata.
  LZeroCount := 0;
  for LI := 0 to LLen - 1 do
    if LAfter[LI] = 0 then
      Inc(LZeroCount);
  CheckTrue(LZeroCount >= LLen - HeaderSlack,
    'wiped secret region must be predominantly zero after release');
end;

procedure TTestSecretBuffer.TestConstantTimeIsAllZeroMatchesVariableTime;
var
  LData: TBytes;
  LLen, LI: Int32;
begin
  // the constant-time test must agree with the fast test on every input
  CheckTrue(TSecureMemory.ConstantTimeIsAllZero(nil), 'an empty array is all-zero');
  CheckTrue(TArrayUtilities.IsAllZero(nil) = TSecureMemory.ConstantTimeIsAllZero(nil),
    'empty agrees');
  for LLen := 1 to 40 do
  begin
    LData := nil;
    SetLength(LData, LLen);
    CheckTrue(TSecureMemory.ConstantTimeIsAllZero(LData), 'a zero-filled array is all-zero');
    CheckTrue(TArrayUtilities.IsAllZero(LData) = TSecureMemory.ConstantTimeIsAllZero(LData),
      'all-zero agrees');
    // a single non-zero byte at each position must be detected by both
    for LI := 0 to LLen - 1 do
    begin
      LData[LI] := $80;
      CheckFalse(TSecureMemory.ConstantTimeIsAllZero(LData), 'a non-zero byte is detected');
      CheckTrue(TArrayUtilities.IsAllZero(LData) = TSecureMemory.ConstantTimeIsAllZero(LData),
        'non-zero agrees');
      LData[LI] := 0;
    end;
  end;
end;

function TTestSecretBuffer.SignOf(AValue: Int32): Int32;
begin
  if AValue < 0 then
    Result := -1
  else if AValue > 0 then
    Result := 1
  else
    Result := 0;
end;

procedure TTestSecretBuffer.CheckOrder(const AName: string; const AA, AB: TBytes;
  AExpectedSign: Int32);
begin
  CheckEquals(AExpectedSign, SignOf(TSecureMemory.ConstantTimeCompareLexicographic(AA, AB)),
    AName + ': A against B');
  CheckEquals(-AExpectedSign, SignOf(TSecureMemory.ConstantTimeCompareLexicographic(AB, AA)),
    AName + ': B against A');
end;

procedure TTestSecretBuffer.CheckCompareMatchesVariableTime(const AName: string;
  const AA, AB: TBytes);
begin
  CheckEquals(SignOf(TArrayUtilities.CompareLexicographic(AA, AB)),
    SignOf(TSecureMemory.ConstantTimeCompareLexicographic(AA, AB)), AName);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareEqualArraysAreZero;
var
  LData: TBytes;
begin
  CheckOrder('one byte', DecodeHex('5A'), DecodeHex('5A'), 0);
  LData := DecodeHex('00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF');
  CheckOrder('thirty-two bytes', LData, System.Copy(LData), 0);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareDifferingFirstByteDecides;
begin
  CheckOrder('first byte smaller', DecodeHex('01FFFFFF'), DecodeHex('02000000'), -1);
  CheckOrder('first byte larger', DecodeHex('03000000'), DecodeHex('02FFFFFF'), 1);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareDifferingLastByteDecides;
begin
  CheckOrder('last byte smaller', DecodeHex('AABBCC01'), DecodeHex('AABBCC02'), -1);
  CheckOrder('last byte larger', DecodeHex('AABBCC03'), DecodeHex('AABBCC02'), 1);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareFirstDifferenceBeatsLaterOnes;
begin
  // the middle byte decides although the last bytes point the other way
  CheckOrder('middle larger', DecodeHex('01090000'), DecodeHex('01020900'), 1);
  CheckOrder('middle smaller', DecodeHex('01020900'), DecodeHex('01090000'), -1);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareBytesAreUnsigned;
begin
  CheckOrder('0x80 against 0x7F', DecodeHex('80'), DecodeHex('7F'), 1);
  CheckOrder('0x00 against 0xFF', DecodeHex('00'), DecodeHex('FF'), -1);
  CheckOrder('0xFF against 0xFE', DecodeHex('FF'), DecodeHex('FE'), 1);
end;

procedure TTestSecretBuffer.TestConstantTimeComparePrefixSortsFirst;
begin
  CheckOrder('one byte longer', DecodeHex('0102'), DecodeHex('010203'), -1);
  CheckOrder('a zero byte longer', DecodeHex('01'), DecodeHex('0100'), -1);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareDifferenceBeatsLength;
begin
  CheckOrder('longer but smaller', DecodeHex('010203'), DecodeHex('02'), -1);
  CheckOrder('shorter but larger', DecodeHex('03'), DecodeHex('010203'), 1);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareEmptyAndNil;
begin
  CheckOrder('nil against nil', nil, nil, 0);
  CheckOrder('nil against one byte', nil, DecodeHex('00'), -1);
  CheckOrder('one byte against nil', DecodeHex('00'), nil, 1);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareMatchesVariableTimeExhaustively;
const
  Values: array [0 .. 7] of Byte = ($00, $01, $7E, $7F, $80, $81, $FE, $FF);
var
  LAll: TArray<TBytes>;
  LCount, LI, LJ, LA, LB: Int32;
begin
  // every array of length 0, 1 and 2 over the boundary byte values, then every pair of them
  LAll := nil;
  SetLength(LAll, 1 + 8 + 64);
  LCount := 1;
  for LI := 0 to 7 do
  begin
    LAll[LCount] := TBytes.Create(Values[LI]);
    Inc(LCount);
  end;
  for LI := 0 to 7 do
    for LJ := 0 to 7 do
    begin
      LAll[LCount] := TBytes.Create(Values[LI], Values[LJ]);
      Inc(LCount);
    end;
  for LA := 0 to LCount - 1 do
    for LB := 0 to LCount - 1 do
      CheckCompareMatchesVariableTime(Format('pair %d, %d', [LA, LB]), LAll[LA], LAll[LB]);
end;

procedure TTestSecretBuffer.TestConstantTimeCompareMatchesVariableTimeOnRandomEqualLengths;
var
  LA, LB: TBytes;
  LShared: Int32;
  LI: Int32;
begin
  for LI := 1 to 1000 do
  begin
    LA := Crypto.Primitives.GetRandom.GenerateBytes(66);
    LB := Crypto.Primitives.GetRandom.GenerateBytes(66);
    // a random-length common prefix, so the deciding byte lands at every position
    LShared := Crypto.Primitives.GetRandom.GenerateBytes(1)[0] mod 67;
    if LShared > 0 then
      Move(LA[0], LB[0], LShared);
    CheckCompareMatchesVariableTime(Format('sample %d', [LI]), LA, LB);
  end;
end;

procedure TTestSecretBuffer.TestConstantTimeCompareMatchesVariableTimeOnRandomUnequalLengths;
var
  LA, LB: TBytes;
  LShared: Int32;
  LI: Int32;
begin
  for LI := 1 to 1000 do
  begin
    LA := Crypto.Primitives.GetRandom.GenerateBytes(66);
    LB := Crypto.Primitives.GetRandom.GenerateBytes(66);
    LShared := Crypto.Primitives.GetRandom.GenerateBytes(1)[0] mod 67;
    if LShared > 0 then
      Move(LA[0], LB[0], LShared);
    // truncate either side, so both the shorter-first and the shorter-second orders occur
    if (Crypto.Primitives.GetRandom.GenerateBytes(1)[0] and 1) = 0 then
      SetLength(LB, Crypto.Primitives.GetRandom.GenerateBytes(1)[0] mod 67)
    else
      SetLength(LA, Crypto.Primitives.GetRandom.GenerateBytes(1)[0] mod 67);
    CheckCompareMatchesVariableTime(Format('sample %d', [LI]), LA, LB);
  end;
end;

procedure TTestSecretBuffer.TestFromStringHoldsUtf8;
var
  LStr: string;
begin
  // FromString carries the passphrase as UTF-8 (so it lives in a wiped buffer, not an immutable
  // string); for ASCII that is the same bytes
  LStr := 'tlslib';
  CheckEqualBytes('ASCII FromString is its UTF-8 octets', DecodeHex('746C736C6962'),
    TSecretBuffer.FromString(LStr).ToBytes);
  CheckEqualBytes('FromString equals UTF8.GetBytes', TEncoding.UTF8.GetBytes(LStr),
    TSecretBuffer.FromString(LStr).ToBytes);
end;

procedure TTestSecretBuffer.TestFromStringNonAsciiIsUtf8;

  procedure CheckRoundTrip(const AHexUtf8, ALabel: string);
  var
    LUtf8: TBytes;
    LStr: string;
  begin
    LUtf8 := DecodeHex(AHexUtf8);
    LStr := TEncoding.UTF8.GetString(LUtf8);
    CheckEqualBytes(ALabel, LUtf8, TSecretBuffer.FromString(LStr).ToBytes);
  end;

begin
  // accented passphrases round-trip as UTF-8; built from known octets so the test does not depend
  // on the source file's encoding
  CheckRoundTrip('636166C3A9', 'e-acute: cafe');
  CheckRoundTrip('C3B1C3BCC3B6C3A7', 'assorted accents: n-tilde u/o-diaeresis c-cedilla');
  CheckRoundTrip('506173732DC3A92D39', 'mixed ASCII and accent: Pass-e-acute-9');
end;

procedure TTestSecretBuffer.TestFromStringEmptyIsZeroLength;
var
  LSecret: ISecretBuffer;
begin
  // an empty string yields a zero-length buffer (an empty passphrase), distinct from nil
  LSecret := TSecretBuffer.FromString('');
  CheckTrue(LSecret <> nil, 'FromString of an empty string returns a buffer, not nil');
  CheckEquals(0, LSecret.Len, 'the buffer is zero-length');
end;

procedure TTestSecretBuffer.TestSliceCopiesTheRange;
var
  LSource, LSlice: ISecretBuffer;
begin
  LSource := TSecretBuffer.From(TBytes.Create(1, 2, 3, 4, 5));
  LSlice := TSecretBuffer.Slice(LSource, 1, 3);
  CheckEqualBytes('the middle of the source', TBytes.Create(2, 3, 4), ReadBack(LSlice));
  CheckEquals(0, TSecretBuffer.Slice(LSource, 5, 0).Len, 'an empty slice at the end');
  CheckEquals(5, TSecretBuffer.Slice(LSource, 0, 5).Len, 'the whole source');
end;

procedure TTestSecretBuffer.TestSliceRefusesOutOfRange;

  function Refused(AOffset, ALength: Int32): Boolean;
  var
    LSource: ISecretBuffer;
  begin
    LSource := TSecretBuffer.From(TBytes.Create(1, 2, 3, 4, 5));
    Result := False;
    try
      TSecretBuffer.Slice(LSource, AOffset, ALength);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  CheckTrue(Refused(0, 6), 'longer than the source');
  CheckTrue(Refused(5, 1), 'starts at the end and asks for more');
  CheckTrue(Refused(-1, 2), 'negative offset');
  CheckTrue(Refused(0, -1), 'negative length');
  // the sum of offset and length would wrap Int32 and pass a 32-bit bound check
  CheckTrue(Refused(High(Int32), 2), 'offset plus length overflows Int32');
  CheckTrue(Refused(2, High(Int32)), 'length plus offset overflows Int32');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSecretBuffer);
{$ELSE}
  RegisterTest(TTestSecretBuffer.Suite);
{$ENDIF FPC}

end.
