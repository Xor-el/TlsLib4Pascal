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
  published
    procedure TestFromHoldsBytes;
    procedure TestToBytesCopiesSecret;
    procedure TestAllocateIsZeroed;
    procedure TestCopyFromRoundTrip;
    procedure TestCopyFromTooLongRaises;
    procedure TestNegativeAllocateRaises;
    procedure TestEmptyBuffer;
    procedure TestWipePrimitiveZeroes;
    procedure TestConstantTimeAreEqual;
    procedure TestWipeOnLastRelease;
    procedure TestConstantTimeIsAllZeroMatchesVariableTime;
    procedure TestFromStringHoldsUtf8;
    procedure TestFromStringNonAsciiIsUtf8;
    procedure TestFromStringEmptyIsZeroLength;
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

procedure TTestSecretBuffer.TestCopyFromRoundTrip;
var
  LIn: TBytes;
  LSecret: ISecretBuffer;
begin
  LIn := DecodeHex('DEADBEEF');
  LSecret := TSecretBuffer.Allocate(System.Length(LIn));
  LSecret.CopyFrom(@LIn[0], System.Length(LIn));
  CheckEqualBytes('CopyFrom round-trip', LIn, ReadBack(LSecret));
end;

procedure TTestSecretBuffer.TestCopyFromTooLongRaises;
var
  LIn: TBytes;
  LSecret: ISecretBuffer;
  LRaised: Boolean;
begin
  LIn := DecodeHex('DEADBEEF');
  LSecret := TSecretBuffer.Allocate(2);
  LRaised := False;
  try
    LSecret.CopyFrom(@LIn[0], System.Length(LIn));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'CopyFrom over-length must raise EArgumentTlsLibException');
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
  LByte: Byte;
begin
  LSecret := TSecretBuffer.From(nil);
  CheckEquals(0, LSecret.Len, 'empty Len');
  CheckTrue(LSecret.DataPtr = nil, 'empty DataPtr must be nil');
  LByte := 0;
  // a zero-length copy is a no-op and must not raise
  LSecret.CopyFrom(@LByte, 0);
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestSecretBuffer);
{$ELSE}
  RegisterTest(TTestSecretBuffer.Suite);
{$ENDIF FPC}

end.
