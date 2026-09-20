{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit WireCodecTests;

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
  TlpTlsLibExceptions,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpWireWriter,
  TlsLibTestBase;

type
  TTestWireCodec = class(TTlsLibAlgorithmTestCase)
  published
    // round-trips
    procedure TestUInt8RoundTrip;
    procedure TestUInt16RoundTrip;
    procedure TestUInt24RoundTrip;
    procedure TestUInt32RoundTrip;
    procedure TestBigEndianEncoding;
    procedure TestBytesRoundTrip;
    procedure TestVectorRoundTripEachWidth;
    procedure TestEmptyVector;
    procedure TestNestedVectorsBackPatched;
    procedure TestRemainingAndEndReached;
    // negative / bounds (reader)
    procedure TestTruncatedReadRaises;
    procedure TestVectorLengthExceedsRemainingRaises;
    procedure TestTrailingBytesRejected;
    procedure TestSkipBeyondRaises;
    // negative (writer)
    procedure TestUInt24OverflowRaises;
    procedure TestVectorBodyTooLongRaises;
    procedure TestInvalidPrefixWidthRaises;
    procedure TestGrowthAcrossManyReallocationsRoundTrips;
  end;

implementation

{ TTestWireCodec }

procedure TTestWireCodec.TestUInt8RoundTrip;
var
  LWriter: TWireWriter;
  LReader: TWireReader;
begin
  LWriter := TWireWriter.Create;
  try
    LWriter.WriteUInt8($A5);
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  CheckEquals($A5, LReader.ReadUInt8, 'uint8');
  CheckTrue(LReader.EndReached, 'consumed');
end;

procedure TTestWireCodec.TestUInt16RoundTrip;
var
  LWriter: TWireWriter;
  LReader: TWireReader;
begin
  LWriter := TWireWriter.Create;
  try
    LWriter.WriteUInt16($1234);
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  CheckEquals($1234, LReader.ReadUInt16, 'uint16');
end;

procedure TTestWireCodec.TestUInt24RoundTrip;
var
  LWriter: TWireWriter;
  LReader: TWireReader;
begin
  LWriter := TWireWriter.Create;
  try
    LWriter.WriteUInt24($ABCDEF);
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  CheckEquals(Int64($ABCDEF), Int64(LReader.ReadUInt24), 'uint24');
end;

procedure TTestWireCodec.TestUInt32RoundTrip;
var
  LWriter: TWireWriter;
  LReader: TWireReader;
begin
  LWriter := TWireWriter.Create;
  try
    LWriter.WriteUInt32($DEADBEEF);
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  CheckEquals(Int64($DEADBEEF), Int64(LReader.ReadUInt32), 'uint32');
end;

procedure TTestWireCodec.TestBigEndianEncoding;
var
  LWriter: TWireWriter;
begin
  LWriter := TWireWriter.Create;
  try
    LWriter.WriteUInt32($01020304);
    LWriter.WriteUInt24($AABBCC);
    LWriter.WriteUInt16($5566);
    CheckEqualBytes('big-endian layout',
      DecodeHex('01020304AABBCC5566'), LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
end;

procedure TTestWireCodec.TestBytesRoundTrip;
var
  LWriter: TWireWriter;
  LReader: TWireReader;
  LData: TBytes;
begin
  LData := DecodeHex('00112233445566778899');
  LWriter := TWireWriter.Create;
  try
    LWriter.WriteBytes(LData);
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  CheckEqualBytes('bytes', LData, LReader.ReadBytes(System.Length(LData)));
end;

procedure TTestWireCodec.TestVectorRoundTripEachWidth;
var
  LWidth: Int32;
  LWriter: TWireWriter;
  LReader, LSub: TWireReader;
  LMarker: TWireVectorMarker;
  LBody: TBytes;
begin
  LBody := DecodeHex('CAFEBABE');
  for LWidth := 1 to 3 do
  begin
    LWriter := TWireWriter.Create;
    try
      LMarker := LWriter.OpenVector(LWidth);
      LWriter.WriteBytes(LBody);
      LWriter.CloseVector(LMarker);
      LReader := TWireReader.Create(LWriter.ToBytes);
    finally
      LWriter.Free;
    end;
    LSub := LReader.OpenVector(LWidth);
    CheckEqualBytes('vector body width ' + IntToStr(LWidth),
      LBody, LSub.ReadBytes(LSub.Remaining));
    LSub.ExpectEnd;
    CheckTrue(LReader.EndReached, 'parent consumed width ' + IntToStr(LWidth));
  end;
end;

procedure TTestWireCodec.TestEmptyVector;
var
  LWriter: TWireWriter;
  LReader, LSub: TWireReader;
  LMarker: TWireVectorMarker;
begin
  LWriter := TWireWriter.Create;
  try
    LMarker := LWriter.OpenVector(2);
    LWriter.CloseVector(LMarker);
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  LSub := LReader.OpenVector(2);
  CheckEquals(0, LSub.Remaining, 'empty vector length');
  LSub.ExpectEnd;
end;

procedure TTestWireCodec.TestNestedVectorsBackPatched;
var
  LWriter: TWireWriter;
  LReader, LOuter, LInner: TWireReader;
  LOuterM, LInnerM: TWireVectorMarker;
begin
  LWriter := TWireWriter.Create;
  try
    LOuterM := LWriter.OpenVector(2);
    LInnerM := LWriter.OpenVector(1);
    LWriter.WriteBytes(DecodeHex('4142')); // 'AB'
    LWriter.CloseVector(LInnerM);
    LWriter.WriteUInt16($9999);
    LWriter.CloseVector(LOuterM);
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  LOuter := LReader.OpenVector(2);
  LInner := LOuter.OpenVector(1);
  CheckEqualBytes('inner body', DecodeHex('4142'),
    LInner.ReadBytes(LInner.Remaining));
  LInner.ExpectEnd;
  CheckEquals($9999, LOuter.ReadUInt16, 'trailing uint16');
  LOuter.ExpectEnd;
  LReader.ExpectEnd;
end;

procedure TTestWireCodec.TestRemainingAndEndReached;
var
  LReader: TWireReader;
begin
  LReader := TWireReader.Create(DecodeHex('01020304'));
  CheckEquals(4, LReader.Remaining, 'remaining 4');
  CheckFalse(LReader.EndReached, 'not end');
  LReader.Skip(4);
  CheckEquals(0, LReader.Remaining, 'remaining 0');
  CheckTrue(LReader.EndReached, 'end');
end;

procedure TTestWireCodec.TestTruncatedReadRaises;
var
  LReader: TWireReader;
  LRaised: Boolean;
begin
  LReader := TWireReader.Create(DecodeHex('0102')); // only 2 bytes
  LRaised := False;
  try
    LReader.ReadUInt32;
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'truncated read must raise decode_error');
end;

procedure TTestWireCodec.TestVectorLengthExceedsRemainingRaises;
var
  LReader: TWireReader;
  LRaised: Boolean;
begin
  // 1-byte prefix claims 3 bytes but only 2 follow
  LReader := TWireReader.Create(DecodeHex('034142'));
  LRaised := False;
  try
    LReader.OpenVector(1);
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'over-long vector length must raise decode_error');
end;

procedure TTestWireCodec.TestTrailingBytesRejected;
var
  LReader, LSub: TWireReader;
  LRaised: Boolean;
begin
  // 1-byte prefix = 3, body 'ABC'; consume only 1 byte then ExpectEnd
  LReader := TWireReader.Create(DecodeHex('03414243'));
  LSub := LReader.OpenVector(1);
  LSub.Skip(1);
  LRaised := False;
  try
    LSub.ExpectEnd;
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'trailing bytes must raise decode_error');
end;

procedure TTestWireCodec.TestSkipBeyondRaises;
var
  LReader: TWireReader;
  LRaised: Boolean;
begin
  LReader := TWireReader.Create(DecodeHex('0102'));
  LRaised := False;
  try
    LReader.Skip(5);
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'skip beyond limit must raise decode_error');
end;

procedure TTestWireCodec.TestUInt24OverflowRaises;
var
  LWriter: TWireWriter;
  LRaised: Boolean;
begin
  LWriter := TWireWriter.Create;
  try
    LRaised := False;
    try
      LWriter.WriteUInt24($1000000); // 2^24, out of range
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'uint24 overflow must raise');
  finally
    LWriter.Free;
  end;
end;

procedure TTestWireCodec.TestVectorBodyTooLongRaises;
var
  LWriter: TWireWriter;
  LMarker: TWireVectorMarker;
  LRaised: Boolean;
  LBody: TBytes;
begin
  LWriter := TWireWriter.Create;
  try
    LBody := nil;
    SetLength(LBody, 256); // exceeds a 1-byte prefix (max 255)
    LMarker := LWriter.OpenVector(1);
    LWriter.WriteBytes(LBody);
    LRaised := False;
    try
      LWriter.CloseVector(LMarker);
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'vector body over prefix width must raise');
  finally
    LWriter.Free;
  end;
end;

procedure TTestWireCodec.TestInvalidPrefixWidthRaises;
var
  LWriter: TWireWriter;
  LRaised: Boolean;
begin
  LWriter := TWireWriter.Create;
  try
    LRaised := False;
    try
      LWriter.OpenVector(5);
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'invalid prefix width must raise');
  finally
    LWriter.Free;
  end;
end;

procedure TTestWireCodec.TestGrowthAcrossManyReallocationsRoundTrips;
var
  LWriter: TWireWriter;
  LReader: TWireReader;
  LI: Int32;
  LOk: Boolean;
begin
  // force many buffer reallocations (the wiping-growth path) and confirm the content survives
  LWriter := TWireWriter.Create;
  try
    for LI := 0 to 4999 do
      LWriter.WriteUInt8(Byte(LI and $FF));
    LReader := TWireReader.Create(LWriter.ToBytes);
  finally
    LWriter.Free;
  end;
  LOk := True;
  for LI := 0 to 4999 do
    if LReader.ReadUInt8 <> Byte(LI and $FF) then
      LOk := False;
  CheckTrue(LOk, 'every byte survives repeated growth');
  CheckTrue(LReader.EndReached, 'all consumed');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestWireCodec);
{$ELSE}
  RegisterTest(TTestWireCodec.Suite);
{$ENDIF FPC}

end.
