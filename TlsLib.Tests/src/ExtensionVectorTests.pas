unit ExtensionVectorTests;

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
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireReader,
  TlpExtensionVector,
  TlsLibTestBase;

type
  /// <summary>
  /// The one extensions&lt;0..2^16-1&gt; codec (RFC 8446 4.2) as a value: byte-exact
  /// Parse/Encode round-trip, the fail-closed parse rules (duplicate -&gt; illegal_parameter,
  /// over-cap / trailing / empty-field -&gt; decode_error), the find/last helpers, the
  /// copy-on-write mutators, and the absolute data offsets used for in-place ECH patching.
  /// </summary>
  TTestExtensionVector = class(TTlsLibTestCase)
  private
    // writes a raw extensions field without any duplicate/cap check, so a malformed field
    // can be constructed for the parse-rule tests
    function MakeField(const ATypes: TArray<UInt16>;
      const ADatas: TArray<TBytes>): TBytes;
    function B(const AValues: array of Byte): TBytes;
    function ParseIsDecodeError(const AField: TBytes): Boolean;
  published
    procedure TestParseEncodeRoundTripByteExact;
    procedure TestEmptyFieldIsDecodeError;
    procedure TestEmptyVectorEncodesTwoZeroBytes;
    procedure TestTrailingBytesAfterVectorIsDecodeError;
    procedure TestTruncatedEntryIsDecodeError;
    procedure TestDuplicateTypeIsIllegalParameter;
    procedure TestSixtyFourEntriesAccepted;
    procedure TestSixtyFifthEntryIsDecodeError;
    procedure TestTryFindAndIndexOf;
    procedure TestTypesInOrder;
    procedure TestIsLast;
    procedure TestInsertBeforeKeepsPskLast;
    procedure TestInsertBeforeAbsentAppends;
    procedure TestInsertAtZeroPrepends;
    procedure TestReplaceRangeCollapsesRun;
    procedure TestSetDataResetsOffset;
    procedure TestDelete;
    procedure TestDataOffsetsAreAbsolute;
    procedure TestCopyDoesNotAlias;
  end;

implementation

function TTestExtensionVector.B(const AValues: array of Byte): TBytes;
var
  LI: Int32;
begin
  System.SetLength(Result, System.Length(AValues));
  for LI := 0 to System.High(AValues) do
    Result[LI] := AValues[LI];
end;

function TTestExtensionVector.MakeField(const ATypes: TArray<UInt16>;
  const ADatas: TArray<TBytes>): TBytes;
var
  LWriter: IWireWriter;
  LOuter, LInner: TWireVectorMarker;
  LI: Int32;
begin
  LWriter := TWireWriter.Create;
  LOuter := LWriter.OpenVector(2);
  for LI := 0 to System.High(ATypes) do
  begin
    LWriter.WriteUInt16(ATypes[LI]);
    LInner := LWriter.OpenVector(2);
    LWriter.WriteBytes(ADatas[LI]);
    LWriter.CloseVector(LInner);
  end;
  LWriter.CloseVector(LOuter);
  Result := LWriter.ToBytes;
end;

function TTestExtensionVector.ParseIsDecodeError(const AField: TBytes): Boolean;
begin
  Result := False;
  try
    TExtensionVector.Parse(AField);
  except
    on EDecodeErrorTlsLibException do
      Result := True;
  end;
end;

procedure TTestExtensionVector.TestParseEncodeRoundTripByteExact;
var
  LField, LReEncoded: TBytes;
  LVec: TExtensionVector;
begin
  // a GREASE type, a zero-length body, and the 0xFFFF edge codepoint
  LField := MakeField(TArray<UInt16>.Create($0A0A, $002B, $FFFF),
    TArray<TBytes>.Create(B([1, 2, 3]), B([]), B([9])));
  LVec := TExtensionVector.Parse(LField);
  CheckEquals(3, LVec.Count, 'three entries');
  LReEncoded := LVec.Encode;
  CheckEquals(System.Length(LField), System.Length(LReEncoded), 'encode length');
  CheckTrue(CompareMem(PByte(LField), PByte(LReEncoded), System.Length(LField)),
    'encode is byte-identical to the parsed field');
end;

procedure TTestExtensionVector.TestEmptyFieldIsDecodeError;
begin
  // an empty field is not the empty vector (that is two zero bytes); the omitted TLS 1.2
  // hello field is the block codec's concern, not this codec's
  CheckTrue(ParseIsDecodeError(nil), 'empty field is a decode_error');
end;

procedure TTestExtensionVector.TestEmptyVectorEncodesTwoZeroBytes;
var
  LBytes: TBytes;
begin
  LBytes := TExtensionVector.Empty.Encode;
  CheckEquals(2, System.Length(LBytes), 'empty vector is a 2-byte length prefix');
  CheckEquals(0, LBytes[0], 'high byte zero');
  CheckEquals(0, LBytes[1], 'low byte zero');
end;

procedure TTestExtensionVector.TestTrailingBytesAfterVectorIsDecodeError;
var
  LField: TBytes;
begin
  LField := MakeField(TArray<UInt16>.Create($0001), TArray<TBytes>.Create(B([1])));
  LField := LField + B([$FF]); // one byte past the vector
  CheckTrue(ParseIsDecodeError(LField),
    'trailing bytes after the vector are a decode_error');
end;

procedure TTestExtensionVector.TestTruncatedEntryIsDecodeError;
begin
  // outer len says 4 but only a 2-byte type follows (no inner length)
  CheckTrue(ParseIsDecodeError(B([$00, $04, $00, $2B])),
    'a truncated entry is a decode_error');
end;

procedure TTestExtensionVector.TestDuplicateTypeIsIllegalParameter;
var
  LField: TBytes;
begin
  LField := MakeField(TArray<UInt16>.Create($002B, $002B),
    TArray<TBytes>.Create(B([1]), B([2])));
  try
    TExtensionVector.Parse(LField);
    Fail('a duplicate extension type must raise');
  except
    on E: EFatalAlertTlsLibException do
      CheckEquals(Ord(TTlsAlertDescription.IllegalParameter), Ord(E.AlertDescription),
        'duplicate -> illegal_parameter');
  end;
end;

procedure TTestExtensionVector.TestSixtyFourEntriesAccepted;
var
  LTypes: TArray<UInt16>;
  LDatas: TArray<TBytes>;
  LI: Int32;
  LVec: TExtensionVector;
begin
  System.SetLength(LTypes, 64);
  System.SetLength(LDatas, 64);
  for LI := 0 to 63 do
  begin
    LTypes[LI] := UInt16(LI);
    LDatas[LI] := B([]);
  end;
  LVec := TExtensionVector.Parse(MakeField(LTypes, LDatas));
  CheckEquals(64, LVec.Count, 'exactly 64 entries is accepted');
end;

procedure TTestExtensionVector.TestSixtyFifthEntryIsDecodeError;
var
  LTypes: TArray<UInt16>;
  LDatas: TArray<TBytes>;
  LI: Int32;
begin
  System.SetLength(LTypes, 65);
  System.SetLength(LDatas, 65);
  for LI := 0 to 64 do
  begin
    LTypes[LI] := UInt16(LI);
    LDatas[LI] := B([]);
  end;
  CheckTrue(ParseIsDecodeError(MakeField(LTypes, LDatas)),
    'a 65th entry is a decode_error');
end;

procedure TTestExtensionVector.TestTryFindAndIndexOf;
var
  LVec: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  LVec := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001, $002B),
    TArray<TBytes>.Create(B([7]), B([8]))));
  CheckEquals(1, LVec.IndexOf($002B), 'IndexOf finds the second entry');
  CheckEquals(-1, LVec.IndexOf($FFFF), 'IndexOf absent is -1');
  CheckTrue(LVec.TryFind($0001, LEntry), 'TryFind hit');
  CheckEquals(7, LEntry.Data[0], 'TryFind returns the entry');
  CheckFalse(LVec.TryFind($FFFF, LEntry), 'TryFind miss');
end;

procedure TTestExtensionVector.TestTypesInOrder;
var
  LTypes: TArray<UInt16>;
begin
  LTypes := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0003, $0001, $0002),
    TArray<TBytes>.Create(B([]), B([]), B([])))).Types;
  CheckEquals(3, System.Length(LTypes), 'three types');
  CheckEquals($0003, LTypes[0], 'order preserved 0');
  CheckEquals($0001, LTypes[1], 'order preserved 1');
  CheckEquals($0002, LTypes[2], 'order preserved 2');
end;

procedure TTestExtensionVector.TestIsLast;
var
  LVec: TExtensionVector;
begin
  LVec := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001, $0029),
    TArray<TBytes>.Create(B([]), B([]))));
  CheckTrue(LVec.IsLast($0029), 'present and last');
  CheckFalse(LVec.IsLast($0001), 'present but not last');
  CheckFalse(LVec.IsLast($FFFF), 'absent');
  CheckFalse(TExtensionVector.Empty.IsLast($0001), 'empty vector');
end;

procedure TTestExtensionVector.TestInsertBeforeKeepsPskLast;
var
  LVec: TExtensionVector;
begin
  // pre_shared_key (0x0029) must stay last (RFC 8446 4.2.11)
  LVec := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001, $0029),
    TArray<TBytes>.Create(B([]), B([]))));
  LVec.InsertBefore($0029, TExtensionEntry.Create($FE0D, B([5])));
  CheckEquals($FE0D, LVec.Types[1], 'inserted before pre_shared_key');
  CheckTrue(LVec.IsLast($0029), 'pre_shared_key stays last');
end;

procedure TTestExtensionVector.TestInsertBeforeAbsentAppends;
var
  LVec: TExtensionVector;
begin
  LVec := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001),
    TArray<TBytes>.Create(B([]))));
  LVec.InsertBefore($0029, TExtensionEntry.Create($FE0D, B([5])));
  CheckTrue(LVec.IsLast($FE0D), 'absent anchor -> appended last');
end;

procedure TTestExtensionVector.TestInsertAtZeroPrepends;
var
  LVec: TExtensionVector;
begin
  LVec := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001),
    TArray<TBytes>.Create(B([]))));
  LVec.InsertAt(0, TExtensionEntry.Create($0000, B([])));
  CheckEquals($0000, LVec.Types[0], 'prepended');
  CheckEquals($0001, LVec.Types[1], 'original shifted');
end;

procedure TTestExtensionVector.TestReplaceRangeCollapsesRun;
var
  LVec: TExtensionVector;
begin
  LVec := TExtensionVector.Parse(MakeField(
    TArray<UInt16>.Create($0001, $0002, $0003, $0004),
    TArray<TBytes>.Create(B([]), B([]), B([]), B([]))));
  // replace the middle two (index 1..2) with one entry
  LVec.ReplaceRange(1, 2, TExtensionEntry.Create($00FD, B([9])));
  CheckEquals(3, LVec.Count, 'run of two collapsed to one');
  CheckEquals($0001, LVec.Types[0], 'head kept');
  CheckEquals($00FD, LVec.Types[1], 'replacement in place');
  CheckEquals($0004, LVec.Types[2], 'tail kept');
end;

procedure TTestExtensionVector.TestSetDataResetsOffset;
var
  LVec: TExtensionVector;
begin
  LVec := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001),
    TArray<TBytes>.Create(B([1, 2]))));
  CheckTrue(LVec.Entries[0].DataOffset >= 0, 'parsed entry has a real offset');
  LVec.SetData(0, B([9, 9, 9]));
  CheckEquals(3, System.Length(LVec.Entries[0].Data), 'data replaced');
  CheckEquals(-1, LVec.Entries[0].DataOffset, 'a constructed body has no offset');
end;

procedure TTestExtensionVector.TestDelete;
var
  LVec: TExtensionVector;
begin
  LVec := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001, $0002, $0003),
    TArray<TBytes>.Create(B([]), B([]), B([]))));
  LVec.Delete(1);
  CheckEquals(2, LVec.Count, 'one removed');
  CheckEquals($0001, LVec.Types[0], 'head kept');
  CheckEquals($0003, LVec.Types[1], 'tail shifted down');
end;

procedure TTestExtensionVector.TestDataOffsetsAreAbsolute;
var
  LBuf: TBytes;
  LReader: TWireReader;
  LVec: TExtensionVector;
begin
  // a 3-byte prefix, then the extensions field: the parsed data offset must be absolute in
  // the whole buffer, not relative to the field (H6/E3 patch received bytes in place)
  LBuf := B([$AA, $BB, $CC]) +
    MakeField(TArray<UInt16>.Create($0001), TArray<TBytes>.Create(B([7])));
  LReader := TWireReader.Create(LBuf);
  LReader.ReadBytes(3); // skip the prefix
  LVec := TExtensionVector.ParseFrom(LReader);
  // 3 prefix + 2 outer len + 2 type + 2 inner len = 9
  CheckEquals(9, LVec.Entries[0].DataOffset, 'data offset is absolute in the buffer');
  CheckEquals(7, LBuf[LVec.Entries[0].DataOffset], 'the offset points at the data');
end;

procedure TTestExtensionVector.TestCopyDoesNotAlias;
var
  LA, LB2: TExtensionVector;
begin
  LA := TExtensionVector.Parse(MakeField(TArray<UInt16>.Create($0001),
    TArray<TBytes>.Create(B([1]))));
  LB2 := LA;              // value copy shares the entry array until a write
  LB2.SetData(0, B([9])); // mutating the copy must not reach LA
  CheckEquals(1, LA.Entries[0].Data[0], 'source is unchanged after mutating the copy');
  CheckEquals(9, LB2.Entries[0].Data[0], 'the copy took the new value');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestExtensionVector);
{$ELSE}
  RegisterTest(TTestExtensionVector.Suite);
{$ENDIF FPC}

end.
