{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit RecordLayerTests;

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
  TlpTlsContentType,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpRecordHeader,
  TlpRecordLayer,
  TlsLibTestBase;

type
  TTestRecordLayer = class(TTlsLibAlgorithmTestCase)
  private
    function MakeTls13(const AKey, AIv: TBytes): IRecordProtection;
    function DrainOne(const ALayer: TRecordLayer;
      out AFragment: TTlsRecordFragment): Boolean;
    function ExpectFatal(const ALayer: TRecordLayer; const AWire: TBytes;
      ADescription: TTlsAlertDescription): Boolean;
  published
    procedure TestPlaintextRecordRoundTrip;
    procedure TestRecordSpanningMultipleFeeds;
    procedure TestCoalescedRecordsBothSurface;
    procedure TestOutboundFragmentsAcrossPlaintextLimit;
    procedure TestWriteRejectsOutOfRangeSlice;
    procedure TestProtected13LoopbackTwoRecords;
    procedure TestRecordOverflowOnOverlongLength;
    procedure TestReassemblyCapTripsFatally;
    procedure TestEmptyRecordFloodCapped;
    procedure TestRecordSizeLimitRejectsOversizeInbound;
    procedure TestChangeCipherSpecDropped;
    procedure TestChangeCipherSpecFloodCapped;
    procedure TestChangeCipherSpecAfterHandshakeRejected;
    procedure TestMalformedChangeCipherSpecRejected;
    procedure TestUnknownContentTypeRejected;
    procedure TestPartialHeaderDoesNotOverRead;
    procedure TestTerminalAfterFatal;
  end;

implementation

{ TTestRecordLayer }

function TTestRecordLayer.MakeTls13(const AKey, AIv: TBytes): IRecordProtection;
begin
  Result := TTls13RecordProtection.Create(TSecretBuffer.From(AKey),
    TSecretBuffer.From(AIv), Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
end;

function TTestRecordLayer.DrainOne(const ALayer: TRecordLayer;
  out AFragment: TTlsRecordFragment): Boolean;
begin
  Result := ALayer.NextIncoming(AFragment);
end;

function TTestRecordLayer.ExpectFatal(const ALayer: TRecordLayer;
  const AWire: TBytes; ADescription: TTlsAlertDescription): Boolean;
var
  LFrag: TTlsRecordFragment;
begin
  Result := False;
  try
    ALayer.ProcessInput(AWire, 0, System.Length(AWire));
    // some record-phase violations are decided at the pull side, not at framing (e.g. a
    // plaintext change_cipher_spec, whose legality depends on the handshake-complete state
    // at the moment it is pulled), so drain to surface them
    while ALayer.NextIncoming(LFrag) do
      ;
  except
    on E: EFatalAlertTlsLibException do
      Result := Ord(E.AlertDescription) = Ord(ADescription);
  end;
end;

procedure TTestRecordLayer.TestPlaintextRecordRoundTrip;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LPayload, LWire: TBytes;
begin
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LPayload := DecodeHex('01020304050607');
    LSend.Write(TTlsContentType.Handshake, LPayload, 0, System.Length(LPayload));
    LWire := LSend.TakeOutgoing;
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    CheckTrue(DrainOne(LRecv, LFrag), 'a fragment is delivered');
    CheckEquals(Ord(TTlsContentType.Handshake), Ord(LFrag.ContentType), 'content type');
    CheckEqualBytes('payload round-trips', LPayload, LFrag.Data);
    CheckFalse(DrainOne(LRecv, LFrag), 'no extra fragment');
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestRecordSpanningMultipleFeeds;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LPayload, LRecord: TBytes;
begin
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LPayload := DecodeHex('cafebabedeadbeef1234');
    LSend.Write(TTlsContentType.ApplicationData, LPayload, 0, System.Length(LPayload));
    LRecord := LSend.TakeOutgoing;
    // feed the single record in three slices; nothing surfaces until complete
    LRecv.ProcessInput(LRecord, 0, 3);
    CheckFalse(DrainOne(LRecv, LFrag), 'incomplete after slice 1');
    LRecv.ProcessInput(LRecord, 3, 4);
    CheckFalse(DrainOne(LRecv, LFrag), 'incomplete after slice 2');
    LRecv.ProcessInput(LRecord, 7, System.Length(LRecord) - 7);
    CheckTrue(DrainOne(LRecv, LFrag), 'complete after final slice');
    CheckEqualBytes('spanned payload', LPayload, LFrag.Data);
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestCoalescedRecordsBothSurface;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LA, LB, LWire: TBytes;
begin
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LA := DecodeHex('1111');
    LB := DecodeHex('2222222222');
    LSend.Write(TTlsContentType.Handshake, LA, 0, System.Length(LA));
    LSend.Write(TTlsContentType.ApplicationData, LB, 0, System.Length(LB));
    // both records arrive coalesced in one buffer
    LWire := LSend.TakeOutgoing;
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    CheckTrue(DrainOne(LRecv, LFrag), 'first record');
    CheckEquals(Ord(TTlsContentType.Handshake), Ord(LFrag.ContentType), 'first type');
    CheckEqualBytes('first payload', LA, LFrag.Data);
    CheckTrue(DrainOne(LRecv, LFrag), 'second record');
    CheckEquals(Ord(TTlsContentType.ApplicationData), Ord(LFrag.ContentType),
      'second type');
    CheckEqualBytes('second payload', LB, LFrag.Data);
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestOutboundFragmentsAcrossPlaintextLimit;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LPayload, LReassembled, LWire: TBytes;
  LI: Int32;
begin
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    // 2^14 + 100 bytes must split into two records
    LPayload := nil;
    SetLength(LPayload, 16384 + 100);
    for LI := 0 to System.Length(LPayload) - 1 do
      LPayload[LI] := Byte(LI and $FF);
    LSend.Write(TTlsContentType.ApplicationData, LPayload, 0, System.Length(LPayload));
    LWire := LSend.TakeOutgoing;
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    LReassembled := nil;
    CheckTrue(DrainOne(LRecv, LFrag), 'first fragment');
    CheckEquals(16384, System.Length(LFrag.Data), 'first fragment is a full 2^14');
    LReassembled := ConcatBytes(LReassembled, LFrag.Data);
    CheckTrue(DrainOne(LRecv, LFrag), 'second fragment');
    CheckEquals(100, System.Length(LFrag.Data), 'second fragment is the remainder');
    LReassembled := ConcatBytes(LReassembled, LFrag.Data);
    CheckEqualBytes('fragments reassemble to the original', LPayload, LReassembled);
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestWriteRejectsOutOfRangeSlice;
var
  LSend: TRecordLayer;
  LData: TBytes;
  LRaised: Boolean;
begin
  LSend := TRecordLayer.Create;
  try
    SetLength(LData, 4);
    // offset+length runs past the source: the single Write chokepoint rejects it loudly
    // rather than over-reading heap into a protected record
    LRaised := False;
    try
      LSend.Write(TTlsContentType.ApplicationData, LData, 2, 5);
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'an out-of-range write slice raises EArgumentTlsLibException');
  finally
    LSend.Free;
  end;
end;

procedure TTestRecordLayer.TestProtected13LoopbackTwoRecords;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LKey, LIv, LA, LB, LWire: TBytes;
begin
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
    LIv := DecodeHex('101112131415161718191a1b');
    LSend.SetWriteProtection(MakeTls13(LKey, LIv));
    LRecv.SetReadProtection(MakeTls13(LKey, LIv));
    LA := DecodeHex('48656c6c6f'); // "Hello"
    LB := DecodeHex('576f726c64'); // "World"
    LSend.Write(TTlsContentType.ApplicationData, LA, 0, 5);
    LSend.Write(TTlsContentType.ApplicationData, LB, 0, 5);
    LWire := LSend.TakeOutgoing;
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    CheckTrue(DrainOne(LRecv, LFrag), 'first protected record');
    CheckEqualBytes('first plaintext', LA, LFrag.Data);
    CheckTrue(DrainOne(LRecv, LFrag), 'second protected record (seq advanced)');
    CheckEqualBytes('second plaintext', LB, LFrag.Data);
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestRecordOverflowOnOverlongLength;
var
  LRecv: TRecordLayer;
begin
  LRecv := TRecordLayer.Create;
  try
    // length 0xFFFF exceeds the 1.3 ciphertext cap
    CheckTrue(ExpectFatal(LRecv, DecodeHex('170303FFFF'),
      TTlsAlertDescription.RecordOverflow), 'over-long record -> record_overflow');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestReassemblyCapTripsFatally;
var
  LRecv: TRecordLayer;
  LWire: TBytes;
begin
  LRecv := TRecordLayer.Create;
  try
    LRecv.MaxInboundBuffer := 64;
    // header claims 200 body bytes (within the record cap) but only 100 arrive:
    // 105 buffered bytes exceed the 64-byte reassembly cap
    LWire := ConcatBytes(DecodeHex('17030300C8'), // length 200
      System.Copy(DecodeHex(StringOfChar('a', 200)), 0, 100));
    CheckTrue(ExpectFatal(LRecv, LWire, TTlsAlertDescription.RecordOverflow),
      'reassembly cap -> record_overflow');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestEmptyRecordFloodCapped;
var
  LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LEmpty, LFlood: TBytes;
  LRaised: Boolean;
  LI: Int32;
begin
  LRecv := TRecordLayer.Create;
  try
    LRecv.MaxConsecutiveEmptyRecords := 3;
    LEmpty := DecodeHex('1703030000'); // application_data, length 0
    LFlood := nil;
    for LI := 0 to 4 do
      LFlood := ConcatBytes(LFlood, LEmpty);
    // framing succeeds; the cap trips on the pull side, where a record's emptiness
    // is known only after it is decrypted under the active read epoch
    LRecv.ProcessInput(LFlood, 0, System.Length(LFlood));
    LRaised := False;
    try
      while DrainOne(LRecv, LFrag) do;
    except
      on E: EFatalAlertTlsLibException do
        LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.UnexpectedMessage);
    end;
    CheckTrue(LRaised, 'a flood of empty records is capped');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestRecordSizeLimitRejectsOversizeInbound;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LKey, LIv, LBig, LWire: TBytes;
  LRaised: Boolean;
begin
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
    LIv := DecodeHex('101112131415161718191a1b');
    LSend.SetWriteProtection(MakeTls13(LKey, LIv));
    LRecv.SetReadProtection(MakeTls13(LKey, LIv));
    // advertise a 100-byte inbound plaintext cap; a 200-byte record is record_overflow
    LRecv.SetRecordSizeLimit(TRecordLimits.MaxPlaintext, 100);
    LBig := nil;
    SetLength(LBig, 200);
    LSend.Write(TTlsContentType.ApplicationData, LBig, 0, 200);
    LWire := LSend.TakeOutgoing;
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    LRaised := False;
    try
      DrainOne(LRecv, LFrag);
    except
      on E: EFatalAlertTlsLibException do
        LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.RecordOverflow);
    end;
    CheckTrue(LRaised, 'an inbound record above the record_size_limit is record_overflow');
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestChangeCipherSpecDropped;
var
  LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
begin
  LRecv := TRecordLayer.Create;
  try
    // a well-formed legacy CCS (type 20, single 0x01) is silently discarded
    LRecv.ProcessInput(DecodeHex('140303000101'), 0, 6);
    CheckFalse(DrainOne(LRecv, LFrag), 'CCS is not delivered');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestChangeCipherSpecFloodCapped;
var
  LRecv: TRecordLayer;
  LCcs, LFlood: TBytes;
  LI: Int32;
begin
  LRecv := TRecordLayer.Create;
  try
    LRecv.MaxChangeCipherSpec := 2;
    LCcs := DecodeHex('140303000101'); // one legal middlebox CCS
    LFlood := nil;
    for LI := 0 to 4 do
      LFlood := ConcatBytes(LFlood, LCcs);
    // the first two are tolerated and dropped; the third trips the cap
    CheckTrue(ExpectFatal(LRecv, LFlood, TTlsAlertDescription.UnexpectedMessage),
      'a change_cipher_spec flood is capped');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestChangeCipherSpecAfterHandshakeRejected;
var
  LRecv: TRecordLayer;
begin
  LRecv := TRecordLayer.Create;
  try
    // once the handshake is complete a change_cipher_spec is outside its legal window
    LRecv.SetHandshakeComplete;
    CheckTrue(ExpectFatal(LRecv, DecodeHex('140303000101'),
      TTlsAlertDescription.UnexpectedMessage),
      'a change_cipher_spec after the handshake is unexpected_message');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestMalformedChangeCipherSpecRejected;
var
  LRecv: TRecordLayer;
begin
  LRecv := TRecordLayer.Create;
  try
    // CCS payload must be exactly 0x01
    CheckTrue(ExpectFatal(LRecv, DecodeHex('140303000100'),
      TTlsAlertDescription.UnexpectedMessage), 'CCS with wrong payload rejected');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestUnknownContentTypeRejected;
var
  LRecv: TRecordLayer;
begin
  LRecv := TRecordLayer.Create;
  try
    // outer content type 0x63 is unknown in the plaintext epoch
    CheckTrue(ExpectFatal(LRecv, DecodeHex('630303000101'),
      TTlsAlertDescription.UnexpectedMessage), 'unknown content type rejected');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestPartialHeaderDoesNotOverRead;
var
  LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
begin
  LRecv := TRecordLayer.Create;
  try
    // three header bytes only: buffered, no exception, no over-read
    LRecv.ProcessInput(DecodeHex('160303'), 0, 3);
    CheckFalse(DrainOne(LRecv, LFrag), 'nothing delivered from a partial header');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestTerminalAfterFatal;
var
  LRecv: TRecordLayer;
  LRaised: Boolean;
begin
  LRecv := TRecordLayer.Create;
  try
    ExpectFatal(LRecv, DecodeHex('170303FFFF'), TTlsAlertDescription.RecordOverflow);
    // any further input is refused
    LRaised := False;
    try
      LRecv.ProcessInput(DecodeHex('1703030000'), 0, 5);
    except
      on E: EInvalidOperationTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'the record layer is terminal after a fatal');
  finally
    LRecv.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRecordLayer);
{$ELSE}
  RegisterTest(TTestRecordLayer.Suite);
{$ENDIF FPC}

end.
