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
  TlpTlsVersion,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoDomainTypes,
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
    procedure TestFramedBacklogBoundAndDiscard;
    procedure TestEmptyRecordFloodCapped;
    procedure TestRecordSizeLimitRejectsOversizeInbound;
    procedure TestRecordSizeLimitCountsInnerPlaintextNotContent;
    procedure TestRecordSizeLimitInnerPlaintextBoundary;
    procedure TestWritePausesAppDataAtRekeyThreshold;
    procedure TestChangeCipherSpecDropped;
    procedure TestChangeCipherSpecBeforeHelloRejected;
    procedure TestTls12UnarmedChangeCipherSpecRejected;
    procedure TestChangeCipherSpecFloodCapped;
    procedure TestChangeCipherSpecAfterHandshakeRejected;
    procedure TestMalformedChangeCipherSpecRejected;
    procedure TestArmedReadStaysNullForPlaintextAlert;
    procedure TestArmedReadActivatesOnChangeCipherSpec;
    procedure TestPlaintextHandshakeWhileArmedRejected;
    procedure TestDoubleArmRejected;
    procedure TestUnknownContentTypeRejected;
    procedure TestPartialHeaderDoesNotOverRead;
    procedure TestTerminalAfterFatal;
    procedure TestTakeOutgoingIntoBufferRetainsRemainder;
    procedure TestTakeOutgoingIntoBufferGuardsBadOffset;
  end;

implementation

{ TTestRecordLayer }

function TTestRecordLayer.MakeTls13(const AKey, AIv: TBytes): IRecordProtection;
begin
  Result := TTls13RecordProtection.Create(TSecretBuffer.From(AKey),
    TSecretBuffer.From(AIv), Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
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

procedure TTestRecordLayer.TestFramedBacklogBoundAndDiscard;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LPayload, LWire: TBytes;
begin
  // the framed backlog (complete records queued but not yet pulled) is bounded so a peer cannot
  // stage unbounded ciphertext while the caller is not pulling (e.g. parked / backpressured)
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LPayload := DecodeHex('01020304050607'); // one small handshake record (~12 wire bytes)
    LSend.Write(TTlsContentType.Handshake, LPayload, 0, System.Length(LPayload));
    LWire := LSend.TakeOutgoing;

    LRecv.MaxFramedBacklog := 20; // two of these records exceed it
    CheckFalse(LRecv.InboundBacklogFull, 'an empty layer is not backlog-full');
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    CheckFalse(LRecv.InboundBacklogFull, 'one framed record is under the cap');
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    CheckTrue(LRecv.InboundBacklogFull, 'two framed records reach the cap');

    // pulling one record relieves the backlog
    CheckTrue(LRecv.NextIncoming(LFrag), 'a framed record is pulled');
    CheckFalse(LRecv.InboundBacklogFull, 'pulling one record drops back under the cap');

    // discarding clears everything and resets the counter
    LRecv.DiscardInbound;
    CheckFalse(LRecv.InboundBacklogFull, 'discard clears the backlog');
    CheckFalse(LRecv.NextIncoming(LFrag), 'discard drops the remaining framed record');
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

procedure TTestRecordLayer.TestRecordSizeLimitCountsInnerPlaintextNotContent;
var
  LRecv: TRecordLayer;
  LAead: IAead;
  LKey, LIv, LInner, LHeader, LCipher, LRecord: TBytes;
  LFrag: TTlsRecordFragment;
  LCipherLen: Int32;
  LRaised: Boolean;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LIv := DecodeHex('101112131415161718191a1b');
  // craft a TLS 1.3 record: 10 content bytes, the application_data inner type, then 100
  // padding bytes. Content (10) is well under a 64-byte limit, but the TLSInnerPlaintext
  // (111) is not - padding must not hide the overflow (RFC 8449).
  LInner := nil;
  SetLength(LInner, 111);
  LInner[10] := Byte(Ord(TTlsContentType.ApplicationData)); // rest stay zero (padding)
  LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(LKey));
  LCipherLen := System.Length(LInner) + LAead.TagSize;
  SetLength(LHeader, TRecordLimits.HeaderLength);
  LHeader[0] := Byte(Ord(TTlsContentType.ApplicationData));
  LHeader[1] := $03;
  LHeader[2] := $03;
  LHeader[3] := Byte(LCipherLen shr 8);
  LHeader[4] := Byte(LCipherLen and $FF);
  LCipher := LAead.Seal(LIv, LHeader, LInner); // seq 0 => nonce = IV
  SetLength(LRecord, System.Length(LHeader) + System.Length(LCipher));
  System.Move(LHeader[0], LRecord[0], System.Length(LHeader));
  System.Move(LCipher[0], LRecord[System.Length(LHeader)], System.Length(LCipher));

  LRecv := TRecordLayer.Create;
  try
    LRecv.SetReadProtection(MakeTls13(LKey, LIv));
    LRecv.SetRecordSizeLimit(TRecordLimits.MaxPlaintext, 64);
    LRaised := False;
    try
      LRecv.ProcessInput(LRecord, 0, System.Length(LRecord));
      DrainOne(LRecv, LFrag);
    except
      on E: EFatalAlertTlsLibException do
        LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.RecordOverflow);
    end;
    CheckTrue(LRaised,
      'padding must not hide an over-limit record: TLSInnerPlaintext is measured, not content');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestRecordSizeLimitInnerPlaintextBoundary;
var
  LSend, LRecv: TRecordLayer;
  LKey, LIv, LData, LWire: TBytes;
  LFrag: TTlsRecordFragment;
  LRaised: Boolean;
begin
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
    LIv := DecodeHex('101112131415161718191a1b');
    LSend.SetWriteProtection(MakeTls13(LKey, LIv));
    LRecv.SetReadProtection(MakeTls13(LKey, LIv));
    // limit 64: 63 content bytes make an inner plaintext of exactly 64 (content + type) and
    // must pass; 64 content bytes make 65 and must be record_overflow
    LData := nil;
    SetLength(LData, 64);
    LSend.Write(TTlsContentType.ApplicationData, LData, 0, 63); // inner 64 == limit
    LSend.Write(TTlsContentType.ApplicationData, LData, 0, 64); // inner 65 > limit
    LWire := LSend.TakeOutgoing;
    LRecv.SetRecordSizeLimit(TRecordLimits.MaxPlaintext, 64);
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    CheckTrue(DrainOne(LRecv, LFrag), 'the inner-plaintext-at-limit record is accepted');
    CheckEquals(63, System.Length(LFrag.Data), 'the accepted record carries its content');
    LRaised := False;
    try
      DrainOne(LRecv, LFrag);
    except
      on E: EFatalAlertTlsLibException do
        LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.RecordOverflow);
    end;
    CheckTrue(LRaised, 'the inner-plaintext-over-limit record is record_overflow');
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestWritePausesAppDataAtRekeyThreshold;
var
  LSend: TRecordLayer;
  LProt: IRecordProtection;
  LSeq: IRecordSequenceControl;
  LData: TBytes;
begin
  LSend := TRecordLayer.Create;
  try
    LProt := MakeTls13(DecodeHex('000102030405060708090a0b0c0d0e0f'),
      DecodeHex('101112131415161718191a1b'));
    LSend.SetWriteProtection(LProt);
    // park the write epoch inside its rekey lead (one below the hard AES-GCM limit 23726566)
    CheckTrue(Supports(LProt, IRecordSequenceControl, LSeq), 'sequence control present');
    LSeq.SetSequenceNumber(UInt64(23726566 - 1));
    CheckTrue(LSend.WriteNeedsKeyUpdate, 'the write epoch reached the rekey threshold');
    LData := nil;
    SetLength(LData, 100);
    // application data seals nothing while at the threshold, so the engine can rekey first
    CheckEquals(0, LSend.Write(TTlsContentType.ApplicationData, LData, 0, 100),
      'application data pauses at the rekey threshold');
    CheckEquals(0, System.Length(LSend.TakeOutgoing), 'nothing was sealed for the app data');
    // a control record (handshake) still seals in full so the KeyUpdate itself can go out
    CheckEquals(4, LSend.Write(TTlsContentType.Handshake, LData, 0, 4),
      'a control record still seals at the threshold');
    CheckTrue(System.Length(LSend.TakeOutgoing) > 0, 'the control record reached the wire');
  finally
    LSend.Free;
  end;
end;

procedure TTestRecordLayer.TestChangeCipherSpecDropped;
var
  LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
begin
  LRecv := TRecordLayer.Create;
  try
    // under TLS 1.3 a well-formed legacy CCS (type 20, single 0x01) is middlebox-compat
    // filler: silently discarded
    LRecv.SetNegotiatedVersion(TTlsVersion.Tls13);
    LRecv.ProcessInput(DecodeHex('140303000101'), 0, 6);
    CheckFalse(DrainOne(LRecv, LFrag), 'CCS is not delivered');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestChangeCipherSpecBeforeHelloRejected;
var
  LRecv: TRecordLayer;
begin
  LRecv := TRecordLayer.Create;
  try
    // before any peer hello fixes the version, a change_cipher_spec is out of its legal
    // window (RFC 8446 D.4): unexpected_message, not silently dropped
    CheckTrue(ExpectFatal(LRecv, DecodeHex('140303000101'),
      TTlsAlertDescription.UnexpectedMessage),
      'a change_cipher_spec before the peer hello is unexpected_message');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestTls12UnarmedChangeCipherSpecRejected;
var
  LRecv: TRecordLayer;
begin
  LRecv := TRecordLayer.Create;
  try
    // a TLS 1.2 change_cipher_spec with no read epoch armed (before ClientKeyExchange, or a
    // stray extra one) is out of its legal window, not dropped (RFC 5246 7.1)
    LRecv.SetNegotiatedVersion(TTlsVersion.Tls12);
    CheckTrue(ExpectFatal(LRecv, DecodeHex('140303000101'),
      TTlsAlertDescription.UnexpectedMessage),
      'an unarmed TLS 1.2 change_cipher_spec is unexpected_message');
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
    LRecv.SetNegotiatedVersion(TTlsVersion.Tls13);
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

procedure TTestRecordLayer.TestArmedReadStaysNullForPlaintextAlert;
var
  LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LKey, LIv: TBytes;
begin
  // a read epoch armed for the peer's change_cipher_spec must NOT activate early: a plaintext
  // alert the peer sends before its CCS (an abort) is read under the still-null epoch. Had the
  // epoch activated at arm time, this plaintext alert would fail to decrypt under AEAD keys.
  LRecv := TRecordLayer.Create;
  try
    LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
    LIv := DecodeHex('101112131415161718191a1b');
    LRecv.ArmReadProtectionOnChangeCipherSpec(MakeTls13(LKey, LIv));
    // a fatal alert record (level 2, certificate_revoked 0x2c) in the clear
    LRecv.ProcessInput(DecodeHex('1503030002022c'), 0, 7);
    CheckTrue(DrainOne(LRecv, LFrag), 'the plaintext alert surfaces under the null epoch');
    CheckEquals(Ord(TTlsContentType.Alert), Ord(LFrag.ContentType), 'it is an alert record');
    CheckEqualBytes('the alert body is read verbatim', DecodeHex('022c'), LFrag.Data);
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestArmedReadActivatesOnChangeCipherSpec;
var
  LSend, LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LKey, LIv, LPayload, LWire: TBytes;
begin
  // the armed read epoch activates when the peer's plaintext change_cipher_spec is consumed, so
  // the record that follows it (here an encrypted application_data record standing in for the
  // peer's encrypted Finished) decrypts under the promoted epoch.
  LSend := TRecordLayer.Create;
  LRecv := TRecordLayer.Create;
  try
    LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
    LIv := DecodeHex('101112131415161718191a1b');
    LSend.SetWriteProtection(MakeTls13(LKey, LIv));
    LRecv.ArmReadProtectionOnChangeCipherSpec(MakeTls13(LKey, LIv));
    LPayload := DecodeHex('48656c6c6f'); // "Hello"
    LSend.Write(TTlsContentType.ApplicationData, LPayload, 0, System.Length(LPayload));
    // the peer's CCS immediately precedes its first protected record
    LWire := ConcatBytes(DecodeHex('140303000101'), LSend.TakeOutgoing);
    LRecv.ProcessInput(LWire, 0, System.Length(LWire));
    CheckTrue(DrainOne(LRecv, LFrag), 'the protected record after the CCS decrypts');
    CheckEqualBytes('it decrypts under the promoted epoch', LPayload, LFrag.Data);
    CheckFalse(DrainOne(LRecv, LFrag), 'no extra fragment');
  finally
    LSend.Free;
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestPlaintextHandshakeWhileArmedRejected;
var
  LRecv: TRecordLayer;
  LFrag: TTlsRecordFragment;
  LKey, LIv: TBytes;
  LFailed: Boolean;
begin
  // while a read epoch is armed, a plaintext handshake record before the peer's CCS is illegal:
  // the Finished is the first message under the new cipher spec (RFC 5246 7.4.9). This covers a
  // full-looking record and a lone 5-byte fragment record (a Finished prefix split across the CCS).
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LIv := DecodeHex('101112131415161718191a1b');

  LRecv := TRecordLayer.Create;
  try
    LRecv.ArmReadProtectionOnChangeCipherSpec(MakeTls13(LKey, LIv));
    // a handshake record (type 0x16) with a 4-byte body, no preceding CCS
    CheckTrue(ExpectFatal(LRecv, DecodeHex('160303000401020304'),
      TTlsAlertDescription.UnexpectedMessage),
      'a plaintext handshake record while armed is unexpected_message');
    // the record layer is now in a failed state: any further pull raises
    LFailed := False;
    try
      LRecv.NextIncoming(LFrag);
    except
      on E: EInvalidOperationTlsLibException do
        LFailed := True;
    end;
    CheckTrue(LFailed, 'the layer is terminal after the violation');
  finally
    LRecv.Free;
  end;

  LRecv := TRecordLayer.Create;
  try
    LRecv.ArmReadProtectionOnChangeCipherSpec(MakeTls13(LKey, LIv));
    // a lone 5-byte handshake fragment record, no preceding CCS
    CheckTrue(ExpectFatal(LRecv, DecodeHex('16030300051400000c00'),
      TTlsAlertDescription.UnexpectedMessage),
      'a plaintext handshake fragment while armed is unexpected_message');
  finally
    LRecv.Free;
  end;
end;

procedure TTestRecordLayer.TestDoubleArmRejected;
var
  LRecv: TRecordLayer;
  LKey, LIv: TBytes;
  LRaised: Boolean;
begin
  // one read install per 1.2 handshake; arming twice without an intervening CCS is a caller bug
  LRecv := TRecordLayer.Create;
  try
    LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
    LIv := DecodeHex('101112131415161718191a1b');
    LRecv.ArmReadProtectionOnChangeCipherSpec(MakeTls13(LKey, LIv));
    LRaised := False;
    try
      LRecv.ArmReadProtectionOnChangeCipherSpec(MakeTls13(LKey, LIv));
    except
      on E: EInvalidOperationTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a second arm without a change_cipher_spec is rejected');
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

procedure TTestRecordLayer.TestTakeOutgoingIntoBufferRetainsRemainder;
var
  LLayer, LExpectLayer: TRecordLayer;
  LPayload, LExpected, LChunk, LGot: TBytes;
  LN1, LN2: Int32;
begin
  LLayer := TRecordLayer.Create;
  LExpectLayer := TRecordLayer.Create;
  try
    LPayload := DecodeHex('01020304050607'); // 7 content bytes -> a 12-byte plaintext record
    // an identically framed second layer yields the full-take bytes the chunks must reproduce
    LExpectLayer.Write(TTlsContentType.Handshake, LPayload, 0, System.Length(LPayload));
    LExpected := LExpectLayer.TakeOutgoing;

    LLayer.Write(TTlsContentType.Handshake, LPayload, 0, System.Length(LPayload));
    // take into a fixed 8-byte buffer twice: the first take fills it to capacity, the second
    // drains the retained remainder
    LChunk := nil;
    SetLength(LChunk, 8);
    LN1 := LLayer.TakeOutgoing(LChunk, 0);
    CheckEquals(8, LN1, 'the first take fills the buffer to capacity');
    LGot := System.Copy(LChunk, 0, LN1);
    LN2 := LLayer.TakeOutgoing(LChunk, 0);
    CheckEquals(System.Length(LExpected) - 8, LN2,
      'the second take returns the retained remainder');
    LGot := ConcatBytes(LGot, System.Copy(LChunk, 0, LN2));
    CheckEqualBytes('the two chunks reproduce the full-take bytes', LExpected, LGot);
    CheckEquals(0, LLayer.PendingOutgoing, 'nothing is left pending after both takes');
  finally
    LLayer.Free;
    LExpectLayer.Free;
  end;
end;

procedure TTestRecordLayer.TestTakeOutgoingIntoBufferGuardsBadOffset;
var
  LLayer, LExpectLayer: TRecordLayer;
  LPayload, LExpected, LDest: TBytes;
begin
  LLayer := TRecordLayer.Create;
  LExpectLayer := TRecordLayer.Create;
  try
    LPayload := DecodeHex('01020304050607');
    LExpectLayer.Write(TTlsContentType.Handshake, LPayload, 0, System.Length(LPayload));
    LExpected := LExpectLayer.TakeOutgoing;

    LLayer.Write(TTlsContentType.Handshake, LPayload, 0, System.Length(LPayload));
    LDest := nil;
    SetLength(LDest, 16);
    // a negative destination offset copies nothing
    CheckEquals(0, LLayer.TakeOutgoing(LDest, -1), 'a negative offset takes nothing');
    // a zero-capacity destination (offset at its end) likewise copies nothing
    CheckEquals(0, LLayer.TakeOutgoing(LDest, System.Length(LDest)),
      'a zero-capacity destination takes nothing');
    // neither guarded take consumed anything: a normal take still returns the pending bytes whole
    CheckEqualBytes('the guarded takes left the pending bytes intact', LExpected,
      LLayer.TakeOutgoing);
  finally
    LLayer.Free;
    LExpectLayer.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRecordLayer);
{$ELSE}
  RegisterTest(TTestRecordLayer.Suite);
{$ENDIF FPC}

end.
