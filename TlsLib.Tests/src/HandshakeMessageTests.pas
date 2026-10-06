{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HandshakeMessageTests;

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
  TlpTlsLibExceptions,
  TlpHandshakeMessage,
  TlsLibTestBase;

type
  TTestHandshakeMessage = class(TTlsLibAlgorithmTestCase)
  private
    function Msg(const AName: string): TBytes;
    function Framed(AType: TTlsHandshakeType; ABodyLength: Int32; AFill: Byte): TBytes;
    procedure CheckMessage(const AWhat: string; const AFramed: TBytes;
      const AMessage: TTlsHandshakeMessage);
  published
    procedure TestReassemblyCapIgnoresConsumedPrefixOfAPartialTail;
    procedure TestOutOfRangeSliceIsRejected;
    procedure TestSmallFragmentsReassembleSeveralMessages;
    procedure TestGrowthAfterPartialConsumptionKeepsTheTail;
    procedure TestReassemblyCapCountsOnlyUnconsumedBytes;
    procedure TestReassemblyCapIsExact;
    procedure TestHandshakeTypeCodec;
    procedure TestFrameRoundTrip;
    procedure TestReassemblyAcrossFragments;
    procedure TestCoalescedMessages;
    procedure TestPartialMessageNeedsMore;
    procedure TestOversizedMessageIsDecodeError;
    procedure TestOversizedNonCertificateMessageIsDecodeError;
    procedure TestMessageHashIsNotWireDecodable;
  end;

implementation

var
  GVectors: TStringList = nil;

function TTestHandshakeMessage.Msg(const AName: string): TBytes;
begin
  if GVectors = nil then
    GVectors := LoadVectorFields('Rfc8448/HandshakeMessages.txt');
  Result := DecodeHex(GVectors.Values[AName]);
end;

function TTestHandshakeMessage.Framed(AType: TTlsHandshakeType; ABodyLength: Int32;
  AFill: Byte): TBytes;
var
  LBody: TBytes;
  LIdx: Int32;
begin
  System.SetLength(LBody, ABodyLength);
  for LIdx := 0 to ABodyLength - 1 do
    LBody[LIdx] := Byte(AFill + LIdx);
  Result := THandshakeFraming.Frame(AType, LBody);
end;

procedure TTestHandshakeMessage.CheckMessage(const AWhat: string; const AFramed: TBytes;
  const AMessage: TTlsHandshakeMessage);
begin
  CheckEquals(AFramed[0], AMessage.TypeByte, AWhat + ': type');
  CheckEqualBytes(AWhat + ': body', System.Copy(AFramed, 4, System.Length(AFramed) - 4),
    AMessage.Body);
  CheckEqualBytes(AWhat + ': raw', AFramed, AMessage.Raw);
end;

procedure TTestHandshakeMessage.TestReassemblyCapIgnoresConsumedPrefixOfAPartialTail;
var
  LDone, LPartial, LWire: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
begin
  LDone := Framed(TTlsHandshakeType.Finished, 32, 0); // 36 bytes
  LPartial := Framed(TTlsHandshakeType.Finished, 32, 5);
  LWire := ConcatBytes(LDone, System.Copy(LPartial, 0, 20));
  LReader := THandshakeMessageReader.Create;
  try
    LReader.MaxTotalLength := 60;
    LReader.Append(LWire, 0, System.Length(LWire)); // 56 held
    CheckTrue(LReader.NextMessage(LMsg), 'the whole message is consumed');
    // 20 bytes remain live while the consumed 36 still sit before them: 20 + 16 fits the cap,
    // but counting the consumed prefix (56 + 16) would not
    LReader.Append(LPartial, 20, 16);
    CheckTrue(LReader.NextMessage(LMsg), 'the partial tail completes');
    CheckMessage('completed tail', LPartial, LMsg);
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestOutOfRangeSliceIsRejected;
var
  LReader: THandshakeMessageReader;
  LWire: TBytes;
  LRaised: Boolean;
begin
  LWire := Framed(TTlsHandshakeType.Finished, 4, 0);
  LReader := THandshakeMessageReader.Create;
  try
    LRaised := False;
    try
      LReader.Append(LWire, 4, System.Length(LWire));
    except
      on EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a slice past the end of the buffer is a caller error');
    CheckFalse(LReader.HasPartial, 'nothing was buffered');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestSmallFragmentsReassembleSeveralMessages;
var
  LFirst, LSecond, LThird, LWire: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LPos, LChunk, LSeen: Int32;
begin
  LFirst := Framed(TTlsHandshakeType.EncryptedExtensions, 5000, 1);
  LSecond := Framed(TTlsHandshakeType.Finished, 0, 0);
  LThird := Framed(TTlsHandshakeType.Certificate, 40000, 9);
  LWire := ConcatBytes(ConcatBytes(LFirst, LSecond), LThird);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.MaxCertificateMessageLength := 50000;
    LSeen := 0;
    LPos := 0;
    while LPos < System.Length(LWire) do
    begin
      LChunk := 7;
      if LChunk > System.Length(LWire) - LPos then
        LChunk := System.Length(LWire) - LPos;
      LReader.Append(LWire, LPos, LChunk);
      Inc(LPos, LChunk);
      while LReader.NextMessage(LMsg) do
      begin
        case LSeen of
          0: CheckMessage('first message', LFirst, LMsg);
          1: CheckMessage('second message', LSecond, LMsg);
          2: CheckMessage('third message', LThird, LMsg);
        end;
        Inc(LSeen);
      end;
    end;
    CheckEquals(3, LSeen, 'all three messages came out');
    CheckFalse(LReader.HasPartial, 'nothing left over');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestGrowthAfterPartialConsumptionKeepsTheTail;
var
  LFirst, LSecond, LWire: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
begin
  // the first feed holds one whole message and the start of another; the second feed does not
  // fit behind it, so the consumed prefix is reclaimed while the partial tail is live
  LFirst := Framed(TTlsHandshakeType.EncryptedExtensions, 700, 3);
  LSecond := Framed(TTlsHandshakeType.CertificateVerify, 1500, 77);
  LWire := ConcatBytes(LFirst, LSecond);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LWire, 0, 1200);
    CheckTrue(LReader.NextMessage(LMsg), 'the first message is whole');
    CheckMessage('first message', LFirst, LMsg);
    CheckFalse(LReader.NextMessage(LMsg), 'the second is still partial');
    LReader.Append(LWire, 1200, System.Length(LWire) - 1200);
    CheckTrue(LReader.NextMessage(LMsg), 'the second message completes');
    CheckMessage('second message survives the reclaim', LSecond, LMsg);
    CheckFalse(LReader.HasPartial, 'nothing left over');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestReassemblyCapCountsOnlyUnconsumedBytes;
var
  LWire: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LIdx: Int32;
begin
  LWire := Framed(TTlsHandshakeType.Finished, 32, 0);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.MaxTotalLength := 40;
    // each 36-byte message is consumed before the next arrives, so 36 never accumulates past 40
    for LIdx := 1 to 5 do
    begin
      LReader.Append(LWire, 0, System.Length(LWire));
      CheckTrue(LReader.NextMessage(LMsg), 'message ' + IntToStr(LIdx));
    end;
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestReassemblyCapIsExact;
var
  LWire: TBytes;
  LReader: THandshakeMessageReader;
  LRaised: Boolean;
begin
  LWire := Framed(TTlsHandshakeType.Finished, 32, 0);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.MaxTotalLength := 36;
    LReader.Append(LWire, 0, 36); // exactly at the cap
    LRaised := False;
    try
      LReader.Append(LWire, 0, 1);
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'one byte past the cap is a decode_error');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestHandshakeTypeCodec;
var
  LType: TTlsHandshakeType;
begin
  CheckEquals(1, TTlsHandshakeType.ClientHello.ToByte, 'client_hello = 1');
  CheckEquals(20, TTlsHandshakeType.Finished.ToByte, 'finished = 20');
  CheckEquals(254, TTlsHandshakeType.MessageHash.ToByte, 'message_hash = 254');
  CheckTrue(TTlsHandshakeType.TryFromByte(11, LType), '11 decodes');
  CheckEquals(Ord(TTlsHandshakeType.Certificate), Ord(LType), '11 = certificate');
  CheckFalse(TTlsHandshakeType.TryFromByte(99, LType), 'unknown type byte rejected');
end;

procedure TTestHandshakeMessage.TestFrameRoundTrip;
var
  LBody, LFramed: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
begin
  LBody := DecodeHex('0102030405');
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.EncryptedExtensions, LBody);
  // header is type(1) + uint24 length
  CheckEqualBytes('framed bytes', DecodeHex('0800000501 02030405'), LFramed);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    CheckTrue(LReader.NextMessage(LMsg), 'one message parses back');
    CheckEquals(8, LMsg.TypeByte, 'type byte preserved');
    CheckEqualBytes('body preserved', LBody, LMsg.Body);
    CheckEqualBytes('raw is the whole message', LFramed, LMsg.Raw);
    CheckFalse(LReader.NextMessage(LMsg), 'nothing left');
    CheckFalse(LReader.HasPartial, 'buffer drained');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestReassemblyAcrossFragments;
var
  LWhole: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LPos, LChunk: Int32;
begin
  // the RFC 8448 ClientHello (200 wire bytes) fed 40 at a time
  LWhole := Msg('client_hello');
  LReader := THandshakeMessageReader.Create;
  try
    LPos := 0;
    while LPos < System.Length(LWhole) do
    begin
      LChunk := 40;
      if LChunk > System.Length(LWhole) - LPos then
        LChunk := System.Length(LWhole) - LPos;
      LReader.Append(LWhole, LPos, LChunk);
      Inc(LPos, LChunk);
      if LPos < System.Length(LWhole) then
        CheckFalse(LReader.NextMessage(LMsg), 'incomplete: no message yet');
    end;
    CheckTrue(LReader.NextMessage(LMsg), 'the message completes on the last fragment');
    CheckEquals(1, LMsg.TypeByte, 'client_hello type');
    CheckEqualBytes('reassembled whole message', LWhole, LMsg.Raw);
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestCoalescedMessages;
var
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LBoth: TBytes;
begin
  // ClientHello and ServerHello coalesced into a single feed
  LBoth := ConcatBytes(Msg('client_hello'), Msg('server_hello'));
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LBoth, 0, System.Length(LBoth));
    CheckTrue(LReader.NextMessage(LMsg), 'first message');
    CheckEquals(1, LMsg.TypeByte, 'client_hello first');
    CheckTrue(LReader.NextMessage(LMsg), 'second message');
    CheckEquals(2, LMsg.TypeByte, 'server_hello second');
    CheckFalse(LReader.NextMessage(LMsg), 'both consumed');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestPartialMessageNeedsMore;
var
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
begin
  LReader := THandshakeMessageReader.Create;
  try
    // a header only (type=finished, length=32) with no body yet
    LReader.Append(DecodeHex('14000020'), 0, 4);
    CheckFalse(LReader.NextMessage(LMsg), 'header alone is not a message');
    CheckTrue(LReader.HasPartial, 'partial bytes are held');
    // then the 32-byte body arrives
    LReader.Append(DecodeHex('00112233445566778899aabbccddeeff' +
      '00112233445566778899aabbccddeeff'), 0, 32);
    CheckTrue(LReader.NextMessage(LMsg), 'the body completes the message');
    CheckEquals(20, LMsg.TypeByte, 'finished type');
    CheckEquals(32, System.Length(LMsg.Body), '32-byte body');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestOversizedMessageIsDecodeError;
var
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LRaised: Boolean;
begin
  LReader := THandshakeMessageReader.Create;
  try
    // the Certificate type is bounded by its own cap (see MaxCertificateMessageLength)
    LReader.MaxCertificateMessageLength := 8;
    // a Certificate header declaring a 100-byte body against an 8-byte cap
    LReader.Append(DecodeHex('0b000064'), 0, 4);
    LRaised := False;
    try
      LReader.NextMessage(LMsg);
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'an oversized declared length is a decode_error');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestOversizedNonCertificateMessageIsDecodeError;
var
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LRaised: Boolean;
begin
  // a non-Certificate type is bounded by the default MaxMessageLength (2^16); the cap check fires
  // on the declared length before any body is buffered
  LReader := THandshakeMessageReader.Create;
  try
    // a Finished (type 0x14) header declaring 0x010001 = 65537 bytes, one past the 2^16 cap
    LReader.Append(DecodeHex('14010001'), 0, 4);
    LRaised := False;
    try
      LReader.NextMessage(LMsg);
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'an oversized non-Certificate message is a decode_error');
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessage.TestMessageHashIsNotWireDecodable;
var
  LType: TTlsHandshakeType;
begin
  // message_hash (254) is a synthetic transcript-only type (RFC 8446 4.4.1); it must never be
  // decodable from the wire, though its code still encodes for transcript synthesis
  CheckFalse(TTlsHandshakeType.TryFromByte(254, LType),
    'message_hash (254) is not wire-decodable');
  CheckEquals(254, TTlsHandshakeType.MessageHash.ToByte,
    'message_hash still encodes to 254 for transcript synthesis');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHandshakeMessage);
{$ELSE}
  RegisterTest(TTestHandshakeMessage.Suite);
{$ENDIF FPC}

finalization
  GVectors.Free;

end.
