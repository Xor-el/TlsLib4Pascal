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
  published
    procedure TestHandshakeTypeCodec;
    procedure TestFrameRoundTrip;
    procedure TestReassemblyAcrossFragments;
    procedure TestCoalescedMessages;
    procedure TestPartialMessageNeedsMore;
    procedure TestOversizedMessageIsDecodeError;
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
    LReader.MaxMessageLength := 8;
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestHandshakeMessage);
{$ELSE}
  RegisterTest(TTestHandshakeMessage.Suite);
{$ENDIF FPC}

finalization
  GVectors.Free;

end.
