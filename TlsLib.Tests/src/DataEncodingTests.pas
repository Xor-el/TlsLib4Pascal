{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit DataEncodingTests;

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
  TlpDataEncoding,
  TlsLibTestBase;

type
  TTestDataEncoding = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestHexEncodeLowerAndUpper;
    procedure TestHexDecodeRoundTripEitherCase;
    procedure TestHexDecodeOddLengthRaises;
    procedure TestHexDecodeNonHexRaises;
    procedure TestTryHexDecodeEitherCase;
    procedure TestTryHexDecodeOddLengthFails;
    procedure TestTryHexDecodeNonHexFails;
    procedure TestBase64KnownVectors;
    procedure TestBase64RoundTripAllLengths;
    procedure TestBase64ToleratesWhitespace;
    procedure TestBase64RejectsMalformed;
  end;

implementation

{ TTestDataEncoding }

procedure TTestDataEncoding.TestHexEncodeLowerAndUpper;
var
  LData: TBytes;
begin
  LData := TBytes.Create($00, $0F, $A5, $FF);
  CheckEquals('000fa5ff', TDataEncoding.HexEncode(LData), 'lowercase is the default');
  CheckEquals('000FA5FF', TDataEncoding.HexEncode(LData, THexCase.Upper),
    'uppercase when requested');
  CheckEquals('', TDataEncoding.HexEncode(nil), 'empty input encodes to empty');
end;

procedure TTestDataEncoding.TestHexDecodeRoundTripEitherCase;
var
  LData: TBytes;
begin
  LData := TBytes.Create($DE, $AD, $BE, $EF, $00, $10);
  CheckEqualBytes('lowercase round-trips', LData,
    TDataEncoding.HexDecode(TDataEncoding.HexEncode(LData)));
  CheckEqualBytes('uppercase decodes too', LData,
    TDataEncoding.HexDecode(TDataEncoding.HexEncode(LData, THexCase.Upper)));
  // mixed case is accepted
  CheckEqualBytes('mixed case decodes', TBytes.Create($AB, $CD),
    TDataEncoding.HexDecode('aBcD'));
end;

procedure TTestDataEncoding.TestHexDecodeOddLengthRaises;
var
  LRaised: Boolean;
  LMessage: string;
begin
  LRaised := False;
  LMessage := '';
  try
    TDataEncoding.HexDecode('abc');
  except
    on E: EArgumentTlsLibException do
    begin
      LRaised := True;
      LMessage := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'an odd-length hex string is rejected');
  CheckTrue(Pos('even number', LMessage) > 0, 'the odd length is named: ' + LMessage);
end;

procedure TTestDataEncoding.TestHexDecodeNonHexRaises;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TDataEncoding.HexDecode('00zz');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-hex character is rejected');
end;

procedure TTestDataEncoding.TestTryHexDecodeEitherCase;
var
  LBytes: TBytes;
begin
  CheckTrue(TDataEncoding.TryHexDecode('aBcD09', LBytes), 'mixed case decodes');
  CheckEqualBytes('mixed case bytes', TBytes.Create($AB, $CD, $09), LBytes);
  CheckTrue(TDataEncoding.TryHexDecode('', LBytes), 'empty decodes');
  CheckEquals(0, System.Length(LBytes), 'empty decodes to no bytes');
end;

procedure TTestDataEncoding.TestTryHexDecodeOddLengthFails;
var
  LBytes: TBytes;
begin
  LBytes := TBytes.Create($01);
  CheckFalse(TDataEncoding.TryHexDecode('abc', LBytes), 'an odd-length hex string fails');
  CheckEquals(0, System.Length(LBytes), 'a failure leaves no bytes');
end;

procedure TTestDataEncoding.TestTryHexDecodeNonHexFails;
var
  LBytes: TBytes;
begin
  CheckFalse(TDataEncoding.TryHexDecode('0g', LBytes), 'a non-hex low digit fails');
  CheckFalse(TDataEncoding.TryHexDecode('g0', LBytes), 'a non-hex high digit fails');
  CheckFalse(TDataEncoding.TryHexDecode('00:1', LBytes),
    'a non-hex character in a later byte fails');
  CheckEquals(0, System.Length(LBytes), 'a failure leaves no bytes');
end;

procedure TTestDataEncoding.TestBase64KnownVectors;
begin
  // RFC 4648 sec. 10
  CheckEquals('', TDataEncoding.Base64Encode(nil), 'empty encodes to empty');
  CheckEquals('Zg==', TDataEncoding.Base64Encode(DecodeHex('66')), 'f');
  CheckEquals('Zm8=', TDataEncoding.Base64Encode(DecodeHex('666f')), 'fo');
  CheckEquals('Zm9v', TDataEncoding.Base64Encode(DecodeHex('666f6f')), 'foo');
  CheckEquals('Zm9vYg==', TDataEncoding.Base64Encode(DecodeHex('666f6f62')), 'foob');
  CheckEquals('Zm9vYmE=', TDataEncoding.Base64Encode(DecodeHex('666f6f6261')), 'fooba');
  CheckEquals('Zm9vYmFy', TDataEncoding.Base64Encode(DecodeHex('666f6f626172')),
    'foobar');
  CheckEqualBytes('decode f', DecodeHex('66'), TDataEncoding.Base64Decode('Zg=='));
  CheckEqualBytes('decode fooba', DecodeHex('666f6f6261'),
    TDataEncoding.Base64Decode('Zm9vYmE='));
  CheckEqualBytes('decode foobar', DecodeHex('666f6f626172'),
    TDataEncoding.Base64Decode('Zm9vYmFy'));
end;

procedure TTestDataEncoding.TestBase64RoundTripAllLengths;
var
  LI, LJ: Int32;
  LData: TBytes;
begin
  for LI := 0 to 64 do
  begin
    SetLength(LData, LI);
    for LJ := 0 to LI - 1 do
      LData[LJ] := Byte((LJ * 7 + LI) and $FF);
    CheckEqualBytes(Format('round-trip of %d bytes', [LI]), LData,
      TDataEncoding.Base64Decode(TDataEncoding.Base64Encode(LData)));
  end;
end;

procedure TTestDataEncoding.TestBase64ToleratesWhitespace;
begin
  CheckEqualBytes('embedded whitespace and newlines are ignored',
    DecodeHex('666f6f62'), TDataEncoding.Base64Decode('Zm9v'#13#10' Yg=='#9));
end;

procedure TTestDataEncoding.TestBase64RejectsMalformed;
const
  LBad: array[0..5] of string = ('Zg', 'Zm9v=', 'Zg==X', 'Zg===', 'Z!==', 'Zg=A');
var
  LI: Int32;
  LRaised: Boolean;
begin
  for LI := 0 to System.High(LBad) do
  begin
    LRaised := False;
    try
      TDataEncoding.Base64Decode(LBad[LI]);
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, Format('"%s" is rejected as malformed base64', [LBad[LI]]));
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestDataEncoding);
{$ELSE}
  RegisterTest(TTestDataEncoding.Suite);
{$ENDIF FPC}

end.
