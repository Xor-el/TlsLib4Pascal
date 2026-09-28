{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit RecordHeaderTests;

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
  TlpRecordHeader,
  TlpWireReader,
  TlsLibTestBase;

type
  TTestRecordHeader = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestContentTypeByteRoundTrip;
    procedure TestUnknownContentTypeByteIsNotGuessed;
    procedure TestVersionCodes;
    procedure TestHeaderWriteToRoundTrip;
    procedure TestUnknownContentTypeSurvivesParse;
    procedure TestOverlongLengthIsRecordOverflow;
    procedure TestTruncatedHeaderIsDecodeError;
  end;

implementation

{ TTestRecordHeader }

procedure TTestRecordHeader.TestContentTypeByteRoundTrip;
var
  LKnown: array of TTlsContentType;
  LType, LBack: TTlsContentType;
  LI: Int32;
begin
  LKnown := [TTlsContentType.Invalid, TTlsContentType.ChangeCipherSpec,
    TTlsContentType.Alert, TTlsContentType.Handshake,
    TTlsContentType.ApplicationData, TTlsContentType.Heartbeat];
  for LI := 0 to System.Length(LKnown) - 1 do
  begin
    LType := LKnown[LI];
    CheckTrue(TTlsContentType.TryFromByte(
      LType.ToByte, LBack), 'known byte maps back');
    CheckEquals(Ord(LType), Ord(LBack), 'content type round-trips');
  end;
end;

procedure TTestRecordHeader.TestUnknownContentTypeByteIsNotGuessed;
var
  LType: TTlsContentType;
  LUnknown: TBytes;
  LI: Int32;
begin
  LUnknown := TBytes.Create(1, 19, 25, 26, 200, 255);
  for LI := 0 to System.Length(LUnknown) - 1 do
    CheckFalse(TTlsContentType.TryFromByte(LUnknown[LI], LType),
      Format('byte %d must not map', [LUnknown[LI]]));
end;

procedure TTestRecordHeader.TestVersionCodes;
var
  LTls12, LTls13, LLegacy, LMade: TTlsVersion;
begin
  LTls12 := TTlsVersion.Tls12;
  LTls13 := TTlsVersion.Tls13;
  LLegacy := TTlsVersion.LegacyRecordInitial;
  CheckEquals($0303, LTls12.WireValue, 'TLS 1.2 wire code');
  CheckEquals($0304, LTls13.WireValue, 'TLS 1.3 wire code');
  CheckEquals($0301, LLegacy.WireValue, 'legacy record code');
  CheckEquals($03, LTls13.MajorByte, 'major byte');
  CheckEquals($04, LTls13.MinorByte, 'minor byte');
  CheckTrue(LTls12.IsSupportedProtocol, '1.2 is negotiable');
  CheckTrue(LTls13.IsSupportedProtocol, '1.3 is negotiable');
  CheckFalse(LLegacy.IsSupportedProtocol, '1.0 is a legacy wire code, not negotiable');
  LMade := TTlsVersion.Create($0303);
  CheckTrue(LMade.Equals(LTls12), 'equality by code');
end;

procedure TTestRecordHeader.TestHeaderWriteToRoundTrip;
var
  LBytes: TBytes;
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
  LType: TTlsContentType;
begin
  LHeader := TTlsRecordHeader.Create(TTlsContentType.Handshake, TTlsVersion.Tls12, 4);
  LBytes := nil;
  SetLength(LBytes, TRecordLimits.HeaderLength);
  LHeader.WriteTo(LBytes, 0);
  CheckEqualBytes('serialized header', DecodeHex('1603030004'), LBytes);

  LReader := TWireReader.Create(LBytes);
  LHeader := TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxCipherTextTls13);
  CheckEquals(22, LHeader.ContentTypeByte, 'content-type byte');
  CheckEquals($0303, LHeader.Version.WireValue, 'version round-trips');
  CheckEquals(4, LHeader.Length, 'length round-trips');
  CheckTrue(LHeader.TryContentType(LType), 'known content type');
  CheckEquals(Ord(TTlsContentType.Handshake), Ord(LType), 'demuxed as handshake');
end;

procedure TTestRecordHeader.TestUnknownContentTypeSurvivesParse;
var
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
  LType: TTlsContentType;
begin
  // content-type 0xFF is unknown: the parse keeps the raw byte and leaves the
  // reject to the record layer's demux (never guesses a type here).
  LReader := TWireReader.Create(DecodeHex('FF03030000'));
  LHeader := TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxCipherTextTls13);
  CheckEquals($FF, LHeader.ContentTypeByte, 'raw byte preserved');
  CheckFalse(LHeader.TryContentType(LType), 'unknown type not resolved');
end;

procedure TTestRecordHeader.TestOverlongLengthIsRecordOverflow;
var
  LReader: TWireReader;
  LRaised: Boolean;
begin
  // length 0xFFFF far exceeds the 1.3 ciphertext cap
  LReader := TWireReader.Create(DecodeHex('170303FFFF'));
  LRaised := False;
  try
    TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxCipherTextTls13);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.RecordOverflow);
  end;
  CheckTrue(LRaised, 'over-long record must raise record_overflow');
end;

procedure TTestRecordHeader.TestTruncatedHeaderIsDecodeError;
var
  LReader: TWireReader;
  LRaised: Boolean;
begin
  // only 3 of the 5 header bytes present: a clean decode_error, no over-read
  LReader := TWireReader.Create(DecodeHex('160303'));
  LRaised := False;
  try
    TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxCipherTextTls13);
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'truncated header must raise decode_error');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRecordHeader);
{$ELSE}
  RegisterTest(TTestRecordHeader.Suite);
{$ENDIF FPC}

end.
