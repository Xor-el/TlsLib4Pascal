{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit AlertProtocolTests;

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
  TlpTlsError,
  TlpTlsLibExceptions,
  TlpTlsAlertProtocol,
  TlpAlertMapping,
  TlsLibTestBase;

type
  TTestAlertProtocol = class(TTlsLibAlgorithmTestCase)
  private
    procedure CheckMapsTo(const AException: Exception;
      ADescription: TTlsAlertDescription; const AName: string);
  published
    procedure TestEncodeDecodeRoundTrip;
    procedure TestCloseNotifyEncodeAndClassification;
    procedure TestUnknownDescriptionIsNotGuessed;
    procedure TestGeneralErrorIsKnownAndFatal;
    procedure TestMalformedAlertLengthRaisesDecodeError;
    procedure TestMappingFatalCarriesOwnDescription;
    procedure TestMappingUnknownExceptionsBecomeInternalError;
    procedure TestErrorForDoesNotLeakForeignMessages;
  end;

implementation

resourcestring
  SDummyReason = 'a fixed non-secret reason';

{ TTestAlertProtocol }

procedure TTestAlertProtocol.CheckMapsTo(const AException: Exception;
  ADescription: TTlsAlertDescription; const AName: string);
var
  LAlert: TTlsAlert;
begin
  try
    LAlert := TAlertMapping.AlertFor(AException);
    CheckEquals(Ord(TTlsAlertLevel.Fatal), Ord(LAlert.Level), AName + ' is fatal');
    CheckEquals(Ord(ADescription), Ord(LAlert.Description), AName + ' description');
  finally
    AException.Free;
  end;
end;

procedure TTestAlertProtocol.TestEncodeDecodeRoundTrip;
var
  LDescriptions: array of TTlsAlertDescription;
  LEncoded: TBytes;
  LDecoded: TReceivedAlert;
  LI: Int32;
begin
  LDescriptions := [TTlsAlertDescription.CloseNotify,
    TTlsAlertDescription.HandshakeFailure, TTlsAlertDescription.DecodeError,
    TTlsAlertDescription.RecordOverflow, TTlsAlertDescription.BadRecordMac,
    TTlsAlertDescription.InternalError, TTlsAlertDescription.ProtocolVersion,
    TTlsAlertDescription.NoApplicationProtocol];
  for LI := 0 to System.Length(LDescriptions) - 1 do
  begin
    LEncoded := TTlsAlertProtocol.Encode(
      TTlsAlert.CreateFatal(LDescriptions[LI]));
    CheckEquals(2, System.Length(LEncoded), 'alert is two bytes');
    CheckEquals(2, LEncoded[0], 'fatal level byte');
    CheckEquals(Ord(LDescriptions[LI]), LEncoded[1], 'description byte');
    LDecoded := TTlsAlertProtocol.Decode(LEncoded, 0, System.Length(LEncoded));
    CheckTrue(LDecoded.HasKnownDescription, 'known description');
    CheckEquals(Ord(LDescriptions[LI]), Ord(LDecoded.Description), 'round-trips');
    CheckTrue(LDecoded.IsFatalLevel, 'fatal level decoded');
  end;
end;

procedure TTestAlertProtocol.TestCloseNotifyEncodeAndClassification;
var
  LEncoded: TBytes;
  LWarning, LFatal: TReceivedAlert;
begin
  LEncoded := TTlsAlertProtocol.Encode(TTlsAlertProtocol.CloseNotify);
  CheckEqualBytes('close_notify is warning + 0', DecodeHex('0100'), LEncoded);
  LWarning := TTlsAlertProtocol.Decode(DecodeHex('0100'), 0, 2);
  CheckTrue(LWarning.IsCloseNotify, 'warning close_notify recognized');
  CheckFalse(LWarning.IsFatalLevel, 'warning level');
  LFatal := TTlsAlertProtocol.Decode(DecodeHex('0200'), 0, 2);
  CheckTrue(LFatal.IsCloseNotify, 'close_notify by description regardless of level');
  CheckTrue(LFatal.IsFatalLevel, 'fatal level');
end;

procedure TTestAlertProtocol.TestUnknownDescriptionIsNotGuessed;
var
  LDecoded: TReceivedAlert;
begin
  LDecoded := TTlsAlertProtocol.Decode(DecodeHex('02FF'), 0, 2);
  CheckFalse(LDecoded.HasKnownDescription, 'unknown code is not mapped');
  CheckEquals($FF, LDecoded.DescriptionByte, 'raw byte preserved');
  CheckFalse(LDecoded.IsCloseNotify, 'not close_notify');
  CheckTrue(LDecoded.IsFatalLevel, 'still classified fatal by level');
end;

procedure TTestAlertProtocol.TestGeneralErrorIsKnownAndFatal;
var
  LDecoded: TReceivedAlert;
begin
  // general_error(117), RFC 9846 6.2
  LDecoded := TTlsAlertProtocol.Decode(DecodeHex('0275'), 0, 2);
  CheckTrue(LDecoded.HasKnownDescription, 'general_error is mapped');
  CheckEquals(Ord(TTlsAlertDescription.GeneralError), Ord(LDecoded.Description),
    'description');
  CheckEquals(117, Ord(TTlsAlertDescription.GeneralError), 'wire code');
  CheckTrue(LDecoded.IsFatalLevel, 'fatal level');
  CheckFalse(LDecoded.IsCloseNotify, 'not close_notify');
end;

procedure TTestAlertProtocol.TestMalformedAlertLengthRaisesDecodeError;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TTlsAlertProtocol.Decode(DecodeHex('02'), 0, 1); // one byte only
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a one-byte alert is a decode_error');

  LRaised := False;
  try
    TTlsAlertProtocol.Decode(DecodeHex('020000'), 0, 3); // trailing byte
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a three-byte alert is a decode_error');
end;

procedure TTestAlertProtocol.TestMappingFatalCarriesOwnDescription;
begin
  CheckMapsTo(EFatalAlertTlsLibException.CreateRes(
    TTlsAlertDescription.RecordOverflow, @SDummyReason),
    TTlsAlertDescription.RecordOverflow, 'record_overflow');
  CheckMapsTo(EFatalAlertTlsLibException.CreateRes(
    TTlsAlertDescription.BadRecordMac, @SDummyReason),
    TTlsAlertDescription.BadRecordMac, 'bad_record_mac');
  CheckMapsTo(EFatalAlertTlsLibException.CreateRes(
    TTlsAlertDescription.UnexpectedMessage, @SDummyReason),
    TTlsAlertDescription.UnexpectedMessage, 'unexpected_message');
  CheckMapsTo(EDecodeErrorTlsLibException.CreateRes(@SDummyReason),
    TTlsAlertDescription.DecodeError, 'decode_error');
end;

procedure TTestAlertProtocol.TestMappingUnknownExceptionsBecomeInternalError;
begin
  // a TlsLib exception that is not a fatal-alert carrier
  CheckMapsTo(EArgumentTlsLibException.CreateRes(@SDummyReason),
    TTlsAlertDescription.InternalError, 'argument -> internal');
  // a foreign exception
  CheckMapsTo(Exception.Create('boom'), TTlsAlertDescription.InternalError,
    'foreign -> internal');
end;

procedure TTestAlertProtocol.TestErrorForDoesNotLeakForeignMessages;
var
  LForeign: Exception;
  LOurs: EBaseTlsLibException;
  LError: TTlsError;
begin
  // a foreign exception's message must not reach the public error
  LForeign := Exception.Create('super-secret-internal-detail');
  try
    LError := TAlertMapping.ErrorFor(LForeign);
    CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LError.Alert.Description),
      'foreign maps to internal_error');
    CheckFalse(Pos('secret', LError.Message) > 0, 'foreign message is not leaked');
  finally
    LForeign.Free;
  end;
  // our own resourcestring message is safe to surface
  LOurs := EArgumentTlsLibException.CreateRes(@SDummyReason);
  try
    LError := TAlertMapping.ErrorFor(LOurs);
    CheckTrue(Pos('non-secret', LError.Message) > 0, 'our reason is surfaced');
  finally
    LOurs.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAlertProtocol);
{$ELSE}
  RegisterTest(TTestAlertProtocol.Suite);
{$ENDIF FPC}

end.
