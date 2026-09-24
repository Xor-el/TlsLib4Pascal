{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit AlertTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsError,
  TlsLibTestBase;

type
  TTestAlert = class(TTlsLibAlgorithmTestCase)
  private
    procedure CheckRoundTrip(ADescription: TTlsAlertDescription; AExpected: Byte);
  published
    procedure TestDescriptionByteRoundTrip;
    procedure TestLevelByte;
    procedure TestUnknownByteRejected;
    procedure TestCreateFatalHelper;
    procedure TestErrorCreateFatal;
    procedure TestErrorCarriesOrigin;
  end;

implementation

{ TTestAlert }

procedure TTestAlert.CheckRoundTrip(ADescription: TTlsAlertDescription;
  AExpected: Byte);
var
  LDecoded: TTlsAlertDescription;
begin
  CheckEquals(AExpected, ADescription.ToByte, 'toByte');
  CheckTrue(TTlsAlertDescription.TryFromByte(AExpected, LDecoded), 'fromByte ok');
  CheckEquals(Ord(ADescription), Ord(LDecoded), 'round-trip');
end;

procedure TTestAlert.TestDescriptionByteRoundTrip;
begin
  CheckRoundTrip(TTlsAlertDescription.CloseNotify, 0);
  CheckRoundTrip(TTlsAlertDescription.UnexpectedMessage, 10);
  CheckRoundTrip(TTlsAlertDescription.BadRecordMac, 20);
  CheckRoundTrip(TTlsAlertDescription.HandshakeFailure, 40);
  CheckRoundTrip(TTlsAlertDescription.DecodeError, 50);
  CheckRoundTrip(TTlsAlertDescription.NoRenegotiation, 100);
  CheckRoundTrip(TTlsAlertDescription.UnsupportedExtension, 110);
  CheckRoundTrip(TTlsAlertDescription.NoApplicationProtocol, 120);
end;

procedure TTestAlert.TestLevelByte;
var
  LWarning, LFatal: TTlsAlertLevel;
begin
  LWarning := TTlsAlertLevel.Warning;
  LFatal := TTlsAlertLevel.Fatal;
  CheckEquals(1, LWarning.ToByte, 'warning');
  CheckEquals(2, LFatal.ToByte, 'fatal');
end;

procedure TTestAlert.TestUnknownByteRejected;
var
  LDecoded: TTlsAlertDescription;
begin
  // 1 and 255 are not assigned RFC 8446 alert codes
  CheckFalse(TTlsAlertDescription.TryFromByte(1, LDecoded), 'code 1 unknown');
  CheckFalse(TTlsAlertDescription.TryFromByte(255, LDecoded), 'code 255 unknown');
end;

procedure TTestAlert.TestCreateFatalHelper;
var
  LAlert: TTlsAlert;
begin
  LAlert := TTlsAlert.CreateFatal(TTlsAlertDescription.BadRecordMac);
  CheckEquals(Ord(TTlsAlertLevel.Fatal), Ord(LAlert.Level), 'level');
  CheckEquals(Ord(TTlsAlertDescription.BadRecordMac), Ord(LAlert.Description),
    'description');
end;

procedure TTestAlert.TestErrorCreateFatal;
var
  LError: TTlsError;
begin
  LError := TTlsError.CreateFatal(TTlsAlertDescription.HandshakeFailure,
    'handshake failed');
  CheckEquals(Ord(TTlsAlertLevel.Fatal), Ord(LError.Alert.Level), 'level');
  CheckEquals(Ord(TTlsAlertDescription.HandshakeFailure),
    Ord(LError.Alert.Description), 'description');
  CheckEquals('handshake failed', LError.Message, 'message');
  CheckEquals(Ord(TTlsErrorOrigin.Unknown), Ord(LError.Origin),
    'origin defaults to unknown');
end;

procedure TTestAlert.TestErrorCarriesOrigin;
var
  LFatal, LPlain: TTlsError;
begin
  LFatal := TTlsError.CreateFatal(TTlsAlertDescription.HandshakeFailure,
    'peer alert', TTlsErrorOrigin.Peer);
  CheckEquals(Ord(TTlsErrorOrigin.Peer), Ord(LFatal.Origin), 'CreateFatal keeps the origin');
  LPlain := TTlsError.Create(TTlsAlert.CreateFatal(TTlsAlertDescription.CloseNotify),
    'local', TTlsErrorOrigin.Local);
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LPlain.Origin), 'Create keeps the origin');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAlert);
{$ELSE}
  RegisterTest(TTestAlert.Suite);
{$ENDIF FPC}

end.
