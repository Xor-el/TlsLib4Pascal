{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ExceptionTests;

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
  TlsLibTestBase;

type
  TTestExceptions = class(TTlsLibAlgorithmTestCase)
  private
    procedure RaiseArgument;
    procedure RaiseArgumentFmt;
    procedure RaiseFatalHandshake;
    procedure RaiseDecodeError;
  published
    procedure TestArgumentExceptionMessage;
    procedure TestCreateResFmt;
    procedure TestFatalAlertCarriesDescription;
    procedure TestDecodeErrorMapsToDecodeError;
    procedure TestHierarchy;
    procedure TestReadTimeoutHierarchy;
  end;

implementation

resourcestring
  STestBoom = 'boom';
  STestValueFmt = 'value %d out of range';

{ TTestExceptions }

procedure TTestExceptions.RaiseArgument;
begin
  raise EArgumentTlsLibException.CreateRes(@STestBoom);
end;

procedure TTestExceptions.RaiseArgumentFmt;
begin
  raise EArgumentTlsLibException.CreateResFmt(@STestValueFmt, [42]);
end;

procedure TTestExceptions.RaiseFatalHandshake;
begin
  raise EFatalAlertTlsLibException.CreateRes(
    TTlsAlertDescription.HandshakeFailure, @STestBoom);
end;

procedure TTestExceptions.RaiseDecodeError;
begin
  raise EDecodeErrorTlsLibException.CreateRes(@STestBoom);
end;

procedure TTestExceptions.TestArgumentExceptionMessage;
var
  LMessage: string;
begin
  LMessage := '';
  try
    RaiseArgument;
  except
    on E: EBaseTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals('boom', LMessage, 'CreateRes message');
end;

procedure TTestExceptions.TestCreateResFmt;
var
  LMessage: string;
begin
  LMessage := '';
  try
    RaiseArgumentFmt;
  except
    on E: EBaseTlsLibException do
      LMessage := E.Message;
  end;
  CheckEquals('value 42 out of range', LMessage, 'CreateResFmt message');
end;

procedure TTestExceptions.TestFatalAlertCarriesDescription;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    RaiseFatalHandshake;
  except
    on E: EFatalAlertTlsLibException do
    begin
      CheckEquals(Ord(TTlsAlertDescription.HandshakeFailure),
        Ord(E.AlertDescription), 'carried description');
      CheckEquals('boom', E.Message, 'message');
      LRaised := True;
    end;
  end;
  CheckTrue(LRaised, 'EFatalAlertTlsLibException must be raised');
end;

procedure TTestExceptions.TestDecodeErrorMapsToDecodeError;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    RaiseDecodeError;
  except
    on E: EFatalAlertTlsLibException do
    begin
      CheckEquals(Ord(TTlsAlertDescription.DecodeError),
        Ord(E.AlertDescription), 'decode_error mapping');
      LRaised := True;
    end;
  end;
  CheckTrue(LRaised, 'EDecodeErrorTlsLibException must map to decode_error');
end;

procedure TTestExceptions.TestHierarchy;
begin
  CheckTrue(EDecodeErrorTlsLibException.InheritsFrom(EFatalAlertTlsLibException),
    'EDecodeError is-a EFatalAlert');
  CheckTrue(EFatalAlertTlsLibException.InheritsFrom(EBaseTlsLibException),
    'EFatalAlert is-a EBase');
  CheckTrue(EArgumentTlsLibException.InheritsFrom(EBaseTlsLibException),
    'EArgument is-a EBase');
end;

procedure TTestExceptions.TestReadTimeoutHierarchy;
var
  LTimeout: ETlsReadTimeout;
begin
  // a handshake timeout is a read timeout by kind, so a host's generic timeout handling catches
  // both phases; neither is a truncation, and neither carries a TLS alert
  CheckTrue(ETlsHandshakeTimeout.InheritsFrom(ETlsReadTimeout),
    'ETlsHandshakeTimeout is-a ETlsReadTimeout');
  CheckTrue(ETlsReadTimeout.InheritsFrom(ETlsStreamError),
    'ETlsReadTimeout is-a ETlsStreamError');
  CheckFalse(ETlsReadTimeout.InheritsFrom(ETlsTransportTruncated),
    'a read timeout is not a truncation');
  LTimeout := ETlsReadTimeout.Create('idle');
  try
    CheckFalse(LTimeout.HasAlert, 'a read timeout carries no alert');
  finally
    LTimeout.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestExceptions);
{$ELSE}
  RegisterTest(TTestExceptions.Suite);
{$ENDIF FPC}

end.
