{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// A real loopback over Indy's IOHandler seam on 127.0.0.1: a TIdTCPServer using our server
/// IOHandler and a TIdTCPClient using our client IOHandler. It asserts a full handshake, a
/// round-tripped line, and the negotiated TLS 1.3 version - proving the Indy adapter end to
/// end. Shared by the FreePascal and Delphi example programs.
/// </summary>
unit IndyLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TIndyLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  DateUtils,
  IdContext,
  IdTCPServer,
  IdTCPClient,
  TlpTlsVersion,
  TlpDataEncoding,
  TlpNegotiationTypes,
  TlsLibIndyTls;

const
  PORT = 28444;
  CRLF = #13#10;

var
  GServerError: string;
  GVector: string;

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
  public
    class function Find: string; static;
    class function FieldHex(const AName: string): string; static;
    class function WriteDer(const AName, AExt, AHex: string): string; static;
  end;

  TEchoHandler = class sealed(TObject)
  public
    procedure DoExecute(AContext: TIdContext);
  end;

class function TVectorLocator.SearchFrom(const AStart: string): string;
const
  REL = 'TlsLib.Tests' + PathDelim + 'Data' + PathDelim + 'Certs' + PathDelim +
    'EcP256Chain.txt';
var
  LDir, LTry: string;
  LI: Integer;
begin
  Result := '';
  LDir := AStart;
  for LI := 0 to 8 do
  begin
    LTry := IncludeTrailingPathDelimiter(LDir) + REL;
    if FileExists(LTry) then
      Exit(LTry);
    LDir := ExtractFileDir(ExcludeTrailingPathDelimiter(LDir));
    if LDir = '' then
      Break;
  end;
end;

class function TVectorLocator.Find: string;
begin
  Result := SearchFrom(ExtractFilePath(ParamStr(0)));
  if Result = '' then
    Result := SearchFrom(GetCurrentDir);
  if Result = '' then
    raise Exception.Create('EcP256Chain.txt vector not found (searched up from the exe and cwd)');
end;

class function TVectorLocator.FieldHex(const AName: string): string;
var
  LLines: TStringList;
  LI: Integer;
  LPrefix: string;
begin
  Result := '';
  LPrefix := AName + '=';
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(GVector);
    for LI := 0 to LLines.Count - 1 do
      if Pos(LPrefix, LLines[LI]) = 1 then
        Exit(Copy(LLines[LI], System.Length(LPrefix) + 1, MaxInt));
  finally
    LLines.Free;
  end;
end;

class function TVectorLocator.WriteDer(const AName, AExt, AHex: string): string;
var
  LBytes: TBytes;
  LFile: TFileStream;
begin
  LBytes := TDataEncoding.HexDecode(AHex);
  Result := IncludeTrailingPathDelimiter(GetEnvironmentVariable('TEMP')) +
    'tlslib_indy_' + AName + AExt;
  LFile := TFileStream.Create(Result, fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

procedure TEchoHandler.DoExecute(AContext: TIdContext);
var
  LLine: string;
begin
  try
    LLine := AContext.Connection.IOHandler.ReadLn;
    AContext.Connection.IOHandler.WriteLn(LLine);
  except
    on E: Exception do
      GServerError := E.ClassName + ': ' + E.Message;
  end;
end;

class function TIndyLoopbackExample.Run: Integer;
var
  LServer: TIdTCPServer;
  LServerIO: TTlsLibServerIOHandler;
  LClient: TIdTCPClient;
  LClientIO: TTlsLibIOHandlerSocket;
  LEcho: string;
  LEchoHandler: TEchoHandler;
  LOk, LTimedOut, LTicketsArrived, LExpressionRefused: Boolean;
  LStarted: TDateTime;
  LLine: string;
  LCipher: UInt16;
begin
  Result := 1;
  GServerError := '';
  GVector := TVectorLocator.Find;
  LEchoHandler := TEchoHandler.Create;
  LServer := TIdTCPServer.Create(nil);
  LClient := TIdTCPClient.Create(nil);
  try
    LServerIO := TTlsLibServerIOHandler.Create(LServer);
    // the server identity as a PKCS#12 file, read by its extension
    LServerIO.SSLOptions.CertFile := TVectorLocator.WriteDer('leaf', '.pfx',
      TVectorLocator.FieldHex('leaf_pfx'));
    LServerIO.SSLOptions.KeyPassword := 'tlslib';
    LServer.IOHandler := LServerIO;
    LServer.DefaultPort := PORT;
    LServer.OnExecute := LEchoHandler.DoExecute;
    LServer.Active := True;

    LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
    LClientIO.SSLOptions.RootCertFile := TVectorLocator.WriteDer('root', '.der',
      TVectorLocator.FieldHex('root_cert'));
    // the client offers one suite, so a negotiated AES-256 proves the list was honoured
    LClientIO.SSLOptions.CipherList := 'TLS_AES_256_GCM_SHA384';
    LClient.IOHandler := LClientIO;
    LClient.Host := 'localhost'; // verify the leaf for its 'localhost' SAN
    LClient.Port := PORT;
    LClient.Connect;
    try
      // the server's session tickets arrive unread in the socket, so Readable turns true yet no
      // line will ever come: a read with ReadTimeout set must still give up, the way Indy's own
      // timed read does (an empty line with ReadLnTimedOut set, not an exception)
      LTicketsArrived := LClientIO.Readable(3000);
      LClient.ReadTimeout := 500;
      LStarted := Now;
      LLine := LClientIO.ReadLn;
      LTimedOut := LTicketsArrived and LClientIO.ReadLnTimedOut and (LLine = '') and
        (MilliSecondsBetween(Now, LStarted) < 5000);
      LClient.ReadTimeout := 0;
      LClientIO.WriteLn('ping from the indy client');
      LEcho := LClientIO.ReadLn;
      LCipher := LClientIO.NegotiatedCipherSuite;
    finally
      LClient.Disconnect;
    end;

    LServer.Active := False;

    // a cipher-string expression is not a suite name: refused naming the property, never skipped
    LExpressionRefused := False;
    LClientIO.SSLOptions.CipherList := 'HIGH';
    try
      LClientIO.SSLOptions.Snapshot;
    except
      on E: Exception do
        LExpressionRefused := Pos('CipherList', E.Message) > 0;
    end;

    LOk := LTimedOut and (LEcho = 'ping from the indy client') and
      (LClientIO.NegotiatedVersion.WireValue = TlsWireVersionTls13) and
      (LCipher = TCipherSuites13.Aes256GcmSha384) and LExpressionRefused;
    if LOk then
    begin
      Writeln('Indy loopback PASS: handshake + timed idle read + echo over TLS 1.3');
      Result := 0;
    end
    else
      Writeln('Indy loopback FAIL: timedOut=', LTimedOut, ' echo="', LEcho, '" suite=', LCipher,
        ' server="', GServerError, '"');
  except
    on E: Exception do
      Writeln('Indy loopback FAIL: ', E.ClassName, ': ', E.Message,
        ' server="', GServerError, '"');
  end;
  LClient.Free;
  LServer.Free;
  LEchoHandler.Free;
end;

end.
