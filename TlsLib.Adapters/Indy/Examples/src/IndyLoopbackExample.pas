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
  IdContext,
  IdTCPServer,
  IdTCPClient,
  TlpTlsVersion,
  TlpDataEncoding,
  TlpIndyTls;

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
    class function WriteDer(const AName, AHex: string): string; static;
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

class function TVectorLocator.WriteDer(const AName, AHex: string): string;
var
  LBytes: TBytes;
  LFile: TFileStream;
begin
  LBytes := TDataEncoding.HexDecode(AHex);
  Result := IncludeTrailingPathDelimiter(GetEnvironmentVariable('TEMP')) +
    'tlslib_indy_' + AName + '.der';
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
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GVector := TVectorLocator.Find;
  LEchoHandler := TEchoHandler.Create;
  LServer := TIdTCPServer.Create(nil);
  LClient := TIdTCPClient.Create(nil);
  try
    LServerIO := TTlsLibServerIOHandler.Create(LServer);
    LServerIO.SSLOptions.CertFile := TVectorLocator.WriteDer('leaf',
      TVectorLocator.FieldHex('leaf_cert'));
    LServerIO.SSLOptions.KeyFile := TVectorLocator.WriteDer('key',
      TVectorLocator.FieldHex('leaf_key'));
    LServer.IOHandler := LServerIO;
    LServer.DefaultPort := PORT;
    LServer.OnExecute := LEchoHandler.DoExecute;
    LServer.Active := True;

    LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
    LClientIO.SSLOptions.RootCertFile := TVectorLocator.WriteDer('root',
      TVectorLocator.FieldHex('root_cert'));
    LClient.IOHandler := LClientIO;
    LClient.Host := 'localhost'; // verify the leaf for its 'localhost' SAN
    LClient.Port := PORT;
    LClient.Connect;
    try
      LClientIO.WriteLn('ping from the indy client');
      LEcho := LClientIO.ReadLn;
    finally
      LClient.Disconnect;
    end;

    LServer.Active := False;

    LOk := (LEcho = 'ping from the indy client') and
      (LClientIO.NegotiatedVersion.WireValue = TlsWireVersionTls13);
    if LOk then
    begin
      Writeln('Indy loopback PASS: handshake + echo over TLS 1.3');
      Result := 0;
    end
    else
      Writeln('Indy loopback FAIL: echo="', LEcho, '" server="', GServerError, '"');
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
