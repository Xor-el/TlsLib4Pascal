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
/// A real loopback over Synapse's TCustomSSL seam on 127.0.0.1: both ends are TTCPBlockSocket
/// instances created with our SSLImplementation plugin. The server runs on a background
/// thread, the client on the caller's thread. It asserts a full handshake and a round-tripped
/// line - proving the Synapse plugin end to end. Shared by the FreePascal and Delphi example
/// programs.
/// </summary>
unit SynapseLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TSynapseLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  blcksock,
  TlpDataEncoding,
  TlpSynapseTls;

const
  PORT = '28445';
  CRLF = #13#10;

var
  GLeafFile, GKeyFile, GRootFile: string;
  GReady: TEvent;
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

  TServerThread = class(TThread)
  protected
    procedure Execute; override;
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
    'tlslib_syn_' + AName + '.der';
  LFile := TFileStream.Create(Result, fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

procedure TServerThread.Execute;
var
  LListener, LClient: TTCPBlockSocket;
  LLine: string;
begin
  LListener := TTCPBlockSocket.Create;
  try
    try
      LListener.CreateSocket;
      LListener.SetLinger(True, 1000);
      LListener.Bind('127.0.0.1', PORT);
      LListener.Listen;
      GReady.SetEvent;
      if LListener.CanRead(5000) then
      begin
        LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
        try
          LClient.Socket := LListener.Accept;
          LClient.SSL.CertificateFile := GLeafFile;
          LClient.SSL.PrivateKeyFile := GKeyFile;
          if not LClient.SSLAcceptConnection then
            raise Exception.Create('ssl accept failed: ' + LClient.SSL.LastErrorDesc);
          LLine := LClient.RecvString(5000);
          LClient.SendString(LLine + CRLF);
        finally
          LClient.Free;
        end;
      end;
    except
      on E: Exception do
      begin
        GServerError := E.ClassName + ': ' + E.Message;
        GReady.SetEvent;
      end;
    end;
  finally
    LListener.Free;
  end;
end;

class function TSynapseLoopbackExample.Run: Integer;
var
  LServer: TServerThread;
  LClient: TTCPBlockSocket;
  LEcho: string;
begin
  Result := 1;
  GServerError := '';
  GVector := TVectorLocator.Find;
  GReady := TEvent.Create(nil, True, False, '');
  try
    GLeafFile := TVectorLocator.WriteDer('leaf', TVectorLocator.FieldHex('leaf_cert'));
    GKeyFile := TVectorLocator.WriteDer('key', TVectorLocator.FieldHex('leaf_key'));
    GRootFile := TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('root_cert'));

    LServer := TServerThread.Create(True);
    LServer.FreeOnTerminate := False;
    LServer.Start;
    GReady.WaitFor(5000);
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
    try
      LClient.SSL.CertCAFile := GRootFile;
      LClient.SSL.VerifyCert := True;
      LClient.SSL.SNIHost := 'localhost'; // verify the leaf for its 'localhost' SAN
      LClient.Connect('127.0.0.1', PORT);
      if LClient.LastError <> 0 then
        raise Exception.Create('tcp connect failed');
      LClient.SSLDoConnect;
      if not LClient.SSL.SSLEnabled then
        raise Exception.Create('ssl connect failed: ' + LClient.SSL.LastErrorDesc);
      LClient.SendString('ping from the synapse client' + CRLF);
      LEcho := LClient.RecvString(5000);
    finally
      LClient.Free;
    end;

    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    if LEcho = 'ping from the synapse client' then
    begin
      Writeln('Synapse loopback PASS: handshake + echo');
      Result := 0;
    end
    else
      Writeln('Synapse loopback FAIL: echo="', LEcho, '"');
    LServer.Free;
  except
    on E: Exception do
      Writeln('Synapse loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
