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
/// A real loopback over mORMot's own socket seam on 127.0.0.1: our INetTls (via the global
/// NewNetTls factory) drives both ends. The server runs on a background thread, the client on
/// the caller's thread. It asserts a full handshake, a round-tripped application message, and
/// the negotiated TLS 1.3 version - proving the mORMot adapter end to end. Shared by the
/// FreePascal and Delphi example programs.
/// </summary>
unit MormotLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TMormotLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  mormot.core.base,
  mormot.core.unicode,
  mormot.net.sock,
  TlpDataEncoding,
  TlpMormotTls;

const
  PORT = '28443';
  HOST = '127.0.0.1';
  PINGHEX = '70696e672066726f6d20746865206d6f724d6f7420636c69656e74';

var
  GLeafFile, GKeyFile, GRootFile: RawUtf8;
  GReady: TEvent;
  GServerError: string;
  GVector: string;

type
  // resolves the shared test vector by walking up from the exe (and cwd), so the example
  // runs from any build/output location - no machine-specific path
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
  public
    class function Find: string; static;
    class function FieldHex(const AName: string): string; static;
    class procedure WriteDer(const AName, AHex: string; out APath: RawUtf8); static;
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

class procedure TVectorLocator.WriteDer(const AName, AHex: string;
  out APath: RawUtf8);
var
  LBytes: TBytes;
  LFile: TFileStream;
begin
  LBytes := TDataEncoding.HexDecode(AHex);
  APath := StringToUtf8(IncludeTrailingPathDelimiter(GetEnvironmentVariable('TEMP')) +
    'tlslib_mormot_' + AName + '.der');
  LFile := TFileStream.Create(Utf8ToString(APath), fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

procedure TServerThread.Execute;
var
  LListener, LClient: TNetSocket;
  LAddr: TNetAddr;
  LCtx: TNetTlsContext;
  LTls: INetTls;
  LLastErr, LCipher: RawUtf8;
  LBuf: TBytes;
  LLen: Integer;
begin
  try
    FillCharFast(LCtx, SizeOf(LCtx), 0);
    LCtx.CertificateFile := GLeafFile;
    LCtx.PrivateKeyFile := GKeyFile;
    if NewSocket(HOST, PORT, nlTcp, {dobind=}True, 3000, 3000, 3000, 0,
      LListener) <> nrOK then
      raise Exception.Create('server bind failed');
    GReady.SetEvent;
    if LListener.Accept(LClient, LAddr, {async=}False) <> nrOK then
      raise Exception.Create('accept failed');
    LTls := NewTlsLib4PascalTls;
    LTls.AfterAccept(LClient, LCtx, @LLastErr, @LCipher);
    SetLength(LBuf, 4096);
    LLen := System.Length(LBuf);
    if LTls.Receive(@LBuf[0], LLen) = nrOK then
      LTls.Send(@LBuf[0], LLen);
  except
    on E: Exception do
    begin
      GServerError := E.ClassName + ': ' + E.Message;
      GReady.SetEvent;
    end;
  end;
end;

class function TMormotLoopbackExample.Run: Integer;
var
  LServer: TServerThread;
  LCtx: TNetTlsContext;
  LSock: TNetSocket;
  LTls: INetTls;
  LPing, LEcho: TBytes;
  LLen: Integer;
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GVector := TVectorLocator.Find;
  GReady := TEvent.Create(nil, True, False, '');
  try
    TVectorLocator.WriteDer('leaf', TVectorLocator.FieldHex('leaf_cert'), GLeafFile);
    TVectorLocator.WriteDer('key', TVectorLocator.FieldHex('leaf_key'), GKeyFile);
    TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('root_cert'), GRootFile);

    LServer := TServerThread.Create(True);
    LServer.FreeOnTerminate := False;
    LServer.Start;
    GReady.WaitFor(5000);
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    FillCharFast(LCtx, SizeOf(LCtx), 0);
    LCtx.CACertificatesFile := GRootFile;
    if NewSocket(HOST, PORT, nlTcp, {dobind=}False, 3000, 3000, 3000, 0, LSock) <> nrOK then
      raise Exception.Create('client connect failed');
    LTls := NewTlsLib4PascalTls;
    // connect to 127.0.0.1 but verify the certificate for 'localhost' (its SAN)
    LTls.AfterConnection(LSock, LCtx, 'localhost');

    LPing := TDataEncoding.HexDecode(PINGHEX);
    LLen := System.Length(LPing);
    LTls.Send(@LPing[0], LLen);
    SetLength(LEcho, 4096);
    LLen := System.Length(LEcho);
    LTls.Receive(@LEcho[0], LLen);

    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    LOk := (LLen = System.Length(LPing)) and CompareMem(@LEcho[0], @LPing[0], LLen)
      and (LTls.GetCipherName = 'TLSv1.3');
    if LOk then
    begin
      Writeln('mORMot loopback PASS: handshake + echo over ', LTls.GetCipherName);
      Result := 0;
    end
    else
      Writeln('mORMot loopback FAIL: echo/version mismatch');
    LServer.Free;
  except
    on E: Exception do
      Writeln('mORMot loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
