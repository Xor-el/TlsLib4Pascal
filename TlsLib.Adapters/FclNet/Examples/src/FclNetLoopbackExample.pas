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
/// A real loopback over fcl-net's TSSLSocketHandler seam on 127.0.0.1: the server is a fcl-net
/// TInetServer whose accepted connections carry our TTlsLibSocketHandler (supplied through
/// OnCreateClientSocketHandler); the client is a fcl-net TInetSocket driven with the same handler
/// class. The server runs on a background thread, the client on the caller's thread. It asserts a
/// full TLS 1.3 handshake and a round-tripped line - proving the fcl-net adapter end to end.
/// </summary>
unit FclNetLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  TlpTlsVersion;

type
  TFclNetLoopbackExample = class sealed(TObject)
  strict private
    class function VersionText(const AVersion: TTlsVersion): string; static;
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  ssockets,
  TlpDataEncoding,
  TlpFclNetTls;

const
  PORT = 28446;
  PING = 'ping from the fclnet client';

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
    class var FVector: string;
  public
    class procedure Locate; static;
    class function FieldHex(const AName: string): string; static;
    class function WriteDer(const AName, AHex: string): string; static;
  end;

  /// <summary>The loopback server: binds 127.0.0.1:PORT, hands each accepted connection a fcl-net
  /// TTlsLibSocketHandler carrying the leaf cert/key, then echoes the one line the client sends.</summary>
  TServerThread = class(TThread)
  strict private
  var
    FLeafFile, FKeyFile, FError: string;
    FReady: TEvent;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
  protected
    procedure Execute; override;
  public
    constructor Create(const ALeaf, AKey: string; AReady: TEvent);
    property Error: string read FError;
  end;

{ TVectorLocator }

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

class procedure TVectorLocator.Locate;
begin
  FVector := SearchFrom(ExtractFilePath(ParamStr(0)));
  if FVector = '' then
    FVector := SearchFrom(GetCurrentDir);
  if FVector = '' then
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
    LLines.LoadFromFile(FVector);
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
  Result := IncludeTrailingPathDelimiter(GetTempDir) + 'tlslib_fcl_' + AName + '.der';
  LFile := TFileStream.Create(Result, fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

{ TServerThread }

constructor TServerThread.Create(const ALeaf, AKey: string; AReady: TEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FLeafFile := ALeaf;
  FKeyFile := AKey;
  FReady := AReady;
end;

procedure TServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  // fcl-net asks the server for a handler per accepted connection: hand it a configured one
  // carrying the server credential (its Accept runs our server handshake automatically)
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.Certificate.FileName := FLeafFile;
  LHandler.CertificateData.PrivateKey.FileName := FKeyFile;
  AHandler := LHandler;
end;

procedure TServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  // the handshake already ran during accept; move one line of plaintext through our records
  try
    SetLength(LBuf, 1024);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
      AStream.Write(LBuf[0], LN); // echo it back
  except
    on E: Exception do
      FError := 'server connection: ' + E.ClassName + ': ' + E.Message;
  end;
  // we own the accepted stream in OnConnect: freeing it flushes close_notify then closes the socket
  AStream.Free;
end;

procedure TServerThread.Execute;
var
  LServer: TInetServer;
begin
  LServer := TInetServer.Create('127.0.0.1', PORT);
  try
    try
      LServer.ReuseAddress := True;
      LServer.MaxConnections := 1;
      LServer.OnCreateClientSocketHandler := MakeHandler;
      LServer.OnConnect := HandleConnect;
      LServer.Listen; // bind + listen before the client is told to connect
      FReady.SetEvent;
      LServer.StartAccepting; // blocks until the one connection is handled
    except
      on E: Exception do
      begin
        FError := 'server: ' + E.ClassName + ': ' + E.Message;
        FReady.SetEvent;
      end;
    end;
  finally
    LServer.Free;
  end;
end;

{ TFclNetLoopbackExample }

class function TFclNetLoopbackExample.VersionText(const AVersion: TTlsVersion): string;
begin
  case AVersion.WireValue of
    TlsWireVersionTls13:
      Result := 'TLSv1.3';
    TlsWireVersionTls12:
      Result := 'TLSv1.2';
  else
    Result := 'unknown';
  end;
end;

class function TFclNetLoopbackExample.Run: Integer;
var
  LServer: TServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LReady: TEvent;
  LLeaf, LKey, LRoot, LEcho, LVersion: string;
  LOut: AnsiString;
  LBuf: TBytes;
  LN: Integer;
begin
  Result := 1;
  LEcho := '';
  LVersion := '';
  TVectorLocator.Locate;
  LReady := TEvent.Create(nil, True, False, '');
  try
    LLeaf := TVectorLocator.WriteDer('leaf', TVectorLocator.FieldHex('leaf_cert'));
    LKey := TVectorLocator.WriteDer('key', TVectorLocator.FieldHex('leaf_key'));
    LRoot := TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('root_cert'));

    LServer := TServerThread.Create(LLeaf, LKey, LReady);
    try
      LServer.Start;
      LReady.WaitFor(5000);
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);

      // the client: 'localhost' resolves to 127.0.0.1 (IPv4) and is also the name we verify the
      // leaf's SAN against; the pinned root is the trust source (fail-closed without one)
      LHandler := TTlsLibSocketHandler.Create;
      LHandler.CertificateData.CertCA.FileName := LRoot; // pinned root (VerifyPeerCert defaults True)
      LSock := TInetSocket.Create('localhost', PORT, LHandler); // handler set => no auto-connect
      try
        try
          LSock.Connect; // TCP connect + our TLS handshake
        except
          // TInetSocket raises a generic connect error when our handshake refuses; surface why
          on E: ESocketError do
            raise Exception.Create('handshake failed: ' + LHandler.LastErrorDesc);
        end;
        LVersion := VersionText(LHandler.NegotiatedVersion); // read before LSock.Free drops the handler
        LOut := AnsiString(PING);
        LSock.Write(LOut[1], System.Length(LOut));
        SetLength(LBuf, 1024);
        LN := LSock.Read(LBuf[0], System.Length(LBuf));
        if LN > 0 then
          SetString(LEcho, PAnsiChar(@LBuf[0]), LN);
      finally
        LSock.Free; // frees the handler, flushes close_notify, closes the socket
      end;

      LServer.WaitFor;
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
    finally
      LServer.Free;
    end;

    if LEcho = PING then
    begin
      WriteLn('FclNet loopback PASS: ', LVersion, ' handshake + echo');
      Result := 0;
    end
    else
      WriteLn('FclNet loopback FAIL: echo="', LEcho, '"');
  except
    on E: Exception do
      WriteLn('FclNet loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  LReady.Free;
end;

end.
