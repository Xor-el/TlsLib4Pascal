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
/// A real loopback proving the fcl-net adapter scopes TLS resumption per trust config: two client
/// handlers with the SAME pinned root share the frozen config the adapter memoises (and its session
/// cache), so the second connection resumes; a handler with a DIFFERENT pinned root gets its own
/// config and cache, cannot see the first config's session, and does a full handshake - which its
/// (wrong) root then rejects. A shared cache or a signature that failed to distinguish the root
/// would instead resume the first session, send no certificate, and succeed - the bypass this guards.
/// Four sequential legs against one server: full, resume, reject (isolation), resume-again.
/// </summary>
unit FclNetResumptionScopeExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TFclNetResumptionScopeExample = class sealed(TObject)
  public
    /// <summary>Runs the four-leg loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  ssockets,
  TlpDataEncoding,
  TlsLibFclNetTls;

const
  PORT = 28448;
  PING = 'ping from the fclnet client';
  // legs 1, 2 and 4 complete a handshake; leg 3 (the reject leg) does not, so the server's accept
  // loop - which counts only completed handshakes - is bounded by the three that finish
  SUCCESSFUL_LEGS = 3;

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart, ARel: string): string; static;
  public
    class function FieldHex(const AVectorRel, AName: string): string; static;
    class function WriteDer(const AName, AHex: string): string; static;
  end;

  /// <summary>The loopback server: binds 127.0.0.1:PORT and hands each of the LEGS accepted
  /// connections a fcl-net TTlsLibSocketHandler carrying the same leaf cert/key (so the adapter's
  /// server config - and its STEK - stay stable across the legs), then echoes the client's line.
  /// A leg whose client rejects the certificate fails its handshake; the server tolerates it and
  /// keeps accepting.</summary>
  TServerThread = class(TThread)
  strict private
  var
    FLeafFile, FKeyFile, FError: string;
    FReady: TEvent;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
    procedure HandleAcceptError(Sender: TObject; ASocket: Longint; AError: Exception;
      var AErrorAction: TAcceptErrorAction);
  protected
    procedure Execute; override;
  public
    constructor Create(const ALeaf, AKey: string; AReady: TEvent);
    property Error: string read FError;
  end;

{ TVectorLocator }

class function TVectorLocator.SearchFrom(const AStart, ARel: string): string;
var
  LDir, LTry: string;
  LI: Integer;
begin
  Result := '';
  LDir := AStart;
  for LI := 0 to 8 do
  begin
    LTry := IncludeTrailingPathDelimiter(LDir) + ARel;
    if FileExists(LTry) then
      Exit(LTry);
    LDir := ExtractFileDir(ExcludeTrailingPathDelimiter(LDir));
    if LDir = '' then
      Break;
  end;
end;

class function TVectorLocator.FieldHex(const AVectorRel, AName: string): string;
var
  LPath: string;
  LLines: TStringList;
  LI: Integer;
  LPrefix: string;
  LRel: string;
begin
  Result := '';
  LRel := 'TlsLib.Tests' + PathDelim + 'Data' + PathDelim + 'Certs' + PathDelim + AVectorRel;
  LPath := SearchFrom(ExtractFilePath(ParamStr(0)), LRel);
  if LPath = '' then
    LPath := SearchFrom(GetCurrentDir, LRel);
  if LPath = '' then
    raise Exception.Create(AVectorRel + ' vector not found (searched up from the exe and cwd)');
  LPrefix := AName + '=';
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(LPath);
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
  Result := IncludeTrailingPathDelimiter(GetTempDir) + 'tlslib_fclrs_' + AName + '.der';
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
  try
    SetLength(LBuf, 1024);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
      AStream.Write(LBuf[0], LN);
  except
    // a leg the client aborts (the reject leg) surfaces here as a read/write error; not fatal
  end;
  AStream.Free;
end;

procedure TServerThread.HandleAcceptError(Sender: TObject; ASocket: Longint;
  AError: Exception; var AErrorAction: TAcceptErrorAction);
begin
  // should the reject leg's server-side handshake raise (rather than return a nil stream), ignore
  // it so the accept loop continues to the remaining legs
  AErrorAction := aeaIgnore;
end;

procedure TServerThread.Execute;
var
  LServer: TInetServer;
begin
  LServer := TInetServer.Create('127.0.0.1', PORT);
  try
    try
      LServer.ReuseAddress := True;
      LServer.MaxConnections := SUCCESSFUL_LEGS;
      LServer.OnCreateClientSocketHandler := MakeHandler;
      LServer.OnConnect := HandleConnect;
      LServer.OnAcceptError := HandleAcceptError;
      LServer.Listen;
      FReady.SetEvent;
      LServer.StartAccepting; // returns once the completed handshakes reach SUCCESSFUL_LEGS
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

{ TFclNetResumptionScopeExample }

class function TFclNetResumptionScopeExample.Run: Integer;
var
  LServer: TServerThread;
  LReady: TEvent;
  LLeaf, LKey, LRoot, LWrongRoot: string;

  // one leg: connect with ARootFile as the pinned trust, echo a line, return whether it resumed;
  // AConnected reports whether the TLS handshake completed at all
  function Leg(const ARootFile: string; out AConnected: Boolean): Boolean;
  var
    LSock: TInetSocket;
    LHandler: TTlsLibSocketHandler;
    LOut: AnsiString;
    LBuf: TBytes;
    LN: Integer;
  begin
    Result := False;
    AConnected := False;
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := ARootFile; // pinned root (the only per-leg difference)
    LSock := TInetSocket.Create('localhost', PORT, LHandler);
    try
      try
        LSock.Connect;
        AConnected := True;
      except
        on ESocketError do
          Exit; // the reject leg lands here: the wrong root refused the server certificate
      end;
      // drain the round trip so the server's post-handshake NewSessionTicket reaches the client
      // cache before this leg tears down (otherwise the next same-trust leg cannot resume)
      LOut := AnsiString(PING);
      LSock.Write(LOut[1], System.Length(LOut));
      SetLength(LBuf, 1024);
      LN := LSock.Read(LBuf[0], System.Length(LBuf));
      if LN <= 0 then
        raise Exception.Create('no echo on a connected leg');
      Result := LHandler.Resumed; // read before LSock.Free drops the handler
    finally
      LSock.Free;
    end;
  end;

  procedure Fail(const AMsg: string);
  begin
    WriteLn('FclNet resumption-scope FAIL: ', AMsg);
  end;

var
  LConnected: Boolean;
begin
  Result := 1;
  LReady := TEvent.Create(nil, True, False, '');
  try
    LLeaf := TVectorLocator.WriteDer('leaf', TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_cert'));
    LKey := TVectorLocator.WriteDer('key', TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_key'));
    LRoot := TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('EcP256Chain.txt', 'root_cert'));
    // a different, unrelated CA: it does NOT sign the server chain, so a full handshake under it
    // must fail - which is exactly what an isolated (correct) cache forces on the reject leg
    LWrongRoot := TVectorLocator.WriteDer('wrongroot',
      TVectorLocator.FieldHex('ClientAuthChain.txt', 'root_cert'));

    LServer := TServerThread.Create(LLeaf, LKey, LReady);
    try
      LServer.Start;
      LReady.WaitFor(5000);
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);

      // leg 1: trust A, first connection - a full handshake, nothing to resume yet
      if Leg(LRoot, LConnected) then
      begin
        Fail('leg 1 (trust A, first) unexpectedly resumed');
        Exit;
      end;
      if not LConnected then
      begin
        Fail('leg 1 (trust A, first) did not connect');
        Exit;
      end;

      // leg 2: trust A again, fresh handler - same signature => same memoised config+cache => resumes
      if not Leg(LRoot, LConnected) then
      begin
        Fail('leg 2 (trust A, second) did not resume - the adapter is not reusing the config/cache');
        Exit;
      end;

      // leg 3: a DIFFERENT root, otherwise identical - its own config+cache, so no resume, a full
      // handshake, and the wrong root rejects the server. A shared cache would resume A's session
      // (no certificate sent) and connect - the bypass
      if Leg(LWrongRoot, LConnected) or LConnected then
      begin
        Fail('leg 3 (trust B) connected/resumed - a different-trust config reused another''s session');
        Exit;
      end;

      // leg 4: trust A once more - proves leg 3 neither poisoned A's cache nor killed the server
      if not Leg(LRoot, LConnected) then
      begin
        Fail('leg 4 (trust A, again) did not resume after the reject leg');
        Exit;
      end;

      LServer.WaitFor;
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
    finally
      LServer.Free;
    end;

    WriteLn('FclNet resumption-scope PASS: same-trust resumes, different-trust is isolated');
    Result := 0;
  except
    on E: Exception do
      WriteLn('FclNet resumption-scope FAIL: ', E.ClassName, ': ', E.Message);
  end;
  LReady.Free;
end;

end.
