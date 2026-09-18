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
/// A real loopback proving the Synapse plugin scopes TLS resumption per trust config: two clients
/// with the SAME pinned root share the frozen config the adapter memoises (and its session cache),
/// so the second connection resumes; a client with a DIFFERENT pinned root gets its own config and
/// cache, cannot see the first config's session, and does a full handshake - which its (wrong) root
/// then rejects. A shared cache or a signature that failed to distinguish the root would instead
/// resume the first session, send no certificate, and connect - the bypass this guards. Four
/// sequential legs against one server: full, resume, reject (isolation), resume-again. Shared by the
/// FreePascal and Delphi example programs.
/// </summary>
unit SynapseResumptionScopeExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TSynapseResumptionScopeExample = class sealed(TObject)
  public
    /// <summary>Runs the four-leg loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  blcksock,
  TlpDataEncoding,
  TlsLibSynapseTls;

const
  PORT = '28450';
  PING = 'ping from the synapse client';
  CRLF = #13#10;
  LEGS = 4; // the reject leg still opens a TCP connection, so the server accepts all four

var
  GLeafFile, GKeyFile: string;
  GReady: TEvent;
  GServerError: string;

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart, ARel: string): string; static;
  public
    class function FieldHex(const AVectorRel, AName: string): string; static;
    class function WriteDer(const AName, AHex: string): string; static;
  end;

  // accepts the LEGS connections in order, running the server handshake and echoing each completed
  // one; the reject leg's SSLAcceptConnection returns False, which is skipped
  TServerThread = class(TThread)
  protected
    procedure Execute; override;
  end;

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
  LPath, LRel, LPrefix: string;
  LLines: TStringList;
  LI: Integer;
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
  Result := IncludeTrailingPathDelimiter(GetEnvironmentVariable('TEMP')) +
    'tlslib_synrs_' + AName + '.der';
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
  LListener, LPeer: TTCPBlockSocket;
  LI: Integer;
begin
  LListener := TTCPBlockSocket.Create;
  try
    try
      LListener.CreateSocket;
      LListener.SetLinger(True, 1000);
      LListener.Bind('127.0.0.1', PORT);
      LListener.Listen;
      GReady.SetEvent;
      for LI := 1 to LEGS do
      begin
        if not LListener.CanRead(5000) then
          Break;
        LPeer := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
        try
          LPeer.Socket := LListener.Accept;
          LPeer.SSL.CertificateFile := GLeafFile;
          LPeer.SSL.PrivateKeyFile := GKeyFile;
          // the reject leg's handshake fails here (returns False); the completed legs echo one line
          if LPeer.SSLAcceptConnection then
            LPeer.SendString(LPeer.RecvString(5000) + CRLF);
        finally
          LPeer.Free;
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

class function TSynapseResumptionScopeExample.Run: Integer;
var
  LServer: TServerThread;
  LRoot, LWrongRoot: string;

  // one leg: connect a fresh client with ARootFile as the pinned trust, echo a line, return whether
  // it resumed; AConnected reports whether the TLS handshake completed at all
  function Leg(const ARootFile: string; out AConnected: Boolean): Boolean;
  var
    LClient: TTCPBlockSocket;
  begin
    Result := False;
    AConnected := False;
    LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
    try
      LClient.SSL.CertCAFile := ARootFile; // pinned root (the only per-leg difference)
      LClient.SSL.VerifyCert := True;
      LClient.SSL.SNIHost := 'localhost';
      LClient.Connect('127.0.0.1', PORT);
      if LClient.LastError <> 0 then
        raise Exception.Create('tcp connect failed');
      LClient.SSLDoConnect;
      if not LClient.SSL.SSLEnabled then
        Exit; // the reject leg lands here: the wrong root refused the server certificate
      AConnected := True;
      // drain the round trip so the server's post-handshake NewSessionTicket reaches the client
      // cache before this leg tears down (otherwise the next same-trust leg cannot resume)
      LClient.SendString(PING + CRLF);
      if LClient.RecvString(5000) <> PING then
        raise Exception.Create('no echo on a connected leg');
      Result := (LClient.SSL as TSSLTlsLib).Resumed; // read before LClient.Free drops the stream
    finally
      LClient.Free;
    end;
  end;

  procedure Fail(const AMsg: string);
  begin
    Writeln('Synapse resumption-scope FAIL: ', AMsg);
  end;

var
  LConnected: Boolean;
begin
  Result := 1;
  GServerError := '';
  GReady := TEvent.Create(nil, True, False, '');
  try
    GLeafFile := TVectorLocator.WriteDer('leaf',
      TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_cert'));
    GKeyFile := TVectorLocator.WriteDer('key',
      TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_key'));
    LRoot := TVectorLocator.WriteDer('root',
      TVectorLocator.FieldHex('EcP256Chain.txt', 'root_cert'));
    // a different, unrelated CA: it does NOT sign the server chain, so a full handshake under it
    // must fail - which is exactly what an isolated (correct) cache forces on the reject leg
    LWrongRoot := TVectorLocator.WriteDer('wrongroot',
      TVectorLocator.FieldHex('ClientAuthChain.txt', 'root_cert'));

    LServer := TServerThread.Create(True);
    LServer.FreeOnTerminate := False;
    try
      LServer.Start;
      GReady.WaitFor(5000);
      if GServerError <> '' then
        raise Exception.Create('server: ' + GServerError);

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

      // leg 2: trust A again, fresh client - same signature => same memoised config+cache => resumes
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
      if GServerError <> '' then
        raise Exception.Create('server: ' + GServerError);
    finally
      LServer.Free;
    end;

    Writeln('Synapse resumption-scope PASS: same-trust resumes, different-trust is isolated');
    Result := 0;
  except
    on E: Exception do
      Writeln('Synapse resumption-scope FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
