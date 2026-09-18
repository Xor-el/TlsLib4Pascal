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
/// A real loopback proving the Indy adapter scopes TLS resumption per trust config: two client
/// handlers with the SAME pinned root share the frozen config the adapter memoises (and its session
/// cache), so the second connection resumes; a handler with a DIFFERENT pinned root gets its own
/// config and cache, cannot see the first config's session, and does a full handshake - which its
/// (wrong) root then rejects. A shared cache or a signature that failed to distinguish the root
/// would instead resume the first session, send no certificate, and connect - the bypass this guards.
/// Four sequential legs against one server: full, resume, reject (isolation), resume-again. Shared
/// by the FreePascal and Delphi example programs.
/// </summary>
unit IndyResumptionScopeExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TIndyResumptionScopeExample = class sealed(TObject)
  public
    /// <summary>Runs the four-leg loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  IdContext,
  IdTCPServer,
  IdTCPClient,
  TlpDataEncoding,
  TlsLibIndyTls;

const
  PORT = 28449;
  PING = 'ping from the indy client';

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart, ARel: string): string; static;
  public
    class function FieldHex(const AVectorRel, AName: string): string; static;
    class function WriteDer(const AName, AHex: string): string; static;
  end;

  // echoes the one line a completed-handshake leg sends; a leg whose client rejects the certificate
  // never reaches here (its handshake fails first)
  TEchoHandler = class sealed(TObject)
  public
    procedure DoExecute(AContext: TIdContext);
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
    'tlslib_indyrs_' + AName + '.der';
  LFile := TFileStream.Create(Result, fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

procedure TEchoHandler.DoExecute(AContext: TIdContext);
begin
  try
    AContext.Connection.IOHandler.WriteLn(AContext.Connection.IOHandler.ReadLn);
  except
    // a leg the client aborts (the reject leg) surfaces here; not fatal to the server
  end;
end;

class function TIndyResumptionScopeExample.Run: Integer;
var
  LServer: TIdTCPServer;
  LServerIO: TTlsLibServerIOHandler;
  LEchoHandler: TEchoHandler;
  LRoot, LWrongRoot: string;

  // one leg: connect a fresh client with ARootFile as the pinned trust, echo a line, return whether
  // it resumed; AConnected reports whether the TLS handshake completed at all
  function Leg(const ARootFile: string; out AConnected: Boolean): Boolean;
  var
    LClient: TIdTCPClient;
    LClientIO: TTlsLibIOHandlerSocket;
  begin
    Result := False;
    AConnected := False;
    LClient := TIdTCPClient.Create(nil);
    try
      LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
      LClientIO.SSLOptions.RootCertFile := ARootFile; // pinned root (the only per-leg difference)
      LClient.IOHandler := LClientIO;
      LClient.Host := 'localhost';
      LClient.Port := PORT;
      try
        LClient.Connect;
        AConnected := True;
      except
        Exit; // the reject leg lands here: the wrong root refused the server certificate
      end;
      try
        // drain the round trip so the server's post-handshake NewSessionTicket reaches the client
        // cache before this leg disconnects (otherwise the next same-trust leg cannot resume)
        LClientIO.WriteLn(PING);
        if LClientIO.ReadLn <> PING then
          raise Exception.Create('no echo on a connected leg');
        Result := LClientIO.Resumed; // read before Disconnect drops the stream
      finally
        LClient.Disconnect;
      end;
    finally
      LClient.Free;
    end;
  end;

  procedure Fail(const AMsg: string);
  begin
    Writeln('Indy resumption-scope FAIL: ', AMsg);
  end;

var
  LConnected: Boolean;
begin
  Result := 1;
  LEchoHandler := TEchoHandler.Create;
  LServer := TIdTCPServer.Create(nil);
  try
    try
      LServerIO := TTlsLibServerIOHandler.Create(LServer);
      LServerIO.SSLOptions.CertFile := TVectorLocator.WriteDer('leaf',
        TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_cert'));
      LServerIO.SSLOptions.KeyFile := TVectorLocator.WriteDer('key',
        TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_key'));
      LServer.IOHandler := LServerIO;
      LServer.DefaultPort := PORT;
      LServer.OnExecute := LEchoHandler.DoExecute;
      LServer.Active := True;

      LRoot := TVectorLocator.WriteDer('root',
        TVectorLocator.FieldHex('EcP256Chain.txt', 'root_cert'));
      // a different, unrelated CA: it does NOT sign the server chain, so a full handshake under it
      // must fail - which is exactly what an isolated (correct) cache forces on the reject leg
      LWrongRoot := TVectorLocator.WriteDer('wrongroot',
        TVectorLocator.FieldHex('ClientAuthChain.txt', 'root_cert'));

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

      LServer.Active := False;
      Writeln('Indy resumption-scope PASS: same-trust resumes, different-trust is isolated');
      Result := 0;
    except
      on E: Exception do
        Writeln('Indy resumption-scope FAIL: ', E.ClassName, ': ', E.Message);
    end;
  finally
    LServer.Free;
    LEchoHandler.Free;
  end;
end;

end.
