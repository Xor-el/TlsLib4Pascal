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
/// A real loopback proving the mORMot adapter scopes TLS resumption per trust config: two clients
/// with the SAME pinned root share the frozen config the adapter memoises (and its session cache),
/// so the second connection resumes; a client with a DIFFERENT pinned root gets its own config and
/// cache, cannot see the first config's session, and does a full handshake - which its (wrong) root
/// then rejects. A shared cache or a signature that failed to distinguish the root would instead
/// resume the first session, send no certificate, and connect - the bypass this guards. Four
/// sequential legs against one server: full, resume, reject (isolation), resume-again. The concrete
/// TTlsLibNetTls is created directly (used via INetTls for the handshake) so its Resumed can be
/// read. Shared by the FreePascal and Delphi example programs.
/// </summary>
unit MormotResumptionScopeExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TMormotResumptionScopeExample = class sealed(TObject)
  public
    /// <summary>Runs the four-leg loopback; returns 0 on success, 1 on failure.</summary>
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
  TlsLibMormotTls;

const
  PORT = '28451';
  HOST = '127.0.0.1';
  PINGHEX = '70696e672066726f6d20746865206d6f724d6f7420636c69656e74';
  LEGS = 4; // the reject leg still opens a TCP connection, so the server accepts all four

var
  GLeafFile, GKeyFile: RawUtf8;
  GReady: TEvent;
  GServerError: string;

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart, ARel: string): string; static;
  public
    class function FieldHex(const AVectorRel, AName: string): string; static;
    class procedure WriteDer(const AName, AHex: string; out APath: RawUtf8); static;
  end;

  // accepts the LEGS connections in order, running the server handshake and echoing each completed
  // one; the reject leg's AfterAccept raises, which is caught and skipped
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

class procedure TVectorLocator.WriteDer(const AName, AHex: string; out APath: RawUtf8);
var
  LBytes: TBytes;
  LFile: TFileStream;
begin
  LBytes := TDataEncoding.HexDecode(AHex);
  APath := StringToUtf8(IncludeTrailingPathDelimiter(GetEnvironmentVariable('TEMP')) +
    'tlslib_mormotrs_' + AName + '.der');
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
  LLen, LI: Integer;
begin
  try
    FillCharFast(LCtx, SizeOf(LCtx), 0);
    LCtx.CertificateFile := GLeafFile;
    LCtx.PrivateKeyFile := GKeyFile;
    if NewSocket(HOST, PORT, nlTcp, {dobind=}True, 3000, 3000, 3000, 0, LListener) <> nrOK then
      raise Exception.Create('server bind failed');
    GReady.SetEvent;
    for LI := 1 to LEGS do
    begin
      if LListener.Accept(LClient, LAddr, {async=}False) <> nrOK then
        Break;
      LTls := TTlsLibNetTls.Create; // the interface owns it
      try
        // the reject leg's server-side handshake raises here; the completed legs echo one line
        LTls.AfterAccept(LClient, LCtx, @LLastErr, @LCipher);
        SetLength(LBuf, 4096);
        LLen := System.Length(LBuf);
        if LTls.Receive(@LBuf[0], LLen) = nrOK then
          LTls.Send(@LBuf[0], LLen);
      except
        // the reject leg: the client refused our certificate; not fatal to the server loop
      end;
      LTls := nil;
      LClient.ShutdownAndClose({rdwr=}True);
    end;
  except
    on E: Exception do
    begin
      GServerError := E.ClassName + ': ' + E.Message;
      GReady.SetEvent;
    end;
  end;
end;

class function TMormotResumptionScopeExample.Run: Integer;
var
  LServer: TServerThread;
  LRoot, LWrongRoot: RawUtf8;

  // one leg: connect a fresh client with ARootFile as the pinned trust, echo a line, return whether
  // it resumed; AConnected reports whether the TLS handshake completed at all
  function Leg(const ARootFile: RawUtf8; out AConnected: Boolean): Boolean;
  var
    LCtx: TNetTlsContext;
    LSock: TNetSocket;
    LConcrete: TTlsLibNetTls;
    LTls: INetTls;
    LPing, LEcho: TBytes;
    LLen: Integer;
  begin
    Result := False;
    AConnected := False;
    FillCharFast(LCtx, SizeOf(LCtx), 0);
    LCtx.CACertificatesFile := ARootFile; // pinned root (the only per-leg difference)
    if NewSocket(HOST, PORT, nlTcp, {dobind=}False, 3000, 3000, 3000, 0, LSock) <> nrOK then
      raise Exception.Create('tcp connect failed');
    LConcrete := TTlsLibNetTls.Create;
    LTls := LConcrete; // used via INetTls; the interface owns it
    try
      try
        LTls.AfterConnection(LSock, LCtx, 'localhost');
        AConnected := True;
      except
        LSock.ShutdownAndClose(True);
        Exit; // the reject leg lands here: the wrong root refused the server certificate
      end;
      // drain the round trip so the server's post-handshake NewSessionTicket reaches the client
      // cache before this leg tears down (otherwise the next same-trust leg cannot resume)
      LPing := TDataEncoding.HexDecode(PINGHEX);
      LLen := System.Length(LPing);
      LTls.Send(@LPing[0], LLen);
      SetLength(LEcho, 4096);
      LLen := System.Length(LEcho);
      if (LTls.Receive(@LEcho[0], LLen) <> nrOK) or (LLen <> System.Length(LPing)) then
        raise Exception.Create('no echo on a connected leg');
      Result := LConcrete.Resumed;
    finally
      LTls := nil;
      LSock.ShutdownAndClose(True);
    end;
  end;

  procedure Fail(const AMsg: string);
  begin
    Writeln('mORMot resumption-scope FAIL: ', AMsg);
  end;

var
  LConnected: Boolean;
begin
  Result := 1;
  GServerError := '';
  GReady := TEvent.Create(nil, True, False, '');
  try
    TVectorLocator.WriteDer('leaf', TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_cert'), GLeafFile);
    TVectorLocator.WriteDer('key', TVectorLocator.FieldHex('EcP256Chain.txt', 'leaf_key'), GKeyFile);
    TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('EcP256Chain.txt', 'root_cert'), LRoot);
    // a different, unrelated CA: it does NOT sign the server chain, so a full handshake under it
    // must fail - which is exactly what an isolated (correct) cache forces on the reject leg
    TVectorLocator.WriteDer('wrongroot',
      TVectorLocator.FieldHex('ClientAuthChain.txt', 'root_cert'), LWrongRoot);

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

    Writeln('mORMot resumption-scope PASS: same-trust resumes, different-trust is isolated');
    Result := 0;
  except
    on E: Exception do
      Writeln('mORMot resumption-scope FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
