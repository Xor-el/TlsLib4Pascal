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
/// A heavy-throughput loopback over the mORMot adapter on 127.0.0.1, to confirm the record
/// layer keeps making progress under sustained bulk transfer (no wedge). It runs in two phases
/// over one connection so a single blocking socket never deadlocks: phase 1 streams a large
/// payload client -> server (the client's outbound path), phase 2 streams it back
/// server -> client (the server's outbound path). Each side only writes or only reads within a
/// phase. A watchdog aborts the process if progress stops. Shared by the FreePascal and Delphi
/// example programs.
/// </summary>
unit MormotWedgeDemoExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TMormotWedgeDemoExample = class sealed(TObject)
  public
    /// <summary>Runs the demo; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  DateUtils,
  mormot.core.base,
  mormot.core.unicode,
  mormot.net.sock,
  TlpDataEncoding,
  TlsLibMormotTls;

const
  PORT = '28453';
  HOST = '127.0.0.1';
  BULK = 32 * 1024 * 1024;
  CHUNK = 1024 * 1024;
  WEDGE_TIMEOUT_MS = 45000;

var
  GLeafFile, GKeyFile, GRootFile: RawUtf8;
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
    class procedure WriteDer(const AName, AHex: string; out APath: RawUtf8); static;
  end;

  TWatchdog = class(TThread)
  strict private
  var
    FDone: TEvent;
    FDeadlineMs: UInt32;
  protected
    procedure Execute; override;
  public
    constructor Create(ADeadlineMs: UInt32);
    destructor Destroy; override;
    procedure Disarm;
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
    'tlslib_mormotwedge_' + AName + '.der');
  LFile := TFileStream.Create(Utf8ToString(APath), fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

{ TWatchdog }

constructor TWatchdog.Create(ADeadlineMs: UInt32);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FDeadlineMs := ADeadlineMs;
  FDone := TEvent.Create(nil, True, False, '');
end;

destructor TWatchdog.Destroy;
begin
  inherited Destroy;
  FDone.Free;
end;

procedure TWatchdog.Execute;
begin
  if FDone.WaitFor(FDeadlineMs) = wrTimeout then
  begin
    WriteLn('mORMot wedge demo FAIL: no progress within ', FDeadlineMs, ' ms (wedge)');
    Flush(Output);
    Halt(2);
  end;
end;

procedure TWatchdog.Disarm;
begin
  FDone.SetEvent;
end;

{ TServerThread }

procedure TServerThread.Execute;
var
  LListener, LClient: TNetSocket;
  LAddr: TNetAddr;
  LCtx: TNetTlsContext;
  LTls: INetTls;
  LLastErr, LCipher: RawUtf8;
  LChunk, LRx: TBytes;
  LI, LOff, LLen: Integer;
  LMoved: Int64;
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

    SetLength(LChunk, CHUNK);
    SetLength(LRx, CHUNK);
    for LI := 0 to CHUNK - 1 do
      LChunk[LI] := Byte(LI);
    // phase 1: drain BULK from the client
    LMoved := 0;
    while LMoved < BULK do
    begin
      LOff := 0;
      while LOff < CHUNK do
      begin
        LLen := CHUNK - LOff;
        if LTls.Receive(@LRx[LOff], LLen) <> nrOK then
          raise Exception.Create('server receive failed');
        if LLen <= 0 then
          raise Exception.Create('client closed during phase 1');
        Inc(LOff, LLen);
      end;
      Inc(LMoved, CHUNK);
    end;
    // phase 2: stream BULK back
    LMoved := 0;
    while LMoved < BULK do
    begin
      LOff := 0;
      while LOff < CHUNK do
      begin
        LLen := CHUNK - LOff;
        if LTls.Send(@LChunk[LOff], LLen) <> nrOK then
          raise Exception.Create('server send failed');
        Inc(LOff, LLen);
      end;
      Inc(LMoved, CHUNK);
    end;
  except
    on E: Exception do
    begin
      GServerError := E.ClassName + ': ' + E.Message;
      GReady.SetEvent;
    end;
  end;
end;

{ TMormotWedgeDemoExample }

class function TMormotWedgeDemoExample.Run: Integer;
var
  LServer: TServerThread;
  LCtx: TNetTlsContext;
  LSock: TNetSocket;
  LTls: INetTls;
  LWatch: TWatchdog;
  LChunk, LRx: TBytes;
  LI, LOff, LLen: Integer;
  LMoved: Int64;
  LStart: TDateTime;
  LSeconds, LMbps: Double;
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GVector := TVectorLocator.Find;
  GReady := TEvent.Create(nil, True, False, '');
  LWatch := TWatchdog.Create(WEDGE_TIMEOUT_MS);
  LOk := True;
  LSeconds := 0.0;
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
    LTls.AfterConnection(LSock, LCtx, 'localhost');

    LWatch.Start;
    LStart := Now;
    SetLength(LChunk, CHUNK);
    SetLength(LRx, CHUNK);
    for LI := 0 to CHUNK - 1 do
      LChunk[LI] := Byte(LI);

    // phase 1: stream BULK to the server
    LMoved := 0;
    while LMoved < BULK do
    begin
      LOff := 0;
      while LOff < CHUNK do
      begin
        LLen := CHUNK - LOff;
        if LTls.Send(@LChunk[LOff], LLen) <> nrOK then
          raise Exception.Create('client send failed');
        Inc(LOff, LLen);
      end;
      Inc(LMoved, CHUNK);
    end;

    // phase 2: read BULK back and verify the pattern
    LMoved := 0;
    while LMoved < BULK do
    begin
      LOff := 0;
      while LOff < CHUNK do
      begin
        LLen := CHUNK - LOff;
        if LTls.Receive(@LRx[LOff], LLen) <> nrOK then
          raise Exception.Create('client receive failed');
        if LLen <= 0 then
          raise Exception.Create('server closed during phase 2');
        Inc(LOff, LLen);
      end;
      for LI := 0 to CHUNK - 1 do
        if LRx[LI] <> Byte(LI) then
        begin
          LOk := False;
          Break;
        end;
      Inc(LMoved, CHUNK);
    end;

    LSeconds := MilliSecondsBetween(Now, LStart) / 1000.0;
    LWatch.Disarm;

    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);
    LServer.Free;

    if LOk then
    begin
      if LSeconds > 0.0 then
        LMbps := (Int64(2) * BULK) / LSeconds / 1024.0 / 1024.0
      else
        LMbps := 0.0;
      WriteLn(Format('mORMot wedge demo PASS: %d MB each way, no wedge, %.1f MB/s aggregate',
        [BULK div (1024 * 1024), LMbps]));
      Result := 0;
    end
    else
      WriteLn('mORMot wedge demo FAIL: payload mismatch');
  except
    on E: Exception do
      WriteLn('mORMot wedge demo FAIL: ', E.ClassName, ': ', E.Message);
  end;
  LWatch.Disarm;
  LWatch.WaitFor;
  LWatch.Free;
  GReady.Free;
end;

end.
