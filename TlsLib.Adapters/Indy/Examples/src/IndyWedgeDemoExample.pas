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
/// A heavy-throughput loopback over the Indy adapter on 127.0.0.1, to confirm the record layer
/// keeps making progress under sustained bulk transfer (no wedge). It runs in two phases over
/// one connection so a single blocking socket never deadlocks: phase 1 streams a large payload
/// client -> server (the client's outbound path), phase 2 streams it back server -> client (the
/// server's outbound path). Each side only writes or only reads within a phase, so the reader
/// always drains the pipe. A watchdog aborts the process if progress stops, so a wedge fails
/// loudly instead of hanging. Shared by the FreePascal and Delphi example programs.
/// </summary>
unit IndyWedgeDemoExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TIndyWedgeDemoExample = class sealed(TObject)
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
  IdGlobal,
  IdContext,
  IdIOHandler,
  IdTCPServer,
  IdTCPClient,
  TlpDataEncoding,
  TlsLibIndyTls;

const
  PORT = 28451;
  BULK = 32 * 1024 * 1024;    // total bytes streamed each way
  CHUNK = 1024 * 1024;        // per Write/Read: many records per write (>16 KiB record ceiling)
  WEDGE_TIMEOUT_MS = 30000;

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

  TBulkHandler = class sealed(TObject)
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
    'tlslib_indywedge_' + AName + '.der';
  LFile := TFileStream.Create(Result, fmCreate);
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
    WriteLn('Indy wedge demo FAIL: no progress within ', FDeadlineMs, ' ms (wedge)');
    Flush(Output);
    Halt(2);
  end;
end;

procedure TWatchdog.Disarm;
begin
  FDone.SetEvent;
end;

{ TBulkHandler }

procedure TBulkHandler.DoExecute(AContext: TIdContext);
var
  LIo: TIdIOHandler;
  LChunk, LRx: TIdBytes;
  LI: Integer;
  LMoved: Int64;
begin
  try
    LIo := AContext.Connection.IOHandler;
    SetLength(LChunk, CHUNK);
    for LI := 0 to CHUNK - 1 do
      LChunk[LI] := Byte(LI);
    // phase 1: drain BULK bytes from the client (AEAD integrity guarantees the content)
    LMoved := 0;
    while LMoved < BULK do
    begin
      LIo.ReadBytes(LRx, CHUNK, False); // reads exactly CHUNK
      Inc(LMoved, CHUNK);
    end;
    // phase 2: stream BULK bytes back
    LMoved := 0;
    while LMoved < BULK do
    begin
      LIo.Write(LChunk);
      Inc(LMoved, CHUNK);
    end;
    AContext.Connection.Disconnect; // end this connection's execute loop cleanly
  except
    on E: Exception do
      GServerError := E.ClassName + ': ' + E.Message;
  end;
end;

{ TIndyWedgeDemoExample }

class function TIndyWedgeDemoExample.Run: Integer;
var
  LServer: TIdTCPServer;
  LServerIO: TTlsLibServerIOHandler;
  LClient: TIdTCPClient;
  LClientIO: TTlsLibIOHandlerSocket;
  LHandler: TBulkHandler;
  LWatch: TWatchdog;
  LChunk, LRx: TIdBytes;
  LI: Integer;
  LMoved: Int64;
  LStart: TDateTime;
  LSeconds, LMbps: Double;
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GVector := TVectorLocator.Find;
  LOk := True;
  LSeconds := 0.0;
  LHandler := TBulkHandler.Create;
  LServer := TIdTCPServer.Create(nil);
  LClient := TIdTCPClient.Create(nil);
  LWatch := TWatchdog.Create(WEDGE_TIMEOUT_MS);
  try
    LServerIO := TTlsLibServerIOHandler.Create(LServer);
    LServerIO.SSLOptions.CertFile := TVectorLocator.WriteDer('leaf',
      TVectorLocator.FieldHex('leaf_cert'));
    LServerIO.SSLOptions.KeyFile := TVectorLocator.WriteDer('key',
      TVectorLocator.FieldHex('leaf_key'));
    LServer.IOHandler := LServerIO;
    LServer.DefaultPort := PORT;
    LServer.OnExecute := LHandler.DoExecute;
    LServer.Active := True;

    LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
    LClientIO.SSLOptions.RootCertFile := TVectorLocator.WriteDer('root',
      TVectorLocator.FieldHex('root_cert'));
    LClient.IOHandler := LClientIO;
    LClient.Host := 'localhost';
    LClient.Port := PORT;
    LClient.Connect;
    try
      LWatch.Start;
      LStart := Now;
      SetLength(LChunk, CHUNK);
      for LI := 0 to CHUNK - 1 do
        LChunk[LI] := Byte(LI);

      // phase 1: stream BULK to the server (many records per write)
      LMoved := 0;
      while LMoved < BULK do
      begin
        LClientIO.Write(LChunk);
        Inc(LMoved, CHUNK);
      end;

      // phase 2: read BULK back and verify the pattern
      LMoved := 0;
      while LMoved < BULK do
      begin
        LClientIO.ReadBytes(LRx, CHUNK, False);
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
    finally
      LClient.Disconnect;
    end;

    LServer.Active := False;

    if LOk and (GServerError = '') then
    begin
      if LSeconds > 0.0 then
        LMbps := (Int64(2) * BULK) / LSeconds / 1024.0 / 1024.0
      else
        LMbps := 0.0;
      WriteLn(Format('Indy wedge demo PASS: %d MB each way, no wedge, %.1f MB/s aggregate',
        [BULK div (1024 * 1024), LMbps]));
      Result := 0;
    end
    else
      WriteLn('Indy wedge demo FAIL: payload mismatch or server error="', GServerError, '"');
  except
    on E: Exception do
      WriteLn('Indy wedge demo FAIL: ', E.ClassName, ': ', E.Message,
        ' server="', GServerError, '"');
  end;
  LWatch.Disarm;
  LWatch.WaitFor;
  LWatch.Free;
  LClient.Free;
  LServer.Free;
  LHandler.Free;
end;

end.
