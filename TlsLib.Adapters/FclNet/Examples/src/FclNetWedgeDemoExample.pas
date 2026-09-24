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
/// A heavy-throughput loopback over the fcl-net adapter on 127.0.0.1, to confirm the record
/// layer keeps making progress under sustained bulk transfer (no wedge). It runs in two phases
/// over one connection so a single blocking socket never deadlocks: phase 1 streams a large
/// payload client -> server (exercising the client's outbound path), phase 2 streams it back
/// server -> client (the server's outbound path). Each side only writes or only reads within a
/// phase, so the reader always drains the pipe. A watchdog aborts the process if either side
/// stops making progress, so a wedge fails loudly instead of hanging.
/// </summary>
unit FclNetWedgeDemoExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TFclNetWedgeDemoExample = class sealed(TObject)
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
  ssockets,
  TlpDataEncoding,
  TlsLibFclNetTls;

const
  PORT = 28450;
  // total bytes streamed in each direction; large enough that one direction queues many records
  // and the pump drains them in many takes - the shape the outbound buffer governs
  BULK = 32 * 1024 * 1024;
  // per Write/Read call: well above the 16 KiB record ceiling, so each write queues several records
  CHUNK = 1024 * 1024;
  // if a phase makes no progress for this long, treat it as a wedge and abort
  WEDGE_TIMEOUT_MS = 30000;

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

  /// <summary>Aborts the process if not disarmed before the deadline, so a wedged transfer fails
  /// loudly with a non-zero exit instead of hanging the run.</summary>
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

  /// <summary>The loopback server: reads BULK bytes (phase 1), then writes BULK bytes back
  /// (phase 2), so each phase moves data in a single direction.</summary>
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
  Result := IncludeTrailingPathDelimiter(GetTempDir) + 'tlslib_fclwedge_' + AName + '.der';
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
    WriteLn('FclNet wedge demo FAIL: no progress within ', FDeadlineMs, ' ms (wedge)');
    Flush(Output);
    Halt(2);
  end;
end;

procedure TWatchdog.Disarm;
begin
  FDone.SetEvent;
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
  LGot, LSent, LOff: Integer;
  LReceived: Int64;
begin
  try
    SetLength(LBuf, CHUNK);
    // phase 1: drain BULK bytes from the client
    LReceived := 0;
    while LReceived < BULK do
    begin
      LGot := AStream.Read(LBuf[0], System.Length(LBuf));
      if LGot <= 0 then
        raise Exception.Create('client closed during phase 1');
      Inc(LReceived, LGot);
    end;
    // phase 2: stream BULK bytes back (fill from a fixed pattern; the client verifies it)
    for LOff := 0 to System.High(LBuf) do
      LBuf[LOff] := Byte(LOff);
    LSent := 0;
    while LSent < BULK do
    begin
      LGot := BULK - LSent;
      if LGot > System.Length(LBuf) then
        LGot := System.Length(LBuf);
      AStream.WriteBuffer(LBuf[0], LGot);
      Inc(LSent, LGot);
    end;
  except
    on E: Exception do
      FError := 'server connection: ' + E.ClassName + ': ' + E.Message;
  end;
  AStream.Free; // flushes close_notify then closes the socket
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
      LServer.Listen;
      FReady.SetEvent;
      LServer.StartAccepting;
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

{ TFclNetWedgeDemoExample }

class function TFclNetWedgeDemoExample.Run: Integer;
var
  LServer: TServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LReady: TEvent;
  LWatch: TWatchdog;
  LLeaf, LKey, LRoot: string;
  LTx, LRx: TBytes;
  LGot, LSent, LOff: Integer;
  LReceived: Int64;
  LStart: TDateTime;
  LSeconds, LMbps: Double;
  LOk: Boolean;
begin
  Result := 1;
  TVectorLocator.Locate;
  LReady := TEvent.Create(nil, True, False, '');
  LWatch := TWatchdog.Create(WEDGE_TIMEOUT_MS);
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

      LHandler := TTlsLibSocketHandler.Create;
      LHandler.CertificateData.CertCA.FileName := LRoot;
      LSock := TInetSocket.Create('localhost', PORT, LHandler);
      try
        try
          LSock.Connect;
        except
          on E: ESocketError do
            raise Exception.Create('handshake failed: ' + LHandler.LastErrorDesc);
        end;
        LWatch.Start;
        LStart := Now;

        // phase 1: stream BULK to the server in large chunks (many records per write)
        SetLength(LTx, CHUNK);
        for LOff := 0 to System.High(LTx) do
          LTx[LOff] := Byte(LOff);
        LSent := 0;
        while LSent < BULK do
        begin
          LGot := BULK - LSent;
          if LGot > System.Length(LTx) then
            LGot := System.Length(LTx);
          LSock.WriteBuffer(LTx[0], LGot);
          Inc(LSent, LGot);
        end;

        // phase 2: read BULK back and verify the server's pattern byte-for-byte
        SetLength(LRx, CHUNK);
        LReceived := 0;
        LOk := True;
        while LReceived < BULK do
        begin
          LGot := LSock.Read(LRx[0], System.Length(LRx));
          if LGot <= 0 then
            raise Exception.Create('server closed during phase 2');
          for LOff := 0 to LGot - 1 do
            if LRx[LOff] <> Byte((LReceived + LOff) mod System.Length(LTx)) then
            begin
              LOk := False;
              Break;
            end;
          Inc(LReceived, LGot);
        end;

        LSeconds := MilliSecondsBetween(Now, LStart) / 1000.0;
        LWatch.Disarm;
      finally
        LSock.Free;
      end;

      LServer.WaitFor;
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
    finally
      LServer.Free;
    end;

    if LOk and (LReceived = BULK) then
    begin
      if LSeconds > 0.0 then
        LMbps := (Int64(2) * BULK) / LSeconds / 1024.0 / 1024.0
      else
        LMbps := 0.0;
      WriteLn(Format('FclNet wedge demo PASS: %d MB each way, no wedge, %.1f MB/s aggregate',
        [BULK div (1024 * 1024), LMbps]));
      Result := 0;
    end
    else
      WriteLn('FclNet wedge demo FAIL: payload mismatch or short read');
  except
    on E: Exception do
      WriteLn('FclNet wedge demo FAIL: ', E.ClassName, ': ', E.Message);
  end;
  LWatch.Disarm;
  LWatch.WaitFor;
  LWatch.Free;
  LReady.Free;
end;

end.
