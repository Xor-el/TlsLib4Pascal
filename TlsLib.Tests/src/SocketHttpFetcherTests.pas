{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SocketHttpFetcherTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  SyncObjs,
{$IFDEF FPC}
  fpcunit,
  testregistry,
  Sockets,
{$IFDEF UNIX}
  UnixType,
  fphttpclient, // TEMP-DIAG
{$ENDIF}
{$ELSE}
  TestFramework,
  System.Net.Socket,
{$ENDIF FPC}
  TlpIClock,
  TlpClock,
  TlpIHttpFetcher,
  TlpTlsLibExceptions,
  TlpSocketHttpFetcher,
  MockClock,
  TlsLibTestBase;

type
  /// <summary>
  /// The fetcher's timeout bounds the whole exchange: a responder that keeps sending, each read
  /// inside the per-read wait, still stops at the budget. The body case steps a mock clock so it
  /// does not wait; the header case runs against the real clock, because no progress callback
  /// exists in that phase on every client and the budget must come from elapsed time.
  /// </summary>
  TTestSocketHttpFetcher = class(TTlsLibTestCase)
  published
    procedure TestSteadyResponseWithinBudgetIsFetched;
    procedure TestLongResponseIsCutOffAtTheBudget;
    procedure TestTrickledHeadersAreCutOffAtTheBudget;
    procedure TestNilClockIsRefused;
{$IFDEF UNIX}
    procedure TestTempDiagTimeoutOption; // TEMP-DIAG
{$ENDIF}
  end;

implementation

{$IFDEF FPC}
const
  // a client that has given up must not kill the process with SIGPIPE on the next send:
  // MSG_NOSIGNAL per send where it exists, else the SO_NOSIGPIPE option (Darwin)
{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}
  SEND_FLAGS = 0;
  NOSIGPIPE_SOCKOPT = SO_NOSIGPIPE;
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID) OR DEFINED(TLSLIB_BSD)}
  SEND_FLAGS = MSG_NOSIGNAL;
  NOSIGPIPE_SOCKOPT = 0;
{$ELSE}
  SEND_FLAGS = 0;
  NOSIGPIPE_SOCKOPT = 0;
{$IFEND}
{$ENDIF}

type
  // a one-connection server on 127.0.0.1; the socket calls live here and nowhere else
  TLoopbackServer = class(TObject)
  strict private
    FPort: Word;
    FClosed: Boolean;
    FClient, FListener: TSocket;
  public
    constructor Create;
    destructor Destroy; override;
    property Port: Word read FPort;
    // waits for the client; False once the server has been closed
    function Accept: Boolean;
    // up to ACount bytes; 0 or less once the client has gone
    function Receive(var ABuffer; ACount: Int32): Int32;
    function Send(const ABuffer; ACount: Int32): Boolean;
    // frees an Accept that is waiting
    procedure Close;
  end;

  // answers one request with a large body in small writes, or with a response head that arrives a
  // line at a time
  TResponder = class(TThread)
  strict private
  const
    BodyChunk = 1024;
    HeaderLines = 100;
    HeaderPauseMs = 100;
  var
    FServer: TLoopbackServer;
    FBodySize: Int32;
    FTrickleHeaders: Boolean;
    FStop: TEvent;
    function SendText(const AText: AnsiString): Boolean;
    function ReadRequest: Boolean;
    procedure SendHeadTrickled;
    procedure SendBody;
  protected
    procedure Execute; override;
  public
    constructor Create(ABodySize: Int32; ATrickleHeaders: Boolean);
    destructor Destroy; override;
    function Url: string;
  end;

{ TLoopbackServer }

constructor TLoopbackServer.Create;
{$IFDEF FPC}
var
  LAddr: TInetSockAddr;
  LLen: TSockLen;
{$ENDIF}
begin
  inherited Create;
{$IFDEF FPC}
  FClient := -1;
  FListener := fpSocket(AF_INET, SOCK_STREAM, 0);
  LAddr := Default(TInetSockAddr);
  LAddr.sin_family := AF_INET;
  LAddr.sin_addr.s_addr := HToNL($7F000001);
  fpBind(FListener, @LAddr, SizeOf(LAddr));
  fpListen(FListener, 1);
  LLen := SizeOf(LAddr);
  fpGetSockName(FListener, @LAddr, @LLen);
  FPort := NToHs(LAddr.sin_port);
{$ELSE}
  FListener := TSocket.Create(TSocketType.TCP);
  FListener.Listen('127.0.0.1', '', 0);
  FPort := FListener.LocalEndpoint.Port;
{$ENDIF}
end;

destructor TLoopbackServer.Destroy;
begin
  Close;
{$IFDEF FPC}
  if FClient >= 0 then
    CloseSocket(FClient);
{$ELSE}
  // a forced close skips the shutdown that fails on a listener or a client that has gone
  if FClient <> nil then
    FClient.Close(True);
  FListener.Close(True);
  FClient.Free;
  FListener.Free;
{$ENDIF}
  inherited Destroy;
end;

function TLoopbackServer.Accept: Boolean;
{$IFDEF FPC}
var
  LOn: Integer;
{$ENDIF}
begin
{$IFDEF FPC}
  FClient := fpAccept(FListener, nil, nil);
  Result := FClient >= 0;
  if Result and (NOSIGPIPE_SOCKOPT <> 0) then
  begin
    LOn := 1;
    fpSetSockOpt(FClient, SOL_SOCKET, NOSIGPIPE_SOCKOPT, @LOn, SizeOf(LOn));
  end;
{$ELSE}
  // short waits, so a Close from another thread is noticed
  while (FClient = nil) and not FClosed do
    FClient := FListener.Accept(100);
  Result := FClient <> nil;
{$ENDIF}
end;

function TLoopbackServer.Receive(var ABuffer; ACount: Int32): Int32;
begin
{$IFDEF FPC}
  Result := fpRecv(FClient, @ABuffer, ACount, 0);
{$ELSE}
  Result := FClient.Receive(ABuffer, ACount);
{$ENDIF}
end;

function TLoopbackServer.Send(const ABuffer; ACount: Int32): Boolean;
begin
{$IFDEF FPC}
  Result := fpSend(FClient, @ABuffer, ACount, SEND_FLAGS) > 0;
{$ELSE}
  Result := FClient.Send(ABuffer, ACount) > 0;
{$ENDIF}
end;

procedure TLoopbackServer.Close;
begin
  if FClosed then
    Exit;
  FClosed := True;
{$IFDEF FPC}
  // a shutdown wakes an accept blocked in another thread, which a close alone does not on Linux
  fpShutdown(FListener, SHUT_RDWR);
  CloseSocket(FListener);
{$ENDIF}
end;

{ TResponder }

constructor TResponder.Create(ABodySize: Int32; ATrickleHeaders: Boolean);
begin
  FServer := TLoopbackServer.Create;
  FBodySize := ABodySize;
  FTrickleHeaders := ATrickleHeaders;
  FStop := TEvent.Create(nil, True, False, '');
  inherited Create(False);
end;

destructor TResponder.Destroy;
begin
  // the event frees a response pause, and closing the server frees an accept
  FStop.SetEvent;
  FServer.Close;
  WaitFor;
  FStop.Free;
  FServer.Free;
  inherited Destroy;
end;

function TResponder.Url: string;
begin
  Result := 'http://127.0.0.1:' + IntToStr(FServer.Port) + '/';
end;

function TResponder.SendText(const AText: AnsiString): Boolean;
begin
  Result := FServer.Send(AText[1], System.Length(AText));
end;

function TResponder.ReadRequest: Boolean;
var
  LBuffer: array [0 .. 4095] of AnsiChar;
  LSeen, LPiece: AnsiString;
  LGot: Int32;
begin
  Result := False;
  LSeen := '';
  repeat
    LGot := FServer.Receive(LBuffer, SizeOf(LBuffer));
    if LGot <= 0 then
      Exit;
    SetString(LPiece, PAnsiChar(@LBuffer[0]), LGot);
    LSeen := LSeen + LPiece;
  until Pos(#13#10#13#10, string(LSeen)) > 0;
  Result := True;
end;

procedure TResponder.SendHeadTrickled;
var
  LI: Int32;
begin
  // a head that never completes, yet never leaves a gap as long as any read wait
  if not SendText('HTTP/1.1 200 OK'#13#10) then
    Exit;
  for LI := 1 to HeaderLines do
  begin
    if not SendText('X-Pad: v'#13#10) then
      Exit;
    if FStop.WaitFor(HeaderPauseMs) = wrSignaled then
      Exit;
  end;
end;

procedure TResponder.SendBody;
var
  LChunk: AnsiString;
  LSent, LCount: Int32;
begin
  if not SendText(AnsiString('HTTP/1.1 200 OK'#13#10'Content-Length: ' + IntToStr(FBodySize) +
    #13#10'Connection: close'#13#10#13#10)) then
    Exit;
  LChunk := AnsiString(StringOfChar('A', BodyChunk));
  LSent := 0;
  while LSent < FBodySize do
  begin
    LCount := FBodySize - LSent;
    if LCount > BodyChunk then
      LCount := BodyChunk;
    if not FServer.Send(LChunk[1], LCount) then
      Exit;
    Inc(LSent, LCount);
  end;
end;

procedure TResponder.Execute;
begin
  if not FServer.Accept then
    Exit;
  if not ReadRequest then
    Exit;
  if FTrickleHeaders then
    SendHeadTrickled
  else
    SendBody;
end;

{ TTestSocketHttpFetcher }

procedure TTestSocketHttpFetcher.TestSteadyResponseWithinBudgetIsFetched;
var
  LResponder: TResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
begin
  // a clock that never moves leaves the whole budget, so the full body arrives
  LResponder := TResponder.Create(256 * 1024, False);
  try
    LFetcher := TSocketHttpFetcher.Create(TMockMonotonicClock.Create(1000, 0) as ITlsMonotonicClock);
    CheckTrue(LFetcher.Get(LResponder.Url, 10000, 1024 * 1024, LResponse),
      'a response inside the budget is fetched');
    CheckEquals(256 * 1024, System.Length(LResponse), 'the whole body arrives');
  finally
    LResponder.Free;
  end;
end;

procedure TTestSocketHttpFetcher.TestLongResponseIsCutOffAtTheBudget;
var
  LResponder: TResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
begin
  // the same body, but every progress check spends 100 ms of a 1000 ms budget: each read is well
  // inside any per-read wait, yet the exchange as a whole must stop
  LResponder := TResponder.Create(256 * 1024, False);
  try
    LFetcher := TSocketHttpFetcher.Create(
      TMockMonotonicClock.Create(1000, 100) as ITlsMonotonicClock);
    CheckFalse(LFetcher.Get(LResponder.Url, 1000, 1024 * 1024, LResponse),
      'a response that outlasts the budget fails closed');
    CheckEquals(0, System.Length(LResponse), 'no partial body is returned');
  finally
    LResponder.Free;
  end;
end;

procedure TTestSocketHttpFetcher.TestTrickledHeadersAreCutOffAtTheBudget;
var
  LResponder: TResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
  LClock: ITlsMonotonicClock;
  LStart: Int64;
begin
  // a line every 100 ms never stalls a read for the 600 ms budget, so only the exchange-wide
  // limit can stop it
  LResponder := TResponder.Create(1024, True);
  try
    LClock := TSystemMonotonicClock.Create;
    LFetcher := TSocketHttpFetcher.Create(LClock);
    LStart := LClock.NowMonotonicMillis;
    CheckFalse(LFetcher.Get(LResponder.Url, 600, 1024 * 1024, LResponse),
      'a head that outlasts the budget fails closed');
    CheckTrue(LClock.NowMonotonicMillis - LStart < 4000,
      'the fetch stops near the budget, not when the responder gives up');
  finally
    LResponder.Free;
  end;
end;

{$IFDEF UNIX}
// TEMP-DIAG: reports what the socket-timeout options and a plain client fetch do on this platform
procedure TTestSocketHttpFetcher.TestTempDiagTimeoutOption;
var
  LSock: TSocket;
  LTime: TTimeVal;
  LR1, LE1, LR2, LE2: Integer;
  LResponder: TResponder;
  LClient: TFPHTTPClient;
  LBody: string;
begin
  LSock := fpSocket(AF_INET, SOCK_STREAM, 0);
  LTime.tv_sec := 5;
  LTime.tv_usec := 0;
  LR1 := fpSetSockOpt(LSock, SOL_SOCKET, SO_RCVTIMEO, @LTime, SizeOf(LTime));
  LE1 := SocketError;
  LR2 := fpSetSockOpt(LSock, SOL_SOCKET, SO_SNDTIMEO, @LTime, SizeOf(LTime));
  LE2 := SocketError;
  CloseSocket(LSock);
  WriteLn('DIAG: SO_RCVTIMEO=', SO_RCVTIMEO, ' SO_SNDTIMEO=', SO_SNDTIMEO, ' sizeof(timeval)=',
    SizeOf(LTime), ' rcv=', LR1, '/errno', LE1, ' snd=', LR2, '/errno', LE2);
  LResponder := TResponder.Create(1024, False);
  try
    LClient := TFPHTTPClient.Create(nil);
    try
      try
        LClient.IOTimeout := 5000;
        LBody := LClient.Get(LResponder.Url);
        WriteLn('DIAG: plain client fetch with IOTimeout ok, bytes=', Length(LBody));
      except
        on E: Exception do
          WriteLn('DIAG: plain client fetch with IOTimeout raised ', E.ClassName, ': ', E.Message);
      end;
    finally
      LClient.Free;
    end;
  finally
    LResponder.Free;
  end;
  Check(True, 'diagnostic only');
end;
{$ENDIF}

procedure TTestSocketHttpFetcher.TestNilClockIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TSocketHttpFetcher.Create(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil clock raises');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSocketHttpFetcher);
{$ELSE}
  RegisterTest(TTestSocketHttpFetcher.Suite);
{$ENDIF FPC}

end.
