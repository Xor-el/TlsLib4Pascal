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

{$IF DEFINED(FPC) OR DEFINED(TLSLIB_MSWINDOWS)}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
  Sockets,
{$ELSE}
  TestFramework,
  Winapi.Winsock2,
{$ENDIF FPC}
  TlpIClock,
  TlpIHttpFetcher,
  TlpTlsLibExceptions,
  TlpSocketHttpFetcher,
  TlsLibTestBase;

type
  /// <summary>
  /// The fetcher's timeout bounds the whole exchange: a responder that keeps sending, each read
  /// inside the per-read wait, still stops at the budget. Time is a stepping clock, so the test
  /// does not wait.
  /// </summary>
  TTestSocketHttpFetcher = class(TTlsLibTestCase)
  published
    procedure TestSteadyResponseWithinBudgetIsFetched;
    procedure TestLongResponseIsCutOffAtTheBudget;
    procedure TestNilClockIsRefused;
  end;

{$IFEND}

implementation

{$IF DEFINED(FPC) OR DEFINED(TLSLIB_MSWINDOWS)}

type
  // advances by a fixed step on every read, so each progress check spends part of the budget
  TSteppingClock = class(TInterfacedObject, ITlsMonotonicClock)
  strict private
    FNow: Int64;
    FStep: Int64;
  public
    constructor Create(AStep: Int64);
    function NowMonotonicMillis: Int64;
  end;

{$IFDEF FPC}
  TSock = TSocket;
{$ELSE}
  TSock = Winapi.Winsock2.TSocket;
{$ENDIF}

  // a loopback HTTP responder: answers one request with a large body in small writes
  TBodyServer = class(TThread)
  strict private
    FListener: TSock;
    FPort: Word;
    FBodySize: Int32;
    procedure Serve(AClient: TSock);
  protected
    procedure Execute; override;
  public
    constructor Create(ABodySize: Int32);
    destructor Destroy; override;
    property Port: Word read FPort;
  end;

{ TSteppingClock }

constructor TSteppingClock.Create(AStep: Int64);
begin
  inherited Create;
  FNow := 1000;
  FStep := AStep;
end;

function TSteppingClock.NowMonotonicMillis: Int64;
begin
  Result := FNow;
  Inc(FNow, FStep);
end;

{ TBodyServer }

constructor TBodyServer.Create(ABodySize: Int32);
var
{$IFDEF FPC}
  LAddr: TInetSockAddr;
  LLen: TSockLen;
{$ELSE}
  LAddr: TSockAddrIn;
  LLen: Integer;
  LData: TWSAData;
{$ENDIF}
begin
  FBodySize := ABodySize;
  FreeOnTerminate := False;
{$IFDEF FPC}
  FListener := fpSocket(AF_INET, SOCK_STREAM, 0);
  LAddr := Default(TInetSockAddr);
  LAddr.sin_family := AF_INET;
  LAddr.sin_addr.s_addr := HToNL($7F000001);
  LAddr.sin_port := 0;
  fpBind(FListener, @LAddr, SizeOf(LAddr));
  fpListen(FListener, 1);
  LLen := SizeOf(LAddr);
  fpGetSockName(FListener, @LAddr, @LLen);
  FPort := NToHs(LAddr.sin_port);
{$ELSE}
  WSAStartup($0202, LData);
  FListener := socket(AF_INET, SOCK_STREAM, 0);
  LAddr := Default(TSockAddrIn);
  LAddr.sin_family := AF_INET;
  LAddr.sin_addr.S_addr := htonl($7F000001);
  LAddr.sin_port := 0;
  bind(FListener, PSockAddr(@LAddr)^, SizeOf(LAddr));
  listen(FListener, 1);
  LLen := SizeOf(LAddr);
  getsockname(FListener, PSockAddr(@LAddr)^, LLen);
  FPort := ntohs(LAddr.sin_port);
{$ENDIF}
  inherited Create(False);
end;

destructor TBodyServer.Destroy;
begin
  // closing the listener frees an Execute still waiting in accept
{$IFDEF FPC}
  CloseSocket(FListener);
{$ELSE}
  closesocket(FListener);
{$ENDIF}
  WaitFor;
  inherited Destroy;
end;

procedure TBodyServer.Execute;
var
  LClient: TSock;
begin
{$IFDEF FPC}
  LClient := fpAccept(FListener, nil, nil);
  if LClient < 0 then
    Exit;
{$ELSE}
  LClient := accept(FListener, nil, nil);
  if LClient = INVALID_SOCKET then
    Exit;
{$ENDIF}
  try
    Serve(LClient);
  except
    // the client may hang up mid-body once it has given up; that is the case under test
  end;
{$IFDEF FPC}
  CloseSocket(LClient);
{$ELSE}
  closesocket(LClient);
{$ENDIF}
end;

procedure TBodyServer.Serve(AClient: TSock);
var
  LBuf: array [0 .. 4095] of Byte;
  LHead, LChunk: AnsiString;
  LSent, LCount, LGot: Int32;
  LSeen: AnsiString;
begin
  // read the request up to the blank line that ends its headers
  LSeen := '';
  repeat
{$IFDEF FPC}
    LGot := fpRecv(AClient, @LBuf[0], SizeOf(LBuf), 0);
{$ELSE}
    LGot := recv(AClient, LBuf[0], SizeOf(LBuf), 0);
{$ENDIF}
    if LGot <= 0 then
      Exit;
    SetLength(LChunk, LGot);
    Move(LBuf[0], LChunk[1], LGot);
    LSeen := LSeen + LChunk;
  until Pos(#13#10#13#10, string(LSeen)) > 0;
  LHead := AnsiString('HTTP/1.1 200 OK'#13#10'Content-Length: ' + IntToStr(FBodySize) +
    #13#10'Connection: close'#13#10#13#10);
{$IFDEF FPC}
  fpSend(AClient, @LHead[1], Length(LHead), 0);
{$ELSE}
  send(AClient, LHead[1], Length(LHead), 0);
{$ENDIF}
  FillChar(LBuf, SizeOf(LBuf), $41);
  LSent := 0;
  while LSent < FBodySize do
  begin
    LCount := FBodySize - LSent;
    if LCount > 1024 then
      LCount := 1024;
{$IFDEF FPC}
    if fpSend(AClient, @LBuf[0], LCount, 0) <= 0 then
      Exit;
{$ELSE}
    if send(AClient, LBuf[0], LCount, 0) <= 0 then
      Exit;
{$ENDIF}
    Inc(LSent, LCount);
  end;
end;

{ TTestSocketHttpFetcher }

procedure TTestSocketHttpFetcher.TestSteadyResponseWithinBudgetIsFetched;
var
  LServer: TBodyServer;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
begin
  // a clock that never moves leaves the whole budget, so the full body arrives
  LServer := TBodyServer.Create(256 * 1024);
  try
    LFetcher := TSocketHttpFetcher.Create(TSteppingClock.Create(0) as ITlsMonotonicClock);
    CheckTrue(LFetcher.Get('http://127.0.0.1:' + IntToStr(LServer.Port) + '/', 10000,
      1024 * 1024, LResponse), 'a response inside the budget is fetched');
    CheckEquals(256 * 1024, System.Length(LResponse), 'the whole body arrives');
  finally
    LServer.Free;
  end;
end;

procedure TTestSocketHttpFetcher.TestLongResponseIsCutOffAtTheBudget;
var
  LServer: TBodyServer;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
begin
  // the same server and body, but every progress check spends 100 ms of a 1000 ms budget: each
  // read is well inside any per-read wait, yet the exchange as a whole must stop
  LServer := TBodyServer.Create(256 * 1024);
  try
    LFetcher := TSocketHttpFetcher.Create(TSteppingClock.Create(100) as ITlsMonotonicClock);
    CheckFalse(LFetcher.Get('http://127.0.0.1:' + IntToStr(LServer.Port) + '/', 1000,
      1024 * 1024, LResponse), 'a response that outlasts the budget fails closed');
    CheckEquals(0, System.Length(LResponse), 'no partial body is returned');
  finally
    LServer.Free;
  end;
end;

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

{$IFEND}

end.
