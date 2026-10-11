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
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpIClock,
  TlpClock,
  TlpIHttpFetcher,
  TlpITlsTransport,
  TlpINetSocket,
  TlpNetSocket,
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
    procedure TestSilentResponderIsCutOffAtTheBudget;
    procedure TestNilClockIsRefused;
  end;

implementation

type
  // what a responder does with the request: a large body in small writes, a response head that
  // arrives a line at a time, or nothing at all
  TResponderMode = (Body, TrickledHead, Silent);

  TResponder = class(TThread)
  strict private
  const
    BodyChunk = 1024;
    HeaderLines = 100;
    HeaderPauseMs = 100;
    AcceptPollMs = 100;
  var
    FListener: ITcpListener;
    FStream: ITlsTimedTransport;
    FBodySize: Int32;
    FMode: TResponderMode;
    FStop: TEvent;
    function SendText(const AText: string): Boolean;
    function ReadRequest: Boolean;
    procedure SendHeadTrickled;
    procedure SendBody;
  protected
    procedure Execute; override;
  public
    constructor Create(ABodySize: Int32; AMode: TResponderMode);
    destructor Destroy; override;
    function Url: string;
  end;

{ TResponder }

constructor TResponder.Create(ABodySize: Int32; AMode: TResponderMode);
begin
  FListener := TTcpListener.Create('127.0.0.1', 0) as ITcpListener;
  FBodySize := ABodySize;
  FMode := AMode;
  FStop := TEvent.Create(nil, True, False, '');
  inherited Create(False);
end;

destructor TResponder.Destroy;
begin
  // the event frees a response pause, and the accept loop ends on Terminated
  Terminate;
  FStop.SetEvent;
  WaitFor;
  FStop.Free;
  FStream := nil;
  FListener := nil;
  inherited Destroy;
end;

function TResponder.Url: string;
begin
  Result := 'http://127.0.0.1:' + IntToStr(FListener.Port) + '/';
end;

function TResponder.SendText(const AText: string): Boolean;
var
  LBytes: TBytes;
begin
  LBytes := TEncoding.ASCII.GetBytes(AText);
  try
    FStream.Write(LBytes, 0, System.Length(LBytes));
    Result := True;
  except
    on E: Exception do
      Result := False;
  end;
end;

function TResponder.ReadRequest: Boolean;
var
  LBuffer: TBytes;
  LSeen: string;
  LGot: Int32;
begin
  Result := False;
  LSeen := '';
  SetLength(LBuffer, 4096);
  try
    repeat
      LGot := FStream.Read(LBuffer, 0, System.Length(LBuffer));
      if LGot <= 0 then
        Exit;
      LSeen := LSeen + TEncoding.ASCII.GetString(LBuffer, 0, LGot);
    until Pos(#13#10#13#10, LSeen) > 0;
  except
    on E: Exception do
      Exit;
  end;
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
  LChunk: TBytes;
  LSent, LCount: Int32;
begin
  if not SendText('HTTP/1.1 200 OK'#13#10'Content-Length: ' + IntToStr(FBodySize) +
    #13#10'Connection: close'#13#10#13#10) then
    Exit;
  LChunk := TEncoding.ASCII.GetBytes(StringOfChar('A', BodyChunk));
  LSent := 0;
  try
    while LSent < FBodySize do
    begin
      LCount := FBodySize - LSent;
      if LCount > BodyChunk then
        LCount := BodyChunk;
      FStream.Write(LChunk, 0, LCount);
      Inc(LSent, LCount);
    end;
  except
    on E: Exception do
      Exit;
  end;
end;

procedure TResponder.Execute;
begin
  while (FStream = nil) and not Terminated do
    FListener.TryAccept(AcceptPollMs, FStream);
  if FStream = nil then
    Exit;
  if not ReadRequest then
    Exit;
  case FMode of
    TResponderMode.TrickledHead:
      SendHeadTrickled;
    TResponderMode.Silent:
      FStop.WaitFor(INFINITE);
  else
    SendBody;
  end;
end;

{ TTestSocketHttpFetcher }

procedure TTestSocketHttpFetcher.TestSteadyResponseWithinBudgetIsFetched;
var
  LResponder: TResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
begin
  // a clock that never moves leaves the whole budget, so the full body arrives
  LResponder := TResponder.Create(256 * 1024, TResponderMode.Body);
  try
    LFetcher := TSocketHttpFetcher.Create(TMockMonotonicClock.Create(1000, 0) as ITlsMonotonicClock);
    CheckTrue(LFetcher.Get(LResponder.Url, 10000, 1024 * 1024, LResponse),
      'a response inside the budget is fetched');
    CheckEquals(256 * 1024, System.Length(LResponse), 'the whole body arrives');
  finally
    LFetcher := nil;
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
  LResponder := TResponder.Create(256 * 1024, TResponderMode.Body);
  try
    LFetcher := TSocketHttpFetcher.Create(
      TMockMonotonicClock.Create(1000, 100) as ITlsMonotonicClock);
    CheckFalse(LFetcher.Get(LResponder.Url, 1000, 1024 * 1024, LResponse),
      'a response that outlasts the budget fails closed');
    CheckEquals(0, System.Length(LResponse), 'no partial body is returned');
  finally
    LFetcher := nil;
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
  LResponder := TResponder.Create(1024, TResponderMode.TrickledHead);
  try
    LClock := TSystemMonotonicClock.Create;
    LFetcher := TSocketHttpFetcher.Create(LClock);
    LStart := LClock.NowMonotonicMillis;
    CheckFalse(LFetcher.Get(LResponder.Url, 600, 1024 * 1024, LResponse),
      'a head that outlasts the budget fails closed');
    CheckTrue(LClock.NowMonotonicMillis - LStart < 4000,
      'the fetch stops near the budget, not when the responder gives up');
  finally
    LFetcher := nil;
    LResponder.Free;
  end;
end;

procedure TTestSocketHttpFetcher.TestSilentResponderIsCutOffAtTheBudget;
var
  LResponder: TResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
  LClock: ITlsMonotonicClock;
  LStart: Int64;
begin
  // a responder that takes the request and says nothing: only a wait on the socket, not the
  // check after a read, can end this, and the kernel's receive timeout is not available on every CPU
  LResponder := TResponder.Create(1024, TResponderMode.Silent);
  try
    LClock := TSystemMonotonicClock.Create;
    LFetcher := TSocketHttpFetcher.Create(LClock);
    LStart := LClock.NowMonotonicMillis;
    CheckFalse(LFetcher.Get(LResponder.Url, 600, 1024 * 1024, LResponse),
      'a responder that goes silent fails closed');
    CheckTrue(LClock.NowMonotonicMillis - LStart < 4000,
      'the fetch stops near the budget, not when the responder gives up');
  finally
    LFetcher := nil;
    LResponder.Free;
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

end.
