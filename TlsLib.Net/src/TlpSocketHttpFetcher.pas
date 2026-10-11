{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSocketHttpFetcher;

{ A reference IHttpFetcher over the RTL HTTP client - deliberately OUTSIDE the sans-IO core
  package (the core references only the IHttpFetcher interface and never a socket). A host
  can use this to drive the live-revocation checker, or supply its own fetcher built on its
  framework's HTTP stack. It is fail-closed by contract: any transport error, a non-2xx
  status, a timeout, or an empty body is reported as a False result with no body, never a
  raised exception. }

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  SyncObjs,
{$IFDEF FPC}
  ssockets,
  fphttpclient,
  TlpNetSocket,
{$ELSE}
  System.Net.HttpClient,
  System.Net.URLClient,
{$ENDIF FPC}
  TlpHttpUrl,
  TlpIClock,
  TlpClock,
  TlpTlsLibExceptions,
  TlpIHttpFetcher;

type
  /// <summary>A blocking IHttpFetcher backed by the RTL HTTP client (FPC fphttpclient /
  /// Delphi System.Net.HttpClient). Suitable for live OCSP (POST) and CRL (GET) retrieval.
  /// The timeout bounds the whole exchange once the host name is resolved, so a responder that
  /// trickles bytes or goes silent cannot hold the caller past it; name resolution itself is not
  /// bounded. On Free Pascal the bytes received, response head included, are capped at the size cap
  /// plus a fixed allowance; elsewhere the cap applies to the body. On Free Pascal an https responder
  /// is the exception to the silent case: its reads rely on the socket's own receive timeout, and the
  /// client numbers its socket-option constants the same on every Linux CPU, so on PowerPC, MIPS and
  /// SPARC one that goes completely silent blocks that fetch until TCP gives up (a trickle is still
  /// cut off at the budget, because every read is checked; plain http is unaffected), and a peer
  /// that resets the connection can raise SIGPIPE in the TLS library's own write. Also on Free
  /// Pascal the client's own connect writes past its select set for a descriptor numbered 1024 or
  /// more on Unix, so it must not be used in a process that may hold that many: supply your own
  /// fetcher there. No destination is filtered: a responder URL naming a loopback, private or
  /// link-local host is fetched like any other, so wrap IHttpFetcher where egress is policed. The
  /// injected clock may be read from another thread. Never raises; a failed exchange yields False
  /// with an empty response.</summary>
  TSocketHttpFetcher = class sealed(TInterfacedObject, IHttpFetcher)
  strict private
    FClock: ITlsMonotonicClock;
  public
    /// <summary>A fetcher whose deadline reads the real monotonic clock.</summary>
    constructor Create; overload;
    /// <summary>A fetcher whose deadline reads AClock; nil raises.</summary>
    constructor Create(const AClock: ITlsMonotonicClock); overload;
    function Get(const AUrl: string; ATimeoutMs: Cardinal; AMaxBytes: Int32;
      out AResponse: TBytes): Boolean;
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; AMaxBytes: Int32; out AResponse: TBytes): Boolean;
  end;

implementation

const
  // what a response head may take beyond the body cap: the status line and headers
  ResponseHeadAllowance = Int64(64 * 1024);

resourcestring
  SNilClock ='a clock is required (pass a clock, not nil)';
  SFetchBudgetExceeded = 'revocation fetch exceeded its time budget';
  SResponseTooLarge = 'revocation response exceeds the size cap';

type
  // one exchange's whole-time budget: a timeout the RTL applies per read would let a responder that
  // sends a byte per period hold the caller indefinitely, so progress is checked against this. It
  // also caps the bytes the exchange may receive, response head included
  TFetchDeadline = class sealed(TObject)
  strict private
    FClock: ITlsMonotonicClock;
    FExpiresAt: Int64;
    FBounded: Boolean;
    FReceiveCap: Int64;
  public
    // ATimeoutMs = 0 leaves the exchange unbounded
    constructor Create(const AClock: ITlsMonotonicClock; ATimeoutMs: Cardinal);
    function Expired: Boolean;
    // raises once the budget is spent
    procedure Check;
    // the budget left, for clamping a per-read timeout: 0 when unbounded, else at least 1 and
    // within the Int32 the RTL clients take
    function RemainingMs: Int32;
    // the connect timeout the RTL client takes: the budget left, in whole seconds rounded up
    function ConnectTimeoutMs: Int32;
    // ACap = 0 leaves the received bytes uncounted
    procedure LimitReceive(ACap: Int64);
    // raises once ATotal, the bytes the exchange has received so far, passes the cap
    procedure CheckReceived(ATotal: Int64);
    property Bounded: Boolean read FBounded;
  end;

  // a memory-backed sink that refuses to buffer past the cap or the budget; the raise reaches
  // Fetch's except, which turns it into the fail-closed False the contract already promises
  TBoundedMemoryStream = class(TStream)
  strict private
  const
    // a coarse outer bound on any single revocation download: the fetcher URL is peer-chosen (AIA /
    // CDP), so an unbounded body would let a hostile responder exhaust memory. The revocation checker
    // applies its own tighter per-artifact caps on top; this only stops the download growing unbounded.
    MaxResponseBytes = Int64(32 * 1024 * 1024);
  var
    FInner: TMemoryStream;
    FCap: Int64;
    FDeadline: TFetchDeadline;
  protected
    function GetSize: Int64; override;
    procedure SetSize(const ANewSize: Int64); override;
  public
    constructor Create(AMaxBytes: Int64; const ADeadline: TFetchDeadline);
    // the body cap AMaxBytes asks for
    class function EffectiveCap(AMaxBytes: Int64): Int64; static;
    destructor Destroy; override;
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
  end;

  // one fetch against the RTL client; the types above are private to this unit, so the steps that
  // use them live here rather than on the public class
  TSocketHttpExchange = class sealed(TObject)
  strict private
    class function ReadStreamBytes(const AStream: TStream): TBytes; static;
    // runs AMethod against AUrl, attaching ABody (nil for GET) tagged AContentType, writing the
    // response body into ASink and returning the HTTP status; a raised error, the size cap and the
    // deadline all reach Fetch's fail-closed except
    class function Execute(const AMethod, AUrl, AContentType: string; const ABody: TStream;
      const ADeadline: TFetchDeadline; const ASink: TStream): Integer; static;
  public
    // the whole fail-closed contract: request-stream lifetime, bounded response sink, the
    // try/except that swallows every error, the deadline, the 2xx gate, and the bytes-out
    class function Fetch(const AClock: ITlsMonotonicClock; const AMethod, AUrl,
      AContentType: string; const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32;
      out AResponse: TBytes): Boolean; static;
  end;

{ TFetchDeadline }

constructor TFetchDeadline.Create(const AClock: ITlsMonotonicClock; ATimeoutMs: Cardinal);
begin
  inherited Create;
  FClock := AClock;
  FBounded := ATimeoutMs > 0;
  if FBounded then
    FExpiresAt := AClock.NowMonotonicMillis + Int64(ATimeoutMs);
end;

function TFetchDeadline.Expired: Boolean;
begin
  Result := FBounded and (FClock.NowMonotonicMillis >= FExpiresAt);
end;

procedure TFetchDeadline.Check;
begin
  if Expired then
    raise EWriteError.CreateRes(@SFetchBudgetExceeded);
end;

function TFetchDeadline.RemainingMs: Int32;
var
  LLeft: Int64;
begin
  if not FBounded then
    Exit(0);
  LLeft := FExpiresAt - FClock.NowMonotonicMillis;
  if LLeft < 1 then
    LLeft := 1;
  if LLeft > High(Int32) then
    LLeft := High(Int32);
  Result := Int32(LLeft);
end;

function TFetchDeadline.ConnectTimeoutMs: Int32;
var
  LSeconds: Int64;
begin
  // the RTL client counts a connect timeout in whole seconds, so a smaller budget would be none
  LSeconds := (Int64(RemainingMs) + 999) div 1000;
  if LSeconds * 1000 > High(Int32) then
    Result := (High(Int32) div 1000) * 1000
  else
    Result := Int32(LSeconds * 1000);
end;

procedure TFetchDeadline.LimitReceive(ACap: Int64);
begin
  FReceiveCap := ACap;
end;

procedure TFetchDeadline.CheckReceived(ATotal: Int64);
begin
  if (FReceiveCap > 0) and (ATotal > FReceiveCap) then
    raise EWriteError.CreateRes(@SResponseTooLarge);
end;

{ TBoundedMemoryStream }

constructor TBoundedMemoryStream.Create(AMaxBytes: Int64; const ADeadline: TFetchDeadline);
begin
  inherited Create;
  FDeadline := ADeadline;
  FInner := TMemoryStream.Create;
  FCap := EffectiveCap(AMaxBytes);
end;

class function TBoundedMemoryStream.EffectiveCap(AMaxBytes: Int64): Int64;
begin
  // honour the caller's bound, but never above the coarse outer limit
  if (AMaxBytes > 0) and (AMaxBytes < MaxResponseBytes) then
    Result := AMaxBytes
  else
    Result := MaxResponseBytes;
end;

destructor TBoundedMemoryStream.Destroy;
begin
  FInner.Free;
  inherited Destroy;
end;

function TBoundedMemoryStream.GetSize: Int64;
begin
  Result := FInner.Size;
end;

procedure TBoundedMemoryStream.SetSize(const ANewSize: Int64);
begin
  // hold the cap on a resize too, so nothing can preallocate a buffer past it around the Write guard
  if ANewSize > FCap then
    raise EWriteError.CreateRes(@SResponseTooLarge);
  FInner.Size := ANewSize;
end;

function TBoundedMemoryStream.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  Result := FInner.Read(ABuffer, ACount);
end;

function TBoundedMemoryStream.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  FDeadline.Check;
  if (FInner.Position + ACount) > FCap then
    raise EWriteError.CreateRes(@SResponseTooLarge);
  Result := FInner.Write(ABuffer, ACount);
end;

function TBoundedMemoryStream.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  Result := FInner.Seek(AOffset, AOrigin);
end;

{ TSocketHttpExchange }

class function TSocketHttpExchange.ReadStreamBytes(const AStream: TStream): TBytes;
var
  LLen: Int64;
begin
  Result := nil;
  if AStream = nil then
    Exit;
  AStream.Position := 0;
  LLen := AStream.Size;
  if LLen <= 0 then
    Exit;
  SetLength(Result, LLen);
  AStream.ReadBuffer(Result[0], LLen);
end;

// everything specific to one RTL client is in this one block
{$IFDEF FPC}

type
  // waits on the socket for no longer than what is left of the budget before each read, so a
  // responder that goes silent ends the exchange on every CPU, and keeps a send to a peer that has
  // gone from killing the process
  TDeadlineSocketHandler = class sealed(TSocketHandler)
  strict private
    FDeadline: TFetchDeadline;
  public
    constructor Create(const ADeadline: TFetchDeadline); reintroduce;
    function Connect: Boolean; override;
    function Recv(const Buffer; Count: Integer): Integer; override;
  end;

  // whether the socket accepts a receive timeout: some targets refuse the option
  TReceiveTimeoutSupport = (Unknown, Usable, Refused);

  // the client calls DoDataRead on every socket read, response head included
  TDeadlineHttpClient = class(TFPHTTPClient)
  strict private
    FDeadline: TFetchDeadline;
    FSecure: Boolean;
    FReceiveTimeout: TReceiveTimeoutSupport;
    procedure HoldReadsToBudget;
    function ReceiveTimeoutUsable: Boolean;
    procedure CapReceived(Sender: TObject; const AContentLength, ACurrentPos: Int64);
  protected
    function GetSocketHandler(const UseSSL: Boolean): TSocketHandler; override;
    procedure ConnectToServer(const AHost: string; APort: Integer;
      UseSSL: Boolean = False); override;
    procedure DoDataRead; override;
  public
    constructor Create(const ADeadline: TFetchDeadline); reintroduce;
  end;

constructor TDeadlineSocketHandler.Create(const ADeadline: TFetchDeadline);
begin
  inherited Create;
  FDeadline := ADeadline;
end;

function TDeadlineSocketHandler.Connect: Boolean;
begin
  Result := inherited Connect;
  if Result then
  begin
    Socket.WriteFlags := TNetOs.SendFlags;
    TNetOs.ArmAgainstSigPipe(TNetHandle(Socket.Handle));
  end;
end;

function TDeadlineSocketHandler.Recv(const Buffer; Count: Integer): Integer;
begin
  if FDeadline.Bounded then
    repeat
      // raises once the budget is spent, which ends a wait that timed out
      FDeadline.Check;
    until TNetOs.Wait(TNetHandle(Socket.Handle), TNetWait.Readable, FDeadline.RemainingMs);
  Result := inherited Recv(Buffer, Count);
end;

constructor TDeadlineHttpClient.Create(const ADeadline: TFetchDeadline);
begin
  inherited Create(nil);
  FDeadline := ADeadline;
  OnDataReceived := CapReceived;
end;

procedure TDeadlineHttpClient.CapReceived(Sender: TObject; const AContentLength,
  ACurrentPos: Int64);
begin
  FDeadline.CheckReceived(ACurrentPos);
end;

// the client numbers its socket-option constants the same on every Linux CPU, so the option is
// refused on PowerPC, MIPS and SPARC; a throwaway socket tells which kind of target this is
function TDeadlineHttpClient.ReceiveTimeoutUsable: Boolean;
var
  LHandle: TNetHandle;
  LStream: TSocketStream;
begin
  Result := False;
  if TNetOs.OpenStream(LHandle) <> 0 then
    Exit;
  LStream := TSocketStream.Create(Longint(LHandle));
  try
    try
      LStream.IOTimeout := 1000;
      Result := True;
    except
      on ESocketError do
        Result := False;
    end;
  finally
    LStream.Free;
  end;
end;

function TDeadlineHttpClient.GetSocketHandler(const UseSSL: Boolean): TSocketHandler;
begin
  FSecure := UseSSL;
  if UseSSL then
    Result := inherited GetSocketHandler(UseSSL)
  else
    Result := TDeadlineSocketHandler.Create(FDeadline);
end;

// a wait on the raw socket cannot tell an encrypted stream that holds decrypted bytes from a
// silent one, so an https read keeps the socket's own receive timeout, where the target has one
procedure TDeadlineHttpClient.HoldReadsToBudget;
begin
  if FSecure and FDeadline.Bounded and (FReceiveTimeout = TReceiveTimeoutSupport.Usable) then
    IOTimeout := FDeadline.RemainingMs;
end;

procedure TDeadlineHttpClient.ConnectToServer(const AHost: string; APort: Integer;
  UseSSL: Boolean);
begin
  // the client applies the receive timeout to the socket before the connect, which is what bounds
  // a TLS handshake
  if UseSSL and FDeadline.Bounded then
  begin
    if FReceiveTimeout = TReceiveTimeoutSupport.Unknown then
      if ReceiveTimeoutUsable then
        FReceiveTimeout := TReceiveTimeoutSupport.Usable
      else
        FReceiveTimeout := TReceiveTimeoutSupport.Refused;
    if FReceiveTimeout = TReceiveTimeoutSupport.Usable then
      IOTimeout := FDeadline.RemainingMs;
  end;
  inherited ConnectToServer(AHost, APort, UseSSL);
end;

procedure TDeadlineHttpClient.DoDataRead;
begin
  inherited DoDataRead;
  // a trickle in any phase is cut off, and the next https read waits no longer than what is left
  FDeadline.Check;
  HoldReadsToBudget;
end;

class function TSocketHttpExchange.Execute(const AMethod, AUrl, AContentType: string;
  const ABody: TStream; const ADeadline: TFetchDeadline; const ASink: TStream): Integer;
var
  LClient: TDeadlineHttpClient;
begin
  LClient := TDeadlineHttpClient.Create(ADeadline);
  try
    // reads wait inside the socket handler; the connect is bounded here
    if ADeadline.Bounded then
      LClient.ConnectTimeout := ADeadline.ConnectTimeoutMs;
    // the responder URL is peer-chosen; do not chase redirects it hands us
    LClient.AllowRedirect := False;
    if ABody <> nil then
    begin
      LClient.AddHeader('Content-Type', AContentType);
      LClient.RequestBody := ABody;
    end;
    // [] accepts any status without raising, so the 2xx gate lives once in Fetch
    LClient.HTTPMethod(AMethod, AUrl, ASink, []);
    Result := LClient.ResponseStatusCode;
  finally
    LClient.Free;
  end;
end;

{$ELSE}

type
  // the client reports no progress while it reads the response head, so a responder that trickles
  // it would never reach a progress hook; this cancels the request when the budget runs out. The
  // cancel is verified on WinHTTP; other back ends rely on the deadline check after the exchange
  TDeadlineWatchdog = class(TThread)
  strict private
    FRequest: IHTTPRequest;
    FDeadline: TFetchDeadline;
    FFinished: TEvent;
  protected
    procedure Execute; override;
  public
    constructor Create(const ARequest: IHTTPRequest; const ADeadline: TFetchDeadline);
    destructor Destroy; override;
    procedure Stop;
  end;

constructor TDeadlineWatchdog.Create(const ARequest: IHTTPRequest;
  const ADeadline: TFetchDeadline);
begin
  inherited Create(False);
  FRequest := ARequest;
  FDeadline := ADeadline;
  FFinished := TEvent.Create(nil, True, False, '');
end;

destructor TDeadlineWatchdog.Destroy;
begin
  FFinished.Free;
  inherited Destroy;
end;

procedure TDeadlineWatchdog.Execute;
begin
  while FFinished.WaitFor(Cardinal(FDeadline.RemainingMs)) = wrTimeout do
    if FDeadline.Expired then
    begin
      FRequest.Cancel;
      Exit;
    end;
end;

procedure TDeadlineWatchdog.Stop;
begin
  FFinished.SetEvent;
  WaitFor;
end;

class function TSocketHttpExchange.Execute(const AMethod, AUrl, AContentType: string;
  const ABody: TStream; const ADeadline: TFetchDeadline; const ASink: TStream): Integer;
var
  LClient: THTTPClient;
  LRequest: IHTTPRequest;
  LResponse: IHTTPResponse;
  LWatchdog: TDeadlineWatchdog;
begin
  LClient := THTTPClient.Create;
  LWatchdog := nil;
  try
    if ADeadline.Bounded then
    begin
      LClient.ConnectionTimeout := ADeadline.RemainingMs;
      LClient.ResponseTimeout := ADeadline.RemainingMs;
    end;
    // the responder URL is peer-chosen; do not chase redirects it hands us, and never offer it the
    // process's Windows credentials
    LClient.HandleRedirects := False;
    LClient.UseDefaultCredentials := False;
    LRequest := LClient.GetRequest(AMethod, AUrl);
    if ABody <> nil then
    begin
      LRequest.SetHeaderValue('Content-Type', AContentType);
      LRequest.SourceStream := ABody;
    end;
    if ADeadline.Bounded then
      LWatchdog := TDeadlineWatchdog.Create(LRequest, ADeadline);
    try
      LResponse := LClient.Execute(LRequest, ASink, nil);
    finally
      if LWatchdog <> nil then
      begin
        LWatchdog.Stop;
        LWatchdog.Free;
      end;
    end;
    Result := LResponse.StatusCode;
  finally
    LClient.Free;
  end;
end;

{$ENDIF FPC}

class function TSocketHttpExchange.Fetch(const AClock: ITlsMonotonicClock; const AMethod, AUrl,
  AContentType: string; const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32;
  out AResponse: TBytes): Boolean;
var
  LRequest: TMemoryStream;
  LSink: TStream;
  LDeadline: TFetchDeadline;
  LUrl: THttpUrl;
  LStatus: Integer;
begin
  Result := False;
  AResponse := nil;
  LRequest := nil;
  LSink := nil;
  LDeadline := TFetchDeadline.Create(AClock, ATimeoutMs);
  try
    // the URL is peer-chosen (AIA / CDP): a malformed one fails closed here, and the RTL client
    // only ever parses the canonical text we produce, so the two parsers cannot disagree
    if THttpUrl.TryParse(AUrl, LUrl) then
    begin
      if System.Length(ABody) > 0 then
      begin
        LRequest := TMemoryStream.Create;
        LRequest.WriteBuffer(ABody[0], System.Length(ABody));
        LRequest.Position := 0;
      end;
      LSink := TBoundedMemoryStream.Create(AMaxBytes, LDeadline);
      // the head is not part of the body the sink caps, so the exchange gets a fixed allowance for it
      LDeadline.LimitReceive(TBoundedMemoryStream.EffectiveCap(AMaxBytes) + ResponseHeadAllowance);
      LStatus := Execute(AMethod, LUrl.ToString, AContentType, LRequest, LDeadline, LSink);
      // a cancel can end the exchange with a short response rather than an error
      LDeadline.Check;
      if (LStatus >= 200) and (LStatus < 300) then
      begin
        AResponse := ReadStreamBytes(LSink);
        Result := System.Length(AResponse) > 0;
      end;
    end;
  except
    // fail-closed: any transport/HTTP error, the size-cap overflow or the deadline is a failed fetch
    Result := False;
    AResponse := nil;
  end;
  LRequest.Free;
  LSink.Free;
  LDeadline.Free;
end;

{ TSocketHttpFetcher }

constructor TSocketHttpFetcher.Create;
begin
  Create(TSystemMonotonicClock.Create as ITlsMonotonicClock);
end;

constructor TSocketHttpFetcher.Create(const AClock: ITlsMonotonicClock);
begin
  inherited Create;
  if AClock = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilClock);
  FClock := AClock;
end;

function TSocketHttpFetcher.Get(const AUrl: string; ATimeoutMs: Cardinal;
  AMaxBytes: Int32; out AResponse: TBytes): Boolean;
begin
  Result := TSocketHttpExchange.Fetch(FClock, 'GET', AUrl, '', nil, ATimeoutMs, AMaxBytes,
    AResponse);
end;

function TSocketHttpFetcher.Post(const AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32;
  out AResponse: TBytes): Boolean;
begin
  Result := TSocketHttpExchange.Fetch(FClock, 'POST', AUrl, AContentType, ABody, ATimeoutMs,
    AMaxBytes, AResponse);
end;

end.
