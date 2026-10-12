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

{ A reference IHttpFetcher - deliberately OUTSIDE the sans-IO core package (the core references
  only the IHttpFetcher interface and never a socket). An http responder is fetched with a strict
  HTTP/1.1 exchange over TlsLib.Net's own sockets, an https one with the RTL HTTP client. A host
  can use this to drive the live-revocation checker, or supply its own fetcher built on its
  framework's HTTP stack. It is fail-closed by contract: any transport error, a non-2xx status,
  a timeout, or an empty body is reported as a False result with no body, never a raised
  exception. }

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  SyncObjs,
{$IFDEF FPC}
  ssockets,
  fphttpclient,
{$ELSE}
  System.Net.HttpClient,
  System.Net.URLClient,
{$ENDIF FPC}
  TlpHttpUrl,
  TlpIClock,
  TlpClock,
  TlpITlsTransport,
  TlpINetSocket,
  TlpNetSocket,
  TlpTlsLibExceptions,
  TlpIHttpFetcher;

type
  /// <summary>How a TSocketHttpFetcher reaches responders.</summary>
  TSocketHttpFetcherSettings = record
    /// <summary>Measures every fetch's budget; required.</summary>
    Clock: ITlsMonotonicClock;
    /// <summary>Resolves the responder or proxy host; required. It is the place to police
    /// egress, such as refusing loopback or private answers.</summary>
    Resolver: IHostResolver;
    /// <summary>An http forward proxy, an IPv4 literal or a host name; empty connects directly.
    /// An https responder does not use it.</summary>
    ProxyHost: string;
    /// <summary>The proxy's port; required with a ProxyHost.</summary>
    ProxyPort: Word;
    /// <summary>The system monotonic clock and TSystemHostResolver, with no proxy.</summary>
    class function Defaults: TSocketHttpFetcherSettings; static;
  end;

  /// <summary>A blocking IHttpFetcher for live OCSP (POST) and CRL (GET) retrieval.
  /// An http responder is fetched with a strict HTTP/1.1 exchange (RFC 9112) over TTcpConnector:
  /// the timeout (0 means 60 s) bounds the connect and every read, so a responder that trickles
  /// bytes or goes silent cannot hold the caller past it, on every target; the response head is capped at
  /// 64 KiB and the body at the size cap; every wait polls, so no descriptor number can overrun a
  /// select set. The request is sent unbounded, as it fits a socket buffer, and a POST's content
  /// type must be a bare type/subtype. A redirect, a 101, a 204 and a coded or ambiguously framed
  /// body all fail.
  /// An https responder goes through the RTL HTTP client (FPC fphttpclient / Delphi
  /// System.Net.HttpClient), without the proxy. There, on Free Pascal the bytes received, response
  /// head included, are capped at the size cap plus a fixed allowance; elsewhere the cap applies
  /// to the body. On Free Pascal a silent https responder is cut off by the socket's own receive
  /// timeout, and the client numbers its socket-option constants the same on every Linux CPU, so
  /// on PowerPC, MIPS and SPARC one that goes completely silent blocks that fetch until TCP gives
  /// up (a trickle is still cut off at the budget, because every read is checked), and a peer that
  /// resets the connection can raise SIGPIPE in the TLS library's own write. Also on Free Pascal
  /// the client's own connect writes past its select set for a descriptor numbered 1024 or more
  /// on Unix, so https responders must not be used in a process that may hold that many: supply
  /// your own fetcher there. On Delphi only WinHTTP is verified to cut an https responder that
  /// trickles its head at the budget; other back ends check the budget after the exchange.
  /// Name resolution is not bounded by the timeout. No destination is filtered unless the
  /// settings' resolver filters it. The injected clock may be read from another thread. Never
  /// raises; a failed exchange yields False with an empty response.</summary>
  TSocketHttpFetcher = class sealed(TInterfacedObject, IHttpFetcher)
  strict private
    FSettings: TSocketHttpFetcherSettings;
  public
    /// <summary>A fetcher with TSocketHttpFetcherSettings.Defaults.</summary>
    constructor Create; overload;
    /// <summary>The defaults, with the deadline read from AClock; nil raises.</summary>
    constructor Create(const AClock: ITlsMonotonicClock); overload;
    /// <summary>Raises on a nil Clock or Resolver, or a ProxyHost with port 0.</summary>
    constructor Create(const ASettings: TSocketHttpFetcherSettings); overload;
    function Get(const AUrl: string; ATimeoutMs: Cardinal; AMaxBytes: Int32;
      out AResponse: TBytes): Boolean;
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; AMaxBytes: Int32; out AResponse: TBytes): Boolean;
  end;

implementation

const
  // what a response head may take beyond the body cap: the status line and headers
  ResponseHeadAllowance = Int64(64 * 1024);
  // a fetch asked for no timeout gets this one for the connect and again for the reads
  UnboundedTimeoutMs = Int32(60000);

resourcestring
  SNilClock ='a clock is required (pass a clock, not nil)';
  SNilResolver = 'a host resolver is required (pass a resolver, not nil)';
  SProxyPortMissing = 'a proxy host needs a non-zero proxy port';
  SFetchBudgetExceeded = 'revocation fetch exceeded its time budget';
  SResponseTooLarge = 'revocation response exceeds the size cap';
  SUnsafeRequest = 'the request target, host or media type is not safe to send';
  SIPv6Responder = 'an IPv6 responder cannot be reached';
  SMalformedResponse = 'the response is not well-formed HTTP/1.1';
  SResponseHeadTooLarge = 'the response head or a chunk line exceeds its size limit';
  SUnexpectedStatus = 'the response status is not a 2xx with a body';
  SUnsupportedFraming = 'the response body framing or coding is not supported';
  SResponseTruncated = 'the response ended early';

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

  // strict HTTP/1.1 (RFC 9112): what a revocation responder does not need is refused, not read
  THttpExchange = class sealed(TObject)
  strict private
  const
    MaxHeadBytes = Int32(64 * 1024);
    MaxHeadFields = Int32(100);
    MaxInterimResponses = Int32(8);
    MaxChunkLineBytes = Int32(4096);
    MaxChunkSizeDigits = Int32(16);
    ReadBufferBytes = Int32(16 * 1024);
  var
    FTransport: ITlsTransport;
    FBuffer: TBytes;
    FBufferPos: Int32;
    FBufferEnd: Int32;
    // shared by every interim head, the final head and the trailers
    FHeadBytesLeft: Int32;
    FHeadFieldsLeft: Int32;
    FTransferCodings: Int32;
    FChunked: Boolean;
    FLengthFields: Int32;
    FLengthText: string;
    class function IsToken(const AText: string): Boolean; static;
    class function IsVisibleAscii(const AText: string): Boolean; static;
    // a control character other than HT at or after AFrom
    class function HasControl(const AText: string; AFrom: Int32): Boolean; static;
    class function ParseChunkSize(const ALine: string): Int64; static;
    class function ParseContentLength(const AText: string; ACap: Int64): Int64; static;
    // False at the end of the stream
    function Fill: Boolean;
    function NextByte: Byte;
    // copies up to ACount bytes into ASink; fewer only at the end of the stream
    function Drain(const ASink: TStream; ACount: Int64): Int64;
    function ReadLine(var ABudget: Int32): string;
    function ReadStatusLine: Int32;
    procedure ReadFields(ARecordFraming: Boolean);
    procedure ReadChunked(const ASink: TStream; ACap: Int64);
  public
    constructor Create(const ATransport: ITlsTransport);
    // raises, before anything is sent, on a target, host or media type that could split it
    class function BuildRequest(const AMethod, ATarget, AHost, AContentType: string;
      const ABody: TBytes): TBytes; static;
    // the body into ASink, at most ACap bytes; returns the status, a 2xx other than 204, or raises
    function ReadResponse(const ASink: TStream; ACap: Int64): Int32;
  end;

  // one fetch; the steps using the private types above live here rather than on the public class
  TSocketHttpExchange = class sealed(TObject)
  strict private
    class function ReadStreamBytes(const AStream: TStream): TBytes; static;
    // an http AUrl through the settings' resolver and proxy, the body capped at ACap
    class function ExecutePlain(const ASettings: TSocketHttpFetcherSettings;
      const AUrl: THttpUrl; const AMethod, AContentType: string; const ABody: TBytes;
      const ADeadline: TFetchDeadline; const ASink: TStream; ACap: Int64): Integer; static;
    // runs AMethod against AUrl with the RTL client, attaching ABody (nil for GET) tagged
    // AContentType, writing the response body into ASink and returning the HTTP status; a raised
    // error, the size cap and the deadline all reach Fetch's fail-closed except
    class function Execute(const AMethod, AUrl, AContentType: string; const ABody: TStream;
      const ADeadline: TFetchDeadline; const ASink: TStream): Integer; static;
  public
    // the whole fail-closed contract: bounded response sink, the try/except that swallows every
    // error, the deadline, the 2xx gate, and the bytes-out
    class function Fetch(const ASettings: TSocketHttpFetcherSettings; const AMethod, AUrl,
      AContentType: string; const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32;
      out AResponse: TBytes): Boolean; static;
  end;

{ TSocketHttpFetcherSettings }

class function TSocketHttpFetcherSettings.Defaults: TSocketHttpFetcherSettings;
begin
  Result := Default(TSocketHttpFetcherSettings);
  Result.Clock := TSystemMonotonicClock.Create;
  Result.Resolver := TSystemHostResolver.Create;
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

{ THttpExchange }

constructor THttpExchange.Create(const ATransport: ITlsTransport);
begin
  inherited Create;
  FTransport := ATransport;
  SetLength(FBuffer, ReadBufferBytes);
  FHeadBytesLeft := MaxHeadBytes;
  FHeadFieldsLeft := MaxHeadFields;
end;

class function THttpExchange.IsToken(const AText: string): Boolean;
var
  LI: Int32;
begin
  // tchar (RFC 9110 5.6.2)
  Result := AText <> '';
  for LI := 1 to System.Length(AText) do
    if not CharInSet(AText[LI], ['!', '#', '$', '%', '&', '''', '*', '+', '-', '.', '^', '_',
      '`', '|', '~', '0' .. '9', 'a' .. 'z', 'A' .. 'Z']) then
      Exit(False);
end;

class function THttpExchange.IsVisibleAscii(const AText: string): Boolean;
var
  LI: Int32;
begin
  Result := AText <> '';
  for LI := 1 to System.Length(AText) do
    if not CharInSet(AText[LI], ['!' .. '~']) then
      Exit(False);
end;

class function THttpExchange.HasControl(const AText: string; AFrom: Int32): Boolean;
var
  LI: Int32;
begin
  for LI := AFrom to System.Length(AText) do
    if ((AText[LI] < ' ') and (AText[LI] <> #9)) or (AText[LI] = #127) then
      Exit(True);
  Result := False;
end;

class function THttpExchange.ParseChunkSize(const ALine: string): Int64;
var
  LI, LDigit, LDigits: Int32;
begin
  Result := 0;
  LI := 1;
  while LI <= System.Length(ALine) do
  begin
    case ALine[LI] of
      '0' .. '9':
        LDigit := Ord(ALine[LI]) - Ord('0');
      'a' .. 'f':
        LDigit := Ord(ALine[LI]) - Ord('a') + 10;
      'A' .. 'F':
        LDigit := Ord(ALine[LI]) - Ord('A') + 10;
    else
      Break;
    end;
    if (LI > MaxChunkSizeDigits) or (Result > (High(Int64) - LDigit) div 16) then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
    Result := (Result * 16) + LDigit;
    Inc(LI);
  end;
  LDigits := LI - 1;
  // whitespace and a chunk extension may follow the size and are ignored (RFC 9112 7.1.1)
  while (LI <= System.Length(ALine)) and CharInSet(ALine[LI], [' ', #9]) do
    Inc(LI);
  if (LDigits = 0) or ((LI <= System.Length(ALine)) and (ALine[LI] <> ';')) or
    HasControl(ALine, LI) then
    raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
end;

class function THttpExchange.ParseContentLength(const AText: string; ACap: Int64): Int64;
var
  LI: Int32;
begin
  if AText = '' then
    raise EPeerInputTlsLibException.CreateRes(@SUnsupportedFraming);
  Result := 0;
  for LI := 1 to System.Length(AText) do
  begin
    if (AText[LI] < '0') or (AText[LI] > '9') then
      raise EPeerInputTlsLibException.CreateRes(@SUnsupportedFraming);
    Result := (Result * 10) + (Ord(AText[LI]) - Ord('0'));
    // checked per digit, so no run of digits can overflow
    if Result > ACap then
      raise EWriteError.CreateRes(@SResponseTooLarge);
  end;
end;

class function THttpExchange.BuildRequest(const AMethod, ATarget, AHost,
  AContentType: string; const ABody: TBytes): TBytes;
var
  LText: string;
  LSlash, LHeadLength: Int32;
begin
  LSlash := Pos('/', AContentType);
  // the URL parser already refused these characters; a CR, LF or space here would split the request
  if not IsVisibleAscii(ATarget) or not IsVisibleAscii(AHost) or ((AMethod = 'POST') and
    ((LSlash = 0) or not IsToken(Copy(AContentType, 1, LSlash - 1)) or
    not IsToken(Copy(AContentType, LSlash + 1, MaxInt)))) then
    raise EArgumentTlsLibException.CreateRes(@SUnsafeRequest);
  LText := AMethod + ' ' + ATarget + ' HTTP/1.1'#13#10'Host: ' + AHost + #13#10;
  if AMethod = 'POST' then
    LText := LText + 'Content-Type: ' + AContentType + #13#10'Content-Length: ' +
      IntToStr(System.Length(ABody)) + #13#10;
  LText := LText + 'Connection: close'#13#10#13#10;
  Result := TEncoding.ASCII.GetBytes(LText);
  LHeadLength := System.Length(Result);
  SetLength(Result, LHeadLength + System.Length(ABody));
  if System.Length(ABody) > 0 then
    Move(ABody[0], Result[LHeadLength], System.Length(ABody));
end;

function THttpExchange.Fill: Boolean;
begin
  FBufferPos := 0;
  FBufferEnd := FTransport.Read(FBuffer, 0, System.Length(FBuffer));
  Result := FBufferEnd > 0;
  if not Result then
    FBufferEnd := 0;
end;

function THttpExchange.NextByte: Byte;
begin
  if (FBufferPos = FBufferEnd) and not Fill then
    raise EPeerInputTlsLibException.CreateRes(@SResponseTruncated);
  Result := FBuffer[FBufferPos];
  Inc(FBufferPos);
end;

function THttpExchange.Drain(const ASink: TStream; ACount: Int64): Int64;
var
  LTake: Int64;
begin
  Result := 0;
  while Result < ACount do
  begin
    if (FBufferPos = FBufferEnd) and not Fill then
      Exit;
    LTake := FBufferEnd - FBufferPos;
    if LTake > ACount - Result then
      LTake := ACount - Result;
    ASink.WriteBuffer(FBuffer[FBufferPos], Int32(LTake));
    Inc(FBufferPos, Int32(LTake));
    Inc(Result, LTake);
  end;
end;

function THttpExchange.ReadLine(var ABudget: Int32): string;
var
  LByte: Byte;
  LLength: Int32;
  LCarriage: Boolean;
begin
  Result := '';
  LLength := 0;
  LCarriage := False;
  repeat
    LByte := NextByte;
    Dec(ABudget);
    if ABudget < 0 then
      raise EPeerInputTlsLibException.CreateRes(@SResponseHeadTooLarge);
    // a bare LF ends a line, but a CR must be followed by one (RFC 9112 2.2)
    if LCarriage and (LByte <> 10) then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
    LCarriage := LByte = 13;
    if (LByte <> 10) and not LCarriage then
    begin
      if LLength = System.Length(Result) then
        SetLength(Result, (LLength * 2) + 64);
      Inc(LLength);
      Result[LLength] := Char(LByte);
    end;
  until LByte = 10;
  SetLength(Result, LLength);
end;

function THttpExchange.ReadStatusLine: Int32;
var
  LLine: string;
  LI: Int32;
begin
  LLine := ReadLine(FHeadBytesLeft);
  // HTTP-version SP 3DIGIT, then SP and a reason phrase that may be empty (RFC 9112 4)
  if ((Copy(LLine, 1, 9) <> 'HTTP/1.1 ') and (Copy(LLine, 1, 9) <> 'HTTP/1.0 ')) or
    (System.Length(LLine) < 12) or ((System.Length(LLine) > 12) and (LLine[13] <> ' ')) or
    HasControl(LLine, 13) then
    raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
  Result := 0;
  for LI := 10 to 12 do
  begin
    if (LLine[LI] < '0') or (LLine[LI] > '9') then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
    Result := (Result * 10) + (Ord(LLine[LI]) - Ord('0'));
  end;
end;

procedure THttpExchange.ReadFields(ARecordFraming: Boolean);
var
  LLine, LName, LValue: string;
  LColon: Int32;
begin
  LLine := ReadLine(FHeadBytesLeft);
  while LLine <> '' do
  begin
    Dec(FHeadFieldsLeft);
    LColon := Pos(':', LLine);
    LName := Copy(LLine, 1, LColon - 1);
    // a token right up to the colon refuses obs-fold and whitespace before the colon (RFC 9112 5)
    if (FHeadFieldsLeft < 0) or not IsToken(LName) or
      HasControl(LLine, LColon + 1) then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
    LValue := Trim(Copy(LLine, LColon + 1, MaxInt));
    if ARecordFraming then
    begin
      if SameText(LName, 'Transfer-Encoding') then
      begin
        Inc(FTransferCodings);
        FChunked := SameText(LValue, 'chunked');
      end
      else if SameText(LName, 'Content-Length') then
      begin
        Inc(FLengthFields);
        FLengthText := LValue;
      end
      // no coding was asked for, so none can be undone (RFC 9110 8.4)
      else if SameText(LName, 'Content-Encoding') and not SameText(LValue, 'identity') then
        raise EPeerInputTlsLibException.CreateRes(@SUnsupportedFraming);
    end;
    LLine := ReadLine(FHeadBytesLeft);
  end;
end;

procedure THttpExchange.ReadChunked(const ASink: TStream; ACap: Int64);
var
  LTotal, LSize: Int64;
  LLineBudget: Int32;
begin
  LTotal := 0;
  repeat
    LLineBudget := MaxChunkLineBytes;
    LSize := ParseChunkSize(ReadLine(LLineBudget));
    if LSize > ACap - LTotal then
      raise EWriteError.CreateRes(@SResponseTooLarge);
    Inc(LTotal, LSize);
    if (LSize > 0) and ((Drain(ASink, LSize) < LSize) or (NextByte <> 13) or
      (NextByte <> 10)) then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
  until LSize = 0;
  // trailer fields fall under the head limits and are not used (RFC 9112 7.1.2)
  ReadFields(False);
end;

function THttpExchange.ReadResponse(const ASink: TStream; ACap: Int64): Int32;
var
  LInterim: Int32;
  LLength: Int64;
begin
  LInterim := 0;
  Result := ReadStatusLine;
  // an interim response is skipped, but a 101 would switch protocols (RFC 9110 15.2)
  while (Result div 100 = 1) and (Result <> 101) do
  begin
    Inc(LInterim);
    if LInterim > MaxInterimResponses then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
    ReadFields(False);
    Result := ReadStatusLine;
  end;
  // no redirect is followed, and a 204 has no body to return
  if (Result div 100 <> 2) or (Result = 204) then
    raise EPeerInputTlsLibException.CreateRes(@SUnexpectedStatus);
  ReadFields(True);
  if FTransferCodings > 0 then
  begin
    // a lone chunked coding only, and never beside a Content-Length (RFC 9112 6.3)
    if (FTransferCodings > 1) or not FChunked or (FLengthFields > 0) then
      raise EPeerInputTlsLibException.CreateRes(@SUnsupportedFraming);
    ReadChunked(ASink, ACap);
  end
  else if FLengthFields > 1 then
    raise EPeerInputTlsLibException.CreateRes(@SUnsupportedFraming)
  else if FLengthFields = 1 then
  begin
    LLength := ParseContentLength(FLengthText, ACap);
    if Drain(ASink, LLength) < LLength then
      raise EPeerInputTlsLibException.CreateRes(@SResponseTruncated);
  end
  else
    Drain(ASink, High(Int64));
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

class function TSocketHttpExchange.ExecutePlain(const ASettings: TSocketHttpFetcherSettings;
  const AUrl: THttpUrl; const AMethod, AContentType: string; const ABody: TBytes;
  const ADeadline: TFetchDeadline; const ASink: TStream; ACap: Int64): Integer;
var
  LHost, LTarget, LConnectHost: string;
  LConnectPort: Word;
  LConnectMs, LReadMs: Int32;
  LRequest: TBytes;
  LConnector: ITcpConnector;
  LTransport: ITlsTimedTransport;
  LExchange: THttpExchange;
begin
  // the connector is IPv4-only, and the Host field would need the brackets
  if AUrl.HostKind = THttpHostKind.IPv6 then
    raise EArgumentTlsLibException.CreateRes(@SIPv6Responder);
  LHost := AUrl.Host;
  if AUrl.Port <> THttpUrl.DefaultPort(AUrl.Scheme) then
    LHost := LHost + ':' + IntToStr(AUrl.Port);
  // a proxy is sent the absolute form (RFC 9112 3.2.2)
  if ASettings.ProxyHost <> '' then
  begin
    LTarget := AUrl.ToString;
    LConnectHost := ASettings.ProxyHost;
    LConnectPort := ASettings.ProxyPort;
  end
  else
  begin
    LTarget := AUrl.PathAndQuery;
    LConnectHost := AUrl.Host;
    LConnectPort := AUrl.Port;
  end;
  LRequest := THttpExchange.BuildRequest(AMethod, LTarget, LHost, AContentType, ABody);
  if ADeadline.Bounded then
    LConnectMs := ADeadline.RemainingMs
  else
    LConnectMs := UnboundedTimeoutMs;
  LConnector := TTcpConnector.Create(LConnectMs, ASettings.Resolver);
  LTransport := LConnector.Connect(LConnectHost, LConnectPort);
  LTransport.UseClock(ASettings.Clock);
  if ADeadline.Bounded then
    LReadMs := ADeadline.RemainingMs
  else
    LReadMs := UnboundedTimeoutMs;
  // one deadline for every read that follows, so a trickle cannot outlast the budget
  LTransport.SetReadTimeout(LReadMs);
  LTransport.Write(LRequest, 0, System.Length(LRequest));
  LExchange := THttpExchange.Create(LTransport);
  try
    Result := LExchange.ReadResponse(ASink, ACap);
  finally
    LExchange.Free;
  end;
end;

// everything specific to one RTL client is in this one block
{$IFDEF FPC}

type
  // whether the socket accepts a receive timeout: some targets refuse the option
  TReceiveTimeoutSupport = (Unknown, Usable, Refused);

  // the client calls DoDataRead on every socket read, response head included
  TDeadlineHttpClient = class(TFPHTTPClient)
  strict private
    FDeadline: TFetchDeadline;
    FReceiveTimeout: TReceiveTimeoutSupport;
    function ReceiveTimeoutUsable: Boolean;
    procedure CapReceived(Sender: TObject; const AContentLength, ACurrentPos: Int64);
  protected
    procedure ConnectToServer(const AHost: string; APort: Integer;
      UseSSL: Boolean = False); override;
    procedure DoDataRead; override;
  public
    constructor Create(const ADeadline: TFetchDeadline); reintroduce;
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

procedure TDeadlineHttpClient.ConnectToServer(const AHost: string; APort: Integer;
  UseSSL: Boolean);
begin
  // the client applies the receive timeout to the socket before the connect, which is what bounds
  // a TLS handshake
  if FDeadline.Bounded then
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
  // a raw-socket wait cannot see decrypted bytes the TLS layer holds, so reads keep the timeout
  FDeadline.Check;
  if FDeadline.Bounded and (FReceiveTimeout = TReceiveTimeoutSupport.Usable) then
    IOTimeout := FDeadline.RemainingMs;
end;

class function TSocketHttpExchange.Execute(const AMethod, AUrl, AContentType: string;
  const ABody: TStream; const ADeadline: TFetchDeadline; const ASink: TStream): Integer;
var
  LClient: TDeadlineHttpClient;
begin
  LClient := TDeadlineHttpClient.Create(ADeadline);
  try
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

class function TSocketHttpExchange.Fetch(const ASettings: TSocketHttpFetcherSettings;
  const AMethod, AUrl, AContentType: string; const ABody: TBytes; ATimeoutMs: Cardinal;
  AMaxBytes: Int32; out AResponse: TBytes): Boolean;
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
  LDeadline := TFetchDeadline.Create(ASettings.Clock, ATimeoutMs);
  try
    // the URL is peer-chosen (AIA / CDP): a malformed one fails closed here, and the RTL client
    // only ever parses the canonical text we produce, so the two parsers cannot disagree
    if THttpUrl.TryParse(AUrl, LUrl) then
    begin
      LSink := TBoundedMemoryStream.Create(AMaxBytes, LDeadline);
      if LUrl.Scheme = THttpScheme.Http then
        LStatus := ExecutePlain(ASettings, LUrl, AMethod, AContentType, ABody, LDeadline, LSink,
          TBoundedMemoryStream.EffectiveCap(AMaxBytes))
      else
      begin
        if System.Length(ABody) > 0 then
        begin
          LRequest := TMemoryStream.Create;
          LRequest.WriteBuffer(ABody[0], System.Length(ABody));
          LRequest.Position := 0;
        end;
        // the head is not part of the body the sink caps, so the exchange gets a fixed allowance
        LDeadline.LimitReceive(TBoundedMemoryStream.EffectiveCap(AMaxBytes) +
          ResponseHeadAllowance);
        LStatus := Execute(AMethod, LUrl.ToString, AContentType, LRequest, LDeadline, LSink);
      end;
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
  Create(TSocketHttpFetcherSettings.Defaults);
end;

constructor TSocketHttpFetcher.Create(const AClock: ITlsMonotonicClock);
var
  LSettings: TSocketHttpFetcherSettings;
begin
  LSettings := TSocketHttpFetcherSettings.Defaults;
  LSettings.Clock := AClock;
  Create(LSettings);
end;

constructor TSocketHttpFetcher.Create(const ASettings: TSocketHttpFetcherSettings);
begin
  inherited Create;
  if ASettings.Clock = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilClock);
  if ASettings.Resolver = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilResolver);
  if (ASettings.ProxyHost <> '') and (ASettings.ProxyPort = 0) then
    raise EArgumentTlsLibException.CreateRes(@SProxyPortMissing);
  FSettings := ASettings;
end;

function TSocketHttpFetcher.Get(const AUrl: string; ATimeoutMs: Cardinal;
  AMaxBytes: Int32; out AResponse: TBytes): Boolean;
begin
  Result := TSocketHttpExchange.Fetch(FSettings, 'GET', AUrl, '', nil, ATimeoutMs, AMaxBytes,
    AResponse);
end;

function TSocketHttpFetcher.Post(const AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32;
  out AResponse: TBytes): Boolean;
begin
  Result := TSocketHttpExchange.Fetch(FSettings, 'POST', AUrl, AContentType, ABody, ATimeoutMs,
    AMaxBytes, AResponse);
end;

end.
