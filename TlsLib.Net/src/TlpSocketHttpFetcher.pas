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
  only the IHttpFetcher interface and never a socket). Every responder is fetched with one strict
  HTTP/1.1 exchange over TlsLib.Net's own sockets, https through the library's own TLS client. A
  host can use this to drive the live-revocation checker, or supply its own fetcher built on its
  framework's HTTP stack. It is fail-closed by contract: any transport error, a non-2xx status,
  a timeout, or an empty body is reported as a False result with no body, never a raised
  exception. }

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpHttpUrl,
  TlpIClock,
  TlpClock,
  TlpITlsConfig,
  TlpTrustTypes,
  TlpITlsTransport,
  TlpTlsConnection,
  TlpINetSocket,
  TlpNetSocket,
  TlpTlsLibExceptions,
  TlpIHttpFetcher;

type
  /// <summary>How a TSocketHttpFetcher reaches responders.</summary>
  TSocketHttpFetcherSettings = record
    /// <summary>Measures every fetch's budget; required. The TLS timeouts run on the TlsConfig's own
    /// clock, with the budget left passed as a duration.</summary>
    Clock: ITlsMonotonicClock;
    /// <summary>Resolves the host the fetcher dials, the proxy under a proxy (whose own address
    /// policy then covers the responder); required.</summary>
    Resolver: IHostResolver;
    /// <summary>Consulted with the parsed URL before every connect, direct or proxied; nil admits
    /// all. It may be called from several threads at once.</summary>
    DestinationPolicy: IFetchDestinationPolicy;
    /// <summary>The TLS client config for an https responder; nil fails every https fetch. It must
    /// not arm a certificate-verdict park (WithAsyncCertificateVerdict, WithLiveRevocationVerdict):
    /// there is no resolver here, and a live-revocation one would recurse into this fetcher.</summary>
    TlsConfig: ITlsClientConfig;
    /// <summary>A forward proxy, an IPv4 literal or a host name; empty connects directly. An http
    /// request is sent to it in absolute form, an https one through a CONNECT tunnel.</summary>
    ProxyHost: string;
    /// <summary>The proxy's port; required with a ProxyHost.</summary>
    ProxyPort: Word;
    /// <summary>The system monotonic clock and TSystemHostResolver, with no TLS config, no proxy
    /// and no destination policy.</summary>
    class function Defaults: TSocketHttpFetcherSettings; static;
  end;

  /// <summary>A blocking IHttpFetcher for live OCSP (POST) and CRL (GET) retrieval, over
  /// TTcpConnector with a strict HTTP/1.1 exchange (RFC 9112) and, for https, a TTlsConnection
  /// built from the settings' TlsConfig. The timeout (0 means 60 s) bounds the connect, the TLS
  /// handshake, the proxy tunnel and every read, so a responder that trickles bytes or goes silent
  /// cannot hold the caller past it; name resolution is outside it. The response head is capped at
  /// 64 KiB and the body at the size cap; every wait polls, so no descriptor number can overrun a
  /// select set. The request is sent unbounded, as it fits a socket buffer, and a POST's content
  /// type must be a bare type/subtype. A redirect, a 101, a 204, a coded or ambiguously framed body
  /// and an https body cut off without close_notify all fail, as does an https URL with no
  /// TlsConfig, an IPv6 responder and a port on the standard blocked-port list. No other destination
  /// is filtered unless the settings' DestinationPolicy or resolver filters it. The injected clock
  /// may be read from another thread. Never raises; a failed exchange yields False with an empty
  /// response.</summary>
  TSocketHttpFetcher = class sealed(TInterfacedObject, IHttpFetcher)
  strict private
    FSettings: TSocketHttpFetcherSettings;
  public
    /// <summary>A fetcher with TSocketHttpFetcherSettings.Defaults.</summary>
    constructor Create; overload;
    /// <summary>The defaults, with the deadline read from AClock; nil raises.</summary>
    constructor Create(const AClock: ITlsMonotonicClock); overload;
    /// <summary>Raises on a nil Clock or Resolver, a ProxyHost with port 0, or a TlsConfig that
    /// arms a certificate-verdict park.</summary>
    constructor Create(const ASettings: TSocketHttpFetcherSettings); overload;
    function Get(const AUrl: string; ATimeoutMs: Cardinal; AMaxBytes: Int32;
      out AResponse: TBytes): Boolean;
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; AMaxBytes: Int32; out AResponse: TBytes): Boolean;
  end;

implementation

const
  // the budget of a fetch asked for no timeout
  UnboundedTimeoutMs = Int32(60000);

resourcestring
  SNilClock ='a clock is required (pass a clock, not nil)';
  SNilResolver = 'a host resolver is required (pass a resolver, not nil)';
  SProxyPortMissing = 'a proxy host needs a non-zero proxy port';
  SDeferredVerdictConfig = 'the fetcher''s TLS config must not defer its certificate verdict';
  SNoTlsConfig = 'an https responder needs a TLS config';
  SFetchBudgetExceeded = 'revocation fetch exceeded its time budget';
  SResponseTooLarge = 'revocation response exceeds the size cap';
  SUnsafeRequest = 'the request target, host or media type is not safe to send';
  SIPv6Responder = 'an IPv6 responder cannot be reached';
  SDestinationRefused = 'the responder URL is refused by the fetch destination policy';
  SBlockedPort = 'the responder port is on the blocked-port list';
  SMalformedResponse = 'the response is not well-formed HTTP/1.1';
  SResponseHeadTooLarge = 'the response head or a chunk line exceeds its size limit';
  SUnexpectedStatus = 'the response status is not a 2xx with a body';
  SUnsupportedFraming = 'the response body framing or coding is not supported';
  SResponseTruncated = 'the response ended early';

type
  // one fetch's whole-time budget: a per-read timeout would let a responder that sends a byte per
  // period hold the caller indefinitely, so every wait is clamped to what is left of this
  TFetchDeadline = class sealed(TObject)
  strict private
    FClock: ITlsMonotonicClock;
    FExpiresAt: Int64;
  public
    // ATimeoutMs = 0 takes the default budget
    constructor Create(const AClock: ITlsMonotonicClock; ATimeoutMs: Cardinal);
    // raises once the budget is spent
    procedure Check;
    // the budget left, at least 1 so a spent budget still bounds a wait
    function RemainingMs: Int32;
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
    // the final status line was HTTP/1.0
    FHttp10: Boolean;
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
    // past any interim responses to a final 2xx other than 204, else raises
    procedure ReadFinalStatus;
    procedure ReadFields(ARecordFraming: Boolean);
    procedure ReadChunked(const ASink: TStream; ACap: Int64);
  public
    constructor Create(const ATransport: ITlsTransport);
    // raises, before anything is sent, on a target, host or media type that could split it
    class function BuildRequest(const AMethod, ATarget, AHost, AContentType: string;
      const ABody: TBytes): TBytes; static;
    // a 2xx response's body into ASink, at most ACap bytes, else raises
    procedure ReadResponse(const ASink: TStream; ACap: Int64);
    // a 2xx answer to CONNECT, with nothing read past its head, else raises
    procedure ReadTunnelResponse;
  end;

  // the exchange's byte channel over a TLS connection it owns, each read held to the fetch budget
  TTlsChannel = class sealed(TInterfacedObject, ITlsTransport)
  strict private
    FConnection: TTlsConnection;
    FDeadline: TFetchDeadline;
  public
    constructor Create(AConnection: TTlsConnection; const ADeadline: TFetchDeadline);
    destructor Destroy; override;
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  // one fetch; the steps using the private types above live here rather than on the public class
  TSocketHttpExchange = class sealed(TObject)
  strict private
    class function ReadStreamBytes(const AStream: TStream): TBytes; static;
    // the ports a browser refuses for http(s), which carry other protocols (WHATWG Fetch)
    class function IsBlockedPort(APort: Word): Boolean; static;
    // asks the proxy on ATransport for a tunnel to AAuthority (RFC 9110 9.3.6)
    class procedure OpenTunnel(const ATransport: ITlsTransport; const AAuthority: string); static;
    // AUrl through the settings' resolver, proxy and TLS config, the body capped at ACap
    class procedure Execute(const ASettings: TSocketHttpFetcherSettings;
      const AUrl: THttpUrl; const AMethod, AContentType: string; const ABody: TBytes;
      const ADeadline: TFetchDeadline; const ASink: TStream; ACap: Int64); static;
  public
    // the whole fail-closed contract: bounded response sink, the try/except that swallows every
    // error, the deadline, and the bytes-out
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
  if ATimeoutMs = 0 then
    FExpiresAt := AClock.NowMonotonicMillis + UnboundedTimeoutMs
  else
    FExpiresAt := AClock.NowMonotonicMillis + Int64(ATimeoutMs);
end;

procedure TFetchDeadline.Check;
begin
  if FClock.NowMonotonicMillis >= FExpiresAt then
    raise EWriteError.CreateRes(@SFetchBudgetExceeded);
end;

function TFetchDeadline.RemainingMs: Int32;
var
  LLeft: Int64;
begin
  LLeft := FExpiresAt - FClock.NowMonotonicMillis;
  if LLeft < 1 then
    LLeft := 1;
  if LLeft > High(Int32) then
    LLeft := High(Int32);
  Result := Int32(LLeft);
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
  // a tunnel stays open for the TLS bytes that follow it
  if AMethod <> 'CONNECT' then
    LText := LText + 'Connection: close'#13#10;
  Result := TEncoding.ASCII.GetBytes(LText + #13#10);
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
  FHttp10 := Copy(LLine, 1, 9) = 'HTTP/1.0 ';
  Result := 0;
  for LI := 10 to 12 do
  begin
    if (LLine[LI] < '0') or (LLine[LI] > '9') then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
    Result := (Result * 10) + (Ord(LLine[LI]) - Ord('0'));
  end;
end;

procedure THttpExchange.ReadFinalStatus;
var
  LStatus, LInterim: Int32;
begin
  LInterim := 0;
  LStatus := ReadStatusLine;
  // an interim response is skipped, but a 101 would switch protocols (RFC 9110 15.2)
  while (LStatus div 100 = 1) and (LStatus <> 101) do
  begin
    Inc(LInterim);
    if LInterim > MaxInterimResponses then
      raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
    ReadFields(False);
    LStatus := ReadStatusLine;
  end;
  // no redirect is followed, and a 204 has no body to return
  if (LStatus div 100 <> 2) or (LStatus = 204) then
    raise EPeerInputTlsLibException.CreateRes(@SUnexpectedStatus);
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

procedure THttpExchange.ReadResponse(const ASink: TStream; ACap: Int64);
var
  LLength: Int64;
begin
  ReadFinalStatus;
  ReadFields(True);
  if FTransferCodings > 0 then
  begin
    // a lone chunked coding only, never beside a Content-Length (RFC 9112 6.3) or in HTTP/1.0 (6.1)
    if FHttp10 or (FTransferCodings > 1) or not FChunked or (FLengthFields > 0) then
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

procedure THttpExchange.ReadTunnelResponse;
begin
  ReadFinalStatus;
  // a 2xx to CONNECT has no body, and the TLS handshake speaks first (RFC 9110 9.3.6)
  ReadFields(False);
  if FBufferPos <> FBufferEnd then
    raise EPeerInputTlsLibException.CreateRes(@SMalformedResponse);
end;

{ TTlsChannel }

constructor TTlsChannel.Create(AConnection: TTlsConnection; const ADeadline: TFetchDeadline);
begin
  inherited Create;
  FConnection := AConnection;
  FDeadline := ADeadline;
end;

destructor TTlsChannel.Destroy;
begin
  FConnection.CloseNotifyQuietly;
  FConnection.Free;
  inherited Destroy;
end;

function TTlsChannel.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := FConnection.Read(ABuffer[AOffset], AMaxLength, FDeadline.RemainingMs);
end;

procedure TTlsChannel.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  FConnection.Write(ABuffer[AOffset], ALength);
end;

{ TSocketHttpExchange }

class function TSocketHttpExchange.ReadStreamBytes(const AStream: TStream): TBytes;
var
  LLen: Int64;
begin
  Result := nil;
  AStream.Position := 0;
  LLen := AStream.Size;
  if LLen <= 0 then
    Exit;
  SetLength(Result, LLen);
  AStream.ReadBuffer(Result[0], LLen);
end;

class function TSocketHttpExchange.IsBlockedPort(APort: Word): Boolean;
begin
  case APort of
    0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
    101 .. 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427,
    465, 512 .. 515, 526, 530 .. 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995,
    1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665 .. 6669, 6679, 6697,
    10080:
      Result := True;
  else
    Result := False;
  end;
end;

class procedure TSocketHttpExchange.OpenTunnel(const ATransport: ITlsTransport;
  const AAuthority: string);
var
  LRequest: TBytes;
  LExchange: THttpExchange;
begin
  LRequest := THttpExchange.BuildRequest('CONNECT', AAuthority, AAuthority, '', nil);
  ATransport.Write(LRequest, 0, System.Length(LRequest));
  LExchange := THttpExchange.Create(ATransport);
  try
    LExchange.ReadTunnelResponse;
  finally
    LExchange.Free;
  end;
end;

class procedure TSocketHttpExchange.Execute(const ASettings: TSocketHttpFetcherSettings;
  const AUrl: THttpUrl; const AMethod, AContentType: string; const ABody: TBytes;
  const ADeadline: TFetchDeadline; const ASink: TStream; ACap: Int64);
var
  LSecure, LProxied: Boolean;
  LHost, LTarget: string;
  LRequest: TBytes;
  LConnector: ITcpConnector;
  LTransport: ITlsTimedTransport;
  LConnection: TTlsConnection;
  LChannel: ITlsTransport;
  LExchange: THttpExchange;
begin
  // the connector is IPv4-only, and the Host field would need the brackets
  if AUrl.HostKind = THttpHostKind.IPv6 then
    raise EArgumentTlsLibException.CreateRes(@SIPv6Responder);
  if IsBlockedPort(AUrl.Port) then
    raise EArgumentTlsLibException.CreateRes(@SBlockedPort);
  if (ASettings.DestinationPolicy <> nil) and not ASettings.DestinationPolicy.Admits(AUrl) then
    raise EArgumentTlsLibException.CreateRes(@SDestinationRefused);
  LSecure := AUrl.Scheme = THttpScheme.Https;
  if LSecure and (ASettings.TlsConfig = nil) then
    raise EArgumentTlsLibException.CreateRes(@SNoTlsConfig);
  LProxied := ASettings.ProxyHost <> '';
  LHost := AUrl.Host;
  if AUrl.Port <> THttpUrl.DefaultPort(AUrl.Scheme) then
    LHost := LHost + ':' + IntToStr(AUrl.Port);
  // a proxy is sent an http target in absolute form (RFC 9112 3.2.2); https goes through a tunnel
  if LProxied and not LSecure then
    LTarget := AUrl.ToString
  else
    LTarget := AUrl.PathAndQuery;
  LRequest := THttpExchange.BuildRequest(AMethod, LTarget, LHost, AContentType, ABody);
  LConnector := TTcpConnector.Create(ADeadline.RemainingMs, ASettings.Resolver);
  if LProxied then
    LTransport := LConnector.Connect(ASettings.ProxyHost, ASettings.ProxyPort)
  else
    LTransport := LConnector.Connect(AUrl.Host, AUrl.Port);
  LTransport.UseClock(ASettings.Clock);
  // one deadline for every read that follows, so a trickle cannot outlast the budget
  LTransport.SetReadTimeout(ADeadline.RemainingMs);
  if LSecure then
  begin
    if LProxied then
      OpenTunnel(LTransport, AUrl.Host + ':' + IntToStr(AUrl.Port));
    LConnection := TTlsConnection.CreateClient(ASettings.TlsConfig, AUrl.Host, LTransport, nil, 0);
    LChannel := TTlsChannel.Create(LConnection, ADeadline);
    LConnection.Handshake(ADeadline.RemainingMs);
  end
  else
    LChannel := LTransport;
  LChannel.Write(LRequest, 0, System.Length(LRequest));
  LExchange := THttpExchange.Create(LChannel);
  try
    LExchange.ReadResponse(ASink, ACap);
  finally
    LExchange.Free;
  end;
end;

class function TSocketHttpExchange.Fetch(const ASettings: TSocketHttpFetcherSettings;
  const AMethod, AUrl, AContentType: string; const ABody: TBytes; ATimeoutMs: Cardinal;
  AMaxBytes: Int32; out AResponse: TBytes): Boolean;
var
  LSink: TStream;
  LDeadline: TFetchDeadline;
  LUrl: THttpUrl;
begin
  Result := False;
  AResponse := nil;
  LSink := nil;
  LDeadline := TFetchDeadline.Create(ASettings.Clock, ATimeoutMs);
  try
    // the URL is peer-chosen (AIA / CDP): a malformed one fails closed here
    if THttpUrl.TryParse(AUrl, LUrl) then
    begin
      LSink := TBoundedMemoryStream.Create(AMaxBytes, LDeadline);
      Execute(ASettings, LUrl, AMethod, AContentType, ABody, LDeadline, LSink,
        TBoundedMemoryStream.EffectiveCap(AMaxBytes));
      LDeadline.Check;
      AResponse := ReadStreamBytes(LSink);
      Result := System.Length(AResponse) > 0;
    end;
  except
    // fail-closed: any transport/HTTP error, the size-cap overflow or the deadline is a failed fetch
    Result := False;
    AResponse := nil;
  end;
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
  // a verdict park has no resolver here, and a live-revocation one would recurse into this fetcher
  if (ASettings.TlsConfig <> nil) and (ASettings.TlsConfig.AsyncCertificateVerdict.Deferral <>
    TVerdictDeferral.None) then
    raise EArgumentTlsLibException.CreateRes(@SDeferredVerdictConfig);
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
