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

{$I ..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fphttpclient,
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
  /// The timeout bounds the whole exchange, so a responder that trickles bytes cannot hold the
  /// caller past it. Never raises; a failed exchange yields False with an empty response.</summary>
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

resourcestring
  SNilClock = 'a clock is required (pass a clock, not nil)';

type
  // one exchange's whole-time budget: a timeout the RTL applies per read would let a responder that
  // sends a byte per period hold the caller indefinitely, so progress is checked against this
  TFetchDeadline = class sealed(TObject)
  strict private
    FClock: ITlsMonotonicClock;
    FExpiresAt: Int64;
    FBounded: Boolean;
  public
    // ATimeoutMs = 0 leaves the exchange unbounded, as before
    constructor Create(const AClock: ITlsMonotonicClock; ATimeoutMs: Cardinal);
    function Expired: Boolean;
    procedure Check;
    // the budget left, for clamping a per-read timeout; at least 1 so it never reads as "none"
    function RemainingMs: Cardinal;
{$IFDEF FPC}
    procedure OnDataReceived(ASender: TObject; const AContentLength, ACurrentPos: Int64);
{$ELSE}
    procedure OnReceiveData(const ASender: TObject; AContentLength, AReadCount: Int64;
      var AAbort: Boolean);
{$ENDIF}
  end;

  // a memory-backed sink that refuses to buffer past the cap; the overflowing Write raises, and
  // Fetch's except turns that into the fail-closed False the contract already promises
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
    destructor Destroy; override;
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
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
    raise EWriteError.Create('revocation fetch exceeded its time budget');
end;

function TFetchDeadline.RemainingMs: Cardinal;
var
  LLeft: Int64;
begin
  if not FBounded then
    Exit(0);
  LLeft := FExpiresAt - FClock.NowMonotonicMillis;
  if LLeft < 1 then
    LLeft := 1;
  if LLeft > High(Cardinal) then
    LLeft := High(Cardinal);
  Result := Cardinal(LLeft);
end;

{$IFDEF FPC}
procedure TFetchDeadline.OnDataReceived(ASender: TObject; const AContentLength,
  ACurrentPos: Int64);
begin
  // every socket read, headers included, lands here, so a trickle in any phase is cut off
  Check;
end;
{$ELSE}
procedure TFetchDeadline.OnReceiveData(const ASender: TObject; AContentLength,
  AReadCount: Int64; var AAbort: Boolean);
begin
  if Expired then
    AAbort := True;
end;
{$ENDIF}

{ TBoundedMemoryStream }

constructor TBoundedMemoryStream.Create(AMaxBytes: Int64; const ADeadline: TFetchDeadline);
begin
  inherited Create;
  FDeadline := ADeadline;
  FInner := TMemoryStream.Create;
  // honour the caller's bound, but never above the coarse outer limit
  if (AMaxBytes > 0) and (AMaxBytes < MaxResponseBytes) then
    FCap := AMaxBytes
  else
    FCap := MaxResponseBytes;
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
    raise EWriteError.Create('revocation response exceeds the size cap');
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
    raise EWriteError.Create('revocation response exceeds the size cap');
  Result := FInner.Write(ABuffer, ACount);
end;

function TBoundedMemoryStream.Seek(const AOffset: Int64;
  AOrigin: TSeekOrigin): Int64;
begin
  Result := FInner.Seek(AOffset, AOrigin);
end;

function ReadStreamBytes(const AStream: TStream): TBytes;
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

{$IFDEF FPC}

// runs AMethod against AUrl, attaching ABody (nil for GET) tagged AContentType, writing the
// response body into ASink and returning the HTTP status; a raised error, the size cap and the
// deadline all reach Fetch's fail-closed except
function Execute(const AMethod, AUrl, AContentType: string; const ABody: TStream;
  const ADeadline: TFetchDeadline; const ASink: TStream): Integer;
var
  LClient: TFPHTTPClient;
begin
  LClient := TFPHTTPClient.Create(nil);
  try
    // each read waits no longer than what is left of the whole exchange
    if ADeadline.RemainingMs > 0 then
    begin
      LClient.ConnectTimeout := ADeadline.RemainingMs;
      LClient.IOTimeout := ADeadline.RemainingMs;
    end;
    LClient.OnDataReceived := ADeadline.OnDataReceived;
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

// see the FPC overload
function Execute(const AMethod, AUrl, AContentType: string; const ABody: TStream;
  const ADeadline: TFetchDeadline; const ASink: TStream): Integer;
var
  LClient: THTTPClient;
  LRequest: IHTTPRequest;
  LResponse: IHTTPResponse;
begin
  LClient := THTTPClient.Create;
  try
    // each read waits no longer than what is left of the whole exchange
    if ADeadline.RemainingMs > 0 then
    begin
      LClient.ConnectionTimeout := ADeadline.RemainingMs;
      LClient.ResponseTimeout := ADeadline.RemainingMs;
    end;
    LClient.OnReceiveData := ADeadline.OnReceiveData;
    // the responder URL is peer-chosen; do not chase redirects it hands us
    LClient.HandleRedirects := False;
    LRequest := LClient.GetRequest(AMethod, AUrl);
    if ABody <> nil then
    begin
      LRequest.SetHeaderValue('Content-Type', AContentType);
      LRequest.SourceStream := ABody;
    end;
    LResponse := LClient.Execute(LRequest, ASink, nil);
    // an abort from the progress hook can surface as a short response rather than an error
    ADeadline.Check;
    Result := LResponse.StatusCode;
  finally
    LClient.Free;
  end;
end;

{$ENDIF FPC}

// the whole fail-closed contract, shared by both RTLs: request-stream lifetime, bounded response
// sink, the try/except that swallows every error, the 2xx gate, and the bytes-out
function Fetch(const AClock: ITlsMonotonicClock; const AMethod, AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32; out AResponse: TBytes): Boolean;
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
      LStatus := Execute(AMethod, LUrl.ToString, AContentType, LRequest, LDeadline, LSink);
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
  Result := Fetch(FClock, 'GET', AUrl, '', nil, ATimeoutMs, AMaxBytes, AResponse);
end;

function TSocketHttpFetcher.Post(const AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32;
  out AResponse: TBytes): Boolean;
begin
  Result := Fetch(FClock, 'POST', AUrl, AContentType, ABody, ATimeoutMs, AMaxBytes, AResponse);
end;

end.
