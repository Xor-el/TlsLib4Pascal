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
  TlpIHttpFetcher;

type
  /// <summary>A blocking IHttpFetcher backed by the RTL HTTP client (FPC fphttpclient /
  /// Delphi System.Net.HttpClient). Suitable for live OCSP (POST) and CRL (GET) retrieval.
  /// Never raises; a failed exchange yields False with an empty response.</summary>
  TSocketHttpFetcher = class sealed(TInterfacedObject, IHttpFetcher)
  strict private
    class function ReadStreamBytes(const AStream: TStream): TBytes; static;
    /// <summary>Runs AMethod against AUrl, attaching ABody (nil for GET) tagged AContentType,
    /// writing the response body into ASink and returning the HTTP status. Exceptions (incl. the
    /// size-cap overflow) propagate to Fetch, which turns them into the fail-closed False result.</summary>
    class function Execute(const AMethod, AUrl, AContentType: string;
      const ABody: TStream; ATimeoutMs: Cardinal; const ASink: TStream): Integer; static;
    /// <summary>The whole fail-closed contract, shared by both RTLs: request-stream lifetime,
    /// bounded response sink, the try/except that swallows every error, the 2xx gate, and the
    /// bytes-out.</summary>
    class function Fetch(const AMethod, AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean; static;
  public
    function Get(const AUrl: string; ATimeoutMs: Cardinal;
      out AResponse: TBytes): Boolean;
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean;
  end;

implementation

type
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
  protected
    function GetSize: Int64; override;
    procedure SetSize(const ANewSize: Int64); override;
  public
    constructor Create;
    destructor Destroy; override;
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
  end;

constructor TBoundedMemoryStream.Create;
begin
  inherited Create;
  FInner := TMemoryStream.Create;
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
  if ANewSize > MaxResponseBytes then
    raise EWriteError.Create('revocation response exceeds the size cap');
  FInner.Size := ANewSize;
end;

function TBoundedMemoryStream.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  Result := FInner.Read(ABuffer, ACount);
end;

function TBoundedMemoryStream.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  if (FInner.Position + ACount) > MaxResponseBytes then
    raise EWriteError.Create('revocation response exceeds the size cap');
  Result := FInner.Write(ABuffer, ACount);
end;

function TBoundedMemoryStream.Seek(const AOffset: Int64;
  AOrigin: TSeekOrigin): Int64;
begin
  Result := FInner.Seek(AOffset, AOrigin);
end;

{ TSocketHttpFetcher }

class function TSocketHttpFetcher.ReadStreamBytes(const AStream: TStream): TBytes;
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

class function TSocketHttpFetcher.Execute(const AMethod, AUrl, AContentType: string;
  const ABody: TStream; ATimeoutMs: Cardinal; const ASink: TStream): Integer;
var
  LClient: TFPHTTPClient;
begin
  LClient := TFPHTTPClient.Create(nil);
  try
    if ATimeoutMs > 0 then
    begin
      LClient.ConnectTimeout := ATimeoutMs;
      LClient.IOTimeout := ATimeoutMs;
    end;
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

class function TSocketHttpFetcher.Execute(const AMethod, AUrl, AContentType: string;
  const ABody: TStream; ATimeoutMs: Cardinal; const ASink: TStream): Integer;
var
  LClient: THTTPClient;
  LRequest: IHTTPRequest;
  LResponse: IHTTPResponse;
begin
  LClient := THTTPClient.Create;
  try
    if ATimeoutMs > 0 then
    begin
      LClient.ConnectionTimeout := ATimeoutMs;
      LClient.ResponseTimeout := ATimeoutMs;
    end;
    // the responder URL is peer-chosen; do not chase redirects it hands us
    LClient.HandleRedirects := False;
    LRequest := LClient.GetRequest(AMethod, AUrl);
    if ABody <> nil then
    begin
      LRequest.SetHeaderValue('Content-Type', AContentType);
      LRequest.SourceStream := ABody;
    end;
    LResponse := LClient.Execute(LRequest, ASink, nil);
    Result := LResponse.StatusCode;
  finally
    LClient.Free;
  end;
end;

{$ENDIF FPC}

class function TSocketHttpFetcher.Fetch(const AMethod, AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean;
var
  LRequest: TMemoryStream;
  LSink: TStream;
  LStatus: Integer;
begin
  Result := False;
  AResponse := nil;
  LRequest := nil;
  LSink := nil;
  try
    if System.Length(ABody) > 0 then
    begin
      LRequest := TMemoryStream.Create;
      LRequest.WriteBuffer(ABody[0], System.Length(ABody));
      LRequest.Position := 0;
    end;
    LSink := TBoundedMemoryStream.Create;
    LStatus := Execute(AMethod, AUrl, AContentType, LRequest, ATimeoutMs, LSink);
    if (LStatus >= 200) and (LStatus < 300) then
    begin
      AResponse := ReadStreamBytes(LSink);
      Result := System.Length(AResponse) > 0;
    end;
  except
    // fail-closed: any transport/HTTP error, or the size-cap overflow, is a failed fetch
    Result := False;
    AResponse := nil;
  end;
  LRequest.Free;
  LSink.Free;
end;

function TSocketHttpFetcher.Get(const AUrl: string; ATimeoutMs: Cardinal;
  out AResponse: TBytes): Boolean;
begin
  Result := Fetch('GET', AUrl, '', nil, ATimeoutMs, AResponse);
end;

function TSocketHttpFetcher.Post(const AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean;
begin
  Result := Fetch('POST', AUrl, AContentType, ABody, ATimeoutMs, AResponse);
end;

end.
