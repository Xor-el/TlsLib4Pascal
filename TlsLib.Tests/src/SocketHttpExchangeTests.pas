{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SocketHttpExchangeTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpIHttpFetcher,
  TlpITlsTransport,
  TlpINetSocket,
  TlpNetSocket,
  TlpTlsLibExceptions,
  TlpSocketHttpFetcher,
  TlsLibTestBase;

type
  /// <summary>Replays a scripted http response through a loopback responder, so the fetcher's
  /// strict HTTP/1.1 reader sees exactly the bytes a test chose.</summary>
  TSocketHttpExchangeTestCase = class abstract(TTlsLibTestCase)
  strict protected
  const
    CRLF = #13#10;
    DefaultCap = Int32(1024);
    OkHead = 'HTTP/1.1 200 OK' + CRLF;
    ChunkedHead = OkHead + 'Transfer-Encoding: chunked' + CRLF + CRLF;
  strict protected
    /// <summary>Gets the responder's answer to AScript; ABody is the body as text.</summary>
    function FetchScript(const AScript: string; AMaxBytes: Int32; out ABody: string): Boolean;
    procedure CheckFetches(const AScript, AExpectedBody, AMessage: string);
    procedure CheckRefused(const AScript, AMessage: string); overload;
    procedure CheckRefused(const AScript: string; AMaxBytes: Int32; const AMessage: string); overload;
    /// <summary>ACount field lines of AWidth value characters each.</summary>
    function PadFields(ACount, AWidth: Int32): string;
  end;

  /// <summary>Status lines, field lines and the head limits.</summary>
  TTestHttpResponseHead = class(TSocketHttpExchangeTestCase)
  published
    procedure TestWellFormedResponseIsFetched;
    procedure TestHttp10AndAnEmptyReasonAreAccepted;
    procedure TestBareLineFeedIsAccepted;
    procedure TestBadVersionIsRefused;
    procedure TestStatusOtherThanThreeDigitsIsRefused;
    procedure TestBareCarriageReturnIsRefused;
    procedure TestObsFoldIsRefused;
    procedure TestSpaceBeforeColonIsRefused;
    procedure TestNonTokenFieldNameIsRefused;
    procedure TestControlInFieldValueIsRefused;
    procedure TestHeadPast64KiBIsRefused;
    procedure TestMoreThan100FieldsAreRefused;
    procedure TestEightInterimResponsesAreSkipped;
    procedure TestNinthInterimResponseIsRefused;
    procedure TestSwitchingProtocolsIsRefused;
    procedure TestNoContentIsRefused;
    procedure TestRedirectIsRefused;
    procedure TestNotModifiedIsRefused;
    procedure TestNotFoundIsRefused;
    procedure TestEmptyBodyIsRefused;
    procedure TestEarlyCloseInTheHeadIsRefused;
  end;

  /// <summary>Content-Length, Transfer-Encoding, Content-Encoding and a close-delimited body.</summary>
  TTestHttpResponseFraming = class(TSocketHttpExchangeTestCase)
  published
    procedure TestRepeatedContentLengthIsRefused;
    procedure TestMalformedContentLengthIsRefused;
    procedure TestContentLengthPastTheCapIsRefused;
    procedure TestContentLengthAtTheCapIsFetched;
    procedure TestShortContentLengthBodyIsRefused;
    procedure TestTransferEncodingWithContentLengthIsRefused;
    procedure TestTransferCodingOtherThanChunkedIsRefused;
    procedure TestRepeatedTransferEncodingIsRefused;
    procedure TestContentEncodingIsRefused;
    procedure TestIdentityContentEncodingIsFetched;
    procedure TestCloseDelimitedBodyIsFetched;
    procedure TestCloseDelimitedBodyPastTheCapIsRefused;
  end;

  /// <summary>Chunked transfer coding (RFC 9112 7.1).</summary>
  TTestHttpChunkedBody = class(TSocketHttpExchangeTestCase)
  published
    procedure TestChunkedBodyIsFetched;
    procedure TestExtensionsAndTrailersAreIgnored;
    procedure TestNonHexSizeIsRefused;
    procedure TestSeventeenDigitSizeIsRefused;
    procedure TestOverflowingSizeIsRefused;
    procedure TestMissingCrlfAfterDataIsRefused;
    procedure TestExtensionPast4KiBIsRefused;
    procedure TestTrailersPastTheHeadLimitAreRefused;
    procedure TestTotalPastTheCapIsRefused;
    procedure TestLastChunkWithoutFinalCrlfIsRefused;
    procedure TestEarlyCloseInEveryStateIsRefused;
  end;

  /// <summary>The request written, the resolver seam, the proxy and the settings checks.</summary>
  TTestSocketHttpFetcherRequest = class(TSocketHttpExchangeTestCase)
  published
    procedure TestPostSendsBodyAndContentType;
    procedure TestInjectedContentTypeIsNotSent;
    procedure TestResolverMapsTheResponderName;
    procedure TestRefusingResolverPreventsTheConnect;
    procedure TestProxyIsSentTheAbsoluteForm;
    procedure TestIPv6ResponderIsRefused;
    procedure TestNilResolverIsRefused;
    procedure TestProxyWithoutPortIsRefused;
  end;

implementation

type
  // accepts one connection, records the request, answers with a fixed script and closes
  TScriptedResponder = class(TThread)
  strict private
  const
    AcceptPollMs = 100;
    RequestReadMs = 5000;
  var
    FListener: ITcpListener;
    FScript: TBytes;
    FRequest: string;
    FAccepted: Boolean;
    function ReadRequest(const AStream: ITlsTimedTransport): string;
  protected
    procedure Execute; override;
  public
    constructor Create(const AScript: string);
    destructor Destroy; override;
    function Port: Word;
    function Url: string;
    // stops the responder; the request it read, '' when nothing connected
    function Finish: string;
    // valid after Finish
    property Accepted: Boolean read FAccepted;
  end;

  // answers one name with 127.0.0.1 and refuses every other
  TMappingResolver = class sealed(TInterfacedObject, IHostResolver)
  strict private
    FName: string;
  public
    constructor Create(const AName: string);
    function TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
  end;

{ TScriptedResponder }

constructor TScriptedResponder.Create(const AScript: string);
var
  LI: Int32;
begin
  FListener := TTcpListener.Create('127.0.0.1', 0) as ITcpListener;
  SetLength(FScript, System.Length(AScript));
  for LI := 1 to System.Length(AScript) do
    FScript[LI - 1] := Byte(Ord(AScript[LI]));
  inherited Create(False);
end;

destructor TScriptedResponder.Destroy;
begin
  Terminate;
  WaitFor;
  FListener := nil;
  inherited Destroy;
end;

function TScriptedResponder.Port: Word;
begin
  Result := FListener.Port;
end;

function TScriptedResponder.Url: string;
begin
  Result := 'http://127.0.0.1:' + IntToStr(Port) + '/';
end;

function TScriptedResponder.Finish: string;
begin
  Terminate;
  WaitFor;
  Result := FRequest;
end;

function TScriptedResponder.ReadRequest(const AStream: ITlsTimedTransport): string;
var
  LBuffer: TBytes;
  LGot, LI, LHeadEnd, LLengthAt, LBodyLength: Int32;
  LRest: string;
begin
  Result := '';
  SetLength(LBuffer, 4096);
  LBodyLength := 0;
  repeat
    LGot := AStream.Read(LBuffer, 0, System.Length(LBuffer));
    if LGot <= 0 then
      Exit;
    for LI := 0 to LGot - 1 do
      Result := Result + Char(LBuffer[LI]);
    LHeadEnd := Pos(#13#10#13#10, Result);
    if LHeadEnd > 0 then
    begin
      LLengthAt := Pos(#13#10'Content-Length: ', Result);
      if (LLengthAt > 0) and (LLengthAt < LHeadEnd) then
      begin
        LRest := Copy(Result, LLengthAt + 18, MaxInt);
        LBodyLength := StrToIntDef(Copy(LRest, 1, Pos(#13#10, LRest) - 1), 0);
      end;
    end;
  until (LHeadEnd > 0) and (System.Length(Result) >= LHeadEnd + 3 + LBodyLength);
end;

procedure TScriptedResponder.Execute;
var
  LStream: ITlsTimedTransport;
begin
  LStream := nil;
  while (LStream = nil) and not Terminated do
    FListener.TryAccept(AcceptPollMs, LStream);
  if LStream = nil then
    Exit;
  FAccepted := True;
  try
    LStream.SetReadTimeout(RequestReadMs);
    FRequest := ReadRequest(LStream);
    if System.Length(FScript) > 0 then
      LStream.Write(FScript, 0, System.Length(FScript));
  except
    // the fetcher may hang up first, which is what a refused response does
    on E: Exception do
      Exit;
  end;
end;

{ TMappingResolver }

constructor TMappingResolver.Create(const AName: string);
begin
  inherited Create;
  FName := AName;
end;

function TMappingResolver.TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
begin
  AAddress := nil;
  Result := SameText(AHost, FName);
  if Result then
    AAddress := TBytes.Create(127, 0, 0, 1);
end;

{ TSocketHttpExchangeTestCase }

function TSocketHttpExchangeTestCase.FetchScript(const AScript: string; AMaxBytes: Int32;
  out ABody: string): Boolean;
var
  LResponder: TScriptedResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
  LI: Int32;
begin
  LResponder := TScriptedResponder.Create(AScript);
  try
    LFetcher := TSocketHttpFetcher.Create;
    Result := LFetcher.Get(LResponder.Url, 5000, AMaxBytes, LResponse);
  finally
    LFetcher := nil;
    LResponder.Free;
  end;
  ABody := '';
  for LI := 0 to System.Length(LResponse) - 1 do
    ABody := ABody + Char(LResponse[LI]);
end;

procedure TSocketHttpExchangeTestCase.CheckFetches(const AScript, AExpectedBody,
  AMessage: string);
var
  LBody: string;
begin
  CheckTrue(FetchScript(AScript, DefaultCap, LBody), AMessage);
  CheckEquals(AExpectedBody, LBody, AMessage + ': the body');
end;

procedure TSocketHttpExchangeTestCase.CheckRefused(const AScript, AMessage: string);
begin
  CheckRefused(AScript, DefaultCap, AMessage);
end;

procedure TSocketHttpExchangeTestCase.CheckRefused(const AScript: string; AMaxBytes: Int32;
  const AMessage: string);
var
  LBody: string;
begin
  CheckFalse(FetchScript(AScript, AMaxBytes, LBody), AMessage);
  CheckEquals('', LBody, AMessage + ': no body is returned');
end;

function TSocketHttpExchangeTestCase.PadFields(ACount, AWidth: Int32): string;
var
  LI: Int32;
  LValue: string;
begin
  Result := '';
  LValue := StringOfChar('v', AWidth);
  for LI := 1 to ACount do
    Result := Result + 'X-Pad' + IntToStr(LI) + ': ' + LValue + CRLF;
end;

{ TTestHttpResponseHead }

procedure TTestHttpResponseHead.TestWellFormedResponseIsFetched;
begin
  CheckFetches(OkHead + 'Content-Length: 5' + CRLF + 'Server:  x  ' + CRLF + CRLF + 'hello',
    'hello', 'a well-formed response');
end;

procedure TTestHttpResponseHead.TestHttp10AndAnEmptyReasonAreAccepted;
begin
  CheckFetches('HTTP/1.0 200 ' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok', 'ok',
    'HTTP/1.0 with an empty reason');
  CheckFetches('HTTP/1.1 200' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok', 'ok',
    'a status line without a reason');
end;

procedure TTestHttpResponseHead.TestBareLineFeedIsAccepted;
begin
  CheckFetches('HTTP/1.1 200 OK'#10'Content-Length: 2'#10#10'ok', 'ok', 'bare LF line ends');
end;

procedure TTestHttpResponseHead.TestBadVersionIsRefused;
begin
  CheckRefused('HTTP/2.0 200 OK' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'an HTTP/2.0 status line');
  CheckRefused('http/1.1 200 OK' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a lower-case version');
  CheckRefused('HTTP/1.1  200 OK' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'two spaces after the version');
end;

procedure TTestHttpResponseHead.TestStatusOtherThanThreeDigitsIsRefused;
begin
  CheckRefused('HTTP/1.1 20 OK' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a two-digit status');
  CheckRefused('HTTP/1.1 2000 OK' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a four-digit status');
  CheckRefused('HTTP/1.1 2x0 OK' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a status with a letter');
end;

procedure TTestHttpResponseHead.TestBareCarriageReturnIsRefused;
begin
  CheckRefused(OkHead + 'X-A: b'#13'c' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a CR not followed by LF');
end;

procedure TTestHttpResponseHead.TestObsFoldIsRefused;
begin
  CheckRefused(OkHead + 'X-A: b' + CRLF + ' c' + CRLF + 'Content-Length: 2' + CRLF + CRLF +
    'ok', 'an obs-fold continuation line');
end;

procedure TTestHttpResponseHead.TestSpaceBeforeColonIsRefused;
begin
  CheckRefused(OkHead + 'Content-Length : 2' + CRLF + CRLF + 'ok',
    'whitespace between the field name and the colon');
end;

procedure TTestHttpResponseHead.TestNonTokenFieldNameIsRefused;
begin
  CheckRefused(OkHead + 'X(A): b' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a field name that is not a token');
  CheckRefused(OkHead + ': b' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'an empty field name');
  CheckRefused(OkHead + 'NoColon' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a field line without a colon');
end;

procedure TTestHttpResponseHead.TestControlInFieldValueIsRefused;
begin
  CheckRefused(OkHead + 'X-A: b'#1'c' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a control character in a value');
  CheckFetches(OkHead + 'X-A: b'#9'c' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok', 'ok',
    'a tab in a value');
end;

procedure TTestHttpResponseHead.TestHeadPast64KiBIsRefused;
begin
  CheckFetches(OkHead + PadFields(60, 1000) + 'Content-Length: 2' + CRLF + CRLF + 'ok', 'ok',
    'a 60 KB head');
  CheckRefused(OkHead + PadFields(70, 1000) + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a 70 KB head');
end;

procedure TTestHttpResponseHead.TestMoreThan100FieldsAreRefused;
begin
  CheckFetches(OkHead + PadFields(99, 1) + 'Content-Length: 2' + CRLF + CRLF + 'ok', 'ok',
    '100 fields');
  CheckRefused(OkHead + PadFields(100, 1) + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    '101 fields');
end;

procedure TTestHttpResponseHead.TestEightInterimResponsesAreSkipped;
var
  LInterim: string;
  LI: Int32;
begin
  LInterim := '';
  for LI := 1 to 8 do
    LInterim := LInterim + 'HTTP/1.1 100 Continue' + CRLF + 'X-I: ' + IntToStr(LI) + CRLF + CRLF;
  CheckFetches(LInterim + OkHead + 'Content-Length: 2' + CRLF + CRLF + 'ok', 'ok',
    'eight interim responses before the final one');
end;

procedure TTestHttpResponseHead.TestNinthInterimResponseIsRefused;
var
  LInterim: string;
  LI: Int32;
begin
  LInterim := '';
  for LI := 1 to 9 do
    LInterim := LInterim + 'HTTP/1.1 103 Early Hints' + CRLF + CRLF;
  CheckRefused(LInterim + OkHead + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'nine interim responses');
end;

procedure TTestHttpResponseHead.TestSwitchingProtocolsIsRefused;
begin
  CheckRefused('HTTP/1.1 101 Switching Protocols' + CRLF + 'Upgrade: x' + CRLF + CRLF + OkHead +
    'Content-Length: 2' + CRLF + CRLF + 'ok', 'a 101 response');
end;

procedure TTestHttpResponseHead.TestNoContentIsRefused;
begin
  CheckRefused('HTTP/1.1 204 No Content' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a 204 response, even one that sends bytes after its head');
end;

procedure TTestHttpResponseHead.TestRedirectIsRefused;
begin
  CheckRefused('HTTP/1.1 301 Moved Permanently' + CRLF + 'Location: http://127.0.0.1/' + CRLF +
    'Content-Length: 2' + CRLF + CRLF + 'ok', 'a redirect');
end;

procedure TTestHttpResponseHead.TestNotModifiedIsRefused;
begin
  CheckRefused('HTTP/1.1 304 Not Modified' + CRLF + CRLF, 'a 304 response');
end;

procedure TTestHttpResponseHead.TestNotFoundIsRefused;
begin
  CheckRefused('HTTP/1.1 404 Not Found' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'no',
    'a 404 with a body');
end;

procedure TTestHttpResponseHead.TestEmptyBodyIsRefused;
begin
  CheckRefused(OkHead + 'Content-Length: 0' + CRLF + CRLF, 'a 200 with an empty body');
end;

procedure TTestHttpResponseHead.TestEarlyCloseInTheHeadIsRefused;
begin
  CheckRefused('HTTP/1.1 200', 'a close inside the status line');
  CheckRefused(OkHead + 'Content-Le', 'a close inside a field line');
  CheckRefused(OkHead + 'Content-Length: 2' + CRLF, 'a close before the empty line');
end;

{ TTestHttpResponseFraming }

procedure TTestHttpResponseFraming.TestRepeatedContentLengthIsRefused;
begin
  CheckRefused(OkHead + 'Content-Length: 2' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'two equal Content-Length fields');
  CheckRefused(OkHead + 'Content-Length: 2' + CRLF + 'Content-Length: 3' + CRLF + CRLF + 'ok',
    'two different Content-Length fields');
end;

procedure TTestHttpResponseFraming.TestMalformedContentLengthIsRefused;
begin
  CheckRefused(OkHead + 'Content-Length: +2' + CRLF + CRLF + 'ok', 'a signed length');
  CheckRefused(OkHead + 'Content-Length: 2, 2' + CRLF + CRLF + 'ok', 'a length list');
  CheckRefused(OkHead + 'Content-Length: 0x2' + CRLF + CRLF + 'ok', 'a hex length');
  CheckRefused(OkHead + 'Content-Length:' + CRLF + CRLF + 'ok', 'an empty length');
  CheckRefused(OkHead + 'Content-Length: 99999999999999999999999' + CRLF + CRLF + 'ok',
    'a length past Int64');
end;

procedure TTestHttpResponseFraming.TestContentLengthPastTheCapIsRefused;
begin
  CheckRefused(OkHead + 'Content-Length: 1025' + CRLF + CRLF + StringOfChar('a', 1025),
    'a length one past the cap');
end;

procedure TTestHttpResponseFraming.TestContentLengthAtTheCapIsFetched;
begin
  CheckFetches(OkHead + 'Content-Length: 1024' + CRLF + CRLF + StringOfChar('a', 1024),
    StringOfChar('a', 1024), 'a length at the cap');
end;

procedure TTestHttpResponseFraming.TestShortContentLengthBodyIsRefused;
begin
  CheckRefused(OkHead + 'Content-Length: 10' + CRLF + CRLF + 'hello',
    'a body shorter than its length');
end;

procedure TTestHttpResponseFraming.TestTransferEncodingWithContentLengthIsRefused;
begin
  CheckRefused(OkHead + 'Content-Length: 5' + CRLF + 'Transfer-Encoding: chunked' + CRLF + CRLF +
    '5' + CRLF + 'hello' + CRLF + '0' + CRLF + CRLF, 'Transfer-Encoding beside Content-Length');
end;

procedure TTestHttpResponseFraming.TestTransferCodingOtherThanChunkedIsRefused;
begin
  CheckRefused(OkHead + 'Transfer-Encoding: gzip, chunked' + CRLF + CRLF + '5' + CRLF + 'hello' +
    CRLF + '0' + CRLF + CRLF, 'gzip before chunked');
  CheckRefused(OkHead + 'Transfer-Encoding: identity' + CRLF + CRLF + 'hello',
    'an identity transfer coding');
  CheckFetches(OkHead + 'Transfer-Encoding: Chunked' + CRLF + CRLF + '5' + CRLF + 'hello' + CRLF +
    '0' + CRLF + CRLF, 'hello', 'chunked in another case');
end;

procedure TTestHttpResponseFraming.TestRepeatedTransferEncodingIsRefused;
begin
  CheckRefused(OkHead + 'Transfer-Encoding: chunked' + CRLF + 'Transfer-Encoding: chunked' + CRLF +
    CRLF + '5' + CRLF + 'hello' + CRLF + '0' + CRLF + CRLF, 'two Transfer-Encoding fields');
end;

procedure TTestHttpResponseFraming.TestContentEncodingIsRefused;
begin
  CheckRefused(OkHead + 'Content-Encoding: gzip' + CRLF + 'Content-Length: 2' + CRLF + CRLF + 'ok',
    'a gzip content coding');
end;

procedure TTestHttpResponseFraming.TestIdentityContentEncodingIsFetched;
begin
  CheckFetches(OkHead + 'Content-Encoding: identity' + CRLF + 'Content-Length: 2' + CRLF + CRLF +
    'ok', 'ok', 'an identity content coding');
end;

procedure TTestHttpResponseFraming.TestCloseDelimitedBodyIsFetched;
begin
  CheckFetches(OkHead + CRLF + 'read to close', 'read to close', 'a close-delimited body');
end;

procedure TTestHttpResponseFraming.TestCloseDelimitedBodyPastTheCapIsRefused;
begin
  CheckRefused(OkHead + CRLF + StringOfChar('a', 1025), 'a close-delimited body past the cap');
end;

{ TTestHttpChunkedBody }

procedure TTestHttpChunkedBody.TestChunkedBodyIsFetched;
begin
  CheckFetches(ChunkedHead + '5' + CRLF + 'hello' + CRLF + 'a' + CRLF + ' world!!!!' + CRLF + '0' +
    CRLF + CRLF, 'hello world!!!!', 'two chunks');
  CheckFetches(ChunkedHead + '0000000000000005' + CRLF + 'hello' + CRLF + '0' + CRLF + CRLF,
    'hello', 'a sixteen-digit size');
end;

procedure TTestHttpChunkedBody.TestExtensionsAndTrailersAreIgnored;
begin
  CheckFetches(ChunkedHead + '5 ;name=value' + CRLF + 'hello' + CRLF + '0;last' + CRLF +
    'X-Trailer: v' + CRLF + CRLF, 'hello', 'an extension and a trailer');
  CheckFetches(ChunkedHead + '5;' + StringOfChar('e', 4000) + CRLF + 'hello' + CRLF + '0' + CRLF +
    CRLF, 'hello', 'an extension inside the line limit');
end;

procedure TTestHttpChunkedBody.TestNonHexSizeIsRefused;
begin
  CheckRefused(ChunkedHead + 'g' + CRLF + 'hello' + CRLF + '0' + CRLF + CRLF, 'a non-hex size');
  CheckRefused(ChunkedHead + CRLF + 'hello' + CRLF + '0' + CRLF + CRLF, 'an empty size line');
  CheckRefused(ChunkedHead + '5x' + CRLF + 'hello' + CRLF + '0' + CRLF + CRLF,
    'a size followed by junk');
end;

procedure TTestHttpChunkedBody.TestSeventeenDigitSizeIsRefused;
begin
  CheckRefused(ChunkedHead + '00000000000000005' + CRLF + 'hello' + CRLF + '0' + CRLF + CRLF,
    'a seventeen-digit size');
end;

procedure TTestHttpChunkedBody.TestOverflowingSizeIsRefused;
begin
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello' + CRLF + '8000000000000000' + CRLF + '0' + CRLF +
    CRLF, 'a size past Int64');
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello' + CRLF + 'FFFFFFFFFFFFFFFB' + CRLF + '0' + CRLF +
    CRLF, 'a size that would wrap to a negative one');
end;

procedure TTestHttpChunkedBody.TestMissingCrlfAfterDataIsRefused;
begin
  CheckRefused(ChunkedHead + '5' + CRLF + 'helloX' + CRLF + '0' + CRLF + CRLF,
    'data longer than its size');
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello'#10'0' + CRLF + CRLF, 'data ended by a bare LF');
  CheckRefused(ChunkedHead + '5' + CRLF + 'helloXY0' + CRLF + CRLF, 'data ended by two other bytes');
end;

procedure TTestHttpChunkedBody.TestExtensionPast4KiBIsRefused;
begin
  CheckRefused(ChunkedHead + '5;' + StringOfChar('e', 5000) + CRLF + 'hello' + CRLF + '0' + CRLF +
    CRLF, 'an extension past the line limit');
end;

procedure TTestHttpChunkedBody.TestTrailersPastTheHeadLimitAreRefused;
begin
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello' + CRLF + '0' + CRLF + PadFields(70, 1000) +
    CRLF, 'trailers past the head limit');
end;

procedure TTestHttpChunkedBody.TestTotalPastTheCapIsRefused;
begin
  CheckRefused(ChunkedHead + '258' + CRLF + StringOfChar('a', 600) + CRLF + '258' + CRLF +
    StringOfChar('a', 600) + CRLF + '0' + CRLF + CRLF, 'chunks past the cap');
end;

procedure TTestHttpChunkedBody.TestLastChunkWithoutFinalCrlfIsRefused;
begin
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello' + CRLF + '0' + CRLF,
    'a last chunk without the final CRLF');
end;

procedure TTestHttpChunkedBody.TestEarlyCloseInEveryStateIsRefused;
begin
  CheckRefused(ChunkedHead, 'a close before the first size');
  CheckRefused(ChunkedHead + '5', 'a close inside a size line');
  CheckRefused(ChunkedHead + '5' + CRLF + 'hel', 'a close inside the data');
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello', 'a close before the data CRLF');
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello' + CRLF, 'a close before the next size');
  CheckRefused(ChunkedHead + '5' + CRLF + 'hello' + CRLF + '0' + CRLF + 'X-T: v',
    'a close inside a trailer');
end;

{ TTestSocketHttpFetcherRequest }

procedure TTestSocketHttpFetcherRequest.TestPostSendsBodyAndContentType;
var
  LResponder: TScriptedResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
  LRequest: string;
begin
  LResponder := TScriptedResponder.Create(OkHead + 'Content-Length: 2' + CRLF + CRLF + 'ok');
  try
    LFetcher := TSocketHttpFetcher.Create;
    CheckTrue(LFetcher.Post(LResponder.Url + 'ocsp', 'application/ocsp-request',
      TBytes.Create(1, 2, 65), 5000, DefaultCap, LResponse), 'the POST is answered');
    LRequest := LResponder.Finish;
    CheckEquals('POST /ocsp HTTP/1.1' + CRLF + 'Host: 127.0.0.1:' + IntToStr(LResponder.Port) +
      CRLF + 'Content-Type: application/ocsp-request' + CRLF + 'Content-Length: 3' + CRLF +
      'Connection: close' + CRLF + CRLF + #1#2'A', LRequest, 'the request as written');
  finally
    LFetcher := nil;
    LResponder.Free;
  end;
end;

procedure TTestSocketHttpFetcherRequest.TestInjectedContentTypeIsNotSent;
var
  LResponder: TScriptedResponder;
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
begin
  LResponder := TScriptedResponder.Create(OkHead + 'Content-Length: 2' + CRLF + CRLF + 'ok');
  try
    LFetcher := TSocketHttpFetcher.Create;
    CheckFalse(LFetcher.Post(LResponder.Url, 'application/ocsp-request' + CRLF + 'X-Evil: 1',
      TBytes.Create(1), 5000, DefaultCap, LResponse), 'a Content-Type with a CRLF fails');
    CheckFalse(LFetcher.Post(LResponder.Url, 'application/ocsp-request; q=1', TBytes.Create(1),
      5000, DefaultCap, LResponse), 'a Content-Type with parameters fails');
    CheckFalse(LFetcher.Post(LResponder.Url, 'application', TBytes.Create(1), 5000, DefaultCap,
      LResponse), 'a Content-Type without a subtype fails');
    LResponder.Finish;
    CheckFalse(LResponder.Accepted, 'nothing reached the responder');
  finally
    LFetcher := nil;
    LResponder.Free;
  end;
end;

procedure TTestSocketHttpFetcherRequest.TestResolverMapsTheResponderName;
var
  LResponder: TScriptedResponder;
  LFetcher: IHttpFetcher;
  LSettings: TSocketHttpFetcherSettings;
  LResponse: TBytes;
  LHost: string;
begin
  LResponder := TScriptedResponder.Create(OkHead + 'Content-Length: 2' + CRLF + CRLF + 'ok');
  try
    LSettings := TSocketHttpFetcherSettings.Defaults;
    LSettings.Resolver := TMappingResolver.Create('responder.test');
    LFetcher := TSocketHttpFetcher.Create(LSettings);
    LHost := 'responder.test:' + IntToStr(LResponder.Port);
    CheckTrue(LFetcher.Get('http://' + LHost + '/crl', 5000, DefaultCap, LResponse),
      'the mapped name is fetched');
    CheckEquals('GET /crl HTTP/1.1' + CRLF + 'Host: ' + LHost + CRLF + 'Connection: close' + CRLF +
      CRLF, LResponder.Finish, 'the Host field names the URL host');
  finally
    LFetcher := nil;
    LResponder.Free;
  end;
end;

procedure TTestSocketHttpFetcherRequest.TestRefusingResolverPreventsTheConnect;
var
  LResponder: TScriptedResponder;
  LFetcher: IHttpFetcher;
  LSettings: TSocketHttpFetcherSettings;
  LResponse: TBytes;
begin
  LResponder := TScriptedResponder.Create(OkHead + 'Content-Length: 2' + CRLF + CRLF + 'ok');
  try
    LSettings := TSocketHttpFetcherSettings.Defaults;
    LSettings.Resolver := TMappingResolver.Create('other.test');
    LFetcher := TSocketHttpFetcher.Create(LSettings);
    CheckFalse(LFetcher.Get(LResponder.Url, 5000, DefaultCap, LResponse),
      'a refused address fails closed');
    LResponder.Finish;
    CheckFalse(LResponder.Accepted, 'no connection was made');
  finally
    LFetcher := nil;
    LResponder.Free;
  end;
end;

procedure TTestSocketHttpFetcherRequest.TestProxyIsSentTheAbsoluteForm;
var
  LProxy: TScriptedResponder;
  LFetcher: IHttpFetcher;
  LSettings: TSocketHttpFetcherSettings;
  LResponse: TBytes;
begin
  LProxy := TScriptedResponder.Create(OkHead + 'Content-Length: 2' + CRLF + CRLF + 'ok');
  try
    LSettings := TSocketHttpFetcherSettings.Defaults;
    LSettings.Resolver := TMappingResolver.Create('proxy.test');
    LSettings.ProxyHost := 'proxy.test';
    LSettings.ProxyPort := LProxy.Port;
    LFetcher := TSocketHttpFetcher.Create(LSettings);
    CheckTrue(LFetcher.Get('http://origin.test:8080/crl?x=1', 5000, DefaultCap, LResponse),
      'the fetch goes through the proxy');
    CheckEquals('GET http://origin.test:8080/crl?x=1 HTTP/1.1' + CRLF + 'Host: origin.test:8080' +
      CRLF + 'Connection: close' + CRLF + CRLF, LProxy.Finish,
      'the proxy is sent the absolute form and the origin host');
  finally
    LFetcher := nil;
    LProxy.Free;
  end;
end;

procedure TTestSocketHttpFetcherRequest.TestIPv6ResponderIsRefused;
var
  LFetcher: IHttpFetcher;
  LResponse: TBytes;
begin
  LFetcher := TSocketHttpFetcher.Create;
  CheckFalse(LFetcher.Get('http://[::1]:9/crl', 2000, DefaultCap, LResponse),
    'an IPv6 responder fails closed');
end;

procedure TTestSocketHttpFetcherRequest.TestNilResolverIsRefused;
var
  LSettings: TSocketHttpFetcherSettings;
  LRaised: Boolean;
begin
  LSettings := TSocketHttpFetcherSettings.Defaults;
  LSettings.Resolver := nil;
  LRaised := False;
  try
    TSocketHttpFetcher.Create(LSettings).Free;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil resolver raises');
end;

procedure TTestSocketHttpFetcherRequest.TestProxyWithoutPortIsRefused;
var
  LSettings: TSocketHttpFetcherSettings;
  LRaised: Boolean;
begin
  LSettings := TSocketHttpFetcherSettings.Defaults;
  LSettings.ProxyHost := '127.0.0.1';
  LRaised := False;
  try
    TSocketHttpFetcher.Create(LSettings).Free;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a proxy host without a port raises');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHttpResponseHead);
  RegisterTest(TTestHttpResponseFraming);
  RegisterTest(TTestHttpChunkedBody);
  RegisterTest(TTestSocketHttpFetcherRequest);
{$ELSE}
  RegisterTest(TTestHttpResponseHead.Suite);
  RegisterTest(TTestHttpResponseFraming.Suite);
  RegisterTest(TTestHttpChunkedBody.Suite);
  RegisterTest(TTestSocketHttpFetcherRequest.Suite);
{$ENDIF FPC}

end.
