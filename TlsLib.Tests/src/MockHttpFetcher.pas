{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockHttpFetcher;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpIHttpFetcher;

type
  /// <summary>An IHttpFetcher double that returns canned Get/Post responses and never touches
  /// the network, so revocation tests run offline; the invocation counts prove no live fetch
  /// happened.</summary>
  TMockHttpFetcher = class(TInterfacedObject, IHttpFetcher)
  strict private
  var
    FGetOk, FPostOk: Boolean;
    FGetBody, FPostBody: TBytes;
    FLastPostUrl, FLastGetUrl: string;
    FGetCount, FPostCount: Int32;
  public
    constructor Create;
    function Get(const AUrl: string; ATimeoutMs: Cardinal;
      out AResponse: TBytes): Boolean;
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean;
    procedure SetPost(AOk: Boolean; const ABody: TBytes);
    procedure SetGet(AOk: Boolean; const ABody: TBytes);
    property LastPostUrl: string read FLastPostUrl;
    property LastGetUrl: string read FLastGetUrl;
    /// <summary>How many times Get/Post were invoked (0 proves no live fetch happened).</summary>
    property GetCount: Int32 read FGetCount;
    property PostCount: Int32 read FPostCount;
  end;

implementation

{ TMockHttpFetcher }

constructor TMockHttpFetcher.Create;
begin
  inherited Create;
  FGetOk := False;
  FPostOk := False;
end;

function TMockHttpFetcher.Get(const AUrl: string; ATimeoutMs: Cardinal;
  out AResponse: TBytes): Boolean;
begin
  Inc(FGetCount);
  FLastGetUrl := AUrl;
  Result := FGetOk;
  if Result then
    AResponse := System.Copy(FGetBody)
  else
    AResponse := nil;
end;

function TMockHttpFetcher.Post(const AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; out AResponse: TBytes): Boolean;
begin
  Inc(FPostCount);
  FLastPostUrl := AUrl;
  Result := FPostOk;
  if Result then
    AResponse := System.Copy(FPostBody)
  else
    AResponse := nil;
end;

procedure TMockHttpFetcher.SetPost(AOk: Boolean; const ABody: TBytes);
begin
  FPostOk := AOk;
  FPostBody := ABody;
end;

procedure TMockHttpFetcher.SetGet(AOk: Boolean; const ABody: TBytes);
begin
  FGetOk := AOk;
  FGetBody := ABody;
end;

end.
