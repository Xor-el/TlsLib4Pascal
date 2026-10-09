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
  TlpArrayUtilities,
  TlpIHttpFetcher,
  MockClock;

type
  /// <summary>An IHttpFetcher double that returns canned Get/Post responses and never touches
  /// the network, so revocation tests run offline; the invocation counts prove no live fetch
  /// happened. A URL can also be scripted to its own result and to take time on an attached
  /// clock, and every call's URL and timeout is recorded.</summary>
  TMockHttpFetcher = class(TInterfacedObject, IHttpFetcher)
  strict private
  type
    TScript = record
      Url: string;
      Ok: Boolean;
      Body: TBytes;
      ElapsedMs: Int64;
      WallStepMs: Int64;
    end;
  var
    FGetOk, FPostOk: Boolean;
    FGetBody, FPostBody: TBytes;
    FLastPostUrl, FLastGetUrl: string;
    FGetCount, FPostCount: Int32;
    FLastMaxBytes: Int32;
    FPostScripts, FGetScripts: TArray<TScript>;
    FClock: TMockClock;
    FTicks: TMockMonotonicClock;
    FPostUrls, FGetUrls: TArray<string>;
    FPostTimeouts, FGetTimeouts: TArray<Cardinal>;
    class function Find(const AScripts: TArray<TScript>; const AUrl: string;
      out AScript: TScript): Boolean; static;
    procedure Spend(AElapsedMs, AWallStepMs: Int64);
  public
    constructor Create;
    /// <summary>Scripts what a POST to AUrl returns and how long it takes: the attached clocks
    /// both advance by AElapsedMs.</summary>
    procedure ScriptPost(const AUrl: string; AOk: Boolean; const ABody: TBytes;
      AElapsedMs: Int64); overload;
    /// <summary>As above, and the wall clock alone also steps by AWallStepMs (negative steps it
    /// back), as an NTP or manual adjustment would.</summary>
    procedure ScriptPost(const AUrl: string; AOk: Boolean; const ABody: TBytes;
      AElapsedMs, AWallStepMs: Int64); overload;
    /// <summary>As ScriptPost, for a GET.</summary>
    procedure ScriptGet(const AUrl: string; AOk: Boolean; const ABody: TBytes;
      AElapsedMs: Int64); overload;
    procedure ScriptGet(const AUrl: string; AOk: Boolean; const ABody: TBytes;
      AElapsedMs, AWallStepMs: Int64); overload;
    /// <summary>The wall clock a scripted call advances; not owned, so the caller keeps it alive.</summary>
    procedure AttachClock(const AClock: TMockClock);
    /// <summary>The elapsed-time clock a scripted call advances; not owned.</summary>
    procedure AttachMonotonicClock(const AClock: TMockMonotonicClock);
    property PostUrls: TArray<string> read FPostUrls;
    property GetUrls: TArray<string> read FGetUrls;
    property PostTimeouts: TArray<Cardinal> read FPostTimeouts;
    property GetTimeouts: TArray<Cardinal> read FGetTimeouts;
    function Get(const AUrl: string; ATimeoutMs: Cardinal; AMaxBytes: Int32;
      out AResponse: TBytes): Boolean;
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; AMaxBytes: Int32; out AResponse: TBytes): Boolean;
    procedure SetPost(AOk: Boolean; const ABody: TBytes);
    procedure SetGet(AOk: Boolean; const ABody: TBytes);
    property LastPostUrl: string read FLastPostUrl;
    property LastGetUrl: string read FLastGetUrl;
    /// <summary>The AMaxBytes the caller passed on the last Get/Post (proves the checker's cap).</summary>
    property LastMaxBytes: Int32 read FLastMaxBytes;
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

class function TMockHttpFetcher.Find(const AScripts: TArray<TScript>; const AUrl: string;
  out AScript: TScript): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to System.High(AScripts) do
    if AScripts[LI].Url = AUrl then
    begin
      AScript := AScripts[LI];
      Exit(True);
    end;
  AScript := Default(TScript);
  Result := False;
end;

procedure TMockHttpFetcher.Spend(AElapsedMs, AWallStepMs: Int64);
var
  LWallMs: Int64;
begin
  if FTicks <> nil then
    FTicks.Advance(AElapsedMs);
  if FClock = nil then
    Exit;
  LWallMs := AElapsedMs + AWallStepMs;
  if LWallMs >= 0 then
    FClock.Advance(UInt64(LWallMs))
  else
    FClock.Retreat(UInt64(-LWallMs));
end;

procedure TMockHttpFetcher.ScriptPost(const AUrl: string; AOk: Boolean; const ABody: TBytes;
  AElapsedMs: Int64);
begin
  ScriptPost(AUrl, AOk, ABody, AElapsedMs, 0);
end;

procedure TMockHttpFetcher.ScriptPost(const AUrl: string; AOk: Boolean; const ABody: TBytes;
  AElapsedMs, AWallStepMs: Int64);
var
  LScript: TScript;
begin
  LScript.Url := AUrl;
  LScript.Ok := AOk;
  LScript.Body := ABody;
  LScript.ElapsedMs := AElapsedMs;
  LScript.WallStepMs := AWallStepMs;
  TArrayUtilities.Append<TScript>(FPostScripts, LScript);
end;

procedure TMockHttpFetcher.ScriptGet(const AUrl: string; AOk: Boolean; const ABody: TBytes;
  AElapsedMs: Int64);
begin
  ScriptGet(AUrl, AOk, ABody, AElapsedMs, 0);
end;

procedure TMockHttpFetcher.ScriptGet(const AUrl: string; AOk: Boolean; const ABody: TBytes;
  AElapsedMs, AWallStepMs: Int64);
var
  LScript: TScript;
begin
  LScript.Url := AUrl;
  LScript.Ok := AOk;
  LScript.Body := ABody;
  LScript.ElapsedMs := AElapsedMs;
  LScript.WallStepMs := AWallStepMs;
  TArrayUtilities.Append<TScript>(FGetScripts, LScript);
end;

procedure TMockHttpFetcher.AttachClock(const AClock: TMockClock);
begin
  FClock := AClock;
end;

procedure TMockHttpFetcher.AttachMonotonicClock(const AClock: TMockMonotonicClock);
begin
  FTicks := AClock;
end;

function TMockHttpFetcher.Get(const AUrl: string; ATimeoutMs: Cardinal;
  AMaxBytes: Int32; out AResponse: TBytes): Boolean;
var
  LScript: TScript;
begin
  Inc(FGetCount);
  FLastGetUrl := AUrl;
  FLastMaxBytes := AMaxBytes;
  TArrayUtilities.Append<string>(FGetUrls, AUrl);
  TArrayUtilities.Append<Cardinal>(FGetTimeouts, ATimeoutMs);
  if Find(FGetScripts, AUrl, LScript) then
  begin
    Spend(LScript.ElapsedMs, LScript.WallStepMs);
    Result := LScript.Ok;
    if Result then
      AResponse := System.Copy(LScript.Body)
    else
      AResponse := nil;
    Exit;
  end;
  Result := FGetOk;
  if Result then
    AResponse := System.Copy(FGetBody)
  else
    AResponse := nil;
end;

function TMockHttpFetcher.Post(const AUrl, AContentType: string;
  const ABody: TBytes; ATimeoutMs: Cardinal; AMaxBytes: Int32;
  out AResponse: TBytes): Boolean;
var
  LScript: TScript;
begin
  Inc(FPostCount);
  FLastPostUrl := AUrl;
  FLastMaxBytes := AMaxBytes;
  TArrayUtilities.Append<string>(FPostUrls, AUrl);
  TArrayUtilities.Append<Cardinal>(FPostTimeouts, ATimeoutMs);
  if Find(FPostScripts, AUrl, LScript) then
  begin
    Spend(LScript.ElapsedMs, LScript.WallStepMs);
    Result := LScript.Ok;
    if Result then
      AResponse := System.Copy(LScript.Body)
    else
      AResponse := nil;
    Exit;
  end;
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
