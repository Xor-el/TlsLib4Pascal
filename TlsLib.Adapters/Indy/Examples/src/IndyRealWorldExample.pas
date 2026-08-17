{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// A real-world proof: an unmodified Indy TIdHTTP client drives a live HTTPS GET and POST to a
/// public test API (postman-echo.com) with its TLS handled entirely by TlsLib4Pascal - a real
/// handshake against a real internet server, real certificate verification, and real HTTP/1.1
/// framing over our records, with zero OpenSSL. It runs twice as an A/B: first pinning the ISRG
/// root (RootCertFile), then trusting the OS system store (UseSystemTrust) with NO manual
/// trust config at all - the "just works" path, verifying the public chain against the platform
/// trust store (Windows crypt32 / macOS SecTrust / Unix bundle). This is a network-gated demo,
/// NOT part of any test gate: it needs outbound HTTPS. Run returns 0 on PASS (both legs), 1 on
/// FAIL, 2 when the network is unreachable (SKIP).
///
/// Trust is real in both legs - the pinned root or the OS store verifies the chain; neither uses
/// InsecureSkipVerify.
/// </summary>
unit IndyRealWorldExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TIndyRealWorldExample = class sealed(TObject)
  strict private
    const
      Host = 'postman-echo.com';
      GetUrl = 'https://postman-echo.com/get';
      PostUrl = 'https://postman-echo.com/post';
      // an echoed marker that proves the POST body round-tripped through our TLS
      Marker = 'tlslib4pascal-realworld-probe';
      TimeoutMs = 15000;
    /// <summary>Walks up from the executable (and cwd) to find the pinned-root PEM, so the
    /// example runs from any build/output location - no machine-specific path.</summary>
    class function FindPinnedRoot: string; static;
    class function SearchFrom(const AStart: string): string; static;
    /// <summary>One live GET+POST. AUseSystemTrust True trusts the OS store (UseSystemTrust,
    /// no manual pin); False pins the ISRG root. Returns 0 PASS / 1 FAIL / 2 SKIP.</summary>
    class function RunOnce(AUseSystemTrust: Boolean;
      const ALabel: string): Integer; static;
  public
    class function Run: Integer; static;
  end;

implementation

uses
  Classes,
  SysUtils,
  IdHTTP,
  IdStack,
  TlpTlsStreamPump,
  TlpIndyTls;

{ TIndyRealWorldExample }

class function TIndyRealWorldExample.SearchFrom(const AStart: string): string;
const
  REL = 'TlsLib.Adapters' + PathDelim + 'Indy' + PathDelim + 'Examples' +
    PathDelim + 'data' + PathDelim + 'isrg-roots.pem';
var
  LDir, LTry: string;
  LI: Integer;
begin
  Result := '';
  LDir := AStart;
  for LI := 0 to 8 do
  begin
    LTry := IncludeTrailingPathDelimiter(LDir) + REL;
    if FileExists(LTry) then
      Exit(LTry);
    LDir := ExtractFileDir(ExcludeTrailingPathDelimiter(LDir));
    if LDir = '' then
      Break;
  end;
end;

class function TIndyRealWorldExample.FindPinnedRoot: string;
begin
  Result := SearchFrom(ExtractFilePath(ParamStr(0)));
  if Result = '' then
    Result := SearchFrom(GetCurrentDir);
  if Result = '' then
    raise Exception.Create(
      'isrg-roots.pem not found (searched up from the exe and cwd)');
end;

class function TIndyRealWorldExample.RunOnce(AUseSystemTrust: Boolean;
  const ALabel: string): Integer;
var
  LGetBody, LPostBody: string;
  LHttp: TIdHTTP;
  LIO: TTlsLibIOHandlerSocket;
  LForm: TStringList;
begin
  Result := 1;
  LGetBody := '';
  LPostBody := '';
  LHttp := TIdHTTP.Create(nil);
  try
    // our Indy IOHandler carries the TLS; TIdHTTP uses it for the https:// connection and sets
    // its Host, so SNI and the verified name are postman-echo.com
    LIO := TTlsLibIOHandlerSocket.Create(LHttp);
    if AUseSystemTrust then
      // trust the OS system store - no RootCertFile, no manual pinning
      LIO.SSLOptions.UseSystemTrust := True
    else
      // pinned trust anchor; VerifyPeer defaults to True
      LIO.SSLOptions.RootCertFile := FindPinnedRoot;
    LHttp.IOHandler := LIO;
    LHttp.HandleRedirects := True;
    LHttp.ConnectTimeout := TimeoutMs;
    LHttp.ReadTimeout := TimeoutMs;
    LHttp.Request.UserAgent := 'TlsLib4Pascal-Example';
    try
      // one TIdHTTP, both verbs: GET then POST an echoed marker back
      LGetBody := LHttp.Get(GetUrl);
      LForm := TStringList.Create;
      try
        LForm.Add('probe=' + Marker);
        LPostBody := LHttp.Post(PostUrl, LForm);
      finally
        LForm.Free;
      end;
    except
      on E: EIdSocketError do
      begin
        // could not reach the host at all: skip rather than fail an offline box
        WriteLn('Indy ', ALabel, ' SKIP: network unreachable (', E.Message, ')');
        Exit(2);
      end;
      on E: ETlsStreamError do
      begin
        // a TLS handshake/record failure IS a failure - surface the alert to diagnose
        if E.HasAlert then
          WriteLn('Indy ', ALabel, ' FAIL: TLS alert ', Ord(E.Alert), ' - ',
            E.Message)
        else
          WriteLn('Indy ', ALabel, ' FAIL: ', E.Message);
        Exit(1);
      end;
      on E: Exception do
      begin
        WriteLn('Indy ', ALabel, ' FAIL: ', E.ClassName, ': ', E.Message);
        Exit(1);
      end;
    end;
  finally
    LHttp.Free;
  end;

  // the GET body echoes the request URL/host; the POST body echoes our marker back
  if (Pos(Host, LGetBody) > 0) and (Pos(Marker, LPostBody) > 0) then
  begin
    WriteLn('Indy ', ALabel, ' PASS: live HTTPS GET + POST through TlsLib4Pascal');
    Result := 0;
  end
  else
    WriteLn('Indy ', ALabel, ' FAIL: unexpected response bodies');
end;

class function TIndyRealWorldExample.Run: Integer;
var
  LPinned, LSystem: Integer;
begin
  // A/B against the same live host: the pinned-root path, then the OS system store with
  // NO manual trust config - both must verify the chain and round-trip GET + POST
  LPinned := RunOnce(False, 'pinned-root');
  LSystem := RunOnce(True, 'system-trust');
  if (LPinned = 2) or (LSystem = 2) then
    Result := 2 // network unreachable on either leg -> SKIP
  else if (LPinned = 0) and (LSystem = 0) then
    Result := 0 // both verified and round-tripped -> PASS
  else
    Result := 1;
end;

end.
