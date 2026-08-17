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
/// A real-world proof: a single unmodified Synapse THTTPSend client drives a live HTTPS GET and
/// POST to a public test API (postman-echo.com) with its TLS handled entirely by TlsLib4Pascal -
/// a real handshake against a real internet server and real HTTP/1.1 framing over our records,
/// with zero OpenSSL. THTTPSend keeps the socket alive, so both requests run over ONE reused TLS
/// connection - the strongest proof that our records carry ordinary application traffic. It runs
/// TWICE against the same host: leg A verifies against a pinned root (CertCAFile), leg B verifies
/// against the OS system-trust store harvested and validated entirely by TlsLib4Pascal
/// (SetTlsLibSynapseSystemTrust, no pinned file) - proving a caller can drop the bundled PEM and
/// lean on the platform anchors instead. This is a network-gated demo, NOT part of any test gate:
/// it needs outbound HTTPS; the pinned root is refreshed only if Let's Encrypt rotates (the leaf
/// rotates ~90 days but always chains to it). Run returns 0 when both legs PASS, 1 on FAIL, 2 when
/// the network is unreachable (SKIP).
///
/// Trust is real on both legs - neither uses VerifyCert := False (our loud InsecureSkipVerify).
/// </summary>
unit SynapseRealWorldExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  Classes;

type
  TSynapseRealWorldExample = class sealed(TObject)
  strict private
    const
      Host = 'postman-echo.com';
      GetUrl = 'https://postman-echo.com/get';
      PostUrl = 'https://postman-echo.com/post';
      // an echoed marker that proves the POST body round-tripped through our TLS
      Marker = 'tlslib4pascal-realworld-probe';
    /// <summary>Walks up from the executable (and cwd) to find the pinned-root PEM, so the
    /// example runs from any build/output location - no machine-specific path.</summary>
    class function FindPinnedRoot: string; static;
    class function SearchFrom(const AStart: string): string; static;
    /// <summary>The response body (a memory stream) as text; the bodies here are ASCII JSON.</summary>
    class function BodyText(const ADoc: TMemoryStream): string; static;
    /// <summary>One live GET+POST over a reused TLS connection. When AUseSystemTrust is False the
    /// chain is verified against the pinned root; when True it is verified against the OS
    /// system-trust anchors with no pinned file. Returns 0 PASS, 1 FAIL, 2 network-unreachable.</summary>
    class function RunOnce(AUseSystemTrust: Boolean; const ALabel: string): Integer; static;
  public
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  blcksock,
  httpsend,
  TlpSynapseTls;

{ TSynapseRealWorldExample }

class function TSynapseRealWorldExample.SearchFrom(const AStart: string): string;
const
  REL = 'TlsLib.Adapters' + PathDelim + 'Synapse' + PathDelim + 'Examples' +
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

class function TSynapseRealWorldExample.FindPinnedRoot: string;
begin
  Result := SearchFrom(ExtractFilePath(ParamStr(0)));
  if Result = '' then
    Result := SearchFrom(GetCurrentDir);
  if Result = '' then
    raise Exception.Create(
      'isrg-roots.pem not found (searched up from the exe and cwd)');
end;

class function TSynapseRealWorldExample.BodyText(const ADoc: TMemoryStream): string;
var
  LAnsi: AnsiString;
begin
  Result := '';
  if ADoc.Size <= 0 then
    Exit;
  SetString(LAnsi, PAnsiChar(ADoc.Memory), Integer(ADoc.Size));
  Result := string(LAnsi);
end;

class function TSynapseRealWorldExample.RunOnce(AUseSystemTrust: Boolean;
  const ALabel: string): Integer;
var
  LRoot, LGetBody, LPostBody: string;
  LHttp: THTTPSend;
  LForm: AnsiString;
begin
  Result := 1;
  LGetBody := '';
  LPostBody := '';
  // uses TlpSynapseTls has already registered our TCustomSSL plugin process-wide, so the
  // socket THTTPSend creates carries TlsLib4Pascal TLS. A pinned bundle uses Synapse's own
  // CertCAFile; the OS system store is an explicit opt-in via our per-connection UseSystemTrust
  // (system trust is never implicit) - reached by casting Sock.SSL to the plugin type.
  begin
    LHttp := THTTPSend.Create;
    try
      if AUseSystemTrust then
        // no pinned file: verify against the OS system-trust store our validator harvests
        (LHttp.Sock.SSL as TSSLTlsLib).UseSystemTrust := True
      else
      begin
        LRoot := FindPinnedRoot;
        LHttp.Sock.SSL.CertCAFile := LRoot; // pinned trust anchor
      end;
      LHttp.Sock.SSL.VerifyCert := True; // real PKIX/host verification (never a bypass)
      LHttp.Protocol := '1.1';           // HTTP/1.1 keep-alive: one TLS connection for both verbs
      LHttp.KeepAlive := True;
      LHttp.UserAgent := 'TlsLib4Pascal-Example';

      // GET - the first request runs the handshake; a failure here tells offline from TLS-broken
      if not LHttp.HTTPMethod('GET', GetUrl) then
      begin
        if LHttp.Sock.SSL.LastError <> 0 then
        begin
          // TCP reached the host but the TLS handshake/record layer failed: that IS a failure
          WriteLn('Synapse real-world FAIL [', ALabel, ']: TLS - ',
            LHttp.Sock.SSL.LastErrorDesc);
          Exit(1);
        end;
        // could not reach the host at all: skip rather than fail an offline box
        WriteLn('Synapse real-world SKIP [', ALabel, ']: network unreachable (',
          LHttp.Sock.LastErrorDesc, ')');
        Exit(2);
      end;
      LGetBody := BodyText(LHttp.Document);

      // POST an echoed marker back over the SAME kept-alive TLS connection
      LHttp.Clear; // resets the document/headers; leaves the live socket (keep-alive) intact
      LForm := AnsiString('probe=' + Marker);
      LHttp.Document.Write(PAnsiChar(LForm)^, Length(LForm));
      LHttp.MimeType := 'application/x-www-form-urlencoded';
      if not LHttp.HTTPMethod('POST', PostUrl) then
      begin
        // the GET already proved the host is reachable, so a POST failure is a real failure
        if LHttp.Sock.SSL.LastError <> 0 then
          WriteLn('Synapse real-world FAIL [', ALabel, ']: TLS - ',
            LHttp.Sock.SSL.LastErrorDesc)
        else
          WriteLn('Synapse real-world FAIL [', ALabel, ']: ',
            LHttp.Sock.LastErrorDesc);
        Exit(1);
      end;
      LPostBody := BodyText(LHttp.Document);
    finally
      LHttp.Free;
    end;
  end;

  // the GET body echoes the request URL/host; the POST body echoes our marker back
  if (Pos(Host, LGetBody) > 0) and (Pos(Marker, LPostBody) > 0) then
  begin
    WriteLn('Synapse real-world PASS [', ALabel,
      ']: live HTTPS GET + POST through TlsLib4Pascal ' +
      '(real handshake, one reused TLS connection, no OpenSSL)');
    Result := 0;
  end
  else
    WriteLn('Synapse real-world FAIL [', ALabel,
      ']: unexpected response bodies');
end;

class function TSynapseRealWorldExample.Run: Integer;
var
  LPinned, LSystem: Integer;
begin
  // leg A: pinned-root trust (the bundled ISRG PEM)
  LPinned := RunOnce({AUseSystemTrust=}False, 'pinned-root');
  if LPinned = 2 then
    Exit(2); // network unreachable - SKIP the whole demo
  // leg B: OS system-trust, no pinned file
  LSystem := RunOnce({AUseSystemTrust=}True, 'system-trust');
  if LSystem = 2 then
    Exit(2);
  if (LPinned = 0) and (LSystem = 0) then
    Result := 0
  else
    Result := 1;
end;

end.
