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
/// A real-world proof: a single unmodified mORMot THttpClientSocket drives a live HTTPS GET and
/// POST to a public test API (postman-echo.com) with its TLS handled entirely by TlsLib4Pascal -
/// a real handshake against a real internet server and real HTTP/1.1 framing over our records,
/// with zero OpenSSL. It runs TWICE against the same host: leg A verifies against a pinned root
/// (CACertificatesFile), leg B verifies against the OS system-trust store harvested and validated
/// entirely by TlsLib4Pascal (CASystemStores, no pinned file) - proving a caller can drop the
/// bundled PEM and lean on the platform anchors instead. With a keep-alive request both verbs run
/// over ONE reused TLS connection - the strongest proof that our records carry ordinary
/// application traffic. This is a network-gated demo, NOT part of any test gate: it needs outbound
/// HTTPS; the pinned root is refreshed only if Let's Encrypt rotates (the leaf rotates ~90 days
/// but always chains to it). Run returns 0 when both legs PASS, 1 on FAIL, 2 when the network is
/// unreachable (SKIP).
///
/// Trust is real on both legs - neither sets IgnoreCertificateErrors (our loud InsecureSkipVerify).
/// </summary>
unit MormotRealWorldExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TMormotRealWorldExample = class sealed(TObject)
  strict private
    const
      Host = 'postman-echo.com';
      Port = '443';
      GetPath = '/get';
      PostPath = '/post';
      // an echoed marker that proves the POST body round-tripped through our TLS
      Marker = 'tlslib4pascal-realworld-probe';
      TimeoutMs = 15000;
      KeepAliveMs = 5000;
    /// <summary>Walks up from the executable (and cwd) to find the pinned-root PEM, so the
    /// example runs from any build/output location - no machine-specific path.</summary>
    class function FindPinnedRoot: string; static;
    class function SearchFrom(const AStart: string): string; static;
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
  mormot.core.base,
  mormot.core.unicode,
  mormot.core.os.security,
  mormot.net.sock,
  mormot.net.client,
  TlpMormotTls;

{ TMormotRealWorldExample }

class function TMormotRealWorldExample.SearchFrom(const AStart: string): string;
const
  REL = 'TlsLib.Adapters' + PathDelim + 'mORMot' + PathDelim + 'Examples' +
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

class function TMormotRealWorldExample.FindPinnedRoot: string;
begin
  Result := SearchFrom(ExtractFilePath(ParamStr(0)));
  if Result = '' then
    Result := SearchFrom(GetCurrentDir);
  if Result = '' then
    raise Exception.Create(
      'isrg-roots.pem not found (searched up from the exe and cwd)');
end;

class function TMormotRealWorldExample.RunOnce(AUseSystemTrust: Boolean;
  const ALabel: string): Integer;
var
  LRoot, LGetBody, LPostBody: string;
  LClient: THttpClientSocket;
  LGetStatus, LPostStatus: Integer;
begin
  Result := 1;
  LGetBody := '';
  LPostBody := '';
  try
    LClient := THttpClientSocket.Create(TimeoutMs);
    try
      if AUseSystemTrust then
        // no pinned file: verify against the OS system-trust store our validator harvests
        LClient.TLS.CASystemStores := [scsRoot]
      else
      begin
        LRoot := FindPinnedRoot;
        LClient.TLS.CACertificatesFile := StringToUtf8(LRoot); // pinned trust anchor
      end;
      // real verification: IgnoreCertificateErrors stays False (never our InsecureSkipVerify)
      // the handshake runs here and verifies the chain for Host (used for SNI too)
      LClient.OpenBind(Host, Port, {dobind=}False, {tls=}True);
      // both verbs over ONE kept-alive TLS connection
      LGetStatus := LClient.Get(GetPath, KeepAliveMs);
      LGetBody := Utf8ToString(LClient.Content);
      LPostStatus := LClient.Post(PostPath, 'probe=' + Marker,
        'application/x-www-form-urlencoded', KeepAliveMs);
      LPostBody := Utf8ToString(LClient.Content);
    finally
      LClient.Free;
    end;
  except
    on E: ENetSock do
    begin
      // mORMot's DoTlsAfter wraps a TLS handshake/record failure into ENetSock with a
      // 'TLS failed' message; a plain connect failure just means the host is unreachable
      if Pos('TLS', E.Message) > 0 then
      begin
        WriteLn('mORMot real-world FAIL [', ALabel, ']: ', E.Message);
        Exit(1);
      end;
      WriteLn('mORMot real-world SKIP [', ALabel, ']: network unreachable (',
        E.Message, ')');
      Exit(2);
    end;
    on E: Exception do
    begin
      WriteLn('mORMot real-world FAIL [', ALabel, ']: ', E.ClassName, ': ',
        E.Message);
      Exit(1);
    end;
  end;

  // the GET body echoes the request URL/host; the POST body echoes our marker back
  if (Pos(Host, LGetBody) > 0) and (Pos(Marker, LPostBody) > 0) then
  begin
    WriteLn('mORMot real-world PASS [', ALabel,
      ']: live HTTPS GET + POST through TlsLib4Pascal ' +
      '(real handshake, one reused TLS connection, no OpenSSL)');
    Result := 0;
  end
  else
    WriteLn('mORMot real-world FAIL [', ALabel,
      ']: unexpected response bodies (GET ', LGetStatus, ', POST ',
      LPostStatus, ')');
end;

class function TMormotRealWorldExample.Run: Integer;
var
  LPinned, LSystem: Integer;
begin
  // point mORMot's NewNetTls factory at our INetTls, so the client socket carries our TLS
  RegisterTlsLib4PascalTls;
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
