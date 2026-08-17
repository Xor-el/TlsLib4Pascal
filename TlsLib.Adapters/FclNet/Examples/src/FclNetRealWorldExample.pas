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
/// A real-world proof: a single unmodified Free Pascal TFPHTTPClient drives a live HTTPS GET and
/// POST to a public test API (postman-echo.com) with its TLS handled entirely by TlsLib4Pascal -
/// a real handshake against a real internet server and real HTTP/1.1 framing over our records,
/// with zero OpenSSL. KeepConnection reuses one TLS connection for both verbs. It runs TWICE
/// against the same host, exercising BOTH ways fcl-net threads config into the auto-created
/// handler: leg A verifies against a pinned root supplied via AfterSocketHandlerCreate (configure
/// the created handler), leg B verifies against the OS system-trust store via OnGetSocketHandler
/// (supply a pre-configured handler). This is a network-gated demo, NOT part of any test gate: it
/// needs outbound HTTPS and exits 0 (both legs PASS) / 2 (SKIP, offline) / 1 (FAIL).
///
/// Trust is real on both legs - neither uses InsecureSkipVerify.
/// </summary>
unit FclNetRealWorldExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TFclNetRealWorldExample = class sealed(TObject)
  strict private
    const
      Host = 'postman-echo.com';
      GetUrl = 'https://postman-echo.com/get';
      PostUrl = 'https://postman-echo.com/post';
      // an echoed marker that proves the POST body round-tripped through our TLS
      Marker = 'tlslib4pascal-realworld-probe';
    class function FindPinnedRoot: string; static;
    class function SearchFrom(const AStart: string): string; static;
    /// <summary>A plaintext TCP probe to tell an offline box (SKIP) from a reachable host whose
    /// TLS failed (a real FAIL).</summary>
    class function HostReachable(const AHost: string; APort: Word): Boolean; static;
    /// <summary>One live GET+POST over a reused TLS connection. When AUseSystemTrust is False the
    /// chain is verified against the pinned root; when True against the OS system-trust anchors
    /// with no pinned file. Returns 0 PASS, 1 FAIL, 2 network-unreachable.</summary>
    class function RunOnce(AUseSystemTrust: Boolean; const ALabel: string): Integer; static;
  public
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  ssockets,
  fphttpclient,
  TlpFclNetTls;

type
  /// <summary>TFPHTTPClient re-publishes OnGetSocketHandler but leaves AfterSocketHandlerCreate
  /// protected; a one-line descendant surfaces it so the demo can exercise BOTH config hooks.</summary>
  TDemoHttpClient = class(TFPHTTPClient)
  published
    property AfterSocketHandlerCreate;
  end;

  /// <summary>Hosts the fcl-net socket-handler event methods (they must be 'of object'). Each leg
  /// wires exactly one hook, so the demo shows both threading points fcl-net offers.</summary>
  TTrustConfigurator = class sealed(TObject)
  strict private
  var
    FPinnedRoot: string;
  public
    constructor Create(const APinnedRoot: string);
    /// <summary>OnGetSocketHandler: supply a pre-configured handler (used for the system-trust leg).</summary>
    procedure SupplySystemTrust(Sender: TObject; const AUseSSL: Boolean;
      out AHandler: TSocketHandler);
    /// <summary>AfterSocketHandlerCreate: configure the auto-created handler (used for the pinned leg).</summary>
    procedure ConfigurePinnedRoot(Sender: TObject; AHandler: TSocketHandler);
  end;

{ TTrustConfigurator }

constructor TTrustConfigurator.Create(const APinnedRoot: string);
begin
  inherited Create;
  FPinnedRoot := APinnedRoot;
end;

procedure TTrustConfigurator.SupplySystemTrust(Sender: TObject;
  const AUseSSL: Boolean; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  AHandler := nil;
  if not AUseSSL then
    Exit; // a plain http:// leg (none here) falls back to the default plaintext handler
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.UseSystemTrust := True; // verify against the OS store our validator harvests
  AHandler := LHandler;            // VerifyPeerCert defaults True (real verification, never a bypass)
end;

procedure TTrustConfigurator.ConfigurePinnedRoot(Sender: TObject;
  AHandler: TSocketHandler);
begin
  // the handler fcl-net auto-created for us: pin it to the bundled root via the native CertCA slot
  // (VerifyPeerCert defaults True, so this really verifies)
  if AHandler is TTlsLibSocketHandler then
    TTlsLibSocketHandler(AHandler).CertificateData.CertCA.FileName := FPinnedRoot;
end;

{ TFclNetRealWorldExample }

class function TFclNetRealWorldExample.SearchFrom(const AStart: string): string;
const
  REL = 'TlsLib.Adapters' + PathDelim + 'FclNet' + PathDelim + 'Examples' +
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

class function TFclNetRealWorldExample.FindPinnedRoot: string;
begin
  Result := SearchFrom(ExtractFilePath(ParamStr(0)));
  if Result = '' then
    Result := SearchFrom(GetCurrentDir);
  if Result = '' then
    raise Exception.Create('isrg-roots.pem not found (searched up from the exe and cwd)');
end;

class function TFclNetRealWorldExample.HostReachable(const AHost: string;
  APort: Word): Boolean;
var
  LSock: TInetSocket;
begin
  Result := False;
  try
    // a Nil handler means a plaintext auto-connecting socket: it just proves TCP reachability
    LSock := TInetSocket.Create(AHost, APort, 5000, nil);
    try
      Result := True;
    finally
      LSock.Free;
    end;
  except
    Result := False;
  end;
end;

class function TFclNetRealWorldExample.RunOnce(AUseSystemTrust: Boolean;
  const ALabel: string): Integer;
var
  LClient: TDemoHttpClient;
  LConfig: TTrustConfigurator;
  LGetBody, LPostBody: string;
begin
  Result := 1;
  LGetBody := '';
  LPostBody := '';
  // uses TlpFclNetTls has registered our TSSLSocketHandler class, so the socket TFPHTTPClient
  // creates for an https:// URL carries TlsLib4Pascal TLS. We feed trust through the two fcl-net
  // hooks: OnGetSocketHandler (supply a ready handler) for system trust, AfterSocketHandlerCreate
  // (tweak the created one) for the pinned root.
  LConfig := TTrustConfigurator.Create(FindPinnedRoot);
  try
    LClient := TDemoHttpClient.Create(nil);
    try
      LClient.KeepConnection := True; // one TLS connection for both verbs
      LClient.ConnectTimeout := 8000;
      LClient.IOTimeout := 15000;
      LClient.AddHeader('User-Agent', 'TlsLib4Pascal-Example');
      if AUseSystemTrust then
        LClient.OnGetSocketHandler := LConfig.SupplySystemTrust
      else
        LClient.AfterSocketHandlerCreate := LConfig.ConfigurePinnedRoot;
      try
        LGetBody := string(LClient.Get(GetUrl)); // the first request runs the handshake
        LPostBody := string(LClient.FormPost(PostUrl, RawByteString('probe=' + Marker)));
      except
        on E: Exception do
        begin
          // reachable host + failed TLS is a real failure; unreachable host is an offline SKIP
          if not HostReachable(Host, 443) then
          begin
            WriteLn('FclNet real-world SKIP [', ALabel, ']: network unreachable');
            Exit(2);
          end;
          WriteLn('FclNet real-world FAIL [', ALabel, ']: TLS - ', E.Message);
          Exit(1);
        end;
      end;
    finally
      LClient.Free;
    end;
  finally
    LConfig.Free;
  end;

  // the GET body echoes the request URL/host; the POST body echoes our marker back
  if (Pos(Host, LGetBody) > 0) and (Pos(Marker, LPostBody) > 0) then
  begin
    WriteLn('FclNet real-world PASS [', ALabel,
      ']: live HTTPS GET + POST through TlsLib4Pascal ' +
      '(real handshake, one reused TLS connection, no OpenSSL)');
    Result := 0;
  end
  else
    WriteLn('FclNet real-world FAIL [', ALabel, ']: unexpected response bodies');
end;

class function TFclNetRealWorldExample.Run: Integer;
var
  LPinned, LSystem: Integer;
begin
  // leg A: pinned-root trust (the bundled ISRG PEM), via AfterSocketHandlerCreate
  LPinned := RunOnce({AUseSystemTrust=}False, 'pinned-root');
  if LPinned = 2 then
    Exit(2); // network unreachable - SKIP the whole demo
  // leg B: OS system-trust, no pinned file, via OnGetSocketHandler
  LSystem := RunOnce({AUseSystemTrust=}True, 'system-trust');
  if LSystem = 2 then
    Exit(2);
  if (LPinned = 0) and (LSystem = 0) then
    Result := 0
  else
    Result := 1;
end;

end.
