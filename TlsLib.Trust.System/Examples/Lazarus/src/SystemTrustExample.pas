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
/// The Free Pascal system-trust demo: a stock TFPHTTPClient GETs a live HTTPS URL with its TLS
/// carried by TlsLib4Pascal's FclNet adapter, trusting the peer against the OS system-trust store
/// (Windows crypt32 / macOS SecTrust through the OS engine, the Unix bundle through our own
/// validator) - no pinned root, no OpenSSL. It is the FPC counterpart to the Delphi FMX/Indy trust
/// demo: the trust *system* is shared, only the transport/host differs per platform.
///
/// It runs TWICE to show BOTH ways to reach OS trust through fcl-net, which auto-creates the
/// handler and exposes no trust property on TFPHTTPClient:
///   leg A - the one-line opt-in default (TlsLibFclNetTrustDefaults.UseSystemTrust): zero hooks;
///   leg B - a per-connection OnGetSocketHandler supplier (needed when trust varies per request).
///
/// This is a network-gated demo, NOT a test gate: it needs outbound HTTPS and exits 0 (both legs
/// PASS) / 2 (SKIP, offline) / 1 (FAIL). Free Pascal only. Desktop OSes need no setup. On Android a
/// GUI variant must call TlsLibAndroidInitTrust(vm) once at startup (see docs/system-trust.md) -
/// this console demo targets the desktop.
///
/// "host-roots" mode (first command-line argument) instead runs the host-roots cells: live sites
/// fetched with the host's own root passed beside the OS roots, each outcome compared with what
/// that root should and should not change, in every trust mode this platform has.
/// </summary>
unit SystemTrustExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  TlpITlsConfig,
  TlpOSSystemTrust;

type
  THostRoot = (hrNone, hrUnrelated, hrBadSsl);

  THostRootCell = record
    Title: string;
    Host: string;
    Url: string;
    HostRoot: THostRoot;
    ExpectConnect: Boolean;
  end;

  TSystemTrustExample = class sealed(TObject)
  strict private
    const
      Host = 'postman-echo.com';
      GetUrl = 'https://postman-echo.com/get';
    class function HostReachable(const AHost: string; APort: Word): Boolean; static;
    /// <summary>One live GET verified against OS trust. AUseOptIn True takes the zero-hook global
    /// default; False takes the per-connection OnGetSocketHandler supplier. 0 PASS, 1 FAIL, 2 SKIP.</summary>
    class function RunOnce(AUseOptIn: Boolean; const ALabel: string): Integer; static;
    class function RootPem(ARoot: THostRoot): string; static;
    class function HostRootConfig(AMode: TSystemTrustMode; ARoot: THostRoot)
      : ITlsClientConfig; static;
    class function HostRootModes: TArray<TSystemTrustMode>; static;
    class function ModeName(AMode: TSystemTrustMode): string; static;
    /// <summary>One cell in one mode: the GET with the cell's host root, then PASS or FAIL against
    /// what the cell expects. 0 PASS, 1 FAIL, 2 SKIP (network unreachable).</summary>
    class function RunHostRootCell(AMode: TSystemTrustMode;
      const ACell: THostRootCell): Integer; static;
  public
    /// <summary>Runs both legs; 0 PASS, 1 FAIL, 2 network-unreachable (SKIP).</summary>
    class function Run: Integer; static;
    /// <summary>Runs the host-roots cells in every mode; 0 all PASS, 1 any FAIL, 2 nothing ran
    /// (network unreachable).</summary>
    class function RunHostRoots: Integer; static;
  end;

implementation

uses
  SysUtils,
  ssockets,
  fphttpclient,
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTlsPresets,
  TlpSystemTrustFacade,
  TlsLibFclNetTls;

const
  // a throwaway test root (CN=TlsLib Intermediate Test Root) that no real site chains to
  UnrelatedRootPem =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIBgzCCASmgAwIBAgIBATAKBggqhkjOPQQDAjAoMSYwJAYDVQQDDB1UbHNMaWIg'#10 +
    'SW50ZXJtZWRpYXRlIFRlc3QgUm9vdDAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MTIz'#10 +
    'MTAwMDAwMFowKDEmMCQGA1UEAwwdVGxzTGliIEludGVybWVkaWF0ZSBUZXN0IFJv'#10 +
    'b3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT524ewl+pvqXr8HEKlzJrrhzw0'#10 +
    'f5W8TGaoqlKoBaYy77oQVqXxono9DEqgsMUVCqSo1pfY6VtQC9kkmcn/XjTro0Iw'#10 +
    'QDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUA1Q+'#10 +
    '+FjTK2FSOrlX4V9kbUWZqPYwCgYIKoZIzj0EAwIDSAAwRQIgPBxmXs7Q0ra5W7Fe'#10 +
    't/rg5tQ35IXWfNJltyoxDPp7HLkCIQD/vilLHCiFmr+DI+7Szxj4rc8D+ZM4XJC6'#10 +
    '/gIoLLhzUg=='#10 +
    '-----END CERTIFICATE-----'#10;
  // the root untrusted-root.badssl.com presents (sha256 43194b56f17cd0b72be548b35ae93adb1664e4023d1d7d0957f5bab66a31fe3d);
  // no OS store trusts it, so it is the host's own root for that site
  BadSslRootPem =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIGfjCCBGagAwIBAgIJAJeg/PrX5Sj9MA0GCSqGSIb3DQEBCwUAMIGBMQswCQYD'#10 +
    'VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j'#10 +
    'aXNjbzEPMA0GA1UECgwGQmFkU1NMMTQwMgYDVQQDDCtCYWRTU0wgVW50cnVzdGVk'#10 +
    'IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE2MDcwNzA2MzEzNVoXDTM2'#10 +
    'MDcwMjA2MzEzNVowgYExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh'#10 +
    'MRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZCYWRTU0wxNDAyBgNV'#10 +
    'BAMMK0JhZFNTTCBVbnRydXN0ZWQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkw'#10 +
    'ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDKQtPMhEH073gis/HISWAi'#10 +
    'bOEpCtOsatA3JmeVbaWal8O/5ZO5GAn9dFVsGn0CXAHR6eUKYDAFJLa/3AhjBvWa'#10 +
    'tnQLoXaYlCvBjodjLEaFi8ckcJHrAYG9qZqioRQ16Yr8wUTkbgZf+er/Z55zi1yn'#10 +
    'CnhWth7kekvrwVDGP1rApeLqbhYCSLeZf5W/zsjLlvJni9OrU7U3a9msvz8mcCOX'#10 +
    'fJX9e3VbkD/uonIbK2SvmAGMaOj/1k0dASkZtMws0Bk7m1pTQL+qXDM/h3BQZJa5'#10 +
    'DwTcATaa/Qnk6YHbj/MaS5nzCSmR0Xmvs/3CulQYiZJ3kypns1KdqlGuwkfiCCgD'#10 +
    'yWJy7NE9qdj6xxLdqzne2DCyuPrjFPS0mmYimpykgbPnirEPBF1LW3GJc9yfhVXE'#10 +
    'Cc8OY8lWzxazDNNbeSRDpAGbBeGSQXGjAbliFJxwLyGzZ+cG+G8lc+zSvWjQu4Xp'#10 +
    'GJ+dOREhQhl+9U8oyPX34gfKo63muSgo539hGylqgQyzj+SX8OgK1FXXb2LS1gxt'#10 +
    'VIR5Qc4MmiEG2LKwPwfU8Yi+t5TYjGh8gaFv6NnksoX4hU42gP5KvjYggDpR+NSN'#10 +
    'CGQSWHfZASAYDpxjrOo+rk4xnO+sbuuMk7gORsrl+jgRT8F2VqoR9Z3CEdQxcCjR'#10 +
    '5FsfTymZCk3GfIbWKkaeLQIDAQABo4H2MIHzMB0GA1UdDgQWBBRvx4NzSbWnY/91'#10 +
    '3m1u/u37l6MsADCBtgYDVR0jBIGuMIGrgBRvx4NzSbWnY/913m1u/u37l6MsAKGB'#10 +
    'h6SBhDCBgTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNV'#10 +
    'BAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBkJhZFNTTDE0MDIGA1UEAwwrQmFk'#10 +
    'U1NMIFVudHJ1c3RlZCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eYIJAJeg/PrX'#10 +
    '5Sj9MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IC'#10 +
    'AQBQU9U8+jTRT6H9AIFm6y50tXTg/ySxRNmeP1Ey9Zf4jUE6yr3Q8xBv9gTFLiY1'#10 +
    'qW2qfkDSmXVdBkl/OU3+xb5QOG5hW7wVolWQyKREV5EvUZXZxoH7LVEMdkCsRJDK'#10 +
    'wYEKnEErFls5WPXY3bOglBOQqAIiuLQ0f77a2HXULDdQTn5SueW/vrA4RJEKuWxU'#10 +
    'iD9XPnVZ9tPtky2Du7wcL9qhgTddpS/NgAuLO4PXh2TQ0EMCll5reZ5AEr0NSLDF'#10 +
    'c/koDv/EZqB7VYhcPzr1bhQgbv1dl9NZU0dWKIMkRE/T7vZ97I3aPZqIapC2ulrf'#10 +
    'KrlqjXidwrGFg8xbiGYQHPx3tHPZxoM5WG2voI6G3s1/iD+B4V6lUEvivd3f6tq7'#10 +
    'd1V/3q1sL5DNv7TvaKGsq8g5un0TAkqaewJQ5fXLigF/yYu5a24/GUD783MdAPFv'#10 +
    'gWz8F81evOyRfpf9CAqIswMF+T6Dwv3aw5L9hSniMrblkg+ai0K22JfoBcGOzMtB'#10 +
    'Ke/Ps2Za56dTRoY/a4r62hrcGxufXd0mTdPaJLw3sJeHYjLxVAYWQq4QKJQWDgTS'#10 +
    'dAEWyN2WXaBFPx5c8KIW95Eu8ShWE00VVC3oA4emoZ2nrzBXLrUScifY6VaYYkkR'#10 +
    '2O2tSqU8Ri3XRdgpNPDWp8ZL49KhYGYo3R/k98gnMHiY5g=='#10 +
    '-----END CERTIFICATE-----'#10;

  HostRootCells: array[0..5] of THostRootCell = (
    (Title: 'public site, unrelated host root'; Host: 'postman-echo.com';
      Url: 'https://postman-echo.com/get'; HostRoot: hrUnrelated; ExpectConnect: True),
    (Title: 'untrusted-root.badssl.com, its root as host root';
      Host: 'untrusted-root.badssl.com'; Url: 'https://untrusted-root.badssl.com/';
      HostRoot: hrBadSsl; ExpectConnect: True),
    (Title: 'untrusted-root.badssl.com, no host root';
      Host: 'untrusted-root.badssl.com'; Url: 'https://untrusted-root.badssl.com/';
      HostRoot: hrNone; ExpectConnect: False),
    (Title: 'expired.badssl.com, host root present (expiry is final)';
      Host: 'expired.badssl.com'; Url: 'https://expired.badssl.com/';
      HostRoot: hrBadSsl; ExpectConnect: False),
    (Title: 'wrong.host.badssl.com, host root present (name is final)';
      Host: 'wrong.host.badssl.com'; Url: 'https://wrong.host.badssl.com/';
      HostRoot: hrBadSsl; ExpectConnect: False),
    (Title: 'self-signed.badssl.com, unrelated host root';
      Host: 'self-signed.badssl.com'; Url: 'https://self-signed.badssl.com/';
      HostRoot: hrUnrelated; ExpectConnect: False));

type
  /// <summary>Supplies a per-connection FclNet handler configured for OS system trust. This is the
  /// general path - use it whenever trust must vary per request (a pinned CA here, the OS store
  /// there); the event is 'of object', so it lives on an instance. For a process-wide "always trust
  /// the OS" default, prefer the one-line TlsLibFclNetTrustDefaults opt-in instead (leg A). A
  /// non-nil AConfig replaces the slot-driven build with that fully built client config.</summary>
  TSystemTrustSupplier = class sealed(TObject)
  strict private
    FConfig: ITlsClientConfig;
  public
    constructor Create(const AConfig: ITlsClientConfig);
    procedure OnGetHandler(Sender: TObject; const AUseSSL: Boolean;
      out AHandler: TSocketHandler);
  end;

{ TSystemTrustSupplier }

constructor TSystemTrustSupplier.Create(const AConfig: ITlsClientConfig);
begin
  inherited Create;
  FConfig := AConfig;
end;

procedure TSystemTrustSupplier.OnGetHandler(Sender: TObject;
  const AUseSSL: Boolean; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  AHandler := nil;
  if not AUseSSL then
    Exit; // a plain http:// request keeps the default plaintext handler
  LHandler := TTlsLibSocketHandler.Create;
  if FConfig <> nil then
    LHandler.ClientConfig := FConfig
  else
    LHandler.UseSystemTrust := True; // verify against the OS store
  AHandler := LHandler;              // VerifyPeerCert defaults True (real verification, never a bypass)
end;

{ TSystemTrustExample }

class function TSystemTrustExample.HostReachable(const AHost: string;
  APort: Word): Boolean;
var
  LSock: TInetSocket;
begin
  Result := False;
  try
    LSock := TInetSocket.Create(AHost, APort, 5000, nil); // plaintext TCP reachability probe
    try
      Result := True;
    finally
      LSock.Free;
    end;
  except
    Result := False;
  end;
end;

class function TSystemTrustExample.RunOnce(AUseOptIn: Boolean;
  const ALabel: string): Integer;
var
  LClient: TFPHTTPClient;
  LSupplier: TSystemTrustSupplier;
  LBody: string;
begin
  Result := 1;
  LBody := '';
  LSupplier := nil;
  // leg A: flip the process-wide opt-in so the auto-created handler trusts the OS store - no hook.
  // leg B: leave the opt-in off and configure trust per connection through OnGetSocketHandler.
  if AUseOptIn then
    TlsLibFclNetTrustDefaults.UseSystemTrust := True
  else
    LSupplier := TSystemTrustSupplier.Create(nil);
  try
    LClient := TFPHTTPClient.Create(nil);
    try
      LClient.ConnectTimeout := 8000;
      LClient.IOTimeout := 15000;
      LClient.AddHeader('User-Agent', 'TlsLib4Pascal-Example');
      if not AUseOptIn then
        LClient.OnGetSocketHandler := LSupplier.OnGetHandler;
      try
        LBody := string(LClient.Get(GetUrl));
      except
        on E: Exception do
        begin
          if not HostReachable(Host, 443) then
          begin
            WriteLn('System-trust demo SKIP [', ALabel, ']: network unreachable');
            Exit(2);
          end;
          WriteLn('System-trust demo FAIL [', ALabel, ']: TLS - ', E.Message);
          Exit(1);
        end;
      end;
    finally
      LClient.Free;
    end;
  finally
    if AUseOptIn then
      // reset the global so leg B is a genuine per-connection demonstration, not the leftover default
      TlsLibFclNetTrustDefaults.UseSystemTrust := False
    else
      LSupplier.Free;
  end;

  if Pos(Host, LBody) > 0 then
  begin
    WriteLn('System-trust demo PASS [', ALabel,
      ']: live HTTPS GET verified against the OS system-trust store ' +
      '(harvested + validated by TlsLib4Pascal, no OpenSSL)');
    Result := 0;
  end
  else
    WriteLn('System-trust demo FAIL [', ALabel, ']: unexpected response body');
end;

class function TSystemTrustExample.RootPem(ARoot: THostRoot): string;
begin
  case ARoot of
    hrUnrelated:
      Result := UnrelatedRootPem;
    hrBadSsl:
      Result := BadSslRootPem;
  else
    Result := '';
  end;
end;

class function TSystemTrustExample.HostRootConfig(AMode: TSystemTrustMode;
  ARoot: THostRoot): ITlsClientConfig;
var
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LHostRoots: ITrustAnchorStore;
  LPem: string;
begin
  LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  LPkix := TDefaultPkixProvider.Create as IPkixProvider;
  LHostRoots := nil;
  LPem := RootPem(ARoot);
  if LPem <> '' then
    LHostRoots := TTrustAnchorStore.Create(
      LPkix.Certificates.LoadChain(TBytes(BytesOf(LPem)))) as ITrustAnchorStore;
  Result := TTlsPresets.Compatible(LCrypto, LPkix).Client
    .WithServerVerification(TSystemTrust.ServerVerification(LPkix, AMode, LHostRoots).Build)
    .Build;
end;

class function TSystemTrustExample.HostRootModes: TArray<TSystemTrustMode>;
begin
  // Anchors is a second engine only where Default is the OS one; elsewhere they are the same
  if TOSSystemTrust.Supports(TSystemTrustMode.Anchors) and
    TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
    Result := TArray<TSystemTrustMode>.Create(TSystemTrustMode.Default, TSystemTrustMode.Anchors)
  else
    Result := TArray<TSystemTrustMode>.Create(TSystemTrustMode.Default);
end;

class function TSystemTrustExample.ModeName(AMode: TSystemTrustMode): string;
begin
  if AMode = TSystemTrustMode.Anchors then
    Exit('Anchors (own validator over the harvested OS roots)');
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
    Result := 'Default = Delegate (OS engine)'
  else
    Result := 'Default = Anchors (own validator over the harvested OS roots)';
end;

class function TSystemTrustExample.RunHostRootCell(AMode: TSystemTrustMode;
  const ACell: THostRootCell): Integer;
var
  LClient: TFPHTTPClient;
  LSupplier: TSystemTrustSupplier;
  LConnected: Boolean;
  LDetail, LTag: string;
begin
  LConnected := True;
  LDetail := 'connected';
  LSupplier := TSystemTrustSupplier.Create(HostRootConfig(AMode, ACell.HostRoot));
  try
    LClient := TFPHTTPClient.Create(nil);
    try
      LClient.ConnectTimeout := 8000;
      LClient.IOTimeout := 15000;
      LClient.AddHeader('User-Agent', 'TlsLib4Pascal-Example');
      LClient.OnGetSocketHandler := LSupplier.OnGetHandler;
      try
        LClient.Get(ACell.Url);
      except
        on E: EHTTPClient do
          LDetail := 'connected, HTTP status ' + IntToStr(E.StatusCode);
        on E: Exception do
        begin
          if not HostReachable(ACell.Host, 443) then
          begin
            WriteLn('  SKIP: ', ACell.Title, ': network unreachable');
            Exit(2);
          end;
          LConnected := False;
          LDetail := 'refused (' + E.Message + ')';
        end;
      end;
    finally
      LClient.Free;
    end;
  finally
    LSupplier.Free;
  end;
  if LConnected = ACell.ExpectConnect then
  begin
    LTag := 'PASS';
    Result := 0;
  end
  else
  begin
    LTag := 'FAIL';
    Result := 1;
  end;
  WriteLn('  ', LTag, ': ', ACell.Title, ': expected ',
    BoolToStr(ACell.ExpectConnect, 'connect', 'refuse'), ', ', LDetail);
end;

class function TSystemTrustExample.RunHostRoots: Integer;
var
  LModes: TArray<TSystemTrustMode>;
  LMode, LCell, LCellResult: Integer;
  LAnyFail, LAnyRan: Boolean;
begin
  LModes := HostRootModes;
  LAnyFail := False;
  LAnyRan := False;
  for LMode := 0 to High(LModes) do
  begin
    WriteLn('Host roots, mode ', ModeName(LModes[LMode]), ':');
    for LCell := 0 to High(HostRootCells) do
    begin
      LCellResult := RunHostRootCell(LModes[LMode], HostRootCells[LCell]);
      LAnyFail := LAnyFail or (LCellResult = 1);
      LAnyRan := LAnyRan or (LCellResult <> 2);
    end;
  end;
  if LAnyFail then
    Result := 1
  else if LAnyRan then
    Result := 0
  else
    Result := 2;
end;

class function TSystemTrustExample.Run: Integer;
var
  LOptIn, LSupplier: Integer;
begin
  // leg A: the zero-ceremony opt-in default (recommended for "just trust the OS")
  LOptIn := RunOnce(True, 'opt-in default');
  if LOptIn = 2 then
    Exit(2); // network unreachable - SKIP the whole demo
  // leg B: the per-connection OnGetSocketHandler supplier (general path)
  LSupplier := RunOnce(False, 'per-connection hook');
  if LSupplier = 2 then
    Exit(2);
  if (LOptIn = 0) and (LSupplier = 0) then
    Result := 0
  else
    Result := 1;
end;

end.
