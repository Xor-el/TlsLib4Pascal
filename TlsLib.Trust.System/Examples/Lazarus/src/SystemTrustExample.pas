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
/// (Windows crypt32 / macOS SecTrust / Unix bundle) that TlsLib4Pascal harvests and validates
/// itself - no pinned root, no OpenSSL. It is the FPC counterpart to the Delphi FMX/Indy trust
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
/// </summary>
unit SystemTrustExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TSystemTrustExample = class sealed(TObject)
  strict private
    const
      Host = 'postman-echo.com';
      GetUrl = 'https://postman-echo.com/get';
    class function HostReachable(const AHost: string; APort: Word): Boolean; static;
    /// <summary>One live GET verified against OS trust. AUseOptIn True takes the zero-hook global
    /// default; False takes the per-connection OnGetSocketHandler supplier. 0 PASS, 1 FAIL, 2 SKIP.</summary>
    class function RunOnce(AUseOptIn: Boolean; const ALabel: string): Integer; static;
  public
    /// <summary>Runs both legs; 0 PASS, 1 FAIL, 2 network-unreachable (SKIP).</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  ssockets,
  fphttpclient,
  TlpFclNetTls;

type
  /// <summary>Supplies a per-connection FclNet handler configured for OS system trust. This is the
  /// general path - use it whenever trust must vary per request (a pinned CA here, the OS store
  /// there); the event is 'of object', so it lives on an instance. For a process-wide "always trust
  /// the OS" default, prefer the one-line TlsLibFclNetTrustDefaults opt-in instead (leg A).</summary>
  TSystemTrustSupplier = class sealed(TObject)
  public
    procedure OnGetHandler(Sender: TObject; const AUseSSL: Boolean;
      out AHandler: TSocketHandler);
  end;

{ TSystemTrustSupplier }

procedure TSystemTrustSupplier.OnGetHandler(Sender: TObject;
  const AUseSSL: Boolean; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  AHandler := nil;
  if not AUseSSL then
    Exit; // a plain http:// request keeps the default plaintext handler
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.UseSystemTrust := True; // verify against the OS store our validator harvests
  AHandler := LHandler;            // VerifyPeerCert defaults True (real verification, never a bypass)
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
    LSupplier := TSystemTrustSupplier.Create;
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

class function TSystemTrustExample.Run: Integer;
var
  LOptIn, LSupplier: Integer;
begin
  // leg A: the zero-ceremony opt-in default (recommended for "just trust the OS")
  LOptIn := RunOnce({AUseOptIn=}True, 'opt-in default');
  if LOptIn = 2 then
    Exit(2); // network unreachable - SKIP the whole demo
  // leg B: the per-connection OnGetSocketHandler supplier (general path)
  LSupplier := RunOnce({AUseOptIn=}False, 'per-connection hook');
  if LSupplier = 2 then
    Exit(2);
  if (LOptIn = 0) and (LSupplier = 0) then
    Result := 0
  else
    Result := 1;
end;

end.
