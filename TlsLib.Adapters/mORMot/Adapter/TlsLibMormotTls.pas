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
/// The mORMot integration adapter: drives TlsLib4Pascal's managed TLS engine behind
/// mORMot's own INetTls "swap-your-SSL" seam. An existing mORMot app gets our managed
/// TLS by pointing the global NewNetTls factory at NewTlsLib4PascalTls - no fork, no
/// recompile of mORMot. This unit is the only place our types and mORMot's types meet:
/// it maps mORMot's TNetTlsContext (plus the process-wide setters) onto the host-neutral
/// adapter core (config composition, timed transport, session drive) and supplies the
/// mORMot socket glue.
/// </summary>
unit TlsLibMormotTls;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  mormot.net.sock,
  mormot.core.os.security,
  mormot.core.base,
  mormot.core.unicode,
  TlpTlsAlert,
  TlpEchConfig,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfigMemo,
  TlpTlsConfigMemo,
  TlpTlsLibExceptions,
  TlpTlsAdapterCore,
  TlpSystemTrustFacade;

/// <summary>Sets a process-wide augment-only verify callback the adapter threads into every
/// client handshake (it runs after the built-in pipeline and can only additionally reject).
/// mORMot builds an INetTls per connection through a global factory, so the adapter's neutral
/// hooks are configured with these unit-level setters. nil clears it.</summary>
procedure SetTlsLibMormotVerifyCallback(const ACallback: TTlsCertificateVerifyCallback);
/// <summary>Sets a process-wide out-of-band verdict resolver for the CLIENT role (e.g. live
/// OCSP/CRL over the SERVER's chain): when set, every client handshake parks after the pipeline
/// accepts the server chain and this decides it. Pair it with a client-config resolver
/// (TOSSystemTrust.LiveRevocationResolver over a client config binds server-auth EKU). For an mTLS
/// server that must vet the CLIENT chain, use SetTlsLibMormotServerVerdictResolver instead - the
/// two roles evaluate different EKUs, so one resolver cannot serve both. ADeadlineMs is the
/// resolver's fetch budget. nil clears it.</summary>
procedure SetTlsLibMormotVerdictResolver(const AResolver: TCertificateVerdictResolver;
  ADeadlineMs: Cardinal);
/// <summary>Sets a process-wide out-of-band verdict resolver for the SERVER role (live revocation
/// over an mTLS CLIENT's chain): when set, every server handshake that requests client auth parks
/// after the pipeline accepts the client chain and this decides it. Pair it with a server-config
/// resolver (binds client-auth EKU). ADeadlineMs is the resolver's fetch budget. nil clears it.</summary>
procedure SetTlsLibMormotServerVerdictResolver(
  const AResolver: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
/// <summary>Sets a process-wide, fully-built client config that REPLACES the context-driven build:
/// when set, every client handshake uses it as-is, and a TNetTlsContext that also carries cert/trust
/// fields is not allowed alongside it (the adapter raises). The verdict resolver still applies, but
/// only if this config armed the deferral (WithLiveRevocationVerdict/WithAsyncCertificateVerdict) -
/// else the handshake never parks. The escape hatch to the full builder API - cipher order, groups,
/// resumption, ALPN. nil clears it.</summary>
procedure SetTlsLibMormotClientConfig(const AConfig: ITlsClientConfig);
/// <summary>Sets a process-wide, fully-built server config that REPLACES the context-driven build
/// (the server-side counterpart of SetTlsLibMormotClientConfig; same conflict rule). nil clears it.</summary>
procedure SetTlsLibMormotServerConfig(const AConfig: ITlsServerConfig);
/// <summary>Sets a process-wide crypto provider for the context-driven build (hashing, RNG, cert
/// parsing). nil (the default) uses the shared default; set it to inject a custom backend (HSM,
/// FIPS, a test mock). Not allowed alongside a process-wide config-in
/// (SetTlsLibMormot{Client,Server}Config), which carries its own provider; this only governs the
/// context-driven path.</summary>
procedure SetTlsLibMormotCrypto(const ACryptoProvider: ICryptoProvider);
/// <summary>Sets a process-wide PKIX provider for the context-driven build (certificate parsing,
/// path validation, revocation). nil (the default) uses the shared default; set it to inject a
/// custom backend. Not allowed alongside a process-wide config-in, which carries its own PKIX
/// provider; this only governs the context-driven path.</summary>
procedure SetTlsLibMormotPkix(const APkix: IPkixProvider);
/// <summary>Enables/disables TLS session resumption for the context-driven build (a server issues
/// tickets; a client caches and reuses them), so a reconnect skips the asymmetric handshake.
/// Forward-secret (TLS 1.3 psk_dhe_ke); 0-RTT is never enabled. Default True.</summary>
procedure SetTlsLibMormotSessionResumption(AEnabled: Boolean);
/// <summary>Sets the process-wide read timeout (ms) bounding every handshake, so a peer that
/// connects but sends no data cannot park the connection's thread. Deliberately NOT an app-read
/// deadline. 0 (the default) uses the 30 s library default; a positive value overrides it.</summary>
procedure SetTlsLibMormotHandshakeTimeout(AMs: Int32);
/// <summary>Clears the process-wide build-once config caches so the next handshake rebuilds from
/// current inputs. Call after rotating a certificate/key to purge the retired credential (a cached
/// config holds its private key alive). Call only with no TLS traffic in flight.</summary>
procedure FlushTlsLibMormotConfigCache;

type
  /// <summary>An ITlsTransport over a mORMot TNetSocket: raw ciphertext moves through the socket's
  /// blocking Recv/Send, and the handshake-phase read cap comes from the shared timed-transport
  /// base. nrClosed is an orderly EOF (0); nrRetry is retried.</summary>
  TMormotSocketTransport = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FSocket: TNetSocket;
  strict protected
    function WaitReadable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(ASocket: TNetSocket);
  end;

  /// <summary>
  /// TlsLib4Pascal's implementation of mORMot's INetTls. AfterConnection runs the client
  /// handshake; AfterAccept runs the server handshake; Send / Receive / ReceivePending move
  /// application data. It maps the input fields of TNetTlsContext onto the host-neutral adapter
  /// core (cert/key, trust, client-auth, and the loud IgnoreCertificateErrors escape hatch).
  /// </summary>
  TTlsLibNetTls = class sealed(TInterfacedObject, INetTls)
  strict private
  var
    FSession: TTlsAdapterSession;
    /// <summary>The host-neutral snapshot the adapter core composes into a TLS configuration for
    /// the given role: the process-wide setters overlaid with this connection's TNetTlsContext.
    /// A client always composes its peer trust from the context; a server does so only when it
    /// requests a client certificate.</summary>
    class function Snapshot(const AContext: TNetTlsContext;
      AIsClient: Boolean): TTlsAdapterOptions; static;
    class function BuildClientEngine(var AContext: TNetTlsContext;
      const AHost: string): ITlsEngine; static;
    class function BuildServerEngine(const AContext: TNetTlsContext): ITlsEngine; static;
    procedure DriveHandshake(ASocket: TNetSocket; const AEngine: ITlsEngine;
      AIsClient: Boolean; const AHost: string);
  public
    destructor Destroy; override;
    // INetTls
    procedure AfterConnection(Socket: TNetSocket; var Context: TNetTlsContext;
      const ServerAddress: RawUtf8);
    procedure AfterBind(Socket: TNetSocket; var Context: TNetTlsContext;
      const ServerAddress: RawUtf8);
    procedure AfterAccept(Socket: TNetSocket; const BoundContext: TNetTlsContext;
      LastError, CipherName: PRawUtf8);
    function GetCipherName: RawUtf8;
    function GetRawTls: pointer;
    function GetRawCert(SignHashName: PRawUtf8 = nil): RawByteString;
    function Receive(Buffer: pointer; var Length: integer): TNetResult;
    function ReceivePending: integer;
    function Send(Buffer: pointer; var Length: integer): TNetResult;
    // beyond INetTls: cast the INetTls to TTlsLibNetTls to read these post-handshake
    /// <summary>The negotiated named group (key_share curve) wire codepoint once the handshake
    /// completes (0 if none).</summary>
    function NegotiatedGroup: UInt16;
    /// <summary>The SNI server_name for this connection: the host a client requested (server side)
    /// or the host we sent (client side); empty when none.</summary>
    function PeerServerName: string;
    /// <summary>The Encrypted Client Hello outcome for this connection (RFC 9849).</summary>
    function EchStatus: TEchStatus;
    /// <summary>Whether this connection resumed an earlier session rather than doing a full
    /// handshake (RFC 8446 2.2 / RFC 5246 7.3).</summary>
    function Resumed: Boolean;
  end;

/// <summary>The factory to point mORMot's global at: `NewNetTls := @NewTlsLib4PascalTls;`.</summary>
function NewTlsLib4PascalTls: INetTls;

/// <summary>Convenience one-liner: makes TlsLib4Pascal the process-wide TLS provider for
/// every mORMot TCrtSocket created afterwards.</summary>
procedure RegisterTlsLib4PascalTls;

implementation

resourcestring
  SCARawUnsupported = 'the mORMot TLS context supplies CACertificatesRaw (in-memory OpenSSL ' +
    'X509 handles); TlsLib4Pascal is OpenSSL-free and cannot consume them - pass the CA chain ' +
    'as a PEM/DER file via CACertificatesFile, or use TSystemTrust for the OS anchors';
  SMormotReceiveFailed = 'mORMot socket receive failed (nr=%d)';
  SMormotSendFailed = 'mORMot socket send failed (nr=%d)';
  SMormotTrustSourceHint = 'CACertificatesFile or CASystemStores';

var
  // process-wide neutral hooks the per-connection adapter threads into each client handshake
  GVerifyCallback: TTlsCertificateVerifyCallback;
  // the client-role resolver evaluates the server's chain; the server-role resolver evaluates an
  // mTLS client's chain. They bind different EKUs, so the two roles keep separate hooks
  GVerdictResolver: TCertificateVerdictResolver;
  GVerdictDeadlineMs: Cardinal;
  GServerVerdictResolver: TCertificateVerdictResolver;
  GServerVerdictDeadlineMs: Cardinal;
  // process-wide fully-built configs that, when set, REPLACE the context-driven build
  GClientConfig: ITlsClientConfig;
  GServerConfig: ITlsServerConfig;
  // mORMot builds an INetTls per connection, so the build-once memos for the context-driven
  // path live process-wide
  GServerConfigMemo: ITlsServerConfigMemo;
  GClientConfigMemo: ITlsClientConfigMemo;
  // an injected provider for the context-driven build; nil uses the shared default
  GCrypto: ICryptoProvider;
  // an injected PKIX provider for the context-driven build; nil uses the shared default
  GPkix: IPkixProvider;
  // whether the context-driven build enables session resumption (default True, set in init)
  GSessionResumption: Boolean;
  // the read timeout (ms) bounding every handshake; 0 uses the library default
  GHandshakeTimeoutMs: Int32;

procedure SetTlsLibMormotVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback);
begin
  GVerifyCallback := ACallback;
end;

procedure SetTlsLibMormotVerdictResolver(const AResolver: TCertificateVerdictResolver;
  ADeadlineMs: Cardinal);
begin
  GVerdictResolver := AResolver;
  GVerdictDeadlineMs := ADeadlineMs;
end;

procedure SetTlsLibMormotServerVerdictResolver(
  const AResolver: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
begin
  GServerVerdictResolver := AResolver;
  GServerVerdictDeadlineMs := ADeadlineMs;
end;

procedure SetTlsLibMormotClientConfig(const AConfig: ITlsClientConfig);
begin
  GClientConfig := AConfig;
end;

procedure SetTlsLibMormotServerConfig(const AConfig: ITlsServerConfig);
begin
  GServerConfig := AConfig;
end;

procedure SetTlsLibMormotCrypto(const ACryptoProvider: ICryptoProvider);
begin
  GCrypto := ACryptoProvider;
end;

procedure SetTlsLibMormotPkix(const APkix: IPkixProvider);
begin
  GPkix := APkix;
end;

procedure SetTlsLibMormotSessionResumption(AEnabled: Boolean);
begin
  GSessionResumption := AEnabled;
end;

procedure SetTlsLibMormotHandshakeTimeout(AMs: Int32);
begin
  GHandshakeTimeoutMs := AMs;
end;

procedure FlushTlsLibMormotConfigCache;
begin
  GServerConfigMemo.Clear;
  GClientConfigMemo.Clear;
end;

{ TMormotSocketTransport }

constructor TMormotSocketTransport.Create(ASocket: TNetSocket);
begin
  inherited Create;
  FSocket := ASocket;
end;

function TMormotSocketTransport.WaitReadable(AMs: Int32): Boolean;
begin
  // WaitFor readiness, not SO_RCVTIMEO: mORMot's Recv maps a receive timeout to nrRetry, which
  // would spin the read loop instead of surfacing the elapsed cap
  Result := neRead in FSocket.WaitFor(AMs, [neRead]);
end;

function TMormotSocketTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LLen: Integer;
  LRes: TNetResult;
begin
  repeat
    LLen := AMaxLength;
    LRes := FSocket.Recv(@ABuffer[AOffset], LLen);
    case LRes of
      nrOK:
        // a zero-length OK read means the peer closed
        if LLen > 0 then
          Exit(LLen)
        else
          Exit(0);
      nrClosed:
        Exit(0);
      nrRetry:
        ; // a blocking socket rarely reports this; read again
    else
      raise ETlsStreamError.Create(Format(SMormotReceiveFailed, [Ord(LRes)]));
    end;
  until False;
end;

function TMormotSocketTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
var
  LLen: Integer;
  LRes: TNetResult;
begin
  repeat
    LLen := ALength;
    LRes := FSocket.Send(@ABuffer[AOffset], LLen);
    case LRes of
      nrOK:
        Exit(LLen);
      nrRetry:
        ; // loop and send the remainder
    else
      raise ETlsStreamError.Create(Format(SMormotSendFailed, [Ord(LRes)]));
    end;
  until False;
end;

{ TTlsLibNetTls }

destructor TTlsLibNetTls.Destroy;
begin
  // close_notify before the session goes away, so a strict peer reads a clean shutdown rather than
  // a truncation (RFC 8446 6.1). The INetTls seam has no explicit close hook, but mORMot's
  // TCrtSocket.Close releases this interface (running us here) BEFORE it closes the socket, so the
  // socket is still open and the alert goes out. Best-effort: a write to a peer that already RST
  // the connection is expected and ignored.
  if FSession <> nil then
    FSession.CloseNotifyQuietly;
  FSession.Free;
  FSession := nil;
  inherited Destroy;
end;

class function TTlsLibNetTls.Snapshot(const AContext: TNetTlsContext;
  AIsClient: Boolean): TTlsAdapterOptions;
var
  LWantTrust: Boolean;
begin
  Result := TTlsAdapterOptions.Default;
  Result.Crypto := GCrypto;
  Result.Pkix := GPkix;
  Result.Certificate := TTlsAdapterBlobSource.FromFile(Utf8ToString(AContext.CertificateFile));
  Result.PrivateKey := TTlsAdapterBlobSource.FromFile(Utf8ToString(AContext.PrivateKeyFile));
  Result.KeyPassword := Utf8ToString(AContext.PrivatePassword);
  // trust sources: a client always composes them from the context; a server does so only when it
  // requests a client certificate, so a server without client auth names no source and requests
  // none. scsRoot/scsCA are the anchor-bearing OS stores our harvester collects (scsMY personal
  // identity and scsSpc code-signing are not server-auth anchors and must not turn system trust
  // on). A CACertificatesFile bundle and the OS store union - either counts. UseSystemTrust reaches
  // the OS store through the host-neutral installer seam, so the core never depends on the
  // system-trust package.
  LWantTrust := AIsClient or AContext.ClientCertificateAuthentication;
  if LWantTrust then
  begin
    if AContext.CACertificatesFile <> '' then
    begin
      SetLength(Result.TrustAnchors, 1);
      Result.TrustAnchors[0] :=
        TTlsAdapterBlobSource.FromFile(Utf8ToString(AContext.CACertificatesFile));
    end;
    if (scsRoot in AContext.CASystemStores) or (scsCA in AContext.CASystemStores) then
      Result.SystemTrust := TSystemTrustInstaller.Create as ISystemTrustInstaller;
  end;
  // a client maps IgnoreCertificateErrors onto the loud InsecureSkipVerify (never a silent bypass);
  // a server always verifies a requested client certificate, so its verify posture stays on
  if AIsClient then
  begin
    Result.VerifyPeer := not AContext.IgnoreCertificateErrors;
    Result.InsecureSkipVerify := AContext.IgnoreCertificateErrors;
  end
  else
  begin
    Result.VerifyPeer := True;
    Result.InsecureSkipVerify := False;
  end;
  // CheckHostName and ClientAuth keep the composable defaults (True / Required); mORMot exposes no
  // knob for either, and offers no ALPN surface
  Result.VerifyCallback := GVerifyCallback;
  Result.ClientVerdictResolver := GVerdictResolver;
  Result.ClientVerdictDeadlineMs := GVerdictDeadlineMs;
  Result.ServerVerdictResolver := GServerVerdictResolver;
  Result.ServerVerdictDeadlineMs := GServerVerdictDeadlineMs;
  Result.SessionResumption := GSessionResumption;
  Result.HandshakeTimeoutMs := GHandshakeTimeoutMs;
  Result.ClientConfig := GClientConfig;
  Result.ServerConfig := GServerConfig;
  Result.TrustSourceHint := SMormotTrustSourceHint;
end;

class function TTlsLibNetTls.BuildClientEngine(var AContext: TNetTlsContext;
  const AHost: string): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // CACertificatesRaw carries live OpenSSL X509 handles we cannot consume; reject before composing
  // (it is never part of the build signature)
  if AContext.CACertificatesRaw <> nil then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SCARawUnsupported);
  // a process-wide config supplied via SetTlsLibMormotClientConfig REPLACES the context-driven build
  // outright; the composer's conflict guard fails loud when the context also carries cert/trust
  // fields, rather than dropping them silently
  LConfig := TTlsAdapterConfigComposer.ResolveClientConfig(Snapshot(AContext, True),
    GClientConfigMemo, 'SetTlsLibMormotClientConfig');
  AContext.Enabled := True;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, AHost);
end;

class function TTlsLibNetTls.BuildServerEngine(
  const AContext: TNetTlsContext): ITlsEngine;
begin
  if AContext.CACertificatesRaw <> nil then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SCARawUnsupported);
  Result := TTlsEngineFactory.CreateServerEngine(
    TTlsAdapterConfigComposer.ResolveServerConfig(Snapshot(AContext, False),
    GServerConfigMemo, 'SetTlsLibMormotServerConfig'));
end;

procedure TTlsLibNetTls.DriveHandshake(ASocket: TNetSocket;
  const AEngine: ITlsEngine; AIsClient: Boolean; const AHost: string);
var
  LResolver: TCertificateVerdictResolver;
begin
  // attach the role-correct resolver: a client parks on the server's chain, a server (client auth)
  // on the mTLS client's chain - the two bind different EKUs, so one resolver cannot serve both
  if AIsClient then
    LResolver := GVerdictResolver
  else
    LResolver := GServerVerdictResolver;
  // bound the handshake read by the process-wide timeout (0 = the library default); the session
  // arms and clears the cap, even when the handshake raised, so a later app read is not left bounded
  FSession := TTlsAdapterSession.Create(AEngine,
    TMormotSocketTransport.Create(ASocket), AIsClient, AHost, LResolver);
  FSession.Handshake(GHandshakeTimeoutMs);
end;

procedure TTlsLibNetTls.AfterConnection(Socket: TNetSocket;
  var Context: TNetTlsContext; const ServerAddress: RawUtf8);
var
  LHost: string;
begin
  LHost := Utf8ToString(ServerAddress);
  DriveHandshake(Socket, BuildClientEngine(Context, LHost), True, LHost);
  Context.CipherName := GetCipherName;
end;

procedure TTlsLibNetTls.AfterBind(Socket: TNetSocket;
  var Context: TNetTlsContext; const ServerAddress: RawUtf8);
begin
  // we build a fresh engine per accepted connection from the bound context, so there is
  // no shared server state to set up here (unlike an OpenSSL SSL_CTX)
  Context.Enabled := True;
end;

procedure TTlsLibNetTls.AfterAccept(Socket: TNetSocket;
  const BoundContext: TNetTlsContext; LastError, CipherName: PRawUtf8);
begin
  try
    DriveHandshake(Socket, BuildServerEngine(BoundContext), False, '');
    if CipherName <> nil then
      CipherName^ := GetCipherName;
  except
    on E: Exception do
    begin
      if LastError <> nil then
        LastError^ := StringToUtf8(E.Message);
      raise;
    end;
  end;
end;

function TTlsLibNetTls.GetCipherName: RawUtf8;
begin
  // we do not surface the raw suite name; report the negotiated protocol version, which is
  // what mORMot logs the cipher for
  if FSession <> nil then
    Result := StringToUtf8(FSession.VersionName)
  else
    Result := '';
end;

function TTlsLibNetTls.NegotiatedGroup: UInt16;
begin
  if FSession <> nil then
    Result := FSession.NegotiatedGroup
  else
    Result := 0;
end;

function TTlsLibNetTls.PeerServerName: string;
begin
  if FSession <> nil then
    Result := FSession.PeerServerName
  else
    Result := '';
end;

function TTlsLibNetTls.EchStatus: TEchStatus;
begin
  if FSession <> nil then
    Result := FSession.EchStatus
  else
    Result := TEchStatus.NotOffered;
end;

function TTlsLibNetTls.Resumed: Boolean;
begin
  if FSession <> nil then
    Result := FSession.Resumed
  else
    Result := False;
end;

function TTlsLibNetTls.GetRawTls: pointer;
begin
  // there is no underlying PSSL/OpenSSL handle: TlsLib4Pascal is a managed engine
  Result := nil;
end;

function TTlsLibNetTls.GetRawCert(SignHashName: PRawUtf8): RawByteString;
var
  LLeaf: TBytes;
begin
  // the peer leaf certificate DER (mORMot uses it for certificate pinning / peer info). We do
  // not surface the signature-hash name, so TLS channel binding that requires it stays inert.
  Result := '';
  if FSession = nil then
    Exit;
  LLeaf := FSession.PeerLeaf;
  if System.Length(LLeaf) > 0 then
    SetString(Result, PAnsiChar(@LLeaf[0]), System.Length(LLeaf));
end;

function TTlsLibNetTls.Receive(Buffer: pointer; var Length: integer): TNetResult;
var
  LGot: Integer;
begin
  try
    LGot := FSession.Read(Buffer^, Length);
    Length := LGot;
    if LGot > 0 then
      Result := nrOK
    else
      // a zero-length read is a clean close_notify EOF (truncation raises)
      Result := nrClosed;
  except
    Length := 0;
    Result := nrFatalError;
  end;
end;

function TTlsLibNetTls.ReceivePending: integer;
begin
  Result := FSession.PendingReadBytes;
end;

function TTlsLibNetTls.Send(Buffer: pointer; var Length: integer): TNetResult;
begin
  try
    FSession.Write(Buffer^, Length);
    Result := nrOK;
  except
    Length := 0;
    Result := nrFatalError;
  end;
end;

function NewTlsLib4PascalTls: INetTls;
begin
  Result := TTlsLibNetTls.Create;
end;

procedure RegisterTlsLib4PascalTls;
begin
  NewNetTls := NewTlsLib4PascalTls;
end;

initialization
  GServerConfigMemo := NewTlsServerConfigMemo;
  GClientConfigMemo := NewTlsClientConfigMemo;
  GSessionResumption := True;

end.
