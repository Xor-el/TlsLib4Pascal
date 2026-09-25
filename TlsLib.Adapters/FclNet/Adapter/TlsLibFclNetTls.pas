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
/// The fcl-net integration adapter: drives TlsLib4Pascal's managed TLS engine behind Free
/// Pascal's own TSSLSocketHandler "swap-your-SSL" seam - so a stock TFPHTTPClient HTTPS request
/// (or any TInetSocket) speaks our managed TLS instead of OpenSSL. Include this unit and its
/// initialization block registers TTlsLibSocketHandler as fcl-net's default SSL handler class.
/// This unit is the only place our types and fcl-net's types meet: it maps fcl-net's
/// CertificateData and handler settings onto the host-neutral adapter core (config composition,
/// timed transport, session drive) and supplies the fcl-net socket glue. Free Pascal only.
/// </summary>
unit TlsLibFclNetTls;

{$I ..\..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
{$IFDEF UNIX}
  BaseUnix,
{$ENDIF}
  sockets,
  ssockets,
  sslsockets,
  sslbase,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpEchConfig,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfigMemo,
  TlpTlsConfigMemo,
  TlpTlsLibExceptions,
  TlpTlsConnection,
  TlpSystemTrustFacade;

type
  /// <summary>An ITlsTransport over a raw fcl-net socket handle: raw ciphertext moves through
  /// the Sockets unit's fpRecv/fpSend on Socket.Handle, bypassing the SSL-aware handler methods
  /// (which carry decrypted application data and would otherwise recurse). fcl-net has no readiness
  /// wait, so the handshake read cap is enforced by SO_RCVTIMEO on the handle (set through
  /// Socket.IOTimeout by the handler); this transport only classifies the resulting recv errno: an
  /// expiry under the handshake cap is ETlsHandshakeTimeout, one on an application read (the
  /// caller's own Socket.IOTimeout) is the retryable ETlsReadTimeout, never end of stream.</summary>
  TFclNetSocketTransport = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FHandle: THandle;
  strict protected
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(AHandle: THandle);
  end;

  /// <summary>The benign certificate generator fcl-net's TSSLSocketHandler constructor demands:
  /// TlsLib4Pascal never mints self-signed certificates (a server must supply a real
  /// CertificateData.Certificate/PrivateKey), so an attempt to generate one fails loudly rather
  /// than silently.</summary>
  TFclNetNoCertGenerator = class(TX509Certificate)
  public
    function CreateCertificateAndKey: TCertAndKey; override;
  end;

  /// <summary>Process-wide DEFAULTS a freshly created handler adopts at construction, for the
  /// TFPHTTPClient case where fcl-net exposes no handler to configure (it auto-creates one per
  /// connection). Explicit opt-in - everything here is off unless you set it, so trust stays
  /// fail-closed and system trust is never implicit. Per-connection config (a handler you build in
  /// OnGetSocketHandler, or one passed to a raw TInetSocket) still overrides these.</summary>
  TFclNetTrustDefaults = record
  public
    /// <summary>When True, every new handler starts with UseSystemTrust set - so a plain
    /// TFPHTTPClient verifies against the OS store with no OnGetSocketHandler hook. Set once at
    /// startup. Defaults to False.</summary>
    UseSystemTrust: Boolean;
    /// <summary>A crypto provider every new handler starts with (hashing, RNG, cert parsing) - so
    /// an auto-created handler (a plain TFPHTTPClient) uses a custom backend (HSM, FIPS, a test
    /// mock). nil (the default) uses the process-wide shared default. Set once at startup.</summary>
    Crypto: ICryptoProvider;
    /// <summary>A PKIX provider every new handler starts with (certificate parsing, path
    /// validation, revocation). nil (the default) uses the process-wide shared default. Set once
    /// at startup.</summary>
    Pkix: IPkixProvider;
    /// <summary>Whether every new handler starts with TLS session resumption enabled (a server
    /// issues tickets; a client caches and reuses them), so a reconnect skips the asymmetric
    /// handshake. Forward-secret (TLS 1.3 psk_dhe_ke); 0-RTT is never enabled. Defaults to True
    /// (set at unit init); set False at startup to make resumption opt-in.</summary>
    SessionResumption: Boolean;
  end;

  /// <summary>
  /// TlsLib4Pascal's implementation of fcl-net's TSSLSocketHandler. Connect / Accept run the
  /// handshake over Socket.Handle; Send / Recv move application data; Shutdown / Close send
  /// close_notify; BytesAvailable reports buffered plaintext. Peer trust is sourced from fcl-net's
  /// native CertificateData slots (CertCA / TrustedCertificate -> anchors, Certificate +
  /// PrivateKey -> our own credential) plus the extension properties fcl-net lacks (UseSystemTrust,
  /// a custom store/verifier, ALPN, the augment / async verdict hooks). Verification is governed by
  /// fcl-net's native VerifyPeerCert: this adapter defaults it True (secure by default, overriding
  /// fcl-net's own False), so real verification runs and fails closed when no trust source is named.
  /// Set VerifyPeerCert := False for the loud dangerous bypass (system trust is never implicit).
  /// </summary>
  TTlsLibSocketHandler = class(TSSLSocketHandler)
  strict private
  var
    FConnection: TTlsConnection;
    FUserCrypto: ICryptoProvider;
    FUserPkix: IPkixProvider;
    FSessionResumption: Boolean;
    FLastErrorDesc: string;
    FUseSystemTrust: Boolean;
    FCheckHostName: Boolean;
    FCustomTrustStore: ITrustAnchorStore;
    FCustomServerCertVerifier: IServerCertificateVerifier;
    FCustomClientCertVerifier: IClientCertificateVerifier;
    FAlpnProtocols: TArray<string>;
    FKeyPassword: string;
    FVerifyCallback: TTlsCertificateVerifyCallback;
    FVerdictResolver: TCertificateVerdictResolver;
    FVerdictDeadlineMs: Cardinal;
    FServerVerdictResolver: TCertificateVerdictResolver;
    FServerVerdictDeadlineMs: Cardinal;
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
    FHandshakeTimeoutMs: Integer;
    /// <summary>A fcl-net cert slot as a host-neutral blob source: its inline bytes when present,
    /// else its file path, else empty.</summary>
    class function SslDataBlob(const AData: TSSLData): TTlsBlobSource; static;
    /// <summary>The host-neutral snapshot the adapter core composes into a TLS configuration: one
    /// value per handshake, so a handler setting changed mid-connection is never seen half-applied.
    /// The role (client vs server) is chosen by the caller when it resolves the config and attaches
    /// the resolver, not here.</summary>
    function Snapshot: TTlsOptions;
    function BuildClientEngine(const AHost: string): ITlsEngine;
    function BuildServerEngine: ITlsEngine;
    function DriveHandshake(AIsClient: Boolean; const AHost: string): Boolean;
  public
    constructor Create; override;
    destructor Destroy; override;
    function CreateCertGenerator: TX509Certificate; override;
    function Connect: Boolean; override;
    function Accept: Boolean; override;
    function Close: Boolean; override;
    function Shutdown(BiDirectional: Boolean): Boolean; override;
    function Send(const Buffer; Count: Integer): Integer; override;
    function Recv(const Buffer; Count: Integer): Integer; override;
    function BytesAvailable: Integer; override;
    /// <summary>The negotiated protocol version once the handshake completes.</summary>
    function NegotiatedVersion: TTlsVersion;
    /// <summary>The negotiated cipher-suite wire codepoint once the handshake completes (0 if none).</summary>
    function NegotiatedCipherSuite: UInt16;
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
    /// <summary>A human-readable description of the last Connect/Accept/Send/Recv failure.</summary>
    property LastErrorDesc: string read FLastErrorDesc;
    /// <summary>Opt into the OS system-trust anchors (Windows crypt32 / macOS SecTrust / Unix
    /// bundle). Unions with a CertCA / TrustedCertificate bundle and any CustomTrustStore. System
    /// trust is never implicit: when verifying you must name at least one source or the build fails
    /// closed. Defaults to False.</summary>
    property UseSystemTrust: Boolean read FUseSystemTrust write FUseSystemTrust;
    /// <summary>Whether the peer certificate's identity is checked against the host (RFC 6125).
    /// Defaults to True; set False to verify the chain but not the name.</summary>
    property CheckHostName: Boolean read FCheckHostName write FCheckHostName;
    /// <summary>The password for an encrypted CertificateData.PrivateKey, if any.</summary>
    property KeyPassword: string read FKeyPassword write FKeyPassword;
    /// <summary>An injected anchor store; when set it UNIONS with the CertCA / TrustedCertificate
    /// bundle and UseSystemTrust.</summary>
    property CustomTrustStore: ITrustAnchorStore read FCustomTrustStore
      write FCustomTrustStore;
    /// <summary>A whole-verifier for the peer SERVER certificate (client connections) that
    /// REPLACES the built-in pipeline outright (exclusive of every anchor source).</summary>
    property CustomServerCertificateVerifier: IServerCertificateVerifier
      read FCustomServerCertVerifier write FCustomServerCertVerifier;
    /// <summary>A whole-verifier for the peer CLIENT certificate (mTLS server connections) that
    /// REPLACES the built-in pipeline outright.</summary>
    property CustomClientCertificateVerifier: IClientCertificateVerifier
      read FCustomClientCertVerifier write FCustomClientCertVerifier;
    /// <summary>The ALPN protocols to offer (client) or select from (server), most-preferred
    /// first (e.g. ['h2', 'http/1.1']). Empty offers none.</summary>
    property AlpnProtocols: TArray<string> read FAlpnProtocols write FAlpnProtocols;
    /// <summary>An augment-only peer-certificate hook: it runs after the built-in pipeline and can
    /// only additionally reject (never loosen it).</summary>
    property VerifyCallback: TTlsCertificateVerifyCallback read FVerifyCallback
      write FVerifyCallback;
    /// <summary>The CLIENT-role verdict resolver: when assigned, a client handshake parks after
    /// the pipeline accepts the SERVER's chain and this resolves it out-of-band (e.g. live
    /// OCSP/CRL over a server-auth trust engine); augment-only, fail-closed. For an mTLS server
    /// that must vet the CLIENT chain use ServerVerdictResolver - the two roles bind different
    /// EKUs, so one resolver cannot serve both.</summary>
    property VerdictResolver: TCertificateVerdictResolver read FVerdictResolver
      write FVerdictResolver;
    /// <summary>The fetch budget (ms) the client-role resolver is given; 0 leaves it to the
    /// resolver.</summary>
    property VerdictDeadlineMs: Cardinal read FVerdictDeadlineMs
      write FVerdictDeadlineMs;
    /// <summary>The SERVER-role verdict resolver: when assigned, a server handshake that requests
    /// a client certificate parks after the pipeline accepts the CLIENT's chain and this resolves
    /// it out-of-band (live client-cert revocation over a client-auth trust engine); augment-only,
    /// fail-closed.</summary>
    property ServerVerdictResolver: TCertificateVerdictResolver read FServerVerdictResolver
      write FServerVerdictResolver;
    /// <summary>The fetch budget (ms) the server-role resolver is given; 0 leaves it to the
    /// resolver.</summary>
    property ServerVerdictDeadlineMs: Cardinal read FServerVerdictDeadlineMs
      write FServerVerdictDeadlineMs;
    /// <summary>A fully-built client config that REPLACES the property-driven build: when set, the
    /// cert/trust properties (CertificateData trust/cert, UseSystemTrust, a custom store/verifier,
    /// ALPN) are not allowed alongside it (the handler raises). The verdict resolvers
    /// (VerdictResolver/ServerVerdictResolver) still apply - runtime stream hooks, not part of the
    /// frozen config - provided the supplied config itself armed the deferral
    /// (WithLiveRevocationVerdict/WithAsyncCertificateVerdict), else the handshake never parks. The
    /// escape hatch to the full builder API - cipher order, groups, resumption. For a stock
    /// TFPHTTPClient, set it in an OnGetSocketHandler hook.</summary>
    property ClientConfig: ITlsClientConfig read FClientConfig write FClientConfig;
    /// <summary>A fully-built server config that REPLACES the property-driven build (the server-side
    /// counterpart of ClientConfig; same conflict rule).</summary>
    property ServerConfig: ITlsServerConfig read FServerConfig write FServerConfig;
    /// <summary>The crypto provider the property-driven build uses (hashing, RNG, cert parsing);
    /// seeded from TlsLibFclNetTrustDefaults.Crypto at construction. nil uses the process-wide
    /// shared default; set it to inject a custom backend (HSM, FIPS, a test mock). Not allowed
    /// alongside a supplied ClientConfig/ServerConfig, which carries its own provider.</summary>
    property Crypto: ICryptoProvider read FUserCrypto write FUserCrypto;
    /// <summary>The PKIX provider the property-driven build uses (certificate parsing, path
    /// validation, revocation); seeded from TlsLibFclNetTrustDefaults.Pkix at construction. nil uses
    /// the process-wide shared default; set it to inject a custom backend. Not allowed alongside a
    /// supplied ClientConfig/ServerConfig, which carries its own PKIX provider.</summary>
    property Pkix: IPkixProvider read FUserPkix write FUserPkix;
    /// <summary>TLS session resumption (a server issues session tickets; a client caches and reuses
    /// them), so a reconnect skips the asymmetric handshake. Forward-secret (TLS 1.3 psk_dhe_ke);
    /// 0-RTT is never enabled. Seeded from TlsLibFclNetTrustDefaults.SessionResumption (True); set
    /// False to force a full handshake every connection.</summary>
    property SessionResumption: Boolean read FSessionResumption write FSessionResumption;
    /// <summary>The read timeout (ms) bounding the handshake, so a peer that connects but sends no
    /// data cannot park the connection's thread. 0 (the default) falls back to Socket.IOTimeout when
    /// that is set, else the 30 s library default; a positive value overrides both.</summary>
    property HandshakeTimeoutMs: Integer read FHandshakeTimeoutMs write FHandshakeTimeoutMs;
  end;

var
  /// <summary>The process-wide handler defaults (see TFclNetTrustDefaults). Off by default; set a
  /// field once at startup to make the common case need no per-connection hook.</summary>
  TlsLibFclNetTrustDefaults: TFclNetTrustDefaults;

/// <summary>Clears the process-wide build-once config caches so the next handshake rebuilds from
/// current inputs. Call after rotating a certificate/key to purge the retired credential (a cached
/// config holds its private key alive). Call only with no TLS traffic in flight.</summary>
procedure FlushTlsLibFclNetConfigCache;

implementation

const
{$IF DEFINED(UNIX) AND NOT DEFINED(DARWIN)}
  // MSG_NOSIGNAL suppresses SIGPIPE when writing to a peer whose read end has closed; platforms
  // that do not declare it (Windows, Darwin) use 0 here
  TRANSPORT_FLAGS = MSG_NOSIGNAL;
{$ELSE}
  TRANSPORT_FLAGS = 0;
{$IFEND}
  // Windows SO_RCVTIMEO expiry code; a literal so the Unix build needs no winsock symbol
  WSAETIMEDOUT_CODE = 10060;

resourcestring
  SFclNetSendNoProgress = 'fcl-net socket send returned no progress';
  SFclNetHandshakeReadTimedOut = 'the peer sent no handshake data within %d ms';
  SFclNetReceiveTimedOut = 'the socket receive timeout elapsed with no data from the peer';
  SPeerVerifyRejected = 'the OnVerifyCertificate handler rejected the peer certificate';
  SNoSelfSignedCerts = 'TlsLib4Pascal does not generate self-signed certificates; supply ' +
    'CertificateData.Certificate and CertificateData.PrivateKey';
  SNoHostForNameCheck = 'CheckHostName is on but the socket carries no host to verify the ' +
    'certificate identity against (RFC 6125); connect through a TInetSocket that carries the ' +
    'host, or set CheckHostName := False to verify the chain only';
  SFclNetTrustSourceHint = 'CertificateData.CertCA / TrustedCertificate, UseSystemTrust, or a ' +
    'CustomTrustStore/CustomVerifier';

var
  // fcl-net creates the handler per connection, so the build-once memos live process-wide
  GServerConfigMemo: ITlsServerConfigMemo;
  GClientConfigMemo: ITlsClientConfigMemo;

{ TFclNetSocketTransport }

constructor TFclNetSocketTransport.Create(AHandle: THandle);
begin
  inherited Create;
  FHandle := AHandle;
end;

function TFclNetSocketTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LErr: Integer;
begin
  // a signal that interrupts a blocking recv is not an error - retry, as the plain fcl-net
  // handler does; a genuine timeout or close is classified below
  repeat
    Result := fpRecv(FHandle, @ABuffer[AOffset], AMaxLength, TRANSPORT_FLAGS);
{$IFDEF UNIX}
  until (Result >= 0) or (SocketError <> ESysEINTR);
{$ELSE}
  until True;
{$ENDIF}
  if Result >= 0 then
    Exit; // > 0 bytes, or 0 for an orderly close (the pump reports a truncated handshake)
  // Result < 0: a receive-timeout errno is SO_RCVTIMEO firing on a silent peer - our handshake cap
  // while it is armed, else the caller's own application-read timeout, which is retryable and
  // must not be misreported as a truncation; any other error surfaces as end-of-stream
  LErr := SocketError;
  if (LErr = EsockEWOULDBLOCK) or (LErr = WSAETIMEDOUT_CODE) then
  begin
    if ReadTimeoutMs > 0 then
      raise ETlsHandshakeTimeout.Create(
        Format(SFclNetHandshakeReadTimedOut, [ReadTimeoutMs]));
    raise ETlsReadTimeout.Create(SFclNetReceiveTimedOut);
  end;
  Result := 0;
end;

function TFclNetSocketTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  // retry a signal-interrupted send rather than reporting it as no progress
  repeat
    Result := fpSend(FHandle, @ABuffer[AOffset], ALength, TRANSPORT_FLAGS);
{$IFDEF UNIX}
  until (Result > 0) or (SocketError <> ESysEINTR);
{$ELSE}
  until True;
{$ENDIF}
  if Result <= 0 then
    raise ETlsStreamError.Create(SFclNetSendNoProgress);
end;

{ TFclNetNoCertGenerator }

function TFclNetNoCertGenerator.CreateCertificateAndKey: TCertAndKey;
begin
  Result := Default(TCertAndKey);
  raise ESSLSocketError.Create(SNoSelfSignedCerts);
end;

{ TTlsLibSocketHandler }

constructor TTlsLibSocketHandler.Create;
begin
  inherited Create;
  FCheckHostName := True;
  // adopt the process-wide opt-in defaults (off unless the app set them); fcl-net auto-creates the
  // handler for TFPHTTPClient, so this is the only place a global "use the OS store" preference can
  // reach it. A per-connection handler still overrides afterwards.
  FUseSystemTrust := TlsLibFclNetTrustDefaults.UseSystemTrust;
  FUserCrypto := TlsLibFclNetTrustDefaults.Crypto;
  FUserPkix := TlsLibFclNetTrustDefaults.Pkix;
  FSessionResumption := TlsLibFclNetTrustDefaults.SessionResumption;
  // secure by default: fcl-net's own handler leaves VerifyPeerCert False (so stock TFPHTTPClient
  // does NOT verify), we default it True and fail closed without a trust source. Opt OUT with
  // VerifyPeerCert := False for the loud dangerous bypass.
  VerifyPeerCert := True;
end;

destructor TTlsLibSocketHandler.Destroy;
begin
  FConnection.Free;
  FConnection := nil;
  inherited Destroy;
end;

function TTlsLibSocketHandler.CreateCertGenerator: TX509Certificate;
begin
  // the base constructor stores this; we never mint certificates, so hand back a placeholder that
  // refuses rather than the base's outright raise (which would break construction)
  Result := TFclNetNoCertGenerator.Create;
end;

class function TTlsLibSocketHandler.SslDataBlob(
  const AData: TSSLData): TTlsBlobSource;
begin
  // each fcl-net cert slot holds EITHER inline bytes OR a file path; prefer the bytes
  if System.Length(AData.Value) > 0 then
    Result := TTlsBlobSource.FromBytes(AData.Value)
  else
    Result := TTlsBlobSource.FromFile(AData.FileName);
end;

function TTlsLibSocketHandler.Snapshot: TTlsOptions;
var
  LAnchors: TArray<TTlsBlobSource>;
begin
  Result := TTlsOptions.Default;
  Result.Crypto := FUserCrypto;
  Result.Pkix := FUserPkix;
  Result.Certificate := SslDataBlob(CertificateData.Certificate);
  Result.PrivateKey := SslDataBlob(CertificateData.PrivateKey);
  Result.KeyPassword := FKeyPassword;
  // fcl-net exposes two anchor slots; add each only when named so HasClientTrustSource stays honest
  LAnchors := nil;
  if not CertificateData.CertCA.Empty then
  begin
    SetLength(LAnchors, System.Length(LAnchors) + 1);
    LAnchors[System.High(LAnchors)] := SslDataBlob(CertificateData.CertCA);
  end;
  if not CertificateData.TrustedCertificate.Empty then
  begin
    SetLength(LAnchors, System.Length(LAnchors) + 1);
    LAnchors[System.High(LAnchors)] := SslDataBlob(CertificateData.TrustedCertificate);
  end;
  Result.TrustAnchors := LAnchors;
  // UseSystemTrust opts into the OS store through the host-neutral installer seam, so the core
  // never depends on the system-trust package
  if FUseSystemTrust then
    Result.SystemTrust := TSystemTrustInstaller.Create as ISystemTrustInstaller;
  Result.CustomTrustStore := FCustomTrustStore;
  Result.ServerCertificateVerifier := FCustomServerCertVerifier;
  Result.ClientCertificateVerifier := FCustomClientCertVerifier;
  Result.VerifyPeer := VerifyPeerCert;
  Result.InsecureSkipVerify := not VerifyPeerCert;
  Result.CheckHostName := FCheckHostName;
  // ClientAuth keeps the composable default (Required); fcl-net exposes no mode knob
  Result.AlpnProtocols := FAlpnProtocols;
  Result.VerifyCallback := FVerifyCallback;
  Result.ClientVerdictResolver := FVerdictResolver;
  Result.ClientVerdictDeadlineMs := FVerdictDeadlineMs;
  Result.ServerVerdictResolver := FServerVerdictResolver;
  Result.ServerVerdictDeadlineMs := FServerVerdictDeadlineMs;
  Result.SessionResumption := FSessionResumption;
  Result.HandshakeTimeoutMs := FHandshakeTimeoutMs;
  Result.ClientConfig := FClientConfig;
  Result.ServerConfig := FServerConfig;
  Result.TrustSourceHint := SFclNetTrustSourceHint;
end;

function TTlsLibSocketHandler.BuildClientEngine(const AHost: string): ITlsEngine;
var
  LOptions: TTlsOptions;
begin
  LOptions := Snapshot;
  // host-name verification requested but the socket carries no host to check against: fail closed
  // rather than silently verifying only the chain (RFC 6125). A per-connection check, not baked
  // into the memoised config, so it never applies to a supplied ClientConfig.
  if FCheckHostName and VerifyPeerCert and (AHost = '') and (FClientConfig = nil) then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoHostForNameCheck);
  Result := TTlsEngineFactory.CreateClientEngine(
    TTlsConfigComposer.ResolveClientConfig(LOptions, GClientConfigMemo, 'ClientConfig'), AHost);
end;

function TTlsLibSocketHandler.BuildServerEngine: ITlsEngine;
var
  LOptions: TTlsOptions;
begin
  LOptions := Snapshot;
  // a server never consults VerifyPeerCert (that switch governs a client verifying a server); it
  // requests and verifies a client certificate whenever a client-trust source is named, so force
  // the composer's server-side gate on regardless of the client-oriented VerifyPeer value
  LOptions.VerifyPeer := True;
  Result := TTlsEngineFactory.CreateServerEngine(
    TTlsConfigComposer.ResolveServerConfig(LOptions, GServerConfigMemo, 'ServerConfig'));
end;

function TTlsLibSocketHandler.DriveHandshake(AIsClient: Boolean;
  const AHost: string): Boolean;
const
  DefaultHandshakeReadTimeoutMs = 30000; // when neither the property nor Socket.IOTimeout is set
var
  LEngine: ITlsEngine;
  LResolver: TCertificateVerdictResolver;
  LPriorTimeoutMs, LEffectiveMs: Integer;
begin
  Result := False;
  FLastError := 0;
  FLastErrorDesc := '';
  try
    // a reused handler drops any prior session so we rebuild cleanly on the new socket instead of
    // leaking the previous stream over a stale engine
    FConnection.Free;
    FConnection := nil;
    if AIsClient then
      LEngine := BuildClientEngine(AHost)
    else
      LEngine := BuildServerEngine;
    // attach the role-correct resolver: a client parks on the server's chain, a server (client
    // auth) on the mTLS client's chain - the two bind different EKUs
    if AIsClient then
      LResolver := FVerdictResolver
    else
      LResolver := FServerVerdictResolver;
    FConnection := TTlsConnection.Create(LEngine,
      TFclNetSocketTransport.Create(Socket.Handle), AIsClient, AHost, LResolver);
    // fcl-net has no readiness wait, so the handshake read is bounded by SO_RCVTIMEO through
    // Socket.IOTimeout: the property when set, else today's IOTimeout, else the default; restore it
    // after. The session arms and clears its own read cap (used to classify the recv errno).
    LEffectiveMs := FHandshakeTimeoutMs;
    if LEffectiveMs <= 0 then
      LEffectiveMs := Socket.IOTimeout;
    if LEffectiveMs <= 0 then
      LEffectiveMs := DefaultHandshakeReadTimeoutMs;
    LPriorTimeoutMs := Socket.IOTimeout;
    Socket.IOTimeout := LEffectiveMs;
    try
      FConnection.Handshake(LEffectiveMs);
    finally
      Socket.IOTimeout := LPriorTimeoutMs;
    end;
    // fcl-net's native OnVerifyCertificate hook runs after our pipeline accepts the chain and can
    // only additionally reject (augment-only, fail-closed)
    if not DoVerifyCert then
    begin
      FConnection.CloseNotify;
      raise ETlsStreamError.Create(TTlsAlertDescription.BadCertificate, SPeerVerifyRejected);
    end;
    SetSSLActive(True);
    Result := True;
  except
    on E: Exception do
    begin
      FLastError := 1;
      FLastErrorDesc := E.Message;
    end;
  end;
end;

function TTlsLibSocketHandler.Connect: Boolean;
var
  LHost: string;
begin
  LHost := '';
  if Socket is TInetSocket then
    LHost := TInetSocket(Socket).Host; // SNI + the name we verify the certificate for
  Result := DriveHandshake(True, LHost);
end;

function TTlsLibSocketHandler.Accept: Boolean;
begin
  Result := DriveHandshake(False, '');
end;

function TTlsLibSocketHandler.Shutdown(BiDirectional: Boolean): Boolean;
begin
  // best effort: flush close_notify, then optionally shut the transport write side. A peer that
  // already vanished must not turn a clean shutdown into an exception.
  if FConnection <> nil then
    FConnection.CloseNotifyQuietly;
  SetSSLActive(False);
  if BiDirectional and (Socket <> nil) then
    fpShutdown(Socket.Handle, 1);
  Result := True;
end;

function TTlsLibSocketHandler.Close: Boolean;
begin
  Result := Shutdown(False);
end;

function TTlsLibSocketHandler.Send(const Buffer; Count: Integer): Integer;
begin
  // fcl-net's handler is error-code based: clear the error and convert a fatal engine/transport
  // failure into a negative count + a stored last-error rather than letting it propagate
  FLastError := 0;
  FLastErrorDesc := '';
  try
    FConnection.Write(PByte(@Buffer)^, Count);
    Result := Count;
  except
    on E: Exception do
    begin
      FLastError := 1;
      FLastErrorDesc := E.Message;
      Result := -1;
    end;
  end;
end;

function TTlsLibSocketHandler.Recv(const Buffer; Count: Integer): Integer;
begin
  FLastError := 0;
  FLastErrorDesc := '';
  try
    // a clean close_notify surfaces as 0 (EOF, no error)
    Result := FConnection.Read(PByte(@Buffer)^, Count);
  except
    on E: Exception do
    begin
      FLastError := 1;
      FLastErrorDesc := E.Message;
      Result := -1;
    end;
  end;
end;

function TTlsLibSocketHandler.BytesAvailable: Integer;
begin
  if FConnection <> nil then
    Result := FConnection.PendingReadBytes
  else
    Result := 0;
end;

function TTlsLibSocketHandler.NegotiatedVersion: TTlsVersion;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedVersion
  else
    Result := TTlsVersion.Create(0);
end;

function TTlsLibSocketHandler.NegotiatedCipherSuite: UInt16;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedCipherSuite
  else
    Result := 0;
end;

function TTlsLibSocketHandler.NegotiatedGroup: UInt16;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedGroup
  else
    Result := 0;
end;

function TTlsLibSocketHandler.PeerServerName: string;
begin
  if FConnection <> nil then
    Result := FConnection.PeerServerName
  else
    Result := '';
end;

function TTlsLibSocketHandler.EchStatus: TEchStatus;
begin
  if FConnection <> nil then
    Result := FConnection.EchStatus
  else
    Result := TEchStatus.NotOffered;
end;

function TTlsLibSocketHandler.Resumed: Boolean;
begin
  if FConnection <> nil then
    Result := FConnection.Resumed
  else
    Result := False;
end;

procedure FlushTlsLibFclNetConfigCache;
begin
  GServerConfigMemo.Clear;
  GClientConfigMemo.Clear;
end;

initialization
  GServerConfigMemo := NewTlsServerConfigMemo;
  GClientConfigMemo := NewTlsClientConfigMemo;
  TlsLibFclNetTrustDefaults.SessionResumption := True;
  TSSLSocketHandler.SetDefaultHandlerClass(TTlsLibSocketHandler);

end.
