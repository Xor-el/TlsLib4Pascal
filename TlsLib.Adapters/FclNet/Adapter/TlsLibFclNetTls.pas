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
/// This is the only place our types and fcl-net's types meet. Free Pascal only.
/// </summary>
unit TlsLibFclNetTls;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  sockets,
  ssockets,
  sslsockets,
  sslbase,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfigMemo,
  TlpTlsConfigMemo,
  TlpTlsSignatureBuilder,
  TlpSessionTicketKeys,
  TlpInMemorySessionCache,
  TlpITlsTransport,
  TlpTlsStreamPump,
  TlpTlsStream,
  TlpSystemTrustFacade;

type
  /// <summary>An ITlsTransport over a raw fcl-net socket handle: raw ciphertext moves through
  /// the Sockets unit's fpRecv/fpSend on Socket.Handle, bypassing the SSL-aware handler methods
  /// (which carry decrypted application data and would otherwise recurse).</summary>
  TFclNetSocketTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FHandle: THandle;
  public
    constructor Create(AHandle: THandle);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
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
    Provider: ICryptoProvider;
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
    FStream: TTlsStream;
    FTransport: ITlsTransport;
    FEngine: ITlsEngine;
    FProvider: ICryptoProvider;
    FUserProvider: ICryptoProvider;
    FSessionResumption: Boolean;
    FLastErrorDesc: string;
    FUseSystemTrust: Boolean;
    FCheckHostName: Boolean;
    FCustomTrustStore: ITrustAnchorStore;
    FCustomVerifier: ICertificateVerifier;
    FAlpnProtocols: TArray<string>;
    FKeyPassword: string;
    FVerifyCallback: TTlsCertificateVerifyCallback;
    FVerdictResolver: TTlsVerdictResolver;
    FVerdictDeadlineMs: Cardinal;
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
    function LoadFileBytes(const APath: string): TBytes;
    function SSLDataBytes(const AData: TSSLData): TBytes;
    /// <summary>The injected provider, or the process-wide shared default when none is set.</summary>
    function EffectiveProvider: ICryptoProvider;
    function HasTrustSource: Boolean;
    /// <summary>Raises when a supplied config is set together with cert/trust properties a
    /// fully-built config replaces (APropertyName names the config property in the message).</summary>
    procedure GuardNoConflict(const APropertyName: string);
    procedure ApplyClientTrust(const ABuilder: ITlsClientConfigBuilder);
    procedure ApplyServerClientAuth(const ABuilder: ITlsServerConfigBuilder);
    function BuildClientConfig: ITlsClientConfig;
    function BuildServerConfig: ITlsServerConfig;
    function ClientSignature: string;
    function ServerSignature: string;
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
    /// <summary>A whole-verifier that REPLACES the built-in pipeline outright (exclusive of every
    /// anchor source).</summary>
    property CustomVerifier: ICertificateVerifier read FCustomVerifier
      write FCustomVerifier;
    /// <summary>The ALPN protocols to offer (client) or select from (server), most-preferred
    /// first (e.g. ['h2', 'http/1.1']). Empty offers none.</summary>
    property AlpnProtocols: TArray<string> read FAlpnProtocols write FAlpnProtocols;
    /// <summary>An augment-only peer-certificate hook: it runs after the built-in pipeline and can
    /// only additionally reject (never loosen it).</summary>
    property VerifyCallback: TTlsCertificateVerifyCallback read FVerifyCallback
      write FVerifyCallback;
    /// <summary>When assigned, the handshake parks after the pipeline accepts the peer chain and
    /// this resolves the verdict out-of-band (e.g. live OCSP/CRL); augment-only, fail-closed.</summary>
    property VerdictResolver: TTlsVerdictResolver read FVerdictResolver
      write FVerdictResolver;
    /// <summary>The advisory deadline (ms) for an awaited verdict; 0 leaves it to the resolver.</summary>
    property VerdictDeadlineMs: Cardinal read FVerdictDeadlineMs
      write FVerdictDeadlineMs;
    /// <summary>A fully-built client config that REPLACES the property-driven build: when set, the
    /// cert/trust properties (CertificateData trust/cert, UseSystemTrust, a custom store/verifier,
    /// ALPN) are not allowed alongside it (the handler raises). VerdictResolver still applies - it is
    /// a runtime stream hook, not part of the frozen config. The escape hatch to the full builder API
    /// - cipher order, groups, resumption. For a stock TFPHTTPClient, set it in an OnGetSocketHandler
    /// hook.</summary>
    property ClientConfig: ITlsClientConfig read FClientConfig write FClientConfig;
    /// <summary>A fully-built server config that REPLACES the property-driven build (the server-side
    /// counterpart of ClientConfig; same conflict rule).</summary>
    property ServerConfig: ITlsServerConfig read FServerConfig write FServerConfig;
    /// <summary>The crypto provider the property-driven build uses (hashing, RNG, cert parsing);
    /// seeded from TlsLibFclNetTrustDefaults.Provider at construction. nil uses the process-wide
    /// shared default; set it to inject a custom backend (HSM, FIPS, a test mock). Not allowed
    /// alongside a supplied ClientConfig/ServerConfig, which carries its own provider.</summary>
    property Provider: ICryptoProvider read FUserProvider write FUserProvider;
    /// <summary>TLS session resumption (a server issues session tickets; a client caches and reuses
    /// them), so a reconnect skips the asymmetric handshake. Forward-secret (TLS 1.3 psk_dhe_ke);
    /// 0-RTT is never enabled. Seeded from TlsLibFclNetTrustDefaults.SessionResumption (True); set
    /// False to force a full handshake every connection.</summary>
    property SessionResumption: Boolean read FSessionResumption write FSessionResumption;
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
{$IFDEF UNIX}
  // suppress SIGPIPE on a write to a peer that has gone away (Unix has no MSG_NOSIGNAL on Windows)
  TRANSPORT_FLAGS = MSG_NOSIGNAL;
{$ELSE}
  TRANSPORT_FLAGS = 0;
{$ENDIF}

resourcestring
  SNoServerCredential = 'the fcl-net CertificateData supplies no server Certificate/PrivateKey';
  SNoClientTrust = 'VerifyPeerCert is on but no trust source was named; set CertificateData.CertCA ' +
    '/ TrustedCertificate, UseSystemTrust, or a CustomTrustStore/CustomVerifier (system trust is ' +
    'never implicit), or set VerifyPeerCert := False to skip verification';
  SPeerVerifyRejected = 'the OnVerifyCertificate handler rejected the peer certificate';
  SNoSelfSignedCerts = 'TlsLib4Pascal does not generate self-signed certificates; supply ' +
    'CertificateData.Certificate and CertificateData.PrivateKey';
  SNoHostForNameCheck = 'CheckHostName is on but the socket carries no host to verify the ' +
    'certificate identity against (RFC 6125); connect through a TInetSocket that carries the ' +
    'host, or set CheckHostName := False to verify the chain only';
  SConfigAndOptionsConflict = '%s is set together with cert/trust properties that a fully-built ' +
    'config replaces; supply either the config or the cert/trust properties, not both';

var
  // fcl-net creates the handler per connection, so the build-once memos live process-wide
  GServerConfigMemo: ITlsServerConfigMemo;
  GClientConfigMemo: ITlsClientConfigMemo;

// a cert slot is either inline bytes or a file path; sign the bytes by digest, the file by stat
procedure SignSslData(var ASig: TTlsSignatureBuilder; const AName: string;
  const AData: TSSLData);
begin
  if System.Length(AData.Value) > 0 then
    ASig.AddBytesDigest(AName, AData.Value)
  else
    ASig.AddFile(AName, AData.FileName);
end;

{ TFclNetSocketTransport }

constructor TFclNetSocketTransport.Create(AHandle: THandle);
begin
  inherited Create;
  FHandle := AHandle;
end;

function TFclNetSocketTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := fpRecv(FHandle, @ABuffer[AOffset], AMaxLength, TRANSPORT_FLAGS);
  if Result <= 0 then
    Result := 0; // <0 error or 0 orderly close: surface as EOF to the pump
end;

procedure TFclNetSocketTransport.Write(const ABuffer: TBytes; AOffset,
  ALength: Int32);
var
  LOff, LRemain, LN: Integer;
begin
  LOff := AOffset;
  LRemain := ALength;
  while LRemain > 0 do
  begin
    LN := fpSend(FHandle, @ABuffer[LOff], LRemain, TRANSPORT_FLAGS);
    if LN <= 0 then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        'fcl-net socket send returned no progress');
    Inc(LOff, LN);
    Dec(LRemain, LN);
  end;
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
  FUserProvider := TlsLibFclNetTrustDefaults.Provider;
  FSessionResumption := TlsLibFclNetTrustDefaults.SessionResumption;
  // secure by default: fcl-net's own handler leaves VerifyPeerCert False (so stock TFPHTTPClient
  // does NOT verify), we default it True and fail closed without a trust source. Opt OUT with
  // VerifyPeerCert := False for the loud dangerous bypass.
  VerifyPeerCert := True;
end;

destructor TTlsLibSocketHandler.Destroy;
begin
  FStream.Free;
  inherited Destroy;
end;

function TTlsLibSocketHandler.CreateCertGenerator: TX509Certificate;
begin
  // the base constructor stores this; we never mint certificates, so hand back a placeholder that
  // refuses rather than the base's outright raise (which would break construction)
  Result := TFclNetNoCertGenerator.Create;
end;

function TTlsLibSocketHandler.LoadFileBytes(const APath: string): TBytes;
var
  LStream: TFileStream;
begin
  Result := nil;
  LStream := TFileStream.Create(APath, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      LStream.ReadBuffer(Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

function TTlsLibSocketHandler.SSLDataBytes(const AData: TSSLData): TBytes;
begin
  // each fcl-net cert slot holds EITHER inline bytes OR a file path; prefer the bytes
  if System.Length(AData.Value) > 0 then
    Result := AData.Value
  else if AData.FileName <> '' then
    Result := LoadFileBytes(AData.FileName)
  else
    Result := nil;
end;

function TTlsLibSocketHandler.HasTrustSource: Boolean;
begin
  Result := (FCustomVerifier <> nil) or (not CertificateData.CertCA.Empty) or
    (not CertificateData.TrustedCertificate.Empty) or FUseSystemTrust or
    (FCustomTrustStore <> nil);
end;

procedure TTlsLibSocketHandler.GuardNoConflict(const APropertyName: string);
begin
  // a supplied config owns trust/credential entirely; naming these alongside it would be silently
  // dropped, so fail loud. VerdictResolver is excluded: it is a runtime stream hook (not part of
  // the frozen config) and still applies with a supplied config.
  if HasTrustSource or (not CertificateData.Certificate.Empty) or
    (System.Length(FAlpnProtocols) > 0) or Assigned(FVerifyCallback) or
    (FUserProvider <> nil) then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
      Format(SConfigAndOptionsConflict, [APropertyName]));
end;

function TTlsLibSocketHandler.EffectiveProvider: ICryptoProvider;
begin
  if FUserProvider <> nil then
    Result := FUserProvider
  else
    Result := TDefaultCryptoProvider.Shared;
end;

procedure TTlsLibSocketHandler.ApplyClientTrust(
  const ABuilder: ITlsClientConfigBuilder);
begin
  // compose peer trust from orthogonal sources: a whole-verifier REPLACES the pipeline, else the
  // CertCA / TrustedCertificate bundles + the OS anchors + a custom store all UNION. Adding both a
  // verifier and an anchor source is left to fail as the builder's typed conflict.
  if FCustomVerifier <> nil then
    ABuilder.WithCertificateVerifier(FCustomVerifier);
  if not CertificateData.CertCA.Empty then
    ABuilder.WithTrustAnchors(SSLDataBytes(CertificateData.CertCA));
  if not CertificateData.TrustedCertificate.Empty then
    ABuilder.WithTrustAnchors(SSLDataBytes(CertificateData.TrustedCertificate));
  if FUseSystemTrust then
    TSystemTrust.WithSystemTrust(ABuilder, FProvider);
  if FCustomTrustStore <> nil then
    ABuilder.WithTrustStore(FCustomTrustStore);
end;

procedure TTlsLibSocketHandler.ApplyServerClientAuth(
  const ABuilder: ITlsServerConfigBuilder);
begin
  if FCustomVerifier <> nil then
    ABuilder.WithCertificateVerifier(FCustomVerifier);
  if not CertificateData.CertCA.Empty then
    ABuilder.WithTrustAnchors(SSLDataBytes(CertificateData.CertCA));
  if not CertificateData.TrustedCertificate.Empty then
    ABuilder.WithTrustAnchors(SSLDataBytes(CertificateData.TrustedCertificate));
  if FUseSystemTrust then
    TSystemTrust.WithSystemTrust(ABuilder, FProvider);
  if FCustomTrustStore <> nil then
    ABuilder.WithTrustStore(FCustomTrustStore);
end;

function TTlsLibSocketHandler.BuildClientConfig: ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  FProvider := EffectiveProvider;
  LClient := TTlsPresets.Compatible(FProvider).Client;
  // VerifyPeerCert is fcl-net's native verify switch: True runs real verification (and fails closed
  // below when no source is named), False accepts the chain unverified (our loud dangerous bypass).
  // This adapter defaults it True in the constructor, so an unconfigured handler is secure.
  if HasTrustSource then
    ApplyClientTrust(LClient)
  else
  begin
    // verifying with no source named fails closed; system trust is never implicit
    if VerifyPeerCert then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoClientTrust);
    // skipping verification still needs a source to satisfy the builder
    LClient.WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
  end;
  if not VerifyPeerCert then
    LClient.WithDangerousInsecureSkipVerify(True);
  if not FCheckHostName then
    LClient.WithNameCheck(False);
  if System.Length(FAlpnProtocols) > 0 then
    LClient.WithAlpnProtocols(FAlpnProtocols);
  // an optional client credential for mutual TLS
  if not CertificateData.Certificate.Empty then
    LClient.WithCredential(SSLDataBytes(CertificateData.Certificate),
      SSLDataBytes(CertificateData.PrivateKey), FKeyPassword);
  // an app's augment-only verify rule, and the async-verdict flag (the resolver itself is a
  // runtime stream hook applied in DriveHandshake, not part of the frozen config)
  if Assigned(FVerifyCallback) then
    LClient.WithCertificateVerifyCallback(FVerifyCallback);
  if Assigned(FVerdictResolver) then
    LClient.WithAsyncCertificateVerdict(True, FVerdictDeadlineMs);
  if FSessionResumption then
  begin
    LClient.WithResumption(True);
    LClient.WithSessionCache(TInMemorySessionCache.Shared);
  end
  else
    LClient.WithResumption(False);
  Result := LClient.Build;
end;

function TTlsLibSocketHandler.BuildServerConfig: ITlsServerConfig;
var
  LServer: ITlsServerConfigBuilder;
begin
  // a clear message when no cert is configured, rather than an opaque file-open error
  // (DriveHandshake wraps this into FLastError/FLastErrorDesc - no exception escapes)
  if CertificateData.Certificate.Empty then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoServerCredential);
  FProvider := EffectiveProvider;
  LServer := TTlsPresets.Compatible(FProvider).Server
    .WithCredential(SSLDataBytes(CertificateData.Certificate),
    SSLDataBytes(CertificateData.PrivateKey), FKeyPassword);
  if System.Length(FAlpnProtocols) > 0 then
    LServer.WithAlpnProtocols(FAlpnProtocols);
  // client-cert auth is optional: request + verify only when a client-trust source is named (same
  // composable model as the client). UseSystemTrust here validates CLIENT certs against the OS
  // public web-PKI roots - a broad surface most mTLS servers do not want.
  if HasTrustSource then
  begin
    LServer.WithPeerAuth(TClientAuthMode.Required);
    ApplyServerClientAuth(LServer);
  end;
  if FSessionResumption then
  begin
    LServer.WithResumption(True);
    LServer.WithSessionTicketKeys(TStekTicketKeyManager.Shared);
  end
  else
    LServer.WithResumption(False);
  Result := LServer.Build;
end;

function TTlsLibSocketHandler.ClientSignature: string;
var
  LSig: TTlsSignatureBuilder;
  LProto: string;
  LProvider: ICryptoProvider;
begin
  LProvider := EffectiveProvider;
  LSig := TTlsSignatureBuilder.Create(LProvider);
  LSig.AddPointer('provider', LProvider);
  LSig.AddFlag('resume', FSessionResumption);
  SignSslData(LSig, 'cert', CertificateData.Certificate);
  SignSslData(LSig, 'key', CertificateData.PrivateKey);
  SignSslData(LSig, 'ca', CertificateData.CertCA);
  SignSslData(LSig, 'trusted', CertificateData.TrustedCertificate);
  LSig.AddSecret('keypw', FKeyPassword);
  LSig.AddFlag('verifyPeer', VerifyPeerCert);
  LSig.AddFlag('checkHost', FCheckHostName);
  LSig.AddFlag('systemTrust', FUseSystemTrust);
  LSig.AddPointer('customVerifier', FCustomVerifier);
  LSig.AddPointer('customStore', FCustomTrustStore);
  for LProto in FAlpnProtocols do
    LSig.AddText('alpn', LProto);
  LSig.AddMethod('verifyCb', TMethod(FVerifyCallback));
  LSig.AddFlag('asyncVerdict', Assigned(FVerdictResolver));
  LSig.AddCardinal('deadline', FVerdictDeadlineMs);
  Result := LSig.Value;
end;

function TTlsLibSocketHandler.ServerSignature: string;
var
  LSig: TTlsSignatureBuilder;
  LProto: string;
  LProvider: ICryptoProvider;
begin
  LProvider := EffectiveProvider;
  LSig := TTlsSignatureBuilder.Create(LProvider);
  LSig.AddPointer('provider', LProvider);
  LSig.AddFlag('resume', FSessionResumption);
  SignSslData(LSig, 'cert', CertificateData.Certificate);
  SignSslData(LSig, 'key', CertificateData.PrivateKey);
  SignSslData(LSig, 'ca', CertificateData.CertCA);
  SignSslData(LSig, 'trusted', CertificateData.TrustedCertificate);
  LSig.AddSecret('keypw', FKeyPassword);
  LSig.AddFlag('systemTrust', FUseSystemTrust);
  LSig.AddPointer('customVerifier', FCustomVerifier);
  LSig.AddPointer('customStore', FCustomTrustStore);
  for LProto in FAlpnProtocols do
    LSig.AddText('alpn', LProto);
  Result := LSig.Value;
end;

function TTlsLibSocketHandler.BuildClientEngine(const AHost: string): ITlsEngine;
var
  LCfg: ITlsClientConfig;
  LSig: string;
begin
  // a fully-built config supplied by the app REPLACES the property-driven build outright; naming
  // cert/trust properties alongside it fails loud rather than dropping them silently
  if FClientConfig <> nil then
  begin
    GuardNoConflict('ClientConfig');
    Exit(TTlsEngineFactory.CreateClientEngine(FClientConfig, AHost));
  end;
  // host-name verification requested but the socket carries no host to check against: fail closed
  // rather than silently verify only the chain and skip RFC 6125 (a per-connection check)
  if FCheckHostName and VerifyPeerCert and (AHost = '') then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoHostForNameCheck);
  LSig := ClientSignature;
  if not GClientConfigMemo.TryGet(LSig, LCfg) then
    LCfg := GClientConfigMemo.StoreOrAdopt(LSig, BuildClientConfig);
  Result := TTlsEngineFactory.CreateClientEngine(LCfg, AHost);
end;

function TTlsLibSocketHandler.BuildServerEngine: ITlsEngine;
var
  LCfg: ITlsServerConfig;
  LSig: string;
begin
  if FServerConfig <> nil then
  begin
    GuardNoConflict('ServerConfig');
    Exit(TTlsEngineFactory.CreateServerEngine(FServerConfig));
  end;
  LSig := ServerSignature;
  if not GServerConfigMemo.TryGet(LSig, LCfg) then
    LCfg := GServerConfigMemo.StoreOrAdopt(LSig, BuildServerConfig);
  Result := TTlsEngineFactory.CreateServerEngine(LCfg);
end;

function TTlsLibSocketHandler.DriveHandshake(AIsClient: Boolean;
  const AHost: string): Boolean;
const
  // handshake read bound when the app sets no IOTimeout
  DefaultHandshakeReadTimeoutMs = 30000;
var
  LPriorTimeoutMs, LEffectiveMs: Integer;
begin
  Result := False;
  FLastError := 0;
  FLastErrorDesc := '';
  try
    // a reused handler drops any prior session so we rebuild cleanly on the new socket instead of
    // leaking the previous stream over a stale engine
    FStream.Free;
    FStream := nil;
    FTransport := nil;
    FEngine := nil;
    if AIsClient then
      FEngine := BuildClientEngine(AHost)
    else
      FEngine := BuildServerEngine;
    FTransport := TFclNetSocketTransport.Create(Socket.Handle) as ITlsTransport;
    FStream := TTlsStream.Create(FTransport, FEngine, AIsClient, AHost);
    if Assigned(FVerdictResolver) then
      FStream.SetCertificateVerdictResolver(FVerdictResolver);
    // bound the handshake read: the app's IOTimeout when set, else the default; restore it after
    LPriorTimeoutMs := Socket.IOTimeout;
    LEffectiveMs := LPriorTimeoutMs;
    if LEffectiveMs <= 0 then
      LEffectiveMs := DefaultHandshakeReadTimeoutMs;
    Socket.IOTimeout := LEffectiveMs;
    try
      FStream.Handshake;
    finally
      Socket.IOTimeout := LPriorTimeoutMs;
    end;
    // fcl-net's native OnVerifyCertificate hook runs after our pipeline accepts the chain and can
    // only additionally reject (augment-only, fail-closed)
    if not DoVerifyCert then
    begin
      FStream.CloseNotify;
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
  try
    if FStream <> nil then
      FStream.CloseNotify;
  except
    // ignore: the write side may already be gone
  end;
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
    FStream.Write(PByte(@Buffer)^, Count);
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
    Result := FStream.Read(PByte(@Buffer)^, Count);
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
  if FStream <> nil then
    Result := FStream.PendingReadBytes
  else
    Result := 0;
end;

function TTlsLibSocketHandler.NegotiatedVersion: TTlsVersion;
begin
  if FStream <> nil then
    Result := FStream.ConnectionInfo.NegotiatedVersion
  else
    Result := TTlsVersion.Create(0);
end;

function TTlsLibSocketHandler.NegotiatedCipherSuite: UInt16;
begin
  if FStream <> nil then
    Result := FStream.ConnectionInfo.CipherSuite
  else
    Result := 0;
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
