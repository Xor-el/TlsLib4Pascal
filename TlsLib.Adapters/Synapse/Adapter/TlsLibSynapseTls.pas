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
/// The Synapse integration plugin: drives TlsLib4Pascal's managed TLS engine behind
/// Synapse's TCustomSSL "swap-your-SSL" seam. Include this unit and Synapse's TTCPBlockSocket
/// speaks our managed TLS instead of OpenSSL - the initialization block registers it as the
/// process-wide SSLImplementation. This is a compile-time plugin: exactly ONE SSL plugin unit
/// may be linked per project (do not also link ssl_openssl). This unit is the only place our
/// types and Synapse's types meet.
/// </summary>
unit TlsLibSynapseTls;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  blcksock,
  synsock,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpCryptoAlgorithms,
  TlpDataEncoding,
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

/// <summary>Sets a process-wide augment-only verify callback the plugin threads into every
/// client handshake (it runs after the built-in pipeline and can only additionally reject).
/// nil clears it. The Synapse plugin is created per socket by SSLImplementation, so its
/// neutral (non-TCustomSSL) hooks are configured through these unit-level setters.</summary>
procedure SetTlsLibSynapseVerifyCallback(const ACallback: TTlsCertificateVerifyCallback);
/// <summary>Sets a process-wide out-of-band verdict resolver (e.g. live OCSP/CRL): when set,
/// every client handshake parks after the pipeline accepts the chain and this decides it.
/// ADeadlineMs is advisory. nil clears it.</summary>
procedure SetTlsLibSynapseVerdictResolver(const AResolver: TTlsVerdictResolver;
  ADeadlineMs: Cardinal);
/// <summary>Clears the process-wide build-once config caches so the next handshake rebuilds from
/// current inputs. Call after rotating a certificate/key to purge the retired credential (a cached
/// config holds its private key alive). Call only with no TLS traffic in flight.</summary>
procedure FlushTlsLibSynapseConfigCache;

type
  /// <summary>An ITlsTransport over a raw Synapse socket handle: raw ciphertext moves through
  /// synsock Recv/Send, bypassing TTCPBlockSocket's SSL-aware buffered methods (which would
  /// otherwise recurse back into this plugin once SSLEnabled is set).</summary>
  TSynapseSocketTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FHandle: TSocket;
  public
    constructor Create(AHandle: TSocket);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>
  /// TlsLib4Pascal's implementation of Synapse's TCustomSSL. Connect / Accept run the
  /// handshake; SendBuffer / RecvBuffer move application data; WaitingData reports buffered
  /// plaintext; Shutdown / BiShutdown send close_notify. It maps the TCustomSSL properties
  /// (cert/key files, CA, VerifyCert, SNIHost) onto our immutable config.
  /// </summary>
  TSSLTlsLib = class(TCustomSSL)
  strict private
  var
    FStream: TTlsStream;
    FTransport: ITlsTransport;
    FEngine: ITlsEngine;
    FProvider: ICryptoProvider;
    FUserProvider: ICryptoProvider;
    FUseSystemTrust: Boolean;
    FSessionResumption: Boolean;
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
    function LoadFileBytes(const APath: string): TBytes;
    /// <summary>The injected provider, or the process-wide shared default when none is set.</summary>
    function EffectiveProvider: ICryptoProvider;
    function BuildClientConfig: ITlsClientConfig;
    function BuildServerConfig: ITlsServerConfig;
    function ClientSignature: string;
    function ServerSignature: string;
    function BuildClientEngine: ITlsEngine;
    function BuildServerEngine: ITlsEngine;
    /// <summary>Raises when a supplied config is set together with cert/trust properties a
    /// fully-built config replaces (APropertyName names the config property in the message).</summary>
    procedure GuardNoConflict(const APropertyName: string);
    function DriveHandshake(AIsClient: Boolean; const AHost: string): Boolean;
    /// <summary>The peer leaf certificate (DER), or empty when none was presented.</summary>
    function PeerLeaf: TBytes;
    /// <summary>Runs Synapse's native OnVerifyCert hook, if set, after a handshake; returns
    /// False when the app rejected the peer certificate.</summary>
    function RunPeerVerifyHook: Boolean;
  public
    constructor Create(const AValue: TTCPBlockSocket); override;
    destructor Destroy; override;
    function LibVersion: string; override;
    function LibName: string; override;
    function Connect: boolean; override;
    function Accept: boolean; override;
    function Shutdown: boolean; override;
    function BiShutdown: boolean; override;
    function SendBuffer(Buffer: TMemory; Len: Integer): Integer; override;
    function RecvBuffer(Buffer: TMemory; Len: Integer): Integer; override;
    function WaitingData: Integer; override;
    function GetSSLVersion: string; override;
    function GetCipherName: string; override;
    /// <summary>The negotiated cipher-suite wire codepoint once the handshake completes (0 if none).
    /// Synapse's TCustomSSL has no such accessor, so cast Sock.SSL to TSSLTlsLib to read it.</summary>
    function NegotiatedCipherSuite: UInt16;
    // native peer-certificate accessors an OnVerifyCert handler reads (no OpenSSL type)
    function GetPeerSubject: string; override;
    function GetPeerIssuer: string; override;
    function GetPeerName: string; override;
    function GetPeerFingerprint: AnsiString; override;
    function GetPeerSerialNo: integer; override;
    /// <summary>Opt this connection into the OS system-trust anchors. Alone it verifies against
    /// the OS store; combined with a CertCAFile bundle it UNIONS the two (the "public web PKI +
    /// private CA" case). Synapse exposes no such switch, so it lives here; cast Sock.SSL to
    /// TSSLTlsLib to set it. System trust is never implicit - when VerifyCert is on you must
    /// name a source (this or CertCAFile) or the build fails closed. Per-connection (never a
    /// process-wide global), so it composes and stays thread-safe.</summary>
    property UseSystemTrust: Boolean read FUseSystemTrust write FUseSystemTrust;
    /// <summary>A fully-built client config that REPLACES the property-driven build: when set, the
    /// cert/trust properties (CertCAFile, CertificateFile, UseSystemTrust) are not allowed alongside
    /// it (the plugin raises). The escape hatch to the full builder API - cipher order, groups,
    /// resumption, ALPN. Cast Sock.SSL to TSSLTlsLib to set it.</summary>
    property ClientConfig: ITlsClientConfig read FClientConfig write FClientConfig;
    /// <summary>A fully-built server config that REPLACES the property-driven build (the server-side
    /// counterpart of ClientConfig; same conflict rule).</summary>
    property ServerConfig: ITlsServerConfig read FServerConfig write FServerConfig;
    /// <summary>The crypto provider the property-driven build uses (hashing, RNG, cert parsing).
    /// nil (the default) uses the process-wide shared default; set it to inject a custom backend
    /// (HSM, FIPS, a test mock). Not allowed alongside a supplied ClientConfig/ServerConfig, which
    /// carries its own provider. Cast Sock.SSL to TSSLTlsLib to set it.</summary>
    property Provider: ICryptoProvider read FUserProvider write FUserProvider;
    /// <summary>TLS session resumption (a server issues session tickets; a client caches and reuses
    /// them) so a reconnect skips the asymmetric handshake. Forward-secret (TLS 1.3 psk_dhe_ke);
    /// 0-RTT is never enabled. Default True; cast Sock.SSL to TSSLTlsLib to set it False.</summary>
    property SessionResumption: Boolean read FSessionResumption write FSessionResumption;
  end;

implementation

resourcestring
  SNoServerCredential = 'the Synapse SSL config supplies no server certificate/key';
  SPeerVerifyRejected = 'the OnVerifyCert handler rejected the peer certificate';
  SNoTrustSource = 'VerifyCert is on but no trust source was named; set a CertCAFile bundle ' +
    'and/or UseSystemTrust (system trust is never implicit), or set VerifyCert := False to skip';
  SConfigAndOptionsConflict = '%s is set together with cert/trust properties that a fully-built ' +
    'config replaces; supply either the config or the cert/trust properties, not both';

var
  // process-wide neutral hooks the per-socket plugin threads into each client handshake
  GVerifyCallback: TTlsCertificateVerifyCallback;
  GVerdictResolver: TTlsVerdictResolver;
  GVerdictDeadlineMs: Cardinal;
  // the plugin is created per socket, so the build-once memos live process-wide (like the hooks
  // above); keyed so several servers with different certs in one process do not thrash
  GServerConfigMemo: ITlsServerConfigMemo;
  GClientConfigMemo: ITlsClientConfigMemo;

procedure SetTlsLibSynapseVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback);
begin
  GVerifyCallback := ACallback;
end;

procedure SetTlsLibSynapseVerdictResolver(const AResolver: TTlsVerdictResolver;
  ADeadlineMs: Cardinal);
begin
  GVerdictResolver := AResolver;
  GVerdictDeadlineMs := ADeadlineMs;
end;

procedure FlushTlsLibSynapseConfigCache;
begin
  GServerConfigMemo.Clear;
  GClientConfigMemo.Clear;
end;

{ TSynapseSocketTransport }

constructor TSynapseSocketTransport.Create(AHandle: TSocket);
begin
  inherited Create;
  FHandle := AHandle;
end;

function TSynapseSocketTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := synsock.Recv(FHandle, @ABuffer[AOffset], AMaxLength, MSG_NOSIGNAL);
  if Result <= 0 then
    Result := 0; // <0 error or 0 orderly close: surface as EOF to the pump
end;

procedure TSynapseSocketTransport.Write(const ABuffer: TBytes; AOffset,
  ALength: Int32);
var
  LOff, LRemain, LN: Integer;
begin
  LOff := AOffset;
  LRemain := ALength;
  while LRemain > 0 do
  begin
    LN := synsock.Send(FHandle, @ABuffer[LOff], LRemain, MSG_NOSIGNAL);
    if LN <= 0 then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        'Synapse socket send returned no progress');
    Inc(LOff, LN);
    Dec(LRemain, LN);
  end;
end;

{ TSSLTlsLib }

constructor TSSLTlsLib.Create(const AValue: TTCPBlockSocket);
begin
  inherited Create(AValue);
  // secure by default: Synapse's TCustomSSL defaults VerifyCert to False (no verification); we flip
  // it to True so a dropped-in plugin verifies. Opt OUT with VerifyCert := False for the loud bypass.
  VerifyCert := True;
  FSessionResumption := True;
end;

destructor TSSLTlsLib.Destroy;
begin
  FStream.Free;
  inherited Destroy;
end;

function TSSLTlsLib.LibVersion: string;
begin
  Result := 'TlsLib4Pascal';
end;

function TSSLTlsLib.LibName: string;
begin
  Result := 'TlsLibSynapseTls';
end;

function TSSLTlsLib.LoadFileBytes(const APath: string): TBytes;
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

procedure TSSLTlsLib.GuardNoConflict(const APropertyName: string);
begin
  // a supplied config owns trust/credential entirely; naming these alongside it would be silently
  // dropped, so fail loud. The native OnVerifyCert hook and the process-wide verdict resolver are
  // runtime hooks (not part of the frozen config) and still apply, so they are not conflicts.
  if (FCertificateFile <> '') or (FPrivateKeyFile <> '') or (FCertCAFile <> '') or
    FUseSystemTrust or (FUserProvider <> nil) then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
      Format(SConfigAndOptionsConflict, [APropertyName]));
end;

function TSSLTlsLib.EffectiveProvider: ICryptoProvider;
begin
  if FUserProvider <> nil then
    Result := FUserProvider
  else
    Result := TDefaultCryptoProvider.Shared;
end;

function TSSLTlsLib.BuildClientConfig: ITlsClientConfig;
var
  LProvider: ICryptoProvider;
  LClient: ITlsClientConfigBuilder;
begin
  LProvider := EffectiveProvider;
  LClient := TTlsPresets.Compatible(LProvider).Client;
  // Synapse exposes no dedicated system-trust switch, so we compose peer trust from the props it
  // already has (CertCAFile + VerifyCert) plus our per-connection UseSystemTrust. System trust is
  // never implicit - it must be asked for:
  //   VerifyCert=False                             -> the loud InsecureSkipVerify bypass, never silent
  //   VerifyCert=True, CertCAFile set              -> pin to that CA bundle
  //   VerifyCert=True, UseSystemTrust              -> OS system-trust store
  //   VerifyCert=True, UseSystemTrust + CertCAFile -> UNION: system anchors PLUS the private bundle
  //   VerifyCert=True, neither                     -> fail closed (no implicit trust)
  // (OS store = Windows crypt32 / macOS SecTrust / Unix bundle.)
  if FVerifyCert then
  begin
    if (FCertCAFile = '') and (not FUseSystemTrust) then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoTrustSource);
    if FCertCAFile <> '' then
      LClient.WithTrustAnchors(LoadFileBytes(FCertCAFile));
    if FUseSystemTrust then
      TSystemTrust.WithSystemTrust(LClient, LProvider);
  end
  else
  begin
    // a client build still requires a trust source even when verification is skipped
    LClient.WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
    LClient.WithDangerousInsecureSkipVerify(True);
  end;
  if FCertificateFile <> '' then
    LClient.WithCredential(LoadFileBytes(FCertificateFile),
      LoadFileBytes(FPrivateKeyFile), FKeyPassword);
  // the process-wide neutral augment hook, and an out-of-band verdict resolver that parks
  // the handshake for a decision (live revocation etc.)
  if Assigned(GVerifyCallback) then
    LClient.WithCertificateVerifyCallback(GVerifyCallback);
  if Assigned(GVerdictResolver) then
    LClient.WithAsyncCertificateVerdict(True, GVerdictDeadlineMs);
  if FSessionResumption then
  begin
    LClient.WithResumption(True);
    LClient.WithSessionCache(TInMemorySessionCache.Shared);
  end
  else
    LClient.WithResumption(False);
  Result := LClient.Build;
end;

function TSSLTlsLib.BuildServerConfig: ITlsServerConfig;
var
  LProvider: ICryptoProvider;
  LServer: ITlsServerConfigBuilder;
begin
  // a clear message when no cert is configured, rather than an opaque file-open error
  // (DriveHandshake wraps this into FLastError/FLastErrorDesc - no exception escapes)
  if FCertificateFile = '' then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoServerCredential);
  LProvider := EffectiveProvider;
  LServer := TTlsPresets.Compatible(LProvider).Server
    .WithCredential(LoadFileBytes(FCertificateFile), LoadFileBytes(FPrivateKeyFile),
    FKeyPassword);
  if FSessionResumption then
  begin
    LServer.WithResumption(True);
    LServer.WithSessionTicketKeys(TStekTicketKeyManager.Shared);
  end
  else
    LServer.WithResumption(False);
  Result := LServer.Build;
end;

function TSSLTlsLib.ClientSignature: string;
var
  LSig: TTlsSignatureBuilder;
  LProvider: ICryptoProvider;
begin
  LProvider := EffectiveProvider;
  LSig := TTlsSignatureBuilder.Create(LProvider);
  LSig.AddPointer('provider', LProvider);
  LSig.AddFlag('resume', FSessionResumption);
  LSig.AddFile('cert', FCertificateFile);
  LSig.AddFile('key', FPrivateKeyFile);
  LSig.AddSecret('keypw', FKeyPassword);
  LSig.AddFile('ca', FCertCAFile);
  LSig.AddFlag('verifyCert', FVerifyCert);
  LSig.AddFlag('systemTrust', FUseSystemTrust);
  // the process-wide hooks are baked into the built config, so they belong in the key
  LSig.AddMethod('verifyCb', TMethod(GVerifyCallback));
  LSig.AddFlag('asyncVerdict', Assigned(GVerdictResolver));
  LSig.AddCardinal('deadline', GVerdictDeadlineMs);
  Result := LSig.Value;
end;

function TSSLTlsLib.ServerSignature: string;
var
  LSig: TTlsSignatureBuilder;
  LProvider: ICryptoProvider;
begin
  LProvider := EffectiveProvider;
  LSig := TTlsSignatureBuilder.Create(LProvider);
  LSig.AddPointer('provider', LProvider);
  LSig.AddFlag('resume', FSessionResumption);
  LSig.AddFile('cert', FCertificateFile);
  LSig.AddFile('key', FPrivateKeyFile);
  LSig.AddSecret('keypw', FKeyPassword);
  Result := LSig.Value;
end;

function TSSLTlsLib.BuildClientEngine: ITlsEngine;
var
  LCfg: ITlsClientConfig;
  LSig: string;
begin
  // a fully-built config supplied by the app REPLACES the property-driven build outright; naming
  // cert/trust properties alongside it fails loud rather than dropping them silently
  if FClientConfig <> nil then
  begin
    GuardNoConflict('ClientConfig');
    FProvider := FClientConfig.Provider;
    Exit(TTlsEngineFactory.CreateClientEngine(FClientConfig, FSNIHost));
  end;
  LSig := ClientSignature;
  if not GClientConfigMemo.TryGet(LSig, LCfg) then
    LCfg := GClientConfigMemo.StoreOrAdopt(LSig, BuildClientConfig);
  FProvider := LCfg.Provider; // the peer-info accessors reuse the config's provider
  Result := TTlsEngineFactory.CreateClientEngine(LCfg, FSNIHost);
end;

function TSSLTlsLib.BuildServerEngine: ITlsEngine;
var
  LCfg: ITlsServerConfig;
  LSig: string;
begin
  if FServerConfig <> nil then
  begin
    GuardNoConflict('ServerConfig');
    FProvider := FServerConfig.Provider;
    Exit(TTlsEngineFactory.CreateServerEngine(FServerConfig));
  end;
  LSig := ServerSignature;
  if not GServerConfigMemo.TryGet(LSig, LCfg) then
    LCfg := GServerConfigMemo.StoreOrAdopt(LSig, BuildServerConfig);
  FProvider := LCfg.Provider;
  Result := TTlsEngineFactory.CreateServerEngine(LCfg);
end;

function TSSLTlsLib.DriveHandshake(AIsClient: Boolean;
  const AHost: string): Boolean;
const
  HandshakeReadTimeoutMs = 20000;
begin
  Result := False;
  try
    // a reconnect reuses this TCustomSSL instance; drop any prior session so we rebuild on the
    // new socket cleanly instead of leaking the previous stream over a stale engine
    FStream.Free;
    FStream := nil;
    FTransport := nil;
    FEngine := nil;
    if AIsClient then
      FEngine := BuildClientEngine
    else
      FEngine := BuildServerEngine;
    FTransport := TSynapseSocketTransport.Create(FSocket.Socket) as ITlsTransport;
    FStream := TTlsStream.Create(FTransport, FEngine, AIsClient, AHost);
    if Assigned(GVerdictResolver) then
      FStream.SetCertificateVerdictResolver(GVerdictResolver);
    // a peer that connects but never sends its flight (a browser speculative/backup socket) must
    // not park this thread forever; SO_RCVTIMEO bounds the transport's blocking Recv during the
    // handshake (both share FSocket.Socket), then is cleared so application reads block normally
    FSocket.SetRecvTimeout(HandshakeReadTimeoutMs);
    try
      FStream.Handshake;
    finally
      FSocket.SetRecvTimeout(0);
    end;
    // Synapse's native OnVerifyCert hook (RFC-agnostic, no OpenSSL type): the app inspects
    // the peer via GetPeer* and returns False to reject - fail-closed
    if not RunPeerVerifyHook then
    begin
      FStream.CloseNotify;
      raise ETlsStreamError.Create(TTlsAlertDescription.BadCertificate,
        SPeerVerifyRejected);
    end;
    FSSLEnabled := True;
    Result := True;
  except
    on E: Exception do
    begin
      FLastError := 1;
      FLastErrorDesc := E.Message;
    end;
  end;
end;

function TSSLTlsLib.PeerLeaf: TBytes;
var
  LChain: TArray<TBytes>;
begin
  Result := nil;
  if FEngine = nil then
    Exit;
  LChain := FEngine.PeerCertificates;
  if System.Length(LChain) > 0 then
    Result := LChain[0];
end;

function TSSLTlsLib.RunPeerVerifyHook: Boolean;
begin
  // no hook set, or no peer certificate to judge, means nothing to add to the built-in verdict
  Result := True;
  if not Assigned(FOnVerifyCert) then
    Exit;
  if System.Length(PeerLeaf) = 0 then
    Exit;
  Result := FOnVerifyCert(Self);
end;

function TSSLTlsLib.Connect: boolean;
begin
  Result := DriveHandshake(True, FSNIHost);
end;

function TSSLTlsLib.Accept: boolean;
begin
  Result := DriveHandshake(False, '');
end;

function TSSLTlsLib.Shutdown: boolean;
begin
  if FStream <> nil then
    FStream.CloseNotify;
  FSSLEnabled := False;
  Result := True;
end;

function TSSLTlsLib.BiShutdown: boolean;
begin
  Result := Shutdown;
end;

function TSSLTlsLib.SendBuffer(Buffer: TMemory; Len: Integer): Integer;
begin
  // TCustomSSL is error-code based (like ssl_openssl): clear the error, and convert a fatal
  // engine/transport failure into a <=0 count + FLastError rather than letting it propagate
  FLastError := 0;
  FLastErrorDesc := '';
  try
    FStream.Write(PByte(Buffer)^, Len);
    Result := Len;
  except
    on E: Exception do
    begin
      FLastError := 1;
      FLastErrorDesc := E.Message;
      Result := -1; // Synapse treats <=0 as failure, mirroring ssl_openssl
    end;
  end;
end;

function TSSLTlsLib.RecvBuffer(Buffer: TMemory; Len: Integer): Integer;
begin
  FLastError := 0;
  FLastErrorDesc := '';
  try
    // a clean close_notify surfaces as 0 (no error), matching ssl_openssl's ZERO_RETURN path
    Result := FStream.Read(PByte(Buffer)^, Len);
  except
    on E: Exception do
    begin
      FLastError := 1;
      FLastErrorDesc := E.Message;
      Result := -1;
    end;
  end;
end;

function TSSLTlsLib.WaitingData: Integer;
begin
  if FStream <> nil then
    Result := FStream.PendingReadBytes
  else
    Result := 0;
end;

function TSSLTlsLib.GetSSLVersion: string;
begin
  if (FStream = nil) then
    Exit('');
  case FEngine.NegotiatedVersion.WireValue of
    TlsWireVersionTls13:
      Result := 'TLSv1.3';
    TlsWireVersionTls12:
      Result := 'TLSv1.2';
  else
    Result := '';
  end;
end;

function TSSLTlsLib.GetCipherName: string;
begin
  Result := GetSSLVersion;
end;

function TSSLTlsLib.NegotiatedCipherSuite: UInt16;
begin
  if FStream <> nil then
    Result := FEngine.NegotiatedCipherSuite
  else
    Result := 0;
end;

function TSSLTlsLib.GetPeerSubject: string;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
  LLeaf: TBytes;
begin
  Result := '';
  LLeaf := PeerLeaf;
  if (FProvider <> nil) and (System.Length(LLeaf) > 0) and
    FProvider.CertificatePeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) then
    Result := LSubject;
end;

function TSSLTlsLib.GetPeerIssuer: string;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
  LLeaf: TBytes;
begin
  Result := '';
  LLeaf := PeerLeaf;
  if (FProvider <> nil) and (System.Length(LLeaf) > 0) and
    FProvider.CertificatePeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) then
    Result := LIssuer;
end;

function TSSLTlsLib.GetPeerName: string;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
  LLeaf: TBytes;
begin
  Result := '';
  LLeaf := PeerLeaf;
  if (FProvider <> nil) and (System.Length(LLeaf) > 0) and
    FProvider.CertificatePeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) then
    Result := LCommonName;
end;

function TSSLTlsLib.GetPeerFingerprint: AnsiString;
var
  LLeaf, LDigest: TBytes;
  LHash: IHash;
begin
  // the SHA-256 fingerprint of the leaf DER, lowercase hex (a fingerprint is a hash; the
  // exact digest is adapter convention)
  Result := '';
  LLeaf := PeerLeaf;
  if (FProvider = nil) or (System.Length(LLeaf) = 0) then
    Exit;
  LHash := FProvider.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LLeaf, 0, System.Length(LLeaf));
  LDigest := LHash.DoFinal;
  Result := AnsiString(TDataEncoding.HexEncode(LDigest));
end;

function TSSLTlsLib.GetPeerSerialNo: integer;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
  LLeaf: TBytes;
begin
  Result := 0;
  LLeaf := PeerLeaf;
  if (FProvider <> nil) and (System.Length(LLeaf) > 0) and
    FProvider.CertificatePeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) and
    (LSerialHex <> '') then
    // a serial can exceed 32 bits; take the low 8 hex digits Synapse's integer can hold
    Result := Integer(StrToInt64Def('$' +
      Copy(LSerialHex, System.Length(LSerialHex) - 7, 8), 0));
end;

initialization
  SSLImplementation := TSSLTlsLib;
  GServerConfigMemo := NewTlsServerConfigMemo;
  GClientConfigMemo := NewTlsClientConfigMemo;

end.
