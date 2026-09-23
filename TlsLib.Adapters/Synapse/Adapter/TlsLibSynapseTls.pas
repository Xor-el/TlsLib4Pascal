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
/// types and Synapse's types meet: it maps Synapse's TCustomSSL properties onto the host-neutral
/// adapter core (config composition, timed transport, session drive) and supplies the Synapse
/// socket glue.
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
  TlpTlsAlert,
  TlpEchConfig,
  TlpCryptoDomainTypes,
  TlpDataEncoding,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfigMemo,
  TlpTlsConfigMemo,
  TlpTlsLibExceptions,
  TlpTlsConnection,
  TlpSystemTrustFacade;

/// <summary>Sets a process-wide augment-only verify callback the plugin threads into every
/// client handshake (it runs after the built-in pipeline and can only additionally reject).
/// nil clears it. The Synapse plugin is created per socket by SSLImplementation, so its
/// neutral (non-TCustomSSL) hooks are configured through these unit-level setters.</summary>
procedure SetTlsLibSynapseVerifyCallback(const ACallback: TTlsCertificateVerifyCallback);
/// <summary>Sets a process-wide out-of-band verdict resolver for the CLIENT role (e.g. live
/// OCSP/CRL over the SERVER's chain): when set, every client handshake parks after the pipeline
/// accepts the server chain and this decides it. Pair it with a client-config resolver (binds
/// server-auth EKU). For an mTLS server that must vet the CLIENT chain, use
/// SetTlsLibSynapseServerVerdictResolver - the two roles evaluate different EKUs, so one resolver
/// cannot serve both. ADeadlineMs is the resolver's fetch budget. nil clears it.</summary>
procedure SetTlsLibSynapseVerdictResolver(const AResolver: TCertificateVerdictResolver;
  ADeadlineMs: Cardinal);
/// <summary>Sets a process-wide out-of-band verdict resolver for the SERVER role (live revocation
/// over an mTLS CLIENT's chain): when set, a server handshake that requests a client certificate
/// parks after the pipeline accepts the client chain and this decides it. Pair it with a
/// server-config resolver (binds client-auth EKU). ADeadlineMs is the resolver's fetch budget.
/// nil clears it.</summary>
procedure SetTlsLibSynapseServerVerdictResolver(
  const AResolver: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
/// <summary>Clears the process-wide build-once config caches so the next handshake rebuilds from
/// current inputs. Call after rotating a certificate/key to purge the retired credential (a cached
/// config holds its private key alive). Call only with no TLS traffic in flight.</summary>
procedure FlushTlsLibSynapseConfigCache;

type
  /// <summary>An ITlsTransport over a Synapse block socket: raw ciphertext moves through synsock
  /// Recv/Send on the socket handle, bypassing TTCPBlockSocket's SSL-aware buffered methods
  /// (which would otherwise recurse back into this plugin once SSLEnabled is set). The
  /// handshake-phase read cap comes from the shared timed-transport base; readiness is polled with
  /// CanRead so no socket option (which Synapse cannot read back to restore) is touched.</summary>
  TSynapseSocketTransport = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FSocket: TTCPBlockSocket;
  strict protected
    function WaitReadable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(const ASocket: TTCPBlockSocket);
  end;

  /// <summary>
  /// TlsLib4Pascal's implementation of Synapse's TCustomSSL. Connect / Accept run the
  /// handshake; SendBuffer / RecvBuffer move application data; WaitingData reports buffered
  /// plaintext; Shutdown / BiShutdown send close_notify. It maps the TCustomSSL properties
  /// (cert/key files, CA, VerifyCert, SNIHost) plus the per-connection extras Synapse lacks
  /// (UseSystemTrust, a supplied config, Crypto/Pkix, resumption, the handshake read cap) onto the
  /// host-neutral adapter core.
  /// </summary>
  TSSLTlsLib = class(TCustomSSL)
  strict private
  var
    FConnection: TTlsConnection;
    FCrypto: ICryptoProvider;
    FUserCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    FUserPkix: IPkixProvider;
    FUseSystemTrust: Boolean;
    FSessionResumption: Boolean;
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
    FHandshakeTimeoutMs: Integer;
    /// <summary>The host-neutral snapshot the adapter core composes into a TLS configuration: one
    /// value per handshake, so a property changed mid-connection is never seen half-applied. The
    /// role (client vs server) is chosen by the caller when it resolves the config and attaches the
    /// resolver, not here.</summary>
    function Snapshot: TTlsOptions;
    function BuildClientEngine: ITlsEngine;
    function BuildServerEngine: ITlsEngine;
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
    /// <summary>The negotiated named group (key_share curve) wire codepoint once the handshake
    /// completes (0 if none). Cast Sock.SSL to TSSLTlsLib to read it.</summary>
    function NegotiatedGroup: UInt16;
    /// <summary>The SNI server_name for this connection: the host a client requested (server side)
    /// or the host we sent (client side); empty when none. Cast Sock.SSL to TSSLTlsLib to read it.</summary>
    function PeerServerName: string;
    /// <summary>The Encrypted Client Hello outcome for this connection (RFC 9849).</summary>
    function EchStatus: TEchStatus;
    /// <summary>Whether this connection resumed an earlier session rather than doing a full
    /// handshake (RFC 8446 2.2 / RFC 5246 7.3). Cast Sock.SSL to TSSLTlsLib to read it.</summary>
    function Resumed: Boolean;
    // native peer-certificate accessors an OnVerifyCert handler reads
    function GetPeerSubject: string; override;
    function GetPeerIssuer: string; override;
    function GetPeerName: string; override;
    function GetPeerFingerprint: AnsiString; override;
    function GetPeerSerialNo: integer; override;
    /// <summary>Opt this connection into the OS system-trust anchors. On a client it trusts the
    /// server's chain against the OS store; on a server with VerifyCert it trusts an mTLS client's
    /// chain against the OS store too - a very broad surface, since client certificates normally
    /// chain to a private CA (prefer CertCAFile there). Alone it verifies against the OS store;
    /// combined with a CertCAFile bundle it UNIONS the two. Synapse exposes no such switch, so it
    /// lives here; cast Sock.SSL to TSSLTlsLib to set it. System trust is never implicit - when
    /// VerifyCert is on you must name a source (this or CertCAFile) or the build fails closed.
    /// Per-connection, never a process-wide global, so it composes and stays thread-safe.</summary>
    property UseSystemTrust: Boolean read FUseSystemTrust write FUseSystemTrust;
    /// <summary>A fully-built client config that REPLACES the property-driven build: when set, the
    /// cert/trust properties (CertCAFile, CertificateFile, UseSystemTrust) are not allowed alongside
    /// it (the plugin raises). The verdict resolver still applies, but only if this config armed the
    /// deferral (WithLiveRevocationVerdict/WithAsyncCertificateVerdict) - else the handshake never
    /// parks. The escape hatch to the full builder API - cipher order, groups, resumption, ALPN.
    /// Cast Sock.SSL to TSSLTlsLib to set it.</summary>
    property ClientConfig: ITlsClientConfig read FClientConfig write FClientConfig;
    /// <summary>A fully-built server config that REPLACES the property-driven build (the server-side
    /// counterpart of ClientConfig; same conflict rule).</summary>
    property ServerConfig: ITlsServerConfig read FServerConfig write FServerConfig;
    /// <summary>The crypto provider the property-driven build uses (hashing, RNG, cert parsing).
    /// nil (the default) uses the process-wide shared default; set it to inject a custom backend
    /// (HSM, FIPS, a test mock). Not allowed alongside a supplied ClientConfig/ServerConfig, which
    /// carries its own provider. Cast Sock.SSL to TSSLTlsLib to set it.</summary>
    property Crypto: ICryptoProvider read FUserCrypto write FUserCrypto;
    /// <summary>The PKIX provider the property-driven build uses (certificate parsing, path
    /// validation, revocation). nil (the default) uses the process-wide shared default; set it to
    /// inject a custom backend. Not allowed alongside a supplied ClientConfig/ServerConfig, which
    /// carries its own PKIX provider. Cast Sock.SSL to TSSLTlsLib to set it.</summary>
    property Pkix: IPkixProvider read FUserPkix write FUserPkix;
    /// <summary>TLS session resumption (a server issues session tickets; a client caches and reuses
    /// them) so a reconnect skips the asymmetric handshake. Forward-secret (TLS 1.3 psk_dhe_ke);
    /// 0-RTT is never enabled. Default True; cast Sock.SSL to TSSLTlsLib to set it False.</summary>
    property SessionResumption: Boolean read FSessionResumption write FSessionResumption;
    /// <summary>The read timeout (ms) bounding the handshake, so a peer that connects but sends no
    /// data cannot park the connection's thread. Deliberately NOT an app-read deadline. 0 (the
    /// default) uses the 30 s library default; a positive value overrides it. Cast Sock.SSL to
    /// TSSLTlsLib to set it.</summary>
    property HandshakeTimeoutMs: Integer read FHandshakeTimeoutMs write FHandshakeTimeoutMs;
  end;

implementation

resourcestring
  SPeerVerifyRejected = 'the OnVerifyCert handler rejected the peer certificate';
  SSynapseSendNoProgress = 'Synapse socket send returned no progress';
  SSynapseTrustSourceHint = 'a CertCAFile bundle and/or UseSystemTrust';

var
  // process-wide neutral hooks the per-socket plugin threads into each client handshake
  GVerifyCallback: TTlsCertificateVerifyCallback;
  // the client-role resolver evaluates the server's chain; the server-role resolver an mTLS
  // client's chain. They bind different EKUs, so the two roles keep separate hooks
  GVerdictResolver: TCertificateVerdictResolver;
  GVerdictDeadlineMs: Cardinal;
  GServerVerdictResolver: TCertificateVerdictResolver;
  GServerVerdictDeadlineMs: Cardinal;
  // the plugin is created per socket, so the build-once memos live process-wide (like the hooks
  // above); keyed so several servers with different certs in one process do not thrash
  GServerConfigMemo: ITlsServerConfigMemo;
  GClientConfigMemo: ITlsClientConfigMemo;

procedure SetTlsLibSynapseVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback);
begin
  GVerifyCallback := ACallback;
end;

procedure SetTlsLibSynapseVerdictResolver(const AResolver: TCertificateVerdictResolver;
  ADeadlineMs: Cardinal);
begin
  GVerdictResolver := AResolver;
  GVerdictDeadlineMs := ADeadlineMs;
end;

procedure SetTlsLibSynapseServerVerdictResolver(
  const AResolver: TCertificateVerdictResolver; ADeadlineMs: Cardinal);
begin
  GServerVerdictResolver := AResolver;
  GServerVerdictDeadlineMs := ADeadlineMs;
end;

procedure FlushTlsLibSynapseConfigCache;
begin
  GServerConfigMemo.Clear;
  GClientConfigMemo.Clear;
end;

{ TSynapseSocketTransport }

constructor TSynapseSocketTransport.Create(const ASocket: TTCPBlockSocket);
begin
  inherited Create;
  FSocket := ASocket;
end;

function TSynapseSocketTransport.WaitReadable(AMs: Int32): Boolean;
begin
  Result := FSocket.CanRead(AMs);
end;

function TSynapseSocketTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  // 0 on an orderly close and a negative error both surface as end-of-stream to the pump (the base
  // coerces the negative to 0)
  Result := synsock.Recv(FSocket.Socket, @ABuffer[AOffset], AMaxLength, MSG_NOSIGNAL);
end;

function TSynapseSocketTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  Result := synsock.Send(FSocket.Socket, @ABuffer[AOffset], ALength, MSG_NOSIGNAL);
  if Result <= 0 then
    raise ETlsStreamError.Create(SSynapseSendNoProgress);
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
  FConnection.Free;
  FConnection := nil;
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

function TSSLTlsLib.Snapshot: TTlsOptions;
begin
  Result := TTlsOptions.Default;
  Result.Crypto := FUserCrypto;
  Result.Pkix := FUserPkix;
  Result.Certificate := TTlsBlobSource.FromFile(FCertificateFile);
  Result.PrivateKey := TTlsBlobSource.FromFile(FPrivateKeyFile);
  Result.KeyPassword := FKeyPassword;
  // Synapse gates trust on its native VerifyCert: a CertCAFile bundle and UseSystemTrust are trust
  // sources only when verifying, so a skip-verify client names none (kept off HasClientTrustSource).
  // UseSystemTrust reaches the OS store through the host-neutral installer seam, so the core never
  // depends on the system-trust package.
  if FVerifyCert then
  begin
    if FCertCAFile <> '' then
    begin
      SetLength(Result.TrustAnchors, 1);
      Result.TrustAnchors[0] := TTlsBlobSource.FromFile(FCertCAFile);
    end;
    if FUseSystemTrust then
      Result.SystemTrust := TSystemTrustInstaller.Create as ISystemTrustInstaller;
  end;
  Result.VerifyPeer := FVerifyCert;
  Result.InsecureSkipVerify := not FVerifyCert;
  // CheckHostName keeps the composable default (True); Synapse exposes no knob. VerifyCert on a
  // server requests (does not require) a client certificate, so the client-auth mode is Requested.
  Result.ClientAuth := TClientAuthMode.Requested;
  Result.VerifyCallback := GVerifyCallback;
  Result.ClientVerdictResolver := GVerdictResolver;
  Result.ClientVerdictDeadlineMs := GVerdictDeadlineMs;
  Result.ServerVerdictResolver := GServerVerdictResolver;
  Result.ServerVerdictDeadlineMs := GServerVerdictDeadlineMs;
  Result.SessionResumption := FSessionResumption;
  Result.HandshakeTimeoutMs := FHandshakeTimeoutMs;
  Result.ClientConfig := FClientConfig;
  Result.ServerConfig := FServerConfig;
  Result.TrustSourceHint := SSynapseTrustSourceHint;
end;

function TSSLTlsLib.BuildClientEngine: ITlsEngine;
var
  LOptions: TTlsOptions;
  LConfig: ITlsClientConfig;
begin
  LOptions := Snapshot;
  // a fully-built config supplied by the app REPLACES the property-driven build outright; the
  // composer's conflict guard fails loud when cert/trust properties are named alongside it
  LConfig := TTlsConfigComposer.ResolveClientConfig(LOptions, GClientConfigMemo,
    'ClientConfig');
  // the peer-info accessors reuse the config's providers (crypto for hashing, pkix for parsing)
  FCrypto := LConfig.Crypto;
  FPkix := LConfig.Pkix;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, FSNIHost);
end;

function TSSLTlsLib.BuildServerEngine: ITlsEngine;
var
  LOptions: TTlsOptions;
  LConfig: ITlsServerConfig;
begin
  LOptions := Snapshot;
  LConfig := TTlsConfigComposer.ResolveServerConfig(LOptions, GServerConfigMemo,
    'ServerConfig');
  FCrypto := LConfig.Crypto;
  FPkix := LConfig.Pkix;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TSSLTlsLib.DriveHandshake(AIsClient: Boolean;
  const AHost: string): Boolean;
var
  LEngine: ITlsEngine;
  LResolver: TCertificateVerdictResolver;
begin
  Result := False;
  try
    // a reconnect reuses this TCustomSSL instance; drop any prior session so we rebuild on the
    // new socket cleanly instead of leaking the previous stream over a stale engine
    FConnection.Free;
    FConnection := nil;
    if AIsClient then
      LEngine := BuildClientEngine
    else
      LEngine := BuildServerEngine;
    // attach the role-correct resolver: a client parks on the server's chain, a server (client
    // auth) on the mTLS client's chain - the two bind different EKUs
    if AIsClient then
      LResolver := GVerdictResolver
    else
      LResolver := GServerVerdictResolver;
    FConnection := TTlsConnection.Create(LEngine,
      TSynapseSocketTransport.Create(FSocket), AIsClient, AHost, LResolver);
    // bound the handshake read by HandshakeTimeoutMs; the session arms and clears the cap, even
    // when the handshake raised, so a later app read is not left bounded
    FConnection.Handshake(FHandshakeTimeoutMs);
    // Synapse's native OnVerifyCert hook: the app inspects the peer via GetPeer* and returns
    // False to reject - fail-closed
    if not RunPeerVerifyHook then
    begin
      FConnection.CloseNotify;
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
begin
  if FConnection <> nil then
    Result := FConnection.PeerLeaf
  else
    Result := nil;
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
  // best-effort: a close_notify write to a peer that already closed must not raise here
  if FConnection <> nil then
    FConnection.CloseNotifyQuietly;
  FSSLEnabled := False;
  Result := True;
end;

function TSSLTlsLib.BiShutdown: boolean;
begin
  Result := Shutdown;
end;

function TSSLTlsLib.SendBuffer(Buffer: TMemory; Len: Integer): Integer;
begin
  // TCustomSSL is error-code based: clear the error, and convert a fatal engine/transport
  // failure into a <=0 count + FLastError rather than letting it propagate
  FLastError := 0;
  FLastErrorDesc := '';
  try
    FConnection.Write(PByte(Buffer)^, Len);
    Result := Len;
  except
    on E: Exception do
    begin
      FLastError := 1;
      FLastErrorDesc := E.Message;
      Result := -1; // Synapse treats <=0 as failure
    end;
  end;
end;

function TSSLTlsLib.RecvBuffer(Buffer: TMemory; Len: Integer): Integer;
begin
  FLastError := 0;
  FLastErrorDesc := '';
  try
    // a clean close_notify surfaces as 0 (no error)
    Result := FConnection.Read(PByte(Buffer)^, Len);
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
  if FConnection <> nil then
    Result := FConnection.PendingReadBytes
  else
    Result := 0;
end;

function TSSLTlsLib.GetSSLVersion: string;
begin
  if FConnection <> nil then
    Result := FConnection.VersionName
  else
    Result := '';
end;

function TSSLTlsLib.GetCipherName: string;
begin
  Result := GetSSLVersion;
end;

function TSSLTlsLib.NegotiatedCipherSuite: UInt16;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedCipherSuite
  else
    Result := 0;
end;

function TSSLTlsLib.NegotiatedGroup: UInt16;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedGroup
  else
    Result := 0;
end;

function TSSLTlsLib.PeerServerName: string;
begin
  if FConnection <> nil then
    Result := FConnection.PeerServerName
  else
    Result := '';
end;

function TSSLTlsLib.EchStatus: TEchStatus;
begin
  if FConnection <> nil then
    Result := FConnection.EchStatus
  else
    Result := TEchStatus.NotOffered;
end;

function TSSLTlsLib.Resumed: Boolean;
begin
  if FConnection <> nil then
    Result := FConnection.Resumed
  else
    Result := False;
end;

function TSSLTlsLib.GetPeerSubject: string;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
  LLeaf: TBytes;
begin
  Result := '';
  LLeaf := PeerLeaf;
  if (FPkix <> nil) and (System.Length(LLeaf) > 0) and
    FPkix.Certificates.PeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) then
    Result := LSubject;
end;

function TSSLTlsLib.GetPeerIssuer: string;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
  LLeaf: TBytes;
begin
  Result := '';
  LLeaf := PeerLeaf;
  if (FPkix <> nil) and (System.Length(LLeaf) > 0) and
    FPkix.Certificates.PeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) then
    Result := LIssuer;
end;

function TSSLTlsLib.GetPeerName: string;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
  LLeaf: TBytes;
begin
  Result := '';
  LLeaf := PeerLeaf;
  if (FPkix <> nil) and (System.Length(LLeaf) > 0) and
    FPkix.Certificates.PeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) then
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
  if (FCrypto = nil) or (System.Length(LLeaf) = 0) then
    Exit;
  LHash := FCrypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
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
  if (FPkix <> nil) and (System.Length(LLeaf) > 0) and
    FPkix.Certificates.PeerInfo(LLeaf, LSubject, LIssuer, LCommonName, LSerialHex) and
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
