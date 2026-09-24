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
/// The Indy integration adapter: drives TlsLib4Pascal's managed TLS engine behind Indy's
/// TIdSSLIOHandlerSocketBase / TIdServerIOHandlerSSLBase "swap-your-SSL" seam. Drop a
/// TTlsLibIOHandlerSocket into a TIdTCPClient.IOHandler (or a TTlsLibServerIOHandler into a
/// TIdTCPServer.IOHandler) and existing code gets our managed TLS - no OpenSSL. This unit
/// is the only place our types and Indy's types meet: it maps Indy's SSLOptions onto the
/// host-neutral adapter core (config composition, timed transport, session drive) and supplies
/// the Indy socket glue.
/// </summary>
unit TlsLibIndyTls;

{$I ..\..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  Classes,
  SysUtils,
  SyncObjs,
  IdGlobal,
  IdSSL,
  IdIOHandler,
  IdSocketHandle,
  IdThread,
  IdYarn,
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
  /// <summary>The TLS settings an Indy integrator sets on the adapter (the neutral analogue
  /// of Indy's OpenSSL SSLOptions): the cert/key/CA files and the verify posture. Indy's SSL
  /// base carries no trust surface (RootCertFile/VerifyMode live only on its OpenSSL handler),
  /// so this class is ours. Peer trust composes from orthogonal sources - a RootCertFile bundle,
  /// UseSystemTrust for the OS anchors, and/or an injected CustomTrustStore all UNION; a
  /// custom verifier replaces the pipeline outright. System trust is never implicit.</summary>
  TTlsLibSSLOptions = class(TPersistent)
  strict private
  var
    FCertFile: string;
    FKeyFile: string;
    FKeyPassword: string;
    FRootCertFile: string;
    FVerifyPeer: Boolean;
    FInsecureSkipVerify: Boolean;
    FUseSystemTrust: Boolean;
    FCustomTrustStore: ITrustAnchorStore;
    FCustomServerCertVerifier: IServerCertificateVerifier;
    FCustomClientCertVerifier: IClientCertificateVerifier;
    FVerifyCallback: TTlsCertificateVerifyCallback;
    FVerdictResolver: TCertificateVerdictResolver;
    FVerdictDeadlineMs: Cardinal;
    FServerVerdictResolver: TCertificateVerdictResolver;
    FServerVerdictDeadlineMs: Cardinal;
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
    FCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    FSessionResumption: Boolean;
    FHandshakeTimeoutMs: Integer;
  public
    constructor Create;
    procedure Assign(ASource: TPersistent); override;
    /// <summary>The host-neutral snapshot the adapter core composes into a TLS configuration: one
    /// value per handshake, so a design-time property changed mid-connection is never seen
    /// half-applied. The role (client vs server) is chosen by the caller when it resolves the
    /// config and attaches the resolver, not here.</summary>
    function Snapshot: TTlsOptions;
    /// <summary>A fully-built client config that REPLACES the options-driven build: when set, the
    /// cert/trust options here are not allowed alongside it (the adapter raises). The verdict
    /// resolvers (VerdictResolver/ServerVerdictResolver and their deadlines) are the exception -
    /// runtime stream hooks, not part of the frozen config - and still apply, provided the supplied
    /// config itself armed the deferral (WithLiveRevocationVerdict/WithAsyncCertificateVerdict);
    /// otherwise the handshake never parks and the resolver never fires. The escape hatch to the
    /// full builder API (cipher order, groups, resumption, ALPN, ...).</summary>
    property ClientConfig: ITlsClientConfig read FClientConfig write FClientConfig;
    /// <summary>A fully-built server config that REPLACES the options-driven build (the server-side
    /// counterpart of ClientConfig; same conflict rule).</summary>
    property ServerConfig: ITlsServerConfig read FServerConfig write FServerConfig;
    /// <summary>The crypto provider the options-driven build uses (hashing, RNG, cert parsing).
    /// nil (the default) uses the process-wide shared default. Set it to inject a custom backend
    /// (HSM, FIPS, a test mock). Not allowed alongside a supplied ClientConfig/ServerConfig, which
    /// carries its own provider.</summary>
    property Crypto: ICryptoProvider read FCrypto write FCrypto;
    /// <summary>The PKIX provider the options-driven build uses (certificate parsing, path
    /// validation, revocation). nil (the default) uses the process-wide shared default. Set it to
    /// inject a custom backend. Not allowed alongside a supplied ClientConfig/ServerConfig, which
    /// carries its own PKIX provider.</summary>
    property Pkix: IPkixProvider read FPkix write FPkix;
    /// <summary>An augment-only peer-certificate hook: it runs after the built-in pipeline and
    /// can only additionally reject (never loosen it). The neutral bridge for an app's own
    /// verify rule.</summary>
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
    /// <summary>An injected anchor store; when set it UNIONS with RootCertFile and UseSystemTrust
    /// (e.g. a fully custom root set alongside the OS anchors).</summary>
    property CustomTrustStore: ITrustAnchorStore read FCustomTrustStore
      write FCustomTrustStore;
    /// <summary>A whole-verifier for the peer SERVER certificate (client connections) that
    /// REPLACES the built-in pipeline outright (exclusive of every anchor source - RootCertFile,
    /// UseSystemTrust, CustomTrustStore).</summary>
    property CustomServerCertificateVerifier: IServerCertificateVerifier
      read FCustomServerCertVerifier write FCustomServerCertVerifier;
    /// <summary>A whole-verifier for the peer CLIENT certificate (mTLS server connections) that
    /// REPLACES the built-in pipeline outright.</summary>
    property CustomClientCertificateVerifier: IClientCertificateVerifier
      read FCustomClientCertVerifier write FCustomClientCertVerifier;
  published
    property CertFile: string read FCertFile write FCertFile;
    property KeyFile: string read FKeyFile write FKeyFile;
    property KeyPassword: string read FKeyPassword write FKeyPassword;
    property RootCertFile: string read FRootCertFile write FRootCertFile;
    /// <summary>Whether the peer certificate is verified (a server verifies a requested
    /// client certificate). Default True.</summary>
    property VerifyPeer: Boolean read FVerifyPeer write FVerifyPeer;
    /// <summary>DANGEROUS: accept the peer chain with no PKIX/host/pinning checks. For tests and
    /// pinned/self-signed development peers only - never production.</summary>
    property InsecureSkipVerify: Boolean read FInsecureSkipVerify write FInsecureSkipVerify;
    /// <summary>Opt into the OS system-trust anchors (Windows crypt32 / macOS SecTrust / Unix
    /// bundle). Unions with RootCertFile and any CustomTrustStore. System trust is never implicit:
    /// when VerifyPeer is on you must name at least one source or the build fails closed. Defaults
    /// to False.</summary>
    property UseSystemTrust: Boolean read FUseSystemTrust write FUseSystemTrust;
    /// <summary>TLS session resumption (a server issues session tickets; a client caches and
    /// reuses them), so a reconnect skips the asymmetric handshake. Forward-secret (TLS 1.3
    /// psk_dhe_ke); 0-RTT is never enabled. Default True; set False to force a full handshake
    /// every connection.</summary>
    property SessionResumption: Boolean read FSessionResumption write FSessionResumption default True;
    /// <summary>The read timeout (ms) bounding the server/client handshake, so a peer that
    /// connects but sends no data cannot park the connection's thread. Deliberately NOT
    /// IOHandler.ReadTimeout (that is an app-read deadline). 0 (default) uses the 30 s library
    /// default; set a positive value to override.</summary>
    property HandshakeTimeoutMs: Integer read FHandshakeTimeoutMs write FHandshakeTimeoutMs;
  end;

  /// <summary>An ITlsTransport over an Indy socket binding: raw ciphertext moves through the
  /// binding's blocking Receive/Send, and the handshake-phase read cap comes from the shared
  /// timed-transport base.</summary>
  TIndySocketTransport = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FBinding: TIdSocketHandle;
  strict protected
    function WaitReadable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(ABinding: TIdSocketHandle);
  end;

  /// <summary>
  /// The Indy client (and server-peer) SSL IOHandler backed by TlsLib4Pascal. StartSSL runs
  /// the handshake over the underlying socket; SendEnc / RecvEnc move application data;
  /// PassThrough is honoured so STARTTLS defers the handshake until it is turned off.
  /// </summary>
  TTlsLibIOHandlerSocket = class(TIdSSLIOHandlerSocketBase)
  strict private
  var
    FOptions: TTlsLibSSLOptions;
    FConnection: TTlsConnection;
    FServerMemo: ITlsServerConfigMemo;   // shared with the listener; server peers reuse one config
    FHandshakeLock: TCriticalSection;    // serializes the deferred first-touch handshake
    procedure DoHandshake;
    procedure ResetTlsSession;
    function BuildEngine(AIsClient: Boolean): ITlsEngine;
  private
    /// <summary>The listener hands each server peer its shared config memo (same-unit only).</summary>
    procedure AdoptServerMemo(const AMemo: ITlsServerConfigMemo);
    /// <summary>Marks a just-accepted server peer as TLS-wanted WITHOUT handshaking, so the
    /// handshake defers off the shared listener thread to this peer's own worker thread at
    /// first RecvEnc/SendEnc (same-unit only; called from the server IOHandler's Accept).</summary>
    procedure PrepareServerHandshakeDeferred;
  protected
    procedure InitComponent; override;
    procedure SetPassThrough(const AValue: Boolean); override;
    function RecvEnc(var ABuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;
  public
    destructor Destroy; override;
    function Readable(AMSec: Integer): Boolean; override;
    /// <summary>Sends a TLS close_notify (best-effort, half-close) before the socket is torn down,
    /// so a strict peer sees a clean shutdown instead of a truncation (RFC 8446 6.1).</summary>
    procedure Close; override;
    function Clone: TIdSSLIOHandlerSocketBase; override;
    procedure StartSSL; override;
    procedure ConnectClient; override;
    procedure AfterAccept; override;
    /// <summary>The negotiated protocol version once the handshake completes.</summary>
    function NegotiatedVersion: TTlsVersion;
    /// <summary>The negotiated cipher-suite wire codepoint once the handshake completes (0 if none).</summary>
    function NegotiatedCipherSuite: UInt16;
    /// <summary>The negotiated named group (key_share curve) wire codepoint once the handshake
    /// completes (0 if none).</summary>
    function NegotiatedGroup: UInt16;
    /// <summary>The SNI server_name for this connection once the handshake completes: the host a
    /// client requested (server side) or the host we sent (client side); empty when none.</summary>
    function PeerServerName: string;
    /// <summary>The Encrypted Client Hello outcome for this connection (RFC 9849): Accepted when
    /// ECH was offered and the inner ClientHello was used, Rejected/Greased/NotOffered otherwise.</summary>
    function EchStatus: TEchStatus;
    /// <summary>Whether this connection resumed an earlier session rather than doing a full
    /// handshake (RFC 8446 2.2 / RFC 5246 7.3).</summary>
    function Resumed: Boolean;
    /// <summary>Clears the process-wide client config cache (shared by all handlers), so the next
    /// connect rebuilds from current SSLOptions; this also drops the cached sessions those configs
    /// owned. Call after rotating the client credential to purge the retired key.</summary>
    class procedure FlushConfigCache;
  published
    property SSLOptions: TTlsLibSSLOptions read FOptions;
  end;

  /// <summary>The Indy server SSL IOHandler: it accepts a connection, wraps it in a peer
  /// TTlsLibIOHandlerSocket sharing this server's SSLOptions, and runs the server handshake.</summary>
  TTlsLibServerIOHandler = class(TIdServerIOHandlerSSLBase)
  strict private
  var
    FOptions: TTlsLibSSLOptions;
    FServerMemo: ITlsServerConfigMemo;   // the listener builds its server config once, all peers reuse it
  protected
    procedure InitComponent; override;
  public
    destructor Destroy; override;
    function Accept(ASocket: TIdSocketHandle; AListenerThread: TIdThread;
      AYarn: TIdYarn): TIdIOHandler; override;
    function MakeClientIOHandler: TIdSSLIOHandlerSocketBase; override;
    function MakeFTPSvrPort: TIdSSLIOHandlerSocketBase; override;
    function MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase; override;
    /// <summary>Clears the build-once server config cache shared by this listener's peers, so the
    /// next accepted connection rebuilds from current SSLOptions. Call after rotating the server
    /// certificate/key to purge the retired credential (a cached config holds its private key alive).</summary>
    procedure FlushConfigCache;
  published
    property SSLOptions: TTlsLibSSLOptions read FOptions;
  end;

implementation

var
  // process-global so handlers sharing a trust config reuse one frozen config and its session cache
  GClientConfigMemo: ITlsClientConfigMemo;

resourcestring
  SIndyTrustSourceHint =
    'a RootCertFile bundle, UseSystemTrust, or a CustomTrustStore/custom verifier';
  SIndySendNoProgress = 'Indy socket send returned no progress';

{ TTlsLibSSLOptions }

constructor TTlsLibSSLOptions.Create;
begin
  inherited Create;
  FVerifyPeer := True;
  FInsecureSkipVerify := False;
  FUseSystemTrust := False;
  FSessionResumption := True;
end;

procedure TTlsLibSSLOptions.Assign(ASource: TPersistent);
var
  LSrc: TTlsLibSSLOptions;
begin
  if ASource is TTlsLibSSLOptions then
  begin
    LSrc := TTlsLibSSLOptions(ASource);
    FCertFile := LSrc.FCertFile;
    FKeyFile := LSrc.FKeyFile;
    FKeyPassword := LSrc.FKeyPassword;
    FRootCertFile := LSrc.FRootCertFile;
    FVerifyPeer := LSrc.FVerifyPeer;
    FInsecureSkipVerify := LSrc.FInsecureSkipVerify;
    FUseSystemTrust := LSrc.FUseSystemTrust;
    FCustomTrustStore := LSrc.FCustomTrustStore;
    FCustomServerCertVerifier := LSrc.FCustomServerCertVerifier;
    FCustomClientCertVerifier := LSrc.FCustomClientCertVerifier;
    FVerifyCallback := LSrc.FVerifyCallback;
    FVerdictResolver := LSrc.FVerdictResolver;
    FVerdictDeadlineMs := LSrc.FVerdictDeadlineMs;
    FServerVerdictResolver := LSrc.FServerVerdictResolver;
    FServerVerdictDeadlineMs := LSrc.FServerVerdictDeadlineMs;
    FClientConfig := LSrc.FClientConfig;
    FServerConfig := LSrc.FServerConfig;
    FCrypto := LSrc.FCrypto;
    FPkix := LSrc.FPkix;
    FSessionResumption := LSrc.FSessionResumption;
    FHandshakeTimeoutMs := LSrc.FHandshakeTimeoutMs;
  end
  else
    inherited Assign(ASource);
end;

function TTlsLibSSLOptions.Snapshot: TTlsOptions;
begin
  Result := TTlsOptions.Default;
  Result.Crypto := FCrypto;
  Result.Pkix := FPkix;
  Result.Certificate := TTlsBlobSource.FromFile(FCertFile);
  Result.PrivateKey := TTlsBlobSource.FromFile(FKeyFile);
  Result.KeyPassword := FKeyPassword;
  // a named RootCertFile is one trust anchor; leaving it out keeps HasClientTrustSource honest
  if FRootCertFile <> '' then
  begin
    SetLength(Result.TrustAnchors, 1);
    Result.TrustAnchors[0] := TTlsBlobSource.FromFile(FRootCertFile);
  end;
  // UseSystemTrust opts into the OS store through the host-neutral installer seam, so the core
  // never depends on the system-trust package
  if FUseSystemTrust then
    Result.SystemTrust := TSystemTrustInstaller.Create as ISystemTrustInstaller;
  Result.CustomTrustStore := FCustomTrustStore;
  Result.ServerCertificateVerifier := FCustomServerCertVerifier;
  Result.ClientCertificateVerifier := FCustomClientCertVerifier;
  Result.VerifyPeer := FVerifyPeer;
  Result.InsecureSkipVerify := FInsecureSkipVerify;
  // CheckHostName and ClientAuth keep the composable defaults (True / Required); Indy exposes no
  // knob for either, and offers no ALPN surface
  Result.VerifyCallback := FVerifyCallback;
  Result.ClientVerdictResolver := FVerdictResolver;
  Result.ClientVerdictDeadlineMs := FVerdictDeadlineMs;
  Result.ServerVerdictResolver := FServerVerdictResolver;
  Result.ServerVerdictDeadlineMs := FServerVerdictDeadlineMs;
  Result.SessionResumption := FSessionResumption;
  Result.HandshakeTimeoutMs := FHandshakeTimeoutMs;
  Result.ClientConfig := FClientConfig;
  Result.ServerConfig := FServerConfig;
  Result.TrustSourceHint := SIndyTrustSourceHint;
end;

{ TIndySocketTransport }

constructor TIndySocketTransport.Create(ABinding: TIdSocketHandle);
begin
  inherited Create;
  FBinding := ABinding;
end;

function TIndySocketTransport.WaitReadable(AMs: Int32): Boolean;
begin
  Result := FBinding.Readable(AMs);
end;

function TIndySocketTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LTmp: TIdBytes;
begin
  LTmp := nil;
  SetLength(LTmp, AMaxLength);
  Result := FBinding.Receive(LTmp); // 0 on an orderly close, else the byte count
  if Result > 0 then
    Move(LTmp[0], ABuffer[AOffset], Result);
end;

function TIndySocketTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
var
  LTmp: TIdBytes;
begin
  LTmp := nil;
  SetLength(LTmp, ALength);
  Move(ABuffer[AOffset], LTmp[0], ALength);
  Result := FBinding.Send(LTmp, 0, ALength);
  if Result <= 0 then
    raise ETlsStreamError.Create(SIndySendNoProgress);
end;

{ TTlsLibIOHandlerSocket }

procedure TTlsLibIOHandlerSocket.InitComponent;
begin
  inherited InitComponent;
  FOptions := TTlsLibSSLOptions.Create;
  FHandshakeLock := TCriticalSection.Create;
  // Indy's base defaults PassThrough to True (connect plaintext, upgrade later). We default it to
  // False so assigning this handler to a raw client means "do TLS on connect" without extra setup.
  // Callers that want plaintext override it: TIdHTTP sets it True for http:// (False for https://),
  // and STARTTLS clients set it True until they upgrade.
  fPassThrough := False;
end;

destructor TTlsLibIOHandlerSocket.Destroy;
begin
  // belt-and-braces for a handler freed directly without a prior Close: emit close_notify while
  // the socket may still be open. Idempotent - a no-op when Close already sent it.
  if FConnection <> nil then
    FConnection.CloseNotifyQuietly;
  FConnection.Free;
  FConnection := nil; // inherited Destroy calls Close; keep it from touching a freed session
  FOptions.Free;
  FHandshakeLock.Free;
  inherited Destroy;
end;

procedure TTlsLibIOHandlerSocket.Close;
begin
  // send a TLS close_notify before the transport goes away, so a strict peer reads a clean
  // shutdown rather than a truncation (RFC 8446 6.1). Best-effort and half-close: CloseNotify
  // only writes and flushes (it never waits for the peer's answering close_notify, so there is
  // no wedge), is idempotent, and no-ops on a stream that never finished the handshake. A write
  // to an already-dead peer is expected and ignored.
  if FConnection <> nil then
    FConnection.CloseNotifyQuietly;
  inherited Close;
end;

procedure TTlsLibIOHandlerSocket.PrepareServerHandshakeDeferred;
begin
  // set the field directly so the handshake is NOT triggered here (SetPassThrough would run
  // it inline). PassThrough=False makes Indy route reads/writes through RecvEnc/SendEnc, where
  // the handshake then runs lazily on this connection's worker thread.
  fPassThrough := False;
  // AfterAccept (which we no longer call on the listener thread) would have copied the
  // accepted binding's IP version; restore it so an IPv6-accepted server peer reports correctly
  if Binding <> nil then
    IPVersion := Binding.IPVersion;
end;

function TTlsLibIOHandlerSocket.Readable(AMSec: Integer): Boolean;
begin
  // a poll-style server checks Readable before reading; run the deferred handshake here too
  // (not only in RecvEnc/SendEnc) so the handshake is driven - and a fully-silent peer is
  // aborted by the handshake read timeout rather than pinning this worker thread. Then surface
  // engine-buffered plaintext (a record coalesced with the peer's final flight) that a raw
  // socket select cannot see, before falling back to the base socket-readability check.
  if (not fPassThrough) and (FConnection = nil) and (Binding <> nil) and
    Binding.HandleAllocated then
    DoHandshake;
  if (FConnection <> nil) and (FConnection.PendingReadBytes > 0) then
    Exit(True);
  Result := inherited Readable(AMSec);
end;

procedure TTlsLibIOHandlerSocket.AdoptServerMemo(const AMemo: ITlsServerConfigMemo);
begin
  FServerMemo := AMemo;
end;

function TTlsLibIOHandlerSocket.BuildEngine(AIsClient: Boolean): ITlsEngine;
var
  LOptions: TTlsOptions;
begin
  LOptions := FOptions.Snapshot;
  // a fully-built config supplied by the app REPLACES the options-driven build outright; the
  // composer's conflict guard fails loud when cert/trust options are named alongside it
  if AIsClient then
    Exit(TTlsEngineFactory.CreateClientEngine(
      TTlsConfigComposer.ResolveClientConfig(LOptions, GClientConfigMemo,
      'SSLOptions.ClientConfig'), Host));
  // a server peer reuses the listener's shared memo so all peers bind to one config identity; a
  // standalone handler doing its own accepts (no TTlsLibServerIOHandler listener) lazily owns one,
  // so its config - and the default STEK minted into it - stay stable across the connections it
  // serves (this is serialized by the handshake lock)
  if FServerMemo = nil then
    FServerMemo := NewTlsServerConfigMemo;
  Result := TTlsEngineFactory.CreateServerEngine(
    TTlsConfigComposer.ResolveServerConfig(LOptions, FServerMemo, 'SSLOptions.ServerConfig'));
end;

procedure TTlsLibIOHandlerSocket.DoHandshake;
var
  LEngine: ITlsEngine;
  LResolver: TCertificateVerdictResolver;
begin
  if FConnection <> nil then
    Exit; // fast path: handshake already run
  // the deferred handshake can be reached concurrently by RecvEnc, SendEnc and Readable (a
  // broadcaster writing while the worker reads); serialize so it runs exactly once
  FHandshakeLock.Enter;
  try
    if FConnection <> nil then
      Exit;
    LEngine := BuildEngine(not IsPeer);
    // pick the role-correct resolver: a client (not IsPeer) parks on the server's chain, a
    // server on the mTLS client's chain - the two bind different EKUs, so one resolver cannot
    // serve both
    if not IsPeer then
      LResolver := FOptions.VerdictResolver
    else
      LResolver := FOptions.ServerVerdictResolver;
    FConnection := TTlsConnection.Create(LEngine, TIndySocketTransport.Create(Binding),
      not IsPeer, Host, LResolver);
    // bound the handshake read by the dedicated HandshakeTimeoutMs option, NOT app ReadTimeout
    // (a short app-read deadline would wrongly abort slow-but-valid handshakes); the session
    // arms and clears the cap, even when the handshake raised
    FConnection.Handshake(FOptions.HandshakeTimeoutMs);
  finally
    FHandshakeLock.Leave;
  end;
end;

procedure TTlsLibIOHandlerSocket.StartSSL;
begin
  if not PassThrough then
    DoHandshake;
end;

procedure TTlsLibIOHandlerSocket.ResetTlsSession;
begin
  // a fresh underlying connection invalidates any prior TLS session: drop the session (and with
  // it the stream, engine and transport) so the next handshake runs anew instead of reusing
  // stale keys on a new socket
  FConnection.Free;
  FConnection := nil;
end;

procedure TTlsLibIOHandlerSocket.ConnectClient;
var
  LWantsTls: Boolean;
begin
  // Indy may drop keep-alive and reconnect between requests; discard any prior TLS session so
  // this new socket handshakes fresh rather than encrypting with the closed session's keys
  ResetTlsSession;
  // Honour the caller's PassThrough exactly like the stock SSL IOHandler: PassThrough=False
  // means TLS is wanted on connect (an https:// request); PassThrough=True means stay plaintext -
  // a plain http:// connection, or a STARTTLS upgrade deferred until SetPassThrough turns it off.
  LWantsTls := not PassThrough;
  // Establish the plaintext TCP connection first, setting the field directly so SetPassThrough
  // does not fire a handshake mid-connect, then restore the caller's intent.
  fPassThrough := True;
  try
    inherited ConnectClient;
  finally
    fPassThrough := not LWantsTls;
  end;
  StartSSL; // handshakes only when PassThrough is False (TLS wanted); plaintext passes through
end;

procedure TTlsLibIOHandlerSocket.AfterAccept;
begin
  inherited AfterAccept;
  StartSSL; // server-side: PassThrough was set False by the accept path
end;

procedure TTlsLibIOHandlerSocket.SetPassThrough(const AValue: Boolean);
begin
  // STARTTLS: turning pass-through off on a live connection triggers the handshake
  if (not AValue) and fPassThrough and (Binding <> nil) and Binding.HandleAllocated then
  begin
    fPassThrough := False;
    DoHandshake;
  end
  else
    fPassThrough := AValue;
end;

function TTlsLibIOHandlerSocket.RecvEnc(var ABuffer: TIdBytes): Integer;
var
  LTmp: TBytes;
begin
  // a deferred server handshake runs here, on this connection's own worker thread, the first
  // time the application touches the stream - never on the shared listener thread
  if FConnection = nil then
    DoHandshake;
  LTmp := nil;
  SetLength(LTmp, 32768);
  Result := FConnection.Read(LTmp[0], System.Length(LTmp));
  SetLength(ABuffer, Result);
  if Result > 0 then
    Move(LTmp[0], ABuffer[0], Result);
end;

function TTlsLibIOHandlerSocket.SendEnc(const ABuffer: TIdBytes;
  const AOffset, ALength: Integer): Integer;
begin
  if FConnection = nil then
    DoHandshake;
  FConnection.Write(ABuffer[AOffset], ALength);
  Result := ALength;
end;

function TTlsLibIOHandlerSocket.NegotiatedVersion: TTlsVersion;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedVersion
  else
    Result := TTlsVersion.Create(0);
end;

function TTlsLibIOHandlerSocket.NegotiatedCipherSuite: UInt16;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedCipherSuite
  else
    Result := 0;
end;

function TTlsLibIOHandlerSocket.NegotiatedGroup: UInt16;
begin
  if FConnection <> nil then
    Result := FConnection.NegotiatedGroup
  else
    Result := 0;
end;

function TTlsLibIOHandlerSocket.PeerServerName: string;
begin
  if FConnection <> nil then
    Result := FConnection.PeerServerName
  else
    Result := '';
end;

function TTlsLibIOHandlerSocket.EchStatus: TEchStatus;
begin
  if FConnection <> nil then
    Result := FConnection.EchStatus
  else
    Result := TEchStatus.NotOffered;
end;

function TTlsLibIOHandlerSocket.Resumed: Boolean;
begin
  if FConnection <> nil then
    Result := FConnection.Resumed
  else
    Result := False;
end;

class procedure TTlsLibIOHandlerSocket.FlushConfigCache;
begin
  if GClientConfigMemo <> nil then
    GClientConfigMemo.Clear;
end;

function TTlsLibIOHandlerSocket.Clone: TIdSSLIOHandlerSocketBase;
var
  LClone: TTlsLibIOHandlerSocket;
begin
  LClone := TTlsLibIOHandlerSocket.Create(nil);
  LClone.SSLOptions.Assign(FOptions);
  Result := LClone;
end;

{ TTlsLibServerIOHandler }

procedure TTlsLibServerIOHandler.InitComponent;
begin
  inherited InitComponent;
  FOptions := TTlsLibSSLOptions.Create;
  FServerMemo := NewTlsServerConfigMemo;
end;

destructor TTlsLibServerIOHandler.Destroy;
begin
  FOptions.Free;
  inherited Destroy;
end;

function TTlsLibServerIOHandler.Accept(ASocket: TIdSocketHandle;
  AListenerThread: TIdThread; AYarn: TIdYarn): TIdIOHandler;
var
  LIO: TTlsLibIOHandlerSocket;
begin
  Result := nil;
  LIO := TTlsLibIOHandlerSocket.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.Open;
    while not AListenerThread.Stopped do
      if ASocket.Select(250) then
        if (not AListenerThread.Stopped) and LIO.Binding.Accept(ASocket.Handle) then
        begin
          LIO.IsPeer := True;
          LIO.SSLOptions.Assign(FOptions);
          LIO.AdoptServerMemo(FServerMemo); // all peers share the listener's build-once config
          // do NOT handshake here: Accept runs on the single listener thread, so a silent peer
          // would wedge every connection. Defer it to this peer's worker thread.
          LIO.PrepareServerHandshakeDeferred;
          Result := LIO;
          LIO := nil;
          Break;
        end;
  finally
    LIO.Free;
  end;
end;

function TTlsLibServerIOHandler.MakeClientIOHandler: TIdSSLIOHandlerSocketBase;
var
  LIO: TTlsLibIOHandlerSocket;
begin
  LIO := TTlsLibIOHandlerSocket.Create(nil);
  LIO.PassThrough := True;
  LIO.SSLOptions.Assign(FOptions);
  LIO.AdoptServerMemo(FServerMemo);
  Result := LIO;
end;

function TTlsLibServerIOHandler.MakeFTPSvrPort: TIdSSLIOHandlerSocketBase;
begin
  Result := MakeClientIOHandler;
end;

function TTlsLibServerIOHandler.MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase;
begin
  Result := MakeClientIOHandler;
end;

procedure TTlsLibServerIOHandler.FlushConfigCache;
begin
  if FServerMemo <> nil then
    FServerMemo.Clear;
end;

initialization
  GClientConfigMemo := NewTlsClientConfigMemo;

finalization
  if GClientConfigMemo <> nil then
    GClientConfigMemo.Clear;
  GClientConfigMemo := nil;

end.
