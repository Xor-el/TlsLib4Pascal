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
/// is the only place our types and Indy's types meet.
/// </summary>
unit TlsLibIndyTls;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  Classes,
  SysUtils,
  IdGlobal,
  IdSSL,
  IdIOHandler,
  IdSocketHandle,
  IdThread,
  IdYarn,
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
  TlpITlsTransport,
  TlpTlsStreamPump,
  TlpTlsStream,
  TlpSystemTrustFacade;

type
  /// <summary>The TLS settings an Indy integrator sets on the adapter (the neutral analogue
  /// of Indy's OpenSSL SSLOptions): the cert/key/CA files and the verify posture. Indy's SSL
  /// base carries no trust surface (RootCertFile/VerifyMode live only on its OpenSSL handler),
  /// so this class is ours. Peer trust composes from orthogonal sources - a RootCertFile bundle,
  /// UseSystemTrust for the OS anchors, and/or an injected CustomTrustStore all UNION; a
  /// CustomVerifier replaces the pipeline outright. System trust is never implicit.</summary>
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
    FCustomVerifier: ICertificateVerifier;
    FVerifyCallback: TTlsCertificateVerifyCallback;
    FVerdictResolver: TTlsVerdictResolver;
    FVerdictDeadlineMs: Cardinal;
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
  private
    /// <summary>Raises when a supplied config is set together with cert/trust options a fully-built
    /// config would replace (APropertyName names the config property in the message). The IOHandler
    /// calls it at build time so a silently-dropped source fails loud.</summary>
    procedure GuardNoConflict(const APropertyName: string);
  public
    constructor Create;
    procedure Assign(ASource: TPersistent); override;
    /// <summary>A fully-built client config that REPLACES the options-driven build: when set, the
    /// cert/trust options here are not allowed alongside it (the adapter raises). VerdictResolver/
    /// VerdictDeadlineMs are the exception - a runtime stream hook, not part of the frozen config -
    /// and still apply (arm them with WithAsyncCertificateVerdict). The escape hatch to the full
    /// builder API (cipher order, groups, resumption, ALPN, ...).</summary>
    property ClientConfig: ITlsClientConfig read FClientConfig write FClientConfig;
    /// <summary>A fully-built server config that REPLACES the options-driven build (the server-side
    /// counterpart of ClientConfig; same conflict rule).</summary>
    property ServerConfig: ITlsServerConfig read FServerConfig write FServerConfig;
    /// <summary>An augment-only peer-certificate hook: it runs after the built-in pipeline and
    /// can only additionally reject (never loosen it). The neutral bridge for an app's own
    /// verify rule.</summary>
    property VerifyCallback: TTlsCertificateVerifyCallback read FVerifyCallback
      write FVerifyCallback;
    /// <summary>When assigned, the handshake parks after the pipeline accepts the peer chain
    /// and this resolves the verdict out-of-band (e.g. live OCSP/CRL); augment-only,
    /// fail-closed.</summary>
    property VerdictResolver: TTlsVerdictResolver read FVerdictResolver
      write FVerdictResolver;
    /// <summary>The advisory deadline (ms) for an awaited verdict; 0 leaves it to the resolver.</summary>
    property VerdictDeadlineMs: Cardinal read FVerdictDeadlineMs
      write FVerdictDeadlineMs;
    /// <summary>An injected anchor store; when set it UNIONS with RootCertFile and UseSystemTrust
    /// (e.g. a fully custom root set alongside the OS anchors).</summary>
    property CustomTrustStore: ITrustAnchorStore read FCustomTrustStore
      write FCustomTrustStore;
    /// <summary>A whole-verifier that REPLACES the built-in pipeline outright (exclusive of every
    /// anchor source - RootCertFile, UseSystemTrust, CustomTrustStore).</summary>
    property CustomVerifier: ICertificateVerifier read FCustomVerifier
      write FCustomVerifier;
  published
    property CertFile: string read FCertFile write FCertFile;
    property KeyFile: string read FKeyFile write FKeyFile;
    property KeyPassword: string read FKeyPassword write FKeyPassword;
    property RootCertFile: string read FRootCertFile write FRootCertFile;
    /// <summary>Whether the peer certificate is verified (a server verifies a requested
    /// client certificate). Default True.</summary>
    property VerifyPeer: Boolean read FVerifyPeer write FVerifyPeer;
    /// <summary>DANGEROUS: accept the peer chain with no PKIX/host/pinning checks. Maps onto
    /// our loud InsecureSkipVerify; test-only.</summary>
    property InsecureSkipVerify: Boolean read FInsecureSkipVerify write FInsecureSkipVerify;
    /// <summary>Opt into the OS system-trust anchors (Windows crypt32 / macOS SecTrust / Unix
    /// bundle). Unions with RootCertFile and any CustomTrustStore. System trust is never implicit:
    /// when VerifyPeer is on you must name at least one source or the build fails closed. Defaults
    /// to False.</summary>
    property UseSystemTrust: Boolean read FUseSystemTrust write FUseSystemTrust;
  end;

  /// <summary>An ITlsTransport over an Indy socket binding: raw ciphertext moves through the
  /// binding's blocking Receive/Send.</summary>
  TIndySocketTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FBinding: TIdSocketHandle;
  public
    constructor Create(ABinding: TIdSocketHandle);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
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
    FStream: TTlsStream;
    FTransport: ITlsTransport;
    FEngine: ITlsEngine;
    FClientMemo: ITlsClientConfigMemo;   // reuses the client config across reconnects
    FServerMemo: ITlsServerConfigMemo;   // shared with the listener; server peers reuse one config
    procedure DoHandshake;
    procedure ResetTlsSession;
    function LoadFileBytes(const APath: string): TBytes;
    function BuildClientConfig: ITlsClientConfig;
    function BuildServerConfig: ITlsServerConfig;
    function ClientSignature: string;
    function ServerSignature: string;
    function BuildEngine(AIsClient: Boolean): ITlsEngine;
  private
    /// <summary>The listener hands each server peer its shared config memo (same-unit only).</summary>
    procedure AdoptServerMemo(const AMemo: ITlsServerConfigMemo);
  protected
    procedure InitComponent; override;
    procedure SetPassThrough(const AValue: Boolean); override;
    function RecvEnc(var ABuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;
  public
    destructor Destroy; override;
    function Clone: TIdSSLIOHandlerSocketBase; override;
    procedure StartSSL; override;
    procedure ConnectClient; override;
    procedure AfterAccept; override;
    /// <summary>The negotiated protocol version once the handshake completes.</summary>
    function NegotiatedVersion: TTlsVersion;
    /// <summary>The negotiated cipher-suite wire codepoint once the handshake completes (0 if none).</summary>
    function NegotiatedCipherSuite: UInt16;
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
  published
    property SSLOptions: TTlsLibSSLOptions read FOptions;
  end;

implementation

resourcestring
  SNoServerCredential = 'the Indy SSLOptions supply no server CertFile/KeyFile';
  SNoClientTrust = 'VerifyPeer is on but no trust source was named; set a RootCertFile bundle, ' +
    'UseSystemTrust, or a CustomTrustStore/CustomVerifier (system trust is never implicit), or ' +
    'set VerifyPeer := False to skip verification';
  SConfigAndOptionsConflict = 'SSLOptions.%s is set together with cert/trust options that a ' +
    'fully-built config replaces; supply either the config or the cert/trust options, not both';

{ TTlsLibSSLOptions }

constructor TTlsLibSSLOptions.Create;
begin
  inherited Create;
  FVerifyPeer := True;
  FInsecureSkipVerify := False;
  FUseSystemTrust := False;
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
    FCustomVerifier := LSrc.FCustomVerifier;
    FVerifyCallback := LSrc.FVerifyCallback;
    FVerdictResolver := LSrc.FVerdictResolver;
    FVerdictDeadlineMs := LSrc.FVerdictDeadlineMs;
    FClientConfig := LSrc.FClientConfig;
    FServerConfig := LSrc.FServerConfig;
  end
  else
    inherited Assign(ASource);
end;

procedure TTlsLibSSLOptions.GuardNoConflict(const APropertyName: string);
begin
  // a supplied config owns trust/credential entirely; naming these alongside it would be silently
  // dropped, so fail loud. VerdictResolver is deliberately excluded: it is a runtime stream hook
  // (not part of the frozen config) and still applies with a supplied config.
  if (FCertFile <> '') or (FKeyFile <> '') or (FRootCertFile <> '') or FUseSystemTrust or
    (FCustomVerifier <> nil) or (FCustomTrustStore <> nil) or Assigned(FVerifyCallback) then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
      Format(SConfigAndOptionsConflict, [APropertyName]));
end;

{ TIndySocketTransport }

constructor TIndySocketTransport.Create(ABinding: TIdSocketHandle);
begin
  inherited Create;
  FBinding := ABinding;
end;

function TIndySocketTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LTmp: TIdBytes;
begin
  LTmp := nil;
  SetLength(LTmp, AMaxLength);
  Result := FBinding.Receive(LTmp); // 0 on an orderly close, else the byte count
  if Result > 0 then
    Move(LTmp[0], ABuffer[AOffset], Result)
  else
    Result := 0;
end;

procedure TIndySocketTransport.Write(const ABuffer: TBytes; AOffset,
  ALength: Int32);
var
  LTmp: TIdBytes;
  LOff, LRemain, LN: Integer;
begin
  LTmp := nil;
  SetLength(LTmp, ALength);
  Move(ABuffer[AOffset], LTmp[0], ALength);
  LOff := 0;
  LRemain := ALength;
  while LRemain > 0 do
  begin
    LN := FBinding.Send(LTmp, LOff, LRemain);
    if LN <= 0 then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        'Indy socket send returned no progress');
    Inc(LOff, LN);
    Dec(LRemain, LN);
  end;
end;

{ TTlsLibIOHandlerSocket }

procedure TTlsLibIOHandlerSocket.InitComponent;
begin
  inherited InitComponent;
  FOptions := TTlsLibSSLOptions.Create;
  FClientMemo := NewTlsClientConfigMemo;
  // Indy's base defaults PassThrough to True (connect plaintext, upgrade later). We default it to
  // False so assigning this handler to a raw client means "do TLS on connect" without extra setup -
  // the ergonomic common case. Callers that want plaintext override it: TIdHTTP sets it True for
  // http:// (False for https://), and STARTTLS clients set it True until they upgrade.
  fPassThrough := False;
end;

destructor TTlsLibIOHandlerSocket.Destroy;
begin
  FStream.Free;
  FOptions.Free;
  inherited Destroy;
end;

function TTlsLibIOHandlerSocket.LoadFileBytes(const APath: string): TBytes;
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

procedure TTlsLibIOHandlerSocket.AdoptServerMemo(const AMemo: ITlsServerConfigMemo);
begin
  FServerMemo := AMemo;
end;

function TTlsLibIOHandlerSocket.BuildClientConfig: ITlsClientConfig;
var
  LProvider: ICryptoProvider;
  LClient: ITlsClientConfigBuilder;
  LHasSource: Boolean;
begin
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LClient := TTlsPresets.Compatible(LProvider).Client;
  // compose peer trust from orthogonal sources: a whole-verifier REPLACES the pipeline, else a
  // RootCertFile bundle + the OS anchors + a custom store all UNION. Adding both a verifier and
  // an anchor source is left to fail as the builder's typed conflict. System trust is never
  // implicit; verifying with no source named fails closed.
  LHasSource := (FOptions.CustomVerifier <> nil) or (FOptions.RootCertFile <> '') or
    FOptions.UseSystemTrust or (FOptions.CustomTrustStore <> nil);
  if FOptions.CustomVerifier <> nil then
    LClient.WithCertificateVerifier(FOptions.CustomVerifier);
  if FOptions.RootCertFile <> '' then
    LClient.WithTrustAnchors(LoadFileBytes(FOptions.RootCertFile));
  if FOptions.UseSystemTrust then
    TSystemTrust.WithSystemTrust(LClient, LProvider);
  if FOptions.CustomTrustStore <> nil then
    LClient.WithTrustStore(FOptions.CustomTrustStore);
  if not LHasSource then
  begin
    if FOptions.VerifyPeer and (not FOptions.InsecureSkipVerify) then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoClientTrust);
    // skipping verification still needs a source to satisfy the builder
    LClient.WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
  end;
  if FOptions.InsecureSkipVerify or (not FOptions.VerifyPeer) then
    LClient.WithDangerousInsecureSkipVerify(True);
  if FOptions.CertFile <> '' then
    LClient.WithCredential(LoadFileBytes(FOptions.CertFile),
      LoadFileBytes(FOptions.KeyFile), FOptions.KeyPassword);
  // an app's augment-only verify rule, and the async-verdict flag (the resolver itself is a
  // runtime stream hook applied in DoHandshake, not part of the frozen config)
  if Assigned(FOptions.VerifyCallback) then
    LClient.WithCertificateVerifyCallback(FOptions.VerifyCallback);
  if Assigned(FOptions.VerdictResolver) then
    LClient.WithAsyncCertificateVerdict(True, FOptions.VerdictDeadlineMs);
  Result := LClient.Build;
end;

function TTlsLibIOHandlerSocket.BuildServerConfig: ITlsServerConfig;
var
  LProvider: ICryptoProvider;
  LServer: ITlsServerConfigBuilder;
  LHasSource: Boolean;
begin
  if FOptions.CertFile = '' then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoServerCredential);
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LServer := TTlsPresets.Compatible(LProvider).Server
    .WithCredential(LoadFileBytes(FOptions.CertFile),
    LoadFileBytes(FOptions.KeyFile), FOptions.KeyPassword);
  if FOptions.VerifyPeer then
  begin
    // client-cert auth is optional: request+verify only when a client-trust source is named
    // (same composable model as the client). Note UseSystemTrust here validates CLIENT certs
    // against the OS public web-PKI roots - a broad surface most mTLS servers do not want.
    LHasSource := (FOptions.CustomVerifier <> nil) or (FOptions.RootCertFile <> '') or
      FOptions.UseSystemTrust or (FOptions.CustomTrustStore <> nil);
    if LHasSource then
    begin
      LServer.WithPeerAuth(TClientAuthMode.Required);
      if FOptions.CustomVerifier <> nil then
        LServer.WithCertificateVerifier(FOptions.CustomVerifier);
      if FOptions.RootCertFile <> '' then
        LServer.WithTrustAnchors(LoadFileBytes(FOptions.RootCertFile));
      if FOptions.UseSystemTrust then
        TSystemTrust.WithSystemTrust(LServer, LProvider);
      if FOptions.CustomTrustStore <> nil then
        LServer.WithTrustStore(FOptions.CustomTrustStore);
    end;
  end;
  Result := LServer.Build;
end;

function TTlsLibIOHandlerSocket.ClientSignature: string;
var
  LSig: TTlsSignatureBuilder;
begin
  LSig := TTlsSignatureBuilder.Create(nil); // all inputs are files/scalars/pointers - no hashing
  LSig.AddFile('cert', FOptions.CertFile);
  LSig.AddFile('key', FOptions.KeyFile);
  LSig.AddText('keypw', FOptions.KeyPassword);
  LSig.AddFile('root', FOptions.RootCertFile);
  LSig.AddFlag('verifyPeer', FOptions.VerifyPeer);
  LSig.AddFlag('skipVerify', FOptions.InsecureSkipVerify);
  LSig.AddFlag('systemTrust', FOptions.UseSystemTrust);
  LSig.AddPointer('customVerifier', FOptions.CustomVerifier);
  LSig.AddPointer('customStore', FOptions.CustomTrustStore);
  LSig.AddMethod('verifyCb', TMethod(FOptions.VerifyCallback));
  LSig.AddFlag('asyncVerdict', Assigned(FOptions.VerdictResolver));
  LSig.AddCardinal('deadline', FOptions.VerdictDeadlineMs);
  Result := LSig.Value;
end;

function TTlsLibIOHandlerSocket.ServerSignature: string;
var
  LSig: TTlsSignatureBuilder;
begin
  LSig := TTlsSignatureBuilder.Create(nil);
  LSig.AddFile('cert', FOptions.CertFile);
  LSig.AddFile('key', FOptions.KeyFile);
  LSig.AddText('keypw', FOptions.KeyPassword);
  LSig.AddFlag('verifyPeer', FOptions.VerifyPeer);
  LSig.AddFile('root', FOptions.RootCertFile);
  LSig.AddFlag('systemTrust', FOptions.UseSystemTrust);
  LSig.AddPointer('customVerifier', FOptions.CustomVerifier);
  LSig.AddPointer('customStore', FOptions.CustomTrustStore);
  Result := LSig.Value;
end;

function TTlsLibIOHandlerSocket.BuildEngine(AIsClient: Boolean): ITlsEngine;
var
  LClientCfg: ITlsClientConfig;
  LServerCfg: ITlsServerConfig;
  LSig: string;
begin
  // a fully-built config supplied by the app REPLACES the options-driven build outright; naming
  // cert/trust options alongside it fails loud rather than dropping them silently
  if AIsClient then
  begin
    if FOptions.ClientConfig <> nil then
    begin
      FOptions.GuardNoConflict('ClientConfig');
      Exit(TTlsEngineFactory.CreateClientEngine(FOptions.ClientConfig, Host));
    end;
    // build the frozen config once and reuse it across reconnects on this handler
    LSig := ClientSignature;
    if not FClientMemo.TryGet(LSig, LClientCfg) then
      LClientCfg := FClientMemo.StoreOrAdopt(LSig, BuildClientConfig);
    Exit(TTlsEngineFactory.CreateClientEngine(LClientCfg, Host));
  end;
  if FOptions.ServerConfig <> nil then
  begin
    FOptions.GuardNoConflict('ServerConfig');
    Exit(TTlsEngineFactory.CreateServerEngine(FOptions.ServerConfig));
  end;
  // a server peer reuses the listener's shared memo, so all peers bind to one config identity
  if FServerMemo <> nil then
  begin
    LSig := ServerSignature;
    if not FServerMemo.TryGet(LSig, LServerCfg) then
      LServerCfg := FServerMemo.StoreOrAdopt(LSig, BuildServerConfig);
    Exit(TTlsEngineFactory.CreateServerEngine(LServerCfg));
  end;
  Exit(TTlsEngineFactory.CreateServerEngine(BuildServerConfig));
end;

procedure TTlsLibIOHandlerSocket.DoHandshake;
begin
  if FStream <> nil then
    Exit; // handshake already run
  FEngine := BuildEngine(not IsPeer);
  FTransport := TIndySocketTransport.Create(Binding) as ITlsTransport;
  FStream := TTlsStream.Create(FTransport, FEngine, not IsPeer, Host);
  if Assigned(FOptions.VerdictResolver) then
    FStream.SetCertificateVerdictResolver(FOptions.VerdictResolver);
  FStream.Handshake;
end;

procedure TTlsLibIOHandlerSocket.StartSSL;
begin
  if not PassThrough then
    DoHandshake;
end;

procedure TTlsLibIOHandlerSocket.ResetTlsSession;
begin
  // a fresh underlying connection invalidates any prior TLS session: drop the stream, engine,
  // and transport so the next handshake runs anew instead of reusing stale keys on a new socket
  FStream.Free;
  FStream := nil;
  FTransport := nil;
  FEngine := nil;
end;

procedure TTlsLibIOHandlerSocket.ConnectClient;
var
  LWantsTls: Boolean;
begin
  // Indy may drop keep-alive and reconnect between requests; discard any prior TLS session so
  // this new socket handshakes fresh rather than encrypting with the closed session's keys
  ResetTlsSession;
  // Honour the caller's PassThrough exactly like the stock OpenSSL IOHandler: PassThrough=False
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
  LTmp := nil;
  SetLength(LTmp, 32768);
  Result := FStream.Read(LTmp[0], System.Length(LTmp));
  SetLength(ABuffer, Result);
  if Result > 0 then
    Move(LTmp[0], ABuffer[0], Result);
end;

function TTlsLibIOHandlerSocket.SendEnc(const ABuffer: TIdBytes;
  const AOffset, ALength: Integer): Integer;
begin
  FStream.Write(ABuffer[AOffset], ALength);
  Result := ALength;
end;

function TTlsLibIOHandlerSocket.NegotiatedVersion: TTlsVersion;
begin
  if FStream <> nil then
    Result := FStream.ConnectionInfo.NegotiatedVersion
  else
    Result := TTlsVersion.Create(0);
end;

function TTlsLibIOHandlerSocket.NegotiatedCipherSuite: UInt16;
begin
  if FStream <> nil then
    Result := FStream.ConnectionInfo.CipherSuite
  else
    Result := 0;
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
          LIO.PassThrough := False; // a straight TLS server upgrades on accept
          LIO.AfterAccept;
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

end.
