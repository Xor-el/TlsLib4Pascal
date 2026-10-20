{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ConfigResumptionTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpCryptoDomainTypes,
  TlpEchConfig,
  TlpEchClient,
  TlpInMemoryEchKeyStore,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpCertificateVerifierSource,
  TlpTlsAlert,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpISession,
  TlpSession,
  TlpISecretBuffer,
  TlpSecretBuffer,
  MockSessionStores,
  MockCertificateVerifiers,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpCoreExtensions,
  TlsLibTestHandshakeDecoder,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  TTestConfigResumption = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
  var
    FCerts: TStringList;
    // the engine and outcome of the re-entry probes run from a session-cache Store callback
    FProbeEngine: ITlsEngine;
    FProbeStores: Int32;
    FProbeRefused: Boolean;
    procedure ProbeProcessInputFromStore;
    procedure ProbeSetVerdictFromStore;
    /// <summary>Resumes a cached TLS 1.2 session under a reverify park, with AOnStored run from
    /// the client's session-cache Store when the accepted verdict resumes the handshake.</summary>
    procedure ResumeAndAcceptWithStoreProbe(AOnStored: TSessionCacheEvent);
    /// <summary>The stapling server credential: leaf + issuer with a current Good OCSP response
    /// sealed on it, so a staple-requesting client completes a full handshake under a Hard posture.</summary>
    function StaplingCredential: TTlsCredential;
    /// <summary>A TLS 1.3 stapling server that issues AIssueTickets resumable tickets.</summary>
    function NewStaplingServer13(const AStore: ISessionStore;
      AIssueTickets: Int32): ITlsEngine;
    /// <summary>A TLS 1.2 stapling server that resumes by default.</summary>
    function NewStaplingServer12(const AStore: ISessionStore): ITlsEngine;
    /// <summary>A permissive (default Soft) TLS 1.3 client that trusts the stapling root and seeds
    /// the cache.</summary>
    function NewStaplingSeedClient13(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>The TLS 1.2 seed client twin.</summary>
    function NewStaplingSeedClient12(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>A Hard + Reverify TLS 1.3 client with the given verdict deferral: LiveRevocation
    /// still offers resumption, None / HostDecision are withheld by the engine factory.</summary>
    function NewHardReverifyClient13(const ACache: ISessionCache;
      const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
    /// <summary>The TLS 1.2 Hard + Reverify client twin.</summary>
    function NewHardReverifyClient12(const ACache: ISessionCache;
      const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
    /// <summary>A Hard + ReuseOriginal TLS 1.3 client: it never re-verifies on resume, so the
    /// gate leaves resumption offered.</summary>
    function NewHardReuseOriginalClient13(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>A TLS 1.3 client engine built through the public config surface. A non-empty
    /// AScope opts the config into sharing sessions with configs given the same scope.</summary>
    function NewClient13(const ACache: ISessionCache; AResumption: Boolean;
      const AScope: TBytes): ITlsEngine;
    /// <summary>A TLS 1.3 client whose server-cert verifier rejects every chain (a strict config).</summary>
    function NewRejectingClient13(const ACache: ISessionCache): ITlsEngine;
    /// <summary>Like NewRejectingClient13 but with Reverify, so it re-checks a resumed server.</summary>
    function NewReverifyRejectClient13(const ACache: ISessionCache; const AScope: TBytes;
      const AVerifier: IServerCertificateVerifier): ITlsEngine;
    /// <summary>A permissive client with Reverify + async verdict: the resumption handshake
    /// re-checks inline (accepts) then parks at ServerFinished for the out-of-band verdict.</summary>
    function NewReverifyAsyncClient13(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>A TLS 1.3 server engine; AIssueTickets tickets, resumption toggle.</summary>
    function NewServer13(const AStore: ISessionStore; AIssueTickets: Int32;
      AResumption: Boolean): ITlsEngine;
    /// <summary>A resuming TLS 1.3 server that issues no tickets and seals/accepts only under
    /// AScope, so it declines a ticket another scope issued.</summary>
    function NewScopedServer13(const AStore: ISessionStore;
      const AScope: TBytes): ITlsEngine;
    function NewClient12(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>A permissive TLS 1.2 client with Reverify + async verdict: the abbreviated
    /// resumption handshake re-checks inline (accepts) then parks at the abbreviated
    /// ServerFinished for the out-of-band verdict.</summary>
    function NewReverifyAsyncClient12(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    function NewServer12(const AStore: ISessionStore): ITlsEngine;
    /// <summary>A TLS 1.2 server holding both a session store and ticket keys.</summary>
    function NewServer12WithTicketKeys(const AStore: ISessionStore;
      const AKeys: ISessionTicketKeyManager): ITlsEngine;
    /// <summary>A client and server that both speak TLS 1.2 and 1.3, so each runs behind its
    /// version dispatcher.</summary>
    function NewDualClient(const ACache: ISessionCache): ITlsEngine;
    function NewDualServer(const AStore: ISessionStore): ITlsEngine;
    procedure PumpToCompletion(const AClient, AServer: ITlsEngine);
    /// <summary>Like PumpToCompletion but resolves a parked peer-certificate verdict with
    /// AAccept/AAlert, so the async park (initial-cert or reverify-on-resume) can proceed.</summary>
    procedure PumpToCompletionResolving(const AClient, AServer: ITlsEngine;
      AAccept: Boolean; AAlert: TTlsAlertDescription);
    procedure CheckClientDataReachesServer(const AClient, AServer: ITlsEngine);
  protected
    procedure SetUp; override;
  published
    procedure TestTls13StoreResumptionViaConfig;
    procedure TestTls13BadBinderReplayDoesNotConsumeStoreTicket;
    procedure TestTls13DeclinedTicketIsNotConsumed;
    procedure TestTls13LostCommitRaceFallsBackToFullHandshake;
    procedure TestTls12TicketKeysBesideAStoreSealTheTicketAndStoreNothing;
    procedure TestTls12SessionIdResumptionKeepsStoredSession;
    procedure TestTls12ResumptionViaConfig;
    procedure TestDefaultServerIssuesTicketsOutOfBox;
    procedure TestResumptionOffServerIssuesNoTicket;
    procedure TestStrictPresetLeavesResumptionOff;
    procedure TestStrictResumptionReEnabledWithNoGuard;
    procedure TestSharedCacheDoesNotResumeAcrossConfigurations;
    procedure TestSharedCacheDoesNotResumeAcrossConfigurationsTls12;
    procedure TestSharedSessionScopeResumesAcrossRebuiltConfigs;
    procedure TestReverifyOnResumeRejectsUntrustedServer;
    procedure TestEchRejectChecksTheStoredChainAgainstTheHostBeforeThePublicName;
    procedure TestReverifyOnResumeAsyncParkAcceptsCompletes;
    procedure TestReverifyOnResumeAsyncParkRejectAborts;
    procedure TestLateVerdictAfterFatalAbortQueuesNothing;
    procedure TestExporterWithheldDuringReverifyPark;
    procedure TestTls12ReverifyOnResumeAsyncParkAcceptsCompletes;
    procedure TestTls12ReverifyOnResumeAsyncParkRejectAborts;
    procedure TestTls12ReverifyOnResumeExporterWithheld;
    // the verdict resume holds the engine's re-entrancy guard across the machine callbacks
    procedure TestVerdictResumeRefusesProcessInputFromSessionCacheStore;
    procedure TestVerdictResumeRefusesSetCertificateVerdictFromSessionCacheStore;
    procedure TestStartHandshakeRefusesProcessInputFromSessionCacheTake;
    procedure TestRepeatStartHandshakeTakesTheSessionCacheOnce;
    // invariants that must not move: a resume that CAN obtain a fresh revocation verdict, or that
    // never re-verifies, still resumes exactly as before (guards against widening the gate)
    procedure TestHardReverifyWithLiveVerdictStillResumes;
    procedure TestTls12HardReverifyWithLiveVerdictStillResumes;
    procedure TestHardReuseOriginalStillResumes;
    procedure TestSoftReverifyWithoutLiveVerdictStillResumes;
    // Hard + Reverify needs a live verdict; Build refuses it otherwise
    procedure TestHardReverifyWithoutLiveVerdictIsRefusedAtBuild;
    procedure TestHardReverifyHostDecisionIsRefusedAtBuild;
    // a fatal alert reaches the sessions through the version dispatchers
    procedure TestFatalAlertDropsTls13SessionsBehindTheDispatchers;
    procedure TestFatalAlertDropsTheClientSessionBehindItsDispatcherOnTls12;
  end;

implementation

type
  // a client session cache that can hand back a tampered copy of the cached 1.3 session (same
  // ticket, wrong resumption secret) and later restore the genuine one, to model an attacker who
  // replays a victim's plaintext ticket identity
  TTamperingSessionCache = class(TInterfacedObject, ISessionCache)
  strict private
    FInner: ISessionCache;
    FTamper: Boolean;
    FIdentity, FServerName: string;
    FOriginal: IResumableSession;
  public
    constructor Create(const AInner: ISessionCache);
    procedure Store(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    procedure Remove(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    function Take(const AServerIdentity, AServerName: string; ANowMillis: UInt64;
      out ASession: IResumableSession): Boolean;
    procedure SetKxHint(const AServerIdentity, AServerName: string; AGroup: UInt16);
    function KxHint(const AServerIdentity, AServerName: string): UInt16;
    procedure Clear;
    function Count: Int32;
    /// <summary>Puts the genuine session back into the inner cache.</summary>
    procedure Restore;
    property Tamper: Boolean read FTamper write FTamper;
  end;

  // a session store that removes a session right after it is looked up, standing in for another
  // connection that commits the same ticket between this connection's lookup and its commit
  TRacingSessionStore = class(TInterfacedObject, ISessionStore)
  strict private
    FInner: ISessionStore;
  public
    constructor Create(const AInner: ISessionStore);
    function Put(const ASession: IResumableSession): TBytes;
    procedure PutWithId(const AId: TBytes; const ASession: IResumableSession);
    function Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
    function Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
    procedure Remove(const AId: TBytes);
    procedure Clear;
    function Count: Int32;
  end;

{ TRacingSessionStore }

constructor TRacingSessionStore.Create(const AInner: ISessionStore);
begin
  inherited Create;
  FInner := AInner;
end;

function TRacingSessionStore.Put(const ASession: IResumableSession): TBytes;
begin
  Result := FInner.Put(ASession);
end;

procedure TRacingSessionStore.PutWithId(const AId: TBytes; const ASession: IResumableSession);
begin
  FInner.PutWithId(AId, ASession);
end;

function TRacingSessionStore.Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
begin
  Result := FInner.Peek(AId, ASession);
  if Result then
    FInner.Remove(AId);
end;

function TRacingSessionStore.Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
begin
  Result := FInner.Take(AId, ASession);
end;

procedure TRacingSessionStore.Remove(const AId: TBytes);
begin
  FInner.Remove(AId);
end;

procedure TRacingSessionStore.Clear;
begin
  FInner.Clear;
end;

function TRacingSessionStore.Count: Int32;
begin
  Result := FInner.Count;
end;

{ TTamperingSessionCache }

constructor TTamperingSessionCache.Create(const AInner: ISessionCache);
begin
  inherited Create;
  FInner := AInner;
end;

procedure TTamperingSessionCache.Store(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
  FIdentity := AServerIdentity;
  FServerName := AServerName;
  FInner.Store(AServerIdentity, AServerName, ASession);
end;

procedure TTamperingSessionCache.Remove(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
  FInner.Remove(AServerIdentity, AServerName, ASession);
end;

function TTamperingSessionCache.Take(const AServerIdentity, AServerName: string;
  ANowMillis: UInt64; out ASession: IResumableSession): Boolean;
var
  L13: ITls13ResumableSession;
  LWrong: TBytes;
begin
  Result := FInner.Take(AServerIdentity, AServerName, ANowMillis, ASession);
  if not (Result and FTamper and Supports(ASession, ITls13ResumableSession, L13)) then
    Exit;
  // keep the real session aside and hand back one with the same ticket but a wrong secret, so the
  // ClientHello names a genuine identity yet carries a binder the server cannot verify
  FOriginal := ASession;
  LWrong := nil;
  SetLength(LWrong, L13.ResumptionSecret.Len);
  FillChar(LWrong[0], System.Length(LWrong), $5A);
  ASession := TTls13ResumableSession.Create(ASession.CipherSuite, ASession.Hash,
    TSecretBuffer.From(LWrong), ASession.Alpn, ASession.ServerName, L13.TicketIdentity,
    ASession.TicketLifetime, L13.TicketAgeAdd, ASession.IssuedAtMillis, L13.MaxEarlyData,
    ASession.PeerCertificates, ASession.ResumptionScope);
end;

procedure TTamperingSessionCache.Restore;
begin
  FInner.Store(FIdentity, FServerName, FOriginal);
end;

procedure TTamperingSessionCache.SetKxHint(const AServerIdentity, AServerName: string;
  AGroup: UInt16);
begin
  FInner.SetKxHint(AServerIdentity, AServerName, AGroup);
end;

function TTamperingSessionCache.KxHint(const AServerIdentity, AServerName: string): UInt16;
begin
  Result := FInner.KxHint(AServerIdentity, AServerName);
end;

procedure TTamperingSessionCache.Clear;
begin
  FInner.Clear;
end;

function TTamperingSessionCache.Count: Int32;
begin
  Result := FInner.Count;
end;

{ TTestConfigResumption }

procedure TTestConfigResumption.SetUp;
begin
  inherited SetUp;
  FCerts := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
end;

function TTestConfigResumption.StaplingCredential: TTlsCredential;
begin
  // leaf + issuer, with a current Good OCSP response sealed on the credential so the server
  // sends a CertificateStatus when the client requests one
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'issuer_cert'));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_key'), nil);
  Result.OcspStaple := TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'ocsp_good');
end;

function TTestConfigResumption.NewStaplingServer13(const AStore: ISessionStore;
  AIssueTickets: Int32): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(StaplingCredential)
    .WithResumption(True)
    .WithSessionStore(AStore)
    .Tls13.WithTicketCount(AIssueTickets)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewStaplingServer12(
  const AStore: ISessionStore): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCredential(StaplingCredential)
    .WithSessionStore(AStore)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewStaplingSeedClient13(const ACache: ISessionCache;
  const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // permissive: trusts the stapling root and completes a full handshake, caching the ticket the
  // strict client draws from; the host check is disabled to isolate the resumption behaviour
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(TTlsLibTestCertificates.Field(
      'Certs/OcspStapling.txt', 'root_cert')).Build)
    .WithDangerousDisableServerNameCheck
    .WithResumption(True)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewStaplingSeedClient12(const ACache: ISessionCache;
  const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithServerVerification(TServerVerification.WebPki(TTlsLibTestCertificates.Field(
      'Certs/OcspStapling.txt', 'root_cert')).Build)
    .WithDangerousDisableServerNameCheck
    .WithResumption(True)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewHardReverifyClient13(const ACache: ISessionCache;
  const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(TTlsLibTestCertificates.Field(
      'Certs/OcspStapling.txt', 'root_cert'))
    .WithRevocation(TRevocationPosture.Hard).Build)
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithResumption(True)
    .WithSessionCache(ACache).WithResumptionScope(AScope);
  if ADeferral = TVerdictDeferral.LiveRevocation then
    LClient.WithLiveRevocationVerdict(0)
  else if ADeferral = TVerdictDeferral.HostDecision then
    LClient.WithAsyncCertificateVerdict(0);
  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, ServerHost);
end;

function TTestConfigResumption.NewHardReverifyClient12(const ACache: ISessionCache;
  const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithServerVerification(TServerVerification.WebPki(TTlsLibTestCertificates.Field(
      'Certs/OcspStapling.txt', 'root_cert'))
    .WithRevocation(TRevocationPosture.Hard).Build)
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithResumption(True)
    .WithSessionCache(ACache).WithResumptionScope(AScope);
  if ADeferral = TVerdictDeferral.LiveRevocation then
    LClient.WithLiveRevocationVerdict(0)
  else if ADeferral = TVerdictDeferral.HostDecision then
    LClient.WithAsyncCertificateVerdict(0);
  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, ServerHost);
end;

function TTestConfigResumption.NewHardReuseOriginalClient13(
  const ACache: ISessionCache; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // Hard posture but the default ReuseOriginal (no re-verify on resume), so the gate never fires
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(TTlsLibTestCertificates.Field(
      'Certs/OcspStapling.txt', 'root_cert'))
    .WithRevocation(TRevocationPosture.Hard).Build)
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True)
    .WithResumption(True)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewClient13(const ACache: ISessionCache;
  AResumption: Boolean; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // Hardened is TLS 1.3-only; the public surface wires the cache and resumption toggle
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumption(AResumption)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewRejectingClient13(
  const ACache: ISessionCache): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.Custom(
    TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate)
    as IServerCertificateVerifier))
    .WithResumption(True)
    .WithSessionCache(ACache)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewReverifyRejectClient13(
  const ACache: ISessionCache; const AScope: TBytes;
  const AVerifier: IServerCertificateVerifier): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.Custom(AVerifier))
    .WithResumption(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewReverifyAsyncClient13(
  const ACache: ISessionCache; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // permissive trust accepts the server chain inline; Reverify + async verdict make the
  // resumption handshake check the stored chain before offering it, then park at ServerFinished
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumption(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithAsyncCertificateVerdict(0)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewServer13(const AStore: ISessionStore;
  AIssueTickets: Int32; AResumption: Boolean): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithResumption(AResumption)
    .WithSessionStore(AStore)
    .Tls13.WithTicketCount(AIssueTickets)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewScopedServer13(const AStore: ISessionStore;
  const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithResumption(True)
    .WithSessionStore(AStore)
    .WithResumptionScope(AScope)
    .Tls13.WithTicketCount(0)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewClient12(const ACache: ISessionCache;
  const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewReverifyAsyncClient12(
  const ACache: ISessionCache; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // permissive trust accepts the resumed chain inline; Reverify + async verdict make the
  // abbreviated resumption check the stored chain before offering it, then park for the verdict
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumption(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithAsyncCertificateVerdict(0)
    .WithSessionCache(ACache).WithResumptionScope(AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewServer12(const AStore: ISessionStore): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCredential(ServerCredential)
    .WithSessionStore(AStore)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewServer12WithTicketKeys(const AStore: ISessionStore;
  const AKeys: ISessionTicketKeyManager): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCredential(ServerCredential)
    .WithSessionStore(AStore)
    .WithSessionTicketKeys(AKeys)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewDualClient(const ACache: ISessionCache): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumption(True)
    .WithSessionCache(ACache)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewDualServer(const AStore: ISessionStore): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithSessionStore(AStore)
    .Tls13.WithTicketCount(1)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

procedure TTestConfigResumption.PumpToCompletion(const AClient, AServer: ITlsEngine);
begin
  RunHandshake(AClient, AServer);
  // flush any post-handshake NewSessionTicket from the server to the client
  Pump(AServer, AClient);
end;

procedure TTestConfigResumption.PumpToCompletionResolving(const AClient,
  AServer: ITlsEngine; AAccept: Boolean; AAlert: TTlsAlertDescription);
var
  LIterations: Int32;
begin
  AClient.StartHandshake;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    // resolve a parked peer-certificate verdict so the client can emit its withheld flight
    if AClient.AwaitingCertificateVerdict then
      AClient.SetCertificateVerdict(AAccept, AAlert);
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
  Pump(AServer, AClient);
end;

procedure TTestConfigResumption.CheckClientDataReachesServer(const AClient, AServer: ITlsEngine);
var
  LFromClient: TBytes;
begin
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes('the server decrypts the client application data', LFromClient,
    ReadAllApp(AServer));
end;

procedure TTestConfigResumption.TestTls13StoreResumptionViaConfig;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the public surface: a store-backed 1.3 server issues one stateful ticket; a later
  // handshake resumes it. The store single-use consumption proves the config wired through.
  // One logical client reconnecting keeps its scope, so both connections share it.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 1, True);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial 1.3 handshake completed');
  CheckEquals(1, LStore.Count, 'the server stored one resumable session');
  CheckEquals(1, LCache.Count, 'the client cached the ticket');

  // the resuming server issues no new ticket, so a consumed store proves resumption
  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 0, True);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resuming server completed');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  CheckEquals(0, LStore.Count, 'the stored session was consumed (resumed via the config)');
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestConfigResumption.TestTls13BadBinderReplayDoesNotConsumeStoreTicket;
var
  LTamper: TTamperingSessionCache;
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a store handle travels in the clear, so anyone who saw a ClientHello can replay its identity.
  // A binder the server cannot verify is fatal, but it must not use the victim's ticket up
  LTamper := TTamperingSessionCache.Create(TInMemorySessionCache.Create as ISessionCache);
  LCache := LTamper;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 1, True);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the server stored the victim''s ticket');

  LTamper.Tamper := True;
  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 0, True);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'a binder that does not verify is fatal');
  CheckEquals(1, LStore.Count, 'the replay did not consume the victim''s ticket');

  LTamper.Tamper := False;
  LTamper.Restore;
  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 0, True);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the victim still resumes');
  CheckEquals(0, LStore.Count, 'the genuine resumption used the ticket up (single-use)');
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestConfigResumption.TestTls13DeclinedTicketIsNotConsumed;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LHello: TBytes;
  LIterations: Int32;
begin
  // a server whose resumption scope differs opens the ticket, then declines it (the scope check
  // runs after the session is recovered). A decline leaves the stored ticket alone, so only an
  // actual resumption uses it up
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 1, True);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the server stored one ticket');

  LClient := NewClient13(LCache, True, LScope);
  LServer := NewScopedServer13(LStore, Crypto.Primitives.GetRandom.GenerateBytes(16));
  LClient.StartHandshake;
  LHello := Drain(LClient);
  CheckTrue(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LHello)
    .Contains(TExtensionTypes.PreSharedKey), 'the ClientHello offers the ticket');
  Feed(LServer, LHello);
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LServer, LClient);
    Pump(LClient, LServer);
    Inc(LIterations);
  end;
  CheckFalse(LServer.IsTerminal, 'the declined connection fell back to a full handshake');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the other scope did not resume the ticket');
  CheckEquals(1, LStore.Count, 'the declined ticket is still in the store');
end;

procedure TTestConfigResumption.TestTls13LostCommitRaceFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LInner, LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // two connections can both recover the same stored ticket and both verify its binder; only one
  // commit wins. The racing store models the winner by removing the ticket right after this
  // connection recovers it, so this connection's commit loses and must fall back to a full
  // handshake rather than resume (or fail) on a ticket someone else already used
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LInner := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LStore := TRacingSessionStore.Create(LInner);

  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 1, True);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the server stored one ticket');

  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 0, True);
  PumpToCompletion(LClient, LServer);
  CheckEquals(0, LCache.Count, 'the client drew the ticket to offer it');
  CheckEquals(0, LInner.Count, 'the racing lookup removed the ticket');
  CheckFalse(LServer.IsTerminal, 'losing the commit is a decline, not a failure');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the ticket was not resumed twice');
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestConfigResumption.TestTls12TicketKeysBesideAStoreSealTheTicketAndStoreNothing;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStoreImpl: TMockSessionStore;
  LStore: ISessionStore;
  LKeys: ISessionTicketKeyManager;
  LClient, LServer: ITlsEngine;
begin
  // TLS 1.2 seals its ticket with the keys even when a store is configured; the store would
  // only serve a session id, and none is kept once the ticket carries the session
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStoreImpl := TMockSessionStore.Create;
  LStore := LStoreImpl;
  LKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12WithTicketKeys(LStore, LKeys);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client received one ticket');
  CheckEquals(0, LStore.Count, 'the ticket carries the session, so the store holds none');

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12WithTicketKeys(LStore, LKeys);
  CheckFalse(DriveObservingServerCert(LClient, LServer), 'the second handshake resumed');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed from the ticket');
  CheckEquals(0, LStoreImpl.TakeCount, 'resumption never touched the store');
  CheckEquals(0, LStore.Count, 'and the store is still empty');
end;

procedure TTestConfigResumption.TestTls12SessionIdResumptionKeepsStoredSession;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStoreImpl: TMockSessionStore;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a 1.2 session id is reusable and travels in the clear: resumption looks it up without removing
  // it, so the store is never touched by Take and the session stays resumable
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStoreImpl := TMockSessionStore.Create;
  LStore := LStoreImpl;

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the server stored the 1.2 session');

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  CheckFalse(DriveObservingServerCert(LClient, LServer), 'the second handshake resumed');
  CheckFalse(LServer.IsTerminal, 'the resumption did not fail');
  CheckEquals(0, LStoreImpl.TakeCount, 'resumption never removed the stored session');
  CheckEquals(1, LStore.Count, 'the session is still stored');
end;

procedure TTestConfigResumption.TestTls12ResumptionViaConfig;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a TLS 1.2 client and server through the public surface: the second handshake resumes,
  // proven by the abbreviated server flight (no plaintext Certificate). One logical client
  // reconnecting shares its scope across both connections.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial 1.2 handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    '1.2 resumption via the config is abbreviated (no Certificate)');
  CheckFalse(LServer.IsTerminal, 'the 1.2 resume did not fail');
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestConfigResumption.TestDefaultServerIssuesTicketsOutOfBox;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a server built through the public surface with only a credential - no WithSessionStore and
  // no WithDefaultSessionTicketKeys - resumes out of the box: the resume-by-default posture mints
  // a STEK, so the server issues a ticket the client caches and can later present. One frozen
  // config is reused across both handshakes so the same STEK opens the ticket. One logical client
  // reconnecting shares its scope across both connections.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;

  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial handshake completed');
  CheckTrue(LCache.Count >= 1, 'the default server issued a ticket the client cached');

  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resuming server completed');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  // prove it actually resumed via the out-of-box ticket, not a silent full-handshake fallback
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the second handshake resumed off the auto-issued ticket');
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestConfigResumption.TestResumptionOffServerIssuesNoTicket;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // WithResumption(False) opts a server out even under the resume-by-default posture: no STEK is
  // engaged, so no ticket is issued and the client caches nothing
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient13(LCache, True, nil);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithResumption(False).Build);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckEquals(0, LCache.Count, 'a resumption-off server issued no ticket');
end;

procedure TTestConfigResumption.TestStrictPresetLeavesResumptionOff;
var
  LClient, LServer: ITlsEngine;
  LRefusedCache, LRefusedStore: Boolean;
begin
  // the Strict preset defaults resumption OFF: a cache or store supplied on top would never be
  // engaged, so Build refuses it rather than leave it silently inert
  LRefusedCache := False;
  try
    TTlsPresets.Strict(Crypto, Pkix).Client
      .WithServerVerification(
        TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
      .WithSessionCache(TInMemorySessionCache.Create).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRefusedCache := True;
  end;
  CheckTrue(LRefusedCache, 'a session cache with resumption off is refused');
  LRefusedStore := False;
  try
    TTlsPresets.Strict(Crypto, Pkix).Server.WithCredential(ServerCredential)
      .WithSessionStore(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRefusedStore := True;
  end;
  CheckTrue(LRefusedStore, 'a session store with resumption off is refused');

  // control: Strict as it ships completes a handshake and resumes nothing
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Build, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the Strict handshake completed');
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestConfigResumption.TestStrictResumptionReEnabledWithNoGuard;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // Strict is a mutable starting point: re-enabling resumption on it needs no ceremony. One logical
  // client reconnecting shares its scope across both connections.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Crypto, Pkix).Client
    .WithResumption(True).WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithSessionCache(LCache).WithResumptionScope(LScope).Build,
    ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Crypto, Pkix).Server
    .WithResumption(True).WithCredential(ServerCredential).WithSessionStore(LStore)
    .Tls13.WithTicketCount(1).Build);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LStore.Count, 're-enabled Strict stored a session');

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Crypto, Pkix).Client
    .WithResumption(True).WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithSessionCache(LCache).WithResumptionScope(LScope).Build,
    ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Crypto, Pkix).Server
    .WithResumption(True).WithCredential(ServerCredential).WithSessionStore(LStore)
    .Tls13.WithTicketCount(0).Build);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 're-enabled Strict resume did not fail');
  CheckEquals(0, LStore.Count, 're-enabled Strict resumed (store consumed)');
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestConfigResumption.TestSharedCacheDoesNotResumeAcrossConfigurations;
var
  LCache: ISessionCache;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a permissive client establishes and caches a resumable session; one STEK-backed server config
  // is reused so the ticket stays openable across the connections below
  LCache := TInMemorySessionCache.Create;
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, nil);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the permissive handshake completed');
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // a client whose verifier rejects every chain, given the SAME cache instance but its own
  // configuration, must not see the permissive config's session (scopes differ by construction):
  // it runs a full handshake and its verifier rejects the server. Were it to resume, its verifier
  // would never be consulted (a resumed handshake sends no certificate) - the bypass this prevents.
  LClient := NewRejectingClient13(LCache);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.Resumed, 'a shared cache does not resume across configurations');
  CheckTrue(LClient.IsTerminal,
    'so the strict config runs a full handshake and its verifier rejects the server');
end;

procedure TTestConfigResumption.TestSharedCacheDoesNotResumeAcrossConfigurationsTls12;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the 1.2 twin of the isolation property: one cache instance shared by two client configurations
  // (each its own fresh scope) does not resume across them
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, nil);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the first 1.2 configuration cached a session');

  // a different configuration sharing the same cache cannot see it (scopes differ), so the server
  // flight carries a full Certificate rather than an abbreviated resume
  LClient := NewClient12(LCache, nil);
  LServer := NewServer12(LStore);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a shared cache does not resume a 1.2 session across configurations');
end;

procedure TTestConfigResumption.TestSharedSessionScopeResumesAcrossRebuiltConfigs;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // two client configurations given the SAME explicit scope share sessions through one cache (the
  // caller asserts they trust identically) - the pattern an app rebuilding its config per connection
  // relies on to keep resuming
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the first scoped configuration cached a session');

  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'a configuration with the same scope resumes the shared session');

  // a configuration with no explicit scope (a fresh per-build one) does not resume across them,
  // even sharing the same cache instance; a scoped session must remain for the check to be real
  CheckTrue(LCache.Count >= 1, 'a session remains for the unshared configuration to be denied');
  LClient := NewClient13(LCache, True, nil);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.Resumed,
    'an unshared-scope configuration does not draw another configuration''s session');
end;

procedure TTestConfigResumption.TestReverifyOnResumeRejectsUntrustedServer;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
  LRejecting: TFixedVerdictVerifier;
  LVerifier: IServerCertificateVerifier;
begin
  // a permissive client caches a resumable session, storing the server chain it verified; the two
  // configs share a scope so the resuming one draws the stored session (they trust identically)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the permissive handshake completed');
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // a Reverify client drawing the same session declines it, then its full handshake fails too;
  // the verifier is asked twice: once before the offer, once for the fresh chain
  LBefore := LCache.Count;
  LRejecting := TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate);
  LVerifier := LRejecting;
  LClient := NewReverifyRejectClient13(LCache, LScope, LVerifier);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session (single-use Take)');
  CheckEquals(2, LRejecting.Calls, 'the offer-time check and the full handshake each verified');
  CheckTrue(LClient.IsTerminal, 'the full handshake rejected the untrusted server');
end;

procedure TTestConfigResumption.TestEchRejectChecksTheStoredChainAgainstTheHostBeforeThePublicName;
var
  LCache: ISessionCache;
  LScope, LPublicKey, LConfigList: TBytes;
  LSk: ISecretBuffer;
  LSuite: TEchCipherSuite;
  LConfig: TEchConfig;
  LRecorder: TRecordingServerVerifier;
  LVerifier: IServerCertificateVerifier;
  LClient, LServer: ITlsEngine;

  function NewEchClient: ITlsEngine;
  begin
    Result := TTlsEngineFactory.CreateClientEngine(
      TTlsPresets.Hardened(Crypto, Pkix).Client
      .WithServerVerification(TServerVerification.Custom(LVerifier))
      .WithResumption(True)
      .WithResumeVerification(TResumeVerification.Reverify)
      .WithSessionCache(LCache).WithResumptionScope(LScope)
      .Tls13.WithEch(TEchClientModes.Enable(LConfigList)).Build, ServerHost);
  end;

begin
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey, LSk);
  LSuite.KdfId := THpkeKdf.HKDF_SHA256;
  LSuite.AeadId := THpkeAead.AES_128_GCM;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, $E1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey, TArray<TEchCipherSuite>.Create(LSuite), 0,
    TEncoding.ASCII.GetBytes('cover.example'), nil);
  LConfigList := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);

  // an ECH-accepted connection caches a session verified against the origin host
  LRecorder := TRecordingServerVerifier.Create(TFixedVerdictVerifier.CreateAccepting(True)
    as IServerCertificateVerifier);
  LVerifier := LRecorder;
  LClient := NewEchClient;
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Tls13.WithEchKeyStore(TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Crypto)).Build);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'ECH was accepted');
  CheckTrue(LCache.Count >= 1, 'the accepted connection cached a session');

  // the resumption meets a server that rejects ECH: the stored chain is checked before the offer,
  // against the host, and only the reject's retry verifies the public_name
  LRecorder := TRecordingServerVerifier.Create(TFixedVerdictVerifier.CreateAccepting(True)
    as IServerCertificateVerifier);
  LVerifier := LRecorder;
  LClient := NewEchClient;
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the ECH reject aborted the connection');
  CheckEquals(2, System.Length(LRecorder.Names), 'the chain was verified twice');
  CheckEquals(ServerHost, LRecorder.Names[0], 'the offer-time check ran against the host');
  CheckEquals('cover.example', LRecorder.Names[1], 'the reject then verified the public_name');
end;

procedure TTestConfigResumption.TestReverifyOnResumeAsyncParkAcceptsCompletes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
begin
  // a permissive client caches a resumable session (shared scope so the resuming config draws it)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // resume with Reverify + async: the offer-time check passes, the handshake parks at
  // ServerFinished (the client Finished is withheld), and the accepted out-of-band verdict
  // drives the withheld continuation to completion
  LClient := NewReverifyAsyncClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletionResolving(LClient, LServer, True,
    TTlsAlertDescription.BadCertificate);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the async reverify-on-resume handshake resumed');
  CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted verdict did not abort');
  // a Reverify resume re-runs PKIX here, so the presented stored chain and the validated path both surface
  LInfo := LClient.ConnectionInfo;
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the presented chain is the stored leaf-only credential');
  CheckEqualBytes('the presented chain leaf is the server leaf',
    DecodeHex(FCerts.Values['leaf_cert']), LInfo.PeerCertificates[0]);
  CheckTrue(System.Length(LInfo.ValidatedPath) >= 2,
    'the Reverify resume validated a path beyond the presented leaf');
  CheckEqualBytes('the validated path leaf is the server leaf',
    DecodeHex(FCerts.Values['leaf_cert']), LInfo.ValidatedPath[0]);
  CheckEqualBytes('the validated path terminates at the trust root',
    DecodeHex(FCerts.Values['root_cert']),
    LInfo.ValidatedPath[System.High(LInfo.ValidatedPath)]);
end;

procedure TTestConfigResumption.TestLateVerdictAfterFatalAbortQueuesNothing;
var
  LCache: ISessionCache;
  LScope, LBad, LOut: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
begin
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);

  LClient := NewReverifyAsyncClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient.StartHandshake;
  LIterations := 0;
  while (not LClient.AwaitingCertificateVerdict) and LClient.IsHandshaking and
    (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client parked on the reverify verdict');

  // the parked client still owes its closing flight; a fatal abort while parked must win
  LBad := DecodeHex('ff03030005' + '0102030405');
  LClient.ProcessInput(LBad, 0, System.Length(LBad));
  CheckTrue(LClient.IsTerminal, 'the bad record header aborts the engine');
  System.SetLength(LOut, 4096);
  LClient.TakeOutgoing(LOut, 0);
  CheckFalse(LClient.WantsWrite, 'only the fatal alert was queued');

  LClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  CheckFalse(LClient.WantsWrite, 'a late accept queues no Finished behind the alert');
  CheckTrue(LClient.IsTerminal, 'the engine stays terminal');
end;

procedure TTestConfigResumption.TestExporterWithheldDuringReverifyPark;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LIterations, LBefore: Int32;
  LInfo: TTlsConnectionInfo;
begin
  // cache a resumable session (shared scope so the resuming config draws it)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);

  // resume with reverify + async: drive until the client parks on the verdict. It has processed
  // ServerFinished (so its application/exporter secrets are derived), but the resumed identity is
  // not yet accepted.
  LBefore := LCache.Count;
  LClient := NewReverifyAsyncClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient.StartHandshake;
  LIterations := 0;
  while (not LClient.AwaitingCertificateVerdict) and LClient.IsHandshaking and
    (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client parked on the reverify verdict');
  // it drew the cached session (single-use Take) to reach this park, proving a resumption not a
  // full handshake (which would also park under an async verdict)
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  // the presented chain is already surfaced before the park (it is emitted with the verified chain,
  // ahead of the verdict), even though the resumed identity is not yet accepted
  LInfo := LClient.ConnectionInfo;
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the presented chain is populated before the park clears');
  CheckEqualBytes('the presented chain leaf is the server leaf',
    DecodeHex(FCerts.Values['leaf_cert']), LInfo.PeerCertificates[0]);
  // the exporter is withheld while parked, even though the secret is derived - no keying
  // material is exported over an unverified resumed identity
  CheckEquals(0, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test',
    DecodeHex('00010203'), 32)), 'no export while parked on the reverify verdict');

  // accept and complete; the exporter is then available
  LClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  LIterations := 0;
  while LClient.IsHandshaking and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the handshake completed after the accepted verdict');
  CheckEquals(32, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test',
    DecodeHex('00010203'), 32)), 'the exporter is available after the peer is accepted');
  // once accepted, the Reverify resume has also validated a path here
  LInfo := LClient.ConnectionInfo;
  CheckTrue(System.Length(LInfo.ValidatedPath) >= 2,
    'the Reverify resume validated a path beyond the presented leaf');
  CheckEqualBytes('the validated path leaf is the server leaf',
    DecodeHex(FCerts.Values['leaf_cert']), LInfo.ValidatedPath[0]);
  CheckEqualBytes('the validated path terminates at the trust root',
    DecodeHex(FCerts.Values['root_cert']),
    LInfo.ValidatedPath[System.High(LInfo.ValidatedPath)]);
end;

procedure TTestConfigResumption.TestReverifyOnResumeAsyncParkRejectAborts;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // resume with Reverify + async, then REJECT the out-of-band verdict: the parked handshake
  // aborts fail-closed with the resolver's alert (augment-only); the client Finished is never sent
  LBefore := LCache.Count;
  LClient := NewReverifyAsyncClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletionResolving(LClient, LServer, False,
    TTlsAlertDescription.CertificateRevoked);
  // it drew the cached session (single-use Take), proving it parked on a resumption not a full handshake
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.IsTerminal, 'a rejected park aborted the resumed handshake');
end;

procedure TTestConfigResumption.ProbeProcessInputFromStore;
var
  LNothing: TBytes;
begin
  Inc(FProbeStores);
  LNothing := nil;
  try
    FProbeEngine.ProcessInput(LNothing, 0, 0);
  except
    on EInvalidOperationTlsLibException do
      FProbeRefused := True;
  end;
end;

procedure TTestConfigResumption.ProbeSetVerdictFromStore;
begin
  Inc(FProbeStores);
  try
    FProbeEngine.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  except
    on EInvalidOperationTlsLibException do
      FProbeRefused := True;
  end;
end;

procedure TTestConfigResumption.ResumeAndAcceptWithStoreProbe(AOnStored: TSessionCacheEvent);
var
  LCacheImpl: TMockSessionCache;
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCacheImpl := TMockSessionCache.Create;
  LCache := LCacheImpl as ISessionCache;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');
  LClient := NewReverifyAsyncClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  FProbeEngine := LClient;
  FProbeStores := 0;
  FProbeRefused := False;
  LCacheImpl.OnStored := AOnStored;
  try
    PumpToCompletionResolving(LClient, LServer, True, TTlsAlertDescription.BadCertificate);
  finally
    LCacheImpl.OnStored := nil;
    FProbeEngine := nil;
  end;
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the parked resumption completed');
  CheckTrue(FProbeStores > 0, 'the accepted verdict re-stored the session through the cache');
end;

procedure TTestConfigResumption.TestVerdictResumeRefusesProcessInputFromSessionCacheStore;
begin
  ResumeAndAcceptWithStoreProbe(ProbeProcessInputFromStore);
  CheckTrue(FProbeRefused, 'ProcessInput from inside the resume is refused');
end;

procedure TTestConfigResumption.TestVerdictResumeRefusesSetCertificateVerdictFromSessionCacheStore;
begin
  ResumeAndAcceptWithStoreProbe(ProbeSetVerdictFromStore);
  CheckTrue(FProbeRefused, 'SetCertificateVerdict from inside the resume is refused');
end;

procedure TTestConfigResumption.TestStartHandshakeRefusesProcessInputFromSessionCacheTake;
var
  LCacheImpl: TMockSessionCache;
  LCache: ISessionCache;
  LClient: ITlsEngine;
begin
  LCacheImpl := TMockSessionCache.Create;
  LCache := LCacheImpl as ISessionCache;
  LClient := NewClient12(LCache, Crypto.Primitives.GetRandom.GenerateBytes(16));
  FProbeEngine := LClient;
  FProbeStores := 0;
  FProbeRefused := False;
  LCacheImpl.OnTake := ProbeProcessInputFromStore;
  try
    LClient.StartHandshake;
  finally
    LCacheImpl.OnTake := nil;
    FProbeEngine := nil;
  end;
  CheckTrue(FProbeStores > 0, 'the start looked the session up through the cache');
  CheckTrue(FProbeRefused, 'ProcessInput from inside the start is refused');
end;

procedure TTestConfigResumption.TestRepeatStartHandshakeTakesTheSessionCacheOnce;
var
  LCacheImpl: TMockSessionCache;
  LCache: ISessionCache;
  LClient: ITlsEngine;
  LRefused: Boolean;
begin
  LCacheImpl := TMockSessionCache.Create;
  LCache := LCacheImpl as ISessionCache;
  LClient := NewClient12(LCache, Crypto.Primitives.GetRandom.GenerateBytes(16));
  FProbeEngine := LClient;
  FProbeStores := 0;
  LCacheImpl.OnTake := ProbeProcessInputFromStore;
  LRefused := False;
  try
    LClient.StartHandshake;
    try
      LClient.StartHandshake;
    except
      on EInvalidOperationTlsLibException do
        LRefused := True;
    end;
  finally
    LCacheImpl.OnTake := nil;
    FProbeEngine := nil;
  end;
  CheckTrue(LRefused, 'the second start is refused');
  CheckEquals(1, FProbeStores, 'the session cache was taken once');
end;

procedure TTestConfigResumption.TestTls12ReverifyOnResumeAsyncParkAcceptsCompletes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
begin
  // a permissive 1.2 client caches a resumable session (shared scope so the resuming config draws it)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');

  // resume with Reverify + async: the offer-time check passes, the abbreviated handshake parks at
  // the server Finished (the client Finished is withheld), and the accepted out-of-band verdict
  // drives the withheld continuation to completion
  LClient := NewReverifyAsyncClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletionResolving(LClient, LServer, True,
    TTlsAlertDescription.BadCertificate);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the async reverify-on-resume 1.2 handshake resumed');
  CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted verdict did not abort');
  // a Reverify resume re-runs PKIX here, so the presented stored chain and the validated path both surface
  LInfo := LClient.ConnectionInfo;
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the presented chain is the stored leaf-only credential');
  CheckEqualBytes('the presented chain leaf is the server leaf',
    DecodeHex(FCerts.Values['leaf_cert']), LInfo.PeerCertificates[0]);
  CheckTrue(System.Length(LInfo.ValidatedPath) >= 2,
    'the Reverify resume validated a path beyond the presented leaf');
  CheckEqualBytes('the validated path leaf is the server leaf',
    DecodeHex(FCerts.Values['leaf_cert']), LInfo.ValidatedPath[0]);
  CheckEqualBytes('the validated path terminates at the trust root',
    DecodeHex(FCerts.Values['root_cert']),
    LInfo.ValidatedPath[System.High(LInfo.ValidatedPath)]);
end;

procedure TTestConfigResumption.TestTls12ReverifyOnResumeAsyncParkRejectAborts;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');

  // resume, then REJECT the out-of-band verdict: the parked handshake aborts fail-closed with the
  // resolver's alert (augment-only); the client Finished is never sent, so the server also aborts
  LClient := NewReverifyAsyncClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletionResolving(LClient, LServer, False,
    TTlsAlertDescription.CertificateRevoked);
  // the client drew the one cached session (single-use Take), proving it resumed rather than
  // running a full handshake that would also end terminal
  CheckEquals(0, LCache.Count, 'the client drew the cached 1.2 session to resume it');
  CheckTrue(LClient.IsTerminal, 'a rejected park aborted the resumed 1.2 handshake');
  CheckTrue(LServer.IsTerminal, 'the abort reached the server');
end;

procedure TTestConfigResumption.TestTls12ReverifyOnResumeExporterWithheld;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LInfo: TTlsConnectionInfo;
begin
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);

  // drive until the client parks on the verdict; no verdict is supplied, so the handshake must
  // not complete and no keying material may be exported over the unverified resumed identity
  LClient := NewReverifyAsyncClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  LClient.StartHandshake;
  LIterations := 0;
  while (not LClient.AwaitingCertificateVerdict) and LClient.IsHandshaking and
    (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the 1.2 client parked on the reverify verdict');
  // it drew the one cached session (single-use Take) to reach this park, proving a resumption
  CheckEquals(0, LCache.Count, 'the client drew the cached 1.2 session to resume it');
  CheckTrue(LClient.IsHandshaking, 'the parked 1.2 handshake has not completed without a verdict');
  // the presented chain is already surfaced before the park clears, ahead of the verdict
  LInfo := LClient.ConnectionInfo;
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the presented chain is populated before the park clears');
  CheckEqualBytes('the presented chain leaf is the server leaf',
    DecodeHex(FCerts.Values['leaf_cert']), LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test',
    DecodeHex('00010203'), 32)), 'no export while parked on the reverify verdict');
end;

procedure TTestConfigResumption.TestHardReverifyWithLiveVerdictStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // a live-revocation deferral gives the reverified resume a fresh channel, so a Hard client with
  // WithLiveRevocationVerdict still resumes: the resume re-checks inline (accepts) then parks for
  // the live verdict, which the accepted resolution clears. Guards the gate from widening to
  // posture alone.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 1);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the seed full handshake completed');
  CheckTrue(LCache.Count >= 1, 'the seed client cached a session');

  LBefore := LCache.Count;
  LClient := NewHardReverifyClient13(LCache, LScope, TVerdictDeferral.LiveRevocation);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletionResolving(LClient, LServer, True, TTlsAlertDescription.BadCertificate);
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'Hard + Reverify + LiveRevocation still resumes');
  CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted live verdict did not abort');
end;

procedure TTestConfigResumption.TestTls12HardReverifyWithLiveVerdictStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the TLS 1.2 twin: a Hard + Reverify + LiveRevocation client resumes the abbreviated handshake,
  // re-checks inline, parks for the live verdict, and completes on the accepted resolution
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient12(LCache, LScope);
  LServer := NewStaplingServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the seed 1.2 client cached a session');

  LClient := NewHardReverifyClient12(LCache, LScope, TVerdictDeferral.LiveRevocation);
  LServer := NewStaplingServer12(LStore);
  PumpToCompletionResolving(LClient, LServer, True, TTlsAlertDescription.BadCertificate);
  // the abbreviated resume completes, so the server re-issues a ticket the client re-caches;
  // ConnectionInfo.Resumed (not the cache count) is the resume tell here
  CheckTrue(LClient.ConnectionInfo.Resumed,
    '1.2 Hard + Reverify + LiveRevocation still resumes');
  CheckFalse(LClient.IsHandshaking, 'the resumed 1.2 handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted live verdict did not abort');
end;

procedure TTestConfigResumption.TestHardReuseOriginalStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // ReuseOriginal never re-verifies on resume (a resumption sends no certificate), so a Hard
  // posture has nothing to satisfy: the gate is on Reverify only, and this still resumes
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 1);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the seed client cached a session');

  LBefore := LCache.Count;
  LClient := NewHardReuseOriginalClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletion(LClient, LServer);
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'Hard + ReuseOriginal still resumes');
  CheckFalse(LClient.IsTerminal, 'the ReuseOriginal resume did not abort');
  // ReuseOriginal re-verifies nothing here, so no path was validated on this connection
  CheckEquals(0, System.Length(LClient.ConnectionInfo.ValidatedPath),
    'a ReuseOriginal resume validates no path on the client');
end;

procedure TTestConfigResumption.TestSoftReverifyWithoutLiveVerdictStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LConfig: ITlsClientConfig;
  LBefore: Int32;
  LInfo: TTlsConnectionInfo;
begin
  // a Soft posture accepts an indeterminate (unstapled) resume inline, so a Soft + Reverify client
  // with no live deferral still resumes: the gate is Hard-only
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 1);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the seed client cached a session');

  LBefore := LCache.Count;
  // Soft (the default posture) + Reverify, no live deferral
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(TTlsLibTestCertificates.Field(
      'Certs/OcspStapling.txt', 'root_cert')).Build)
    .WithDangerousDisableServerNameCheck
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithResumption(True)
    .WithSessionCache(LCache).WithResumptionScope(LScope)
    .Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletion(LClient, LServer);
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'Soft + Reverify (no live verdict) still resumes');
  CheckFalse(LClient.IsTerminal, 'the Soft reverify resume did not abort');
  // a Reverify resume re-runs PKIX here, so the presented stored chain and the validated path both surface
  LInfo := LClient.ConnectionInfo;
  CheckEquals(2, System.Length(LInfo.PeerCertificates),
    'the presented chain is the stored leaf + issuer credential');
  CheckEqualBytes('the presented chain leaf is the stapling leaf',
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_cert'),
    LInfo.PeerCertificates[0]);
  CheckTrue(System.Length(LInfo.ValidatedPath) >= System.Length(LInfo.PeerCertificates),
    'the Reverify resume validated a path at least as long as the presented chain');
  CheckEqualBytes('the validated path leaf is the stapling leaf',
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_cert'),
    LInfo.ValidatedPath[0]);
  CheckEqualBytes('the validated path terminates at the stapling root',
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'root_cert'),
    LInfo.ValidatedPath[System.High(LInfo.ValidatedPath)]);
end;

procedure TTestConfigResumption.TestHardReverifyWithoutLiveVerdictIsRefusedAtBuild;
var
  LCache: ISessionCache;
  LRefused: Boolean;
begin
  // a Hard + Reverify client with no live-revocation channel could never obtain a fresh verdict on
  // a resume (no staple travels): Build refuses it instead of silently never resuming
  LCache := TInMemorySessionCache.Create;
  LRefused := False;
  try
    NewHardReverifyClient13(LCache, Crypto.Primitives.GetRandom.GenerateBytes(16),
      TVerdictDeferral.None);
  except
    on E: EInvalidOperationTlsLibException do
      LRefused := Pos('WithLiveRevocationVerdict', E.Message) > 0;
  end;
  CheckTrue(LRefused, 'Hard + Reverify without a live verdict is refused at Build');
end;

procedure TTestConfigResumption.TestHardReverifyHostDecisionIsRefusedAtBuild;
var
  LCache: ISessionCache;
  LRefused: Boolean;
begin
  // a host-decision park cannot settle revocation on a resume either
  LCache := TInMemorySessionCache.Create;
  LRefused := False;
  try
    NewHardReverifyClient13(LCache, Crypto.Primitives.GetRandom.GenerateBytes(16),
      TVerdictDeferral.HostDecision);
  except
    on E: EInvalidOperationTlsLibException do
      LRefused := Pos('WithLiveRevocationVerdict', E.Message) > 0;
  end;
  CheckTrue(LRefused, 'Hard + Reverify with a host-decision verdict is refused at Build');
end;

procedure TTestConfigResumption.TestFatalAlertDropsTls13SessionsBehindTheDispatchers;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewDualClient(LCache);
  LServer := NewDualServer(LStore);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.NegotiatedVersion.WireValue = TlsWireVersionTls13,
    'the dual-version peers negotiated TLS 1.3');
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');
  CheckEquals(1, LStore.Count, 'the server stored the ticket it issued');
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  Pump(LServer, LClient);
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(0, LStore.Count, 'the server dispatcher forwards the fatal alert');
  CheckEquals(0, LCache.Count, 'the client dispatcher forwards the fatal alert');
end;

procedure TTestConfigResumption.TestFatalAlertDropsTheClientSessionBehindItsDispatcherOnTls12;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewDualClient(LCache);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.NegotiatedVersion.WireValue = TlsWireVersionTls12,
    'the dual-version client negotiated TLS 1.2');
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  Pump(LServer, LClient);
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(0, LCache.Count, 'the client dispatcher forwards the fatal alert');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestConfigResumption);
{$ELSE}
  RegisterTest(TTestConfigResumption.Suite);
{$ENDIF FPC}

end.
