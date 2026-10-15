{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls12ResumptionTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsVersion,
  TlpTlsAlert,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpCryptoDomainTypes,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpExtensionVector,
  TlpTlsLibExceptions,
  TlpAlpnProtocols,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpIHandshakeMachine,
  TlpHandshakeMessage,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpServerName,
  TlpCertificateVerifier,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpISession,
  TlpSession,
  TlpSystemTimeUtilities,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpSessionTicketStrategy,
  MockClock,
  MockSessionStores,
  MockCertificateVerifiers,
  TlpTlsPresets,
  TlpITlsConfigBuilder,
  TlpTlsEngineFactory,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpVersionDispatchMachine,
  TlsLibTestHandshakeDecoder,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  TTestTls12Resumption = class(TTlsLibHandshakeTestCase)
  private const
    TlsSuite = TCipherSuites12.EcdheEcdsaAes128GcmSha256;
    ServerHost = 'localhost';
  private
  var
    FClientAlpn: TArray<TBytes>;
    FServerAlpn: TArray<TBytes>;
    // per-test overrides the builders below honor when set: the peers' clocks, and a Reverify
    // client whose resumption-occasion verifier is FResumeVerifier (nil falls back to the primary)
    FClientClock, FServerClock: ITlsClock;
    FReverify: Boolean;
    FResumeVerifier: IServerCertificateVerifier;
    /// <summary>Drains the engine's event queue, returning how many SessionTicketReceived it held.</summary>
    function CountTicketEvents(const AEngine: ITlsEngine): Int32;
    /// <summary>The length of the ticket the client cached after a server sealed one under a key
    /// name of ANameLength bytes.</summary>
    function CachedTicketLength(ANameLength: Int32): Int32;
    /// <summary>The key name length that makes a sealed ticket ATicketLength bytes.</summary>
    function NameLengthForTicket(ATicketLength: Int32): Int32;
    /// <summary>A client holding a session id plus a ticket it was never sealed, resuming by id
    /// against a server with no ticket strategy: the server resumes without a NewSessionTicket.</summary>
    procedure ResumeByIdWithoutNewSessionTicket(out AClient: ITlsEngine;
      out ACache: ISessionCache; out ATicket: TBytes);
    function AgedCopy(const ASession: IResumableSession; AAgeMillis: UInt64): IResumableSession;
    function NewClient(const ACache: ISessionCache; AOfferEms: Boolean): ITlsEngine;
    /// <summary>A dual-version client (offers TLS 1.3 and 1.2 in one ClientHello) drawing
    /// from and storing into ACache; against a 1.2-only server it negotiates 1.2 and can
    /// resume a cached 1.2 session.</summary>
    function NewDualVersionClient(const ACache: ISessionCache): ITlsEngine;
    function NewDualVersionClientWith(const ACache: ISessionCache;
      AEarlyData: Boolean): ITlsEngine;
    /// <summary>A TLS 1.2 server: AStore drives session-id resumption, AStek stateless
    /// tickets; AWithCredential=False makes it credential-less (cannot run a full
    /// handshake).</summary>
    function NewServer(const AStore: ISessionStore;
      const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
      AWithCredential: Boolean): ITlsEngine;
    /// <summary>NewServer with an explicit downgrade-sentinel switch and policy for resuming a
    /// session established without EMS.</summary>
    function NewPolicyServer(const AStore: ISessionStore;
      const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
      AWithCredential, AEmitSentinel: Boolean; AMode: TNonEmsResumption): ITlsEngine;
    /// <summary>NewPolicyServer that can also require the extension; the builder refuses Require with
    /// Resume, but a machine built directly must still hold the line.</summary>
    function NewServerWith(const AStore: ISessionStore;
      const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
      AWithCredential, AEmitSentinel: Boolean; AMode: TNonEmsResumption;
      ARequireEms: Boolean): ITlsEngine;
    /// <summary>A full non-EMS handshake against a server that resumes such sessions, leaving the
    /// issued session in ACache (and in AStore, or sealed under AStek): a session minted elsewhere.</summary>
    procedure MintNonEmsSession(const ACache: ISessionCache; const AStore: ISessionStore;
      const AStek: ISessionTicketKeyManager);
    /// <summary>A second connection resuming the session MintNonEmsSession left behind, against a
    /// server with the given policy; the client offers no EMS, so neither side uses the extension.</summary>
    procedure OfferMintedSession(const ACache: ISessionCache; const AStore: ISessionStore;
      const AStek: ISessionTicketKeyManager; AMode: TNonEmsResumption;
      out AClient, AServer: ITlsEngine);
    function MakeTicketSession(const ATicket: TBytes;
      AExtendedMasterSecret: Boolean): IResumableSession;
    /// <summary>The first ClientHello flight of a client that holds a cached ticket session made
    /// with (or without) EMS and offers EMS iff AOfferEms.</summary>
    function CachedSessionHello(AEmsSession, AOfferEms: Boolean;
      const ATicket: TBytes): TBytes;
    function MakeStoredSession(const AIdentity: TBytes; const ASecret: ISecretBuffer;
      const AHost: string): IResumableSession;
    // shared mTLS-resumption scaffolding parameterized by the resumption scope
    function BuildMtlsClient(const ACache: ISessionCache;
      const ACredential: TTlsCredential): ITlsEngine;
    function BuildMtlsServer(const AStek: ISessionTicketKeyManager;
      AClientAuth: TClientAuthMode; const AClientRoot, AScope: TBytes): ITlsEngine;
    /// <summary>A TLS 1.2 session like ASession, but holding ATicket and authenticated at
    /// AAuthenticatedAt.</summary>
    function Reauthenticated(const ASession: ITls12ResumableSession; const ATicket: TBytes;
      AAuthenticatedAt: UInt64): IResumableSession;
    /// <summary>A full handshake against a STEK server on the mock clocks, then a ticket resumption
    /// after six days: AClientSession is what the client cached afterwards, AServerSession what the
    /// server sealed into the renewed ticket.</summary>
    procedure RenewAfterSixDays(AAdvanceServerClock: Boolean;
      out AClientSession, AServerSession: IResumableSession);
    /// <summary>A ticket resumption where the server's sealed copy was authenticated AServerAgeMs ago
    /// and the client's cached copy AClientAgeMs ago; True when the server ran a full handshake.</summary>
    function ResumesAsFullHandshake(AServerAgeMs, AClientAgeMs: UInt64): Boolean;
    /// <summary>A full ticket handshake against AStek, then a Reverify client (1.2-only, or
    /// dual-version) whose resumption verifier rejects when ARejectResume; returns True when the
    /// server ran a full handshake for the second connection.</summary>
    function ReverifyResumeIsFull(const AStek: ISessionTicketKeyManager;
      ADualVersion, ARejectResume: Boolean; out AClient: ITlsEngine): Boolean;
    /// <summary>A full session-id handshake, leaving the session in AStore and ACache.</summary>
    procedure EstablishSessionIdSession(const AStore: ISessionStore; const ACache: ISessionCache;
      out AClient, AServer: ITlsEngine);
  published
    procedure TestSessionIdResumeIsAbbreviated;
    procedure TestResumeWithoutNewTicketKeepsIssueTime;
    procedure TestResumeWithNewTicketRestampsIssueTime;
    procedure TestMachinesRequireAClock;
    procedure TestDispatchersRequireAClock;
    procedure TestTicketResumeIsAbbreviated;
    procedure TestTls12ServerReportsProtocolVersionAsEarlyDataReason;
    procedure TestDualClientOnTls12ReportsItsOfferReason;
    procedure TestResumptionWithoutNewSessionTicketKeepsTheCachedTicket;
    procedure TestResumptionWithoutNewSessionTicketRaisesNoTicketEvent;
    procedure TestZeroLengthTicketOnResumptionRaisesNoTicketEvent;
    procedure TestFullHandshakeTicketRaisesATicketEvent;
    procedure TestRenewedTicketOnResumptionRaisesATicketEvent;
    procedure TestResumedServerReportsItsSelectedAlpn;
    procedure TestTicketBeyondTheCacheLimitIsNotCached;
    procedure TestTicketAtTheCacheLimitIsCached;
    procedure TestConnectionAfterAnUncachedTicketIsAFullHandshake;
    procedure TestServerHelloCarriesAFreshSessionIdBesideASealedTicket;
    procedure TestSealedTicketIsNotAlsoStoredUnderASessionId;
    procedure TestDecliningSealKeepsTheSessionIdResumable;
    procedure TestTicketResumptionWithoutRenewalKeepsTheCachedSession;
    procedure TestSessionIdResumptionReportsTheOriginalGroup;
    procedure TestTicketResumptionReportsTheOriginalGroup;
    procedure TestResumptionReportsTheOriginalPeerSignatureScheme;
    procedure TestResumePreservesExtendedMasterSecretOn;
    procedure TestResumePreservesExtendedMasterSecretOff;
    procedure TestEmsSessionOfferedWithoutEmsAborts;
    procedure TestNonEmsSessionIdDeclinedByDefault;
    procedure TestNonEmsTicketDeclinedByDefault;
    procedure TestNonEmsSessionIdAbortsWhenConfigured;
    procedure TestNonEmsTicketAbortsWhenConfigured;
    procedure TestNonEmsSessionIdResumesWhenConfigured;
    procedure TestNonEmsTicketResumesWhenConfigured;
    procedure TestNonEmsFullHandshakeIssuesSessionsPerPolicy;
    procedure TestEmsRulesUnaffectedByNonEmsPolicy;
    procedure TestRequiredEmsOverridesNonEmsPolicy;
    procedure TestNonEmsPolicyReachesTheServerThroughTheFactory;
    procedure TestResumedEmsDifferingFromTheCachedSessionAbortsTheClient;
    procedure TestNonEmsSessionOfferedWithEmsFallsBackToFullHandshake;
    procedure TestNonEmsSessionIsOfferedWithExtendedMasterSecret;
    procedure TestEmsSessionIsNotOfferedByAClientWithoutEms;
    procedure TestSessionMatchingTheEmsChoiceIsOffered;
    procedure TestResumptionScopeMismatchDeclinesTicket;
    procedure TestMutualAuthTicketReissueCarriesChain;
    procedure TestDecliningSealStillSendsZeroLengthTicket;
    procedure TestExpiredTicketFallsBackToFullHandshake;
    procedure TestBogusTicketFallsBackToFullHandshake;
    procedure TestNoResumptionWithoutCache;
    procedure TestDualVersionClientResumesTls12;
    procedure TestDualVersionClientAbortsStampedAbbreviatedResumption;
    procedure TestSessionIssuedUnderDifferentSniFallsBackToFullHandshake;
    procedure TestRenewedTicketKeepsTheAuthenticationTimeOnTheClient;
    procedure TestRenewedTicketKeepsTheAuthenticationTimeOnTheServer;
    procedure TestRenewedTicketLifetimeIsCutToTheRemainingChain;
    procedure TestClientCutsTheRenewedTicketLifetimeOnItsOwnClock;
    procedure TestFatalAlertAfterAProvenAbbreviatedResumptionDropsTheStoredId;
    procedure TestReceivedFatalAlertDropsTheServersStoredSessionId;
    procedure TestServerResumesATicketInsideTheAuthenticationLimit;
    procedure TestServerDeclinesATicketPastTheAuthenticationLimit;
    procedure TestClientDoesNotOfferASessionPastTheAuthenticationLimit;
    procedure TestFatalAlertDropsTheServersStoredSessionId;
    procedure TestFatalAlertDropsTheClientsCachedSession;
    procedure TestCloseNotifyKeepsTheStoredSessions;
    procedure TestFailedResumptionByIdDoesNotEvictTheStoredSession;
    procedure TestReverifyFailureOffersNoSessionAndRunsFullHandshake;
    procedure TestReverifyFailureDeclinesAndConsumesASessionIdSession;
    procedure TestReverifyPassResumesTheSessionWithItsValidatedPath;
    procedure TestDualVersionReverifyFailureOffersNoSessionAndRunsFullHandshake;
    procedure TestDualVersionReverifyPassHandsItsValidatedPathToTheTls12Machine;
  end;

implementation

{ TTestTls12Resumption }

function TTestTls12Resumption.NewClient(const ACache: ISessionCache;
  AOfferEms: Boolean): ITlsEngine;
var
  LParams: TClient12HandshakeParams;
begin
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  if FClientClock <> nil then
    LParams.Clock := FClientClock;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TlsSuite);
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.3), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.OfferExtendedMasterSecret := AOfferEms;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
  LParams.ServerName := ServerHost;
  LParams.ServerIdentity := ServerHost + ':443';
  LParams.SessionCache := ACache;
  LParams.AlpnProtocols := FClientAlpn;
  if FReverify then
    LParams.ResumeVerification := TResumeVerification.Reverify;
  LParams.ResumeCertificateVerifier := FResumeVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Resumption.CountTicketEvents(const AEngine: ITlsEngine): Int32;
var
  LEvent: ITlsEvent;
begin
  Result := 0;
  while AEngine.NextEvent(LEvent) do
    if LEvent.Kind = TTlsEventKind.SessionTicketReceived then
      System.Inc(Result);
end;

function TTestTls12Resumption.NewDualVersionClient(
  const ACache: ISessionCache): ITlsEngine;
begin
  Result := NewDualVersionClientWith(ACache, False);
end;

function TTestTls12Resumption.NewDualVersionClientWith(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsEngine;
var
  L13: TClientHandshakeParams;
  L12: TClient12HandshakeParams;
  LVerifier: IServerCertificateVerifier;
  LRandom, LSessionId: TBytes;
begin
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  // the dispatcher sends one unified ClientHello, so both sub-machines must share the same
  // client_random and legacy_session_id (the abbreviated Finished MAC binds them)
  LRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSessionId := Crypto.Primitives.GetRandom.GenerateBytes(32);

  L13 := Default(TClientHandshakeParams);
  L13.Clock := TSystemClock.Create;
  L13.Crypto := Crypto;
  L13.Inspector := Pkix.Certificates;
  L13.Group := TNamedGroups.CreateX25519(Crypto);
  L13.GroupCode := TNamedGroupCatalog.X25519;
  // the unified ClientHello carries the 1.3 machine's supported_groups, which for a 1.2
  // fallback with a P-256 ECDSA server certificate must also list Secp256r1 - TLS 1.2
  // gates the ECDSA leaf's curve on supported_groups (RFC 8422 5.3); the key_share stays
  // X25519-only
  L13.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  L13.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  L13.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  L13.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L13.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256, TlsSuite);
  L13.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  L13.ClientRandom := LRandom;
  L13.LegacySessionId := LSessionId;
  L13.ServerName := ServerHost;
  L13.CertificateVerifier := LVerifier;
  L13.ExpectedServerName := TServerName.DnsName(ServerHost);
  L13.ServerIdentity := ServerHost + ':443';
  L13.SessionCache := ACache;
  L13.EarlyDataEnabled := AEarlyData;
  if FReverify then
    L13.ResumeVerification := TResumeVerification.Reverify;
  L13.ResumeCertificateVerifier := FResumeVerifier;

  L12 := Default(TClient12HandshakeParams);
  L12.Clock := TSystemClock.Create;
  L12.Crypto := Crypto;
  L12.Inspector := Pkix.Certificates;
  L12.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  L12.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  L12.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L12.OfferedSuites := TArray<UInt16>.Create(TlsSuite);
  L12.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  L12.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  L12.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
  L12.ClientRandom := LRandom;
  L12.LegacySessionId := LSessionId;
  L12.ServerName := ServerHost;
  L12.OfferExtendedMasterSecret := True;
  L12.CertificateVerifier := LVerifier;
  L12.ExpectedServerName := TServerName.DnsName(ServerHost);
  L12.ServerIdentity := ServerHost + ':443';
  L12.SessionCache := ACache;
  if FReverify then
    L12.ResumeVerification := TResumeVerification.Reverify;
  L12.ResumeCertificateVerifier := FResumeVerifier;

  Result := TTlsEngine.CreateConfigured(
    TClientVersionDispatchMachine.Create(L13, L12) as IHandshakeMachine, Crypto);
end;

function TTestTls12Resumption.NewServer(const AStore: ISessionStore;
  const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
  AWithCredential: Boolean): ITlsEngine;
begin
  Result := NewPolicyServer(AStore, AStek, ALifetime, AWithCredential, False,
    TNonEmsResumption.Decline);
end;

function TTestTls12Resumption.NewPolicyServer(const AStore: ISessionStore;
  const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
  AWithCredential, AEmitSentinel: Boolean; AMode: TNonEmsResumption): ITlsEngine;
begin
  Result := NewServerWith(AStore, AStek, ALifetime, AWithCredential, AEmitSentinel, AMode, False);
end;

function TTestTls12Resumption.NewServerWith(const AStore: ISessionStore;
  const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
  AWithCredential, AEmitSentinel: Boolean; AMode: TNonEmsResumption;
  ARequireEms: Boolean): ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.NonEmsResumption := AMode;
  LParams.RequireExtendedMasterSecret := ARequireEms;
  LParams.Clock := TSystemClock.Create;
  if FServerClock <> nil then
    LParams.Clock := FServerClock;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.EmitDowngradeSentinel := AEmitSentinel;
  if AWithCredential then
    LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionStore := AStore;
  LParams.SessionTicketKeys := AStek;
  LParams.TicketLifetimeSeconds := ALifetime;
  LParams.AlpnProtocols := FServerAlpn;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

procedure TTestTls12Resumption.MintNonEmsSession(const ACache: ISessionCache;
  const AStore: ISessionStore; const AStek: ISessionTicketKeyManager);
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(ACache, False);
  LServer := NewPolicyServer(AStore, AStek, 7200, True, False, TNonEmsResumption.Resume);
  RunHandshake(LClient, LServer);
  CheckEquals(1, ACache.Count, 'a server that resumes non-EMS sessions issued one');
end;

procedure TTestTls12Resumption.OfferMintedSession(const ACache: ISessionCache;
  const AStore: ISessionStore; const AStek: ISessionTicketKeyManager; AMode: TNonEmsResumption;
  out AClient, AServer: ITlsEngine);
begin
  AClient := NewClient(ACache, False);
  AServer := NewPolicyServer(AStore, AStek, 7200, True, False, AMode);
end;

function TTestTls12Resumption.MakeTicketSession(const ATicket: TBytes;
  AExtendedMasterSecret: Boolean): IResumableSession;
begin
  Result := TTls12ResumableSession.Create(TlsSuite, THashAlgorithm.SHA_256,
    TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(48)), nil, ATicket,
    AExtendedMasterSecret, nil, '', 7200, UInt64(TSystemTimeUtilities.UtcUnixMs), nil, nil);
end;

function TTestTls12Resumption.CachedSessionHello(AEmsSession, AOfferEms: Boolean;
  const ATicket: TBytes): TBytes;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LCache.Store(ServerHost + ':443', ServerHost, MakeTicketSession(ATicket, AEmsSession));
  LClient := NewClient(LCache, AOfferEms);
  LClient.StartHandshake;
  Result := Drain(LClient);
end;

procedure TTestTls12Resumption.TestNonEmsSessionIsOfferedWithExtendedMasterSecret;
var
  LTicket, LFlight: TBytes;
begin
  LTicket := DecodeHex('a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5');
  LFlight := CachedSessionHello(False, True, LTicket);
  // the abbreviated offer still carries extended_master_secret (RFC 7627 5.3); a server that
  // supports it then declines the old session and the full handshake that follows has it
  CheckTrue(ContainsBytes(LFlight, LTicket), 'the cached ticket is offered');
  // the only difference from a hello that does not offer EMS is the empty 4-byte extension
  CheckEquals(System.Length(CachedSessionHello(False, False, LTicket)) + 4,
    System.Length(LFlight),
    'extended_master_secret is offered alongside the non-EMS session');
end;

procedure TTestTls12Resumption.TestEmsSessionIsNotOfferedByAClientWithoutEms;
var
  LTicket: TBytes;
begin
  LTicket := DecodeHex('a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5');
  // a hello without EMS must not present an EMS session (the server would abort it)
  CheckFalse(ContainsBytes(CachedSessionHello(True, False, LTicket), LTicket),
    'an EMS session is not offered without extended_master_secret');
end;

procedure TTestTls12Resumption.TestSessionMatchingTheEmsChoiceIsOffered;
var
  LTicket: TBytes;
begin
  LTicket := DecodeHex('a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5');
  CheckTrue(ContainsBytes(CachedSessionHello(True, True, LTicket), LTicket),
    'an EMS session is offered by an EMS client');
  CheckTrue(ContainsBytes(CachedSessionHello(False, False, LTicket), LTicket),
    'a non-EMS session is offered by a non-EMS client');
end;

function TTestTls12Resumption.MakeStoredSession(const AIdentity: TBytes;
  const ASecret: ISecretBuffer; const AHost: string): IResumableSession;
begin
  // a session-id session (RFC 5246 7.3): the id resumes via the store, AHost is the host it was
  // issued under and what the cross-host guard checks
  Result := TTls12ResumableSession.Create(TlsSuite, THashAlgorithm.SHA_256, ASecret, AIdentity,
    nil, True, nil, AHost, 7200, UInt64(TSystemTimeUtilities.UtcUnixMs), nil, nil);
end;

procedure TTestTls12Resumption.TestSessionIdResumeIsAbbreviated;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;
begin
  // a store (no STEK) drives session-id resumption (RFC 5246 7.3)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the session id');
  CheckEquals(1, LStore.Count, 'the server stored the session under its id');

  // resume: the credentialed server still resumes; the abbreviated flight omits the
  // Certificate, which proves it did not silently fall back to a full handshake
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'session-id resumption is abbreviated (no Certificate)');
  CheckFalse(LClient.IsHandshaking, 'the resuming client completed');
  CheckFalse(LServer.IsHandshaking, 'the resuming server completed');
  CheckFalse(LClient.IsTerminal, 'the resuming client did not fail');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  // the resumed client surfaces the stored server chain and, with no re-verification, validates no path
  LServerCred := ServerCredential;
  LInfo := LClient.ConnectionInfo;
  CheckTrue(LInfo.Resumed, 'the client reports a resumed handshake');
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the resumed client surfaces the stored server chain');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
  CheckAppDataFlows(LClient, LServer);
end;

function TTestTls12Resumption.AgedCopy(const ASession: IResumableSession;
  AAgeMillis: UInt64): IResumableSession;
var
  L12: ITls12ResumableSession;
begin
  L12 := ASession as ITls12ResumableSession;
  Result := TTls12ResumableSession.Create(L12.CipherSuite, L12.Hash, L12.MasterSecret,
    L12.SessionId, L12.SessionTicket, L12.ExtendedMasterSecret, L12.Alpn, L12.ServerName,
    7200, UInt64(TSystemTimeUtilities.UtcUnixMs) - AAgeMillis, L12.PeerCertificates,
    L12.ResumptionScope);
end;

procedure TTestTls12Resumption.TestResumeWithoutNewTicketKeepsIssueTime;
const
  AgeMillis = UInt64(3600000);
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LSession, LAged, LAfter: IResumableSession;
begin
  // a session-id resumption issues no new ticket, so the session the client re-stores is the one it
  // offered and must keep its original issue time: restamping it every resume would let the
  // retention cap never bite
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LSession), 'the session was cached');
  LAged := AgedCopy(LSession, AgeMillis);
  LCache.Store(ServerHost + ':443', ServerHost, LAged);

  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer), 'the resumption is abbreviated');
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LAfter), 'the resumed session was re-cached');
  CheckEquals(Int64(LAged.IssuedAtMillis), Int64(LAfter.IssuedAtMillis),
    'the re-stored session keeps its original issue time');
  CheckEquals(Int64(LAged.TicketLifetime), Int64(LAfter.TicketLifetime),
    'and its original lifetime');
end;

procedure TTestTls12Resumption.TestResumeWithNewTicketRestampsIssueTime;
const
  AgeMillis = UInt64(3600000);
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession, LAged, LAfter: IResumableSession;
begin
  // a renewed ticket is a fresh credential: its issue time is the new one, not the old session's
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LSession), 'the session was cached');
  LAged := AgedCopy(LSession, AgeMillis);
  LCache.Store(ServerHost + ':443', ServerHost, LAged);

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer), 'the resumption is abbreviated');
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LAfter), 'the renewed session was re-cached');
  CheckTrue(LAfter.IssuedAtMillis > LAged.IssuedAtMillis + AgeMillis div 2,
    'a renewed ticket carries a fresh issue time');
end;

procedure TTestTls12Resumption.TestTicketResumeIsAbbreviated;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;
begin
  // a STEK (no store) drives stateless RFC 5077 ticket resumption
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'ticket resumption is abbreviated (no Certificate)');
  CheckFalse(LServer.IsHandshaking, 'the ticket resume completed');
  CheckFalse(LServer.IsTerminal, 'the ticket resume did not fail');
  // a fresh ticket is issued on the abbreviated handshake so the session stays resumable
  CheckEquals(1, LCache.Count, 'the client re-cached a renewed ticket');
  // the resumed client surfaces the stored server chain and, with no re-verification, validates no path
  LServerCred := ServerCredential;
  LInfo := LClient.ConnectionInfo;
  CheckTrue(LInfo.Resumed, 'the client reports a resumed handshake');
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the resumed client surfaces the stored server chain');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.ResumeByIdWithoutNewSessionTicket(out AClient: ITlsEngine;
  out ACache: ISessionCache; out ATicket: TBytes);
var
  LStore: ISessionStore;
  LServer: ITlsEngine;
  LFirst: IResumableSession;
  L12: ITls12ResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  ACache := TInMemorySessionCache.Create;
  AClient := NewClient(ACache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  RunHandshake(AClient, LServer);
  CheckTrue(ACache.Take(ServerHost + ':443', ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs),
    LFirst), 'the session id session was cached');
  CheckTrue(Supports(LFirst, ITls12ResumableSession, L12), 'a TLS 1.2 session');
  // a ticket the server never sealed: only the id resumes, and no NewSessionTicket replaces it
  ATicket := DecodeHex('0102030405060708');
  ACache.Store(ServerHost + ':443', ServerHost, TTls12ResumableSession.Create(L12.CipherSuite,
    L12.Hash, L12.MasterSecret, L12.SessionId, ATicket, L12.ExtendedMasterSecret, L12.Alpn,
    L12.ServerName, L12.TicketLifetime, L12.IssuedAtMillis, L12.PeerCertificates,
    L12.ResumptionScope, nil, nil, L12.NamedGroup, L12.PeerSignatureScheme,
    L12.AuthenticatedAtMillis) as IResumableSession);
  AClient := NewClient(ACache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  RunHandshake(AClient, LServer);
  CheckTrue(AClient.ConnectionInfo.Resumed, 'the id resumed');
end;

procedure TTestTls12Resumption.TestResumptionWithoutNewSessionTicketKeepsTheCachedTicket;
var
  LClient: ITlsEngine;
  LCache: ISessionCache;
  LTicket: TBytes;
  LAfter: IResumableSession;
  L12: ITls12ResumableSession;
begin
  ResumeByIdWithoutNewSessionTicket(LClient, LCache, LTicket);
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs),
    LAfter), 'the resumed session was cached again');
  CheckTrue(Supports(LAfter, ITls12ResumableSession, L12), 'a TLS 1.2 session');
  CheckEqualBytes('the ticket is the one resumed with', LTicket, L12.SessionTicket);
end;

procedure TTestTls12Resumption.TestResumptionWithoutNewSessionTicketRaisesNoTicketEvent;
var
  LClient: ITlsEngine;
  LCache: ISessionCache;
  LTicket: TBytes;
begin
  ResumeByIdWithoutNewSessionTicket(LClient, LCache, LTicket);
  CheckEquals(0, CountTicketEvents(LClient), 'no ticket arrived');
end;

procedure TTestTls12Resumption.TestZeroLengthTicketOnResumptionRaisesNoTicketEvent;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, TOpenOnlyTicketKeys.Create(LStek) as ISessionTicketKeyManager, 7200,
    True);
  RunHandshake(LClient, LServer);
  CheckEquals(0, CountTicketEvents(LClient), 'a zero-length NewSessionTicket brings no ticket');
end;

procedure TTestTls12Resumption.TestFullHandshakeTicketRaisesATicketEvent;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(TInMemorySessionCache.Create as ISessionCache, True);
  LServer := NewServer(nil, TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(1, CountTicketEvents(LClient), 'the issued ticket was announced');
end;

procedure TTestTls12Resumption.TestRenewedTicketOnResumptionRaisesATicketEvent;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the ticket resumed');
  CheckEquals(1, CountTicketEvents(LClient), 'the renewed ticket was announced');
end;

procedure TTestTls12Resumption.TestResumedServerReportsItsSelectedAlpn;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  FClientAlpn := TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11);
  FServerAlpn := TArray<TBytes>.Create(TAlpnProtocols.Http11);
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the ticket resumed');
  CheckEqualBytes('the abbreviated flight selects the protocol', TAlpnProtocols.Http11,
    LServer.ConnectionInfo.AlpnProtocol);
end;

function TTestTls12Resumption.CachedTicketLength(ANameLength: Int32): Int32;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession: IResumableSession;
  L12: ITls12ResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore,
    TScriptedTicketKeys.Create(ANameLength, Crypto.Primitives.GetRandom.GenerateBytes(32),
    nil) as ISessionTicketKeyManager, 7200, True);
  RunHandshake(LClient, LServer);
  // the session id the server also sent keeps the session cached whatever became of its ticket
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs),
    LSession), 'the session was cached by its id');
  CheckTrue(Supports(LSession, ITls12ResumableSession, L12), 'a TLS 1.2 session');
  Result := System.Length(L12.SessionTicket);
end;

function TTestTls12Resumption.NameLengthForTicket(ATicketLength: Int32): Int32;
begin
  // a ticket is key name, 12-byte nonce, sealed session and 16-byte tag; the session is a fixed size
  Result := ATicketLength - (CachedTicketLength(16) - 16);
end;

procedure TTestTls12Resumption.TestTicketBeyondTheCacheLimitIsNotCached;
begin
  CheckEquals(0, CachedTicketLength(NameLengthForTicket(TSessionTicketLimits.MaxCachedTicketBytes + 1)),
    'a ticket one byte over the limit is ignored');
end;

procedure TTestTls12Resumption.TestTicketAtTheCacheLimitIsCached;
begin
  CheckEquals(TSessionTicketLimits.MaxCachedTicketBytes,
    CachedTicketLength(NameLengthForTicket(TSessionTicketLimits.MaxCachedTicketBytes)),
    'a ticket at the limit is cached');
end;

procedure TTestTls12Resumption.TestConnectionAfterAnUncachedTicketIsAFullHandshake;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LStore: ISessionStore;
  LKeys: ISessionTicketKeyManager;
  LKeysImpl: TScriptedTicketKeys;
  LHello, LFlight: TBytes;
  LExtension: TExtensionEntry;
  LRecordPos, LMsgPos, LMsgLen: Int32;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LKeysImpl := TScriptedTicketKeys.Create(
    NameLengthForTicket(TSessionTicketLimits.MaxCachedTicketBytes + 1),
    Crypto.Primitives.GetRandom.GenerateBytes(32), nil);
  LKeys := LKeysImpl;
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, LKeys, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LKeysImpl.Seals > 0, 'the server sealed an over-limit ticket to issue');
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, LKeys, 7200, True);
  LClient.StartHandshake;
  LHello := Drain(LClient);
  CheckTrue(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LHello)
    .TryFind(TExtensionTypes.SessionTicket, LExtension),
    'the next hello still advertises ticket support');
  CheckEquals(0, System.Length(LExtension.Data),
    'but carries no ticket: the over-limit one was not kept');
  Feed(LServer, LHello);
  LFlight := Drain(LServer);
  CheckTrue(TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(LFlight,
    Ord(TTlsHandshakeType.Certificate), LRecordPos, LMsgPos, LMsgLen),
    'the next connection runs a full handshake');
end;

procedure TTestTls12Resumption.TestServerHelloCarriesAFreshSessionIdBesideASealedTicket;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
begin
  // the id precedes the seal that decides whether it is stored, so it is sent either way (RFC 5077 3.4)
  LClient := NewClient(TInMemorySessionCache.Create as ISessionCache, True);
  LServer := NewServer(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager, 7200,
    True);
  LClient.StartHandshake;
  Pump(LClient, LServer);
  LFlight := Drain(LServer);
  CheckEquals(22, LFlight[0], 'a handshake record');
  CheckEquals(2, LFlight[5], 'opening with the ServerHello');
  // record header 5, handshake header 4, version 2, random 32, then the session id length
  CheckEquals(32, LFlight[43], 'carrying a 32-byte session id');
end;

procedure TTestTls12Resumption.TestSealedTicketIsNotAlsoStoredUnderASessionId;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the session');
  CheckEquals(0, LStore.Count, 'the sealed ticket carries it, so the server stores no id');
end;

procedure TTestTls12Resumption.TestDecliningSealKeepsTheSessionIdResumable;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a seal the strategy declines (an oversized chain) must not leave the client with nothing
  LStek := TScriptedTicketKeys.Create(16, nil, nil) as ISessionTicketKeyManager;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the declined seal falls back to the stored session id');
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer), 'the id resumes abbreviated');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed the session');
end;

procedure TTestTls12Resumption.TestTicketResumptionWithoutRenewalKeepsTheCachedSession;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LFirst, LAfter: IResumableSession;
  L12First, L12After: ITls12ResumableSession;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs),
    LFirst), 'the initial session was cached');
  LCache.Store(ServerHost + ':443', ServerHost, LFirst);
  // the resuming server opens the ticket but seals no new one: the client keeps what it resumed with
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, TOpenOnlyTicketKeys.Create(LStek) as ISessionTicketKeyManager, 7200,
    True);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the ticket resumed');
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs),
    LAfter), 'the resumed session was cached again');
  CheckTrue(Supports(LFirst, ITls12ResumableSession, L12First) and
    Supports(LAfter, ITls12ResumableSession, L12After), 'both are TLS 1.2 sessions');
  CheckEqualBytes('the ticket is the one resumed with', L12First.SessionTicket,
    L12After.SessionTicket);
  CheckEqualBytes('the session id is the one resumed with, not the echoed throwaway',
    L12First.SessionId, L12After.SessionId);
end;

procedure TTestTls12Resumption.TestSessionIdResumptionReportsTheOriginalGroup;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(TNamedGroupCatalog.X25519, LClient.ConnectionInfo.NamedGroup,
    'the full handshake negotiated X25519');
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the session id resumed');
  CheckEquals(TNamedGroupCatalog.X25519, LClient.ConnectionInfo.NamedGroup,
    'the resumed client reports the original group');
  CheckEquals(TNamedGroupCatalog.X25519, LServer.ConnectionInfo.NamedGroup,
    'the resumed server reports the original group');
end;

procedure TTestTls12Resumption.TestTicketResumptionReportsTheOriginalGroup;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the ticket resumed');
  CheckEquals(TNamedGroupCatalog.X25519, LClient.ConnectionInfo.NamedGroup,
    'the resumed client reports the original group');
  CheckEquals(TNamedGroupCatalog.X25519, LServer.ConnectionInfo.NamedGroup,
    'the server reports the group sealed in the ticket');
end;

procedure TTestTls12Resumption.TestResumptionReportsTheOriginalPeerSignatureScheme;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256, LClient.ConnectionInfo.PeerSignatureScheme,
    'the client saw the server sign with ecdsa_secp256r1_sha256');
  CheckEquals(0, LServer.ConnectionInfo.PeerSignatureScheme,
    'a server without client authentication verified no signature');
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the ticket resumed');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256, LClient.ConnectionInfo.PeerSignatureScheme,
    'the resumed client reports the original server signature scheme');
end;

procedure TTestTls12Resumption.TestResumePreservesExtendedMasterSecretOn;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a session established with Extended Master Secret resumes only when the client
  // re-offers EMS; the abbreviated completion proves the EMS state round-tripped
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'an EMS session was cached');

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'an EMS session resumes abbreviated');
  CheckFalse(LServer.IsTerminal, 'the EMS resume did not fail');
  CheckAppDataFlows(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.ExtendedMasterSecret, 'the resumed session reports EMS');
  CheckTrue(LServer.ConnectionInfo.ExtendedMasterSecret, 'on the server too');
  CheckEquals(32, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test', 32)),
    'the resumed EMS session exports');
  CheckEqualBytes('and both peers export the same material',
    LClient.ExportKeyingMaterial('EXPORTER-test', 32),
    LServer.ExportKeyingMaterial('EXPORTER-test', 32));
end;

procedure TTestTls12Resumption.TestResumePreservesExtendedMasterSecretOff;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a server that opts into legacy resumption (RFC 7627 5.3) resumes a session established WITHOUT
  // EMS when the client does not offer EMS on the resumption ClientHello either; an abbreviated
  // completion proves the client aligned its EMS offer to the cached session
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServer := NewPolicyServer(nil, LStek, 7200, True, False, TNonEmsResumption.Resume);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a non-EMS session was cached');

  LClient := NewClient(LCache, False);
  LServer := NewPolicyServer(nil, LStek, 7200, True, False, TNonEmsResumption.Resume);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'a non-EMS session resumes abbreviated');
  CheckFalse(LServer.IsTerminal, 'the non-EMS resume did not fail');
  CheckAppDataFlows(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.ExtendedMasterSecret, 'the resumed session reports no EMS');
  CheckFalse(LServer.ConnectionInfo.ExtendedMasterSecret, 'on the server too');
  CheckEquals(0, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test', 32)),
    'a resumed non-EMS session exports nothing on the client');
  CheckEquals(0, System.Length(LServer.ExportKeyingMaterial('EXPORTER-test', 32)),
    'nor on the server');
end;

procedure TTestTls12Resumption.TestNonEmsSessionIdDeclinedByDefault;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a session minted without EMS (by a node that resumes them) is offered to a default server:
  // RFC 7627 5.3 says a server SHOULD abort rather than resume it, and this one declines to a full
  // handshake instead, leaving the stored session alone
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  MintNonEmsSession(LCache, LStore, nil);
  CheckEquals(1, LStore.Count, 'the minting server stored the session');
  OfferMintedSession(LCache, LStore, nil, TNonEmsResumption.Decline, LClient, LServer);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a non-EMS session is declined to a full handshake (Certificate sent)');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the server did not resume it');
  CheckFalse(LClient.IsTerminal, 'declining is not fatal');
  CheckFalse(LServer.IsTerminal, 'on the server either');
  CheckFalse(LServer.ConnectionInfo.ExtendedMasterSecret, 'the new session is non-EMS too');
  CheckAppDataFlows(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the new non-EMS handshake issued no session');
end;

procedure TTestTls12Resumption.TestNonEmsTicketDeclinedByDefault;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  MintNonEmsSession(LCache, nil, LStek);
  OfferMintedSession(LCache, nil, LStek, TNonEmsResumption.Decline, LClient, LServer);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a non-EMS ticket is declined to a full handshake (Certificate sent)');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the server did not resume it');
  CheckFalse(LClient.IsTerminal, 'declining is not fatal');
  CheckFalse(LServer.IsTerminal, 'on the server either');
  CheckFalse(LServer.ConnectionInfo.ExtendedMasterSecret, 'the new session is non-EMS too');
  CheckAppDataFlows(LClient, LServer);
  CheckEquals(0, LCache.Count, 'the new non-EMS handshake issued no ticket');
end;

procedure TTestTls12Resumption.TestNonEmsSessionIdAbortsWhenConfigured;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  MintNonEmsSession(LCache, LStore, nil);
  OfferMintedSession(LCache, LStore, nil, TNonEmsResumption.Abort, LClient, LServer);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'a non-EMS session aborts under the Abort policy');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'the abort is handshake_failure (RFC 7627 5.2)');
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'handshake_failure reached the client');
  CheckEquals(1, LStore.Count, 'the stored session was not used up');
end;

procedure TTestTls12Resumption.TestNonEmsTicketAbortsWhenConfigured;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  MintNonEmsSession(LCache, nil, LStek);
  OfferMintedSession(LCache, nil, LStek, TNonEmsResumption.Abort, LClient, LServer);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'a non-EMS ticket aborts under the Abort policy');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'the abort is handshake_failure (RFC 7627 5.2)');
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'handshake_failure reached the client');
end;

procedure TTestTls12Resumption.TestNonEmsSessionIdResumesWhenConfigured;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  MintNonEmsSession(LCache, LStore, nil);
  OfferMintedSession(LCache, LStore, nil, TNonEmsResumption.Resume, LClient, LServer);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'the legacy non-EMS session resumes abbreviated');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed it');
  CheckFalse(LServer.ConnectionInfo.ExtendedMasterSecret, 'without EMS');
  CheckEquals(0, System.Length(LServer.ExportKeyingMaterial('EXPORTER-test', 32)),
    'and the exporter stays withheld (RFC 7627 5.4)');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestNonEmsTicketResumesWhenConfigured;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  MintNonEmsSession(LCache, nil, LStek);
  OfferMintedSession(LCache, nil, LStek, TNonEmsResumption.Resume, LClient, LServer);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'the legacy non-EMS ticket resumes abbreviated');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed it');
  CheckFalse(LServer.ConnectionInfo.ExtendedMasterSecret, 'without EMS');
  CheckEquals(0, System.Length(LServer.ExportKeyingMaterial('EXPORTER-test', 32)),
    'and the exporter stays withheld (RFC 7627 5.4)');
  CheckAppDataFlows(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the resumption renewed the ticket');
end;

procedure TTestTls12Resumption.TestNonEmsFullHandshakeIssuesSessionsPerPolicy;
var
  LStek: ISessionTicketKeyManager;
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LMode: TNonEmsResumption;
begin
  // a non-EMS full handshake only leaves a session behind when this server would resume it;
  // otherwise the client would be handed an id or ticket that is always refused
  for LMode := Low(TNonEmsResumption) to High(TNonEmsResumption) do
  begin
    LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
    LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
    LCache := TInMemorySessionCache.Create;
    LClient := NewClient(LCache, False);
    LServer := NewPolicyServer(LStore, LStek, 7200, True, False, LMode);
    RunHandshake(LClient, LServer);
    CheckFalse(LServer.IsTerminal, 'the non-EMS full handshake completes under every policy');
    if LMode = TNonEmsResumption.Resume then
    begin
      CheckEquals(1, LCache.Count, 'Resume issues the client a session');
      CheckEquals(0, LStore.Count, 'carried by its ticket, so the store holds no session id');
    end
    else
    begin
      CheckEquals(0, LCache.Count, 'Decline and Abort issue the client nothing');
      CheckEquals(0, LStore.Count, 'and store nothing');
    end;

    // control: an EMS client is issued a session whatever the policy
    LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
    LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
    LCache := TInMemorySessionCache.Create;
    LClient := NewClient(LCache, True);
    LServer := NewPolicyServer(LStore, LStek, 7200, True, False, LMode);
    RunHandshake(LClient, LServer);
    CheckEquals(1, LCache.Count, 'an EMS client is issued a session under every policy');
    CheckEquals(0, LStore.Count, 'carried by its ticket, so the store holds no session id');
  end;
end;

procedure TTestTls12Resumption.TestEmsRulesUnaffectedByNonEmsPolicy;
var
  LStek: ISessionTicketKeyManager;
  LCache, LCache2: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession: IResumableSession;
  LTicket: TBytes;
  LMode: TNonEmsResumption;
begin
  // RFC 7627 5.3: an EMS session resumes with an EMS hello, aborts without one, and a non-EMS session
  // offered with EMS declines - whatever the policy for the neither-uses-EMS case
  for LMode := Low(TNonEmsResumption) to High(TNonEmsResumption) do
  begin
    LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
    LCache := TInMemorySessionCache.Create;
    LClient := NewClient(LCache, True);
    LServer := NewPolicyServer(nil, LStek, 7200, True, False, LMode);
    RunHandshake(LClient, LServer);
    CheckTrue(LCache.Take(ServerHost + ':443', ServerHost,
      (TSystemClock.Create as ITlsClock).NowUnixMillis, LSession), 'the EMS session was cached');
    LTicket := (LSession as ITls12ResumableSession).SessionTicket;

    // the real session (its own master secret), so the abbreviated handshake can complete
    LCache2 := TInMemorySessionCache.Create;
    LCache2.Store(ServerHost + ':443', ServerHost, LSession);
    LClient := NewClient(LCache2, True);
    LServer := NewPolicyServer(nil, LStek, 7200, True, False, LMode);
    CheckFalse(DriveObservingServerCert(LClient, LServer), 'an EMS session still resumes');
    CheckTrue(LServer.ConnectionInfo.Resumed, 'and is reported resumed');

    LCache2 := TInMemorySessionCache.Create;
    LCache2.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, False));
    LClient := NewClient(LCache2, False);
    LServer := NewPolicyServer(nil, LStek, 7200, True, False, LMode);
    RunHandshake(LClient, LServer);
    CheckTrue(LServer.IsTerminal, 'an EMS session offered without EMS aborts under every policy');

    // a non-EMS session offered with EMS declines, even under Resume
    LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
    LCache := TInMemorySessionCache.Create;
    MintNonEmsSession(LCache, nil, LStek);
    CheckTrue(LCache.Take(ServerHost + ':443', ServerHost,
      (TSystemClock.Create as ITlsClock).NowUnixMillis, LSession), 'the non-EMS session was cached');
    LTicket := (LSession as ITls12ResumableSession).SessionTicket;
    LCache2 := TInMemorySessionCache.Create;
    LCache2.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, True));
    LClient := NewClient(LCache2, True);
    LServer := NewPolicyServer(nil, LStek, 7200, True, False, LMode);
    CheckTrue(DriveObservingServerCert(LClient, LServer),
      'a non-EMS session offered with EMS declines to a full handshake under every policy');
    CheckFalse(LServer.IsTerminal, 'and that is not fatal');
  end;
end;

procedure TTestTls12Resumption.TestRequiredEmsOverridesNonEmsPolicy;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LMode: TNonEmsResumption;
begin
  // a server that requires EMS refuses every non-EMS client, so a non-EMS session is never resumed
  // whatever the policy - including Resume, which only a directly built machine can combine with it
  for LMode := Low(TNonEmsResumption) to High(TNonEmsResumption) do
  begin
    LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
    LCache := TInMemorySessionCache.Create;
    MintNonEmsSession(LCache, nil, LStek);
    LClient := NewClient(LCache, False);
    LServer := NewServerWith(nil, LStek, 7200, True, False, LMode, True);
    RunHandshake(LClient, LServer);
    CheckTrue(LServer.IsTerminal, 'a required-EMS server refuses the non-EMS client');
    CheckFalse(LServer.ConnectionInfo.Resumed, 'and never resumes its session');
    CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
      Int64(Ord(LServer.LastError.Alert.Description)), 'with handshake_failure');
  end;
end;

procedure TTestTls12Resumption.TestNonEmsPolicyReachesTheServerThroughTheFactory;
var
  LStek: ISessionTicketKeyManager;
  LScope: TBytes;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;

  // a factory-built TLS 1.2 server over the shared ticket keys and scope; the machine-level client
  // above is the only way to send a hello without EMS, which a built client always offers
  function BuildServer(AMode: TNonEmsResumption): ITlsEngine;
  begin
    Result := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential).WithSessionTicketKeys(LStek)
      .WithResumptionScope(LScope).Tls12.WithNonEmsResumption(AMode).Build);
  end;

begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LScope := TBytes.Create($45, $4D, $53);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServer := BuildServer(TNonEmsResumption.Resume);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a built Resume server issued a non-EMS session');

  LClient := NewClient(LCache, False);
  LServer := BuildServer(TNonEmsResumption.Abort);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'a built Abort server aborts the non-EMS resumption');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'with handshake_failure');
  CheckTrue(LClient.IsTerminal, 'and the client received the fatal alert');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'handshake_failure reached the client');
end;

procedure TTestTls12Resumption.TestResumedEmsDifferingFromTheCachedSessionAbortsTheClient;
var
  LStek: ISessionTicketKeyManager;
  LCache1, LCache2: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession: IResumableSession;
  LTicket: TBytes;
begin
  // the cache says the session had no EMS but the ticket opens as EMS, so a server that resumes it
  // echoes EMS: the client sees a resumption whose EMS choice differs from the cached session and
  // aborts (RFC 7627 5.3; handshake_failure per 5.2)
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache1 := TInMemorySessionCache.Create;
  LClient := NewClient(LCache1, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LCache1.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LSession),
    'the EMS session was cached');
  LTicket := (LSession as ITls12ResumableSession).SessionTicket;

  LCache2 := TInMemorySessionCache.Create;
  LCache2.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, False));
  LClient := NewClient(LCache2, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'a resumption that changes the EMS choice aborts the client');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the client abort is handshake_failure (RFC 7627 5.2 / 5.3)');
end;

procedure TTestTls12Resumption.TestEmsSessionOfferedWithoutEmsAborts;
var
  LStek: ISessionTicketKeyManager;
  LCache1, LCache2: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession: IResumableSession;
  LTicket: TBytes;
begin
  // establish a real EMS session, then re-present its (EMS) ticket as a non-EMS cache entry so the
  // client offers the ticket without the extension; the server opening it as EMS must abort rather
  // than resume with an inconsistent master secret (RFC 7627 5.3)
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache1 := TInMemorySessionCache.Create;
  LClient := NewClient(LCache1, True);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LCache1.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LSession),
    'the EMS session was cached');
  LTicket := (LSession as ITls12ResumableSession).SessionTicket;

  LCache2 := TInMemorySessionCache.Create;
  LCache2.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, False));
  LClient := NewClient(LCache2, False);
  LServer := NewServer(nil, LStek, 7200, True);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'an EMS session offered without EMS aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'the abort is handshake_failure (RFC 7627 5.2 / 5.3)');
  // the fatal alert reached the wire, not just the server's own state
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the client saw handshake_failure');
end;

procedure TTestTls12Resumption.TestNonEmsSessionOfferedWithEmsFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache1, LCache2: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession: IResumableSession;
  LTicket: TBytes;
begin
  // the reverse direction: a non-EMS session re-presented as EMS so the client offers EMS; the
  // server opening a non-EMS ticket under an EMS offer declines to a full handshake, not an abort
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache1 := TInMemorySessionCache.Create;
  LClient := NewClient(LCache1, False);
  // the non-EMS session is minted by a server that resumes such sessions, since a default one
  // issues none
  LServer := NewPolicyServer(nil, LStek, 7200, True, False, TNonEmsResumption.Resume);
  RunHandshake(LClient, LServer);
  CheckTrue(LCache1.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LSession),
    'the non-EMS session was cached');
  LTicket := (LSession as ITls12ResumableSession).SessionTicket;

  LCache2 := TInMemorySessionCache.Create;
  LCache2.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, True));
  LClient := NewClient(LCache2, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a non-EMS session offered with EMS falls back to a full handshake (Certificate sent)');
  CheckFalse(LServer.IsTerminal, 'the reverse EMS mismatch is not fatal');
end;

function TTestTls12Resumption.BuildMtlsClient(const ACache: ISessionCache;
  const ACredential: TTlsCredential): ITlsEngine;
var
  LParams: TClient12HandshakeParams;
begin
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TlsSuite);
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.OfferExtendedMasterSecret := True;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
  LParams.ServerName := ServerHost;
  LParams.ServerIdentity := ServerHost + ':443';
  LParams.SessionCache := ACache;
  LParams.ClientCredential := ACredential;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Resumption.BuildMtlsServer(const AStek: ISessionTicketKeyManager;
  AClientAuth: TClientAuthMode; const AClientRoot, AScope: TBytes): ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionTicketKeys := AStek;
  LParams.ResumptionScope := AScope;
  LParams.TicketLifetimeSeconds := 7200;
  LParams.ClientAuth := AClientAuth;
  if AClientAuth <> TClientAuthMode.None then
  begin
    LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256);
    LParams.ClientCertificateVerifier := TCertificateVerifier.Create(Pkix,
      TSystemClock.Create as ITlsClock,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(AClientRoot))
      as ITrustAnchorStore, False) as IClientCertificateVerifier;
  end;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

procedure TTestTls12Resumption.TestResumptionScopeMismatchDeclinesTicket;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LCred: TTlsCredential;
  LClientRoot: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCred := ClientAuthCredential(LClientRoot);

  // an issuer under scope A mints an mTLS ticket carrying the verified client chain
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot,
    DecodeHex('a1a1a1a1a1a1a1a1'));
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the scope-A ticket');

  // a configuration sharing the STEK but under scope B declines the ticket (scope mismatch) and
  // completes a full handshake, verifying the client certificate under its own trust
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot,
    DecodeHex('b2b2b2b2b2b2b2b2'));
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a different-scope configuration runs a full handshake (Certificate sent), not a resume');
  CheckFalse(LServer.IsTerminal, 'the full handshake completed');
  CheckTrue(System.Length(LServer.ConnectionInfo.PeerCertificates) > 0,
    'the full handshake verified the client certificate itself');
end;

procedure TTestTls12Resumption.TestMutualAuthTicketReissueCarriesChain;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LCred: TTlsCredential;
  LClientRoot, LScope: TBytes;
  LServerInfo: TTlsConnectionInfo;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCred := ClientAuthCredential(LClientRoot);
  LScope := DecodeHex('5c5c5c5c5c5c5c5c');

  // full mutual-TLS handshake -> ticket #1
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot, LScope);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'ticket #1 was cached');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256, LServer.ConnectionInfo.PeerSignatureScheme,
    'the server verified the client''s CertificateVerify under ecdsa_secp256r1_sha256');
  CheckEquals(1, System.Length(LClient.ConnectionInfo.RequestedSignatureSchemes),
    'the client reports the signature_algorithms of the CertificateRequest');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256,
    LClient.ConnectionInfo.RequestedSignatureSchemes[0], 'the one the server listed');

  // resume ticket #1 and re-issue ticket #2, which must carry the chain forward
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot, LScope);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the first resumption resumed');
  CheckEquals(1, LCache.Count, 'the client holds a ticket for the next connection');

  // resume ticket #2: resumes only if it carried the chain (else Required declines to full)
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot, LScope);
  RunHandshake(LClient, LServer);
  LServerInfo := LServer.ConnectionInfo;
  CheckTrue(LServerInfo.Resumed, 'the re-issued ticket carried the chain, so it resumes again');
  CheckTrue(System.Length(LServerInfo.PeerCertificates) > 0,
    'and the resumed connection surfaces the client chain');
end;

procedure TTestTls12Resumption.TestDecliningSealStillSendsZeroLengthTicket;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LServerWire, LServerOut: TBytes;
  LRecordPos, LMsgPos, LMsgLen, LIterations: Int32;
begin
  // a server that echoed the session_ticket extension MUST still send a NewSessionTicket, even
  // when the strategy declines to seal - a zero-length one - so the client is not left awaiting
  // it (RFC 5077 3.3)
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, TScriptedTicketKeys.Create(16, nil, nil) as ISessionTicketKeyManager,
    7200, True);
  LClient.StartHandshake;
  LServerWire := nil;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    LServerOut := Drain(LServer);
    LServerWire := ConcatBytes(LServerWire, LServerOut);
    Feed(LClient, LServerOut);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the client completed despite the declined ticket');
  CheckFalse(LServer.IsHandshaking, 'the server completed');
  CheckTrue(TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(LServerWire,
    Ord(TTlsHandshakeType.NewSessionTicket), LRecordPos, LMsgPos, LMsgLen),
    'the server still sent a NewSessionTicket (zero-length)');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestExpiredTicketFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a zero-lifetime ticket is expired the instant it is sealed; the resuming server must
  // reject it on freshness and complete a full handshake instead
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 0, True);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the expired ticket was cached');

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 0, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'an expired ticket falls back to a full handshake (Certificate sent)');
  CheckFalse(LClient.IsHandshaking, 'the client completed the full handshake');
  CheckFalse(LServer.IsTerminal, 'an expired ticket is not fatal');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestBogusTicketFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LTicket, LHello, LFlight: TBytes;
  LRecordPos, LMsgPos, LMsgLen: Int32;
begin
  // the client presents a ticket that is not a valid STEK seal; the server cannot open it
  // and completes a full handshake
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LTicket := Crypto.Primitives.GetRandom.GenerateBytes(64);
  LCache.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, False));

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  LClient.StartHandshake;
  LHello := Drain(LClient);
  CheckTrue(ContainsBytes(LHello, LTicket), 'the bogus ticket is offered');
  Feed(LServer, LHello);
  LFlight := Drain(LServer);
  CheckTrue(TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(LFlight,
    Ord(TTlsHandshakeType.Certificate), LRecordPos, LMsgPos, LMsgLen),
    'a bogus ticket falls back to a full handshake (Certificate sent)');
  Feed(LClient, LFlight);
  ExchangeFlights(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client completed the full handshake');
  CheckFalse(LServer.IsTerminal, 'a bogus ticket is not fatal');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestNoResumptionWithoutCache;
var
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // with no client cache the client never offers a session id or ticket, so even a
  // store-backed server runs a full handshake
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient(nil, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'without a cache the handshake is full (Certificate sent)');
  CheckFalse(LClient.IsHandshaking, 'the no-cache handshake completed');
  CheckFalse(LServer.IsTerminal, 'the no-cache handshake did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestDualVersionClientResumesTls12;
var
  LCache: ISessionCache;
  LStek: ISessionTicketKeyManager;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;
begin
  LCache := TInMemorySessionCache.Create;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);

  // connection 1: a dual-version client (offers 1.3 + 1.2) meets a 1.2-only server, so it
  // negotiates 1.2 in full and caches the issued 1.2 session
  LClient := NewDualVersionClient(LCache);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'the first dual-version handshake is full (the server sends a Certificate)');
  CheckFalse(LClient.IsHandshaking, 'the first dual-version handshake completed');
  CheckEquals(1, LCache.Count, 'the dual-version client cached the 1.2 session');

  // connection 2: a fresh dual-version client sharing the cache offers the cached 1.2
  // session in its unified ClientHello; the 1.2 server resumes it (abbreviated, no
  // Certificate) rather than running another full handshake
  LClient := NewDualVersionClient(LCache);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'the resumed dual-version handshake is abbreviated (no server Certificate)');
  CheckFalse(LClient.IsHandshaking, 'the resumed dual-version handshake completed');
  CheckFalse(LServer.IsTerminal, 'the resumed handshake did not fail');
  // through the 1.3->1.2 hand-off the resumed client surfaces the stored server chain and, with no
  // re-verification, validates no path
  LServerCred := ServerCredential;
  LInfo := LClient.ConnectionInfo;
  CheckTrue(LInfo.Resumed, 'the client reports a resumed handshake');
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the resumed client surfaces the stored server chain');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestTls12ServerReportsProtocolVersionAsEarlyDataReason;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, nil, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(Ord(TEarlyDataReason.ProtocolVersion), Ord(LServer.ConnectionInfo.EarlyDataReason),
    'a TLS 1.2 server takes no 0-RTT');
  CheckEquals(Ord(TEarlyDataReason.Disabled), Ord(LClient.ConnectionInfo.EarlyDataReason),
    'a TLS 1.2-only client was not configured for it');
end;

procedure TTestTls12Resumption.TestDualClientOnTls12ReportsItsOfferReason;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewDualVersionClientWith(LCache, True);
  LServer := NewServer(nil, nil, 7200, True);
  RunHandshake(LClient, LServer);
  CheckEquals(Ord(TEarlyDataReason.NoSessionOffered), Ord(LClient.ConnectionInfo.EarlyDataReason),
    'the 1.3 hello offered no early data for want of a session, and the 1.2 hand-off keeps that');
end;

procedure TTestTls12Resumption.TestDualVersionClientAbortsStampedAbbreviatedResumption;
var
  LCache: ISessionCache;
  LStek: ISessionTicketKeyManager;
  LClient, LServer: ITlsEngine;
begin
  // a 1.3-capable client aborts a stamped downgrade even on an abbreviated (resumption)
  // ServerHello, not only on a full one (RFC 9846 4.2.3)
  LCache := TInMemorySessionCache.Create;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);

  LClient := NewDualVersionClient(LCache);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'the first dual-version handshake is full');
  CheckEquals(1, LCache.Count, 'the dual-version client cached the 1.2 session');

  // the resuming server stamps the downgrade sentinel on the abbreviated ServerHello
  LClient := NewDualVersionClient(LCache);
  LServer := NewPolicyServer(nil, LStek, 7200, True, True, TNonEmsResumption.Decline);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the client aborts a stamped abbreviated ServerHello');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the abort is illegal_parameter (RFC 9846 4.2.3)');
end;

procedure TTestTls12Resumption.TestSessionIssuedUnderDifferentSniFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // the 1.2 cross-host resumption guard: a session issued while serving one host must not resume
  // a client that requests another (RFC 6066 3). The client always requests ServerHost, so the
  // server-stored session carries the issuing host the guard checks
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(48));

  // control: issued under the requested host -> resumes (abbreviated, no Certificate)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost + ':443', ServerHost, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LStore.PutWithId(LIdentity, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'a session issued under the requested host resumes');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the control 1.2 handshake resumed');

  // guarded: issued under a different host -> the credentialed server ignores the session id and
  // runs a full handshake (Certificate sent) instead of resuming under the wrong identity
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost + ':443', ServerHost, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LStore.PutWithId(LIdentity, MakeStoredSession(LIdentity, LSecret, 'other.example'));
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a session issued under a different host falls back to a full handshake');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'a session issued under a different host does not resume');
end;

procedure TTestTls12Resumption.TestMachinesRequireAClock;
var
  LClient: TClient12HandshakeParams;
  LServer: TServer12HandshakeParams;
  LMachine: IHandshakeMachine;
  LClientRaised, LServerRaised: Boolean;
begin
  // the clock stamps sessions and checks their freshness, so it is a required input: a missing one
  // is a typed error at construction, not an access violation on the first resumption
  LClient := Default(TClient12HandshakeParams);
  LClient.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LServer := Default(TServer12HandshakeParams);
  LServer.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LServer.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LClientRaised := False;
  LServerRaised := False;
  try
    LMachine := TTls12ClientStateMachine.Create(LClient) as IHandshakeMachine;
  except
    on E: EArgumentTlsLibException do
      LClientRaised := True;
  end;
  try
    LMachine := TTls12ServerStateMachine.Create(LServer) as IHandshakeMachine;
  except
    on E: EArgumentTlsLibException do
      LServerRaised := True;
  end;
  CheckTrue(LClientRaised, 'a 1.2 client without a clock is refused');
  CheckTrue(LServerRaised, 'a 1.2 server without a clock is refused');
end;

procedure TTestTls12Resumption.TestDispatchersRequireAClock;
var
  LClient13: TClientHandshakeParams;
  LClient12: TClient12HandshakeParams;
  LServer13: TServerHandshakeParams;
  LServer12: TServer12HandshakeParams;
  LMachine: IHandshakeMachine;
  LClientRaised, LServerRaised: Boolean;
begin
  // the dual-version dispatchers build their inner machine later, at the first hello, so a missing
  // clock is refused at construction rather than surfacing mid-handshake
  LClient13 := Default(TClientHandshakeParams);
  LClient12 := Default(TClient12HandshakeParams);
  LServer13 := Default(TServerHandshakeParams);
  LServer12 := Default(TServer12HandshakeParams);
  LServer12.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LClientRaised := False;
  LServerRaised := False;
  try
    LMachine := TClientVersionDispatchMachine.Create(LClient13, LClient12) as IHandshakeMachine;
  except
    on E: EArgumentTlsLibException do
      LClientRaised := True;
  end;
  try
    LMachine := TServerVersionDispatchMachine.Create(LServer13, LServer12,
      TArray<UInt16>.Create(TlsWireVersionTls13)) as IHandshakeMachine;
  except
    on E: EArgumentTlsLibException do
      LServerRaised := True;
  end;
  CheckTrue(LClientRaised, 'a client dispatcher without a clock is refused');
  CheckTrue(LServerRaised, 'a server dispatcher without a clock is refused');
end;

function TTestTls12Resumption.Reauthenticated(const ASession: ITls12ResumableSession;
  const ATicket: TBytes; AAuthenticatedAt: UInt64): IResumableSession;
begin
  Result := TTls12ResumableSession.Create(ASession.CipherSuite, ASession.Hash,
    ASession.MasterSecret, ASession.SessionId, ATicket, ASession.ExtendedMasterSecret,
    ASession.Alpn, ASession.ServerName, ASession.TicketLifetime, ASession.IssuedAtMillis,
    ASession.PeerCertificates, ASession.ResumptionScope, ASession.PskIdentity,
    ASession.PskBinding, ASession.NamedGroup, ASession.PeerSignatureScheme,
    AAuthenticatedAt) as IResumableSession;
end;

procedure TTestTls12Resumption.RenewAfterSixDays(AAdvanceServerClock: Boolean;
  out AClientSession, AServerSession: IResumableSession);
const
  StartMs = UInt64(1700000000000);
  SixDaysMs = UInt64(6) * 86400000;
var
  LClientClock, LServerClock: TMockClock;
  LStek: ISessionTicketKeyManager;
  LStrategy: ISessionTicketStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LClientClock := TMockClock.Create(StartMs);
  LServerClock := TMockClock.Create(StartMs);
  FClientClock := LClientClock;
  FServerClock := LServerClock;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 604800, True);
  RunHandshake(LClient, LServer);
  LClientClock.Advance(SixDaysMs);
  if AAdvanceServerClock then
    LServerClock.Advance(SixDaysMs);
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 604800, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer), 'the resumption is abbreviated');
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, StartMs + SixDaysMs, AClientSession),
    'the renewed session was cached');
  LStrategy := TStekTicketStrategy.Create(Crypto, LStek);
  CheckTrue(LStrategy.Open((AClientSession as ITls12ResumableSession).SessionTicket,
    AServerSession), 'the renewed ticket opens');
end;

procedure TTestTls12Resumption.TestRenewedTicketKeepsTheAuthenticationTimeOnTheClient;
var
  LClientSession, LServerSession: IResumableSession;
begin
  RenewAfterSixDays(True, LClientSession, LServerSession);
  CheckTrue(UInt64(1700000000000) = LClientSession.AuthenticatedAtMillis,
    'the client keeps the time of the full handshake');
  CheckTrue(UInt64(1700000000000) + UInt64(6) * 86400000 = LClientSession.IssuedAtMillis,
    'while the renewed ticket is issued now');
end;

procedure TTestTls12Resumption.TestRenewedTicketKeepsTheAuthenticationTimeOnTheServer;
var
  LClientSession, LServerSession: IResumableSession;
begin
  RenewAfterSixDays(True, LClientSession, LServerSession);
  CheckTrue(UInt64(1700000000000) = LServerSession.AuthenticatedAtMillis,
    'the server seals the time of the full handshake');
end;

procedure TTestTls12Resumption.TestRenewedTicketLifetimeIsCutToTheRemainingChain;
var
  LClientSession, LServerSession: IResumableSession;
begin
  RenewAfterSixDays(True, LClientSession, LServerSession);
  // seven days from the authentication, six of them gone: one day left of the 604800 configured
  CheckEquals(86400, Integer(LServerSession.TicketLifetime),
    'the server seals only the remaining day');
end;

procedure TTestTls12Resumption.TestClientCutsTheRenewedTicketLifetimeOnItsOwnClock;
var
  LClientSession, LServerSession: IResumableSession;
begin
  // only the client's clock moved, so the server still advertises the full 604800
  RenewAfterSixDays(False, LClientSession, LServerSession);
  CheckEquals(604800, Integer(LServerSession.TicketLifetime), 'control: the server advertised all seven days');
  CheckEquals(86400, Integer(LClientSession.TicketLifetime),
    'the client caches only the remaining day');
end;

procedure TTestTls12Resumption.TestFatalAlertAfterAProvenAbbreviatedResumptionDropsTheStoredId;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  EstablishSessionIdSession(LStore, LCache, LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer), 'the second connection resumed by id');
  CheckEquals(1, LStore.Count, 'control: the resumed entry is still stored');
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  CheckEquals(0, LStore.Count, 'the id the client proved is dropped');
end;

procedure TTestTls12Resumption.TestReceivedFatalAlertDropsTheServersStoredSessionId;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  EstablishSessionIdSession(LStore, LCache, LClient, LServer);
  LClient.SendAlert(TTlsAlertDescription.InternalError);
  Pump(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server received the fatal alert');
  CheckEquals(0, LStore.Count, 'the peer''s fatal alert ends the stored session');
end;

function TTestTls12Resumption.ResumesAsFullHandshake(AServerAgeMs, AClientAgeMs: UInt64): Boolean;
var
  LStek: ISessionTicketKeyManager;
  LStrategy: ISessionTicketStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LFirst: IResumableSession;
  LOpened: IResumableSession;
  L12First, L12Opened: ITls12ResumableSession;
  LNowMs: UInt64;
  LTicket: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 604800, True);
  RunHandshake(LClient, LServer);
  LNowMs := (TSystemClock.Create as ITlsClock).NowUnixMillis;
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, LNowMs, LFirst), 'the ticket was cached');
  L12First := LFirst as ITls12ResumableSession;
  LStrategy := TStekTicketStrategy.Create(Crypto, LStek);
  CheckTrue(LStrategy.Open(L12First.SessionTicket, LOpened), 'the ticket opens');
  L12Opened := LOpened as ITls12ResumableSession;
  // the server's copy re-sealed with its own authentication age, the client's with another
  LTicket := LStrategy.Seal(Reauthenticated(L12Opened, nil, LNowMs - AServerAgeMs));
  LCache.Store(ServerHost + ':443', ServerHost,
    Reauthenticated(L12First, LTicket, LNowMs - AClientAgeMs));
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 604800, True);
  Result := DriveObservingServerCert(LClient, LServer);
  // an alert-only flight carries no Certificate either, so completion and Resumed must agree
  CheckFalse(LServer.IsTerminal, 'the handshake did not fail');
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckTrue(Result <> LServer.ConnectionInfo.Resumed,
    'a flight without a Certificate is a resumption, one with it a full handshake');
end;

procedure TTestTls12Resumption.TestServerResumesATicketInsideTheAuthenticationLimit;
begin
  CheckFalse(ResumesAsFullHandshake(86400000, 86400000),
    'a ticket authenticated a day ago resumes');
end;

procedure TTestTls12Resumption.TestServerDeclinesATicketPastTheAuthenticationLimit;
begin
  // the client still offers it (its copy is young), so only the server can refuse
  CheckTrue(ResumesAsFullHandshake(UInt64(8) * 86400000, 86400000),
    'a ticket authenticated eight days ago draws a full handshake');
end;

procedure TTestTls12Resumption.TestClientDoesNotOfferASessionPastTheAuthenticationLimit;
begin
  // the server would resume its copy (young), so only the client can withhold the offer
  CheckTrue(ResumesAsFullHandshake(86400000, UInt64(8) * 86400000),
    'a session authenticated eight days ago is not offered');
end;

procedure TTestTls12Resumption.EstablishSessionIdSession(const AStore: ISessionStore;
  const ACache: ISessionCache; out AClient, AServer: ITlsEngine);
begin
  AClient := NewClient(ACache, True);
  AServer := NewServer(AStore, nil, 7200, True);
  RunHandshake(AClient, AServer);
  CheckEquals(1, AStore.Count, 'the server stored the session under its id');
  CheckEquals(1, ACache.Count, 'the client cached the session');
end;

procedure TTestTls12Resumption.TestFatalAlertDropsTheServersStoredSessionId;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  EstablishSessionIdSession(LStore, LCache, LClient, LServer);
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  CheckEquals(0, LStore.Count, 'a connection ended by a fatal alert is not resumable');
end;

procedure TTestTls12Resumption.TestFatalAlertDropsTheClientsCachedSession;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  EstablishSessionIdSession(LStore, LCache, LClient, LServer);
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  Pump(LServer, LClient);
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(0, LCache.Count, 'the session it cached is dropped');
end;

procedure TTestTls12Resumption.TestCloseNotifyKeepsTheStoredSessions;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  EstablishSessionIdSession(LStore, LCache, LClient, LServer);
  LServer.SendClose;
  Pump(LServer, LClient);
  CheckTrue(LClient.IsClosed, 'the client saw the close');
  CheckEquals(1, LStore.Count, 'a clean close leaves the server entry');
  CheckEquals(1, LCache.Count, 'and the client entry');
end;

procedure TTestTls12Resumption.TestFailedResumptionByIdDoesNotEvictTheStoredSession;
var
  LStore: ISessionStore;
  LCache, LAttackerCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LFirst: IResumableSession;
  L12: ITls12ResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  EstablishSessionIdSession(LStore, LCache, LClient, LServer);
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, LFirst), 'the session was cached');
  L12 := LFirst as ITls12ResumableSession;
  // a peer that knows the id but not the master secret: it names the stored session yet cannot
  // prove it, so the failure it provokes must not take the victim's entry with it
  LAttackerCache := TInMemorySessionCache.Create;
  LAttackerCache.Store(ServerHost + ':443', ServerHost, TTls12ResumableSession.Create(
    L12.CipherSuite, L12.Hash, TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(48)),
    L12.SessionId, nil, L12.ExtendedMasterSecret, nil, ServerHost, 7200,
    (TSystemClock.Create as ITlsClock).NowUnixMillis, nil, nil) as IResumableSession);
  LClient := NewClient(LAttackerCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  DriveObservingServerCert(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the unproven resumption ended in a fatal alert');
  CheckEquals(1, LStore.Count, 'the stored session survives');
end;

function TTestTls12Resumption.ReverifyResumeIsFull(const AStek: ISessionTicketKeyManager;
  ADualVersion, ARejectResume: Boolean; out AClient: ITlsEngine): Boolean;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  if ADualVersion then
    LClient := NewDualVersionClient(LCache)
  else
    LClient := NewClient(LCache, True);
  LServer := NewServer(nil, AStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer), 'the first handshake is full');
  CheckEquals(1, LCache.Count, 'the client cached a session');

  FReverify := True;
  if ARejectResume then
    FResumeVerifier := TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate)
      as IServerCertificateVerifier;
  if ADualVersion then
    AClient := NewDualVersionClient(LCache)
  else
    AClient := NewClient(LCache, True);
  LServer := NewServer(nil, AStek, 7200, True);
  Result := DriveObservingServerCert(AClient, LServer);
  CheckFalse(AClient.IsTerminal, 'the second handshake completed without error');
  CheckFalse(AClient.IsHandshaking, 'the second handshake finished');
end;

procedure TTestTls12Resumption.TestReverifyFailureOffersNoSessionAndRunsFullHandshake;
var
  LClient: ITlsEngine;
begin
  CheckTrue(ReverifyResumeIsFull(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom),
    False, True, LClient), 'a declined session is not offered, so the server runs a full one');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the distrusted session was not resumed');
end;

procedure TTestTls12Resumption.TestReverifyFailureDeclinesAndConsumesASessionIdSession;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LFirst, LSecond: IResumableSession;
  LOldId, LNewId: TBytes;
  LClock: ITlsClock;
begin
  LClock := TSystemClock.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  EstablishSessionIdSession(LStore, LCache, LClient, LServer);
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, LClock.NowUnixMillis, LFirst),
    'the session was cached');
  LOldId := (LFirst as ITls12ResumableSession).SessionId;
  LCache.Store(ServerHost + ':443', ServerHost, LFirst);

  FReverify := True;
  FResumeVerifier := TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate)
    as IServerCertificateVerifier;
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'the declined session id is not offered, so the server runs a full handshake');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the distrusted session was not resumed');
  CheckEquals(1, LCache.Count, 'only the full handshake''s session is cached');
  CheckTrue(LCache.Take(ServerHost + ':443', ServerHost, LClock.NowUnixMillis, LSecond),
    'the full handshake was cached');
  LNewId := (LSecond as ITls12ResumableSession).SessionId;
  CheckFalse((System.Length(LOldId) = System.Length(LNewId)) and
    CompareMem(Pointer(LOldId), Pointer(LNewId), System.Length(LOldId)),
    'the declined session was consumed, not kept in the cache');
end;

procedure TTestTls12Resumption.TestReverifyPassResumesTheSessionWithItsValidatedPath;
var
  LClient: ITlsEngine;
begin
  CheckFalse(ReverifyResumeIsFull(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom),
    False, False, LClient), 'a session that passes the check is offered and resumed');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the session resumed');
  CheckTrue(System.Length(LClient.ConnectionInfo.ValidatedPath) > 0,
    'the offer-time check validated a path that the resumed connection reports');
end;

procedure TTestTls12Resumption.TestDualVersionReverifyFailureOffersNoSessionAndRunsFullHandshake;
var
  LClient: ITlsEngine;
begin
  CheckTrue(ReverifyResumeIsFull(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom),
    True, True, LClient), 'a declined session is not offered, so the server runs a full one');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the distrusted session was not resumed');
end;

procedure TTestTls12Resumption.TestDualVersionReverifyPassHandsItsValidatedPathToTheTls12Machine;
var
  LClient: ITlsEngine;
begin
  CheckFalse(ReverifyResumeIsFull(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom),
    True, False, LClient), 'a session that passes the check is offered and resumed');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the session resumed');
  CheckTrue(System.Length(LClient.ConnectionInfo.ValidatedPath) > 0,
    'the parent''s validated path reached the 1.2 machine through the hand-off');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12Resumption);
{$ELSE}
  RegisterTest(TTestTls12Resumption.Suite);
{$ENDIF FPC}

end.
