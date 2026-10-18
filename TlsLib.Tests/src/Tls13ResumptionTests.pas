{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13ResumptionTests;

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
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpClientSessionPolicy,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpTlsConnectionInfo,
  TlpAlpnProtocols,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpTlsLibExceptions,
  TlpIHandshakeMachine,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpArrayUtilities,
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
  TlpAntiReplay,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpHandshakeEffect,
  MockCryptoProvider,
  MockTransport,
  MockClock,
  TlpITlsTransport,
  TlpTlsStream,
  MockSessionStores,
  MockCertificateVerifiers,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  TTestTls13Resumption = class(TTlsLibHandshakeTestCase)
  private
    const
      ServerHost = 'localhost';
    var
      // per-test overrides the builders below honor when set: the peers' clocks and ALPN lists
      FClientClock, FServerClock: ITlsClock;
      FClientAlpn, FServerAlpn: TArray<TBytes>;
    function ClientParams(const ACache: ISessionCache;
      AEarlyData: Boolean): TClientHandshakeParams;
    /// <summary>A framed message of AType whose body is ABody, as the client would receive it.</summary>
    function Framed(AType: TTlsHandshakeType; const ABody: TBytes): TTlsHandshakeMessage;
    function NewClient(const ACache: ISessionCache;
      AEarlyData: Boolean): ITlsEngine;
    /// <summary>A client that key-shares X25519 and also lists secp256r1, and a secp256r1-only
    /// server, so the handshake runs over a HelloRetryRequest.</summary>
    function NewRetryClient(const ACache: ISessionCache; AEarlyData: Boolean): ITlsEngine;
    function NewRetryServer(const AStek: ISessionTicketKeyManager; AIssueTickets: Int32;
      AMaxEarlyData: UInt32; const AAntiReplay: IAntiReplayStrategy): ITlsEngine;
    // AWithCredential False makes the server unable to run a full handshake, so a
    // completed handshake proves the PSK was accepted (resumption).
    function BuildServer(const AStek: ISessionTicketKeyManager;
      const AStore: ISessionStore; AIssueTickets: Int32; ALifetimeSeconds: UInt32;
      AWithCredential: Boolean; AMaxEarlyData: UInt32;
      const AAntiReplay: IAntiReplayStrategy): ITlsEngine;
    procedure PumpToCompletion(const AClient, AServer: ITlsEngine);
    function NewServer(const AStore: ISessionStore; AIssueTickets: Int32;
      ALifetimeSeconds: UInt32; AWithCredential: Boolean): ITlsEngine;
    function NewStekServer(const AStek: ISessionTicketKeyManager;
      AIssueTickets: Int32; ALifetimeSeconds: UInt32;
      AWithCredential: Boolean): ITlsEngine;
    procedure DriveHandshake(const AClient, AServer: ITlsEngine);
    /// <summary>A client offering APsks that, when AReverify, re-verifies resumed servers.</summary>
    function NewExtPskClient(const ACache: ISessionCache;
      const APsks: TArray<TExternalPsk>; AReverify: Boolean): ITlsEngine;
    /// <summary>A credential-less server accepting APsks, so completing proves PSK authentication.</summary>
    function NewExtPskServer(const AStek: ISessionTicketKeyManager;
      const APsks: TArray<TExternalPsk>; AIssueTickets: Int32): ITlsEngine;
    /// <summary>Establishes a 0-RTT-capable ticket, then resumes it with a credential-less server
    /// (so completing proves the resumption), the client writing early data when AClientEarly.</summary>
    procedure ResumeForEarlyData(AClientEarly: Boolean; AFirstMaxEarly, ASecondMaxEarly: UInt32;
      const AAntiReplay: IAntiReplayStrategy; out AClient, AServer: ITlsEngine);
    procedure CheckEarlyDataReasons(AClientReason, AServerReason: TEarlyDataReason;
      const AClient, AServer: ITlsEngine);
    /// <summary>A 0-RTT resumption after the client's clock advanced AClientAdvanceMs and the
    /// server's AServerAdvanceMs since the ticket was issued.</summary>
    procedure ResumeUnderClockSkew(AClientAdvanceMs, AServerAdvanceMs: UInt64;
      out AClient, AServer: ITlsEngine);
    /// <summary>An external-PSK handshake, then (AResume) its ticket resumed; AIdentity is the
    /// configured external identity.</summary>
    procedure ExternalPskHandshake(AResume: Boolean; out AClient, AServer: ITlsEngine;
      out AIdentity: TBytes);
    /// <summary>A Reverify client with 0-RTT on whose resumption-occasion verifier is
    /// AResumeVerifier, and with the given verdict deferral.</summary>
    function NewReverifyEarlyClient(const ACache: ISessionCache;
      const AResumeVerifier: IServerCertificateVerifier;
      ADeferral: TVerdictDeferral): ITlsEngine;
    /// <summary>A full handshake that leaves a 0-RTT-capable ticket in ACache.</summary>
    procedure CacheEarlyDataTicket(const AStek: ISessionTicketKeyManager;
      const AAnti: IAntiReplayStrategy; const ACache: ISessionCache);
    /// <summary>Drives a started handshake to its end, accepting an owed certificate verdict;
    /// True when the client parked for one.</summary>
    function PumpResolvingVerdict(const AClient, AServer: ITlsEngine): Boolean;
    /// <summary>The extension types of the ClientHello at the head of AWire.</summary>
    function OfferedTypes(const AWire: TBytes): TArray<UInt16>;
    function MakeSession(const AIdentity: TBytes; const ASecret: ISecretBuffer;
      ALifetime: UInt32; AMaxEarlyData: UInt32): IResumableSession;
    function MakeSessionForHost(const AIdentity: TBytes; const ASecret: ISecretBuffer;
      ALifetime: UInt32; const AHost: string;
      AMaxEarlyData: UInt32): IResumableSession;
    // shared mTLS-resumption scaffolding parameterized by the resumption scope
    function BuildMtlsClientEngine(const ACache: ISessionCache;
      const ACredential: TTlsCredential): ITlsEngine;
    function BuildMtlsServerEngine(const AStek: ISessionTicketKeyManager; AIssue: Int32;
      AClientAuth: TClientAuthMode; const AClientRoot, AScope: TBytes): ITlsEngine;
    /// <summary>A STEK server that requires a client certificate and also holds APsks.</summary>
    function BuildRequiredAuthPskServer(const AStek: ISessionTicketKeyManager;
      const APsks: TArray<TExternalPsk>; const AClientRoot: TBytes): ITlsEngine;
    /// <summary>A TLS 1.3 session like ASession, but holding ATicket and authenticated at
    /// AAuthenticatedAt.</summary>
    function Reauthenticated(const ASession: ITls13ResumableSession; const ATicket: TBytes;
      AAuthenticatedAt: UInt64): IResumableSession;
    /// <summary>A full handshake against a STEK server on the mock clocks, then a ticket resumption
    /// after six days: AClientSession is the ticket the client cached afterwards, AServerSession what
    /// the server sealed into it.</summary>
    procedure RenewAfterSixDays(AAdvanceServerClock: Boolean;
      out AClientSession, AServerSession: IResumableSession);
    /// <summary>A ticket resumption where the server's sealed copy was authenticated AServerAgeMs ago
    /// and the client's cached copy AClientAgeMs ago; True when the server ran a full handshake.</summary>
    function ResumesAsFullHandshake(AServerAgeMs, AClientAgeMs: UInt64): Boolean;
  published
    procedure TestRenewedTicketKeepsTheAuthenticationTimeOnTheClient;
    procedure TestRenewedTicketKeepsTheAuthenticationTimeOnTheServer;
    procedure TestRenewedTicketLifetimeIsCutToTheRemainingChain;
    procedure TestClientCutsTheRenewedTicketLifetimeOnItsOwnClock;
    procedure TestFullHandshakeTicketKeepsTheHandshakeAuthenticationTime;
    procedure TestFatalAlertFromABadRecordDropsTheClientsCachedTickets;
    procedure TestManyTicketsAreWithdrawnOnlyUpToTheRememberedBound;
    procedure TestResumptionOnTheChainsLastMillisecondMintsNoTicket;
    procedure TestOneFailingRemovalDoesNotStopTheRest;
    procedure TestServerResumesATicketInsideTheAuthenticationLimit;
    procedure TestServerDeclinesATicketPastTheAuthenticationLimit;
    procedure TestClientDoesNotOfferATicketPastTheAuthenticationLimit;
    procedure TestFatalAlertDropsTheClientsCachedTickets;
    procedure TestFatalAlertConsumesTheServersStatefulTickets;
    procedure TestCloseNotifyKeepsTheIssuedTickets;
    procedure TestCloseNotifyFollowedByJunkKeepsTheIssuedTickets;
    procedure TestResumptionCompletesPskDheKe;
    procedure TestMachinesRequireAClock;
    procedure TestSingleUseTicketReplayRejected;
    procedure TestMismatchedBinderAbortsDecryptError;
    procedure TestEmptyPskIdentityAbortsDecodeError;
    procedure TestExpiredTicketNotAccepted;
    procedure TestZeroLifetimeTicketIsNotCached;
    procedure TestCustomSessionCacheAndStoreAreUsed;
    procedure TestStatelessStekResumptionCompletes;
    procedure TestStekRetiredKeyNotAccepted;
    procedure TestStekInvalidTicketFallsBackToFullHandshake;
    procedure TestStoreUpgradesOverStek;
    procedure TestManySmallRecordsQueueByteForByte;
    procedure TestZeroRttAcceptedDeliversEarlyData;
    procedure TestZeroRttClientReportsNoVersionBeforeServerHello;
    procedure TestStreamReadRefusesUntilEarlyDataIsDrained;
    procedure TestZeroRttEarlyExporterMatchesAcrossPeers;
    procedure TestZeroRttRejectWithholdsClientEarlyExporter;
    procedure TestZeroRttAcceptedIsSurfacedOnBothPeers;
    procedure TestZeroRttRejectedIsSurfacedOnNeitherPeer;
    procedure TestZeroRttRetryWithholdsClientEarlyExporter;
    procedure TestZeroRttPskDeclinedWithholdsClientEarlyExporter;
    procedure TestEarlyDataInEncryptedExtensionsAfterPskDeclinedIsRejected;
    procedure TestWriteInEarlyDataWindowIsRefused;
    procedure TestWriteEarlyDataReturnsAcceptedCount;
    procedure TestZeroRttRejectedIsDiscardedNotReplayed;
    procedure TestZeroRttRejectAboveFixedBudgetIsSkipped;
    procedure TestZeroRttAcceptedSizeFollowsTheServersCurrentSetting;
    procedure TestZeroRttForeignTicketKeepsFixedSkipBudget;
    procedure TestZeroRttReplayCaughtByStrikeRegister;
    procedure TestZeroRttOverTicketBudgetIsFatal;
    procedure TestZeroRttUnboundedTicketBudgetStillSends;
    procedure TestZeroRttAntiReplayHoldIsTwiceFreshnessSkew;
    procedure TestEarlyDataOffByDefault;
    procedure TestMutualAuthResumptionCompletes;
    procedure TestMutualAuthRequiredDeclinesForeignTicket;
    procedure TestResumptionScopeMismatchDeclinesTicket;
    procedure TestResumptionSameScopeResumes;
    procedure TestMutualAuthTicketReissueCarriesChain;
    procedure TestTicketIssuedUnderDifferentSniFallsBackToFullHandshake;
    procedure TestExternalPskAcceptedDoesNotSurfaceCachedResumptionChain;
    procedure TestExternalPskSuiteSelectionHonorsClientOrder;
    procedure TestExternalPskTicketResumesOnlyWhilePskIsConfigured;
    procedure TestEarlyDataReasonAcceptedOnBothPeers;
    procedure TestEarlyDataReasonServerDisabledClientPeerDeclined;
    procedure TestEarlyDataReasonClientDisabledServerPeerDeclined;
    procedure TestEarlyDataReasonNoSessionOffered;
    procedure TestEarlyDataReasonUnsupportedForSession;
    procedure TestEarlyDataReasonSessionNotResumed;
    procedure TestEarlyDataReasonReplayDetected;
    procedure TestEarlyDataReasonHelloRetryRequestOnBothPeers;
    procedure TestHelloRetryRequestIsReportedOnBothPeers;
    procedure TestNoHelloRetryRequestIsReportedAsNone;
    procedure TestEarlyDataReasonAlpnMismatchOnTheClient;
    procedure TestEarlyDataReasonAlpnMismatchOnTheServer;
    procedure TestTicketAgeSkewIsReportedPastTheWindow;
    procedure TestStaleTicketAgeDeclinesEarlyData;
    procedure TestTicketAgeSkewIsReportedInsideTheWindow;
    procedure TestTicketAgeSkewWithinTheWindowKeepsEarlyData;
    procedure TestTicketBeyondTheCacheLimitIsNotCached;
    procedure TestTicketAtTheCacheLimitIsCached;
    procedure TestConnectionAfterAnUncachedTicketIsAFullHandshake;
    procedure TestTicketAgeDeobfuscationWrapsBelowTheAgeAdd;
    procedure TestTicketAgeWrapKeepsTheEarlyDataWindowOpen;
    procedure TestTicketAgeServerSideSaturatesIntoUInt32;
    procedure TestTicketAgeServerSideNeverGoesNegative;
    procedure TestExternalPskIsNotAResumption;
    procedure TestExternalPskReportsItsIdentity;
    procedure TestTicketIssuedUnderExternalPskResumes;
    procedure TestTicketIssuedUnderExternalPskKeepsReportingItsIdentity;
    procedure TestExternalPskSatisfiesRequiredClientAuth;
    procedure TestExternalPskTicketResumesUnderRequiredClientAuth;
    procedure TestRequiredClientAuthStillDeclinesAChainlessTicketWithoutAPsk;
    procedure TestExternalPskTicketResumesUnderReverify;
    procedure TestDeclinedTicketWithExternalPskStoresNoChain;
    procedure TestResumedTicketKeepsItsChainForReverify;
    procedure TestReverifyChecksTheStoredChainOnceBeforeTheClientHello;
    procedure TestReverifyPassOffersTheSessionAndEarlyData;
    procedure TestReverifyPassDeliversTheEarlyData;
    procedure TestReverifyPassKeepsTheValidatedPath;
    procedure TestReverifyFailureOffersNoTicketOrEarlyData;
    procedure TestReverifyFailureFallsBackToAFullHandshake;
    procedure TestReverifyRaisingVerifierFailsTheConnectionAndConsumesTheSession;
    procedure TestReverifyWithAsyncVerdictOffersNoEarlyData;
    procedure TestReverifyWithAsyncVerdictStillParksAtServerFinished;
  end;

implementation

type
  /// <summary>An anti-replay strategy that treats every binder as already seen.</summary>
  TRejectingAntiReplay = class(TInterfacedObject, IAntiReplayStrategy)
  public
    function CheckAndRecord(const AUniqueValue: TBytes;
      ANowMillis, AExpiryMillis: UInt64): Boolean;
    procedure Clear;
    function Count: Int32;
  end;

  /// <summary>Wraps the strike register and records the (now, expiry) pair of the last
  /// CheckAndRecord, so a test can observe the hold the server asks for.</summary>
  TRecordingAntiReplay = class(TInterfacedObject, IAntiReplayStrategy)
  strict private
    FInner: IAntiReplayStrategy;
    FCalls: Int32;
    FLastNow, FLastExpiry: UInt64;
  public
    constructor Create;
    function CheckAndRecord(const AUniqueValue: TBytes;
      ANowMillis, AExpiryMillis: UInt64): Boolean;
    procedure Clear;
    function Count: Int32;
    property Calls: Int32 read FCalls;
    property LastNow: UInt64 read FLastNow;
    property LastExpiry: UInt64 read FLastExpiry;
  end;

{ TRejectingAntiReplay }

function TRejectingAntiReplay.CheckAndRecord(const AUniqueValue: TBytes;
  ANowMillis, AExpiryMillis: UInt64): Boolean;
begin
  Result := False;
end;

procedure TRejectingAntiReplay.Clear;
begin
end;

function TRejectingAntiReplay.Count: Int32;
begin
  Result := 0;
end;

{ TRecordingAntiReplay }

constructor TRecordingAntiReplay.Create;
begin
  inherited Create;
  FInner := TStrikeRegisterAntiReplay.Create;
end;

function TRecordingAntiReplay.CheckAndRecord(const AUniqueValue: TBytes;
  ANowMillis, AExpiryMillis: UInt64): Boolean;
begin
  Inc(FCalls);
  FLastNow := ANowMillis;
  FLastExpiry := AExpiryMillis;
  Result := FInner.CheckAndRecord(AUniqueValue, ANowMillis, AExpiryMillis);
end;

procedure TRecordingAntiReplay.Clear;
begin
  FInner.Clear;
end;

function TRecordingAntiReplay.Count: Int32;
begin
  Result := FInner.Count;
end;

{ TTestTls13Resumption }

function TTestTls13Resumption.NewClient(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(ClientParams(ACache, AEarlyData)) as IHandshakeMachine,
    Crypto);
end;

function TTestTls13Resumption.ClientParams(const ACache: ISessionCache;
  AEarlyData: Boolean): TClientHandshakeParams;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  if FClientClock <> nil then
    LParams.Clock := FClientClock;
  LParams.AlpnProtocols := FClientAlpn;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
  LParams.ServerName := ServerHost;
  LParams.SessionCache := ACache;
  LParams.EarlyDataEnabled := AEarlyData;
  Result := LParams;
end;

function TTestTls13Resumption.BuildServer(const AStek: ISessionTicketKeyManager;
  const AStore: ISessionStore; AIssueTickets: Int32; ALifetimeSeconds: UInt32;
  AWithCredential: Boolean; AMaxEarlyData: UInt32;
  const AAntiReplay: IAntiReplayStrategy): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  if FServerClock <> nil then
    LParams.Clock := FServerClock;
  LParams.AlpnProtocols := FServerAlpn;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  if AWithCredential then
    LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionTicketKeys := AStek;
  LParams.SessionStore := AStore;
  LParams.IssueTicketCount := AIssueTickets;
  LParams.TicketLifetimeSeconds := ALifetimeSeconds;
  LParams.MaxEarlyData := AMaxEarlyData;
  LParams.AntiReplay := AAntiReplay;

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Resumption.NewRetryClient(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  // key-shares X25519 but also lists secp256r1, so a secp256r1-only server answers with a
  // HelloRetryRequest
  LParams := ClientParams(ACache, AEarlyData);
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Resumption.NewRetryServer(const AStek: ISessionTicketKeyManager;
  AIssueTickets: Int32; AMaxEarlyData: UInt32;
  const AAntiReplay: IAntiReplayStrategy): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1');
  LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.CookieSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionTicketKeys := AStek;
  LParams.IssueTicketCount := AIssueTickets;
  LParams.TicketLifetimeSeconds := 7200;
  LParams.MaxEarlyData := AMaxEarlyData;
  LParams.AntiReplay := AAntiReplay;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Resumption.NewServer(const AStore: ISessionStore;
  AIssueTickets: Int32; ALifetimeSeconds: UInt32;
  AWithCredential: Boolean): ITlsEngine;
begin
  Result := BuildServer(nil, AStore, AIssueTickets, ALifetimeSeconds, AWithCredential, 0, nil);
end;

function TTestTls13Resumption.NewStekServer(const AStek: ISessionTicketKeyManager;
  AIssueTickets: Int32; ALifetimeSeconds: UInt32;
  AWithCredential: Boolean): ITlsEngine;
begin
  Result := BuildServer(AStek, nil, AIssueTickets, ALifetimeSeconds, AWithCredential, 0, nil);
end;

procedure TTestTls13Resumption.PumpToCompletion(const AClient, AServer: ITlsEngine);
begin
  ExchangeFlights(AClient, AServer);
  // flush any post-handshake NewSessionTicket from the server to the client
  Pump(AServer, AClient);
end;

procedure TTestTls13Resumption.DriveHandshake(const AClient, AServer: ITlsEngine);
begin
  AClient.StartHandshake;
  PumpToCompletion(AClient, AServer);
end;

function TTestTls13Resumption.NewExtPskClient(const ACache: ISessionCache;
  const APsks: TArray<TExternalPsk>; AReverify: Boolean): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := ClientParams(ACache, False);
  LParams.ExternalPsks := APsks;
  if AReverify then
    LParams.ResumeVerification := TResumeVerification.Reverify;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Resumption.NewExtPskServer(const AStek: ISessionTicketKeyManager;
  const APsks: TArray<TExternalPsk>; AIssueTickets: Int32): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.SessionTicketKeys := AStek;
  LParams.IssueTicketCount := AIssueTickets;
  LParams.TicketLifetimeSeconds := 7200;
  LParams.ExternalPsks := APsks;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Resumption.MakeSession(const AIdentity: TBytes;
  const ASecret: ISecretBuffer; ALifetime: UInt32; AMaxEarlyData: UInt32): IResumableSession;
begin
  Result := MakeSessionForHost(AIdentity, ASecret, ALifetime, ServerHost, AMaxEarlyData);
end;

function TTestTls13Resumption.MakeSessionForHost(const AIdentity: TBytes;
  const ASecret: ISecretBuffer; ALifetime: UInt32; const AHost: string;
  AMaxEarlyData: UInt32): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, ASecret, nil, AHost, AIdentity,
    ALifetime, 0, UInt64(TSystemTimeUtilities.UtcUnixMs), AMaxEarlyData, nil, nil);
end;

procedure TTestTls13Resumption.TestResumptionCompletesPskDheKe;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  // first connection: a full handshake that issues one ticket
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial client handshake completed');
  CheckFalse(LServer.IsHandshaking, 'the initial server handshake completed');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the initial client handshake is not resumed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the initial server handshake is not resumed');
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');
  CheckEquals(1, LStore.Count, 'the server stored the resumable session');
  // on the full handshake the presented server chain and the pipeline-built path demonstrably differ:
  // a leaf-only credential is presented, but the validated path assembles the anchor beyond it
  LInfo := LClient.ConnectionInfo;
  CheckTrue(System.Length(LInfo.ValidatedPath) > System.Length(LInfo.PeerCertificates),
    'the validated path is longer than the presented server chain on a full handshake');

  // second connection: the server has NO credential, so it can only complete by
  // accepting the PSK (a full handshake would need a certificate)
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the resuming client completed');
  CheckFalse(LServer.IsHandshaking, 'the credential-less server completed via the PSK');
  CheckFalse(LClient.IsTerminal, 'the resuming client did not fail');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the resuming client reports a resumed handshake');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the resuming server reports a resumed handshake');
  CheckEquals(0, LStore.Count, 'the ticket was consumed (single-use)');
  // the credential-less server proves the chain came from the ticket: the resumed client surfaces the
  // stored server chain, and with no re-verification it validates no path here
  LServerCred := ServerCredential;
  LInfo := LClient.ConnectionInfo;
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the resumed client surfaces the stored server chain from the ticket');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestSingleUseTicketReplayRejected;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // seed a matching client cache entry and server store entry (same identity+secret)
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200, 0));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity, LSecret, 7200, 0));

  // first use resumes against a credential-less server: completion proves acceptance
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the first use resumed');
  CheckFalse(LServer.IsTerminal, 'the first use did not fail');
  CheckEquals(0, LStore.Count, 'the ticket was consumed');

  // replay the same ticket: the store no longer holds it, so a credential-less server
  // cannot resume and cannot run a full handshake - the replay is rejected
  LCache := TInMemorySessionCache.Create;
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200, 0));
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'a replayed single-use ticket is not silently accepted');
end;

procedure TTestTls13Resumption.TestMismatchedBinderAbortsDecryptError;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
begin
  // the client's cached secret differs from the server's stored secret for the same
  // identity, so the server opens the ticket but its binder does not validate
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity,
    TSecretBuffer.From(Filled($AA, 32)), 7200, 0));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity,
    TSecretBuffer.From(Filled($BB, 32)), 7200, 0));

  // a present binder that does not validate against an opened ticket is fatal: the server
  // aborts with decrypt_error rather than silently falling back to a full handshake
  // (RFC 9846 4.3.11.2)
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server aborted on the bad binder');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.DecryptError,
    'the server sent decrypt_error');
end;

procedure TTestTls13Resumption.TestEmptyPskIdentityAbortsDecodeError;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // pre_shared_key identity<1..2^16-1> (RFC 9846 4.3.11): an empty identity is malformed
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(nil,
    TSecretBuffer.From(Filled($AA, 32)), 7200, 0));
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server aborted on the empty identity');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.DecodeError,
    'the server sent decode_error');
end;

procedure TTestTls13Resumption.TestExpiredTicketNotAccepted;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // an expired ticket (lifetime 0) against a credential-less server: the server must
  // reject the PSK on freshness and then cannot run a full handshake, so it does not
  // complete - proving the expired ticket was not accepted
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 0, 0));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity, LSecret, 0, 0));

  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 0, False);
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'an expired ticket is not accepted');
end;

procedure TTestTls13Resumption.TestZeroLifetimeTicketIsNotCached;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a ticket_lifetime of 0 means the client discards it immediately and must not cache it
  // (RFC 9846 4.7.1)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 0, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckFalse(LClient.IsTerminal, 'the handshake did not fail');
  CheckEquals(0, LCache.Count, 'a lifetime-0 ticket is not cached');
end;

procedure TTestTls13Resumption.TestCustomSessionCacheAndStoreAreUsed;
var
  LCacheImpl: TMockSessionCache;
  LStoreImpl: TMockSessionStore;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a user's own ISessionCache/ISessionStore implementations, injected the same way as
  // the shipped defaults; the interface references govern lifetime
  LCacheImpl := TMockSessionCache.Create;
  LCache := LCacheImpl;
  LStoreImpl := TMockSessionStore.Create;
  LStore := LStoreImpl;

  // first connection: a full handshake issues a ticket through the custom store/cache
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the custom cache received the ticket');
  CheckEquals(1, LStore.Count, 'the custom store received the session');

  // second connection resumes: a credential-less server can only complete if the engine
  // actually consulted the custom store and cache
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resume completed through the custom store');
  CheckFalse(LServer.IsTerminal, 'no failure resuming through the custom implementations');
  CheckTrue(LStoreImpl.TakeCount >= 1, 'the engine invoked the custom store Take');
  CheckTrue(LCacheImpl.TakeCount >= 1, 'the engine invoked the custom cache Take');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestStatelessStekResumptionCompletes;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // the default (no store) strategy: AEAD-sealed tickets under a shared STEK, no
  // server-side storage
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the STEK ticket');

  // credential-less: completion proves the sealed ticket was opened and accepted
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the stateless STEK resume completed');
  CheckFalse(LServer.IsTerminal, 'no failure resuming under the STEK');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestStekRetiredKeyNotAccepted;
var
  LStek: IRotatingTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LI: Int32;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;

  // issue a real STEK ticket
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a STEK ticket was issued');

  // rotate the STEK until the issuing key falls out of the decrypt window
  for LI := 0 to 5 do
    LStek.Rotate;

  // the sealed ticket's key is gone: a credential-less server cannot open it and cannot
  // run a full handshake, so it does not complete
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'a ticket sealed under a retired STEK key is not accepted');
end;

procedure TTestTls13Resumption.TestStekInvalidTicketFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a client offering a garbage "ticket" that is not a valid STEK seal
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCache.Store(ServerHost, ServerHost, MakeSession(
    Crypto.Primitives.GetRandom.GenerateBytes(48),
    TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32)), 7200, 0));

  // the server cannot open the bogus ticket and completes a full handshake instead
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client completed a full handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed a full handshake');
  CheckFalse(LServer.IsTerminal, 'an unopenable ticket is not fatal');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestStoreUpgradesOverStek;
var
  LStek: ISessionTicketKeyManager;
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // configuring both a STEK and a store upgrades to the stateful single-use store
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, LStore, 1, 7200, True, 0, nil);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the store (not the STEK) issued the ticket');

  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, LStore, 0, 7200, False, 0, nil);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the store-backed resume completed');
  CheckEquals(0, LStore.Count, 'the store ticket was consumed (single-use), proving the upgrade');
end;

procedure TTestTls13Resumption.TestManySmallRecordsQueueByteForByte;
const
  RecordCount = Int32(9000);
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LOne, LWant, LGot, LStep: TBytes;
  LIdx, LTaken, LRead: Int32;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);

  // one-byte records, read back in odd steps so the queue's consumed prefix is reclaimed while
  // later records are still arriving
  System.SetLength(LOne, 1);
  System.SetLength(LWant, RecordCount);
  System.SetLength(LStep, 7);
  LGot := nil;
  for LIdx := 0 to RecordCount - 1 do
  begin
    LOne[0] := Byte(LIdx * 7 + 3);
    LWant[LIdx] := LOne[0];
    LClient.Write(LOne, 0, 1);
    if LIdx mod 1000 = 999 then
    begin
      Pump(LClient, LServer);
      // take part of what has arrived, leaving a live remainder behind the consumed prefix
      LRead := 0;
      while LRead < 600 do
      begin
        LTaken := LServer.ReadAppData(LStep, 0, 7);
        if LTaken = 0 then
          Break;
        LGot := ConcatBytes(LGot, System.Copy(LStep, 0, LTaken));
        Inc(LRead, LTaken);
      end;
    end;
  end;
  Pump(LClient, LServer);
  repeat
    LTaken := LServer.ReadAppData(LStep, 0, 7);
    if LTaken > 0 then
      LGot := ConcatBytes(LGot, System.Copy(LStep, 0, LTaken));
  until LTaken = 0;
  CheckEqualBytes('the bytes come back in order', LWant, LGot);
  CheckEquals(0, LServer.PendingAppData, 'the queue is drained');
end;

procedure TTestTls13Resumption.TestZeroRttAcceptedDeliversEarlyData;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // first connection: a full handshake issues a ticket authorizing 0-RTT
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a 0-RTT-capable ticket was cached');

  // second connection: send 0-RTT early data. The server has no credential, so it can
  // only complete by accepting the PSK, and the early data must decrypt under the early keys
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461'); // "0RTT early data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the 0-RTT client completed');
  CheckFalse(LServer.IsHandshaking, 'the credential-less server completed via 0-RTT');
  CheckFalse(LServer.IsTerminal, 'no failure on 0-RTT');
  CheckEquals(System.Length(LEarly), LServer.PendingEarlyData,
    'the early data is buffered apart from the 1-RTT queue');
  CheckEquals(0, LServer.PendingAppData,
    'accepted early data is not counted as 1-RTT data');
  CheckEqualBytes('the server received the early data as 0-RTT', LEarly,
    ReadAllEarly(LServer));
  CheckEquals(0, System.Length(ReadAllApp(LServer)),
    'accepted early data is never delivered through the 1-RTT read path');
  CheckEquals(0, LClient.PendingEarlyData, 'a client never holds early data');
end;

procedure TTestTls13Resumption.TestStreamReadRefusesUntilEarlyDataIsDrained;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly, LBuf: TBytes;
  LReadPipe: TMemoryPipe;
  LStream: TTlsStream;
  LRefused, LTruncated: Boolean;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);

  LReadPipe := TMemoryPipe.Create;
  LReadPipe.Close;
  LStream := TTlsStream.Create(TMemoryTransport.Create(LReadPipe, TMemoryPipe.Create) as
    ITlsTransport, LServer, False, '');
  SetLength(LBuf, 64);
  try
    LRefused := False;
    try
      LStream.Read(LBuf[0], 64);
    except
      on E: EInvalidOperationTlsLibException do
        LRefused := True;
    end;
    CheckTrue(LRefused, 'a Read over unread 0-RTT bytes is refused, not blocked or skipped');
    CheckEquals(System.Length(LEarly), LStream.ReadEarlyData(LBuf[0], 64),
      'ReadEarlyData returns the 0-RTT bytes');
    CheckEquals(0, LStream.ReadEarlyData(LBuf[0], 64), 'and then reports none left');
    LTruncated := False;
    try
      LStream.Read(LBuf[0], 64);
    except
      on E: ETlsTransportTruncated do
        LTruncated := True;
    end;
    CheckTrue(LTruncated, 'Read proceeds to the transport once the early data is drained');
  finally
    LStream.Free;
    LReadPipe.Free;
  end;
end;

procedure TTestTls13Resumption.TestZeroRttEarlyExporterMatchesAcrossPeers;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly, LCtx, LClientExp, LServerExp: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  // issue a 0-RTT-capable ticket, then resume with accepted 0-RTT
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461'); // "0RTT early data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the 0-RTT resumption completed');
  // both peers derive the early_exporter_secret over the same ClientHello, so an
  // exported early value agrees end to end (RFC 9846 7.5)
  LCtx := DecodeHex('00010203');
  LClientExp := LClient.ExportEarlyKeyingMaterial('EXPORTER-tlslib', LCtx, 32);
  LServerExp := LServer.ExportEarlyKeyingMaterial('EXPORTER-tlslib', LCtx, 32);
  CheckEquals(32, System.Length(LClientExp), 'the client exported 32 early bytes');
  CheckEqualBytes('client and server derive the same early exporter', LClientExp, LServerExp);
  CheckFalse(AreEqual(LClientExp,
    LClient.ExportKeyingMaterial('EXPORTER-tlslib', LCtx, 32)),
    'the early exporter differs from the application exporter');
end;

procedure TTestTls13Resumption.TestZeroRttRejectWithholdsClientEarlyExporter;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  // issue a 0-RTT-capable ticket, then resume but the server rejects early data (MaxEarlyData 0)
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 0, LAnti);
  LEarly := DecodeHex('7265706c617965642064617461'); // "replayed data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the reject is not fatal');
  // once 0-RTT is rejected the peer derives no early exporter for this connection, so the client
  // withholds it rather than hand back a value that binds to nothing
  CheckEquals(0, System.Length(
    LClient.ExportEarlyKeyingMaterial('EXPORTER-tlslib', DecodeHex('00'), 32)),
    'a rejected 0-RTT client withholds the early exporter');
end;

procedure TTestTls13Resumption.TestZeroRttAcceptedIsSurfacedOnBothPeers;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.EarlyDataAccepted, 'a full handshake accepts no early data');
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.EarlyDataAccepted, 'the client sees its early data accepted');
  CheckTrue(LServer.ConnectionInfo.EarlyDataAccepted, 'the server reports the early data it accepted');
end;

procedure TTestTls13Resumption.TestZeroRttRejectedIsSurfacedOnNeitherPeer;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 0, LAnti);
  LEarly := DecodeHex('7265706c617965642064617461');
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.EarlyDataAccepted, 'the client sees its early data rejected');
  CheckFalse(LServer.ConnectionInfo.EarlyDataAccepted, 'the server reports no accepted early data');
end;

procedure TTestTls13Resumption.TestZeroRttRetryWithholdsClientEarlyExporter;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  // issue a 0-RTT-capable ticket (itself over a HelloRetryRequest), then resume offering 0-RTT: the
  // server retries the client onto another group, which withdraws the early-data offer
  LClient := NewRetryClient(LCache, False);
  LServer := NewRetryServer(LStek, 1, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a 0-RTT-capable ticket was cached');
  // the first handshake taught the cache the server's group, which would let the next ClientHello
  // key-share it directly and skip the retry this test needs
  LCache.SetKxHint(TClientSessionPolicy.CacheIdentity('', ServerHost, nil), ServerHost, 0);
  LClient := NewRetryClient(LCache, True);
  LServer := NewRetryServer(LStek, 0, 16384, LAnti);
  LEarly := DecodeHex('7265706c617965642064617461'); // "replayed data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the retry is not fatal');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the handshake still resumed after the retry');
  // the second ClientHello does not re-offer early_data, so the server derives no early exporter
  // and the client must not hand back one that binds to nothing
  CheckEquals(0, System.Length(
    LClient.ExportEarlyKeyingMaterial('EXPORTER-tlslib', DecodeHex('00'), 32)),
    'a client whose 0-RTT offer a HelloRetryRequest withdrew withholds the early exporter');
end;

function TTestTls13Resumption.Framed(AType: TTlsHandshakeType;
  const ABody: TBytes): TTlsHandshakeMessage;
var
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
begin
  LFramed := THandshakeFraming.Frame(AType, ABody);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

procedure TTestTls13Resumption.TestEarlyDataInEncryptedExtensionsAfterPskDeclinedIsRejected;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LMachine: IHandshakeMachine;
  LSm: TTls13ClientStateMachine;
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsServerHello;
  LEffects: TArray<THandshakeEffect>;
  LBasePoint: TBytes;
  LFailed: Boolean;
  LAlert: TTlsAlertDescription;

begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  // a client that offers a ticket and 0-RTT, fed a ServerHello that selects no PSK (the server
  // fell back to a full handshake): early_data in EncryptedExtensions is then one the response
  // cannot carry, although the client did offer it (RFC 9846 4.3.10). A ticket is used once, so
  // each flow below gets its own, issued through a real handshake.
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  DriveHandshake(LClient, LServer);
  LSm := TTls13ClientStateMachine.Create(ClientParams(LCache, True));
  LMachine := LSm as IHandshakeMachine;
  LMachine.Start;
  CheckTrue(LSm.EarlyDataOffered, 'the client offered 0-RTT with the ticket');
  LBasePoint := Filled(0, 32);
  LBasePoint[0] := 9;
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    LContext.SelectedVersion := TlsWireVersionTls13;
    LContext.SelectedKeyShare.Group := TNamedGroupCatalog.X25519;
    LContext.SelectedKeyShare.KeyExchange := LBasePoint;
    LHello.Random := Filled($01, 32);
    LHello.LegacySessionIdEcho := Filled($33, 32);
    LHello.CipherSuite := TCipherSuites13.Aes128GcmSha256;
    LHello.Extensions := LCodec.ProduceBlock(LContext, TTlsExtensionContextKind.ServerHello);
  finally
    LContext.Free;
  end;
  LEffects := LMachine.ProcessMessage(Framed(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LHello)));
  CheckFalse(FailAlertOf(LEffects, LAlert), 'a ServerHello without a PSK is a full handshake');
  // control: EncryptedExtensions without early_data is accepted
  LEffects := LMachine.ProcessMessage(Framed(TTlsHandshakeType.EncryptedExtensions,
    DecodeHex('0000')));
  CheckFalse(FailAlertOf(LEffects, LAlert), 'control: plain EncryptedExtensions is accepted');

  // the same flow again on a fresh ticket, this time with early_data in EncryptedExtensions
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  DriveHandshake(LClient, LServer);
  LSm := TTls13ClientStateMachine.Create(ClientParams(LCache, True));
  LMachine := LSm as IHandshakeMachine;
  LMachine.Start;
  CheckTrue(LSm.EarlyDataOffered, 'the second client offered 0-RTT with its own ticket');
  LContext := TExtensionContext.Create;
  try
    LContext.SelectedVersion := TlsWireVersionTls13;
    LContext.SelectedKeyShare.Group := TNamedGroupCatalog.X25519;
    LContext.SelectedKeyShare.KeyExchange := LBasePoint;
    LHello.Extensions := LCodec.ProduceBlock(LContext, TTlsExtensionContextKind.ServerHello);
  finally
    LContext.Free;
  end;
  LMachine.ProcessMessage(Framed(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LHello)));
  LEffects := LMachine.ProcessMessage(Framed(TTlsHandshakeType.EncryptedExtensions,
    DecodeHex('0004002a0000')));
  LFailed := FailAlertOf(LEffects, LAlert);
  CheckTrue(LFailed, 'early_data after a declined PSK aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.UnsupportedExtension, 'with unsupported_extension');
end;

procedure TTestTls13Resumption.TestZeroRttPskDeclinedWithholdsClientEarlyExporter;
var
  LStek, LOtherStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LOtherStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  // issue a 0-RTT-capable ticket, then resume against a server holding a DIFFERENT STEK: it cannot
  // open the ticket, so the PSK is declined and the handshake falls back to a full one (this is the
  // PSK-rejected reject path, distinct from the server accepting the PSK but refusing early data)
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LOtherStek, nil, 0, 7200, True, 16384, LAnti);
  LEarly := DecodeHex('7265706c617965642064617461'); // "replayed data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the PSK decline falls back to a full handshake, not fatal');
  CheckEquals(0, System.Length(
    LClient.ExportEarlyKeyingMaterial('EXPORTER-tlslib', DecodeHex('00'), 32)),
    'a client whose PSK was declined withholds the early exporter');
end;

procedure TTestTls13Resumption.TestWriteInEarlyDataWindowIsRefused;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly, LData: TBytes;
  LRaised: Boolean;
begin
  // while the write side is on the early-data epoch, a regular Write must be refused: it would
  // otherwise seal application data under the 0-RTT keys as replayable early data. 0-RTT goes
  // through WriteEarlyData, not Write (RFC 9846 2 / 4.3.10)
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  // first connection issues a 0-RTT-capable ticket
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  // second connection opens the early-data write window
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461'); // "0RTT early data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  LData := DecodeHex('6e6f7065'); // "nope"
  LRaised := False;
  try
    LClient.Write(LData, 0, System.Length(LData));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a plain Write in the early-data window is refused');
  // complete: the early data still arrives as 0-RTT, and a 1-RTT write then succeeds
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the 0-RTT client completed');
  CheckEqualBytes('the early data arrived as 0-RTT', LEarly, ReadAllEarly(LServer));
  LClient.Write(LData, 0, System.Length(LData));
  Pump(LClient, LServer);
  CheckEqualBytes('a 1-RTT write follows once the application epoch is in force', LData,
    ReadAllApp(LServer));
end;

procedure TTestTls13Resumption.TestZeroRttClientReportsNoVersionBeforeServerHello;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 2, LAnti);
  DriveHandshake(LClient, LServer);

  LClient := NewClient(LCache, True);
  LClient.StartHandshake;
  // the early write keys are installed (early data is accepted), but no ServerHello has fixed the version yet
  CheckEquals(2, LClient.WriteEarlyData(DecodeHex('6865'), 0, 2),
    'the early-data keys are installed once the handshake starts');
  CheckEquals(0, Int32(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
    'installing the early-data keys does not publish a negotiated version');
end;

procedure TTestTls13Resumption.TestWriteEarlyDataReturnsAcceptedCount;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // issue a ticket authorizing only 2 bytes of early data
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 2, LAnti);
  DriveHandshake(LClient, LServer);

  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 2, LAnti);
  LEarly := DecodeHex('68656c6c6f'); // "hello" (5 bytes)

  // the window is not open until StartHandshake installs the early write epoch
  CheckEquals(0, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'no early data is accepted before StartHandshake opens the window');
  LClient.StartHandshake;
  // only the ticket's max_early_data (2) is accepted; the caller resends the remainder as 1-RTT
  CheckEquals(2, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'WriteEarlyData accepts only up to the ticket max_early_data budget and returns that count');
  // the budget is now spent
  CheckEquals(0, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'once the budget is spent no further early data is accepted');
  PumpToCompletion(LClient, LServer);
  // the window is closed after completion
  CheckEquals(0, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'no early data is accepted after the handshake completes');
end;

procedure TTestTls13Resumption.TestZeroRttRejectedIsDiscardedNotReplayed;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // issue a 0-RTT-capable ticket
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);

  // resume and send 0-RTT, but the server rejects early data (MaxEarlyData 0). The rejected
  // early data went out under the early keys and the server skips it; the engine does NOT
  // transparently replay it as 1-RTT (RFC 9846 4.3.10 leaves any resend to the application), so
  // nothing is delivered to the server for it.
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 0, LAnti);
  LEarly := DecodeHex('7265706c617965642064617461'); // "replayed data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resumption completed despite the 0-RTT reject');
  CheckFalse(LServer.IsTerminal, 'the reject is not fatal');
  CheckEquals(0, System.Length(ReadAllApp(LServer)) + System.Length(ReadAllEarly(LServer)),
    'the rejected early data is discarded, not auto-replayed as 1-RTT');
end;

procedure TTestTls13Resumption.TestZeroRttRejectAboveFixedBudgetIsSkipped;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // issue a ticket authorizing more early data than the fixed 16 KiB fallback skip budget
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 40000, LAnti);
  DriveHandshake(LClient, LServer);

  // resume and send more than 16 KiB of 0-RTT; the server rejects it (its own MaxEarlyData is 0)
  // but the PSK still opens, so the skip budget tracks the ticket's authorization and the extra
  // bytes are skipped rather than tripping "too much skipped early data"
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 0, LAnti);
  LEarly := Filled($5a, 40000);
  LClient.StartHandshake;
  CheckTrue(LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)) > 16384,
    'the ticket authorized more early data than the fixed fallback');
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the oversize rejected 0-RTT is skipped, not fatal');
  CheckFalse(LServer.IsHandshaking, 'the resumption completed despite the reject');
  CheckEquals(0, System.Length(ReadAllApp(LServer)),
    'the rejected early data is discarded');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestZeroRttAcceptedSizeFollowsTheServersCurrentSetting;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // a ticket authorizing 40000 bytes of 0-RTT, then the server lowers its own setting to 1000: the
  // outstanding ticket must not let a client send more than the server now accepts
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 40000, LAnti);
  DriveHandshake(LClient, LServer);

  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 1000, LAnti);
  LEarly := Filled($5a, 2000);
  LClient.StartHandshake;
  CheckEquals(2000, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'the client sends within the size its ticket authorized');
  PumpToCompletion(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'early data beyond the server''s current setting is fatal');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.UnexpectedMessage,
    'the server sent unexpected_message');
  CheckTrue(System.Length(ReadAllEarly(LServer)) <= 1000,
    'no more than the current setting of early data was delivered');

  // within the lowered setting the same ticket still works
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 40000, LAnti);
  DriveHandshake(LClient, LServer);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 1000, LAnti);
  LEarly := Filled($5a, 500);
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'early data within the current setting is accepted');
  CheckEqualBytes('and delivered', LEarly, ReadAllEarly(LServer));
end;

procedure TTestTls13Resumption.TestZeroRttForeignTicketKeepsFixedSkipBudget;
var
  LStekA, LStekB: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStekA := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStekB := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // a 0-RTT-capable ticket is minted under one STEK
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStekA, nil, 1, 7200, True, 40000, LAnti);
  DriveHandshake(LClient, LServer);

  // resume against a server with a DIFFERENT STEK: the ticket never opens, so no ticket
  // authorization is known and the skip budget stays the fixed fallback. Sending more than that
  // fallback of unreadable early data is treated as too much skipped early data (fatal).
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStekB, nil, 0, 7200, False, 0, LAnti);
  LEarly := Filled($5a, 20000);
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckTrue(LServer.IsTerminal,
    'more than the fixed fallback of unauthorized skipped early data is fatal');
end;

procedure TTestTls13Resumption.TestZeroRttReplayCaughtByStrikeRegister;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServerA, LServerB: ITlsEngine;
  LEarly, LFlight: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServerA := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServerA);

  // capture the exact 0-RTT client flight (ClientHello + CCS + early records)
  LClient := NewClient(LCache, True);
  LServerA := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('7265706c61792061747461636b'); // "replay attack"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  LFlight := Drain(LClient);

  // the first server accepts the early data (records the binder in the register)
  Feed(LServerA, LFlight);
  CheckEqualBytes('the first use delivers the early data', LEarly,
    ReadAllEarly(LServerA));

  // replaying the identical flight to another server sharing the register: the binder is
  // a strike, so 0-RTT is rejected and the early data is skipped, not delivered
  LServerB := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  Feed(LServerB, LFlight);
  CheckEquals(0, System.Length(ReadAllApp(LServerB)) + System.Length(ReadAllEarly(LServerB)),
    'a replayed 0-RTT flight is caught by the strike register and skipped');
end;

procedure TTestTls13Resumption.TestZeroRttOverTicketBudgetIsFatal;
var
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity, LEarly: TBytes;
  LSecret: ISecretBuffer;
begin
  LAnti := TStrikeRegisterAntiReplay.Create;
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  // the client believes the ticket authorizes 4096 bytes; the server's record of that same
  // ticket authorizes only 1024, so the server's accepted window is the smaller budget
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200, 4096));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity, LSecret, 7200, 1024));

  LClient := NewClient(LCache, True);
  LServer := BuildServer(nil, LStore, 0, 7200, False, 16384, LAnti);
  LEarly := Filled($5a, 4096);
  LClient.StartHandshake;
  CheckEquals(4096, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'the client sends up to its cached max_early_data');
  PumpToCompletion(LClient, LServer);
  // more accepted early data than the ticket's max_early_data_size MUST terminate the
  // connection with unexpected_message (RFC 9846 4.7.1)
  CheckTrue(LServer.IsTerminal, 'accepted 0-RTT beyond the ticket budget is fatal');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.UnexpectedMessage,
    'the server sent unexpected_message');
  CheckTrue(System.Length(ReadAllEarly(LServer)) <= 1024,
    'no more than the ticket budget of early data was delivered');
end;

procedure TTestTls13Resumption.TestZeroRttUnboundedTicketBudgetStillSends;
var
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity, LEarly: TBytes;
  LSecret: ISecretBuffer;
begin
  LAnti := TStrikeRegisterAntiReplay.Create;
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  // 0xFFFFFFFF is the conventional "unbounded" max_early_data_size: it must neither truncate
  // the client's budget to nothing nor break the server's accepted window
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200, $FFFFFFFF));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity, LSecret, 7200, $FFFFFFFF));

  LClient := NewClient(LCache, True);
  LServer := BuildServer(nil, LStore, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461'); // "0RTT early data"
  LClient.StartHandshake;
  CheckEquals(System.Length(LEarly),
    LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'an unbounded ticket budget still lets the client send early data');
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'no failure on 0-RTT under an unbounded ticket budget');
  CheckFalse(LServer.IsHandshaking, 'the credential-less server completed via 0-RTT');
  CheckEqualBytes('the early data was delivered', LEarly, ReadAllEarly(LServer));
end;

procedure TTestTls13Resumption.TestZeroRttAntiReplayHoldIsTwiceFreshnessSkew;
const
  // a replay only passes the 60 s freshness check within ~2x that skew of the original
  // twice the 60 s freshness skew, plus 1 ms so the strike outlives the last instant a
  // max-skew replay can still pass the freshness check
  ExpectedHoldMillis = Int64(2 * 60 * 1000) + 1;
var
  LRecorder: TRecordingAntiReplay;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity, LEarly: TBytes;
  LSecret: ISecretBuffer;
begin
  LRecorder := TRecordingAntiReplay.Create;
  LAnti := LRecorder;
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  // a one-day ticket lifetime: the strike hold must not scale with it
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 86400, 16384));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity, LSecret, 86400, 16384));

  LClient := NewClient(LCache, True);
  LServer := BuildServer(nil, LStore, 0, 86400, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461'); // "0RTT early data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the 0-RTT resumption succeeded');
  CheckEqualBytes('the early data was delivered', LEarly, ReadAllEarly(LServer));
  CheckEquals(1, LRecorder.Calls, 'the binder was recorded once');
  CheckEquals(ExpectedHoldMillis, Int64(LRecorder.LastExpiry - LRecorder.LastNow),
    'the strike is held for twice the freshness skew, not the ticket lifetime');
end;

procedure TTestTls13Resumption.TestEarlyDataOffByDefault;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly, LWire: TBytes;
  LTypes: TArray<UInt16>;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // the issued ticket authorizes 0-RTT, but the client does not enable it
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);

  LClient := NewClient(LCache, False); // early data NOT enabled, even though allowed
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('6e6f742073656e74'); // "not sent"
  LClient.StartHandshake;
  CheckEquals(0, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'no early epoch: nothing is written');
  LWire := Drain(LClient);
  LTypes := OfferedTypes(LWire);
  CheckTrue(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.PreSharedKey),
    'the ticket is offered, so the server could accept early data');
  CheckFalse(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.EarlyData),
    'the ClientHello does not offer early data');
  Feed(LServer, LWire);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resumption completed without any early data');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the ticket was resumed');
  CheckEquals(0, LServer.PendingEarlyData, 'the server holds no early data');
  CheckEquals(0, System.Length(ReadAllEarly(LServer)),
    'no early data was delivered when 0-RTT was not enabled');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestMutualAuthResumptionCompletes;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LClientCred: TTlsCredential;
  LClientRoot: TBytes;
  LServerInfo, LClientInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;

  function BuildMtlsClient: ITlsEngine;
  var
    LP: TClientHandshakeParams;
  begin
    LP := Default(TClientHandshakeParams);
    LP.Clock := TSystemClock.Create;
    LP.Crypto := Crypto;
    LP.Inspector := Pkix.Certificates;
    LP.Group := TNamedGroups.CreateX25519(Crypto);
    LP.GroupCode := TNamedGroupCatalog.X25519;
    LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LP.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LP.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
    LP.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    LP.LegacySessionId := Filled($33, 32);
    LP.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
      TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
    LP.ExpectedServerName := TServerName.DnsName(ServerHost);
    LP.ServerName := ServerHost;
    LP.SessionCache := LCache;
    LP.ClientCredential := LClientCred; // present a dual-EKU (clientAuth) leaf as the client certificate
    Result := TTlsEngine.CreateConfigured(
      TTls13ClientStateMachine.Create(LP) as IHandshakeMachine, Crypto);
  end;

  function BuildMtlsStekServer(AIssue: Int32; AWithCredential: Boolean): ITlsEngine;
  var
    LP: TServerHandshakeParams;
  begin
    LP := Default(TServerHandshakeParams);
    LP.Clock := TSystemClock.Create;
    LP.Crypto := Crypto;
    LP.Inspector := Pkix.Certificates;
    LP.Policy := TNegotiationPolicy.CreateDefault(Crypto);
    LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LP.Group := TNamedGroups.CreateX25519(Crypto);
    LP.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    if AWithCredential then
      LP.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
    LP.SessionTicketKeys := LStek;
    LP.IssueTicketCount := AIssue;
    LP.TicketLifetimeSeconds := 7200;
    // mutual TLS: require and verify the client certificate against the root
    LP.ClientAuth := TClientAuthMode.Required;
    LP.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256);
    LP.ClientCertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(LClientRoot))
      as ITrustAnchorStore, False) as IClientCertificateVerifier;
    Result := TTlsEngine.CreateConfigured(
      TTls13ServerStateMachine.Create(LP) as IHandshakeMachine, Crypto);
  end;

begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  // the client presents a dual-EKU (clientAuth) leaf; the server trusts its dedicated root
  LClientCred := ClientAuthCredential(LClientRoot);

  // a full mutual-TLS handshake: the server verifies the client certificate and issues a ticket
  LClient := BuildMtlsClient;
  LServer := BuildMtlsStekServer(1, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the full mutual-TLS handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the ticket');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256, LServer.ConnectionInfo.PeerSignatureScheme,
    'the server verified the client''s CertificateVerify under ecdsa_secp256r1_sha256');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256, LClient.ConnectionInfo.PeerSignatureScheme,
    'the client verified the server''s CertificateVerify under ecdsa_secp256r1_sha256');
  CheckEquals(1, System.Length(LClient.ConnectionInfo.RequestedSignatureSchemes),
    'the client reports the signature_algorithms of the CertificateRequest');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256,
    LClient.ConnectionInfo.RequestedSignatureSchemes[0], 'the one the server listed');

  // resume: client authentication is NOT re-done on a PSK resumption, so the server must not
  // wait for a client Certificate (regression: it used to park in WaitClientCertificate and
  // abort with unexpected_message when the client's Finished arrived). A credential-less
  // server proves completion came from the accepted PSK.
  LClient := BuildMtlsClient;
  LServer := BuildMtlsStekServer(0, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the mutual-TLS resumption completed');
  CheckFalse(LServer.IsTerminal, 'no failure resuming a mutual-TLS session');
  LServerInfo := LServer.ConnectionInfo;
  CheckTrue(LServerInfo.Resumed, 'the mutual-TLS session resumed (not a full handshake)');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256, LServerInfo.PeerSignatureScheme,
    'the resumed server reports the client scheme its ticket carried');
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256,
    LClient.ConnectionInfo.PeerSignatureScheme,
    'the resumed client reports the server scheme its cached session carried');
  // the ticket carried the verified client chain, so the resumed connection surfaces it even
  // though a resumed handshake sends no Certificate (byte-equal to what was presented, which also
  // proves the server accepts its own enlarged ticket back on the wire)
  CheckEquals(System.Length(LClientCred.CertificateChain),
    System.Length(LServerInfo.PeerCertificates),
    'the resumed connection surfaces the client chain the ticket carried');
  CheckEqualBytes('the surfaced client leaf matches the one presented at full handshake',
    LClientCred.CertificateChain[0], LServerInfo.PeerCertificates[0]);
  // no client re-verification runs on the resume, so the server validated no path here
  CheckEquals(0, System.Length(LServerInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the server');
  // the resuming client twin: the stored server chain surfaces as the presented chain, and with no
  // re-verification the client validates no path either
  LServerCred := ServerCredential;
  LClientInfo := LClient.ConnectionInfo;
  CheckEquals(1, System.Length(LClientInfo.PeerCertificates),
    'the resumed client surfaces the stored leaf-only server chain');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LClientInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LClientInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestMutualAuthRequiredDeclinesForeignTicket;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LClientCred: TTlsCredential;
  LClientRoot: TBytes;
  LServerInfo: TTlsConnectionInfo;

  function BuildMtlsClient: ITlsEngine;
  var
    LP: TClientHandshakeParams;
  begin
    LP := Default(TClientHandshakeParams);
    LP.Clock := TSystemClock.Create;
    LP.Crypto := Crypto;
    LP.Inspector := Pkix.Certificates;
    LP.Group := TNamedGroups.CreateX25519(Crypto);
    LP.GroupCode := TNamedGroupCatalog.X25519;
    LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LP.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LP.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
    LP.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    LP.LegacySessionId := Filled($33, 32);
    LP.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
      TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
    LP.ExpectedServerName := TServerName.DnsName(ServerHost);
    LP.ServerName := ServerHost;
    LP.SessionCache := LCache;
    LP.ClientCredential := LClientCred;
    Result := TTlsEngine.CreateConfigured(
      TTls13ClientStateMachine.Create(LP) as IHandshakeMachine, Crypto);
  end;

  // one STEK shared by two server configs; AClientAuth lets the issuer run without client auth
  // and the resumer require it - the operator-shared-STEK cross-config case
  function BuildStekServer(AIssue: Int32; AClientAuth: TClientAuthMode): ITlsEngine;
  var
    LP: TServerHandshakeParams;
  begin
    LP := Default(TServerHandshakeParams);
    LP.Clock := TSystemClock.Create;
    LP.Crypto := Crypto;
    LP.Inspector := Pkix.Certificates;
    LP.Policy := TNegotiationPolicy.CreateDefault(Crypto);
    LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LP.Group := TNamedGroups.CreateX25519(Crypto);
    LP.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    LP.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
    LP.SessionTicketKeys := LStek;
    LP.IssueTicketCount := AIssue;
    LP.TicketLifetimeSeconds := 7200;
    LP.ClientAuth := AClientAuth;
    if AClientAuth <> TClientAuthMode.None then
    begin
      LP.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
        TSignatureSchemes.EcdsaSecp256r1Sha256);
      LP.ClientCertificateVerifier := TCertificateVerifier.Create(Pkix,
        TSystemClock.Create as ITlsClock,
        TTrustAnchorStore.Create(TArray<TBytes>.Create(LClientRoot))
        as ITrustAnchorStore, False) as IClientCertificateVerifier;
    end;
    Result := TTlsEngine.CreateConfigured(
      TTls13ServerStateMachine.Create(LP) as IHandshakeMachine, Crypto);
  end;

begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClientCred := ClientAuthCredential(LClientRoot);

  // a no-client-auth server issues a ticket that carries no client identity
  LClient := BuildMtlsClient;
  LServer := BuildStekServer(1, TClientAuthMode.None);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the no-auth handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the identity-less ticket');

  // a Required server sharing the STEK must NOT resume that identity-less ticket (it would skip
  // client auth): it declines the PSK and runs a full handshake that requests the certificate
  LClient := BuildMtlsClient;
  LServer := BuildStekServer(0, TClientAuthMode.Required);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the fallback full handshake completed');
  CheckFalse(LServer.IsTerminal, 'the fallback full handshake did not fail');
  LServerInfo := LServer.ConnectionInfo;
  CheckFalse(LServerInfo.Resumed, 'a Required server declined the identity-less ticket');
  // the full handshake surfaces the presented client chain (the leaf-only credential) and, apart from
  // it, the validated path the pipeline built (leaf first, with the assembled issuer)
  CheckTrue(System.Length(LServerInfo.PeerCertificates) > 0,
    'the full handshake verified and surfaced the client certificate');
  CheckEqualBytes('the surfaced leaf is the client credential leaf',
    LClientCred.CertificateChain[0], LServerInfo.PeerCertificates[0]);
  CheckTrue(System.Length(LServerInfo.ValidatedPath) >= 2,
    'the validated path assembles the issuer beyond the presented leaf');
  CheckEqualBytes('the validated path leaf is the client credential leaf',
    LClientCred.CertificateChain[0], LServerInfo.ValidatedPath[0]);
  CheckAppDataFlows(LClient, LServer);
end;

function TTestTls13Resumption.BuildMtlsClientEngine(const ACache: ISessionCache;
  const ACredential: TTlsCredential): ITlsEngine;
var
  LP: TClientHandshakeParams;
begin
  LP := Default(TClientHandshakeParams);
  LP.Clock := TSystemClock.Create;
  LP.Crypto := Crypto;
  LP.Inspector := Pkix.Certificates;
  LP.Group := TNamedGroups.CreateX25519(Crypto);
  LP.GroupCode := TNamedGroupCatalog.X25519;
  LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LP.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LP.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LP.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LP.LegacySessionId := Filled($33, 32);
  LP.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LP.ExpectedServerName := TServerName.DnsName(ServerHost);
  LP.ServerName := ServerHost;
  LP.SessionCache := ACache;
  LP.ClientCredential := ACredential;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LP) as IHandshakeMachine, Crypto);
end;

function TTestTls13Resumption.BuildMtlsServerEngine(
  const AStek: ISessionTicketKeyManager; AIssue: Int32; AClientAuth: TClientAuthMode;
  const AClientRoot, AScope: TBytes): ITlsEngine;
var
  LP: TServerHandshakeParams;
begin
  LP := Default(TServerHandshakeParams);
  LP.Clock := TSystemClock.Create;
  LP.Crypto := Crypto;
  LP.Inspector := Pkix.Certificates;
  LP.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LP.Group := TNamedGroups.CreateX25519(Crypto);
  LP.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LP.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LP.SessionTicketKeys := AStek;
  LP.ResumptionScope := AScope;
  LP.IssueTicketCount := AIssue;
  LP.TicketLifetimeSeconds := 7200;
  LP.ClientAuth := AClientAuth;
  if AClientAuth <> TClientAuthMode.None then
  begin
    LP.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256);
    LP.ClientCertificateVerifier := TCertificateVerifier.Create(Pkix,
      TSystemClock.Create as ITlsClock,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(AClientRoot))
      as ITrustAnchorStore, False) as IClientCertificateVerifier;
  end;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LP) as IHandshakeMachine, Crypto);
end;

function TTestTls13Resumption.BuildRequiredAuthPskServer(
  const AStek: ISessionTicketKeyManager; const APsks: TArray<TExternalPsk>;
  const AClientRoot: TBytes): ITlsEngine;
var
  LP: TServerHandshakeParams;
begin
  LP := Default(TServerHandshakeParams);
  LP.Clock := TSystemClock.Create;
  LP.Crypto := Crypto;
  LP.Inspector := Pkix.Certificates;
  LP.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LP.Group := TNamedGroups.CreateX25519(Crypto);
  LP.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LP.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LP.SessionTicketKeys := AStek;
  LP.IssueTicketCount := 1;
  LP.TicketLifetimeSeconds := 7200;
  LP.ClientAuth := TClientAuthMode.Required;
  LP.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LP.ClientCertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(AClientRoot))
    as ITrustAnchorStore, False) as IClientCertificateVerifier;
  LP.ExternalPsks := APsks;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LP) as IHandshakeMachine, Crypto);
end;

procedure TTestTls13Resumption.TestExternalPskTicketResumesUnderRequiredClientAuth;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LPsk: TExternalPsk;
  LPsks: TArray<TExternalPsk>;
  LClientRoot: TBytes;
begin
  // the PSK authenticated the client (RFC 9846 4.4.2), so its ticket resumes under Required
  ClientAuthCredential(LClientRoot);
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LPsk.Identity := DecodeHex('6578742d70736b');
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LPsks := TArray<TExternalPsk>.Create(LPsk);

  LClient := NewExtPskClient(LCache, LPsks, False);
  LServer := BuildRequiredAuthPskServer(LStek, LPsks, LClientRoot);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the PSK handshake completed');
  CheckEquals(1, LCache.Count, 'it issued a ticket');

  LClient := NewExtPskClient(LCache, nil, False);
  LServer := BuildRequiredAuthPskServer(LStek, LPsks, LClientRoot);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the resumption did not fail');
  CheckFalse(LServer.IsHandshaking, 'the resumption completed');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the ticket resumed under Required client auth');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestRequiredClientAuthStillDeclinesAChainlessTicketWithoutAPsk;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LPsk: TExternalPsk;
  LClientRoot: TBytes;
begin
  // a chainless, PSK-less ticket is no client auth: a Required server with a PSK still declines it
  ClientAuthCredential(LClientRoot);
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LPsk.Identity := DecodeHex('6578742d70736b');
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;

  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the unauthenticated handshake issued a ticket');

  LClient := NewClient(LCache, False);
  LServer := BuildRequiredAuthPskServer(LStek, TArray<TExternalPsk>.Create(LPsk), LClientRoot);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the chainless ticket was not resumed');
  CheckTrue(LServer.IsTerminal, 'the full handshake refused the credential-less client');
end;

procedure TTestTls13Resumption.TestResumptionScopeMismatchDeclinesTicket;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LCred: TTlsCredential;
  LClientRoot: TBytes;
  LServerInfo: TTlsConnectionInfo;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCred := ClientAuthCredential(LClientRoot);

  // an issuer under scope A mints an mTLS ticket carrying the verified client chain
  LClient := BuildMtlsClientEngine(LCache, LCred);
  LServer := BuildMtlsServerEngine(LStek, 1, TClientAuthMode.Required, LClientRoot,
    Filled($A1, 8));
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the scope-A ticket');

  // a configuration sharing the STEK but under scope B must not reuse that stored identity: the
  // ticket's scope does not match, so it is declined to a full handshake, which re-requests and
  // verifies the certificate under B's own trust
  LClient := BuildMtlsClientEngine(LCache, LCred);
  LServer := BuildMtlsServerEngine(LStek, 0, TClientAuthMode.Required, LClientRoot,
    Filled($B2, 8));
  DriveHandshake(LClient, LServer);
  LServerInfo := LServer.ConnectionInfo;
  CheckFalse(LServerInfo.Resumed, 'a different-scope configuration does not resume the ticket');
  CheckFalse(LServer.IsTerminal, 'it completes a full handshake instead');
  CheckTrue(System.Length(LServerInfo.PeerCertificates) > 0,
    'the full handshake verified the client certificate itself');
end;

procedure TTestTls13Resumption.TestResumptionSameScopeResumes;
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
  LScope := Filled($5C, 8);

  LClient := BuildMtlsClientEngine(LCache, LCred);
  LServer := BuildMtlsServerEngine(LStek, 1, TClientAuthMode.Required, LClientRoot, LScope);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the ticket');

  // the same scope reuses the stored identity as-is: the resuming server trusts a DIFFERENT client
  // root (so its verifier would reject this chain), yet it still resumes - proving the resumed chain
  // is not re-verified, only the scope is checked
  LClient := BuildMtlsClientEngine(LCache, LCred);
  LServer := BuildMtlsServerEngine(LStek, 0, TClientAuthMode.Required,
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'), LScope);
  DriveHandshake(LClient, LServer);
  LServerInfo := LServer.ConnectionInfo;
  CheckTrue(LServerInfo.Resumed, 'a same-scope configuration resumes without re-verifying the chain');
  CheckTrue(System.Length(LServerInfo.PeerCertificates) > 0,
    'and surfaces the client chain the ticket carried');
end;

procedure TTestTls13Resumption.TestMutualAuthTicketReissueCarriesChain;
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
  LScope := Filled($5C, 8);

  // full mutual-TLS handshake -> ticket #1
  LClient := BuildMtlsClientEngine(LCache, LCred);
  LServer := BuildMtlsServerEngine(LStek, 1, TClientAuthMode.Required, LClientRoot, LScope);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'ticket #1 was cached');

  // resume ticket #1 and re-issue ticket #2, which must carry the chain (and scope) forward
  LClient := BuildMtlsClientEngine(LCache, LCred);
  LServer := BuildMtlsServerEngine(LStek, 1, TClientAuthMode.Required, LClientRoot, LScope);
  DriveHandshake(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the first resumption resumed');
  CheckEquals(1, LCache.Count, 'a fresh ticket #2 was re-issued');

  // resume ticket #2: it resumes only if it carried the chain forward (else a Required server
  // declines the identity-less ticket to a full handshake)
  LClient := BuildMtlsClientEngine(LCache, LCred);
  LServer := BuildMtlsServerEngine(LStek, 0, TClientAuthMode.Required, LClientRoot, LScope);
  DriveHandshake(LClient, LServer);
  LServerInfo := LServer.ConnectionInfo;
  CheckTrue(LServerInfo.Resumed, 'the re-issued ticket carried the chain, so it resumes again');
  CheckTrue(System.Length(LServerInfo.PeerCertificates) > 0,
    'and the resumed connection surfaces the client chain');
end;

procedure TTestTls13Resumption.TestTicketIssuedUnderDifferentSniFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // the cross-host resumption guard: a ticket the server issued while serving one host must not
  // resume a connection that requests a different host (RFC 6066 3), even with a matching binder.
  // The client always requests ServerHost, so the server-stored session carries the issuing host
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));

  // control: issued under the requested host -> resumes
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200, 0));
  LStore.PutWithId(LIdentity, MakeSessionForHost(LIdentity, LSecret, 7200, ServerHost, 0));
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'a ticket issued under the requested host resumes');

  // guarded: issued under a different host -> the credentialed server ignores the PSK and runs a
  // full handshake instead of resuming under the wrong identity
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200, 0));
  LStore.PutWithId(LIdentity, MakeSessionForHost(LIdentity, LSecret, 7200, 'other.example', 0));
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the guarded handshake completed');
  CheckFalse(LServer.IsTerminal, 'the guarded handshake did not fail');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'a ticket issued under a different host does not resume');
end;

procedure TTestTls13Resumption.TestExternalPskAcceptedDoesNotSurfaceCachedResumptionChain;
var
  LStekA, LStekB: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LPsk: TExternalPsk;
  LPsks: TArray<TExternalPsk>;
  LInfo: TTlsConnectionInfo;

  function BuildPskClient: ITlsEngine;
  var
    LParams: TClientHandshakeParams;
  begin
    LParams := Default(TClientHandshakeParams);
    LParams.Clock := TSystemClock.Create;
    LParams.Crypto := Crypto;
    LParams.Inspector := Pkix.Certificates;
    LParams.Group := TNamedGroups.CreateX25519(Crypto);
    LParams.GroupCode := TNamedGroupCatalog.X25519;
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
    LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    LParams.LegacySessionId := Filled($33, 32);
    LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
      TSystemClock.Create as ITlsClock,
      TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
    LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
    LParams.ServerName := ServerHost;
    LParams.SessionCache := LCache;
    // offered alongside the cached resumption ticket: the client presents both in one ClientHello
    LParams.ExternalPsks := LPsks;
    Result := TTlsEngine.CreateConfigured(
      TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
  end;

  function BuildPskStekServer(const AStek: ISessionTicketKeyManager): ITlsEngine;
  var
    LParams: TServerHandshakeParams;
  begin
    LParams := Default(TServerHandshakeParams);
    LParams.Clock := TSystemClock.Create;
    LParams.Crypto := Crypto;
    LParams.Inspector := Pkix.Certificates;
    LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LParams.Group := TNamedGroups.CreateX25519(Crypto);
    LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    // no credential: completing without a certificate proves the peer authenticated via the PSK
    LParams.SessionTicketKeys := AStek;
    LParams.IssueTicketCount := 0;
    LParams.TicketLifetimeSeconds := 7200;
    LParams.ExternalPsks := LPsks;
    Result := TTlsEngine.CreateConfigured(
      TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
  end;

begin
  // a cache hit loads the stored server chain for a possible reverify-on-resume, but if the server
  // then accepts an external PSK (not the resumption ticket) that chain never authenticated this
  // connection and must not be surfaced on the connection info.
  LStekA := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStekB := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LPsk.Identity := DecodeHex('6578742d70736b'); // "ext-psk"
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LPsks := TArray<TExternalPsk>.Create(LPsk);

  // first connection: a full handshake to a cert-authenticating server. It authenticates by the
  // certificate, so the cached ticket carries the verified server chain.
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStekA, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial handshake completed');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the initial handshake is a full handshake');
  CheckEquals(1, LCache.Count, 'the client cached the ticket carrying the server chain');

  // second connection: the client offers BOTH the cached ticket and the external PSK. The resuming
  // server holds a DIFFERENT STEK, so it cannot open the ticket, but it shares the external PSK, so
  // it accepts that instead. The credential-less server completing proves the external PSK was
  // accepted (no certificate path available).
  LClient := BuildPskClient;
  LServer := BuildPskStekServer(LStekB);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the second handshake completed');
  CheckFalse(LClient.IsTerminal, 'the second handshake did not fail');
  CheckFalse(LServer.IsHandshaking, 'the credential-less server completed via the external PSK');
  CheckFalse(LServer.IsTerminal, 'the external-PSK server did not fail');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'an external PSK is not a resumption (RFC 9846 2.2)');
  // the accepted PSK is external, so the cached resumption chain did not authenticate this
  // connection and must not leak onto the connection info
  LInfo := LClient.ConnectionInfo;
  CheckEquals(0, System.Length(LInfo.PeerCertificates),
    'an accepted external PSK does not surface the cached resumption chain');
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'an accepted external PSK validates no path');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestExternalPskTicketResumesOnlyWhilePskIsConfigured;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LPsk, LRotated: TExternalPsk;
  LRandom: IRandom;

  function BuildPskClient(const APsks: TArray<TExternalPsk>): ITlsEngine;
  var
    LParams: TClientHandshakeParams;
  begin
    LParams := Default(TClientHandshakeParams);
    LParams.Clock := TSystemClock.Create;
    LParams.Crypto := Crypto;
    LParams.Inspector := Pkix.Certificates;
    LParams.Group := TNamedGroups.CreateX25519(Crypto);
    LParams.GroupCode := TNamedGroupCatalog.X25519;
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
    LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    LParams.LegacySessionId := Filled($33, 32);
    LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
      TSystemClock.Create as ITlsClock,
      TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
    LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
    LParams.ServerName := ServerHost;
    LParams.SessionCache := LCache;
    LParams.ExternalPsks := APsks;
    Result := TTlsEngine.CreateConfigured(
      TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
  end;

  function BuildPskServer(const APsks: TArray<TExternalPsk>): ITlsEngine;
  var
    LParams: TServerHandshakeParams;
  begin
    LParams := Default(TServerHandshakeParams);
    LParams.Clock := TSystemClock.Create;
    LParams.Crypto := Crypto;
    LParams.Inspector := Pkix.Certificates;
    LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LParams.Group := TNamedGroups.CreateX25519(Crypto);
    LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    // no credential: completing proves the peer authenticated via a PSK
    LParams.SessionTicketKeys := LStek;
    LParams.IssueTicketCount := 1;
    LParams.TicketLifetimeSeconds := 7200;
    LParams.ExternalPsks := APsks;
    Result := TTlsEngine.CreateConfigured(
      TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
  end;

  // one external-PSK handshake that leaves a ticket in the client cache
  procedure IssueTicket;
  begin
    LClient := BuildPskClient(TArray<TExternalPsk>.Create(LPsk));
    LServer := BuildPskServer(TArray<TExternalPsk>.Create(LPsk));
    DriveHandshake(LClient, LServer);
    CheckFalse(LServer.IsHandshaking, 'the external-PSK handshake completed');
  end;

begin
  LRandom := Crypto.Primitives.GetRandom;
  LStek := TStekTicketKeyManager.Create(LRandom);
  LCache := TInMemorySessionCache.Create;
  LPsk.Identity := DecodeHex('6578742d70736b'); // "ext-psk"
  LPsk.Secret := TSecretBuffer.From(LRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LRotated := LPsk;
  LRotated.Secret := TSecretBuffer.From(LRandom.GenerateBytes(32));

  // the ticket the external-PSK handshake issued resumes while that PSK is still configured
  IssueTicket;
  CheckEquals(1, LCache.Count, 'the external-PSK handshake issued a ticket');
  LClient := BuildPskClient(nil);
  LServer := BuildPskServer(TArray<TExternalPsk>.Create(LPsk));
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the ticket resumes while its PSK is configured');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'as a resumption');

  // the PSK removed: the credential-less server cannot open the ticket's session nor run a full one
  IssueTicket;
  LClient := BuildPskClient(nil);
  LServer := BuildPskServer(nil);
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'a ticket outliving its removed PSK is not accepted');

  // the secret rotated under the same identity: the old ticket's binding no longer matches
  IssueTicket;
  LClient := BuildPskClient(nil);
  LServer := BuildPskServer(TArray<TExternalPsk>.Create(LRotated));
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'a ticket made under the old secret is not accepted after rotation');
end;

procedure TTestTls13Resumption.ResumeForEarlyData(AClientEarly: Boolean;
  AFirstMaxEarly, ASecondMaxEarly: UInt32; const AAntiReplay: IAntiReplayStrategy;
  out AClient, AServer: ITlsEngine);
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  AClient := NewClient(LCache, False);
  AServer := BuildServer(LStek, nil, 1, 7200, True, AFirstMaxEarly, AAntiReplay);
  DriveHandshake(AClient, AServer);
  AClient := NewClient(LCache, AClientEarly);
  AServer := BuildServer(LStek, nil, 0, 7200, False, ASecondMaxEarly, AAntiReplay);
  LEarly := DecodeHex('30525454206561726c792064617461');
  AClient.StartHandshake;
  if AClientEarly then
    AClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(AClient, AServer);
end;

procedure TTestTls13Resumption.CheckEarlyDataReasons(AClientReason, AServerReason: TEarlyDataReason;
  const AClient, AServer: ITlsEngine);
begin
  CheckEquals(Ord(AClientReason), Ord(AClient.ConnectionInfo.EarlyDataReason),
    'the client''s early-data reason');
  CheckEquals(Ord(AServerReason), Ord(AServer.ConnectionInfo.EarlyDataReason),
    'the server''s early-data reason');
end;

procedure TTestTls13Resumption.TestEarlyDataReasonAcceptedOnBothPeers;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeForEarlyData(True, 16384, 16384, TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy, LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.Accepted, TEarlyDataReason.Accepted, LClient, LServer);
end;

procedure TTestTls13Resumption.TestEarlyDataReasonServerDisabledClientPeerDeclined;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeForEarlyData(True, 16384, 0, TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy, LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.PeerDeclined, TEarlyDataReason.Disabled, LClient,
    LServer);
end;

procedure TTestTls13Resumption.TestEarlyDataReasonClientDisabledServerPeerDeclined;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeForEarlyData(False, 16384, 16384, TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy, LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.Disabled, TEarlyDataReason.PeerDeclined, LClient,
    LServer);
end;

procedure TTestTls13Resumption.TestEarlyDataReasonNoSessionOffered;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(TInMemorySessionCache.Create as ISessionCache, True);
  LServer := BuildServer(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager, nil, 0, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  DriveHandshake(LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.NoSessionOffered, TEarlyDataReason.NoSessionOffered,
    LClient, LServer);
end;

procedure TTestTls13Resumption.TestEarlyDataReasonUnsupportedForSession;
var
  LClient, LServer: ITlsEngine;
begin
  // the first ticket authorizes no 0-RTT, so the client withholds it and the server sees why
  ResumeForEarlyData(True, 0, 16384, TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy, LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.UnsupportedForSession,
    TEarlyDataReason.UnsupportedForSession, LClient, LServer);
end;

procedure TTestTls13Resumption.TestEarlyDataReasonSessionNotResumed;
var
  LCache: ISessionCache;
  LStek: ISessionTicketKeyManager;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  DriveHandshake(LClient, LServer);
  // a server holding other ticket keys cannot open the ticket and runs a full handshake
  LClient := NewClient(LCache, True);
  LServer := BuildServer(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager, nil, 0, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.SessionNotResumed, TEarlyDataReason.SessionNotResumed,
    LClient, LServer);
end;

procedure TTestTls13Resumption.TestEarlyDataReasonReplayDetected;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeForEarlyData(True, 16384, 16384, TRejectingAntiReplay.Create as IAntiReplayStrategy, LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.PeerDeclined, TEarlyDataReason.ReplayDetected, LClient,
    LServer);
end;

procedure TTestTls13Resumption.TestEarlyDataReasonHelloRetryRequestOnBothPeers;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  LClient := NewRetryClient(LCache, False);
  LServer := NewRetryServer(LStek, 1, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  LCache.SetKxHint(TClientSessionPolicy.CacheIdentity('', ServerHost, nil), ServerHost, 0);
  LClient := NewRetryClient(LCache, True);
  LServer := NewRetryServer(LStek, 0, 16384, LAnti);
  LEarly := DecodeHex('7265706c617965642064617461');
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.HelloRetryRequest, TEarlyDataReason.HelloRetryRequest,
    LClient, LServer);
end;

procedure TTestTls13Resumption.TestHelloRetryRequestIsReportedOnBothPeers;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewRetryClient(LCache, False);
  LServer := NewRetryServer(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager, 1, 16384, TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  DriveHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.HelloRetryRequest, 'the client saw a retry');
  CheckTrue(LServer.ConnectionInfo.HelloRetryRequest, 'the server sent a retry');
end;

procedure TTestTls13Resumption.TestNoHelloRetryRequestIsReportedAsNone;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeForEarlyData(True, 16384, 16384, TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy, LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.HelloRetryRequest, 'the client saw no retry');
  CheckFalse(LServer.ConnectionInfo.HelloRetryRequest, 'the server sent no retry');
end;

procedure TTestTls13Resumption.TestEarlyDataReasonAlpnMismatchOnTheClient;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  FClientAlpn := TArray<TBytes>.Create(TAlpnProtocols.H2);
  FServerAlpn := TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11);
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  DriveHandshake(LClient, LServer);
  // the ticket's protocol is no longer one the client advertises, so it offers no 0-RTT
  FClientAlpn := TArray<TBytes>.Create(TAlpnProtocols.Http11);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckEquals(Ord(TEarlyDataReason.AlpnMismatch), Ord(LClient.ConnectionInfo.EarlyDataReason),
    'the client withholds early data for the ticket''s protocol');
  CheckEquals(Ord(TEarlyDataReason.PeerDeclined), Ord(LServer.ConnectionInfo.EarlyDataReason),
    'so the server sees none offered');
end;

procedure TTestTls13Resumption.TestEarlyDataReasonAlpnMismatchOnTheServer;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  FClientAlpn := TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11);
  FServerAlpn := TArray<TBytes>.Create(TAlpnProtocols.H2);
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  DriveHandshake(LClient, LServer);
  // the resuming server now selects another protocol than the ticket carried: it declines 0-RTT
  FServerAlpn := TArray<TBytes>.Create(TAlpnProtocols.Http11);
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384,
    TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.PeerDeclined, TEarlyDataReason.AlpnMismatch, LClient,
    LServer);
end;

procedure TTestTls13Resumption.ResumeUnderClockSkew(AClientAdvanceMs, AServerAdvanceMs: UInt64;
  out AClient, AServer: ITlsEngine);
var
  LClientClock, LServerClock: TMockClock;
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LAnti: IAntiReplayStrategy;
  LEarly: TBytes;
begin
  LClientClock := TMockClock.Create(1700000000000);
  LServerClock := TMockClock.Create(1700000000000);
  FClientClock := LClientClock;
  FServerClock := LServerClock;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LAnti := TStrikeRegisterAntiReplay.Create;
  AClient := NewClient(LCache, False);
  AServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(AClient, AServer);
  // each side's own clock ages the ticket, so a difference between the two is the skew
  LClientClock.Advance(AClientAdvanceMs);
  LServerClock.Advance(AServerAdvanceMs);
  AClient := NewClient(LCache, True);
  AServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461');
  AClient.StartHandshake;
  AClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(AClient, AServer);
end;

procedure TTestTls13Resumption.TestTicketAgeSkewIsReportedPastTheWindow;
var
  LClient, LServer: ITlsEngine;
begin
  // 101 s reported against 40 s measured
  ResumeUnderClockSkew(101000, 40000, LClient, LServer);
  CheckEquals(61, LServer.ConnectionInfo.TicketAgeSkew, 'the server reports the skew');
end;

procedure TTestTls13Resumption.TestStaleTicketAgeDeclinesEarlyData;
var
  LClient, LServer: ITlsEngine;
begin
  // a skew of +61 s is one past the 60 s freshness window
  ResumeUnderClockSkew(101000, 40000, LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.PeerDeclined, TEarlyDataReason.TicketAgeSkew, LClient,
    LServer);
end;

procedure TTestTls13Resumption.TestTicketAgeSkewIsReportedInsideTheWindow;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeUnderClockSkew(90000, 40000, LClient, LServer);
  CheckEquals(50, LServer.ConnectionInfo.TicketAgeSkew, 'the server reports the skew');
end;

procedure TTestTls13Resumption.TestTicketAgeSkewWithinTheWindowKeepsEarlyData;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeUnderClockSkew(90000, 40000, LClient, LServer);
  CheckEarlyDataReasons(TEarlyDataReason.Accepted, TEarlyDataReason.Accepted, LClient, LServer);
end;

procedure TTestTls13Resumption.TestTicketBeyondTheCacheLimitIsNotCached;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewServer(TFixedLengthTicketStore.Create(
    TSessionTicketLimits.MaxCachedTicketBytes + 1) as ISessionStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(0, LCache.Count, 'a ticket one byte over the limit is ignored');
end;

procedure TTestTls13Resumption.TestTicketAtTheCacheLimitIsCached;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewServer(TFixedLengthTicketStore.Create(
    TSessionTicketLimits.MaxCachedTicketBytes) as ISessionStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a ticket at the limit is cached');
end;

procedure TTestTls13Resumption.TestConnectionAfterAnUncachedTicketIsAFullHandshake;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LStore: ISessionStore;
  LStoreImpl: TFixedLengthTicketStore;
  LWire: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  LStoreImpl := TFixedLengthTicketStore.Create(TSessionTicketLimits.MaxCachedTicketBytes + 1);
  LStore := LStoreImpl;
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LStoreImpl.Puts, 'the server minted the over-limit ticket');
  // the store resumes nothing, so only the hello shows the over-limit ticket was not re-offered
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 7200, True);
  LClient.StartHandshake;
  LWire := Drain(LClient);
  CheckFalse(TArrayUtilities.Contains<UInt16>(OfferedTypes(LWire), TExtensionTypes.PreSharedKey),
    'the next ClientHello offers no ticket');
  Feed(LServer, LWire);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the next connection runs a full handshake');
end;

procedure TTestTls13Resumption.TestTicketAgeDeobfuscationWrapsBelowTheAgeAdd;
var
  LSkew: Int32;
  LFresh: Boolean;
begin
  // 4500 against an age_add of 2^32 - 512 is 5012 ms modulo 2^32 on every compiler, 2 s measured
  TTls13ServerStateMachine.TicketAgeVerdict(4500, $FFFFFE00, 1000, 3000, LSkew, LFresh);
  CheckEquals(3, LSkew, 'the wrapped client age is 5 s against 2 s measured');
end;

procedure TTestTls13Resumption.TestTicketAgeWrapKeepsTheEarlyDataWindowOpen;
var
  LSkew: Int32;
  LFresh: Boolean;
begin
  // 99488 against the same age_add is exactly the 100 s the server measured
  TTls13ServerStateMachine.TicketAgeVerdict(99488, $FFFFFE00, 1000, 101000, LSkew, LFresh);
  CheckTrue(LFresh, 'the wrapped client age agrees with the measured one');
end;

procedure TTestTls13Resumption.TestTicketAgeServerSideSaturatesIntoUInt32;
var
  LSkew: Int32;
  LFresh: Boolean;
begin
  TTls13ServerStateMachine.TicketAgeVerdict(0, 0, 0, UInt64(High(UInt32)) + 5000, LSkew, LFresh);
  CheckEquals(-4294967, LSkew, 'an age beyond 49 days saturates at 2^32 - 1 ms');
end;

procedure TTestTls13Resumption.TestTicketAgeServerSideNeverGoesNegative;
var
  LSkew: Int32;
  LFresh: Boolean;
begin
  TTls13ServerStateMachine.TicketAgeVerdict(0, 0, 5000, 1000, LSkew, LFresh);
  CheckEquals(0, LSkew, 'a ticket stamped in the future has age zero');
end;

procedure TTestTls13Resumption.ExternalPskHandshake(AResume: Boolean;
  out AClient, AServer: ITlsEngine; out AIdentity: TBytes);
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LPsk: TExternalPsk;
  LPsks: TArray<TExternalPsk>;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  AIdentity := DecodeHex('6578742d70736b'); // "ext-psk"
  LPsk.Identity := AIdentity;
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LPsks := TArray<TExternalPsk>.Create(LPsk);
  AClient := NewExtPskClient(LCache, LPsks, False);
  AServer := NewExtPskServer(LStek, LPsks, 1);
  DriveHandshake(AClient, AServer);
  if not AResume then
    Exit;
  CheckEquals(1, LCache.Count, 'the external-PSK handshake issued a ticket');
  AClient := NewExtPskClient(LCache, nil, False);
  AServer := NewExtPskServer(LStek, LPsks, 1);
  DriveHandshake(AClient, AServer);
end;

procedure TTestTls13Resumption.TestExternalPskIsNotAResumption;
var
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
begin
  ExternalPskHandshake(False, LClient, LServer, LIdentity);
  CheckFalse(LServer.IsHandshaking, 'the external-PSK handshake completed');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the client: an external PSK is not a resumption');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the server: an external PSK is not a resumption');
end;

procedure TTestTls13Resumption.TestExternalPskReportsItsIdentity;
var
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
begin
  ExternalPskHandshake(False, LClient, LServer, LIdentity);
  CheckEqualBytes('the client reports the external identity as configured', LIdentity,
    LClient.ConnectionInfo.PskIdentity);
  CheckEqualBytes('the server reports the external identity as configured', LIdentity,
    LServer.ConnectionInfo.PskIdentity);
end;

procedure TTestTls13Resumption.TestTicketIssuedUnderExternalPskResumes;
var
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
begin
  ExternalPskHandshake(True, LClient, LServer, LIdentity);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the client: the ticket is a resumption');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server: the ticket is a resumption');
end;

procedure TTestTls13Resumption.TestTicketIssuedUnderExternalPskKeepsReportingItsIdentity;
var
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
begin
  ExternalPskHandshake(True, LClient, LServer, LIdentity);
  CheckEqualBytes('the client keeps reporting the external identity', LIdentity,
    LClient.ConnectionInfo.PskIdentity);
  CheckEqualBytes('the server keeps reporting the external identity', LIdentity,
    LServer.ConnectionInfo.PskIdentity);
end;

procedure TTestTls13Resumption.TestExternalPskTicketResumesUnderReverify;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LPsk: TExternalPsk;
  LPsks: TArray<TExternalPsk>;
begin
  // a PSK-authenticated ticket has no chain, so a Reverify client resumes it without re-checking
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LPsk.Identity := DecodeHex('6578742d70736b');
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LPsks := TArray<TExternalPsk>.Create(LPsk);

  LClient := NewExtPskClient(LCache, LPsks, True);
  LServer := NewExtPskServer(LStek, LPsks, 1);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the external-PSK handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the ticket');

  LClient := NewExtPskClient(LCache, nil, True);
  LServer := NewExtPskServer(LStek, LPsks, 1);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the Reverify resume of a PSK ticket did not abort');
  CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'as a resumption');
  CheckEquals(0, System.Length(LClient.ConnectionInfo.PeerCertificates),
    'a PSK-authenticated ticket surfaces no chain');
end;

procedure TTestTls13Resumption.TestDeclinedTicketWithExternalPskStoresNoChain;
var
  LStekA, LStekB: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LPsk: TExternalPsk;
  LPsks: TArray<TExternalPsk>;
begin
  // a declined ticket's chain must not ride onto the external-PSK tickets that replace it
  LStekA := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStekB := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LPsk.Identity := DecodeHex('6578742d70736b');
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LPsks := TArray<TExternalPsk>.Create(LPsk);

  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStekA, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the certificate handshake cached a ticket with a chain');

  // the server cannot open that ticket (other STEK) but accepts the external PSK offered beside it
  LClient := NewExtPskClient(LCache, LPsks, False);
  LServer := NewExtPskServer(LStekB, LPsks, 1);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the external PSK was accepted');

  LClient := NewExtPskClient(LCache, nil, True);
  LServer := NewExtPskServer(LStekB, LPsks, 1);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the resume did not abort');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the new ticket resumed');
  CheckEquals(0, System.Length(LClient.ConnectionInfo.PeerCertificates),
    'the new ticket carries no chain from the declined one');
end;

procedure TTestTls13Resumption.TestResumedTicketKeepsItsChainForReverify;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a resumption of a certificate ticket re-issues one that still carries the verified chain
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the full handshake cached a ticket');

  LClient := NewExtPskClient(LCache, nil, True);
  LServer := NewStekServer(LStek, 1, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the first resume');
  CheckTrue(System.Length(LClient.ConnectionInfo.PeerCertificates) > 0,
    'the resumed session surfaces its chain');

  LClient := NewExtPskClient(LCache, nil, True);
  LServer := NewStekServer(LStek, 1, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the second resume');
  CheckTrue(System.Length(LClient.ConnectionInfo.PeerCertificates) > 0,
    'the re-issued ticket kept the chain');
end;

procedure TTestTls13Resumption.TestExternalPskSatisfiesRequiredClientAuth;
var
  LClient, LServer: ITlsEngine;
  LPsk: TExternalPsk;
  LPsks: TArray<TExternalPsk>;
  LClientRoot: TBytes;
  LServerInfo: TTlsConnectionInfo;

  function BuildPskClientNoCred: ITlsEngine;
  var
    LP: TClientHandshakeParams;
  begin
    LP := Default(TClientHandshakeParams);
    LP.Clock := TSystemClock.Create;
    LP.Crypto := Crypto;
    LP.Inspector := Pkix.Certificates;
    LP.Group := TNamedGroups.CreateX25519(Crypto);
    LP.GroupCode := TNamedGroupCatalog.X25519;
    LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LP.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LP.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
    LP.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    LP.LegacySessionId := Filled($33, 32);
    LP.CertificateVerifier := TCertificateVerifier.Create(Pkix,
      TSystemClock.Create as ITlsClock,
      TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
    LP.ExpectedServerName := TServerName.DnsName(ServerHost);
    LP.ServerName := ServerHost;
    // the client offers the external PSK and holds NO client credential: the PSK is its
    // authentication, so a conformant server must not demand a certificate it cannot present
    LP.ExternalPsks := LPsks;
    Result := TTlsEngine.CreateConfigured(
      TTls13ClientStateMachine.Create(LP) as IHandshakeMachine, Crypto);
  end;

begin
  // an accepted external PSK is itself the client's authentication: RFC 9846 4.4.2 forbids a
  // CertificateRequest in a PSK handshake, so a server configured to require a client certificate
  // must still NOT request one when it negotiates a PSK. The credential-less client completing
  // proves it.
  ClientAuthCredential(LClientRoot); // only for the server's client-CA anchor
  LPsk.Identity := DecodeHex('6578742d70736b'); // "ext-psk"
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LPsks := TArray<TExternalPsk>.Create(LPsk);

  LClient := BuildPskClientNoCred;
  LServer := BuildRequiredAuthPskServer(nil, LPsks, LClientRoot);
  DriveHandshake(LClient, LServer);

  CheckFalse(LServer.IsHandshaking, 'the PSK handshake completed');
  CheckFalse(LServer.IsTerminal, 'the server did not fail despite requiring client auth');
  CheckFalse(LClient.IsTerminal, 'the credential-less client completed via the external PSK');
  LServerInfo := LServer.ConnectionInfo;
  // the PSK was accepted and no certificate was requested, so no client certificate was presented
  CheckTrue(System.Length(LServerInfo.PskIdentity) > 0, 'the server accepted the external PSK');
  CheckEquals(0, System.Length(LServerInfo.PeerCertificates),
    'a PSK handshake requests no client certificate (RFC 9846 4.4.2)');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestExternalPskSuiteSelectionHonorsClientOrder;
var
  LHwAes: ICryptoProvider;
  LPsk: TExternalPsk;
  LPsks: TArray<TExternalPsk>;

  function BuildPskClient: ITlsEngine;
  var
    LParams: TClientHandshakeParams;
  begin
    LParams := Default(TClientHandshakeParams);
    LParams.Clock := TSystemClock.Create;
    LParams.Crypto := Crypto;
    LParams.Inspector := Pkix.Certificates;
    LParams.Group := TNamedGroups.CreateX25519(Crypto);
    LParams.GroupCode := TNamedGroupCatalog.X25519;
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    // the client's preference: a SHA-384 suite first (never usable with a SHA-256 PSK), then
    // ChaCha ahead of AES-128 - the opposite of a hardware-AES server's own order
    LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384,
      TCipherSuites13.ChaCha20Poly1305Sha256, TCipherSuites13.Aes128GcmSha256);
    LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
    LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    LParams.LegacySessionId := Filled($44, 32);
    LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
      TSystemClock.Create as ITlsClock,
      TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
    LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
    LParams.ServerName := ServerHost;
    LParams.ExternalPsks := LPsks;
    Result := TTlsEngine.CreateConfigured(
      TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
  end;

  function BuildPskServer(APreference: TServerCipherPreference): ITlsEngine;
  var
    LParams: TServerHandshakeParams;
  begin
    LParams := Default(TServerHandshakeParams);
    LParams.Clock := TSystemClock.Create;
    LParams.Crypto := Crypto;
    LParams.Inspector := Pkix.Certificates;
    // the registry order is the server's preference, so build it under the hardware-AES provider
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(LHwAes);
    LParams.Policy := TNegotiationPolicy.Create(LParams.CipherSuites,
      TNamedGroups.CreateDefaultRegistry(Crypto),
      TArray<UInt16>.Create(TNamedGroupCatalog.X25519),
      TArray<UInt16>.Create(TlsWireVersionTls13), APreference);
    LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LParams.Group := TNamedGroups.CreateX25519(Crypto);
    LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
    // no credential: completing proves the external PSK was accepted
    LParams.SessionTicketKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
    LParams.IssueTicketCount := 0;
    LParams.TicketLifetimeSeconds := 7200;
    LParams.ExternalPsks := LPsks;
    Result := TTlsEngine.CreateConfigured(
      TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
  end;

  procedure CheckNegotiated(APreference: TServerCipherPreference; AExpected: UInt16;
    const AMessage: string);
  var
    LClient, LServer: ITlsEngine;
  begin
    LClient := BuildPskClient;
    LServer := BuildPskServer(APreference);
    DriveHandshake(LClient, LServer);
    CheckFalse(LServer.IsHandshaking, AMessage + ': the credential-less server completed');
    CheckFalse(LServer.IsTerminal, AMessage + ': the handshake did not fail');
    CheckTrue(System.Length(LClient.ConnectionInfo.PskIdentity) > 0,
      AMessage + ': the client negotiated the PSK');
    CheckEquals(AExpected, LServer.ConnectionInfo.CipherSuite, AMessage);
    CheckEquals(AExpected, LClient.ConnectionInfo.CipherSuite, AMessage + ' (client view)');
    CheckAppDataFlows(LClient, LServer);
  end;

begin
  // the external-PSK suite pick goes through the same policy as the certificate path, so
  // WithCipherSuitePreference(ClientOrder) governs it too. A hardware-AES server's own order
  // is AES-128, AES-256, ChaCha; the client prefers ChaCha among the SHA-256 suites.
  LHwAes := TFixedAesProvider.Create(Crypto, True);
  LPsk.Identity := DecodeHex('6578742d70736b'); // "ext-psk"
  LPsk.Secret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LPsk.Context := nil;
  LPsk.Hash := THashAlgorithm.SHA_256;
  LPsks := TArray<TExternalPsk>.Create(LPsk);
  CheckNegotiated(TServerCipherPreference.ServerOrder, TCipherSuites13.Aes128GcmSha256,
    'server order: AES-128-GCM despite the client''s ChaCha preference');
  CheckNegotiated(TServerCipherPreference.ClientOrder, TCipherSuites13.ChaCha20Poly1305Sha256,
    'client order: the client''s first SHA-256 suite (ChaCha) wins on the PSK path');
end;

procedure TTestTls13Resumption.TestMachinesRequireAClock;
var
  LClient: TClientHandshakeParams;
  LServer: TServerHandshakeParams;
  LMachine: IHandshakeMachine;
  LClientRaised, LServerRaised: Boolean;
begin
  // the clock stamps tickets and checks their freshness, so it is a required input: a missing one
  // is a typed error at construction, not an access violation on the first resumption
  LClient := Default(TClientHandshakeParams);
  LClient.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LServer := Default(TServerHandshakeParams);
  LServer.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LClientRaised := False;
  LServerRaised := False;
  try
    LMachine := TTls13ClientStateMachine.Create(LClient) as IHandshakeMachine;
  except
    on E: EArgumentTlsLibException do
      LClientRaised := True;
  end;
  try
    LMachine := TTls13ServerStateMachine.Create(LServer) as IHandshakeMachine;
  except
    on E: EArgumentTlsLibException do
      LServerRaised := True;
  end;
  CheckTrue(LClientRaised, 'a 1.3 client without a clock is refused');
  CheckTrue(LServerRaised, 'a 1.3 server without a clock is refused');
end;

function TTestTls13Resumption.Reauthenticated(const ASession: ITls13ResumableSession;
  const ATicket: TBytes; AAuthenticatedAt: UInt64): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(ASession.CipherSuite, ASession.Hash,
    ASession.ResumptionSecret, ASession.Alpn, ASession.ServerName, ATicket,
    ASession.TicketLifetime, ASession.TicketAgeAdd, ASession.IssuedAtMillis,
    ASession.MaxEarlyData, ASession.PeerCertificates, ASession.ResumptionScope,
    ASession.PskIdentity, ASession.PskBinding, ASession.PeerSignatureScheme,
    AAuthenticatedAt) as IResumableSession;
end;

procedure TTestTls13Resumption.RenewAfterSixDays(AAdvanceServerClock: Boolean;
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
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 604800, True, 0, nil);
  DriveHandshake(LClient, LServer);
  LClientClock.Advance(SixDaysMs);
  if AAdvanceServerClock then
    LServerClock.Advance(SixDaysMs);
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 604800, True, 0, nil);
  DriveHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the second handshake resumed');
  CheckTrue(LCache.Take(ServerHost, ServerHost, StartMs + SixDaysMs, AClientSession),
    'the renewed ticket was cached');
  LStrategy := TStekTicketStrategy.Create(Crypto, LStek);
  CheckTrue(LStrategy.Open((AClientSession as ITls13ResumableSession).TicketIdentity,
    AServerSession), 'the renewed ticket opens');
end;

procedure TTestTls13Resumption.TestRenewedTicketKeepsTheAuthenticationTimeOnTheClient;
var
  LClientSession, LServerSession: IResumableSession;
begin
  RenewAfterSixDays(True, LClientSession, LServerSession);
  CheckTrue(UInt64(1700000000000) = LClientSession.AuthenticatedAtMillis,
    'the client keeps the time of the full handshake');
  CheckTrue(UInt64(1700000000000) + UInt64(6) * 86400000 = LClientSession.IssuedAtMillis,
    'while the renewed ticket is issued now');
end;

procedure TTestTls13Resumption.TestRenewedTicketKeepsTheAuthenticationTimeOnTheServer;
var
  LClientSession, LServerSession: IResumableSession;
begin
  RenewAfterSixDays(True, LClientSession, LServerSession);
  CheckTrue(UInt64(1700000000000) = LServerSession.AuthenticatedAtMillis,
    'the server seals the time of the full handshake');
end;

procedure TTestTls13Resumption.TestRenewedTicketLifetimeIsCutToTheRemainingChain;
var
  LClientSession, LServerSession: IResumableSession;
begin
  RenewAfterSixDays(True, LClientSession, LServerSession);
  // seven days from the authentication, six of them gone: one day left of the 604800 configured
  CheckEquals(86400, Integer(LServerSession.TicketLifetime),
    'the server seals only the remaining day');
end;

procedure TTestTls13Resumption.TestClientCutsTheRenewedTicketLifetimeOnItsOwnClock;
var
  LClientSession, LServerSession: IResumableSession;
begin
  // only the client's clock moved, so the server still advertises the full 604800
  RenewAfterSixDays(False, LClientSession, LServerSession);
  CheckEquals(604800, Integer(LServerSession.TicketLifetime), 'control: the server advertised all seven days');
  CheckEquals(86400, Integer(LClientSession.TicketLifetime),
    'the client caches only the remaining day');
end;

procedure TTestTls13Resumption.TestFullHandshakeTicketKeepsTheHandshakeAuthenticationTime;
const
  StartMs = UInt64(1700000000000);
  SixDaysMs = UInt64(6) * 86400000;
var
  LClientClock: TMockClock;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LHeld, LFlight: TBytes;
  LSession: IResumableSession;
  LIterations: Int32;
begin
  LClientClock := TMockClock.Create(StartMs);
  FClientClock := LClientClock;
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager, 1, 604800, True);
  LClient.StartHandshake;
  LHeld := nil;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    LFlight := Drain(LServer);
    // once the client is done, what the server sends is its post-handshake ticket: hold it back
    if LClient.IsHandshaking then
      Feed(LClient, LFlight)
    else
      LHeld := ConcatBytes(LHeld, LFlight);
    Inc(LIterations);
  end;
  CheckTrue(System.Length(LHeld) > 0, 'the ticket was held back');
  LClientClock.Advance(SixDaysMs);
  Feed(LClient, LHeld);
  CheckTrue(LCache.Take(ServerHost, ServerHost, StartMs + SixDaysMs, LSession),
    'the late ticket was cached');
  CheckTrue(StartMs = LSession.AuthenticatedAtMillis, 'authenticated when the handshake finished');
  CheckTrue(StartMs + SixDaysMs = LSession.IssuedAtMillis, 'issued when the ticket arrived');
end;

procedure TTestTls13Resumption.TestOneFailingRemovalDoesNotStopTheRest;
var
  LInner, LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LInner := TInMemorySessionCache.Create;
  LCache := TFlakyRemoveSessionCache.Create(LInner);
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom)
    as ISessionTicketKeyManager, 3, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(3, LInner.Count, 'the client cached three tickets');
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  Pump(LServer, LClient);
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(1, LInner.Count, 'only the removal that raised left its ticket behind');
end;

procedure TTestTls13Resumption.TestResumptionOnTheChainsLastMillisecondMintsNoTicket;
const
  StartMs = UInt64(1700000000000);
  SevenDaysMs = UInt64(604800) * 1000;
var
  LClientClock, LServerClock: TMockClock;
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LFirst, LStored: IResumableSession;
  L13First, L13Stored: ITls13ResumableSession;
  LHandle: TBytes;
begin
  LClientClock := TMockClock.Create(StartMs);
  LServerClock := TMockClock.Create(StartMs);
  FClientClock := LClientClock;
  FServerClock := LServerClock;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 604800, True);
  DriveHandshake(LClient, LServer);
  CheckTrue(LCache.Take(ServerHost, ServerHost, StartMs, LFirst), 'the ticket was cached');
  L13First := LFirst as ITls13ResumableSession;
  CheckTrue(LStore.Take(L13First.TicketIdentity, LStored), 'the server stored the session');
  L13Stored := LStored as ITls13ResumableSession;
  // re-seal the server's copy with a lifetime past the chain, so only the chain's own limit is left
  LHandle := LStore.Put(TTls13ResumableSession.Create(L13Stored.CipherSuite, L13Stored.Hash,
    L13Stored.ResumptionSecret, L13Stored.Alpn, L13Stored.ServerName, nil, 1209600,
    L13Stored.TicketAgeAdd, L13Stored.IssuedAtMillis, L13Stored.MaxEarlyData,
    L13Stored.PeerCertificates, L13Stored.ResumptionScope, L13Stored.PskIdentity,
    L13Stored.PskBinding, L13Stored.PeerSignatureScheme, L13Stored.AuthenticatedAtMillis)
    as IResumableSession);
  LCache.Store(ServerHost, ServerHost, Reauthenticated(L13First, LHandle, StartMs));
  LClientClock.Advance(SevenDaysMs);
  LServerClock.Advance(SevenDaysMs);
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 604800, True);
  DriveHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the seventh day still resumes');
  CheckEquals(0, LStore.Count, 'but a chain with no time left mints no ticket');
end;

procedure TTestTls13Resumption.TestFatalAlertFromABadRecordDropsTheClientsCachedTickets;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LWire: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');
  LServer.Write(DecodeHex('0102'), 0, 2);
  LWire := Drain(LServer);
  // a corrupted ciphertext byte fails the engine itself (bad_record_mac), not a peer alert
  LWire[System.Length(LWire) - 1] := LWire[System.Length(LWire) - 1] xor $01;
  Feed(LClient, LWire);
  CheckTrue(LClient.IsTerminal, 'the bad record ended the connection');
  CheckEquals(0, LCache.Count, 'the tickets are dropped on the engine''s own failure path');
end;

procedure TTestTls13Resumption.TestManyTicketsAreWithdrawnOnlyUpToTheRememberedBound;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 20, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(20, LCache.Count, 'the client cached every ticket');
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  Pump(LServer, LClient);
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  // the connection remembers its latest 16 tickets and withdraws only those
  CheckEquals(4, LCache.Count, 'the oldest tickets beyond the bound stay cached');
end;

function TTestTls13Resumption.ResumesAsFullHandshake(AServerAgeMs, AClientAgeMs: UInt64): Boolean;
var
  LStek: ISessionTicketKeyManager;
  LStrategy: ISessionTicketStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LFirst, LOpened: IResumableSession;
  L13First, L13Opened: ITls13ResumableSession;
  LNowMs: UInt64;
  LTicket: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 604800, True, 0, nil);
  DriveHandshake(LClient, LServer);
  LNowMs := (TSystemClock.Create as ITlsClock).NowUnixMillis;
  CheckTrue(LCache.Take(ServerHost, ServerHost, LNowMs, LFirst), 'the ticket was cached');
  L13First := LFirst as ITls13ResumableSession;
  LStrategy := TStekTicketStrategy.Create(Crypto, LStek);
  CheckTrue(LStrategy.Open(L13First.TicketIdentity, LOpened), 'the ticket opens');
  L13Opened := LOpened as ITls13ResumableSession;
  // the server's copy re-sealed with its own authentication age, the client's with another
  LTicket := LStrategy.Seal(Reauthenticated(L13Opened, nil, LNowMs - AServerAgeMs));
  LCache.Store(ServerHost, ServerHost, Reauthenticated(L13First, LTicket, LNowMs - AClientAgeMs));
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 604800, True, 0, nil);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the second handshake completed');
  Result := not LClient.ConnectionInfo.Resumed;
end;

procedure TTestTls13Resumption.TestServerResumesATicketInsideTheAuthenticationLimit;
begin
  CheckFalse(ResumesAsFullHandshake(86400000, 86400000),
    'a ticket authenticated a day ago resumes');
end;

procedure TTestTls13Resumption.TestServerDeclinesATicketPastTheAuthenticationLimit;
begin
  // the client still offers it (its copy is young), so only the server can refuse
  CheckTrue(ResumesAsFullHandshake(UInt64(8) * 86400000, 86400000),
    'a ticket authenticated eight days ago draws a full handshake');
end;

procedure TTestTls13Resumption.TestClientDoesNotOfferATicketPastTheAuthenticationLimit;
begin
  // the server would resume its copy (young), so only the client can withhold the offer
  CheckTrue(ResumesAsFullHandshake(86400000, UInt64(8) * 86400000),
    'a ticket authenticated eight days ago is not offered');
end;

procedure TTestTls13Resumption.TestFatalAlertDropsTheClientsCachedTickets;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  Pump(LServer, LClient);
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(0, LCache.Count, 'the tickets it cached are dropped');
end;

procedure TTestTls13Resumption.TestFatalAlertConsumesTheServersStatefulTickets;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the server stored the ticket it issued');
  LServer.SendAlert(TTlsAlertDescription.InternalError);
  CheckEquals(0, LStore.Count, 'a connection ended by a fatal alert leaves no ticket to resume');
end;

procedure TTestTls13Resumption.TestCloseNotifyKeepsTheIssuedTickets;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  LServer.SendClose;
  Pump(LServer, LClient);
  CheckTrue(LClient.IsClosed, 'the client saw the close');
  CheckEquals(1, LStore.Count, 'a clean close leaves the server ticket');
  CheckEquals(1, LCache.Count, 'and the client ticket');
end;

procedure TTestTls13Resumption.TestCloseNotifyFollowedByJunkKeepsTheIssuedTickets;
var
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LWire: TBytes;
  LCached: Int32;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  LCached := LCache.Count;
  CheckTrue(LCached > 0, 'the client cached the issued ticket before the close');
  LServer.SendClose;
  // junk after the close_notify is ignored (RFC 9846 6.1), so the tickets must survive it
  LWire := ConcatBytes(Drain(LServer), DecodeHex('ff03030001'));
  CheckFalse(LClient.ProcessInput(LWire, 0, System.Length(LWire)) = TTlsOutcome.Fatal,
    'a close_notify followed by junk in one feed is not fatal');
  CheckTrue(LClient.IsInboundClosed, 'the close_notify is observed');
  CheckFalse(LClient.IsTerminal, 'the trailing junk does not end the connection');
  CheckEquals(LCached, LCache.Count, 'the client ticket survives the junk');
end;

function TTestTls13Resumption.NewReverifyEarlyClient(const ACache: ISessionCache;
  const AResumeVerifier: IServerCertificateVerifier;
  ADeferral: TVerdictDeferral): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := ClientParams(ACache, True);
  LParams.ResumeVerification := TResumeVerification.Reverify;
  LParams.ResumeCertificateVerifier := AResumeVerifier;
  LParams.Deferral := ADeferral;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

procedure TTestTls13Resumption.CacheEarlyDataTicket(const AStek: ISessionTicketKeyManager;
  const AAnti: IAntiReplayStrategy; const ACache: ISessionCache);
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(ACache, False);
  LServer := BuildServer(AStek, nil, 1, 7200, True, 16384, AAnti);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, ACache.Count, 'a 0-RTT-capable ticket was cached');
end;

function TTestTls13Resumption.OfferedTypes(const AWire: TBytes): TArray<UInt16>;
var
  LLen: Int32;
begin
  LLen := (AWire[3] shl 8) or AWire[4];
  Result := TClientSessionPolicy.OfferedExtensionTypes(System.Copy(AWire, 5, LLen));
end;

procedure TTestTls13Resumption.TestReverifyChecksTheStoredChainOnceBeforeTheClientHello;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LCounter: TRecordingServerVerifier;
  LResumeVerifier: IServerCertificateVerifier;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LCounter := TRecordingServerVerifier.Create(ClientParams(LCache, True).CertificateVerifier);
  LResumeVerifier := LCounter;
  LClient := NewReverifyEarlyClient(LCache, LResumeVerifier, TVerdictDeferral.None);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LClient.StartHandshake;
  CheckEquals(1, LCounter.Calls,
    'the stored chain is checked once, before the ClientHello leaves and before any server byte');
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the session resumed');
  CheckEquals(1, LCounter.Calls, 'the completed handshake did not check the chain again');
end;

procedure TTestTls13Resumption.TestReverifyPassOffersTheSessionAndEarlyData;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient: ITlsEngine;
  LEarly: TBytes;
  LTypes: TArray<UInt16>;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache, nil, TVerdictDeferral.None);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  CheckEquals(System.Length(LEarly), LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'a session that passes the check opens the early-data window');
  LTypes := OfferedTypes(Drain(LClient));
  CheckTrue(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.PreSharedKey),
    'the ClientHello offers the PSK');
  CheckTrue(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.EarlyData),
    'the ClientHello offers early data');
end;

procedure TTestTls13Resumption.TestReverifyPassDeliversTheEarlyData;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache, nil, TVerdictDeferral.None);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the session resumed');
  CheckEquals(Ord(TEarlyDataReason.Accepted), Ord(LClient.ConnectionInfo.EarlyDataReason),
    'the early data was accepted');
  CheckEqualBytes('the server received the early data', LEarly, ReadAllEarly(LServer));
end;

procedure TTestTls13Resumption.TestReverifyPassKeepsTheValidatedPath;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache, nil, TVerdictDeferral.None);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the session resumed');
  CheckTrue(System.Length(LClient.ConnectionInfo.ValidatedPath) > 0,
    'the offer-time check validated a path that the resumed connection reports');
  CheckEquals(1, System.Length(LClient.ConnectionInfo.PeerCertificates),
    'the resumed connection reports the stored chain');
end;

procedure TTestTls13Resumption.TestReverifyFailureOffersNoTicketOrEarlyData;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient: ITlsEngine;
  LEarly: TBytes;
  LTypes: TArray<UInt16>;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache,
    TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate)
    as IServerCertificateVerifier, TVerdictDeferral.None);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  CheckEquals(0, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'a session that fails the check opens no early-data window');
  LTypes := OfferedTypes(Drain(LClient));
  CheckFalse(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.PreSharedKey),
    'no ticket or binder is sent for the distrusted session');
  CheckFalse(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.EarlyData),
    'no early data is offered for the distrusted session');
end;

procedure TTestTls13Resumption.TestReverifyFailureFallsBackToAFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache,
    TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate)
    as IServerCertificateVerifier, TVerdictDeferral.None);
  LServer := BuildServer(LStek, nil, 0, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the fresh chain passed the full handshake verification');
  CheckFalse(LClient.IsHandshaking, 'the client completed');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the distrusted session was not resumed');
  CheckEquals(Ord(TEarlyDataReason.UnsupportedForSession),
    Ord(LClient.ConnectionInfo.EarlyDataReason), 'no early data was offered');
  CheckEquals(0, LServer.PendingEarlyData, 'the server received no early data');
end;

procedure TTestTls13Resumption.TestReverifyRaisingVerifierFailsTheConnectionAndConsumesTheSession;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache,
    TRaisingServerVerifier.Create as IServerCertificateVerifier, TVerdictDeferral.None);
  LClient.StartHandshake;
  CheckTrue(LClient.IsTerminal, 'a verifier that raises fails the connection');
  CheckEquals(0, LCache.Count, 'the drawn session is consumed');
end;

procedure TTestTls13Resumption.TestReverifyWithAsyncVerdictOffersNoEarlyData;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly, LWire: TBytes;
  LTypes: TArray<UInt16>;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache, nil, TVerdictDeferral.HostDecision);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461');
  LClient.StartHandshake;
  CheckEquals(0, LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)),
    'no early window opens while an out-of-band verdict is owed');
  LWire := Drain(LClient);
  LTypes := OfferedTypes(LWire);
  CheckTrue(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.PreSharedKey),
    'the session itself is still offered');
  CheckFalse(TArrayUtilities.Contains<UInt16>(LTypes, TExtensionTypes.EarlyData),
    'no early data is offered');
  Feed(LServer, LWire);
  CheckTrue(PumpResolvingVerdict(LClient, LServer), 'the handshake parked for the verdict');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the handshake completed as a resumption');
  CheckEquals(Ord(TEarlyDataReason.Disabled), Ord(LClient.ConnectionInfo.EarlyDataReason),
    'early data was withheld for the owed verdict');
end;

procedure TTestTls13Resumption.TestReverifyWithAsyncVerdictStillParksAtServerFinished;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;
  CacheEarlyDataTicket(LStek, LAnti, LCache);

  LClient := NewReverifyEarlyClient(LCache, nil, TVerdictDeferral.HostDecision);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LClient.StartHandshake;
  CheckTrue(PumpResolvingVerdict(LClient, LServer),
    'the resumed handshake parked for the out-of-band verdict');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the accepted verdict completed the resumption');
end;

function TTestTls13Resumption.PumpResolvingVerdict(const AClient,
  AServer: ITlsEngine): Boolean;
var
  LIterations: Int32;
begin
  Result := False;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    if AClient.AwaitingCertificateVerdict then
    begin
      Result := True;
      AClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
    end;
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13Resumption);
{$ELSE}
  RegisterTest(TTestTls13Resumption.Suite);
{$ENDIF FPC}

end.
