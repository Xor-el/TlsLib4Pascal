{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13LoopbackTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpIHandshakeMachine,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpServerName,
  TlpCertificateVerifier,
  TlpTrustPolicy,
  TlpSecretBuffer,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpITlsCredentialResolver,
  TlpITlsServerCredentialSet,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpExtensionVector,
  TlpEchConfig,
  TlpEchClient,
  TlpInMemoryEchKeyStore,
  TlpIEch,
  TlpEchServer,
  TlpISession,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpAntiReplay,
  TlpIKeyLog,
  MockKeyLog,
  TlsLibHandshakeTestBase,
  TlsLibTestCertificates,
  TlsLibTestHandshakeDecoder;

type
  TTestTls13Loopback = class(TTlsLibHandshakeTestCase)
  private
    // opt-in NSS key-log sinks: nil by default (helpers skip injection); a test sets them to
    // observe which ClientHello random the exported secrets are keyed by
    FClientKeyLog, FServerKeyLog: TMockKeyLog;
    function MakeEntry(const AHost: string;
      const ACredential: TTlsCredential): TSniCredentialEntry;
    function NewClient: ITlsEngine;
    function NewClientForSni(const ASni, AExpectedHost: string): ITlsEngine;
    function NewClientEd448: ITlsEngine;
    function NewServerEd448: ITlsEngine;
    function NewClientEd25519: ITlsEngine;
    function NewServerEd25519: ITlsEngine;
    function NewServer: ITlsEngine;
    function NewServerWithResolver(
      const AResolver: ITlsServerCredentialResolver): ITlsEngine;
    function BuildEchConfigList(AConfigId: Byte; const APublicName: string;
      out APrivateKey: ISecretBuffer): TBytes;
    function NewEchClientWith(const AConfigList: TBytes;
      const ACache: ISessionCache): ITlsEngine;
    function NewEchAcceptServer(const AConfigList: TBytes;
      const APrivateKey: ISecretBuffer; const AStore: ISessionStore;
      AIssueTickets: Int32): ITlsEngine;
    function NewEchServer: ITlsEngine;
    function NewEchHrrClient(const ACache: ISessionCache): ITlsEngine;
    /// <summary>The ECH server; AVerbatimCookie, when given, replaces the cookie its retry sends.</summary>
    function NewEchHrrServer(const AStore: ISessionStore;
      AIssueTickets: Int32; const AVerbatimCookie: TBytes): ITlsEngine;
    /// <summary>Runs the ECH client through one retry whose cookie has ACookieLength bytes (the
    /// server accepts ECH, or with ARejected rejects it); whether the client aborted.</summary>
    function EchRetryClientAborts(ACookieLength: Int32; ARejected: Boolean;
      out AClient, AServer: ITlsEngine): Boolean;
    /// <summary>The largest cookie the ECH retry echoes without aborting (bisected).</summary>
    function LargestEchRetryCookie(ARejected: Boolean): Int32;
    /// <summary>Checks that a retry with a cookie of ACookieLength bytes aborts with the client's
    /// own internal_error.</summary>
    procedure CheckRetryAbortsWithTheClientsOwnError(ACookieLength: Int32; ARejected: Boolean);
    function NewEchHrrRejectClient(const AConfigList: TBytes): ITlsEngine;
    /// <summary>The ECH-rejecting server; AVerbatimCookie, when given, replaces its retry cookie.</summary>
    function NewEchHrrRejectServer(const AConfigList: TBytes;
      const APrivateKey: ISecretBuffer; const AVerbatimCookie: TBytes): ITlsEngine;
    function NewEchResumeClient(const ACache: ISessionCache;
      AEarlyData: Boolean): ITlsEngine;
    function NewEchResumeServer(const AStore: ISessionStore; AIssueTickets: Int32;
      AMaxEarlyData: UInt32;
      const AAntiReplay: IAntiReplayStrategy): ITlsEngine;
    function NewEchRejectServer(const AConfigList: TBytes;
      const APrivateKey: ISecretBuffer): ITlsEngine;
    function NewHrrClient: ITlsEngine;
    function NewHrrServer: ITlsEngine;
    function NewHrrServerWithPolicy(const APolicy: INegotiationPolicy): ITlsEngine;
    function NewP256OnlyClient: ITlsEngine;
    function NewMultiGroupServer: ITlsEngine;
    function NewHybridClient: ITlsEngine;
    function NewHybridServer: ITlsEngine;
    function NewHybridHrrClient: ITlsEngine;
    function NewHybridHrrServer: ITlsEngine;
    function CountHelloRetryRequests(const AWire: TBytes): Int32;
    function DriveCountingHrr(const AClient, AServer: ITlsEngine): Int32;
    function NewStaplingServer(const AStaple: TBytes): ITlsEngine;
    function NewHardRevocationClient: ITlsEngine;
    // the pre_shared_key extension data (identities + binders) from the outer ClientHello in a
    // record-framed client flight, skipping any leading ChangeCipherSpec; nil when there is none
    function OuterPskExtData(const AFlight: TBytes): TBytes;
  published
    procedure TestEchAcceptLoopback;
    procedure TestEchAcceptKeyLogIsKeyedByInnerRandom;
    procedure TestEchHrrAcceptLoopback;
    procedure TestEchCookieBeyondTheOuterWrapperAbortsWithTheCookieError;
    procedure TestEchRejectedRetryCookieBeyondTheOuterAbortsWithTheCookieError;
    procedure TestEchRejectedRetryCookieBeyondTheOuterVectorAbortsWithTheCookieError;
    procedure TestEchRejectedRetryCookieAtTheLargestRoomContinuesTheRetry;
    procedure TestEchCookieAtTheLargestRoomIsReadByOurReader;
    procedure TestEchRejectHrrLoopback;
    procedure TestEchResumeHrrLoopback;
    procedure TestEchGreasePskBindersDifferAcrossHrr;
    procedure TestEchResumptionLoopback;
    procedure TestEchZeroRttLoopback;
    procedure TestEchResumeThenRejectLoopback;
    procedure TestEchRejectLoopback;
    procedure TestClientServerLoopbackReachesApplicationData;
    procedure TestServerHalfRttWriteIsAccepted;
    procedure TestWriteUnderHandshakeKeysIsRefused;
    procedure TestZeroLengthWriteEmitsNothing;
    procedure TestFatalLevelUserCanceledIsTerminal;
    procedure TestApplicationRecordsQueueNoEvents;
    procedure TestHelloRetryRequestRoundTrip;
    procedure TestHybridDirectHandshakeNegotiates4588;
    procedure TestHybridHrrHandshakeNegotiates4588;
    procedure TestMultiGroupServerSelectsClientGroupWithoutHrr;
    procedure TestCoalescedCrossEpochFlightCompletes;
    procedure TestAppDataAcrossRecordsChunkedReads;
    procedure TestResolverReturningEmptyChainFailsHandshake;
    procedure TestServerHelloPackedWithNextMessageIsExcessData;
    procedure TestSecondClientHelloDroppingTls13IsProtocolVersion;
    procedure TestUnexpectedMessageAbortsWithUnexpectedMessage;
    procedure TestMiddleboxChangeCipherSpec;
    procedure TestWriteAfterInboundCloseNotifyHalfCloses;
    procedure TestErrorAfterOurCloseNotifyQueuesNoAlert;
    procedure TestCoalescedFinalDataAndCloseNotifyBothSurface;
    procedure TestCloseNotifyFollowedByJunkIsACleanClose;
    procedure TestFatalAlertFollowedByJunkSurfacesThePeerAlert;
    procedure TestStapledGoodOcspCompletesUnderHardPosture;
    procedure TestMissingStapleAbortsUnderHardPosture;
    procedure TestSniSelectsHostCredentialAmongMany;
    procedure TestUnknownSniWithoutDefaultAbortsUnrecognizedName;
    procedure TestSniResolverMatchingMatrix;
    procedure TestSniResolverSupportsCredentialSet;
    procedure TestCredentialSetListsDefaultThenEntriesInOrder;
    procedure TestCredentialSetWithoutDefaultListsEntriesOnly;
    procedure TestCredentialSetListsEveryCredentialWithoutDeduplication;
    procedure TestCredentialSetIsAFreshArray;
    procedure TestCredentialSetChainsAreCopies;
    procedure TestCredentialSetOfASingleCredentialListsOne;
    procedure TestEd448ServerCredentialHandshake;
    procedure TestEd25519ServerCredentialHandshake;
  end;

implementation

{ TTestTls13Loopback }

function TTestTls13Loopback.MakeEntry(const AHost: string;
  const ACredential: TTlsCredential): TSniCredentialEntry;
begin
  Result.Host := AHost;
  Result.Credential := ACredential;
end;

function TTestTls13Loopback.NewClient: ITlsEngine;
begin
  // no SNI on the wire; the leaf is name-checked against localhost
  Result := NewClientForSni('', 'localhost');
end;

function TTestTls13Loopback.NewClientForSni(const ASni,
  AExpectedHost: string): ITlsEngine;
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
  // offering a single suite makes the server's choice unambiguous on any CPU
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  // ServerName is the SNI sent on the wire; ExpectedHostName is the name the leaf is checked against
  LParams.ServerName := ASni;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName(AExpectedHost);

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewClientEd448: ITlsEngine;
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
  // offer only ed448 so the server must sign its CertificateVerify with the Ed448 credential
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.Ed448);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/Ed448Chain.txt', 'root_cert')))
    as ITrustAnchorStore, True) as IServerCertificateVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewServerEd448: ITlsEngine;
begin
  Result := NewServerWithResolver(
    TSniCredentialResolver.ForCredential(ServerCredentialEd448));
end;

function TTestTls13Loopback.NewClientEd25519: ITlsEngine;
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
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.Ed25519);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/Ed25519Chain.txt', 'root_cert')))
    as ITrustAnchorStore, True) as IServerCertificateVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewServerEd25519: ITlsEngine;
begin
  Result := NewServerWithResolver(
    TSniCredentialResolver.ForCredential(ServerCredentialEd25519));
end;

function TTestTls13Loopback.NewServer: ITlsEngine;
begin
  Result := NewServerWithResolver(TSniCredentialResolver.ForCredential(ServerCredential));
end;

function TTestTls13Loopback.NewServerWithResolver(
  const AResolver: ITlsServerCredentialResolver): ITlsEngine;
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
  LParams.ServerRandom := Filled($22, 32);
  // the machine serializes EncryptedExtensions itself; the Certificate +
  // CertificateVerify are produced and signed from the credential the resolver picks by SNI
  LParams.CredentialResolver := AResolver;

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.BuildEchConfigList(AConfigId: Byte;
  const APublicName: string; out APrivateKey: ISecretBuffer): TBytes;
var
  LPublicKey: TBytes;
  LConfig: TEchConfig;
  LSuite: TEchCipherSuite;
begin
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey,
    APrivateKey);
  LSuite.KdfId := THpkeKdf.HKDF_SHA256;
  LSuite.AeadId := THpkeAead.AES_128_GCM;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, AConfigId,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey,
    TArray<TEchCipherSuite>.Create(LSuite), 0,
    TEncoding.ASCII.GetBytes(APublicName), nil);
  Result := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));
end;

function TTestTls13Loopback.NewEchClientWith(const AConfigList: TBytes;
  const ACache: ISessionCache): ITlsEngine;
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
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  // the true (inner) SNI; the leaf is checked against it once ECH is accepted
  LParams.ServerName := 'localhost';
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.EchPolicy := TEchClientPolicy.Create(Crypto, AConfigList, False, False)
    as IEchClientPolicy;
  LParams.SessionCache := ACache;
  if FClientKeyLog <> nil then
    LParams.KeyLog := FClientKeyLog as IKeyLog;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewEchAcceptServer(const AConfigList: TBytes;
  const APrivateKey: ISecretBuffer; const AStore: ISessionStore;
  AIssueTickets: Int32): ITlsEngine;
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
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver :=
    TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.EchPolicy := TEchServerPolicy.Keyed(Crypto,
    TInMemoryEchKeyStore.FromConfig(AConfigList, APrivateKey, Crypto), False);
  LParams.SessionStore := AStore;
  LParams.IssueTicketCount := AIssueTickets;
  LParams.TicketLifetimeSeconds := 7200;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewEchServer: ITlsEngine;
var
  LParams: TServerHandshakeParams;
  LVec: TStringList;
  LSk: ISecretBuffer;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver :=
    TSniCredentialResolver.ForCredential(ServerCredential);
  LVec := LoadVectorFields('Certs/Ech.txt');
  try
    LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
      DecodeHex(LVec.Values['config_private_key']));
  finally
    LVec.Free;
  end;
  LParams.EchPolicy := TEchServerPolicy.Keyed(Crypto,
    TInMemoryEchKeyStore.FromConfig(
      TTlsLibTestCertificates.Field('Certs/Ech.txt', 'config_list'), LSk, Crypto), False);
  if FServerKeyLog <> nil then
    LParams.KeyLog := FServerKeyLog as IKeyLog;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewEchRejectServer(const AConfigList: TBytes;
  const APrivateKey: ISecretBuffer): ITlsEngine;
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
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  // an is_retry config the store advertises as retry_configs; its config_id differs from the
  // client's offer, so trial-decrypt finds no match and the server rejects ECH
  LParams.EchPolicy := TEchServerPolicy.Keyed(Crypto,
    TInMemoryEchKeyStore.FromConfig(AConfigList, APrivateKey, Crypto), False);
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewEchHrrClient(
  const ACache: ISessionCache): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.SessionCache := ACache;
  // key-shares X25519 but advertises secp256r1 too, so the ECH-capable secp256r1-only
  // server retries the client onto secp256r1 (a HelloRetryRequest under ECH)
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.ServerName := 'localhost';
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.EchPolicy := TEchClientPolicy.Create(Crypto,
    TTlsLibTestCertificates.Field('Certs/Ech.txt', 'config_list'), False, False)
    as IEchClientPolicy;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewEchHrrServer(const AStore: ISessionStore;
  AIssueTickets: Int32; const AVerbatimCookie: TBytes): ITlsEngine;
var
  LParams: TServerHandshakeParams;
  LVec: TStringList;
  LSk: ISecretBuffer;
  LMachine: IHandshakeMachine;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // offers only secp256r1; a client that key-shared another group is retried
  LParams.Group := TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1');
  LParams.ServerRandom := Filled($22, 32);
  LParams.CookieSecret := TSecretBuffer.From(
    Crypto.Primitives.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver :=
    TSniCredentialResolver.ForCredential(ServerCredential);
  LVec := LoadVectorFields('Certs/Ech.txt');
  try
    LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
      DecodeHex(LVec.Values['config_private_key']));
  finally
    LVec.Free;
  end;
  LParams.EchPolicy := TEchServerPolicy.Keyed(Crypto,
    TInMemoryEchKeyStore.FromConfig(
      TTlsLibTestCertificates.Field('Certs/Ech.txt', 'config_list'), LSk, Crypto), False);
  LParams.SessionStore := AStore;
  LParams.IssueTicketCount := AIssueTickets;
  LParams.TicketLifetimeSeconds := 7200;
  LMachine := TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine;
  if System.Length(AVerbatimCookie) > 0 then
    (LMachine as ITls13ServerReplay).SetVerbatimRetryCookie(AVerbatimCookie);
  Result := TTlsEngine.CreateConfigured(LMachine, Crypto);
end;

function TTestTls13Loopback.NewEchHrrRejectClient(
  const AConfigList: TBytes): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  // key-shares X25519 but advertises secp256r1 too, so a secp256r1-only server retries it
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.ServerName := 'localhost';
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.EchPolicy := TEchClientPolicy.Create(Crypto, AConfigList, False, False)
    as IEchClientPolicy;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewEchHrrRejectServer(const AConfigList: TBytes;
  const APrivateKey: ISecretBuffer; const AVerbatimCookie: TBytes): ITlsEngine;
var
  LParams: TServerHandshakeParams;
  LMachine: IHandshakeMachine;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // offers only secp256r1, so an X25519 key_share is retried; holds a mismatched ECH config, so
  // trial-decrypt fails and ECH is rejected - the reject and the HelloRetryRequest coincide
  LParams.Group := TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1');
  LParams.ServerRandom := Filled($22, 32);
  LParams.CookieSecret := TSecretBuffer.From(
    Crypto.Primitives.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.EchPolicy := TEchServerPolicy.Keyed(Crypto,
    TInMemoryEchKeyStore.FromConfig(AConfigList, APrivateKey, Crypto), False);
  LMachine := TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine;
  if System.Length(AVerbatimCookie) > 0 then
    (LMachine as ITls13ServerReplay).SetVerbatimRetryCookie(AVerbatimCookie);
  Result := TTlsEngine.CreateConfigured(LMachine, Crypto);
end;

function TTestTls13Loopback.NewEchResumeClient(
  const ACache: ISessionCache; AEarlyData: Boolean): ITlsEngine;
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
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.ServerName := 'localhost';
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.EchPolicy := TEchClientPolicy.Create(Crypto,
    TTlsLibTestCertificates.Field('Certs/Ech.txt', 'config_list'), False, False)
    as IEchClientPolicy;
  LParams.SessionCache := ACache;
  LParams.EarlyDataEnabled := AEarlyData;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewEchResumeServer(const AStore: ISessionStore;
  AIssueTickets: Int32; AMaxEarlyData: UInt32;
  const AAntiReplay: IAntiReplayStrategy): ITlsEngine;
var
  LParams: TServerHandshakeParams;
  LVec: TStringList;
  LSk: ISecretBuffer;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver :=
    TSniCredentialResolver.ForCredential(ServerCredential);
  LVec := LoadVectorFields('Certs/Ech.txt');
  try
    LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
      DecodeHex(LVec.Values['config_private_key']));
  finally
    LVec.Free;
  end;
  LParams.EchPolicy := TEchServerPolicy.Keyed(Crypto,
    TInMemoryEchKeyStore.FromConfig(
      TTlsLibTestCertificates.Field('Certs/Ech.txt', 'config_list'), LSk, Crypto), False);
  LParams.SessionStore := AStore;
  LParams.IssueTicketCount := AIssueTickets;
  LParams.TicketLifetimeSeconds := 7200;
  LParams.MaxEarlyData := AMaxEarlyData;
  LParams.AntiReplay := AAntiReplay;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

procedure TTestTls13Loopback.TestEchHrrAcceptLoopback;
var
  LClient, LServer: ITlsEngine;
  LMsg: TBytes;
begin
  // ECH + HelloRetryRequest: the server accepts ECH on CH1, retries the client onto secp256r1,
  // re-opens the inner CH2 at HPKE seq=1, and completes. Completion proves the ECH-HRR accept
  // path end to end (a broken HRR confirmation or seq handling would diverge/abort).
  LClient := NewEchHrrClient(nil);
  LServer := NewEchHrrServer(nil, 0, nil);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the ECH-HRR client did not fail');
  CheckFalse(LServer.IsTerminal, 'the ECH-HRR server did not fail');
  CheckFalse(LClient.IsHandshaking, 'the ECH-HRR client completed');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'ECH accepted across the HRR');
  LMsg := DecodeHex('6563682d687272'); // "ech-hrr"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('app data flows over the ECH-HRR connection', LMsg,
    ReadAllApp(LServer));
end;

function TTestTls13Loopback.EchRetryClientAborts(ACookieLength: Int32; ARejected: Boolean;
  out AClient, AServer: ITlsEngine): Boolean;
var
  LCookie, LClientConfig, LServerConfig: TBytes;
  LClientKey, LServerKey: ISecretBuffer;
begin
  System.SetLength(LCookie, ACookieLength);
  if ARejected then
  begin
    // the server holds a config the client did not offer, so it rejects ECH and retries
    LClientConfig := BuildEchConfigList($AA, 'localhost', LClientKey);
    LServerConfig := BuildEchConfigList($BB, 'localhost', LServerKey);
    AClient := NewEchHrrRejectClient(LClientConfig);
    AServer := NewEchHrrRejectServer(LServerConfig, LServerKey, LCookie);
  end
  else
  begin
    AClient := NewEchHrrClient(nil);
    AServer := NewEchHrrServer(nil, 0, LCookie);
  end;
  AClient.StartHandshake;
  Pump(AClient, AServer);
  Pump(AServer, AClient);
  Result := AClient.IsTerminal;
end;

function TTestTls13Loopback.LargestEchRetryCookie(ARejected: Boolean): Int32;
var
  LClient, LServer: ITlsEngine;
  LLow, LHigh, LMid: Int32;
begin
  // below the result the ECH client completes the retry, above it the outer wrapper overflows
  LLow := 1;
  LHigh := 65400;
  // the bisection never evaluates its own ends, so check them here
  CheckFalse(EchRetryClientAborts(LLow, ARejected, LClient, LServer),
    'a one-byte cookie fits, so the lower end of the search is real');
  CheckTrue(EchRetryClientAborts(LHigh, ARejected, LClient, LServer),
    'an oversize cookie aborts, so the upper end of the search is real');
  while LLow < LHigh do
  begin
    LMid := (LLow + LHigh) div 2;
    if EchRetryClientAborts(LMid, ARejected, LClient, LServer) then
      LHigh := LMid
    else
      LLow := LMid + 1;
  end;
  Result := LLow - 1;
end;

procedure TTestTls13Loopback.CheckRetryAbortsWithTheClientsOwnError(ACookieLength: Int32;
  ARejected: Boolean);
var
  LClient, LServer: ITlsEngine;
begin
  CheckTrue(EchRetryClientAborts(ACookieLength, ARejected, LClient, LServer),
    'the cookie no longer fits, so the retry aborts');
  CheckTrue(LClient.LastError.Alert.Description = TTlsAlertDescription.InternalError,
    'with internal_error');
  // the client's own reason reaches LastError; the encoder would carry its vector-length text
  CheckEquals('the HelloRetryRequest cookie is too large to echo in the second ClientHello',
    LClient.LastError.Message,
    'raised by the client, not the wire writer');
end;

procedure TTestTls13Loopback.TestEchCookieBeyondTheOuterWrapperAbortsWithTheCookieError;
begin
  CheckRetryAbortsWithTheClientsOwnError(LargestEchRetryCookie(False) + 1, False);
end;

procedure TTestTls13Loopback.TestEchRejectedRetryCookieBeyondTheOuterAbortsWithTheCookieError;
begin
  CheckRetryAbortsWithTheClientsOwnError(LargestEchRetryCookie(True) + 1, True);
end;

procedure TTestTls13Loopback.TestEchRejectedRetryCookieBeyondTheOuterVectorAbortsWithTheCookieError;
begin
  // the rejected retry's outer repeats CH1's ech extension, so a cookie 150 bytes past its room
  // still fits the inner yet overflows the outer's extensions vector, not just the body cap
  CheckRetryAbortsWithTheClientsOwnError(LargestEchRetryCookie(True) + 150, True);
end;

procedure TTestTls13Loopback.TestEchRejectedRetryCookieAtTheLargestRoomContinuesTheRetry;
var
  LClient, LServer: ITlsEngine;
begin
  CheckFalse(EchRetryClientAborts(LargestEchRetryCookie(True), True, LClient, LServer),
    'the rejected-ECH retry is sent');
end;

procedure TTestTls13Loopback.TestEchCookieAtTheLargestRoomIsReadByOurReader;
var
  LClient, LServer: ITlsEngine;
  LWire, LHandshake: TBytes;
  LReader: THandshakeMessageReader;
  LMessage: TTlsHandshakeMessage;
  LPos, LLength: Int32;
begin
  CheckFalse(EchRetryClientAborts(LargestEchRetryCookie(False), False, LClient, LServer),
    'the retry is sent');
  // the retry's plaintext handshake records, joined into the message a reader would see
  LWire := Drain(LClient);
  LHandshake := nil;
  LPos := 0;
  while LPos + 5 <= System.Length(LWire) do
  begin
    LLength := (LWire[LPos + 3] shl 8) or LWire[LPos + 4];
    if LWire[LPos] = 22 then
      LHandshake := ConcatBytes(LHandshake, System.Copy(LWire, LPos + 5, LLength));
    System.Inc(LPos, 5 + LLength);
  end;
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LHandshake, 0, System.Length(LHandshake));
    CheckTrue(LReader.NextMessage(LMessage), 'our own reader accepts the largest outer hello');
    CheckTrue(THandshakeMessages.DecodeClientHello(LMessage.Body).Extensions <> nil, 'and decodes it');
  finally
    LReader.Free;
  end;
end;

procedure TTestTls13Loopback.TestEchRejectHrrLoopback;
var
  LClient, LServer: ITlsEngine;
  LConfigClient, LConfigServer: TBytes;
  LSkClient, LSkServer: ISecretBuffer;
begin
  // ECH reject coincident with a HelloRetryRequest: the server holds a mismatched config (so it
  // rejects ECH) and offers only secp256r1 (so it retries the X25519 key_share). The client must
  // send a second ClientHelloOuter whose ech extension is a verbatim copy of the first's (RFC
  // 9849 sec. 6.2.1 by analogy) rather than a plaintext ClientHello - then complete to
  // public_name and abort with ech_required. A malformed or SNI-leaking CH2 would break the
  // outer handshake here.
  LConfigClient := BuildEchConfigList($AA, 'localhost', LSkClient);
  LConfigServer := BuildEchConfigList($BB, 'localhost', LSkServer);
  LClient := NewEchHrrRejectClient(LConfigClient);
  LServer := NewEchHrrRejectServer(LConfigServer, LSkServer, nil);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Rejected,
    'the client saw an ECH reject across the HRR');
  CheckTrue(LClient.LastError.Alert.Description = TTlsAlertDescription.EchRequired,
    'the client aborted with ech_required after completing to public_name');
end;

procedure TTestTls13Loopback.TestEchResumeHrrLoopback;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LClientInfo, LServerInfo: TTlsConnectionInfo;
begin
  // PSK resumption + ECH + HelloRetryRequest together: the resuming client carries the real
  // pre_shared_key on the inner ClientHello, the server retries it onto secp256r1, and the inner
  // CH2's binder must MAC the inner transcript (message_hash(innerCH1), inner HRR, inner CH2).
  // A binder computed over the outer transcript would fail the server's inner binder check.
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  // first ECH connection (itself retried onto secp256r1) issues one resumption ticket
  LClient := NewEchHrrClient(LCache);
  LServer := NewEchHrrServer(LStore, 1, nil);
  RunHandshake(LClient, LServer);
  LClientInfo := LClient.ConnectionInfo;
  CheckTrue(LClientInfo.EchStatus = TEchStatus.Accepted, 'ECH accepted on the first HRR handshake');
  CheckFalse(LClientInfo.Resumed, 'the first handshake is not resumed');
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');

  // second ECH connection: resumes (real inner PSK, GREASE outer PSK) and is retried again, so
  // the inner CH2 binder is recomputed over the rebased inner transcript
  LClient := NewEchHrrClient(LCache);
  LServer := NewEchHrrServer(LStore, 0, nil);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the resuming ECH-HRR client did not fail');
  CheckFalse(LServer.IsTerminal, 'the resuming ECH-HRR server did not fail');
  LClientInfo := LClient.ConnectionInfo;
  LServerInfo := LServer.ConnectionInfo;
  CheckTrue(LClientInfo.EchStatus = TEchStatus.Accepted,
    'ECH accepted on the resumed HRR handshake');
  CheckTrue(LClientInfo.Resumed, 'the ECH client resumed across the HRR via the inner PSK');
  CheckTrue(LServerInfo.Resumed, 'the ECH server resumed across the HRR');
end;

function TTestTls13Loopback.OuterPskExtData(const AFlight: TBytes): TBytes;
var
  LVec: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  Result := nil;
  LVec := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(AFlight);
  if LVec.TryFind(TExtensionTypes.PreSharedKey, LEntry) then
    Result := LEntry.Data;
end;

procedure TTestTls13Loopback.TestEchGreasePskBindersDifferAcrossHrr;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdLen1, LIdLen2, LI: Int32;
  LCh1, LCh2, LPsk1, LPsk2, LIds1, LIds2, LBind1, LBind2: TBytes;
  LSameBinders: Boolean;
begin
  // resume + ECH + HRR: the resuming client carries a GREASE pre_shared_key on the outer, retried
  // across an HRR. CH2 must keep CH1's PSK identities AND obfuscated ticket ages verbatim (a real
  // offer's age moves only by the retry round-trip) while regenerating the binders, as a real
  // resumption CH2 does - a fresh age or a verbatim binder would fingerprint the decoy (RFC 9849
  // sec. 10.10.4, RFC 9846 4.2.2/4.3.11.1)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  // first ECH+HRR handshake issues a resumption ticket
  LClient := NewEchHrrClient(LCache);
  LServer := NewEchHrrServer(LStore, 1, nil);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the first handshake cached a ticket');

  // second handshake: capture CH1 outer, deliver the HRR, capture CH2 outer
  LClient := NewEchHrrClient(LCache);
  LServer := NewEchHrrServer(LStore, 0, nil);
  LClient.StartHandshake;
  LCh1 := Drain(LClient);        // ClientHelloOuter #1 (GREASE outer pre_shared_key)
  Feed(LServer, LCh1);
  Pump(LServer, LClient);        // deliver the HelloRetryRequest
  LCh2 := Drain(LClient);        // ClientHelloOuter #2 (retry, possibly led by a CCS record)

  LPsk1 := OuterPskExtData(LCh1);
  LPsk2 := OuterPskExtData(LCh2);
  CheckTrue(System.Length(LPsk1) > 2, 'CH1 carries a GREASE pre_shared_key');
  CheckTrue(System.Length(LPsk2) > 2, 'CH2 carries a GREASE pre_shared_key');

  // OfferedPsks = PskIdentity list<2> then binders<2>; the identities section (identity + age per
  // offer) is byte-identical across the HRR, and the binders (at the same offset) must differ
  LIdLen1 := (LPsk1[0] shl 8) or LPsk1[1];
  LIdLen2 := (LPsk2[0] shl 8) or LPsk2[1];
  LIds1 := System.Copy(LPsk1, 0, 2 + LIdLen1);
  LIds2 := System.Copy(LPsk2, 0, 2 + LIdLen2);
  CheckEqualBytes('GREASE PSK identities and ages are stable across the HRR', LIds1, LIds2);
  LBind1 := System.Copy(LPsk1, 2 + LIdLen1, System.Length(LPsk1));
  LBind2 := System.Copy(LPsk2, 2 + LIdLen1, System.Length(LPsk2));
  CheckTrue(System.Length(LBind1) > 0, 'there is a binder section');
  LSameBinders := System.Length(LBind1) = System.Length(LBind2);
  if LSameBinders then
    for LI := 0 to System.High(LBind1) do
      if LBind1[LI] <> LBind2[LI] then
      begin
        LSameBinders := False;
        Break;
      end;
  CheckFalse(LSameBinders,
    'GREASE PSK binders are regenerated on the retry ClientHello');
end;

procedure TTestTls13Loopback.TestEchResumptionLoopback;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LClientInfo, LServerInfo: TTlsConnectionInfo;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  // first ECH connection: a full accept that issues one resumption ticket
  LClient := NewEchResumeClient(LCache, False);
  LServer := NewEchResumeServer(LStore, 1, 0, nil);
  RunHandshake(LClient, LServer);
  LClientInfo := LClient.ConnectionInfo;
  CheckTrue(LClientInfo.EchStatus = TEchStatus.Accepted, 'ECH accepted on the first handshake');
  CheckFalse(LClientInfo.Resumed, 'the first handshake is not resumed');
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');

  // second ECH connection: the real PSK rides the inner ClientHello (a GREASE PSK the
  // outer), the server accepts ECH and resumes over the reconstructed inner
  LClient := NewEchResumeClient(LCache, False);
  LServer := NewEchResumeServer(LStore, 0, 0, nil);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the resuming ECH client did not fail');
  CheckFalse(LServer.IsTerminal, 'the resuming ECH server did not fail');
  LClientInfo := LClient.ConnectionInfo;
  LServerInfo := LServer.ConnectionInfo;
  CheckTrue(LClientInfo.EchStatus = TEchStatus.Accepted, 'ECH accepted on the resumed handshake');
  CheckTrue(LClientInfo.Resumed, 'the ECH client resumed via the inner pre_shared_key');
  CheckTrue(LServerInfo.Resumed, 'the ECH server resumed');
end;

procedure TTestTls13Loopback.TestEchResumeThenRejectLoopback;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LConfigA, LConfigB: TBytes;
  LSkA, LSkB: ISecretBuffer;
begin
  // a resuming client offers a GREASE pre_shared_key on the ClientHelloOuter; when the server
  // rejects ECH it must ignore that decoy (it cannot validate the random identity) and complete
  // to the public_name, then the client aborts with ech_required (RFC 9849 sec. 6.1.2 / 6.1.6).
  LConfigA := BuildEchConfigList($AA, 'localhost', LSkA);
  LConfigB := BuildEchConfigList($BB, 'localhost', LSkB);
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  // first: accept config_A and issue a ticket the client caches
  LClient := NewEchClientWith(LConfigA, LCache);
  LServer := NewEchAcceptServer(LConfigA, LSkA, LStore, 1);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the ticket was cached for the resume');

  // second: the resuming client's outer carries a GREASE PSK, but the server holds config_B
  // and rejects; the GREASE PSK must not derail the reject
  LClient := NewEchClientWith(LConfigA, LCache);
  LServer := NewEchRejectServer(LConfigB, LSkB);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Rejected,
    'the resuming client saw an ECH reject (the outer GREASE PSK was ignored)');
  CheckTrue(LClient.LastError.Alert.Description = TTlsAlertDescription.EchRequired,
    'the resuming client aborted with ech_required');
end;

procedure TTestTls13Loopback.TestEchZeroRttLoopback;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LAnti: IAntiReplayStrategy;
  LClient, LServer: ITlsEngine;
  LClientInfo: TTlsConnectionInfo;
  LEarly: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;

  // first ECH connection: a full accept issuing a 0-RTT-capable ticket
  LClient := NewEchResumeClient(LCache, False);
  LServer := NewEchResumeServer(LStore, 1, 16384, LAnti);
  RunHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a 0-RTT-capable ticket was cached over ECH');

  // second ECH connection: send 0-RTT early data. The early keys derive from the inner
  // transcript (RFC 9849 sec. 6.1 / 6.1.5); the server accepts ECH and decrypts the early data.
  LClient := NewEchResumeClient(LCache, True);
  LServer := NewEchResumeServer(LStore, 0, 16384, LAnti);
  LEarly := DecodeHex('6563682d30727474'); // "ech-0rtt"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  ExchangeFlights(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the 0-RTT ECH client did not fail');
  CheckFalse(LServer.IsTerminal, 'the 0-RTT ECH server did not fail');
  LClientInfo := LClient.ConnectionInfo;
  CheckTrue(LClientInfo.EchStatus = TEchStatus.Accepted, 'ECH accepted on the 0-RTT handshake');
  CheckTrue(LClientInfo.Resumed, 'the 0-RTT ECH client resumed');
  CheckEqualBytes('the server received the early data as 0-RTT over ECH', LEarly,
    ReadAllEarly(LServer));
end;

procedure TTestTls13Loopback.TestEchAcceptLoopback;
var
  LClient, LServer: ITlsEngine;
  LMsg: TBytes;
begin
  LClient := NewEchClientWith(
    TTlsLibTestCertificates.Field('Certs/Ech.txt', 'config_list'), nil);
  LServer := NewEchServer;
  RunHandshake(LClient, LServer);
  // completion proves ECH was accepted end to end: the server certificate matches only
  // the inner SNI (localhost), never the public_name, so a reject would abort on the
  // certificate check, and a broken accept confirmation would diverge the transcripts
  CheckFalse(LClient.IsHandshaking, 'the client completed the ECH handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the ECH handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'the client surfaced ECH Accepted');
  CheckTrue(LServer.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'the server surfaced ECH Accepted');
  LMsg := DecodeHex('6563682d6f6b'); // "ech-ok"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts app data over the ECH connection', LMsg,
    ReadAllApp(LServer));
end;

procedure TTestTls13Loopback.TestEchAcceptKeyLogIsKeyedByInnerRandom;
var
  LClient, LServer: ITlsEngine;
  LClientLog, LServerLog: IKeyLog;
  LI: Int32;
  LInner: TBytes;
begin
  // on ECH accept the exported secrets must be logged under the INNER ClientHello random, not the
  // outer public-name random the wire carries ($11), so a key-log consumer can decrypt the true
  // (inner) session rather than the decoy. The interface locals own the sinks, so a build that
  // raises before an engine takes them still frees them; the fields are only cleared here.
  FClientKeyLog := TMockKeyLog.Create;
  LClientLog := FClientKeyLog;
  FServerKeyLog := TMockKeyLog.Create;
  LServerLog := FServerKeyLog;
  try
    LClient := NewEchClientWith(
      TTlsLibTestCertificates.Field('Certs/Ech.txt', 'config_list'), nil);
    LServer := NewEchServer;
    RunHandshake(LClient, LServer);
    CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'ECH was accepted');
    CheckTrue(FClientKeyLog.Count > 0, 'the client logged key material');
    CheckTrue(FServerKeyLog.Count > 0, 'the server logged key material');
    LInner := FClientKeyLog.Entries[0].ClientRandom;
    CheckFalse(AreEqual(LInner, Filled($11, 32)),
      'the key log is not keyed by the outer public-name random');
    for LI := 0 to FClientKeyLog.Count - 1 do
      CheckEqualBytes('every client key-log entry is keyed by the inner random',
        LInner, FClientKeyLog.Entries[LI].ClientRandom);
    for LI := 0 to FServerKeyLog.Count - 1 do
      CheckEqualBytes('the server logs under the same inner random',
        LInner, FServerKeyLog.Entries[LI].ClientRandom);
  finally
    FClientKeyLog := nil;
    FServerKeyLog := nil;
  end;
end;

procedure TTestTls13Loopback.TestEchRejectLoopback;
var
  LClient, LServer: ITlsEngine;
  LClientList, LServerList: TBytes;
  LClientSk, LServerSk: ISecretBuffer;
  LClientInfo: TTlsConnectionInfo;
  LReturnedRetry: TBytes;
begin
  // the client offers config_id $AA (public_name localhost); the server's store holds a
  // different config ($BB, is_retry), so no config_id matches and it rejects ECH, advertising
  // its retry_configs. The client authenticates the localhost leaf against the public_name,
  // completes its flight, then aborts with ech_required and surfaces the retry_configs
  // (RFC 9849 sec. 6.1.6) - never a plaintext fall-back.
  LClientList := BuildEchConfigList($AA, 'localhost', LClientSk);
  LServerList := BuildEchConfigList($BB, 'localhost', LServerSk);
  LClient := NewEchClientWith(LClientList, nil);
  LServer := NewEchRejectServer(LServerList, LServerSk);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the client aborted the rejected ECH handshake');
  LClientInfo := LClient.ConnectionInfo;
  CheckTrue(LClientInfo.EchStatus = TEchStatus.Rejected, 'the client recorded an ECH reject');
  CheckTrue(LClient.LastError.Alert.Description = TTlsAlertDescription.EchRequired,
    'the client aborted with ech_required');
  CheckEqualBytes('the client surfaced the server retry_configs', LServerList,
    LClientInfo.EchRetryConfigs);
  CheckFalse(LClientInfo.EchIsRetryAttempt, 'this handshake was not itself a retry');
  // the getter hands back a defensive copy: mutating the returned retry_configs must not reach
  // the engine's held bytes, so a re-read still yields the server's list unchanged
  LReturnedRetry := LClient.ConnectionInfo.EchRetryConfigs;
  if System.Length(LReturnedRetry) > 0 then
    LReturnedRetry[0] := LReturnedRetry[0] xor $FF;
  CheckEqualBytes('mutating the returned retry_configs does not change a re-read', LServerList,
    LClient.ConnectionInfo.EchRetryConfigs);
end;

function TTestTls13Loopback.NewStaplingServer(const AStaple: TBytes): ITlsEngine;
var
  LParams: TServerHandshakeParams;
  LCred: TTlsCredential;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  // the leaf's issuer travels in the chain so the client can authenticate the staple
  LCred := Default(TTlsCredential);
  LCred.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'issuer_cert'));
  LCred.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_key'), nil);
  LCred.OcspStaple := AStaple;
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(LCred);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewHardRevocationClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
  LOptions: TCertificateVerifierOptions;
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
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  // hard-fail revocation: the leaf must come with a current Good stapled OCSP response, so
  // the client offers status_request to solicit the staple
  LParams.RequestOcspStapling := True;
  LOptions.RevocationPosture := TRevocationPosture.Hard;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'root_cert')))
    as ITrustAnchorStore, True, LOptions) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewHrrClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  // key-shares X25519 but advertises secp256r1 too, so the secp256r1-only server
  // retries the client onto secp256r1
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewHrrServer: ITlsEngine;
begin
  Result := NewHrrServerWithPolicy(TNegotiationPolicy.CreateDefault(Crypto));
end;

function TTestTls13Loopback.NewHrrServerWithPolicy(
  const APolicy: INegotiationPolicy): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := APolicy;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // the server offers only secp256r1; a client that key-shared another group is retried
  LParams.Group := TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1');
  LParams.ServerRandom := Filled($22, 32);
  LParams.CookieSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewP256OnlyClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  // a client that key-shares secp256r1 and lists ONLY secp256r1 (like a JDK 11 client that
  // omits X25519); the server must select secp256r1 rather than insisting on X25519
  LParams.Group := TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1');
  LParams.GroupCode := TNamedGroupCatalog.Secp256r1;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewMultiGroupServer: ITlsEngine;
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
  // the negotiation policy prefers X25519 (and PQ hybrids) ahead of secp256r1; a client that omits
  // them and offers only secp256r1 (mandatory to implement, RFC 9846 9.1) still negotiates it,
  // without a HelloRetryRequest, because it sent that key_share
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  // a cookie secret lets it answer with a HelloRetryRequest if it ever needed to (it must not)
  LParams.CookieSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewHybridClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  // key-share the X25519MLKEM768 hybrid directly: a large (X25519 32 + ML-KEM
  // encaps-key 1184 = 1216 B) key_share, ML-KEM-first on the wire
  LParams.Group := TNamedGroups.CreateX25519MlKem768(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519MlKem768;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewHybridServer: ITlsEngine;
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
  LParams.Group := TNamedGroups.CreateX25519MlKem768(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewHybridHrrClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  // offers [X25519, X25519MLKEM768] but key-shares the classical X25519 first, so a
  // hybrid-only server retries the client onto X25519MLKEM768 (the Compatible-preset path)
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.X25519MlKem768);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.NewHybridHrrServer: ITlsEngine;
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
  // the server offers only the hybrid; a client that key-shared a classical group is retried
  LParams.Group := TNamedGroups.CreateX25519MlKem768(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CookieSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls13Loopback.CountHelloRetryRequests(const AWire: TBytes): Int32;
var
  LI, LJ, LN: Int32;
  LMatch: Boolean;
begin
  // a HelloRetryRequest is a ServerHello whose random is the fixed HRR sentinel
  // (RFC 9846 4.2.3); the 32-byte sentinel is unique enough to scan for directly
  Result := 0;
  LN := System.Length(HelloRetryRequestSentinel);
  LI := 0;
  while LI <= System.Length(AWire) - LN do
  begin
    LMatch := True;
    for LJ := 0 to LN - 1 do
      if AWire[LI + LJ] <> HelloRetryRequestSentinel[LJ] then
      begin
        LMatch := False;
        Break;
      end;
    if LMatch then
    begin
      Inc(Result);
      Inc(LI, LN);
    end
    else
      Inc(LI);
  end;
end;

function TTestTls13Loopback.DriveCountingHrr(const AClient, AServer: ITlsEngine): Int32;
var
  LIterations: Int32;
  LFromServer: TBytes;
begin
  // drive the handshake to completion, counting the HelloRetryRequests the server emits
  Result := 0;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(AClient, AServer);
    LFromServer := Drain(AServer);
    Inc(Result, CountHelloRetryRequests(LFromServer));
    Feed(AClient, LFromServer);
    Inc(LIterations);
  end;
end;

procedure TTestTls13Loopback.TestMultiGroupServerSelectsClientGroupWithoutHrr;
var
  LClient, LServer: ITlsEngine;
  LHrr: Int32;
  LFromClient: TBytes;
begin
  LClient := NewP256OnlyClient;
  LServer := NewMultiGroupServer;

  LClient.StartHandshake;

  // the client key-shared secp256r1 (its only group); the server, though it prefers X25519,
  // selects secp256r1 because the client offered it - and, since the client already sent that
  // key_share, without a HelloRetryRequest
  LHrr := DriveCountingHrr(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail (secp256r1 was negotiated)');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(0, LHrr, 'the server sent no HelloRetryRequest');
  CheckEquals(Integer(TNamedGroupCatalog.Secp256r1), Integer(LClient.ConnectionInfo.NamedGroup),
    'the client''s own group was negotiated');

  LFromClient := DecodeHex('68656c6c6f206f766572207032353620776974686f75742061206872720a');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts application data over the secp256r1 keys',
    LFromClient, ReadAllApp(LServer));
end;

procedure TTestTls13Loopback.TestClientServerLoopbackReachesApplicationData;
var
  LClient, LServer: ITlsEngine;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;

  LClient.StartHandshake; // emits the ClientHello (and the middlebox CCS)
  ExchangeFlights(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');

  // the negotiated application keys carry real data in both directions
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74'); // "hello from the client"
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts the client application data', LFromClient,
    ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572'); // "hello from the server"
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts the server application data', LFromServer,
    ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestServerHalfRttWriteIsAccepted;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LHalfRtt: TBytes;
begin
  // a TLS 1.3 server may write application data from its own Finished onward, before it has
  // received the client Finished (half-RTT, RFC 9846 2 / 4.5.3). This guards the one legitimate
  // path the application-write-epoch gate must not refuse.
  LClient := NewClient;
  LServer := NewServer;
  LClient.StartHandshake;
  // deliver the ClientHello: the server emits ServerHello..Finished and installs its application
  // write epoch, while it still awaits the client Finished
  Pump(LClient, LServer);
  CheckTrue(LServer.IsHandshaking, 'the server has not yet received the client Finished');
  LHalfRtt := DecodeHex('302e352d525454206461746100'); // "0.5-RTT data\0"
  // the write is accepted (queued behind the handshake flight), not refused
  LServer.Write(LHalfRtt, 0, System.Length(LHalfRtt));
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LServer, LClient);
    Pump(LClient, LServer);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the handshake');
  CheckEqualBytes('the client reads the server half-RTT data', LHalfRtt,
    ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestWriteUnderHandshakeKeysIsRefused;
var
  LClient, LServer: ITlsEngine;
  LServerFlight, LData: TBytes;
  LFirstLen: Int32;
  LRaised: Boolean;
begin
  // after the ServerHello the client holds the handshake write epoch, not the application one;
  // a Write must be refused so application data is never sealed under handshake keys (RFC 9846 2)
  LClient := NewClient;
  LServer := NewServer;
  LClient.StartHandshake;
  Pump(LClient, LServer); // ClientHello -> server; the server queues its whole flight
  LServerFlight := Drain(LServer);
  CheckTrue(System.Length(LServerFlight) > 5, 'the server produced a flight');
  // feed only the first record (the plaintext ServerHello): it installs the handshake epoch
  LFirstLen := (LServerFlight[3] shl 8) or LServerFlight[4];
  LClient.ProcessInput(LServerFlight, 0, 5 + LFirstLen);
  CheckTrue(LClient.IsHandshaking, 'the client still awaits the rest of the server flight');
  LData := DecodeHex('6e6f7065'); // "nope"
  LRaised := False;
  try
    LClient.Write(LData, 0, System.Length(LData));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a write on the handshake epoch is refused');
  // feed the rest of the flight; the client completes and the same write now succeeds
  Feed(LClient, System.Copy(LServerFlight, 5 + LFirstLen,
    System.Length(LServerFlight) - (5 + LFirstLen)));
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  Pump(LClient, LServer); // client Finished -> server
  LClient.Write(LData, 0, System.Length(LData));
  Pump(LClient, LServer);
  CheckEqualBytes('the client application data now reaches the server', LData,
    ReadAllApp(LServer));
end;

procedure TTestTls13Loopback.TestZeroLengthWriteEmitsNothing;
var
  LClient, LServer: ITlsEngine;
begin
  // after completion a zero-length application write is a no-op: it must not put an empty
  // application_data record on the wire (library policy; RFC 9846 5.1 / 5.4 allow zero-length data)
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  Drain(LClient); // clear any residual outbound first
  LClient.Write(nil, 0, 0);
  CheckFalse(LClient.WantsWrite, 'a zero-length write queues nothing');
  CheckEquals(0, System.Length(Drain(LClient)), 'no record reached the wire');
end;

procedure TTestTls13Loopback.TestFatalLevelUserCanceledIsTerminal;
var
  LClient, LServer: ITlsEngine;
begin
  // the public SendAlert is fatal-level, so the peer must close (RFC 9846 6.2)
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  LServer.SendAlert(TTlsAlertDescription.UserCanceled);
  Pump(LServer, LClient);
  CheckTrue(LClient.IsTerminal, 'a fatal-level user_canceled ends the connection');
  CheckEquals(Ord(TTlsErrorOrigin.Peer), Ord(LClient.LastError.Origin),
    'the peer ended it');
  CheckEquals(Ord(TTlsAlertDescription.UserCanceled), Ord(LClient.LastError.Alert.Description),
    'with user_canceled');
end;

procedure TTestTls13Loopback.TestApplicationRecordsQueueNoEvents;
var
  LClient, LServer: ITlsEngine;
  LEvent: ITlsEvent;
  LI: Int32;
  LFromClient: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking, 'the handshake completed');
  while LServer.NextEvent(LEvent) do ; // clear the handshake-phase events
  // application data is signalled by PendingAppData, not by an event per record: a stream of
  // records must leave the event queue empty
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  for LI := 1 to 3 do
    LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEquals(3 * System.Length(LFromClient), LServer.PendingAppData,
    'the three records are buffered for the caller');
  CheckFalse(LServer.NextEvent(LEvent), 'application records queue no events');
end;

procedure TTestTls13Loopback.TestHelloRetryRequestRoundTrip;
var
  LClient, LServer: ITlsEngine;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewHrrClient;
  LServer := NewHrrServer;

  // the server answers ClientHello1 with a HelloRetryRequest (the client key-shared
  // X25519 but the server offers only secp256r1); the client retries onto secp256r1,
  // the server rebuilds the transcript from the cookie, and the handshake completes
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed after the retry');
  CheckFalse(LServer.IsHandshaking, 'the server completed after the retry');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');

  // real application data flows both ways over the negotiated secp256r1 keys
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data after a retry',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data after a retry',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestHybridDirectHandshakeNegotiates4588;
var
  LClient, LServer: ITlsEngine;
  LHrr: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewHybridClient;
  LServer := NewHybridServer;

  LClient.StartHandshake;
  // both sides offer only the hybrid and the client key-shared it, so the server
  // selects X25519MLKEM768 in one round trip with no HelloRetryRequest
  LHrr := DriveCountingHrr(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed the hybrid handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the hybrid handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(0, LHrr, 'a direct hybrid handshake needs no HelloRetryRequest');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LClient.ConnectionInfo.NamedGroup), 'the client negotiated X25519MLKEM768');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LServer.ConnectionInfo.NamedGroup), 'the server negotiated X25519MLKEM768');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data over the hybrid keys',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data over the hybrid keys',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestHybridHrrHandshakeNegotiates4588;
var
  LClient, LServer: ITlsEngine;
  LHrr: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewHybridHrrClient;
  LServer := NewHybridHrrServer;

  LClient.StartHandshake;
  // the client key-shared X25519 but offered the hybrid too; the hybrid-only server sends
  // one HelloRetryRequest for 4588, the client resends with the hybrid key_share
  LHrr := DriveCountingHrr(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed after the retry');
  CheckFalse(LServer.IsHandshaking, 'the server completed after the retry');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(1, LHrr, 'exactly one HelloRetryRequest drove the client onto the hybrid');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LClient.ConnectionInfo.NamedGroup), 'the client negotiated X25519MLKEM768 after the retry');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LServer.ConnectionInfo.NamedGroup), 'the server negotiated X25519MLKEM768 after the retry');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data after the hybrid retry',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data after the hybrid retry',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestCoalescedCrossEpochFlightCompletes;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;

  LClient.StartHandshake;

  // every flight is delivered coalesced (one ProcessInput per drain). The server's
  // first flight carries a plaintext ServerHello then the encrypted
  // EncryptedExtensions..Finished in one buffer; completing proves the read epoch
  // installed while handling ServerHello governs the records that follow it
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    PumpCoalesced(LClient, LServer);
    PumpCoalesced(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, 'the client completed the coalesced handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the coalesced handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail on the coalesced flight');
  CheckFalse(LServer.IsTerminal, 'the server did not fail on the coalesced flight');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  PumpCoalesced(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data after a coalesced handshake',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  PumpCoalesced(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data after a coalesced handshake',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestAppDataAcrossRecordsChunkedReads;
var
  LClient, LServer: ITlsEngine;
  LGot: Int32;
  LMsg1, LMsg2, LMsg3, LExpected, LGotAll, LOne: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking, 'the handshake completed');

  // three separate writes arrive as three application-data records => three queue
  // chunks on the server; reading one byte at a time must cross the chunk boundaries
  // and reassemble every record in order
  LMsg1 := DecodeHex('0102030405');
  LMsg2 := DecodeHex('060708');
  LMsg3 := DecodeHex('090a0b0c0d0e0f');
  LClient.Write(LMsg1, 0, System.Length(LMsg1));
  LClient.Write(LMsg2, 0, System.Length(LMsg2));
  LClient.Write(LMsg3, 0, System.Length(LMsg3));
  Pump(LClient, LServer);

  LExpected := ConcatBytes(ConcatBytes(LMsg1, LMsg2), LMsg3);
  LGotAll := nil;
  SetLength(LOne, 1);
  repeat
    LGot := LServer.ReadAppData(LOne, 0, 1);
    if LGot > 0 then
      LGotAll := ConcatBytes(LGotAll, System.Copy(LOne, 0, LGot));
  until LGot = 0;

  CheckEqualBytes('one-byte reads reassemble all records in order', LExpected, LGotAll);
end;

procedure TTestTls13Loopback.TestServerHelloPackedWithNextMessageIsExcessData;
var
  LClient, LServer: ITlsEngine;
  LFlight, LMerged: TBytes;
  LOutcome: TTlsOutcome;
begin
  LClient := NewClient;
  LServer := NewServer;
  LClient.StartHandshake;
  Pump(LClient, LServer);
  LFlight := Drain(LServer);
  // the plaintext ServerHello record also carries an EncryptedExtensions: a handshake message
  // must not follow a key change in the same record (RFC 9846 5.1)
  LMerged := FirstRecordWith(LFlight, DecodeHex('08 00 00 02 00 00'));
  LOutcome := LClient.ProcessInput(LMerged, 0, System.Length(LMerged));
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LOutcome), 'a message packed behind the ServerHello is fatal');
  CheckTrue(LClient.LastError.Alert.Description = TTlsAlertDescription.UnexpectedMessage,
    'it aborts with unexpected_message');
end;

procedure TTestTls13Loopback.TestSecondClientHelloDroppingTls13IsProtocolVersion;
var
  LClient, LServer: ITlsEngine;
  LCh2: TBytes;
  LI: Int32;
  LOutcome: TTlsOutcome;
begin
  LClient := NewHrrClient;
  // a server that also speaks 1.2: SelectVersion alone would accept a 1.2-only retry
  LServer := NewHrrServerWithPolicy(TNegotiationPolicy.Create(
    TCipherSuiteRegistry.CreateDefault(Crypto), TNamedGroups.CreateDefaultRegistry(Crypto),
    TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.X25519),
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12),
    TServerCipherPreference.ServerOrder));
  LClient.StartHandshake;
  Pump(LClient, LServer);
  Pump(LServer, LClient);
  LCh2 := Drain(LClient);
  // rewrite the supported_versions extension (2b 00 03 02 03 04) so the retry offers 1.2 only
  LI := 0;
  while (LI + 6 < System.Length(LCh2)) and not ((LCh2[LI] = $00) and (LCh2[LI + 1] = $2B) and
    (LCh2[LI + 2] = $00) and (LCh2[LI + 3] = $03) and (LCh2[LI + 4] = $02) and
    (LCh2[LI + 5] = $03) and (LCh2[LI + 6] = $04)) do
    Inc(LI);
  CheckTrue(LI + 6 < System.Length(LCh2), 'the retry ClientHello carries supported_versions');
  LCh2[LI + 6] := $03;
  LOutcome := LServer.ProcessInput(LCh2, 0, System.Length(LCh2));
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LOutcome), 'a retry that drops 1.3 is fatal');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.ProtocolVersion,
    'it aborts with protocol_version');
end;

procedure TTestTls13Loopback.TestResolverReturningEmptyChainFailsHandshake;
var
  LClient, LServer: ITlsEngine;
  LNoChain: TTlsCredential;
begin
  LNoChain := ServerCredential;
  LNoChain.CertificateChain := nil;
  LClient := NewClient;
  LServer := NewServerWithResolver(TSniCredentialResolver.ForCredential(LNoChain));
  LClient.StartHandshake;
  Pump(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'a custom resolver handing back no certificate fails the server');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.HandshakeFailure,
    'it aborts with handshake_failure rather than emitting an empty certificate_list');
end;

procedure TTestTls13Loopback.TestUnexpectedMessageAbortsWithUnexpectedMessage;
var
  LClient: ITlsEngine;
  LOutcome: TTlsOutcome;
  LFinishedRecord: TBytes;
begin
  LClient := NewClient;
  LClient.StartHandshake;
  Drain(LClient); // discard the ClientHello flight

  // a client awaiting the ServerHello instead receives a (plaintext) Finished
  LFinishedRecord := DecodeHex('16 03 03 00 24 14 00 00 20' + StringOfChar('0', 64));
  LOutcome := LClient.ProcessInput(LFinishedRecord, 0, System.Length(LFinishedRecord));

  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LOutcome), 'an out-of-order message is fatal');
  CheckTrue(LClient.IsTerminal, 'the engine is terminal');
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage),
    Ord(LClient.LastError.Alert.Description), 'it aborts with unexpected_message');
end;

procedure TTestTls13Loopback.TestMiddleboxChangeCipherSpec;
var
  LClient, LServer: ITlsEngine;
begin
  // before any ServerHello has fixed the version, a bare change_cipher_spec is out of its legal
  // window (RFC 9846 E.4): the client fails with unexpected_message, not a silent drop
  LClient := NewClient;
  LClient.StartHandshake;
  Drain(LClient);
  LClient.ProcessInput(DecodeHex('14 03 03 00 01 01'), 0, 6);
  CheckTrue(LClient.IsTerminal, 'a change_cipher_spec before the ServerHello fails the client');
  CheckTrue(LClient.LastError.Alert.Description = TTlsAlertDescription.UnexpectedMessage,
    'the pre-hello change_cipher_spec is unexpected_message');

  // a normal handshake carries the server's middlebox change_cipher_spec right after its
  // ServerHello; the client drops it once the version is fixed, so the handshake completes
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal,
    'the handshake carrying the middlebox change_cipher_spec completed');
  CheckFalse(LClient.IsHandshaking, 'the client finished the handshake');
end;

procedure TTestTls13Loopback.TestWriteAfterInboundCloseNotifyHalfCloses;
var
  LClient, LServer: ITlsEngine;
  LMsg: TBytes;
  LRaised: Boolean;
begin
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');

  // the server closes its write side; the client receives the inbound close_notify
  LServer.SendClose;
  Pump(LServer, LClient);
  CheckTrue(LClient.IsInboundClosed, 'the client saw the inbound close_notify');
  CheckFalse(LClient.IsTerminal, 'a close after the handshake is not a failure');
  // bytes the peer sends after its close_notify are discarded, not framed (RFC 9846 6.1)
  LMsg := DecodeHex('1703030004deadbeef');
  CheckFalse(LClient.ProcessInput(LMsg, 0, System.Length(LMsg)) = TTlsOutcome.Fatal,
    'input after the close is discarded');
  CheckFalse(LClient.IsTerminal, 'post-close input does not make the engine terminal');
  // under TLS 1.3 an inbound close_notify closes only the read side (RFC 9846 6.1): the client's
  // write half stays open, so it can still write and rekey
  CheckFalse(LClient.WriteClosed, 'the TLS 1.3 write side stays open after an inbound close');
  LMsg := DecodeHex('61667465722d636c6f7365'); // "after-close"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('the client can still write after the inbound close_notify', LMsg,
    ReadAllApp(LServer));
  // a KeyUpdate on the still-open write half is permitted and writes continue under it
  LClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateNotRequested);
  Pump(LClient, LServer);
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('writes continue under the updated keys', LMsg, ReadAllApp(LServer));
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal,
    'the half-close rekey did not fail either side');

  // once the client closes its OWN write side, further writes are API misuse (the FSentClose leg)
  LClient.SendClose;
  CheckTrue(LClient.WriteClosed, 'the write side is closed after our own close_notify');
  LRaised := False;
  try
    LClient.Write(LMsg, 0, System.Length(LMsg));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a write after our own close_notify raises');
end;

procedure TTestTls13Loopback.TestErrorAfterOurCloseNotifyQueuesNoAlert;
var
  LClient, LServer: ITlsEngine;
  LByte, LWire: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  Drain(LClient);
  Drain(LServer);
  LClient.SendClose;
  CheckTrue(System.Length(Drain(LClient)) > 0, 'our close_notify is sent');
  LByte := DecodeHex('61');
  LServer.Write(LByte, 0, System.Length(LByte));
  LWire := Drain(LServer);
  // corrupt the AEAD tag in the last byte of the server's record
  LWire[System.High(LWire)] := LWire[System.High(LWire)] xor $01;
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LClient.ProcessInput(LWire, 0, System.Length(LWire))),
    'a corrupt record after our close_notify is fatal');
  CheckTrue(LClient.IsTerminal, 'the engine is terminal');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LClient.LastError.Origin),
    'the failure is recorded as our own');
  CheckEquals(Ord(TTlsAlertDescription.BadRecordMac), Ord(LClient.LastError.Alert.Description),
    'the recorded alert is bad_record_mac');
  CheckEquals(0, System.Length(Drain(LClient)), 'nothing follows our close_notify');
end;

procedure TTestTls13Loopback.TestCoalescedFinalDataAndCloseNotifyBothSurface;
var
  LClient, LServer: ITlsEngine;
  LMsg, LWire: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');

  // the server sends a final application message and immediately closes, so the
  // application_data record and the close_notify alert are queued together and reach the client
  // coalesced in one feed. Both must surface: the data is not lost behind the close, and the
  // close is not swallowed behind the data (the coalesced-close hang).
  LMsg := DecodeHex('6c6173742d6d657373616765'); // "last-message"
  LServer.Write(LMsg, 0, System.Length(LMsg));
  LServer.SendClose;
  LWire := Drain(LServer);
  FeedCoalesced(LClient, LWire);

  CheckEqualBytes('the coalesced final message is delivered', LMsg, ReadAllApp(LClient));
  CheckTrue(LClient.IsInboundClosed,
    'the close_notify coalesced with the final data is observed, not swallowed');
  CheckFalse(LClient.IsTerminal, 'a clean coalesced close is not a fatal termination');
end;

procedure TTestTls13Loopback.TestCloseNotifyFollowedByJunkIsACleanClose;
var
  LClient, LServer: ITlsEngine;
  LClose, LJunk, LWire: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  Drain(LClient);
  Drain(LServer);

  // bytes after a close_notify are ignored even when they are not a valid record (RFC 9846 6.1)
  LServer.SendClose;
  LClose := Drain(LServer);
  LJunk := DecodeHex('ff03030001');
  SetLength(LWire, System.Length(LClose) + System.Length(LJunk));
  Move(LClose[0], LWire[0], System.Length(LClose));
  Move(LJunk[0], LWire[System.Length(LClose)], System.Length(LJunk));
  CheckFalse(LClient.ProcessInput(LWire, 0, System.Length(LWire)) = TTlsOutcome.Fatal,
    'a close_notify followed by junk in one feed is not fatal');
  CheckTrue(LClient.IsInboundClosed, 'the close_notify is observed');
  CheckFalse(LClient.IsTerminal, 'the trailing junk does not end the connection');
  CheckEquals(0, System.Length(Drain(LClient)), 'no alert answers the trailing junk');
end;

procedure TTestTls13Loopback.TestFatalAlertFollowedByJunkSurfacesThePeerAlert;
var
  LClient, LServer: ITlsEngine;
  LByte, LRecord, LAlert, LJunk, LWire: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;
  RunHandshake(LClient, LServer);
  Drain(LClient);
  Drain(LServer);

  // the server fails on a corrupt record and sends its fatal alert; junk follows it in the feed
  LByte := DecodeHex('61');
  LClient.Write(LByte, 0, System.Length(LByte));
  LRecord := Drain(LClient);
  LRecord[System.High(LRecord)] := LRecord[System.High(LRecord)] xor $01;
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LServer.ProcessInput(LRecord, 0, System.Length(LRecord))),
    'the server rejects the corrupt record');
  LAlert := Drain(LServer);
  LJunk := DecodeHex('ffffffffff');
  SetLength(LWire, System.Length(LAlert) + System.Length(LJunk));
  Move(LAlert[0], LWire[0], System.Length(LAlert));
  Move(LJunk[0], LWire[System.Length(LAlert)], System.Length(LJunk));
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LClient.ProcessInput(LWire, 0, System.Length(LWire))),
    'the client fails on the peer alert');
  CheckEquals(Ord(TTlsErrorOrigin.Peer), Ord(LClient.LastError.Origin),
    'the failure is the peer''s alert, not a local framing error');
  CheckEquals(Ord(TTlsAlertDescription.BadRecordMac), Ord(LClient.LastError.Alert.Description),
    'the recorded alert is the peer''s bad_record_mac');
end;

procedure TTestTls13Loopback.TestStapledGoodOcspCompletesUnderHardPosture;
var
  LClient, LServer: ITlsEngine;
begin
  // the server staples a current Good OCSP response in the leaf CertificateEntry, which a
  // hard-fail client requires (a posture of this library; the format is RFC 9846 4.5.1.1)
  LClient := NewHardRevocationClient;
  LServer := NewStaplingServer(
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'ocsp_good'));
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client accepted the stapled Good response');
  CheckFalse(LServer.IsTerminal, 'the server completed the handshake');
end;

procedure TTestTls13Loopback.TestMissingStapleAbortsUnderHardPosture;
var
  LClient, LServer: ITlsEngine;
begin
  // the same client, but the server staples nothing: hard-fail rejects the leaf
  LClient := NewHardRevocationClient;
  LServer := NewStaplingServer(nil);
  RunHandshake(LClient, LServer);

  CheckTrue(LClient.IsTerminal,
    'the client aborted the handshake for a missing staple under hard-fail');
end;

procedure TTestTls13Loopback.TestSniSelectsHostCredentialAmongMany;
var
  LClient, LServer: ITlsEngine;
  LEntries: TArray<TSniCredentialEntry>;
  LPing: TBytes;
begin
  // a virtual-hosting server: 'localhost' -> the localhost leaf, 'other.example' -> a decoy.
  // A client that requests SNI 'localhost' must be served the localhost leaf (the decoy would
  // fail the client's name check), so a completed, name-verified handshake proves the resolver
  // selected by SNI rather than by config order (the decoy is listed first)
  SetLength(LEntries, 2);
  LEntries[0].Host := 'other.example';
  LEntries[0].Credential := CredentialWithChain(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'wrongname_cert')));
  LEntries[1].Host := 'localhost';
  LEntries[1].Credential := ServerCredential;

  LClient := NewClientForSni('localhost', 'localhost');
  LServer := NewServerWithResolver(TSniCredentialResolver.ForEntries(LEntries));

  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client accepted the localhost leaf it was served by SNI');
  CheckFalse(LServer.IsTerminal, 'the server completed the handshake');

  LPing := DecodeHex('70696e67'); // "ping"
  LClient.Write(LPing, 0, System.Length(LPing));
  Pump(LClient, LServer);
  CheckEqualBytes('application data flows over the SNI-selected credential', LPing,
    ReadAllApp(LServer));
end;

procedure TTestTls13Loopback.TestUnknownSniWithoutDefaultAbortsUnrecognizedName;
var
  LClient, LServer: ITlsEngine;
  LEntries: TArray<TSniCredentialEntry>;
begin
  // the server knows only 'localhost' and has no default credential; a client requesting an
  // unknown host is rejected with unrecognized_name(112) (local policy; RFC 6066 3), not served some
  // arbitrary certificate. This is the discriminator that proves the resolver gates on SNI
  SetLength(LEntries, 1);
  LEntries[0].Host := 'localhost';
  LEntries[0].Credential := ServerCredential;

  LClient := NewClientForSni('unknown.example', 'unknown.example');
  LServer := NewServerWithResolver(TSniCredentialResolver.ForEntries(LEntries));

  RunHandshake(LClient, LServer);

  CheckTrue(LServer.IsTerminal, 'the server aborted the unresolvable-SNI handshake');
  CheckEquals(Ord(TTlsAlertDescription.UnrecognizedName),
    Ord(LServer.LastError.Alert.Description),
    'the server aborts an unknown SNI with unrecognized_name(112)');
end;

procedure TTestTls13Loopback.TestSniResolverMatchingMatrix;
var
  LEntries: TArray<TSniCredentialEntry>;
  LExact, LWildcard, LDefault: TTlsCredential;
  LResolver: ITlsServerCredentialResolver;
  LHello: TTlsClientHelloInfo;
  LGot: TTlsCredential;

  function ResolveFor(const ASni: string; out ACred: TTlsCredential): Boolean;
  begin
    LHello := Default(TTlsClientHelloInfo);
    LHello.ServerName := ASni;
    Result := LResolver.TryResolve(LHello, ACred);
  end;

  function LeafOf(const ACred: TTlsCredential): TBytes;
  begin
    Result := ACred.CertificateChain[0];
  end;

begin
  // exercise the resolver's matching rules directly (no handshake): the credentials are opaque
  // payloads distinguished by their leaf bytes, so wildcard and case-folding are testable
  // without needing a certificate that actually carries those names
  LExact := ServerCredential;        // stands in for host.example.com
  // stands in for *.wild.example
  LWildcard := CredentialWithChain(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'wrongname_cert')));
  LDefault := Default(TTlsCredential);
  LDefault.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'));

  SetLength(LEntries, 2);
  LEntries[0].Host := 'host.example.com';
  LEntries[0].Credential := LExact;
  LEntries[1].Host := '*.wild.example';
  LEntries[1].Credential := LWildcard;
  LResolver := TSniCredentialResolver.Create(LEntries, LDefault);

  CheckTrue(ResolveFor('host.example.com', LGot), 'exact host resolves');
  CheckEqualBytes('exact host -> its credential', LeafOf(LExact), LeafOf(LGot));

  CheckTrue(ResolveFor('HOST.Example.COM', LGot), 'exact host is case-insensitive');
  CheckEqualBytes('case-folded exact host -> its credential', LeafOf(LExact), LeafOf(LGot));

  CheckTrue(ResolveFor('api.wild.example', LGot), 'single-label wildcard resolves');
  CheckEqualBytes('wildcard host -> its credential', LeafOf(LWildcard), LeafOf(LGot));

  CheckTrue(ResolveFor('deep.nested.wild.example', LGot),
    'a wildcard matches only one label but still resolves via the default');
  CheckEqualBytes('multi-label host falls through to the default', LeafOf(LDefault),
    LeafOf(LGot));

  CheckTrue(ResolveFor('', LGot), 'a no-SNI handshake resolves to the default');
  CheckEqualBytes('no SNI -> the default credential', LeafOf(LDefault), LeafOf(LGot));

  CheckTrue(ResolveFor('unrelated.example', LGot), 'an unmatched host resolves to the default');
  CheckEqualBytes('unmatched host -> the default credential', LeafOf(LDefault), LeafOf(LGot));
end;

procedure TTestTls13Loopback.TestSniResolverSupportsCredentialSet;
var
  LEntries: TArray<TSniCredentialEntry>;
  LResolver: ITlsServerCredentialResolver;
  LSet: ITlsServerCredentialSet;
begin
  LEntries := TArray<TSniCredentialEntry>.Create(MakeEntry('a.example', ServerCredential));
  LResolver := TSniCredentialResolver.ForEntries(LEntries);
  CheckTrue(Supports(LResolver, ITlsServerCredentialSet, LSet),
    'the built-in resolver lists its credentials');
end;

procedure TTestTls13Loopback.TestCredentialSetListsDefaultThenEntriesInOrder;
var
  LEntries: TArray<TSniCredentialEntry>;
  LDefault, LFirst, LSecond: TTlsCredential;
  LSet: ITlsServerCredentialSet;
  LListed: TArray<TTlsCredential>;
begin
  LDefault := CredentialWithChain(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')));
  LFirst := ServerCredential;
  LSecond := CredentialWithChain(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'wrongname_cert')));
  LEntries := TArray<TSniCredentialEntry>.Create(MakeEntry('a.example', LFirst),
    MakeEntry('*.b.example', LSecond));
  CheckTrue(Supports(TSniCredentialResolver.Create(LEntries, LDefault) as
    ITlsServerCredentialResolver, ITlsServerCredentialSet, LSet), 'resolver lists its set');
  LListed := LSet.Credentials;
  CheckEquals(3, System.Length(LListed), 'the default plus each entry');
  CheckEqualBytes('default first', LDefault.CertificateChain[0], LListed[0].CertificateChain[0]);
  CheckEqualBytes('first entry second', LFirst.CertificateChain[0],
    LListed[1].CertificateChain[0]);
  CheckEqualBytes('second entry last', LSecond.CertificateChain[0],
    LListed[2].CertificateChain[0]);
end;

procedure TTestTls13Loopback.TestCredentialSetWithoutDefaultListsEntriesOnly;
var
  LEntries: TArray<TSniCredentialEntry>;
  LSet: ITlsServerCredentialSet;
  LListed: TArray<TTlsCredential>;
begin
  LEntries := TArray<TSniCredentialEntry>.Create(MakeEntry('a.example', ServerCredential));
  CheckTrue(Supports(TSniCredentialResolver.ForEntries(LEntries), ITlsServerCredentialSet, LSet),
    'resolver lists its set');
  LListed := LSet.Credentials;
  CheckEquals(1, System.Length(LListed), 'only the entry, no phantom default');
end;

procedure TTestTls13Loopback.TestCredentialSetListsEveryCredentialWithoutDeduplication;
var
  LEntries: TArray<TSniCredentialEntry>;
  LShared, LOther: TTlsCredential;
  LSet: ITlsServerCredentialSet;
  LListed: TArray<TTlsCredential>;
begin
  LShared := ServerCredential;
  LOther := CredentialWithChain(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'wrongname_cert')));
  LEntries := TArray<TSniCredentialEntry>.Create(MakeEntry('a.example', LShared),
    MakeEntry('b.example', LOther));
  CheckTrue(Supports(TSniCredentialResolver.Create(LEntries, LShared) as
    ITlsServerCredentialResolver, ITlsServerCredentialSet, LSet), 'resolver lists its set');
  LListed := LSet.Credentials;
  CheckEquals(3, System.Length(LListed), 'the default and every entry, repeats included');
  CheckEqualBytes('shared credential listed as the default', LShared.CertificateChain[0],
    LListed[0].CertificateChain[0]);
  CheckEqualBytes('the same credential listed again as the first entry',
    LShared.CertificateChain[0], LListed[1].CertificateChain[0]);
  CheckEqualBytes('the other entry follows', LOther.CertificateChain[0],
    LListed[2].CertificateChain[0]);
end;

procedure TTestTls13Loopback.TestCredentialSetIsAFreshArray;
var
  LEntries: TArray<TSniCredentialEntry>;
  LCredential: TTlsCredential;
  LSet: ITlsServerCredentialSet;
  LListed: TArray<TTlsCredential>;
begin
  LCredential := ServerCredential;
  LEntries := TArray<TSniCredentialEntry>.Create(MakeEntry('a.example', LCredential));
  CheckTrue(Supports(TSniCredentialResolver.ForEntries(LEntries), ITlsServerCredentialSet, LSet),
    'resolver lists its set');
  LListed := LSet.Credentials;
  LListed[0].CertificateChain := nil;
  LListed[0].PrivateKey := nil;
  SetLength(LListed, 0);
  LListed := LSet.Credentials;
  CheckEquals(1, System.Length(LListed), 'the resolver still lists its entry');
  CheckEquals(System.Length(LCredential.CertificateChain),
    System.Length(LListed[0].CertificateChain), 'the chain is untouched');
  CheckTrue(LListed[0].PrivateKey <> nil, 'the key is untouched');
end;

procedure TTestTls13Loopback.TestCredentialSetChainsAreCopies;
var
  LEntries: TArray<TSniCredentialEntry>;
  LResolver: ITlsServerCredentialResolver;
  LSet: ITlsServerCredentialSet;
  LListed: TArray<TTlsCredential>;
  LHello: TTlsClientHelloInfo;
  LResolved: TTlsCredential;
  LFirst: Byte;
  LCredential: TTlsCredential;
begin
  LCredential := ServerCredential;
  LCredential.OcspStaple := TBytes.Create($30, $03, $0A, $01, $00);
  LEntries := TArray<TSniCredentialEntry>.Create(MakeEntry('a.example', LCredential));
  LResolver := TSniCredentialResolver.ForEntries(LEntries);
  CheckTrue(Supports(LResolver, ITlsServerCredentialSet, LSet), 'resolver lists its set');
  LHello := Default(TTlsClientHelloInfo);
  LHello.ServerName := 'a.example';
  CheckTrue(LResolver.TryResolve(LHello, LResolved), 'the entry resolves');
  LFirst := LResolved.CertificateChain[0][0];
  LListed := LSet.Credentials;
  LListed[0].CertificateChain[0][0] := LFirst xor $FF;
  CheckTrue(LResolver.TryResolve(LHello, LResolved), 'the entry still resolves');
  CheckEquals(LFirst, LResolved.CertificateChain[0][0], 'the listed chain was a copy');
  LListed[0].OcspStaple[0] := $00;
  CheckTrue(LResolver.TryResolve(LHello, LResolved), 'the entry resolves after the staple edit');
  CheckEquals($30, LResolved.OcspStaple[0], 'the listed staple was a copy');
end;

procedure TTestTls13Loopback.TestCredentialSetOfASingleCredentialListsOne;
var
  LSet: ITlsServerCredentialSet;
  LListed: TArray<TTlsCredential>;
begin
  CheckTrue(Supports(TSniCredentialResolver.ForCredential(ServerCredential),
    ITlsServerCredentialSet, LSet), 'the single-credential resolver lists its set');
  LListed := LSet.Credentials;
  CheckEquals(1, System.Length(LListed), 'only the default');
end;

procedure TTestTls13Loopback.TestEd448ServerCredentialHandshake;
var
  LClient, LServer: ITlsEngine;
  LMsg: TBytes;
begin
  LClient := NewClientEd448;
  LServer := NewServerEd448;
  RunHandshake(LClient, LServer);
  // the server derived ed448 from its credential, signed CertificateVerify with it, and the
  // client verified both the Ed448 cert chain and that signature
  CheckFalse(LClient.IsHandshaking, 'the client completed the Ed448 handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the Ed448 handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  LMsg := DecodeHex('656434343820776f726b73'); // "ed448 works"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('app data flows over the Ed448-authenticated channel', LMsg,
    ReadAllApp(LServer));
end;

procedure TTestTls13Loopback.TestEd25519ServerCredentialHandshake;
var
  LClient, LServer: ITlsEngine;
  LMsg: TBytes;
begin
  LClient := NewClientEd25519;
  LServer := NewServerEd25519;
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client completed the Ed25519 handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the Ed25519 handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  LMsg := DecodeHex('65643235353139'); // "ed25519"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('app data flows over the Ed25519-authenticated channel', LMsg,
    ReadAllApp(LServer));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13Loopback);
{$ELSE}
  RegisterTest(TTestTls13Loopback.Suite);
{$ENDIF FPC}

end.
