{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ConfigBuilderTests;

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
  TlpTlsLibExceptions,
  TlpIClock,
  MockClock,
  TlpTlsVersion,
  TlpAlpnProtocols,
  TlpArrayUtilities,
  TlpSecretBuffer,
  TlpISession,
  TlpSession,
  TlpInMemorySessionCache,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlpInMemorySessionStore,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpICertificateVerifierSource,
  TlpTrustTypes,
  TlpTlsAlert,
  TlpCertificateVerifier,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpNegotiationPolicy,
  TlpSignatureSchemeRegistry,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpICertificateCompression,
  TlpZlibCertificateCompression,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpISecretBuffer,
  TlpCryptoDomainTypes,
  TlpEchConfig,
  TlpIEch,
  TlpInMemoryEchKeyStore,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsConfigBuilder,
  TlpTlsEngineFactory,
  TlpServerName,
  TlpExtensionVector,
  TlpCoreExtensions,
  TlsLibTestHandshakeDecoder,
  TlpTlsLib,
  MockCryptoProvider,
  TlsLibTestProviders,
  TlsLibTestBase;

type
  TTestConfigBuilder = class(TTlsLibAlgorithmTestCase)
  private
    FCerts: TStringList;
    // the endpoint views hold a raw back-reference to their owner, so a helper that hands back a
    // view keeps the owning builder alive here for the test's duration
    FBuilders: TArray<ITlsConfigBuilder>;
    function ServerCredential: TTlsCredential; overload;
    function ServerCredential(const ACrypto: ICryptoProvider): TTlsCredential; overload;
    // the EcP256 leaf paired with a foreign private key from ImportKeys.txt (never its own key),
    // so the key does not own the leaf
    function CredentialWithForeignKey(const AKeyField: string): TTlsCredential;
    function ClientTrust: ITrustAnchorStore;
    function BuildEchConfigList(AConfigId: Byte; const APublicName: string;
      out APrivateKey: ISecretBuffer): TBytes; overload;
    function BuildEchConfigList(AConfigId: Byte; const APublicName: string;
      const AAeadIds: TArray<UInt16>; out APrivateKey: ISecretBuffer): TBytes; overload;
    /// <summary>Whether giving a server builder over a provider without AES-128-GCM an ECH store
    /// whose one config advertises AAeadIds is refused.</summary>
    function EchKeyStoreRefused(const AAeadIds: TArray<UInt16>): Boolean;
    function BuildClientConfig(const ACryptoProvider: ICryptoProvider): ITlsClientConfig;
    function BuildServerConfig(const ACryptoProvider: ICryptoProvider): ITlsServerConfig;
    function DefaultProfile: TTlsConfigProfile;
    function ChainLimitsAccepted(AMaxCert, AMaxTotal: Int32): Boolean;
    function SameOrder(const AA, AB: TArray<UInt16>): Boolean;
    function ServerBuildIsRefused(const ABuilder: ITlsServerConfigBuilder): Boolean;
    function ClientBuildNeedsTls13(const AFacet: ITls13ClientConfigFacet): Boolean;
    function ServerBuildNeedsTls13(const AFacet: ITls13ServerConfigFacet): Boolean;
    /// <summary>Whether Build is refused as invalid operation with AReason in its message.</summary>
    function BuildRefused(const ABuilder: ITlsClientConfigBuilder;
      const AReason: string): Boolean; overload;
    function BuildRefused(const ABuilder: ITlsServerConfigBuilder;
      const AReason: string): Boolean; overload;
    function BuildRefused(const AFacet: ITls13ServerConfigFacet;
      const AReason: string): Boolean; overload;
    function BuildRefused(const AFacet: ITls12ServerConfigFacet;
      const AReason: string): Boolean; overload;
    function HelloSuites(const AWire: TBytes): TArray<UInt16>;
    function NewClientBuilder: ITlsClientConfigBuilder;
    function NewServerBuilder: ITlsServerConfigBuilder;
    function MakePskSpec: TExternalPsk;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure RunHandshake(const AClient, AServer: ITlsEngine);
    // the flight exchange of a handshake whose client has already started and sent its first flight
    procedure ExchangeFlights(const AClient, AServer: ITlsEngine);
    procedure RunEchThroughBuilder(AMode: TServerNameIndication);
    function OmitSniClient(const AVersions: TArray<UInt16>): ITlsClientConfig;
    function RejectEveryChain(const AChain: TArray<TBytes>; const AHostName: string): Boolean;
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEchThroughServerBuilder;
    procedure TestEchBackendThenKeyStoreRejected;
    procedure TestEchKeyStoreThenBackendRejected;
    procedure TestEchPolicyAbsentWithoutEch;
    procedure TestEchBackendPolicyFrozen;
    procedure TestEchKeyStoreTrialDecryptRecordedOnPolicy;
    procedure TestEchKeyStoreCalledAgainReplacesThePolicy;
    procedure TestEchNilKeyStoreRejected;
    procedure TestEchEmptyKeyStoreRejected;
    procedure TestEchKeyStoreRetryConfigsMustBeAValidList;
    procedure TestEchKeyStoreEntryTheProviderCannotServeRefused;
    procedure TestEchKeyStoreEveryAdvertisedSuiteMustBeServable;
    procedure TestEchKeyStoreEntryTheProviderCanServeBuilds;
    procedure TestEmptyEchConfigListWithoutGreaseRejectedAtBuild;
    procedure TestEchGreaseOnlyBuildsWithoutConfig;
    procedure TestEchGreaseFalseWithoutConfigIsNoOp;
    procedure TestEmptySupportedVersionsIsRefused;
    procedure TestNonNegotiableVersionIsRefused;
    procedure TestDuplicateVersionIsRefused;
    procedure TestAlpnEmptyNameIsRefused;
    procedure TestAlpnNonAsciiNameIsRefused;
    procedure TestAlpnOverlongNameIsRefused;
    procedure TestAlpnDuplicateNameIsRefused;
    procedure TestAlpnEmptyListMeansNoAlpn;
    procedure TestAlpnRejectionWithProtocolsIsRefused;
    procedure TestResumptionSettingsAreRefusedWhenResumptionIsOff;
    procedure TestSingleVersionHelloAdvertisesOnlyThatVersionsSuites;
    procedure TestAlpnSetterCopiesCallerArray;
    procedure TestRecordSizeLimitDefaultsToUnset;
    procedure TestExternalPskInnerBytesAreCopied;
    procedure TestNilClockIsRefused;
    procedure TestNilMonotonicClockIsRefused;
    procedure TestMonotonicClockDefaultsToTheSystemSourceAndIsInjectable;
    procedure TestAlpnListBeyondWireLimitIsRefused;
    procedure TestLargestAlpnListStillEncodesInTheClientHello;
    procedure TestServerExternalPskNeedsTls13;
    procedure TestPskOnlyServerMustOfferTls13Only;
    procedure TestTls12NeedsAClassicalEcdheGroup;
    procedure TestOneBuilderConfiguresOneEndpoint;
    procedure TestPreferredGroupsWithNoRegisteredGroupIsRefused;
    procedure TestEmptyPreferredGroupsIsRefusedAtBuild;
    procedure TestNilRegistryIsRefusedAtBuild;
    procedure TestCipherSuiteListNarrowsAndOrdersPerProtocol;
    procedure TestCipherSuiteListLeavesAnUnnamedProtocolIntact;
    procedure TestFailedBuildLeavesTheCipherSuiteListInForce;
    procedure TestCipherSuiteListOutsideTheConfiguredSetIsRefused;
    procedure TestCipherSuiteListIsIndependentOfCallOrder;
    procedure TestEmptyCipherSuiteListIsRefused;
    procedure TestInjectedVerifierRefusesSettingsItIgnores;
    procedure TestTls13SettingsAreRefusedWhenTls13IsNotOffered;
    procedure TestOfferedVersionWithoutASuiteIsRefused;
    procedure TestServerCipherSuiteListOrderDecidesTheNegotiatedSuite;
    procedure TestClientCipherSuiteListIsTheOnlyOfferedSuite;
    procedure TestRecordSizeLimitRoundTrips;
    procedure TestRecordSizeLimitRejectsOutOfRange;
    procedure TestRecordSizeLimitCapsRecordsThroughFactory;
    procedure TestPreferredGroupsSetterCopiesCallerArray;
    procedure TestCertificateCompressorsSetterCopiesCallerArray;
    procedure TestCertificateDecompressorsSetterCopiesCallerArray;
    procedure TestRawBuilderWithoutVersionsIsRefusedAtBuild;
    procedure TestBuilderRejectsMutationAfterBuild;
    procedure TestSecondBuildIsRejected;
    procedure TestReturnedPinsArrayCannotMutateConfig;
    procedure TestWithCertificatePinningRejectsWrongLengthPin;
    procedure TestClientConfigRequiresTrustStore;
    procedure TestPskOnlyClientOfferingTls12IsRefused;
    procedure TestPskOnlyClientWithPskOptionalIsRefused;
    procedure TestPskOnlyTls13ClientBuilds;
    procedure TestServerConfigRequiresCredential;
    procedure TestServerClientAuthRequiresTrustStore;
    // an empty trust store is not a trust source: it must be refused (with a distinct message),
    // an explicit skip-verify builds without one, and the union with a real root still builds
    procedure TestClientEmptyTrustStoreIsRefused;
    procedure TestClientUnionOfEmptyStoresIsRefused;
    procedure TestClientEmptyStoreUnionedWithRealRootBuilds;
    procedure TestClientInsecureSkipVerifyBuildsWithoutTrustStore;
    procedure TestClientInsecureSkipVerifyWithEmptyStoreBuilds;
    procedure TestPskClientWithEmptyStoreIsSteeredAsPskOnly;
    procedure TestServerClientAuthEmptyTrustStoreIsRefused;
    procedure TestServerClientAuthInsecureSkipVerifyBuildsWithoutTrustStore;
    // a client verifier source consumes the client-CA anchors, so it needs roots at Build: refused
    // without them (source-specific message), builds with a real root, inert when client auth is off
    procedure TestServerClientAuthVerifierSourceWithoutAnchorsIsRefused;
    procedure TestServerClientAuthVerifierSourceWithEmptyStoreIsRefused;
    procedure TestServerClientAuthVerifierSourceWithAnchorsBuilds;
    procedure TestServerClientAuthVerifierSourceWithEmptyStoreAndRealRootBuilds;
    procedure TestServerVerifierSourceWithoutPeerAuthIsRefused;
    procedure TestServerTrustInputsWithoutPeerAuthAreRefused;
    procedure TestServerClientAuthVerifierSourceWithSkipVerifyBuilds;
    // the exclusivity count runs before the roots gate, so an instance verifier plus a source is the
    // dual-verifier conflict - never the "source needs anchors" message
    procedure TestServerClientAuthVerifierSourceWithInstanceIsDualVerifier;
    procedure TestMtlsServerWithSuppliedTicketKeysRequiresScope;
    procedure TestEarlyDataWithSuppliedTicketKeysNeedsSharedReplayProtection;
    procedure TestServerEarlyDataBudgetIsCappedAtOneMebibyte;
    procedure TestMtlsServerWithSuppliedKeysAndScopeBuilds;
    procedure TestMtlsServerWithDefaultTicketKeysBuildsWithoutScope;
    procedure TestFacadeDrivesLoopback;
    procedure TestCustomProviderThreadedThroughRawBuilder;
    procedure TestDefaultCertificateChainLimitsAreConservative;
    procedure TestCertificateChainLimitsAreConfigurable;
    procedure TestInvalidCertificateChainLimitsRejected;
    procedure TestInvalidChainEntryCapRejected;
    procedure TestContradictoryStrengthFloorsRejected;
    procedure TestTls13CompressorOverrideLandsInFrozenConfig;
    procedure TestClientBuilderChainBuildsClient;
    procedure TestServerBuilderChainBuildsServer;
    procedure TestVersionFacetForUnofferedVersionIsRefused;
    procedure TestNonEmsResumptionReachesFrozenConfig;
    procedure TestNonEmsResumptionOnTls13OnlyIsRefused;
    procedure TestRequiredEmsWithNonEmsResumeIsRefused;
    procedure TestDefaultRevocationPostureIsSoft;
    procedure TestWithRevocationSetsHardPosture;
    // server-side Hard client-certificate revocation: satisfiable only by a live resolver, so
    // Build fails fast without one, builds with one, and is inert when client auth is off
    procedure TestServerHardClientRevocationWithoutResolverIsRefused;
    procedure TestServerHardClientRevocationWithResolverBuilds;
    procedure TestServerHardClientRevocationHostDecisionIsRefused;
    procedure TestServerHardRevocationWithoutClientAuthIsRefused;
    procedure TestClientHardHostDecisionWithoutStapleIsRefused;
    procedure TestClientHardLiveRevocationBuilds;
    procedure TestAsyncVerdictMapsToHostDecision;
    procedure TestWithCertificatePinningLandsInFrozenConfig;
    procedure TestServerWithOcspStapleLandsInFrozenConfig;
    procedure TestLoadedCredentialReplacesPriorStaple;
    // a credential built by TTlsCredential.Load passes Build's key<->leaf consistency
    procedure TestLoadedCredentialBuildsServer;
    // the credential key/leaf guard: a private key that does not own CertificateChain[0] (wrong
    // key, wrong key family, or a mis-ordered chain) is refused at Build, not left to fail as a
    // rejected CertificateVerify mid-handshake
    procedure TestServerCredentialWithMismatchedKeyRejected;
    procedure TestServerCredentialWithWrongKeyFamilyRejected;
    procedure TestIncompleteCredentialsAreRefusedAtBuild;
    procedure TestMalformedTrustAnchorIsRefusedAtBuild;
    procedure TestSniCredentialWithMismatchedKeyNamesHost;
    procedure TestClientCredentialWithMismatchedKeyRejected;
    procedure TestMatchingCredentialBuildsServer;
    // RFC 8446 4.6.1: a server MUST NOT advertise a ticket lifetime over 604800 seconds
    procedure TestTicketLifetimeAboveCapIsRejected;
    procedure TestTicketLifetimeAtCapIsAccepted;
    procedure TestResumptionScopeAboveCapIsRejected;
    procedure TestResumptionScopeAtCapIsAccepted;
    procedure TestClientResumptionScopeAboveCapIsRejected;
    procedure TestClientResumptionScopeAtCapRoundTrips;
    procedure TestClientResumptionScopeIsOrderInsensitive;
    procedure TestTicketCountAboveCapIsRejected;
    procedure TestTicketCountNegativeIsRejected;
    procedure TestTicketCountAtCapIsAccepted;
    // RFC 8446 8: a server authorizing 0-RTT gets one anti-replay register per config (shared
    // across connections), so a replay across connections is detectable without WithAntiReplay
    procedure TestServerEarlyDataMintsSharedAntiReplayDefault;
    procedure TestServerRejectsPublicSuffixSniWildcard;
    // a restricted (classical-only) registry composes with a preset whose preferred order still
    // names the pruned hybrid: the engine drops it from the offer instead of failing to build,
    // and the handshake negotiates a classical group
    procedure TestClassicalRegistryOverPresetNegotiatesClassical;
    // the asymmetric case: a classical-registry client against a default, post-quantum-preferring
    // server - the client advertises no hybrid, so the server cannot retry it onto a pruned group
    procedure TestClassicalRegistryClientAgainstDefaultServer;
    // a 1.3 server whose registry holds none of its preferred groups is refused at creation, not
    // left to fault on the first ClientHello
    procedure TestServerWithEmptyGroupIntersectionFailsFast;
    // the accessors relocated onto the role configs read their builder defaults
    procedure TestRoleConfigDefaultsForMovedAccessors;
    procedure TestTls13ReportsExtendedMasterSecret;
    procedure TestVerifyCallbackRunsOverInstanceVerifier;
    procedure TestServerNameIndicationOmitReachesConfig;
    procedure TestOmittedSniSendsNoServerNameAndStillVerifiesHost;
    procedure TestOmittedSniStillRejectsWrongHost;
    procedure TestOmittedSniTls12SendsNoServerName;
    procedure TestOmittedSniHrrRetryKeepsServerNameAbsent;
    procedure TestOmittedSniKeepsSessionsApart;
    procedure TestEchWithOmittedSniAcceptsAndVerifiesHost;
  end;

implementation

type
  // a key store that serves another store's entries but advertises the given retry configs
  TRetryOverrideKeyStore = class(TInterfacedObject, IEchServerKeyStore)
  strict private
    FInner: IEchServerKeyStore;
    FRetryConfigs: TBytes;
  public
    constructor Create(const AInner: IEchServerKeyStore; const ARetryConfigs: TBytes);
    function Entries: TArray<TEchKeyEntry>;
    function RetryConfigs: TBytes;
  end;

  // an accept-all client-certificate verifier source, to exercise the Build-time roots gate
  // without a live handshake
  TAcceptAllClientVerifier = class(TInterfacedObject, IClientCertificateVerifier)
  public
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

  TAcceptAllClientVerifierSource = class(TInterfacedObject, IClientCertificateVerifierSource)
  public
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

  // an accept-all server-certificate verifier, standing in for a caller-supplied whole verifier
  TAcceptAllServerVerifier = class(TInterfacedObject, IServerCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

function TAcceptAllClientVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified.Path := AChain;
  AVerified.Outcome := TVerificationOutcome.Trusted;
  AAlert := TTlsAlertDescription.CertificateUnknown;
  Result := True;
end;

function TAcceptAllClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
begin
  Result := TAcceptAllClientVerifier.Create as IClientCertificateVerifier;
end;

function TAcceptAllServerVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified.Path := AChain;
  AVerified.Outcome := TVerificationOutcome.Trusted;
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := True;
end;

{ TTestConfigBuilder }

procedure TTestConfigBuilder.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
end;

procedure TTestConfigBuilder.TearDown;
begin
  FBuilders := nil;
  FCerts.Free;
  inherited TearDown;
end;

function TTestConfigBuilder.ServerCredential: TTlsCredential;
begin
  Result := ServerCredential(Crypto);
end;

function TTestConfigBuilder.ServerCredential(const ACrypto: ICryptoProvider): TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  Result.PrivateKey := ACrypto.Signing.ImportSigningKey(DecodeHex(FCerts.Values['leaf_key']), nil);
end;

function TTestConfigBuilder.ClientTrust: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']))) as ITrustAnchorStore;
end;

function TTestConfigBuilder.CredentialWithForeignKey(
  const AKeyField: string): TTlsCredential;
var
  LKeys: TStringList;
begin
  Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  LKeys := LoadVectorFields('Certs/ImportKeys.txt');
  try
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LKeys.Values[AKeyField]), nil);
  finally
    LKeys.Free;
  end;
end;

function TTestConfigBuilder.BuildClientConfig(
  const ACryptoProvider: ICryptoProvider): ITlsClientConfig;
var
  LBuilder: ITlsConfigBuilder;
begin
  // assemble a client config straight from the raw builder with the given provider
  LBuilder := TTlsConfigBuilder.CreateFromProfile(ACryptoProvider, Pkix, TTlsConfigProfile.Default);
  Result := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(ACryptoProvider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(ACryptoProvider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithTrustStore(ClientTrust)
    .Build;
end;

function TTestConfigBuilder.BuildServerConfig(
  const ACryptoProvider: ICryptoProvider): ITlsServerConfig;
var
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(ACryptoProvider, Pkix, TTlsConfigProfile.Default);
  Result := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(ACryptoProvider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(ACryptoProvider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(ServerCredential)
    .Build;
end;

function TTestConfigBuilder.BuildEchConfigList(AConfigId: Byte;
  const APublicName: string; out APrivateKey: ISecretBuffer): TBytes;
begin
  Result := BuildEchConfigList(AConfigId, APublicName,
    TArray<UInt16>.Create(THpkeAead.AES_128_GCM), APrivateKey);
end;

function TTestConfigBuilder.BuildEchConfigList(AConfigId: Byte;
  const APublicName: string; const AAeadIds: TArray<UInt16>;
  out APrivateKey: ISecretBuffer): TBytes;
var
  LPublicKey: TBytes;
  LConfig: TEchConfig;
  LSuites: TArray<TEchCipherSuite>;
  LI: Int32;
begin
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey,
    APrivateKey);
  SetLength(LSuites, System.Length(AAeadIds));
  for LI := 0 to System.High(AAeadIds) do
  begin
    LSuites[LI].KdfId := THpkeKdf.HKDF_SHA256;
    LSuites[LI].AeadId := AAeadIds[LI];
  end;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, AConfigId,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey, LSuites, 0,
    TEncoding.ASCII.GetBytes(APublicName), nil);
  Result := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));
end;

procedure TTestConfigBuilder.TestEchBackendThenKeyStoreRejected;
var
  LSk: ISecretBuffer;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  // the split-mode backend role holds no ECH keys; pairing WithEchBackend with WithEchKeyStore is a
  // contradictory deployment and is refused (RFC 9849 sec. 7), whichever is called second
  LConfigList := BuildEchConfigList($E1, 'cover.example', LSk);
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchBackend.WithEchKeyStore(
      TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Crypto));
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an ECH key store after a split-mode backend is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreThenBackendRejected;
var
  LSk: ISecretBuffer;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  LConfigList := BuildEchConfigList($E1, 'cover.example', LSk);
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchKeyStore(
      TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Crypto)).WithEchBackend;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a split-mode backend after an ECH key store is refused');
end;

procedure TTestConfigBuilder.TestEchPolicyAbsentWithoutEch;
begin
  CheckTrue(NewServerBuilder.Build.EncryptedClientHello = nil,
    'a server with no ECH configuration has no ECH policy');
end;

procedure TTestConfigBuilder.TestEchBackendPolicyFrozen;
var
  LPolicy: IEchServerPolicy;
begin
  LPolicy := NewServerBuilder.Tls13.WithEchBackend.Build.EncryptedClientHello;
  CheckTrue(LPolicy <> nil, 'a backend server has an ECH policy');
  CheckTrue(LPolicy.Role = TEchServerRole.Backend, 'whose role is Backend');
  CheckTrue(LPolicy.KeyStore = nil, 'and which holds no key store');
  CheckFalse(LPolicy.TrialDecrypt, 'and does not trial-decrypt');
end;

procedure TTestConfigBuilder.TestEchKeyStoreTrialDecryptRecordedOnPolicy;
var
  LSk: ISecretBuffer;
  LStore: IEchServerKeyStore;
  LPolicy: IEchServerPolicy;
begin
  LStore := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E3, 'cover.example', LSk), LSk,
    Crypto);
  LPolicy := NewServerBuilder.Tls13.WithEchKeyStore(LStore).Build.EncryptedClientHello;
  CheckTrue(LPolicy.Role = TEchServerRole.Keyed, 'a key store makes the server Keyed');
  CheckFalse(LPolicy.TrialDecrypt, 'trial decryption is off by default');
  LPolicy := NewServerBuilder.Tls13.WithEchKeyStore(LStore, True).Build.EncryptedClientHello;
  CheckTrue(LPolicy.TrialDecrypt, 'the overload turns trial decryption on');
  CheckTrue(LPolicy.KeyStore = LStore, 'and the policy carries the store');
end;

procedure TTestConfigBuilder.TestEchKeyStoreCalledAgainReplacesThePolicy;
var
  LSk: ISecretBuffer;
  LFirst, LSecond: IEchServerKeyStore;
  LFacet: ITls13ServerConfigFacet;
  LPolicy: IEchServerPolicy;
begin
  LFirst := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E4, 'cover.example', LSk), LSk,
    Crypto);
  LSecond := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E5, 'cover.example', LSk), LSk,
    Crypto);
  LFacet := NewServerBuilder.Tls13.WithEchKeyStore(LFirst);
  LPolicy := LFacet.WithEchKeyStore(LSecond, True).Build.EncryptedClientHello;
  CheckTrue(LPolicy.KeyStore = LSecond, 'the second store replaces the first');
  CheckTrue(LPolicy.TrialDecrypt, 'along with its trial-decrypt setting');
end;

constructor TRetryOverrideKeyStore.Create(const AInner: IEchServerKeyStore;
  const ARetryConfigs: TBytes);
begin
  inherited Create;
  FInner := AInner;
  FRetryConfigs := ARetryConfigs;
end;

function TRetryOverrideKeyStore.Entries: TArray<TEchKeyEntry>;
begin
  Result := FInner.Entries;
end;

function TRetryOverrideKeyStore.RetryConfigs: TBytes;
begin
  Result := FRetryConfigs;
end;

procedure TTestConfigBuilder.TestEchEmptyKeyStoreRejected;
var
  LRaised: Boolean;
begin
  // with no entries a keyed server would reject every ECH offer and advertise no retry configs
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchKeyStore(
      TInMemoryEchKeyStore.Create(nil) as IEchServerKeyStore);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an ECH key store with no entries is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreRetryConfigsMustBeAValidList;
var
  LSk: ISecretBuffer;
  LReal: IEchServerKeyStore;
  LCase: Int32;
  LRaised: Boolean;
begin
  // the retry configs go on the wire as they are: an empty or malformed list is refused up front,
  // while the store's own list passes
  LReal := TInMemoryEchKeyStore.FromConfig(BuildEchConfigList($E6, 'cover.example', LSk), LSk,
    Crypto);
  for LCase := 0 to 2 do
  begin
    LRaised := False;
    try
      case LCase of
        0: NewServerBuilder.Tls13.WithEchKeyStore(
             TRetryOverrideKeyStore.Create(LReal, nil) as IEchServerKeyStore);
        1: NewServerBuilder.Tls13.WithEchKeyStore(
             TRetryOverrideKeyStore.Create(LReal, DecodeHex('00ff0102')) as IEchServerKeyStore);
        2: NewServerBuilder.Tls13.WithEchKeyStore(
             TRetryOverrideKeyStore.Create(LReal, LReal.RetryConfigs) as IEchServerKeyStore);
      end;
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckEquals(LCase < 2, LRaised, Format('retry configs case %d', [LCase]));
  end;
end;

procedure TTestConfigBuilder.TestEchNilKeyStoreRejected;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchKeyStore(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil ECH key store is refused');
end;

function TTestConfigBuilder.EchKeyStoreRefused(const AAeadIds: TArray<UInt16>): Boolean;
var
  LSk: ISecretBuffer;
  LStore: IEchServerKeyStore;
  LServing: ICryptoProvider;
  LOwner: ITlsConfigBuilder;
begin
  // the store is built with a full provider, but the one that serves the handshakes lacks AES-128-GCM
  LStore := TInMemoryEchKeyStore.FromConfig(
    BuildEchConfigList($E2, 'cover.example', AAeadIds, LSk), LSk, Crypto);
  LServing := TMissingAeadProvider.Create(Crypto, TAeadAlgorithm.AES_128_GCM) as ICryptoProvider;
  LOwner := TTlsConfigBuilder.CreateFromProfile(LServing, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  Result := False;
  try
    LOwner.Server.WithCredential(ServerCredential).Tls13.WithEchKeyStore(LStore);
  except
    on E: EArgumentTlsLibException do
      Result := True;
  end;
end;

procedure TTestConfigBuilder.TestEchKeyStoreEntryTheProviderCannotServeRefused;
begin
  CheckTrue(EchKeyStoreRefused(TArray<UInt16>.Create(THpkeAead.AES_128_GCM)),
    'an ECH entry whose only suite the serving provider cannot build is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreEveryAdvertisedSuiteMustBeServable;
begin
  // a client may pick any HPKE suite the config lists, so one the provider cannot build would make
  // the server decline ECH for every client that picks it even though another suite works
  CheckTrue(EchKeyStoreRefused(TArray<UInt16>.Create(THpkeAead.AES_128_GCM, THpkeAead.AES_256_GCM)),
    'an entry advertising one unservable suite among servable ones is refused');
end;

procedure TTestConfigBuilder.TestEchKeyStoreEntryTheProviderCanServeBuilds;
begin
  // the control: the same limited provider builds when every advertised suite is available, so the
  // refusals above are about the suite and nothing else in the setup
  CheckFalse(EchKeyStoreRefused(TArray<UInt16>.Create(THpkeAead.AES_256_GCM)),
    'an entry whose suites the serving provider can all build is accepted');
end;

procedure TTestConfigBuilder.TestEchThroughServerBuilder;
begin
  RunEchThroughBuilder(TServerNameIndication.Send);
end;

procedure TTestConfigBuilder.TestEchWithOmittedSniAcceptsAndVerifiesHost;
begin
  // the outer hello still carries the public_name and the inner none; the leaf matches only
  // localhost, so acceptance proves the host check ran against the host, not the public_name
  RunEchThroughBuilder(TServerNameIndication.Omit);
end;

procedure TTestConfigBuilder.RunEchThroughBuilder(AMode: TServerNameIndication);
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LClientBuilder, LServerBuilder: ITlsConfigBuilder;
  LConfigList: TBytes;
  LSk: ISecretBuffer;
  LMsg, LOuter: TBytes;
begin
  // ECH configured end to end through the public builder: the client offers the config list
  // (Tls13.WithEncryptedClientHello) and the server is keyed with the matching config store
  // (Tls13.WithEchKeyStore + TInMemoryEchKeyStore.FromConfig). The store lands on the frozen
  // config, the factory wires it into the server params, and the handshake accepts. The client
  // offers a full (GREASE-bearing) extension set, so this also covers ECH acceptance with
  // GREASE in the inner ClientHello.
  LConfigList := BuildEchConfigList($D4, 'cover.example', LSk);
  LClientBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LClientConfig := LClientBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithTrustStore(ClientTrust)
    .WithServerNameIndication(AMode)
    .Tls13.WithEncryptedClientHello(LConfigList).Build;
  LServerBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LServerConfig := LServerBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(ServerCredential)
    .Tls13.WithEchKeyStore(TInMemoryEchKeyStore.FromConfig(LConfigList, LSk,
    Crypto)).Build;

  CheckTrue(LServerConfig.EncryptedClientHello <> nil,
    'the builder froze an ECH policy onto the server config');

  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient.StartHandshake;
  LOuter := Drain(LClient);
  // the real name never rides the outer hello, whichever mode: it carries the public_name only
  CheckTrue(ContainsAscii(LOuter, 'cover.example'),
    'the outer hello carries the public_name');
  CheckFalse(ContainsAscii(LOuter, 'localhost'),
    'the outer hello does not carry the real host');
  Feed(LServer, LOuter);
  ExchangeFlights(LClient, LServer);

  // completion proves ECH was accepted: the leaf matches only the inner SNI (localhost), never
  // the public_name, so a reject would abort the client on the certificate check
  CheckFalse(LClient.IsHandshaking, 'the ECH client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the ECH server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the ECH client did not abort');
  CheckFalse(LServer.IsTerminal, 'the ECH server did not abort');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted,
    'the builder-configured connection surfaced ECH Accepted');
  // the server reads the name from the decrypted inner hello
  if AMode = TServerNameIndication.Omit then
    CheckEquals('', LServer.ConnectionInfo.ServerName, 'the inner hello carries no SNI')
  else
    CheckEquals('localhost', LServer.ConnectionInfo.ServerName, 'the inner hello carries the host');
  LMsg := DecodeHex('6563682d6f6b'); // "ech-ok"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Feed(LServer, Drain(LClient));
  CheckEqualBytes('app data flows over the builder-configured ECH connection', LMsg,
    ReadAllApp(LServer));
end;

procedure TTestConfigBuilder.TestEmptyEchConfigListWithoutGreaseRejectedAtBuild;
var
  LRaised: Boolean;
begin
  // an empty ECHConfigList with GREASE off would send the true SNI in the clear: reject at Build
  LRaised := False;
  try
    NewClientBuilder.Tls13.WithEncryptedClientHello(nil).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ECHConfigList with GREASE off is rejected at Build');
end;

procedure TTestConfigBuilder.TestEchGreaseOnlyBuildsWithoutConfig;
var
  LConfig: ITlsClientConfig;
begin
  // GREASE with no config list is the explicit GREASE-only mode; it builds
  LConfig := NewClientBuilder.Tls13.WithEchGrease(True).Build;
  CheckTrue(LConfig.EncryptedClientHello <> nil, 'GREASE-only ECH is configured');
  CheckTrue(LConfig.EncryptedClientHello.GreaseEnabled, 'the policy is GREASE-enabled');
  CheckFalse(LConfig.EncryptedClientHello.Usable,
    'GREASE-only resolved no usable config');
end;

procedure TTestConfigBuilder.TestEchGreaseFalseWithoutConfigIsNoOp;
var
  LConfig: ITlsClientConfig;
begin
  // WithEchGrease(False) with no config list does not configure ECH (it is a no-op, not a
  // fail-closed empty policy), so a caller passing a runtime flag is not surprised by a raise
  LConfig := NewClientBuilder.Tls13.WithEchGrease(False).Build;
  CheckTrue(LConfig.EncryptedClientHello = nil, 'no ECH policy is configured');
  // and turning GREASE on, then off again, leaves the same no-op
  LConfig := NewClientBuilder.Tls13.WithEchGrease(True).WithEchGrease(False).Build;
  CheckTrue(LConfig.EncryptedClientHello = nil, 'GREASE on then off configures no ECH policy');
end;

procedure TTestConfigBuilder.TestEmptySupportedVersionsIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
  LNone: TArray<UInt16>;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LNone := nil;
  LRaised := False;
  try
    LBuilder.Client.WithSupportedVersions(LNone);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty supported-versions set is refused');
end;

procedure TTestConfigBuilder.TestNonNegotiableVersionIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    // TLS 1.0 is not a version the engine can build
    LBuilder.Client.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls10));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-negotiable version is refused');
end;

procedure TTestConfigBuilder.TestDuplicateVersionIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithSupportedVersions(
      TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls13));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a duplicate version is refused');
end;

procedure TTestConfigBuilder.TestAlpnEmptyNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, nil));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ALPN protocol name is refused');
end;

procedure TTestConfigBuilder.TestAlpnNonAsciiNameIsRefused;
var
  LRaised: Boolean;
  LText: string;
begin
  LRaised := False;
  try
    TAlpnProtocols.FromText('h2' + #$00E9);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-ASCII character has no ASCII octets and is refused');
  // an octet above 127 is a legal name on the wire but has no text form
  CheckFalse(TAlpnProtocols.TryToText(TBytes.Create($68, $B2), LText),
    'a name with an octet above 127 has no text form');
  CheckTrue(TAlpnProtocols.TryToText(TAlpnProtocols.H2, LText) and (LText = 'h2'),
    'an ASCII name round-trips through text');
end;

procedure TTestConfigBuilder.TestAlpnOverlongNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised, LAtCapRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(
      TAlpnProtocols.FromText(TArray<string>.Create(StringOfChar('a', 256))));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a 256-byte ALPN protocol name is refused');
  // the 255-byte boundary is legal
  LAtCapRaised := False;
  try
    NewClientBuilder.WithAlpnProtocols(
      TAlpnProtocols.FromText(TArray<string>.Create(StringOfChar('a', 255))));
  except
    on E: EArgumentTlsLibException do
      LAtCapRaised := True;
  end;
  CheckFalse(LAtCapRaised, 'a 255-byte ALPN protocol name is accepted');
end;

procedure TTestConfigBuilder.TestAlpnDuplicateNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(
      TAlpnProtocols.FromText(TArray<string>.Create('h2', 'http/1.1', 'h2')));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a duplicate ALPN protocol name is refused');
end;

procedure TTestConfigBuilder.TestAlpnEmptyListMeansNoAlpn;
var
  LConfig: ITlsClientConfig;
  LNone: TArray<TBytes>;
begin
  LNone := nil;
  LConfig := NewClientBuilder.WithAlpnProtocols(LNone).Build;
  CheckEquals(0, System.Length(LConfig.AlpnProtocols), 'an empty list configures no ALPN');
end;

procedure TTestConfigBuilder.TestAlpnSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<TBytes>;
begin
  LList := TArray<TBytes>.Create(TAlpnProtocols.H2);
  LConfig := NewClientBuilder.WithAlpnProtocols(LList).Build;
  // neither replacing a name nor changing an octet of the caller's arrays may reach the config
  LList[0][0] := Ord('x');
  LList[0] := nil;
  CheckEquals(1, System.Length(LConfig.AlpnProtocols), 'the ALPN list is preserved');
  CheckEqualBytes('the ALPN list is a snapshot of the caller array', TAlpnProtocols.H2,
    LConfig.AlpnProtocols[0]);
end;

procedure TTestConfigBuilder.TestRecordSizeLimitDefaultsToUnset;
begin
  CheckEquals(0, NewClientBuilder.Build.RecordSizeLimit,
    'a client offers no record_size_limit by default');
  CheckEquals(0, NewServerBuilder.Build.RecordSizeLimit,
    'a server offers no record_size_limit by default');
end;

procedure TTestConfigBuilder.TestExternalPskInnerBytesAreCopied;
var
  LPsks, LOut: TArray<TExternalPsk>;
  LConfig: ITlsClientConfig;
begin
  // the frozen config must not alias the caller's identity/context buffers
  LPsks := TArray<TExternalPsk>.Create(MakePskSpec);
  LConfig := NewClientBuilder.Tls13.WithExternalPreSharedKeys(LPsks).Build;
  LPsks[0].Identity[0] := $FF;
  LOut := LConfig.ExternalPsks;
  CheckEquals($61, LOut[0].Identity[0],
    'a caller mutating its identity bytes after Build does not change the config');
  LOut[0].Identity[0] := $EE;
  LOut := LConfig.ExternalPsks;
  CheckEquals($61, LOut[0].Identity[0], 'the accessor returns a copy');
end;

procedure TTestConfigBuilder.TestNilClockIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithClock(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil clock is a typed error, not a silent default');
end;

procedure TTestConfigBuilder.TestNilMonotonicClockIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithMonotonicClock(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil monotonic clock is a typed error on a client builder');
  LRaised := False;
  try
    NewServerBuilder.WithMonotonicClock(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil monotonic clock is a typed error on a server builder');
end;

procedure TTestConfigBuilder.TestMonotonicClockDefaultsToTheSystemSourceAndIsInjectable;
var
  LClock: ITlsMonotonicClock;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
begin
  CheckTrue(NewClientBuilder.Build.MonotonicClock <> nil, 'a client defaults to a clock');
  CheckTrue(NewServerBuilder.Build.MonotonicClock <> nil, 'a server defaults to a clock');
  LClock := TMockMonotonicClock.Create(42) as ITlsMonotonicClock;
  LClientConfig := NewClientBuilder.WithMonotonicClock(LClock).Build;
  CheckTrue(LClientConfig.MonotonicClock = LClock, 'the client config carries the injected clock');
  LServerConfig := NewServerBuilder.WithMonotonicClock(LClock).Build;
  CheckTrue(LServerConfig.MonotonicClock = LClock, 'the server config carries the injected clock');
end;

procedure TTestConfigBuilder.TestAlpnListBeyondWireLimitIsRefused;
var
  LNames: TArray<string>;
  LI: Int32;
  LRaised: Boolean;
begin
  // 64 names of 255 bytes is exactly 16384 wire bytes, the most the list may take
  SetLength(LNames, 64);
  for LI := 0 to 63 do
    LNames[LI] := Format('%.3d', [LI]) + StringOfChar('a', 252);
  NewClientBuilder.WithAlpnProtocols(TAlpnProtocols.FromText(LNames)).Build;
  // one byte more no longer fits
  LNames[63] := LNames[63] + 'a';
  LRaised := False;
  try
    NewClientBuilder.WithAlpnProtocols(TAlpnProtocols.FromText(LNames));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an ALPN list beyond the cap is refused');
end;

procedure TTestConfigBuilder.TestLargestAlpnListStillEncodesInTheClientHello;
var
  LNames: TArray<string>;
  LClient: ITlsEngine;
  LI: Int32;
begin
  // the cap exists so that every list Build accepts also fits the ClientHello's extensions block
  SetLength(LNames, 64);
  for LI := 0 to 63 do
    LNames[LI] := Format('%.3d', [LI]) + StringOfChar('a', 252);
  LClient := TTlsEngineFactory.CreateClientEngine(
    NewClientBuilder.WithAlpnProtocols(TAlpnProtocols.FromText(LNames)).Build, 'localhost');
  LClient.StartHandshake;
  CheckTrue(System.Length(Drain(LClient)) > 16384, 'the ClientHello carries the whole list');
end;

procedure TTestConfigBuilder.TestServerExternalPskNeedsTls13;
var
  LPsks: TArray<TExternalPsk>;
  LRaised: Boolean;
begin
  LPsks := TArray<TExternalPsk>.Create(MakePskSpec);
  NewServerBuilder.Tls13.WithExternalPreSharedKeys(LPsks).Build;
  LRaised := False;
  try
    NewServerBuilder
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
      .Tls13.WithExternalPreSharedKeys(LPsks).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a TLS 1.2-only server cannot honour external PSKs');
end;

procedure TTestConfigBuilder.TestPskOnlyServerMustOfferTls13Only;
var
  LPsks: TArray<TExternalPsk>;
  LOwner: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LPsks := TArray<TExternalPsk>.Create(MakePskSpec);
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LOwner.Server.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .Tls13.WithExternalPreSharedKeys(LPsks).Build;
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LOwner.Server
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13))
      .Tls13.WithExternalPreSharedKeys(LPsks).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a certificate-less PSK server offering TLS 1.2 is refused');
end;

procedure TTestConfigBuilder.TestTls12NeedsAClassicalEcdheGroup;

  function Accepted(const AGroups, AVersions: TArray<UInt16>): Boolean;
  begin
    Result := True;
    try
      NewClientBuilder.WithSupportedVersions(AVersions).WithPreferredGroups(AGroups).Build;
    except
      on E: EArgumentTlsLibException do
        Result := False;
    end;
  end;

var
  LRaised: Boolean;
begin
  CheckTrue(Accepted(TArray<UInt16>.Create(TNamedGroupCatalog.X25519),
    TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13)),
    'a classical group serves TLS 1.2');
  CheckTrue(Accepted(TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768),
    TArray<UInt16>.Create(TlsWireVersionTls13)), 'a hybrid group serves TLS 1.3 alone');
  CheckFalse(Accepted(TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768),
    TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13)),
    'a hybrid-only preference cannot serve the TLS 1.2 it offers');
  LRaised := False;
  try
    NewServerBuilder.WithSupportedVersions(
      TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13))
      .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768)).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the same refusal applies to a server');
end;

procedure TTestConfigBuilder.TestOneBuilderConfiguresOneEndpoint;
var
  LOwner: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LOwner.Client;
  LRaised := False;
  try
    LOwner.Server;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the server view after the client view is refused');
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LOwner.Server;
  LRaised := False;
  try
    LOwner.Client;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the client view after the server view is refused');
  LOwner.Server;
end;

procedure TTestConfigBuilder.TestPreferredGroupsWithNoRegisteredGroupIsRefused;
var
  LRaised: Boolean;
begin
  NewClientBuilder.WithPreferredGroups(
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519)).Build;
  LRaised := False;
  try
    NewClientBuilder.WithPreferredGroups(TArray<UInt16>.Create($FEFE)).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'preferred groups that are all unregistered are refused at Build');
end;

procedure TTestConfigBuilder.TestEmptyPreferredGroupsIsRefusedAtBuild;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithPreferredGroups(nil).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty preferred-group list is a typed error at Build');
end;

procedure TTestConfigBuilder.TestNilRegistryIsRefusedAtBuild;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewClientBuilder.WithCipherSuites(nil).Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil cipher-suite registry is a typed error at Build');
end;

procedure TTestConfigBuilder.TestCipherSuiteListNarrowsAndOrdersPerProtocol;
var
  LConfig: ITlsClientConfig;
  L12, L13: TArray<UInt16>;
begin
  LConfig := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes256GcmSha384,
      TCipherSuites12.EcdheEcdsaAes128GcmSha256, TCipherSuites13.Aes256GcmSha384))
    .Build;
  L12 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls12);
  L13 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls13);
  CheckEquals(2, System.Length(L12), 'only the listed 1.2 suites remain');
  CheckEquals(TCipherSuites12.EcdheEcdsaAes256GcmSha384, L12[0], 'list order is kept');
  CheckEquals(TCipherSuites12.EcdheEcdsaAes128GcmSha256, L12[1], 'list order is kept');
  CheckEquals(1, System.Length(L13), 'only the listed 1.3 suite remains');
  CheckEquals(TCipherSuites13.Aes256GcmSha384, L13[0], 'the listed 1.3 suite');
end;

procedure TTestConfigBuilder.TestFailedBuildLeavesTheCipherSuiteListInForce;
var
  LBuilder: ITlsClientConfigBuilder;
  LConfig: ITlsClientConfig;
  LRaised: Boolean;
  L13: TArray<UInt16>;
begin
  // a Build refused for another reason must not consume the list: a retry that also swaps in a
  // wider registry still narrows, instead of silently carrying the full set
  LBuilder := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384))
    .WithPreferredGroups(TArray<UInt16>.Create($FFFE));
  LRaised := False;
  try
    LBuilder.Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a preferred group nothing registers is refused');
  LConfig := LBuilder.WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519)).Build;
  L13 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls13);
  CheckEquals(1, System.Length(L13), 'the list is still in force after the failed Build');
  CheckEquals(TCipherSuites13.Aes256GcmSha384, L13[0], 'the listed suite');
end;

procedure TTestConfigBuilder.TestCipherSuiteListLeavesAnUnnamedProtocolIntact;
var
  LConfig: ITlsClientConfig;
  L12, L13: TArray<UInt16>;
begin
  // a list naming only 1.2 suites narrows 1.2 and leaves the 1.3 set as configured
  LConfig := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256))
    .Build;
  L12 := TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls12);
  L13 := TNegotiationPolicy.SuiteOrder(DefaultProfile.CipherSuites, TSuiteProtocol.Tls13);
  CheckEquals(1, System.Length(L12), 'the named protocol is narrowed');
  CheckEquals(TCipherSuites12.EcdheEcdsaAes128GcmSha256, L12[0], 'the listed 1.2 suite');
  CheckTrue(SameOrder(L13,
    TNegotiationPolicy.SuiteOrder(LConfig.CipherSuites, TSuiteProtocol.Tls13)),
    'the unnamed protocol keeps its configured suites and order');
end;

procedure TTestConfigBuilder.TestCipherSuiteListOutsideTheConfiguredSetIsRefused;
var
  LRaised: Boolean;
begin
  // the list narrows and reorders; it never admits a suite the configured set does not hold
  LRaised := False;
  try
    NewClientBuilder
      .WithCipherSuiteList(TArray<UInt16>.Create(UInt16($002F)))
      .Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a suite outside the configured set is refused at Build');
end;

procedure TTestConfigBuilder.TestCipherSuiteListIsIndependentOfCallOrder;
var
  LBefore, LAfter: ITlsClientConfig;
  LList: TArray<UInt16>;
begin
  LList := TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes256GcmSha384,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  LBefore := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCipherSuiteList(LList)
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .Build;
  LAfter := NewClientBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .WithCipherSuiteList(LList)
    .Build;
  CheckTrue(SameOrder(
    TNegotiationPolicy.SuiteOrder(LBefore.CipherSuites, TSuiteProtocol.Tls12),
    TNegotiationPolicy.SuiteOrder(LAfter.CipherSuites, TSuiteProtocol.Tls12)),
    'the list applies at Build, whichever order the setters ran in');
end;

procedure TTestConfigBuilder.TestInjectedVerifierRefusesSettingsItIgnores;
  function ClientRefused(const ABuilder: ITlsClientConfigBuilder): Boolean;
  begin
    Result := False;
    try
      ABuilder.Build;
    except
      on E: EInvalidOperationTlsLibException do
        Result := Pos('injected certificate verifier', E.Message) > 0;
    end;
  end;

  function ServerRefused(const ABuilder: ITlsServerConfigBuilder): Boolean;
  begin
    Result := False;
    try
      ABuilder.Build;
    except
      on E: EInvalidOperationTlsLibException do
        Result := Pos('injected certificate verifier', E.Message) > 0;
    end;
  end;

  function NewVerifierServer: ITlsServerConfigBuilder;
  begin
    Result := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required).WithDangerousCertificateVerifier(
      TAcceptAllClientVerifier.Create as IClientCertificateVerifier);
  end;

  function NewVerifierClient: ITlsClientConfigBuilder;
  begin
    Result := TTlsPresets.Compatible(Crypto, Pkix).Client.WithDangerousCertificateVerifier(
      TAcceptAllServerVerifier.Create as IServerCertificateVerifier);
  end;

begin
  // a whole-verifier replaces the built-in verification, so the settings only that verification
  // reads are refused instead of being accepted and ignored
  CheckTrue(ClientRefused(NewVerifierClient.WithIntermediateCertificates(EcP256RootCertificate)),
    'intermediates beside a verifier instance');
  CheckTrue(ClientRefused(NewVerifierClient.WithDangerousInsecureSkipVerify),
    'skip-verify beside a verifier instance');
  CheckTrue(ClientRefused(NewVerifierClient.WithRevocation(TRevocationPosture.Hard)),
    'Hard revocation beside a verifier instance without a live verdict');
  // controls: the verifier alone builds, and Hard builds when a live verdict applies it
  CheckTrue(ClientRefused(NewVerifierClient.WithRevocation(TRevocationPosture.Hard)
    .WithOcspStaplingRequest(True)), 'stapling does not rescue Hard beside a verifier instance');
  // the server-role mirror
  CheckTrue(ServerRefused(NewVerifierServer.WithDangerousInsecureSkipVerify),
    'skip-verify beside a client-certificate verifier instance');
  CheckTrue(ServerRefused(NewVerifierServer.WithIntermediateCertificates(EcP256RootCertificate)),
    'intermediates beside a client-certificate verifier instance');
  CheckTrue(ServerRefused(NewVerifierServer.WithRevocation(TRevocationPosture.Hard)),
    'Hard revocation beside a client-certificate verifier instance');
  CheckTrue(NewVerifierServer.Build <> nil, 'control: the client-certificate verifier alone builds');
  CheckTrue(NewVerifierClient.Build <> nil, 'control: the verifier alone builds');
  CheckTrue(NewVerifierClient.WithRevocation(TRevocationPosture.Hard)
    .WithLiveRevocationVerdict(1000).Build <> nil, 'control: Hard with a live verdict builds');
end;

function TTestConfigBuilder.ClientBuildNeedsTls13(const AFacet: ITls13ClientConfigFacet): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    // the reason is checked too, so a case cannot pass on some unrelated refusal
    on E: EInvalidOperationTlsLibException do
      Result := Pos('TLS 1.3 settings', E.Message) > 0;
  end;
end;

function TTestConfigBuilder.ServerBuildNeedsTls13(const AFacet: ITls13ServerConfigFacet): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos('TLS 1.3 settings', E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const ABuilder: ITlsClientConfigBuilder;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    ABuilder.Build;
  except
    // the reason is checked too, so a case cannot pass on some unrelated refusal
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const ABuilder: ITlsServerConfigBuilder;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    ABuilder.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const AFacet: ITls13ServerConfigFacet;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

function TTestConfigBuilder.BuildRefused(const AFacet: ITls12ServerConfigFacet;
  const AReason: string): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EInvalidOperationTlsLibException do
      Result := Pos(AReason, E.Message) > 0;
  end;
end;

procedure TTestConfigBuilder.TestTls13SettingsAreRefusedWhenTls13IsNotOffered;
var
  LOnly12: TArray<UInt16>;
begin
  // GREASE, the ticket count and the PSK settings are read only by the TLS 1.3 machines; set on a
  // TLS 1.2-only config they would silently do nothing, so the Tls13 facet refuses them at Build
  LOnly12 := TArray<UInt16>.Create(TlsWireVersionTls12);
  CheckTrue(ClientBuildNeedsTls13(NewClientBuilder.WithSupportedVersions(LOnly12)
    .Tls13.WithGrease(False)), 'turning GREASE off on a TLS 1.2-only client');
  CheckTrue(ClientBuildNeedsTls13(NewClientBuilder.WithSupportedVersions(LOnly12)
    .Tls13.WithExternalPskRequired(False)),
    'the PSK-required switch alone, with no PSKs, on a TLS 1.2-only client');
  CheckTrue(ServerBuildNeedsTls13(NewServerBuilder.WithSupportedVersions(LOnly12)
    .Tls13.WithTicketCount(3)), 'a ticket count on a TLS 1.2-only server');
  // restating a default is not a setting: the facet counts as configured only by a non-default value
  CheckTrue(NewClientBuilder.WithSupportedVersions(LOnly12).Tls13.WithGrease(True).Build <> nil,
    'restating the GREASE default on a TLS 1.2-only client is not refused');
  CheckTrue(NewServerBuilder.WithSupportedVersions(LOnly12).Tls13.WithTicketCount(2).Build <> nil,
    'restating the default ticket count on a TLS 1.2-only server is not refused');
  CheckTrue(NewClientBuilder.WithSupportedVersions(LOnly12).Tls13.WithEchGrease(False).Build <> nil,
    'ECH GREASE left off on a TLS 1.2-only client is not refused');
  // controls: the same client and server build once TLS 1.3 is offered, or when no Tls13 setting
  // was touched
  CheckTrue(NewClientBuilder.WithSupportedVersions(LOnly12).Build <> nil,
    'control: a TLS 1.2-only client without Tls13 settings builds');
  CheckTrue(NewServerBuilder.WithSupportedVersions(
    TArray<UInt16>.Create(TlsWireVersionTls13)).Tls13.WithTicketCount(2).Build.TicketCount = 2,
    'control: the ticket count builds with TLS 1.3');
end;

procedure TTestConfigBuilder.TestEmptyCipherSuiteListIsRefused;
var
  LRaised: Boolean;
begin
  // an empty list must not read as "no list", which would leave the preset's full set in force
  LRaised := False;
  try
    NewClientBuilder.WithCipherSuiteList(nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty cipher-suite list is a typed error');
end;

procedure TTestConfigBuilder.TestOfferedVersionWithoutASuiteIsRefused;
var
  LRaised: Boolean;
begin
  // a 1.3-only registry cannot back an offered TLS 1.2
  LRaised := False;
  try
    NewClientBuilder
      .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
      .Build;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an offered version with no cipher suite is refused at Build');
end;

function TTestConfigBuilder.HelloSuites(const AWire: TBytes): TArray<UInt16>;
var
  LPos, LCount, LI: Int32;
begin
  // record header 5, handshake header 4, legacy_version 2, random 32, session id, cipher_suites
  LPos := 5 + 4 + 2 + 32;
  LPos := LPos + 1 + AWire[LPos];
  LCount := ((AWire[LPos] shl 8) or AWire[LPos + 1]) div 2;
  Inc(LPos, 2);
  SetLength(Result, LCount);
  for LI := 0 to LCount - 1 do
    Result[LI] := UInt16((AWire[LPos + 2 * LI] shl 8) or AWire[LPos + 2 * LI + 1]);
end;

procedure TTestConfigBuilder.TestSingleVersionHelloAdvertisesOnlyThatVersionsSuites;
var
  LSuites: TArray<UInt16>;
  LI: Int32;
  LHas13, LHas12: Boolean;
  LClient: ITlsEngine;
begin
  // a dual-version registry offered to a TLS 1.3-only client: no TLS 1.2 suite goes on the wire
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13)).Build, 'localhost');
  LClient.StartHandshake;
  LSuites := HelloSuites(Drain(LClient));
  LHas13 := False;
  LHas12 := False;
  for LI := 0 to System.High(LSuites) do
    if (LSuites[LI] shr 8) = $13 then
      LHas13 := True
    // a GREASE value and the signalling suite values (RFC 8701, RFC 5746, RFC 7507) are not suites
    else if ((LSuites[LI] and $0F0F) <> $0A0A) and (LSuites[LI] <> $00FF) and
      (LSuites[LI] <> $5600) then
      LHas12 := True;
  CheckTrue(LHas13, 'a TLS 1.3 suite is advertised');
  CheckFalse(LHas12, 'no TLS 1.2 suite is advertised to a TLS 1.3-only client');

  // and the reverse: a TLS 1.2-only client advertises no TLS 1.3 suite
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder
    .WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12)).Build, 'localhost');
  LClient.StartHandshake;
  LSuites := HelloSuites(Drain(LClient));
  LHas13 := False;
  for LI := 0 to System.High(LSuites) do
    if (LSuites[LI] shr 8) = $13 then
      LHas13 := True;
  CheckFalse(LHas13, 'no TLS 1.3 suite is advertised to a TLS 1.2-only client');
  CheckTrue(System.Length(LSuites) > 0, 'a TLS 1.2 hello still lists suites');
end;

procedure TTestConfigBuilder.TestResumptionSettingsAreRefusedWhenResumptionIsOff;
begin
  // a setting that only matters when resuming is refused with resumption off, in either order
  CheckTrue(BuildRefused(NewClientBuilder.WithResumption(False)
    .WithSessionCache(TInMemorySessionCache.Create), 'resumption is off'), 'a session cache');
  CheckTrue(BuildRefused(NewClientBuilder.WithSessionCache(TInMemorySessionCache.Create)
    .WithResumption(False), 'resumption is off'),
    'a session cache set before resumption was turned off');
  CheckTrue(BuildRefused(NewClientBuilder.WithResumption(False)
    .WithResumptionScope(Crypto.Primitives.GetRandom.GenerateBytes(8)), 'resumption is off'),
    'a client scope');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False)
    .WithSessionStore(TInMemorySessionStore.Create(Crypto.Primitives.GetRandom)),
    'resumption is off'), 'a session store');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False).WithTicketLifetime(600),
    'resumption is off'), 'a ticket lifetime');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False).Tls13.WithTicketCount(1),
    'resumption is off'), 'a ticket count');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False)
    .WithResumptionScope(Crypto.Primitives.GetRandom.GenerateBytes(8)), 'resumption is off'),
    'a server scope');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False).WithDefaultSessionTicketKeys,
    'resumption is off'), 'default ticket keys');
  CheckTrue(BuildRefused(NewServerBuilder.WithResumption(False)
    .Tls12.WithNonEmsResumption(TNonEmsResumption.Resume), 'resumption is off'),
    'a non-EMS resumption mode');
  // restating a default is not a setting
  CheckTrue(NewServerBuilder.WithResumption(False).WithTicketLifetime(7200)
    .Tls13.WithTicketCount(2).Build <> nil, 'the default ticket settings build with resumption off');
  // controls: nothing supplied builds, and the same settings build with resumption on
  CheckTrue(NewClientBuilder.WithResumption(False).Build <> nil,
    'resumption off alone builds for a client');
  CheckTrue(NewServerBuilder.WithResumption(False).Build <> nil,
    'resumption off alone builds for a server');
  CheckTrue(NewServerBuilder.WithTicketLifetime(600).Tls13.WithTicketCount(1).Build <> nil,
    'ticket settings build with resumption on');
end;

procedure TTestConfigBuilder.TestAlpnRejectionWithProtocolsIsRefused;
begin
  // rejecting every ALPN offer contradicts a list of protocols to select from
  CheckTrue(BuildRefused(NewServerBuilder.WithAlpnRejection(True)
    .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2)), 'ALPN rejection'),
    'rejection with a list');
  CheckTrue(NewServerBuilder.WithAlpnRejection(True).Build <> nil,
    'rejection alone builds');
  CheckTrue(NewServerBuilder.WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2)).Build <> nil,
    'a list alone builds');
end;

procedure TTestConfigBuilder.TestServerCipherSuiteListOrderDecidesTheNegotiatedSuite;
var
  LClient, LServer: ITlsEngine;
begin
  // the host's order is the server's preference whatever the hardware would otherwise favour
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder.Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites13.ChaCha20Poly1305Sha256,
      TCipherSuites13.Aes128GcmSha256)).Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the handshake completed');
  CheckEquals(TCipherSuites13.ChaCha20Poly1305Sha256, LServer.ConnectionInfo.CipherSuite,
    'the first listed suite is negotiated');
end;

procedure TTestConfigBuilder.TestClientCipherSuiteListIsTheOnlyOfferedSuite;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384)).Build,
    'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the handshake completed');
  CheckEquals(TCipherSuites13.Aes256GcmSha384, LServer.ConnectionInfo.CipherSuite,
    'the one listed suite is negotiated');
end;

procedure TTestConfigBuilder.TestRecordSizeLimitRoundTrips;
begin
  CheckEquals(512, NewClientBuilder.WithRecordSizeLimit(512).Build.RecordSizeLimit,
    'the client record_size_limit reaches the frozen config');
  CheckEquals(512, NewServerBuilder.WithRecordSizeLimit(512).Build.RecordSizeLimit,
    'the server record_size_limit reaches the frozen config');
end;

procedure TTestConfigBuilder.TestRecordSizeLimitRejectsOutOfRange;

  function Refused(ALimit: Int32): Boolean;
  begin
    Result := False;
    try
      NewClientBuilder.WithRecordSizeLimit(ALimit);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  // RFC 8449 4: 64 is the minimum; 16384 is the library's cap, legal under both 1.2 (2^14) and
  // 1.3 (2^14+1); 0 opts out
  CheckTrue(Refused(63), 'a record_size_limit below 64 is refused');
  CheckTrue(Refused(16385), 'a record_size_limit above 16384 is refused');
  CheckFalse(Refused(0), 'a record_size_limit of 0 (opt out) is accepted');
  CheckFalse(Refused(64), 'the 64-byte minimum is accepted');
  CheckFalse(Refused(16384), 'the 16384-byte maximum is accepted');
end;

procedure TTestConfigBuilder.TestRecordSizeLimitCapsRecordsThroughFactory;
var
  LClient, LServer: ITlsEngine;
  LPayload, LWire, LReceived: TBytes;
  LI, LPos, LLen, LMax, LCount: Int32;
begin
  // the builder's record_size_limit must reach the record layer through the factory: both peers
  // advertise 512, so a 2000-byte write fragments into several records none past the plaintext cap
  LClient := TTlsEngineFactory.CreateClientEngine(
    NewClientBuilder.WithRecordSizeLimit(512).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(
    NewServerBuilder.WithRecordSizeLimit(512).Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');

  LPayload := nil;
  SetLength(LPayload, 2000);
  for LI := 0 to System.Length(LPayload) - 1 do
    LPayload[LI] := Byte(LI and $FF);
  LClient.Write(LPayload, 0, System.Length(LPayload));
  LWire := Drain(LClient);

  // walk the TLSCiphertext records (5-byte header + length) the write produced
  LMax := 0;
  LCount := 0;
  LPos := 0;
  while LPos + 5 <= System.Length(LWire) do
  begin
    LLen := (LWire[LPos + 3] shl 8) or LWire[LPos + 4];
    Inc(LCount);
    if LLen > LMax then
      LMax := LLen;
    Inc(LPos, 5 + LLen);
  end;
  // a 512-byte plaintext cap => ciphertext <= 511 content + 1 type + 16 tag = 528
  CheckTrue(LMax <= 528, 'no record exceeds the negotiated cap when set through the builder');
  CheckTrue(LCount > 1, 'the oversize write fragmented into several records');

  Feed(LServer, LWire);
  LReceived := ReadAllApp(LServer);
  CheckEqualBytes('the server reassembles the fragmented payload', LPayload, LReceived);
end;

procedure TTestConfigBuilder.TestPreferredGroupsSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<UInt16>;
begin
  LList := TArray<UInt16>.Create(TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1);
  LConfig := NewClientBuilder.WithPreferredGroups(LList).Build;
  LList[0] := TNamedGroupCatalog.Secp384r1; // mutating the caller's array must not reach the config
  CheckEquals(2, System.Length(LConfig.PreferredGroups), 'the preferred-group list is preserved');
  CheckEquals(TNamedGroupCatalog.X25519, LConfig.PreferredGroups[0],
    'the preferred-group list is a snapshot of the caller array');
end;

procedure TTestConfigBuilder.TestCertificateCompressorsSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<ICertificateCompressor>;
begin
  LList := TZlibCertificateCompression.DefaultCompressors;
  CheckTrue(System.Length(LList) > 0, 'there is at least one default compressor to snapshot');
  LConfig := NewClientBuilder.Tls13.WithCertificateCompressors(LList).Build;
  LList[0] := nil; // mutating the caller's array must not reach the config
  CheckTrue(LConfig.CertificateCompressors[0] <> nil,
    'the compressor list is a snapshot of the caller array');
end;

procedure TTestConfigBuilder.TestCertificateDecompressorsSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<ICertificateDecompressor>;
begin
  LList := TZlibCertificateCompression.DefaultDecompressors;
  CheckTrue(System.Length(LList) > 0, 'there is at least one default decompressor to snapshot');
  LConfig := NewClientBuilder.Tls13.WithCertificateDecompressors(LList).Build;
  LList[0] := nil; // mutating the caller's array must not reach the config
  CheckTrue(LConfig.CertificateDecompressors[0] <> nil,
    'the decompressor list is a snapshot of the caller array');
end;

procedure TTestConfigBuilder.TestRawBuilderWithoutVersionsIsRefusedAtBuild;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
  LMsg: string;
begin
  // a builder that never called WithSupportedVersions cannot build a machine
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  LMsg := '';
  try
    LBuilder.Server
      .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
      .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
      .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
      .WithCredential(ServerCredential)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
    begin
      LRaised := True;
      LMsg := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'a build with no offered versions is refused');
  CheckTrue(Pos('must be offered', LMsg) > 0,
    'the message names the missing offered versions');
end;

function TTestConfigBuilder.Drain(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  Result := nil;
  SetLength(LChunk, 65536);
  repeat
    LGot := AEngine.TakeOutgoing(LChunk, 0);
    if LGot > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LGot));
  until LGot = 0;
end;

procedure TTestConfigBuilder.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
var
  LPos, LLen: Int32;
begin
  // one record at a time, so a key-epoch install takes effect before the next record
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    AEngine.ProcessInput(AWire, LPos, 5 + LLen);
    Inc(LPos, 5 + LLen);
  end;
end;

procedure TTestConfigBuilder.RunHandshake(const AClient, AServer: ITlsEngine);
begin
  AClient.StartHandshake;
  ExchangeFlights(AClient, AServer);
end;

procedure TTestConfigBuilder.ExchangeFlights(const AClient, AServer: ITlsEngine);
var
  LIterations: Int32;
begin
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Feed(AServer, Drain(AClient));
    Feed(AClient, Drain(AServer));
    Inc(LIterations);
  end;
end;

function TTestConfigBuilder.ReadAllApp(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  Result := nil;
  SetLength(LChunk, 65536);
  repeat
    LGot := AEngine.ReadAppData(LChunk, 0, System.Length(LChunk));
    if LGot > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LGot));
  until LGot = 0;
end;

procedure TTestConfigBuilder.TestBuilderRejectsMutationAfterBuild;
var
  LClient: ITlsClientConfigBuilder;
  LRaised: Boolean;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LClient.WithTrustStore(ClientTrust);
  LClient.Build;
  LRaised := False;
  try
    LClient.WithDangerousDisableServerNameCheck;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a built configuration rejects further mutation');
end;

procedure TTestConfigBuilder.TestSecondBuildIsRejected;
var
  LClient: ITlsClientConfigBuilder;
  LRaised: Boolean;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LClient.WithTrustStore(ClientTrust);
  LClient.Build;
  LRaised := False;
  try
    LClient.Build; // a builder is single-use
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a second Build on the same builder is rejected');
end;

procedure TTestConfigBuilder.TestReturnedPinsArrayCannotMutateConfig;
var
  LConfig: ITlsClientConfig;
  LPin, LOther: TBytes;
  LPins: TArray<TBytes>;
begin
  LPin := DecodeHex(
    '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  LOther := DecodeHex(
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust)
    .WithCertificatePinning(TArray<TBytes>.Create(LPin))
    .Build;
  // neither reassigning an element nor mutating an inner byte of the returned array
  // may reach the frozen field (the getter deep-copies)
  LPins := LConfig.CertificatePins;
  LPins[0][0] := LPins[0][0] xor $FF;
  LPins[0] := LOther;
  CheckEqualBytes('the frozen config keeps its pin after the returned array is mutated',
    LPin, LConfig.CertificatePins[0]);
end;

procedure TTestConfigBuilder.TestWithCertificatePinningRejectsWrongLengthPin;
var
  LRaised: Boolean;
begin
  // a pin that is not a 32-byte SHA-256 SubjectPublicKeyInfo digest can never match; the builder
  // refuses it rather than let it silently fail every handshake
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithCertificatePinning(TArray<TBytes>.Create(DecodeHex('00112233')));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-32-byte certificate pin is refused at configuration time');
end;

procedure TTestConfigBuilder.TestClientConfigRequiresTrustStore;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Client.Build; // no trust source set
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client config without a trust source is refused');
end;

function TTestConfigBuilder.MakePskSpec: TExternalPsk;
begin
  Result.Identity := TBytes.Create($61, $62);
  Result.Secret := TSecretBuffer.From(TBytes.Create($00, $11, $22, $33, $44, $55, $66, $77,
    $88, $99, $AA, $BB, $CC, $DD, $EE, $FF));
  Result.Context := nil;
  Result.Hash := THashAlgorithm.SHA_256;
end;

procedure TTestConfigBuilder.TestPskOnlyClientOfferingTls12IsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // a PSK-only client (no trust source) that still offers TLS 1.2 could be selected onto the
  // certificate path with nothing to verify against - refused at Build
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Client.Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a PSK-only client offering TLS 1.2 is refused');
end;

procedure TTestConfigBuilder.TestPskOnlyClientWithPskOptionalIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // PSK optional + no trust source means a non-PSK ServerHello falls through to the certificate
  // path with nothing to verify - refused at Build
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Client.Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec))
      .WithExternalPskRequired(False).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a PSK-optional client without a trust source is refused');
end;

procedure TTestConfigBuilder.TestPskOnlyTls13ClientBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // a required-PSK, TLS 1.3-only client with no trust source is the legitimate PSK-only case
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
  CheckTrue(LConfig <> nil, 'a required-PSK TLS 1.3-only client builds without a trust source');
end;

procedure TTestConfigBuilder.TestServerConfigRequiresCredential;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Server.Build; // no credential set
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a server config without a credential is refused');
end;

procedure TTestConfigBuilder.TestServerClientAuthRequiresTrustStore;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // requesting client certificates needs a trust source to verify the chain against;
  // absent one, building must fail fast rather than only failing closed at handshake
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix);
  LRaised := False;
  try
    LBuilder.Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .Build; // client auth on, but no trust source set
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client-auth server without a trust source is refused');
end;

procedure TTestConfigBuilder.TestClientEmptyTrustStoreIsRefused;
var
  LMsg: string;
begin
  // a store object is not a trust source; a store with no roots would "verify" against nothing
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('no root certificates', LMsg) > 0,
    'an empty trust store is refused as not-a-source; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestClientUnionOfEmptyStoresIsRefused;
var
  LUnion: ITrustAnchorStore;
  LMsg: string;
begin
  // a single union store whose children are all empty still yields zero roots: refused, not hidden
  LUnion := TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore,
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore));
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client.WithTrustStore(LUnion).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('no root certificates', LMsg) > 0,
    'a union of empty stores has no roots and is refused; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestClientEmptyStoreUnionedWithRealRootBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // an empty store adds no roots, but a real root alongside it still satisfies the gate
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
    .WithTrustStore(ClientTrust).Build;
  CheckEquals(1, System.Length(LConfig.TrustStore.RootCertificates),
    'the union carries the one real root; the empty store contributes none');
end;

procedure TTestConfigBuilder.TestClientInsecureSkipVerifyBuildsWithoutTrustStore;
var
  LConfig: ITlsClientConfig;
begin
  // Compatible offers 1.3+1.2 and no PSK, so this also proves PSK-only steering does not misfire
  // for a skip-verify client (its certificate path exists and deliberately verifies nothing)
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithDangerousInsecureSkipVerify.Build;
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify, 'the loud skip flag is set');
  CheckNull(LConfig.TrustStore, 'skip-verify composes no anchor store');
end;

procedure TTestConfigBuilder.TestClientInsecureSkipVerifyWithEmptyStoreBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // an empty store alongside explicit skip-verify is tolerated: the store is inert (never consulted)
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithDangerousInsecureSkipVerify
    .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build;
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify,
    'skip-verify with an empty store still builds');
end;

procedure TTestConfigBuilder.TestPskClientWithEmptyStoreIsSteeredAsPskOnly;
var
  LRaised: Boolean;
begin
  // an empty store yields no roots, so a PSK client with no real trust is steered PSK-only and
  // refused for offering 1.2 - not left to reach the certificate path with nothing to verify
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
      .Tls13.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a PSK client whose only "trust" is an empty store is steered PSK-only');
end;

procedure TTestConfigBuilder.TestServerClientAuthEmptyTrustStoreIsRefused;
var
  LMsg: string;
begin
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('no root certificates', LMsg) > 0,
    'a client-auth server with an empty trust store is refused; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestServerClientAuthInsecureSkipVerifyBuildsWithoutTrustStore;
var
  LConfig: ITlsServerConfig;
begin
  // explicit skip-verify satisfies the client-auth trust-source requirement on its own
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithDangerousInsecureSkipVerify.Build;
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify,
    'a client-auth server with skip-verify builds without a trust store');
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithoutAnchorsIsRefused;
var
  LMsg: string;
begin
  // a client verifier source has nothing to consume without anchors: refused at Build, not deferred
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithCertificateVerifierSource(
        TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('verifier source', LMsg) > 0,
    'a client verifier source without anchors is refused with its own message; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithEmptyStoreIsRefused;
var
  LMsg: string;
begin
  // an empty store gives the source nothing to consume: the source message wins over SEmptyTrustStore
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithCertificateVerifierSource(
        TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource)
      .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('verifier source', LMsg) > 0,
    'a source with an empty store is refused with the source message; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithAnchorsBuilds;
var
  LConfig: ITlsServerConfig;
  LSource: IClientCertificateVerifierSource;
begin
  // the composition promise: a source alongside real anchors builds, and the anchors survive
  LSource := TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithCertificateVerifierSource(LSource)
    .WithTrustStore(ClientTrust).Build;
  CheckTrue(LConfig.ClientVerifierSource = LSource, 'the custom source is installed');
  CheckEquals(1, System.Length(LConfig.TrustStore.RootCertificates),
    'the client-CA anchors survive alongside the source');
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithEmptyStoreAndRealRootBuilds;
var
  LConfig: ITlsServerConfig;
begin
  // the gate is roots-based, not store-count: an empty store plus a real root satisfies the source
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithCertificateVerifierSource(
      TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource)
    .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
    .WithTrustStore(ClientTrust).Build;
  CheckTrue(LConfig <> nil, 'a source with an empty store unioned with a real root builds');
end;

function TTestConfigBuilder.ServerBuildIsRefused(const ABuilder: ITlsServerConfigBuilder): Boolean;
begin
  Result := False;
  try
    ABuilder.Build;
  except
    // the reason is checked too, so a case cannot pass on some earlier, unrelated refusal
    on E: EInvalidOperationTlsLibException do
      Result := Pos('WithPeerAuth', E.Message) > 0;
  end;
end;

procedure TTestConfigBuilder.TestServerVerifierSourceWithoutPeerAuthIsRefused;
begin
  // client auth is off, so the source would be ignored and clients admitted unauthenticated
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithCertificateVerifierSource(
      TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource)),
    'a client verifier source without WithPeerAuth is refused');
end;

procedure TTestConfigBuilder.TestServerTrustInputsWithoutPeerAuthAreRefused;
begin
  // each client-certificate trust input is inert on a server that requests no client certificate,
  // so it is refused rather than accepted and ignored
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithTrustStore(ClientTrust)), 'a trust store');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithCertificatePinning(TArray<TBytes>.Create(Crypto.Primitives.GetRandom.GenerateBytes(32)))),
    'a certificate pin');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithCertificateVerifyCallback(RejectEveryChain)),
    'a verify callback');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithDangerousInsecureSkipVerify),
    'skip-verify on its own');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithClientCertificateAuthorities(
      TArray<TBytes>.Create(Crypto.Primitives.GetRandom.GenerateBytes(16)))),
    'a client-CA list');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithLiveRevocationVerdict(1000)), 'a live verdict');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithAsyncCertificateVerdict(1000)), 'an async verdict');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithTrustAnchors(EcP256RootCertificate)),
    'trust anchors given as a certificate');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithIntermediateCertificates(EcP256RootCertificate)),
    'intermediate certificates');
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithDangerousCertificateVerifier(
      TAcceptAllClientVerifier.Create as IClientCertificateVerifier)), 'a verifier instance');
  // control: the same trust store builds once the server requests client certificates
  CheckTrue(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithTrustStore(ClientTrust)
    .WithPeerAuth(TClientAuthMode.Requested).Build <> nil, 'control: with WithPeerAuth');
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithSkipVerifyBuilds;
var
  LConfig: ITlsServerConfig;
begin
  // the skip-verify exemption applies uniformly: the gate does not require anchors. Skip-verify is
  // NOT bypassed into a custom source though - the source still decides at handshake (so with no
  // anchors an OS source would still reject); this only locks that Build permits the combination
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithCertificateVerifierSource(
      TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource)
    .WithDangerousInsecureSkipVerify.Build;
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify,
    'a client verifier source under skip-verify builds');
end;

procedure TTestConfigBuilder.TestServerClientAuthVerifierSourceWithInstanceIsDualVerifier;
var
  LMsg: string;
begin
  // both are custom verifiers: the composition count rejects them before the roots gate is reached
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithDangerousCertificateVerifier(
        TAcceptAllClientVerifier.Create as IClientCertificateVerifier)
      .WithCertificateVerifierSource(
        TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('only one custom', LMsg) > 0,
    'an instance verifier plus a source is the dual-verifier conflict; got: ' + LMsg);
end;

procedure TTestConfigBuilder.TestMtlsServerWithSuppliedTicketKeysRequiresScope;
var
  LRaised: Boolean;
begin
  // a supplied ticket-key manager can be shared across configurations; on a client-auth server
  // that would let a ticket minted under another config's client-CA trust resume here, so a scope
  // is required to partition the tickets
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithTrustStore(ClientTrust)
      .WithSessionTicketKeys(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client-auth server with supplied ticket keys and no scope is refused');
end;

procedure TTestConfigBuilder.TestEarlyDataWithSuppliedTicketKeysNeedsSharedReplayProtection;
var
  LRaised: Boolean;
  LConfig: ITlsServerConfig;
begin
  // an explicit ticket-key manager can be shared across instances, but the default strike
  // register is per configuration, so a replay against another instance would be accepted
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithSessionTicketKeys(TStekTicketKeyManager.Create(
        Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
      .Tls13.WithEarlyData(16384)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('anti-replay', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'early data on supplied ticket keys with no store or anti-replay is refused');
  // naming the anti-replay strategy explicitly takes responsibility for it
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithSessionTicketKeys(TStekTicketKeyManager.Create(
      Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .Tls13.WithEarlyData(16384)
    .WithAntiReplay(TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy)
    .Build;
  CheckTrue(LConfig <> nil, 'an explicit anti-replay strategy builds');
  // a session store makes tickets single-use, so it is the other safe shape
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithSessionTicketKeys(TStekTicketKeyManager.Create(
      Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .WithSessionStore(TInMemorySessionStore.Create(
      Crypto.Primitives.GetRandom) as ISessionStore)
    .Tls13.WithEarlyData(16384)
    .Build;
  CheckTrue(LConfig <> nil, 'a session store makes explicit ticket keys safe for early data');
end;

procedure TTestConfigBuilder.TestServerEarlyDataBudgetIsCappedAtOneMebibyte;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .Tls13.WithEarlyData(1 shl 20);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  // a full allowance of exactly 1 MiB would fill the engine's app-read buffer and stall the
  // handshake before EndOfEarlyData, so the bound is strict
  CheckTrue(LRaised, 'an early-data budget of 1 MiB or more is refused');
  CheckTrue(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Tls13.WithEarlyData((1 shl 20) - 1).Build <> nil, 'just under 1 MiB builds');
end;

procedure TTestConfigBuilder.TestMtlsServerWithSuppliedKeysAndScopeBuilds;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithTrustStore(ClientTrust)
    .WithSessionTicketKeys(TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager)
    .WithResumptionScope(TBytes.Create($73, $63, $6F, $70, $65))
    .Build;
  CheckTrue(LConfig <> nil, 'a client-auth server with supplied keys and an explicit scope builds');
end;

procedure TTestConfigBuilder.TestMtlsServerWithDefaultTicketKeysBuildsWithoutScope;
var
  LConfig: ITlsServerConfig;
begin
  // the per-config default STEK is never shared, so an mTLS server that supplies neither a store
  // nor a key manager needs no scope
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithTrustStore(ClientTrust)
    .Build;
  CheckTrue(LConfig <> nil, 'an mTLS server on the default STEK builds without a scope');
end;

procedure TTestConfigBuilder.TestServerHardClientRevocationWithoutResolverIsRefused;
var
  LRaised: Boolean;
  LMsg: string;
begin
  // a client cannot be asked to staple, so Hard client-cert revocation with no live verdict
  // resolver would reject every client - fail fast at Build
  LRaised := False;
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithTrustStore(ClientTrust)
      .WithRevocation(TRevocationPosture.Hard)
      .Build; // Hard client-cert revocation, but no async resolver
  except
    on E: EInvalidOperationTlsLibException do
    begin
      LRaised := True;
      LMsg := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'a Hard client-cert-revocation server without a resolver is refused');
  CheckTrue(Pos('resolver', LMsg) > 0,
    'the message names the fix (a live verdict resolver)');
end;

procedure TTestConfigBuilder.TestServerHardClientRevocationWithResolverBuilds;
begin
  // with a live-revocation verdict resolver, Hard client-cert revocation is satisfiable - Build
  // succeeds (a host-decision park would not: it does not defer the revocation gate)
  TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithTrustStore(ClientTrust)
    .WithRevocation(TRevocationPosture.Hard)
    .WithLiveRevocationVerdict(0)
    .Build;
  Check(True, 'a Hard client-cert-revocation server with a resolver builds');
end;

procedure TTestConfigBuilder.TestServerHardClientRevocationHostDecisionIsRefused;
var
  LRaised: Boolean;
begin
  // a host-decision park does not defer the revocation gate, so it does not satisfy Hard mTLS
  // (only a live-revocation resolver does) - Build must still refuse
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(ServerCredential)
      .WithPeerAuth(TClientAuthMode.Required)
      .WithTrustStore(ClientTrust)
      .WithRevocation(TRevocationPosture.Hard)
      .WithAsyncCertificateVerdict(0)
      .Build;
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a host-decision park does not satisfy Hard client-cert revocation');
end;

procedure TTestConfigBuilder.TestServerHardRevocationWithoutClientAuthIsRefused;
begin
  // with no client authentication there is no client certificate to check, so a Hard posture
  // would be ignored
  CheckTrue(ServerBuildIsRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithRevocation(TRevocationPosture.Hard)),
    'Hard revocation without WithPeerAuth is refused');
end;

procedure TTestConfigBuilder.TestClientHardHostDecisionWithoutStapleIsRefused;
var
  LRaised: Boolean;
begin
  // a Hard client with neither a staple request nor a live-revocation resolver always-rejects;
  // a host-decision park does not defer the revocation gate, so it does not rescue this
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithTrustStore(ClientTrust)
      .WithRevocation(TRevocationPosture.Hard)
      .WithAsyncCertificateVerdict(0)
      .Build;
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a Hard client with only a host-decision park is refused');
end;

procedure TTestConfigBuilder.TestClientHardLiveRevocationBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // a live-revocation resolver satisfies a Hard client with no staple request, and the frozen
  // config carries the LiveRevocation deferral
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust)
    .WithRevocation(TRevocationPosture.Hard)
    .WithLiveRevocationVerdict(0)
    .Build;
  CheckEquals(Ord(TVerdictDeferral.LiveRevocation),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'the frozen config carries the live-revocation deferral');
end;

procedure TTestConfigBuilder.TestAsyncVerdictMapsToHostDecision;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust)
    .WithAsyncCertificateVerdict(0)
    .Build;
  CheckEquals(Ord(TVerdictDeferral.HostDecision),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'WithAsyncCertificateVerdict enables the host-decision deferral');
end;

procedure TTestConfigBuilder.TestFacadeDrivesLoopback;
var
  LClient, LServer: ITlsEngine;
  LFromClient: TBytes;
begin
  // build the config once via the facade, then create an engine per connection through the factory
  // the facade always builds on the portable provider, so its key must come from that provider
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsLib.NewClientConfig(ClientTrust), 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsLib.NewServerConfig(
    ServerCredential(TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable))));
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the facade client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the facade server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');

  LFromClient := DecodeHex('66616361646520617070206461746121'); // "facade app data!"
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Feed(LServer, Drain(LClient));
  CheckEqualBytes('application data flows over the facade-built connection',
    LFromClient, ReadAllApp(LServer));
end;

procedure TTestConfigBuilder.TestCustomProviderThreadedThroughRawBuilder;
var
  LCustom: ICryptoProvider;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a caller-supplied provider (a distinct ICryptoProvider wrapping the default),
  // the escape hatch the facade points to: pass your own provider to the builder
  LCustom := TFixedAesProvider.Create(Crypto, True) as ICryptoProvider;
  LClientConfig := BuildClientConfig(LCustom);
  LServerConfig := BuildServerConfig(LCustom);

  // the builder threads the exact provider instance into the frozen configs
  CheckTrue(LClientConfig.Crypto = LCustom,
    'the client config carries the caller''s provider');
  CheckTrue(LServerConfig.Crypto = LCustom,
    'the server config carries the caller''s provider');

  // and engines built from those configs complete a handshake end to end
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the custom-provider client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the custom-provider server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
end;

procedure TTestConfigBuilder.TestDefaultCertificateChainLimitsAreConservative;
var
  LConfig: ITlsClientConfig;
  LLimits: TCertificateChainLimits;
begin
  // an untuned client config carries the conservative web-PKI defaults
  LConfig := BuildClientConfig(Crypto);
  LLimits := LConfig.CertificateChainLimits;
  CheckEquals(1 shl 16, LLimits.MaxCertificateLength, 'default max certificate length');
  CheckEquals(1 shl 16, LLimits.MaxTotalChainLength, 'default max certificate message length');
end;

procedure TTestConfigBuilder.TestCertificateChainLimitsAreConfigurable;
var
  LBuilder: ITlsConfigBuilder;
  LConfig: ITlsClientConfig;
  LCustom, LFrozen: TCertificateChainLimits;
begin
  // a caller can tune the caps; the frozen config carries the tuned values
  LCustom := TCertificateChainLimits.Defaults;
  LCustom.MaxCertificateLength := 1 shl 17;
  LCustom.MaxTotalChainLength := 1 shl 20;
  LCustom.MaxChainCertificates := 32;
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithTrustStore(ClientTrust)
    .WithCertificateChainLimits(LCustom)
    .Build;
  LFrozen := LConfig.CertificateChainLimits;
  CheckEquals(1 shl 17, LFrozen.MaxCertificateLength, 'the tuned certificate length');
  CheckEquals(1 shl 20, LFrozen.MaxTotalChainLength, 'the tuned total chain length');
  CheckEquals(32, LFrozen.MaxChainCertificates, 'the tuned chain entry count');
end;

function TTestConfigBuilder.ChainLimitsAccepted(AMaxCert,
  AMaxTotal: Int32): Boolean;
var
  LLimits: TCertificateChainLimits;
  LBuilder: ITlsConfigBuilder;
begin
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxCertificateLength := AMaxCert;
  LLimits.MaxTotalChainLength := AMaxTotal;
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  Result := True;
  try
    LBuilder.Client.WithCertificateChainLimits(LLimits);
  except
    on E: EArgumentTlsLibException do
      Result := False;
  end;
end;

procedure TTestConfigBuilder.TestInvalidChainEntryCapRejected;

  function Accepted(ACap: Int32): Boolean;
  var
    LLimits: TCertificateChainLimits;
  begin
    LLimits := TCertificateChainLimits.Defaults;
    LLimits.MaxChainCertificates := ACap;
    Result := True;
    try
      TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default)
        .Client.WithCertificateChainLimits(LLimits);
    except
      on E: EArgumentTlsLibException do
        Result := False;
    end;
  end;

begin
  CheckTrue(Accepted(16), 'the default entry cap is accepted');
  CheckTrue(Accepted(1), 'a single-entry cap is accepted');
  CheckTrue(Accepted(255), 'the largest entry cap is accepted');
  CheckFalse(Accepted(0), 'a zero entry cap is rejected');
  CheckFalse(Accepted(256), 'an entry cap above 255 is rejected');
end;

procedure TTestConfigBuilder.TestContradictoryStrengthFloorsRejected;

  function Accepted(AMin, AMax: Int32): Boolean;
  var
    LPolicy: TCertificateStrengthPolicy;
  begin
    LPolicy := TCertificateStrengthPolicy.Defaults;
    LPolicy.MinRsaModulusBits := AMin;
    LPolicy.MaxRsaModulusBits := AMax;
    Result := True;
    try
      TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default)
        .Client.WithMinimumCertificateStrength(LPolicy);
    except
      on E: EArgumentTlsLibException do
        Result := False;
    end;
  end;

begin
  CheckTrue(Accepted(2048, 8192), 'the default floors are accepted');
  CheckTrue(Accepted(3072, 0), 'no maximum is accepted');
  CheckTrue(Accepted(4096, 4096), 'equal floors are accepted');
  CheckFalse(Accepted(0, 8192), 'a non-positive minimum is rejected');
  CheckFalse(Accepted(4096, 2048), 'a maximum below the minimum is rejected');
end;

procedure TTestConfigBuilder.TestInvalidCertificateChainLimitsRejected;
begin
  // a byte budget is validated at build time: broken limits are a misconfiguration
  CheckTrue(ChainLimitsAccepted(1 shl 15, 1 shl 16), 'valid limits are accepted');
  CheckFalse(ChainLimitsAccepted(0, 1 shl 16), 'a non-positive per-certificate cap is rejected');
  CheckFalse(ChainLimitsAccepted(1 shl 15, 0), 'a non-positive message cap is rejected');
  CheckFalse(ChainLimitsAccepted(1 shl 17, 1 shl 16),
    'a per-certificate cap above the message cap is rejected');
  CheckFalse(ChainLimitsAccepted($1000000, $1000000),
    'a message cap past the 16 MiB handshake ceiling is rejected');
end;

function TTestConfigBuilder.DefaultProfile: TTlsConfigProfile;
begin
  Result := TTlsConfigProfile.Default;
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  Result.SignatureSchemes := TSignatureSchemeRegistry.CreateDefault;
  Result.NamedGroups := TNamedGroups.CreateDefaultRegistry(Crypto);
  Result.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
  Result.PreferredGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
end;

function TTestConfigBuilder.SameOrder(const AA, AB: TArray<UInt16>): Boolean;
var
  LI: Int32;
begin
  Result := System.Length(AA) = System.Length(AB);
  if Result then
    for LI := 0 to System.High(AA) do
      if AA[LI] <> AB[LI] then
        Exit(False);
end;

function TTestConfigBuilder.NewClientBuilder: ITlsClientConfigBuilder;
var
  LOwner: ITlsConfigBuilder;
begin
  // a chooser seeded with the shared defaults, narrowed to the client view with a trust source
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  Result := LOwner.Client.WithTrustStore(ClientTrust);
end;

function TTestConfigBuilder.NewServerBuilder: ITlsServerConfigBuilder;
var
  LOwner: ITlsConfigBuilder;
begin
  LOwner := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  TArrayUtilities.Append<ITlsConfigBuilder>(FBuilders, LOwner);
  Result := LOwner.Server.WithCredential(ServerCredential);
end;

procedure TTestConfigBuilder.TestTls13CompressorOverrideLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
  LEmptyComp: TArray<ICertificateCompressor>;
  LEmptyDecomp: TArray<ICertificateDecompressor>;
begin
  // the default carries a compressor; clearing the 1.3 knobs must empty the read side
  LConfig := BuildClientConfig(Crypto);
  CheckTrue(System.Length(LConfig.CertificateCompressors) > 0,
    'the default config carries a compressor');
  CheckTrue(System.Length(LConfig.CertificateDecompressors) > 0,
    'the default config carries a decompressor');

  LEmptyComp := nil;
  LEmptyDecomp := nil;
  LConfig := NewClientBuilder.Tls13
    .WithCertificateCompressors(LEmptyComp)
    .WithCertificateDecompressors(LEmptyDecomp)
    .Build;
  CheckEquals(0, System.Length(LConfig.CertificateCompressors),
    'the .Tls13 compressor override lands in the frozen config');
  CheckEquals(0, System.Length(LConfig.CertificateDecompressors),
    'the .Tls13 decompressor override lands in the frozen config');
end;

procedure TTestConfigBuilder.TestClientBuilderChainBuildsClient;
var
  LConfig: ITlsClientConfig;
begin
  // the client builder chained into the .Tls13 facet, built off the facet
  LConfig := NewClientBuilder.Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors)
    .WithCertificateDecompressors(TZlibCertificateCompression.DefaultDecompressors)
    .Build;
  CheckTrue(LConfig <> nil, 'the client chain builds a client config');
  CheckEquals(TlsWireVersionTls13, LConfig.SupportedVersions[0],
    'the client is TLS 1.3');
  CheckTrue(System.Length(LConfig.CertificateCompressors) > 0,
    'the chained compressors reach the frozen config');
end;

procedure TTestConfigBuilder.TestServerBuilderChainBuildsServer;
var
  LConfig: ITlsServerConfig;
begin
  // both versions offered, then cross from the .Tls13 facet into .Tls12 and build
  LConfig := NewServerBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12))
    .Tls13
    .WithCertificateCompressors(TZlibCertificateCompression.DefaultCompressors)
    .Tls12
    .WithExtendedMasterSecret(True)
    .Build;
  CheckTrue(LConfig <> nil, 'the cross-version chain builds a server config');
  CheckEquals(TlsWireVersionTls13, LConfig.SupportedVersions[0],
    'the server offers TLS 1.3 first');
  CheckTrue(LConfig.RequireExtendedMasterSecret,
    'the .Tls12 knob reaches the frozen config');
end;

procedure TTestConfigBuilder.TestVersionFacetForUnofferedVersionIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // configuring a TLS 1.2-only setting on a config that does not offer TLS 1.2 must be
  // refused at build rather than silently ignored - the setting could never apply
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Server
      .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
      .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
      .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
      .WithCredential(ServerCredential)
      .Tls12.WithExtendedMasterSecret(True)
      .Build; // TLS 1.2 configured but only TLS 1.3 offered
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a version facet for an unoffered version is refused at build');
end;

procedure TTestConfigBuilder.TestNonEmsResumptionReachesFrozenConfig;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := NewServerBuilder
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
    .Tls12.WithNonEmsResumption(TNonEmsResumption.Resume).Build;
  CheckEquals(Ord(TNonEmsResumption.Resume), Ord(LConfig.NonEmsResumption),
    'the .Tls12 policy reaches the frozen config');
end;

procedure TTestConfigBuilder.TestNonEmsResumptionOnTls13OnlyIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    NewServerBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .Tls12.WithNonEmsResumption(TNonEmsResumption.Abort).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a TLS 1.2 resumption policy on a TLS 1.3-only server is refused at build');
end;

procedure TTestConfigBuilder.TestRequiredEmsWithNonEmsResumeIsRefused;

  function Builds(AMode: TNonEmsResumption): Boolean;
  begin
    Result := True;
    try
      NewServerBuilder.WithSupportedVersions(
        TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12))
        .Tls12.WithExtendedMasterSecret(True).WithNonEmsResumption(AMode).Build;
    except
      on E: EInvalidOperationTlsLibException do
        Result := False;
    end;
  end;

begin
  // requiring EMS rejects every non-EMS client, so legacy resumption could never apply; the other two
  // policies are subsumed and still build
  CheckFalse(Builds(TNonEmsResumption.Resume), 'required EMS with legacy resumption contradicts itself');
  CheckTrue(Builds(TNonEmsResumption.Decline), 'required EMS with Decline builds');
  CheckTrue(Builds(TNonEmsResumption.Abort), 'required EMS with Abort builds');
end;

procedure TTestConfigBuilder.TestDefaultRevocationPostureIsSoft;
begin
  CheckEquals(Ord(TRevocationPosture.Soft),
    Ord(BuildClientConfig(Crypto).RevocationPosture),
    'the default revocation posture is soft-fail');
end;

procedure TTestConfigBuilder.TestWithRevocationSetsHardPosture;
var
  LConfig: ITlsClientConfig;
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithTrustStore(ClientTrust)
    // Hard requires a way to obtain revocation status, else Build rejects it as always-rejecting;
    // pairing it with a stapling request is the minimal usable configuration
    .WithOcspStaplingRequest(True)
    .WithRevocation(TRevocationPosture.Hard)
    .Build;
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LConfig.RevocationPosture),
    'WithRevocation sets the frozen posture');
end;

procedure TTestConfigBuilder.TestWithCertificatePinningLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
  LBuilder: ITlsConfigBuilder;
  LPin: TBytes;
begin
  LPin := DecodeHex(
    '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithTrustStore(ClientTrust)
    .WithCertificatePinning(TArray<TBytes>.Create(LPin))
    .Build;
  CheckEquals(1, System.Length(LConfig.CertificatePins), 'one pin is stored');
  CheckEqualBytes('the pin round-trips into the frozen config', LPin,
    LConfig.CertificatePins[0]);
end;

procedure TTestConfigBuilder.TestServerWithOcspStapleLandsInFrozenConfig;
var
  LConfig: ITlsServerConfig;
  LBuilder: ITlsConfigBuilder;
  LCredential: TTlsCredential;
  LStaple: TBytes;
begin
  // a staple set on the credential rides through the builder into the frozen config
  LStaple := TBytes.Create($30, $03, $0A, $01, $00);
  LCredential := ServerCredential;
  LCredential.OcspStaple := LStaple;
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(LCredential)
    .Build;
  CheckEqualBytes('the staple round-trips into the frozen config credential', LStaple,
    LConfig.Credential.OcspStaple);
end;

procedure TTestConfigBuilder.TestLoadedCredentialReplacesPriorStaple;
var
  LConfig: ITlsServerConfig;
  LBuilder: ITlsConfigBuilder;
  LStapled: TTlsCredential;
begin
  // a later WithCredential replaces the whole credential (last call wins), and a credential from
  // TTlsCredential.Load is staple-free - so a prior WithCredential's staple cannot bleed through
  LStapled := ServerCredential;
  LStapled.OcspStaple := TBytes.Create($30, $03, $0A, $01, $00);
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LConfig := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(LStapled)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
    DecodeHex(FCerts.Values['leaf_cert']), DecodeHex(FCerts.Values['leaf_key'])))
    .Build;
  CheckEquals(0, System.Length(LConfig.Credential.OcspStaple),
    'the loaded credential cleared the prior staple');
end;

procedure TTestConfigBuilder.TestLoadedCredentialBuildsServer;
var
  LConfig: ITlsServerConfig;
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LConfig := LBuilder.Server.WithCredential(TTlsCredential.Load(Crypto, Pkix,
    DecodeHex(FCerts.Values['leaf_cert']), DecodeHex(FCerts.Values['leaf_key']))).Build;
  CheckEquals(1, System.Length(LConfig.Credential.CertificateChain),
    'the loaded credential freezes its leaf into the config');
end;

procedure TTestConfigBuilder.TestServerCredentialWithMismatchedKeyRejected;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // same key family (EC P-256), different key: the leaf does not belong to the private key
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(CredentialWithForeignKey('ec256_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a credential whose key does not own its leaf is refused at Build');
end;

procedure TTestConfigBuilder.TestServerCredentialWithWrongKeyFamilyRejected;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // an RSA key against an EC leaf: the key-family mismatch surfaces as a wrong-leaf refusal
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(CredentialWithForeignKey('rsa_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a credential whose key family differs from its leaf is refused at Build');
end;

procedure TTestConfigBuilder.TestIncompleteCredentialsAreRefusedAtBuild;
var
  LBuilder: ITlsConfigBuilder;
  LNoChain, LNoKey: TTlsCredential;
  LRaised: Boolean;
begin
  LNoChain := ServerCredential;
  LNoChain.CertificateChain := nil;
  LNoKey := ServerCredential;
  LNoKey.PrivateKey := nil;

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(LNoChain).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('leaf certificate', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a server credential with an empty chain is refused for its chain');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithCredential(LNoKey).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('private key', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a server credential without a key is refused for its key');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Server.WithSniCredential('localhost', LNoKey).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an SNI-mapped credential without a key is refused');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithTrustStore(ClientTrust).WithCredential(LNoKey).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('private key', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a client chain without its key is refused');

  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithTrustStore(ClientTrust).WithCredential(LNoChain).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('leaf certificate', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a client credential with a key but no chain is refused');
end;

procedure TTestConfigBuilder.TestMalformedTrustAnchorIsRefusedAtBuild;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // one junk entry in an otherwise valid store would fail every verification against it
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithTrustStore(TTrustAnchorStore.Create(TArray<TBytes>.Create(
      DecodeHex(FCerts.Values['root_cert']), TBytes.Create(1, 2, 3))) as ITrustAnchorStore).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := Pos('anchor 1 of trust store 0', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'a store with an unparsable root is refused, naming it');
  // control: the same store without the junk entry builds
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  CheckTrue(LBuilder.Client.WithTrustStore(ClientTrust).Build <> nil, 'a valid store builds');
end;

procedure TTestConfigBuilder.TestSniCredentialWithMismatchedKeyNamesHost;
var
  LBuilder: ITlsConfigBuilder;
  LMsg: string;
begin
  // the leaf covers "localhost" (SAN), so coverage passes and the key/leaf guard is what trips;
  // the error must name the offending host
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LMsg := '';
  try
    LBuilder.Server.WithSniCredential('localhost',
      CredentialWithForeignKey('ec256_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('localhost', LMsg) > 0,
    'an inconsistent SNI credential is refused and the error names its host');
end;

procedure TTestConfigBuilder.TestClientCredentialWithMismatchedKeyRejected;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // a client-authentication credential is guarded on the client build path too
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile);
  LRaised := False;
  try
    LBuilder.Client.WithTrustStore(ClientTrust)
      .WithCredential(CredentialWithForeignKey('ec256_pkcs8_der')).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client credential whose key does not own its leaf is refused at Build');
end;

procedure TTestConfigBuilder.TestMatchingCredentialBuildsServer;
var
  LConfig: ITlsServerConfig;
begin
  // the guard does not false-positive: a genuine leaf+key pair builds
  LConfig := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, DefaultProfile)
    .Server.WithCredential(ServerCredential).Build;
  CheckTrue(LConfig <> nil, 'a consistent credential builds');
end;

procedure TTestConfigBuilder.TestTicketLifetimeAboveCapIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LRaised := False;
  try
    LServer.WithTicketLifetime(604801); // one second over the RFC 8446 4.6.1 ceiling
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a ticket lifetime above 604800 seconds is rejected');
end;

procedure TTestConfigBuilder.TestTicketLifetimeAtCapIsAccepted;
var
  LConfig: ITlsServerConfig;
begin
  // the boundary value is legal; only a strictly-greater lifetime is refused
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithTicketLifetime(604800)
    .Build;
  CheckNotNull(LConfig, 'the boundary ticket lifetime (604800) is accepted');
end;

procedure TTestConfigBuilder.TestResumptionScopeAboveCapIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LScope: TBytes;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LScope := nil;
  SetLength(LScope, 33); // one over the 32-byte cap
  LRaised := False;
  try
    LServer.WithResumptionScope(LScope);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a resumption scope above 32 bytes is rejected');
end;

procedure TTestConfigBuilder.TestResumptionScopeAtCapIsAccepted;
var
  LConfig: ITlsServerConfig;
  LScope: TBytes;
begin
  LScope := nil;
  SetLength(LScope, 32); // the boundary value is legal
  FillChar(LScope[0], 32, $5C);
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithResumptionScope(LScope)
    .Build;
  CheckEqualBytes('the boundary resumption scope (32 bytes) round-trips', LScope,
    LConfig.ResumptionScope);
end;

procedure TTestConfigBuilder.TestClientResumptionScopeAboveCapIsRejected;
var
  LClient: ITlsClientConfigBuilder;
  LScope: TBytes;
  LRaised: Boolean;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LScope := nil;
  SetLength(LScope, 33); // one over the 32-byte cap
  LRaised := False;
  try
    LClient.WithResumptionScope(LScope);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client resumption scope above 32 bytes is rejected');
end;

procedure TTestConfigBuilder.TestClientResumptionScopeAtCapRoundTrips;
var
  LConfig: ITlsClientConfig;
  LScope: TBytes;
begin
  LScope := nil;
  SetLength(LScope, 32); // the boundary value is legal
  FillChar(LScope[0], 32, $5C);
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .WithResumptionScope(LScope)
    .Build;
  CheckEqualBytes('the boundary client resumption scope (32 bytes) round-trips', LScope,
    LConfig.SessionScope);
end;

procedure TTestConfigBuilder.TestClientResumptionScopeIsOrderInsensitive;
var
  LConfig: ITlsClientConfig;
  LScope: TBytes;
begin
  LScope := nil;
  SetLength(LScope, 8);
  FillChar(LScope[0], 8, $2A);
  // set the scope BEFORE the cache: the two setters are order-insensitive, so the pinned scope
  // survives (the cache setter no longer clears it)
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust)
    .WithResumptionScope(LScope)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache)
    .Build;
  CheckEqualBytes('the pinned scope survives a later WithSessionCache', LScope,
    LConfig.SessionScope);
end;

procedure TTestConfigBuilder.TestTicketCountAboveCapIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LRaised := False;
  try
    LServer.Tls13.WithTicketCount(9); // one over the cap
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a ticket count above 8 is rejected');
end;

procedure TTestConfigBuilder.TestTicketCountNegativeIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server;
  LRaised := False;
  try
    LServer.Tls13.WithTicketCount(-1);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a negative ticket count is rejected');
end;

procedure TTestConfigBuilder.TestTicketCountAtCapIsAccepted;
var
  LConfig: ITlsServerConfig;
begin
  // the boundary value is legal; only a strictly-greater count is refused
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Tls13.WithTicketCount(8)
    .Build;
  CheckEquals(8, LConfig.TicketCount, 'the boundary ticket count (8) round-trips');
end;

procedure TTestConfigBuilder.TestServerEarlyDataMintsSharedAntiReplayDefault;
var
  LNoEarly, LWithEarly: ITlsServerConfig;
begin
  LNoEarly := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Build;
  CheckFalse(Assigned(LNoEarly.AntiReplay),
    'a server without 0-RTT mints no anti-replay register');
  LWithEarly := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .Tls13.WithEarlyData(16384)
    .Build;
  CheckTrue(Assigned(LWithEarly.AntiReplay),
    'a server authorizing 0-RTT mints a default anti-replay register at Build');
end;

procedure TTestConfigBuilder.TestServerRejectsPublicSuffixSniWildcard;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // a public-suffix wildcard (*.com) can never match a host at runtime, so it is rejected as an
  // SNI pattern at configuration - the same rule name verification enforces
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LBuilder.Server.WithSniCredential('*.com', ServerCredential);
  LRaised := False;
  try
    LBuilder.Server.Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a *.com SNI wildcard is rejected at configuration');
end;

procedure TTestConfigBuilder.TestClassicalRegistryOverPresetNegotiatesClassical;
var
  LClient, LServer: ITlsEngine;
  LClientInfo, LServerInfo: TTlsConnectionInfo;
begin
  // Hardened prefers X25519MLKEM768 first; installing the classical-only registry prunes it.
  // Before the registry became authoritative this raised at engine creation (preferred group not
  // in the registry); now the hybrid is dropped from the offer and X25519 is negotiated instead.
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Crypto))
    .WithTrustStore(ClientTrust).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Crypto))
    .WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  LClientInfo := LClient.ConnectionInfo;
  LServerInfo := LServer.ConnectionInfo;
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClientInfo.NamedGroup),
    'negotiated classical X25519, not the pruned post-quantum hybrid');
  CheckEquals(Integer(LClientInfo.NamedGroup), Integer(LServerInfo.NamedGroup),
    'client and server agree on the negotiated group');
end;

procedure TTestConfigBuilder.TestClassicalRegistryClientAgainstDefaultServer;
var
  LClient, LServer: ITlsEngine;
begin
  // the client's registry is classical-only, so its supported_groups carries no hybrid; the server
  // keeps the default registry and prefers the hybrid, but cannot select or retry onto a group the
  // client never offered. Both settle on X25519 with no fatal - the case the OfferedGroups filter,
  // not the PreferredGroup fix, protects.
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Crypto))
    .WithTrustStore(ClientTrust).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not fail (no retry into a pruned group)');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClient.ConnectionInfo.NamedGroup),
    'negotiated classical X25519 though the server prefers the hybrid');
end;

procedure TTestConfigBuilder.TestServerWithEmptyGroupIntersectionFailsFast;
var
  LReg: INamedGroupRegistry;
  LRaised: Boolean;
begin
  // Hardened prefers the hybrid, X25519 and secp256r1; prune the classical registry down to
  // secp384r1 (which Hardened does not prefer), leaving the registry-vs-preference intersection
  // empty. The server must refuse at creation rather than build with an empty offer and fault on
  // the first ClientHello.
  LReg := TNamedGroups.CreateClassicalRegistry(Crypto);
  LReg.Prune(TNamedGroupCatalog.X25519);
  LReg.Prune(TNamedGroupCatalog.Secp256r1);
  LReg.Prune(TNamedGroupCatalog.Secp521r1);
  LRaised := False;
  try
    TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
      .WithNamedGroups(LReg).WithCredential(ServerCredential).Build);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a server with an empty registry-vs-preference intersection is refused');
end;

procedure TTestConfigBuilder.TestRoleConfigDefaultsForMovedAccessors;
var
  LClient: ITlsClientConfig;
  LServer: ITlsServerConfig;
begin
  // the server-name / cipher-order / ALPN-reject knobs live only on the server config now, and
  // GREASE only on the client config; each surfaces its builder default off the role config
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust).Build;
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  CheckTrue(LServer.ServerNameAcknowledgement, 'a server acknowledges SNI by default');
  CheckEquals(Ord(TServerCipherPreference.ServerOrder), Ord(LServer.CipherSuitePreference),
    'a server imposes its own cipher order by default');
  CheckFalse(LServer.AlpnRejectAll, 'a server does not reject ALPN unconditionally by default');
  CheckEquals(Ord(TNonEmsResumption.Decline), Ord(LServer.NonEmsResumption),
    'a TLS 1.2 server declines non-EMS resumption by default');
  CheckTrue(LClient.Grease, 'a client greases by default');
  CheckEquals(Ord(TServerNameIndication.Send), Ord(LClient.ServerNameIndication),
    'a client sends SNI by default');
end;

function TTestConfigBuilder.OmitSniClient(const AVersions: TArray<UInt16>): ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(AVersions)
    .WithTrustStore(ClientTrust)
    .WithServerNameIndication(TServerNameIndication.Omit).Build;
end;

function TTestConfigBuilder.RejectEveryChain(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := False;
end;

procedure TTestConfigBuilder.TestTls13ReportsExtendedMasterSecret;
var
  LClient, LServer: ITlsEngine;
begin
  // TLS 1.3 always derives the exporter from the full transcript, so it reports EMS as in use
  // (RFC 8446 Appendix D), including a dual-version client that settles on 1.3
  LClient := TTlsEngineFactory.CreateClientEngine(NewClientBuilder.Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the handshake completed');
  CheckTrue(LClient.ConnectionInfo.ExtendedMasterSecret, 'the TLS 1.3 client reports EMS');
  CheckTrue(LServer.ConnectionInfo.ExtendedMasterSecret, 'and the server');
end;

procedure TTestConfigBuilder.TestVerifyCallbackRunsOverInstanceVerifier;
var
  LClient, LServer: ITlsEngine;
begin
  // the callback is the host's own reject rule: it must still run when the whole verifier is a
  // caller-supplied instance that accepts everything
  LClient := TTlsEngineFactory.CreateClientEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithDangerousCertificateVerifier(TAcceptAllServerVerifier.Create as IServerCertificateVerifier)
    .WithCertificateVerifyCallback(RejectEveryChain).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the callback rejected a chain the instance accepted');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown),
    Ord(LClient.LastError.Alert.Description), 'the alert is certificate_unknown');
end;

procedure TTestConfigBuilder.TestServerNameIndicationOmitReachesConfig;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls13));
  CheckEquals(Ord(TServerNameIndication.Omit), Ord(LConfig.ServerNameIndication),
    'the builder choice reaches the frozen config');
  CheckTrue(LConfig.CheckServerName, 'omitting SNI leaves the name check on');
end;

procedure TTestConfigBuilder.TestOmittedSniSendsNoServerNameAndStillVerifiesHost;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
  LMsg: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(
    OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls13)), 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  LClient.StartHandshake;
  LFlight := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
  CheckTrue(LExts.Count > 0, 'the flight carries a ClientHello');
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry), 'no server_name extension');
  CheckFalse(ContainsAscii(LFlight, 'localhost'),
    'the host does not appear on the wire');
  Feed(LServer, LFlight);
  ExchangeFlights(LClient, LServer);
  // completion proves the leaf was still checked against the host: it matches only localhost
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not abort');
  CheckFalse(LServer.IsTerminal, 'the server did not abort');
  CheckEquals('', LServer.ConnectionInfo.ServerName, 'the server saw no SNI');
  LMsg := DecodeHex('736e692d6f6d6974'); // "sni-omit"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Feed(LServer, Drain(LClient));
  CheckEqualBytes('app data flows without SNI', LMsg, ReadAllApp(LServer));
end;

procedure TTestConfigBuilder.TestOmittedSniStillRejectsWrongHost;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(
    OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls13)), 'wrong.example');
  LServer := TTlsEngineFactory.CreateServerEngine(NewServerBuilder.Build);
  LClient.StartHandshake;
  LFlight := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry), 'no server_name extension');
  Feed(LServer, LFlight);
  ExchangeFlights(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'omitting SNI is not a name-check bypass: the client aborts');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(LClient.LastError.Alert.Description), 'the alert is bad_certificate');
end;

procedure TTestConfigBuilder.TestOmittedSniTls12SendsNoServerName;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(
    OmitSniClient(TArray<UInt16>.Create(TlsWireVersionTls12)), 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build);
  LClient.StartHandshake;
  LFlight := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
  CheckTrue(LExts.Count > 0, 'the flight carries a ClientHello');
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry), 'no server_name in the 1.2 hello');
  Feed(LServer, LFlight);
  ExchangeFlights(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the TLS 1.2 handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not abort: ' + LClient.LastError.Message);
  CheckEquals(Integer(TlsWireVersionTls12), Integer(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
    'TLS 1.2 was negotiated');
end;

procedure TTestConfigBuilder.TestOmittedSniHrrRetryKeepsServerNameAbsent;
var
  LClient, LServer: ITlsEngine;
  LCh1, LCh2: TBytes;
  LExts: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  // the server prefers a group the client did not send a key share for, forcing a HelloRetryRequest
  LClient := TTlsEngineFactory.CreateClientEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1))
    .WithTrustStore(ClientTrust)
    .WithServerNameIndication(TServerNameIndication.Omit).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1))
    .WithCredential(ServerCredential).Build);
  LClient.StartHandshake;
  LCh1 := Drain(LClient);
  Feed(LServer, LCh1);
  Feed(LClient, Drain(LServer));
  LCh2 := Drain(LClient);
  LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LCh2);
  CheckTrue(LExts.Count > 0, 'the retry flight carries a ClientHello');
  CheckFalse(LExts.TryFind(TExtensionTypes.ServerName, LEntry),
    'the second ClientHello still has no server_name');
  Feed(LServer, LCh2);
  ExchangeFlights(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server accepted the retry ClientHello');
  CheckFalse(LClient.IsTerminal, 'the client did not abort');
  CheckEquals(Integer(TNamedGroupCatalog.Secp256r1), Integer(LClient.ConnectionInfo.NamedGroup),
    'the retry moved the handshake onto the server''s group');
end;

procedure TTestConfigBuilder.TestOmittedSniKeepsSessionsApart;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LOffered: Boolean;

  function Resumes(AMode: TServerNameIndication): Boolean;
  var
    LClient, LServer: ITlsEngine;
    LFlight: TBytes;
    LExts: TExtensionVector;
    LEntry: TExtensionEntry;
  begin
    LClient := TTlsEngineFactory.CreateClientEngine(
      TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
      .WithTrustStore(ClientTrust).WithSessionCache(LCache).WithResumptionScope(LScope)
      .WithServerNameIndication(AMode).Build, 'localhost');
    LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
    LClient.StartHandshake;
    LFlight := Drain(LClient);
    // whether the client offered a cached session, apart from the server accepting it
    LExts := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFlight);
    LOffered := LExts.TryFind(TExtensionTypes.PreSharedKey, LEntry);
    Feed(LServer, LFlight);
    ExchangeFlights(LClient, LServer);
    // let the post-handshake ticket reach the client's cache
    Feed(LClient, Drain(LServer));
    Result := LClient.ConnectionInfo.Resumed;
  end;

begin
  LCache := TInMemorySessionCache.Create as ISessionCache;
  LScope := TBytes.Create($53, $4E, $49);
  LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithResumptionScope(LScope).Build;
  CheckFalse(Resumes(TServerNameIndication.Send), 'the first handshake is a full one');
  CheckFalse(LOffered, 'nothing cached yet, so no session is offered');
  CheckTrue(Resumes(TServerNameIndication.Send), 'a repeat with SNI resumes');
  CheckTrue(LOffered, 'the cached session is offered');
  // the client's own cache key keeps the two apart: it offers no session, rather than the server
  // declining one
  CheckFalse(Resumes(TServerNameIndication.Omit),
    'a client that omits SNI does not resume a session made with it');
  CheckFalse(LOffered, 'a client that omits SNI does not offer a session made with it');
  CheckTrue(Resumes(TServerNameIndication.Omit), 'a repeat without SNI resumes its own session');
  CheckTrue(LOffered, 'it offers its own cached session');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestConfigBuilder);
{$ELSE}
  RegisterTest(TTestConfigBuilder.Suite);
{$ENDIF FPC}

end.
