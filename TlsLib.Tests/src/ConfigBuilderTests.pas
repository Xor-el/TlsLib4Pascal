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
  TlpTlsVersion,
  TlpArrayUtilities,
  TlpSecretBuffer,
  TlpISession,
  TlpSession,
  TlpInMemorySessionCache,
  TlpSessionTicketKeys,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpTrustTypes,
  TlpTlsAlert,
  TlpCertificateVerifier,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpICertificateCompression,
  TlpZlibCertificateCompression,
  TlpCertificateLimits,
  TlpISecretBuffer,
  TlpCryptoDomainTypes,
  TlpEchConfig,
  TlpInMemoryEchKeyStore,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsConfigBuilder,
  TlpTlsEngineFactory,
  TlpTlsLib,
  MockCryptoProvider,
  TlsLibTestBase;

type
  TTestConfigBuilder = class(TTlsLibAlgorithmTestCase)
  private
    FCerts: TStringList;
    // the endpoint views hold a raw back-reference to their owner, so a helper that hands back a
    // view keeps the owning builder alive here for the test's duration
    FBuilders: TArray<ITlsConfigBuilder>;
    function ServerCredential: TTlsCredential;
    // the EcP256 leaf paired with a foreign private key from ImportKeys.txt (never its own key),
    // so the key does not own the leaf
    function CredentialWithForeignKey(const AKeyField: string): TTlsCredential;
    function ClientTrust: ITrustAnchorStore;
    function BuildEchConfigList(AConfigId: Byte; const APublicName: string;
      out APrivateKey: ISecretBuffer): TBytes;
    function BuildClientConfig(const ACryptoProvider: ICryptoProvider): ITlsClientConfig;
    function BuildServerConfig(const ACryptoProvider: ICryptoProvider): ITlsServerConfig;
    function DefaultProfile: TTlsConfigProfile;
    function ChainLimitsAccepted(AMaxCert, AMaxTotal: Int32): Boolean;
    function NewClientBuilder: ITlsClientConfigBuilder;
    function NewServerBuilder: ITlsServerConfigBuilder;
    function MakePskSpec: TExternalPsk;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure RunHandshake(const AClient, AServer: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEchThroughServerBuilder;
    procedure TestEchSplitModeBackendWithKeyStoreRejected;
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
    procedure TestAlpnSetterCopiesCallerArray;
    procedure TestRecordSizeLimitDefaultsToUnset;
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
    procedure TestServerVerifierSourceWithoutPeerAuthBuildsWithoutAnchors;
    procedure TestServerClientAuthVerifierSourceWithSkipVerifyBuilds;
    // the exclusivity count runs before the roots gate, so an instance verifier plus a source is the
    // dual-verifier conflict - never the "source needs anchors" message
    procedure TestServerClientAuthVerifierSourceWithInstanceIsDualVerifier;
    procedure TestMtlsServerWithSuppliedTicketKeysRequiresScope;
    procedure TestMtlsServerWithSuppliedKeysAndScopeBuilds;
    procedure TestMtlsServerWithDefaultTicketKeysBuildsWithoutScope;
    procedure TestFacadeDrivesLoopback;
    procedure TestCustomProviderThreadedThroughRawBuilder;
    procedure TestDefaultCertificateChainLimitsAreConservative;
    procedure TestCertificateChainLimitsAreConfigurable;
    procedure TestInvalidCertificateChainLimitsRejected;
    procedure TestTls13CompressorOverrideLandsInFrozenConfig;
    procedure TestClientBuilderChainBuildsClient;
    procedure TestServerBuilderChainBuildsServer;
    procedure TestVersionFacetForUnofferedVersionIsRefused;
    procedure TestDefaultRevocationPostureIsSoft;
    procedure TestWithRevocationSetsHardPosture;
    // server-side Hard client-certificate revocation: satisfiable only by a live resolver, so
    // Build fails fast without one, builds with one, and is inert when client auth is off
    procedure TestServerHardClientRevocationWithoutResolverIsRefused;
    procedure TestServerHardClientRevocationWithResolverBuilds;
    procedure TestServerHardClientRevocationHostDecisionIsRefused;
    procedure TestServerHardRevocationWithoutClientAuthBuilds;
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
    procedure TestClientRejectsServerSniCredential;
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
  end;

implementation

type
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
  Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(FCerts.Values['leaf_key']), nil);
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

procedure TTestConfigBuilder.TestEchSplitModeBackendWithKeyStoreRejected;
var
  LSk: ISecretBuffer;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  // the split-mode backend role holds no ECH keys; pairing WithEchSplitModeBackend with
  // WithEchKeyStore is a contradictory deployment and must be refused at Build (RFC 9849 sec. 7)
  LConfigList := BuildEchConfigList($E1, 'cover.example', LSk);
  LRaised := False;
  try
    NewServerBuilder.Tls13.WithEchSplitModeBackend.WithEchKeyStore(
      TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Crypto)).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a split-mode backend combined with an ECH key store is refused');
end;

procedure TTestConfigBuilder.TestEchThroughServerBuilder;
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LClientBuilder, LServerBuilder: ITlsConfigBuilder;
  LConfigList: TBytes;
  LSk: ISecretBuffer;
  LMsg: TBytes;
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

  CheckTrue(LServerConfig.EchKeyStore <> nil,
    'the builder froze an ECH key store onto the server config');

  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);

  // completion proves ECH was accepted: the leaf matches only the inner SNI (localhost), never
  // the public_name, so a reject would abort the client on the certificate check
  CheckFalse(LClient.IsHandshaking, 'the ECH client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the ECH server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the ECH client did not abort');
  CheckFalse(LServer.IsTerminal, 'the ECH server did not abort');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted,
    'the builder-configured connection surfaced ECH Accepted');
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
    LBuilder.Client.WithAlpnProtocols(TArray<string>.Create('h2', ''));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ALPN protocol name is refused');
end;

procedure TTestConfigBuilder.TestAlpnNonAsciiNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(TArray<string>.Create('h2' + #$00E9));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-ASCII ALPN protocol name is refused');
end;

procedure TTestConfigBuilder.TestAlpnOverlongNameIsRefused;
var
  LBuilder: ITlsConfigBuilder;
  LRaised, LAtCapRaised: Boolean;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LRaised := False;
  try
    LBuilder.Client.WithAlpnProtocols(TArray<string>.Create(StringOfChar('a', 256)));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a 256-byte ALPN protocol name is refused');
  // the 255-byte boundary is legal
  LAtCapRaised := False;
  try
    NewClientBuilder.WithAlpnProtocols(TArray<string>.Create(StringOfChar('a', 255)));
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
    LBuilder.Client.WithAlpnProtocols(TArray<string>.Create('h2', 'http/1.1', 'h2'));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a duplicate ALPN protocol name is refused');
end;

procedure TTestConfigBuilder.TestAlpnEmptyListMeansNoAlpn;
var
  LConfig: ITlsClientConfig;
  LNone: TArray<string>;
begin
  LNone := nil;
  LConfig := NewClientBuilder.WithAlpnProtocols(LNone).Build;
  CheckEquals(0, System.Length(LConfig.AlpnProtocols), 'an empty list configures no ALPN');
end;

procedure TTestConfigBuilder.TestAlpnSetterCopiesCallerArray;
var
  LConfig: ITlsClientConfig;
  LList: TArray<string>;
begin
  LList := TArray<string>.Create('h2');
  LConfig := NewClientBuilder.WithAlpnProtocols(LList).Build;
  LList[0] := 'x'; // mutating the caller's array must not reach the built config
  CheckEquals(1, System.Length(LConfig.AlpnProtocols), 'the ALPN list is preserved');
  CheckEquals('h2', LConfig.AlpnProtocols[0], 'the ALPN list is a snapshot of the caller array');
end;

procedure TTestConfigBuilder.TestRecordSizeLimitDefaultsToUnset;
begin
  CheckEquals(0, NewClientBuilder.Build.RecordSizeLimit,
    'a client offers no record_size_limit by default');
  CheckEquals(0, NewServerBuilder.Build.RecordSizeLimit,
    'a server offers no record_size_limit by default');
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
  // RFC 8449 4: 64 is the minimum and 16384 the maximum a sender may ever emit; 0 opts out
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
var
  LIterations: Int32;
begin
  AClient.StartHandshake;
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
    LBuilder.Client.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
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
    LBuilder.Client.WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec))
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
    .WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec)).Build;
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
  LUnion := TUnionTrustAnchorStore.Create(TArray<ITrustAnchorStore>.Create(
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore,
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore)) as ITrustAnchorStore;
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
      .WithExternalPreSharedKeys(TArray<TExternalPsk>.Create(MakePskSpec))
      .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build;
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

procedure TTestConfigBuilder.TestServerVerifierSourceWithoutPeerAuthBuildsWithoutAnchors;
var
  LConfig: ITlsServerConfig;
begin
  // client auth is off, so the source is inert and no anchors are required (parity with anchors)
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithCertificateVerifierSource(
      TAcceptAllClientVerifierSource.Create as IClientCertificateVerifierSource).Build;
  CheckTrue(LConfig <> nil, 'a client verifier source without client auth builds without anchors');
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

procedure TTestConfigBuilder.TestServerHardRevocationWithoutClientAuthBuilds;
begin
  // with no client authentication there is no client certificate to check, so the Hard posture
  // is inert and the guard must not fire
  TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithRevocation(TRevocationPosture.Hard)
    .Build;
  Check(True, 'Hard revocation without client auth builds (guard inert)');
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
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsLib.NewClientConfig(ClientTrust), 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsLib.NewServerConfig(ServerCredential));
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
  LCustom.MaxCertificateLength := 1 shl 17;
  LCustom.MaxTotalChainLength := 1 shl 20;
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
end;

function TTestConfigBuilder.ChainLimitsAccepted(AMaxCert,
  AMaxTotal: Int32): Boolean;
var
  LLimits: TCertificateChainLimits;
  LBuilder: ITlsConfigBuilder;
begin
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
  Result.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  Result.SignatureSchemes := TSignatureSchemeRegistry.CreateDefault;
  Result.NamedGroups := TNamedGroups.CreateDefaultRegistry(Crypto);
  Result.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
  Result.PreferredGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
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
    LServer.WithTicketCount(9); // one over the cap
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
    LServer.WithTicketCount(-1);
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
    .WithTicketCount(8)
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

procedure TTestConfigBuilder.TestClientRejectsServerSniCredential;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // SNI-keyed server credential selection is server-only; building a client from a builder that
  // carries it is a configuration error, not a silent drop
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix, TTlsConfigProfile.Default);
  LBuilder.Server.WithSniCredential('localhost', ServerCredential);
  // a trust store makes an otherwise-valid client, so the only thing that can fail Build is the
  // server-only SNI credential guard (not a missing trust source)
  LBuilder.Client.WithTrustStore(ClientTrust);
  LRaised := False;
  try
    LBuilder.Client.Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client configuration rejects server-only SNI credential settings');
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
  CheckTrue(LClient.Grease, 'a client greases by default');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestConfigBuilder);
{$ELSE}
  RegisterTest(TTestConfigBuilder.Suite);
{$ENDIF FPC}

end.
