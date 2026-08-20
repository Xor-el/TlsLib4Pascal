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
  TlpICryptoProvider,
  TlpICertificateTrust,
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
    function ServerCredential: TTlsCredential;
    function ClientTrust: ITrustAnchorStore;
    function BuildClientConfig(const AProvider: ICryptoProvider): ITlsClientConfig;
    function BuildServerConfig(const AProvider: ICryptoProvider): ITlsServerConfig;
    function NewClientBuilder: ITlsConfigBuilder;
    function NewServerBuilder: ITlsConfigBuilder;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure RunHandshake(const AClient, AServer: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBuilderRejectsMutationAfterBuild;
    procedure TestSecondBuildIsRejected;
    procedure TestReturnedPinsArrayCannotMutateConfig;
    procedure TestClientConfigRequiresTrustStore;
    procedure TestServerConfigRequiresCredential;
    procedure TestServerClientAuthRequiresTrustStore;
    procedure TestFacadeDrivesLoopback;
    procedure TestCustomProviderThreadedThroughRawBuilder;
    procedure TestDefaultCertificateChainLimitsAreConservative;
    procedure TestCertificateChainLimitsAreConfigurable;
    procedure TestTls13CompressorOverrideLandsInFrozenConfig;
    procedure TestClientBuilderChainBuildsClient;
    procedure TestServerBuilderChainBuildsServer;
    procedure TestVersionFacetForUnofferedVersionIsRefused;
    procedure TestEndpointViewBackReferenceDoesNotCountOwner;
    procedure TestDefaultRevocationPostureIsSoft;
    procedure TestWithRevocationSetsHardPosture;
    // server-side Hard client-certificate revocation: satisfiable only by a live resolver, so
    // Build fails fast without one, builds with one, and is inert when client auth is off
    procedure TestServerHardClientRevocationWithoutResolverIsRefused;
    procedure TestServerHardClientRevocationWithResolverBuilds;
    procedure TestServerHardRevocationWithoutClientAuthBuilds;
    procedure TestWithCertificatePinningLandsInFrozenConfig;
    procedure TestServerWithOcspStapleLandsInFrozenConfig;
    procedure TestFieldwiseCredentialClearsPriorStaple;
    // RFC 8446 4.6.1: a server MUST NOT advertise a ticket lifetime over 604800 seconds
    procedure TestTicketLifetimeAboveCapIsRejected;
    procedure TestTicketLifetimeAtCapIsAccepted;
    procedure TestClientRejectsServerSniCredential;
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
  end;

implementation

{ TTestConfigBuilder }

procedure TTestConfigBuilder.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
end;

procedure TTestConfigBuilder.TearDown;
begin
  FCerts.Free;
  inherited TearDown;
end;

function TTestConfigBuilder.ServerCredential: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  Result.PrivateKey := Provider.ImportSigningKey(DecodeHex(FCerts.Values['leaf_key']));
end;

function TTestConfigBuilder.ClientTrust: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']))) as ITrustAnchorStore;
end;

function TTestConfigBuilder.BuildClientConfig(
  const AProvider: ICryptoProvider): ITlsClientConfig;
var
  LBuilder: ITlsConfigBuilder;
begin
  // assemble a client config straight from the raw builder with the given provider
  LBuilder := TTlsConfigBuilder.Create(AProvider);
  Result := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(AProvider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(AProvider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithTrustStore(ClientTrust)
    .Build;
end;

function TTestConfigBuilder.BuildServerConfig(
  const AProvider: ICryptoProvider): ITlsServerConfig;
var
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.Create(AProvider);
  Result := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(AProvider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(AProvider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(ServerCredential)
    .Build;
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
  LClient := TTlsPresets.Compatible(Provider).Client;
  LClient.WithTrustStore(ClientTrust);
  LClient.Build;
  LRaised := False;
  try
    LClient.WithNameCheck(False);
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
  LClient := TTlsPresets.Compatible(Provider).Client;
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
  LConfig := TTlsPresets.Compatible(Provider).Client
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
  LBuilder := TTlsPresets.Compatible(Provider);
  LRaised := False;
  try
    LBuilder.Client.Build; // no trust source set
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client config without a trust source is refused');
end;

procedure TTestConfigBuilder.TestServerConfigRequiresCredential;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsPresets.Compatible(Provider);
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
  LBuilder := TTlsPresets.Compatible(Provider);
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
    TTlsPresets.Compatible(Provider).Server
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
  // with a live verdict resolver, Hard client-cert revocation is satisfiable - Build succeeds
  TTlsPresets.Compatible(Provider).Server
    .WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithTrustStore(ClientTrust)
    .WithRevocation(TRevocationPosture.Hard)
    .WithAsyncCertificateVerdict(True, 0)
    .Build;
  Check(True, 'a Hard client-cert-revocation server with a resolver builds');
end;

procedure TTestConfigBuilder.TestServerHardRevocationWithoutClientAuthBuilds;
begin
  // with no client authentication there is no client certificate to check, so the Hard posture
  // is inert and the guard must not fire
  TTlsPresets.Compatible(Provider).Server
    .WithCredential(ServerCredential)
    .WithRevocation(TRevocationPosture.Hard)
    .Build;
  Check(True, 'Hard revocation without client auth builds (guard inert)');
end;

procedure TTestConfigBuilder.TestFacadeDrivesLoopback;
var
  LClient, LServer: ITlsEngine;
  LFromClient: TBytes;
begin
  LClient := TTlsLib.NewClientEngine('localhost', ClientTrust);
  LServer := TTlsLib.NewServerEngine(ServerCredential);
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
  LCustom := TFixedAesProvider.Create(Provider, True) as ICryptoProvider;
  LClientConfig := BuildClientConfig(LCustom);
  LServerConfig := BuildServerConfig(LCustom);

  // the builder threads the exact provider instance into the frozen configs
  CheckTrue(LClientConfig.Provider = LCustom,
    'the client config carries the caller''s provider');
  CheckTrue(LServerConfig.Provider = LCustom,
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
  LConfig := BuildClientConfig(Provider);
  LLimits := LConfig.CertificateChainLimits;
  CheckEquals(10, LLimits.MaxChainLength, 'default max chain length');
  CheckEquals(1 shl 16, LLimits.MaxCertificateLength, 'default max certificate length');
  CheckEquals(1 shl 18, LLimits.MaxTotalChainLength, 'default max total chain length');
end;

procedure TTestConfigBuilder.TestCertificateChainLimitsAreConfigurable;
var
  LBuilder: ITlsConfigBuilder;
  LConfig: ITlsClientConfig;
  LCustom, LFrozen: TCertificateChainLimits;
begin
  // a caller can tune the caps; the frozen config carries the tuned values
  LCustom.MaxChainLength := 25;
  LCustom.MaxCertificateLength := 1 shl 17;
  LCustom.MaxTotalChainLength := 1 shl 20;
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithTrustStore(ClientTrust)
    .WithCertificateChainLimits(LCustom)
    .Build;
  LFrozen := LConfig.CertificateChainLimits;
  CheckEquals(25, LFrozen.MaxChainLength, 'the tuned chain length is frozen in');
  CheckEquals(1 shl 17, LFrozen.MaxCertificateLength, 'the tuned certificate length');
  CheckEquals(1 shl 20, LFrozen.MaxTotalChainLength, 'the tuned total chain length');
end;

function TTestConfigBuilder.NewClientBuilder: ITlsConfigBuilder;
var
  LBuilder: TTlsConfigBuilder;
begin
  // common-configured on the shared owner; the caller narrows via .Client
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LBuilder.WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider));
  LBuilder.WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault);
  LBuilder.WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider));
  LBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
  LBuilder.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519));
  LBuilder.WithTrustStore(ClientTrust);
  Result := LBuilder;
end;

function TTestConfigBuilder.NewServerBuilder: ITlsConfigBuilder;
var
  LBuilder: TTlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LBuilder.WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider));
  LBuilder.WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault);
  LBuilder.WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider));
  LBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
  LBuilder.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519));
  LBuilder.WithCredential(ServerCredential);
  Result := LBuilder;
end;

procedure TTestConfigBuilder.TestTls13CompressorOverrideLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
  LEmptyComp: TArray<ICertificateCompressor>;
  LEmptyDecomp: TArray<ICertificateDecompressor>;
begin
  // the default carries a compressor; clearing the 1.3 knobs must empty the read side
  LConfig := BuildClientConfig(Provider);
  CheckTrue(System.Length(LConfig.CertificateCompressors) > 0,
    'the default config carries a compressor');
  CheckTrue(System.Length(LConfig.CertificateDecompressors) > 0,
    'the default config carries a decompressor');

  LEmptyComp := nil;
  LEmptyDecomp := nil;
  LConfig := NewClientBuilder.Client.Tls13
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
  LConfig := NewClientBuilder.Client.Tls13
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
  LConfig := NewServerBuilder.Server
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
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LRaised := False;
  try
    LBuilder.Server
      .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider))
      .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
      .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider))
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

procedure TTestConfigBuilder.TestEndpointViewBackReferenceDoesNotCountOwner;
var
  LRaw: TTlsConfigBuilder;
  LBuilder: ITlsConfigBuilder;
begin
  LRaw := TTlsConfigBuilder.Create(Provider);
  LBuilder := LRaw;
  CheckEquals(1, LRaw.RefCount, 'one reference holds the builder');
  LRaw.Client.WithNameCheck(True);
  CheckEquals(1, LRaw.RefCount,
    'the endpoint-view back-reference does not count the builder');
  LBuilder := nil;
end;

procedure TTestConfigBuilder.TestDefaultRevocationPostureIsSoft;
begin
  CheckEquals(Ord(TRevocationPosture.Soft),
    Ord(BuildClientConfig(Provider).RevocationPosture),
    'the default revocation posture is soft-fail');
end;

procedure TTestConfigBuilder.TestWithRevocationSetsHardPosture;
var
  LConfig: ITlsClientConfig;
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider))
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
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LConfig := LBuilder.Client
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider))
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
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LConfig := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(LCredential)
    .Build;
  CheckEqualBytes('the staple round-trips into the frozen config credential', LStaple,
    LConfig.Credential.OcspStaple);
end;

procedure TTestConfigBuilder.TestFieldwiseCredentialClearsPriorStaple;
var
  LConfig: ITlsServerConfig;
  LBuilder: ITlsConfigBuilder;
  LStapled: TTlsCredential;
begin
  // a field-wise WithCredential replaces the whole credential: a staple from a prior
  // WithCredential(record) must not bleed through (last call wins)
  LStapled := ServerCredential;
  LStapled.OcspStaple := TBytes.Create($30, $03, $0A, $01, $00);
  LBuilder := TTlsConfigBuilder.Create(Provider);
  LConfig := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Provider))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Provider))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(LStapled)
    .WithCredential(DecodeHex(FCerts.Values['leaf_cert']),
    DecodeHex(FCerts.Values['leaf_key']))
    .Build;
  CheckEquals(0, System.Length(LConfig.Credential.OcspStaple),
    'the field-wise credential cleared the prior staple');
end;

procedure TTestConfigBuilder.TestTicketLifetimeAboveCapIsRejected;
var
  LServer: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LServer := TTlsPresets.Compatible(Provider).Server;
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
  LConfig := TTlsPresets.Compatible(Provider).Server
    .WithCredential(ServerCredential)
    .WithTicketLifetime(604800)
    .Build;
  CheckNotNull(LConfig, 'the boundary ticket lifetime (604800) is accepted');
end;

procedure TTestConfigBuilder.TestClientRejectsServerSniCredential;
var
  LBuilder: ITlsConfigBuilder;
  LRaised: Boolean;
begin
  // SNI-keyed server credential selection is server-only; building a client from a builder that
  // carries it is a configuration error, not a silent drop
  LBuilder := TTlsConfigBuilder.Create(Provider);
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

procedure TTestConfigBuilder.TestClassicalRegistryOverPresetNegotiatesClassical;
var
  LClient, LServer: ITlsEngine;
begin
  // Hardened prefers X25519MLKEM768 first; installing the classical-only registry prunes it.
  // Before the registry became authoritative this raised at engine creation (preferred group not
  // in the registry); now the hybrid is dropped from the offer and X25519 is negotiated instead.
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Hardened(Provider).Client
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Provider))
    .WithTrustStore(ClientTrust).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Provider).Server
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Provider))
    .WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClient.NegotiatedGroup),
    'negotiated classical X25519, not the pruned post-quantum hybrid');
  CheckEquals(Integer(LClient.NegotiatedGroup), Integer(LServer.NegotiatedGroup),
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
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Hardened(Provider).Client
    .WithNamedGroups(TNamedGroups.CreateClassicalRegistry(Provider))
    .WithTrustStore(ClientTrust).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Provider).Server
    .WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckFalse(LClient.IsTerminal, 'the client did not fail (no retry into a pruned group)');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClient.NegotiatedGroup),
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
  LReg := TNamedGroups.CreateClassicalRegistry(Provider);
  LReg.Prune(TNamedGroupCatalog.X25519);
  LReg.Prune(TNamedGroupCatalog.Secp256r1);
  LReg.Prune(TNamedGroupCatalog.Secp521r1);
  LRaised := False;
  try
    TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Provider).Server
      .WithNamedGroups(LReg).WithCredential(ServerCredential).Build);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a server with an empty registry-vs-preference intersection is refused');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestConfigBuilder);
{$ELSE}
  RegisterTest(TTestConfigBuilder.Suite);
{$ENDIF FPC}

end.
