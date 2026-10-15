{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls12DualVersionTests;

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
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpExtensionVector,
  TlpHandshakeEffect,
  TlpSecretBuffer,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsLibExceptions,
  TlpIHandshakeMachine,
  TlpICertificateTrust,
  TlpServerName,
  TlpCertificateVerifier,
  TlpCertificateVerifierSource,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlpVersionDispatchMachine,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  TTestTls12DualVersion = class(TTlsLibHandshakeTestCase)
  private
    function DualSuites: TArray<UInt16>;
    function Client13Params: TClientHandshakeParams;
    function Client12Params: TClient12HandshakeParams;
    function Server13Params: TServerHandshakeParams;
    function Server12Params: TServer12HandshakeParams;
    function NewDualClient: ITlsEngine;
    function NewHybridOfferingDualClient: ITlsEngine;
    function NewServerDispatch(const AVersions: TArray<UInt16>): ITlsEngine;
    function NewDowngradeAttacker: ITlsEngine;
    procedure CheckExchangesData(const AClient, AServer: ITlsEngine;
      const AMsg: string);
    /// <summary>Frames a ClientHello with the given cipher_suites and raw extensions
    /// block (a length-prefixed vector), parsed back into a handshake message.</summary>
    function MakeClientHello(const ACipherSuites: TArray<UInt16>;
      const AExtensions: TBytes): TTlsHandshakeMessage;
    function HasAnyFail(const AEffects: TArray<THandshakeEffect>): Boolean;
    /// <summary>The dual-version client's real ClientHello with its legacy_version set to
    /// ALegacyVersion.</summary>
    function RealClientHello(ALegacyVersion: UInt16): TTlsHandshakeMessage;
    /// <summary>Whether AServer aborts the real ClientHello at ALegacyVersion with
    /// protocol_version.</summary>
    function AbortsProtocolVersion(const AServer: IHandshakeMachine;
      ALegacyVersion: UInt16): Boolean;
  published
    procedure TestDispatcherAcceptsLegacyVersion0303;
    procedure TestDispatcherRejectsLegacyVersion0302WithSupportedVersions;
    procedure TestDispatcherRejectsLegacyVersion0304WithSupportedVersions;
    procedure TestDispatcherRejectsLegacyVersion0300WithSupportedVersions;
    procedure TestDispatcherRejectsLegacyVersion0000WithSupportedVersions;
    procedure TestDispatcherRejectsLegacyVersion0302WithTls12OnlySupportedVersions;
    procedure TestDispatcherWithoutSupportedVersionsKeepsLegacyVersionHandling;
    procedure TestTls12OnlyDispatcherRejectsLegacyVersion0302WithSupportedVersions;
    procedure TestStandaloneTls12ServerRejectsLegacyVersion0300WithSupportedVersions;
    procedure TestScsvOutranksLegacyVersionRejection;
    procedure TestStandaloneTls13ServerAcceptsLegacyVersion0303;
    procedure TestStandaloneTls13ServerRejectsLegacyVersion0304;
    procedure TestStandaloneTls13ServerRejectsLegacyVersion0300;
    procedure TestDualClientDualServerNegotiates13;
    procedure TestDualClientTls13OnlyServerNegotiates13;
    procedure TestDualClientTls12OnlyServerNegotiates12;
    procedure TestDualClientOfferingHybridExcludesItOnTls12;
    procedure TestForcedDowngradeIsDetectedAndAborts;
    procedure TestGarbageFirstRecordAbortsWithoutRaising;
    procedure TestFirstMessageOfTheWrongTypeIsUnexpectedMessage;
    procedure TestTls12ServerHelloWithTls13ExtensionIsRefused;
    procedure TestServerHelloTls13LegacyVersionWithoutSupportedVersionsIsProtocolVersion;
    procedure TestServerHelloSelectingAnUnofferedVersionIsProtocolVersion;
    procedure TestServerHelloSelectingPreTls13VersionIsRefusedByTheDispatcher;
    procedure TestServerHelloSelectingTls13ReachesTheTls13Machine;
    procedure TestScsvFromLowerClientAborts;
    procedure TestSpuriousFallbackSaysWhy;
    procedure TestScsvFromCurrentClientDoesNotAbort;
    procedure TestScsvToLegacyOnlyServerDoesNotAbort;
    procedure TestScsvWithFutureLegacyVersionAndNoExtensionIsFallbackAtDispatcher;
    procedure TestScsvWithFutureLegacyVersionAndNoExtensionIsFallbackAtStandaloneTls13Server;
    procedure TestScsvFromPre12ClientToTls12OnlyDispatcherAborts;
    procedure TestScsvFromPre12ClientToStandaloneTls12ServerAborts;
    procedure TestScsvWithGreaseAndPre12VersionToStandaloneTls12ServerAborts;
    procedure TestScsvWithGreaseOnlyVersionsIsNotFallbackAtStandaloneServers;
    procedure TestPre12ClientWithoutScsvToStandaloneTls12ServerIsProtocolVersion;
    procedure TestScsvWithGreaseVersionStillDetectsFallback;
    procedure TestScsvWithGreaseAndCurrentVersionDoesNotAbort;
    procedure TestScsvToStandaloneTls13ServerAborts;
    procedure TestScsvWithTls13OfferToStandaloneServerIsNotFallback;
    procedure TestGreaseOnlySupportedVersionsRejected;
    procedure TestServerRejectsSupportedVersionsWithoutCommonVersion;
    procedure TestLegacyEchHelloWithoutKeyStoreStaysOnTls12;
    procedure TestServerWithoutSignatureAlgorithmsIsHandshakeFailure;
    procedure TestEmptySupportedVersionsAtDispatchIsDecodeError;
    procedure TestTls13OnlyDispatcherRejectsTls12OnlyOffer;
    procedure TestTls12OnlyServerRejectsTls13OnlyOffer;
    procedure TestCompatiblePresetEngineLoopback;
    procedure TestCompatiblePresetMutualTlsCompletes;
    procedure TestClientEngineWithoutHostFailsClosed;
  end;

implementation

{ TTestTls12DualVersion }

function TTestTls12DualVersion.DualSuites: TArray<UInt16>;
begin
  // one 1.3 suite and one ECDHE-ECDSA 1.2 suite: the negotiated version alone decides
  Result := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
end;

function TTestTls12DualVersion.Client13Params: TClientHandshakeParams;
begin
  Result := Default(TClientHandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Crypto := Crypto;
  Result.Inspector := Pkix.Certificates;
  Result.Group := TNamedGroups.CreateX25519(Crypto);
  Result.GroupCode := TNamedGroupCatalog.X25519;
  // the unified ClientHello carries these supported_groups; a 1.2 fallback with a P-256
  // ECDSA server certificate needs Secp256r1 listed too, since TLS 1.2 gates the ECDSA
  // leaf's curve on supported_groups (RFC 8422 5.3). The key_share stays X25519-only
  Result.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  Result.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.OfferedSuites := DualSuites;
  Result.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.Grease := False;
  Result.ClientRandom := Filled($11, 32);
  Result.LegacySessionId := Filled($33, 32);
  Result.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  Result.ExpectedServerName := TServerName.DnsName('localhost');
end;

function TTestTls12DualVersion.Client12Params: TClient12HandshakeParams;
begin
  Result := Default(TClient12HandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Crypto := Crypto;
  Result.Inspector := Pkix.Certificates;
  Result.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.OfferedSuites := DualSuites;
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.3), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  Result.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  Result.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12);
  // the client random matches Client13Params so a 1.2 hand-off stays consistent
  Result.ClientRandom := Filled($11, 32);
  Result.LegacySessionId := Filled($33, 32);
  Result.OfferExtendedMasterSecret := True;
  Result.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTlsLibTestCertificates.EcP256RootStore, True) as IServerCertificateVerifier;
  Result.ExpectedServerName := TServerName.DnsName('localhost');
end;

function TTestTls12DualVersion.Server13Params: TServerHandshakeParams;
begin
  Result := Default(TServerHandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Crypto := Crypto;
  Result.Inspector := Pkix.Certificates;
  Result.Policy := TNegotiationPolicy.Create(
    TCipherSuiteRegistry.CreateDualVersion(Crypto),
    TNamedGroups.CreateDefaultRegistry(Crypto),
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519),
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12), TServerCipherPreference.ServerOrder);
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.Group := TNamedGroups.CreateX25519(Crypto);
  Result.ServerRandom := Filled($22, 32);
  Result.CookieSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32));
  Result.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
end;

function TTestTls12DualVersion.Server12Params: TServer12HandshakeParams;
begin
  Result := Default(TServer12HandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Crypto := Crypto;
  Result.Inspector := Pkix.Certificates;
  Result.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.Group := TNamedGroups.CreateX25519(Crypto);
  Result.ServerRandom := Filled($22, 32);
  Result.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
end;

function TTestTls12DualVersion.NewDualClient: ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(TClientVersionDispatchMachine.Create(
    Client13Params, Client12Params) as IHandshakeMachine, Crypto);
end;

function TTestTls12DualVersion.NewHybridOfferingDualClient: ITlsEngine;
var
  L13: TClientHandshakeParams;
  L12: TClient12HandshakeParams;
begin
  L13 := Client13Params;
  L12 := Client12Params;
  // additionally advertise the X25519MLKEM768 hybrid in supported_groups (hybrid first);
  // the key_share stays classical X25519, so a 1.2 handshake must ignore the hybrid
  L13.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768,
    TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1);
  L12.OfferedGroups := L13.OfferedGroups;
  Result := TTlsEngine.CreateConfigured(TClientVersionDispatchMachine.Create(
    L13, L12) as IHandshakeMachine, Crypto);
end;

function TTestTls12DualVersion.NewServerDispatch(
  const AVersions: TArray<UInt16>): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(TServerVersionDispatchMachine.Create(
    Server13Params, Server12Params, AVersions) as IHandshakeMachine, Crypto);
end;

function TTestTls12DualVersion.NewDowngradeAttacker: ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  // a 1.3-capable server that (maliciously) answers a 1.3+1.2 client with 1.2 and
  // stamps the RFC 9846 downgrade sentinel
  LParams := Server12Params;
  LParams.EmitDowngradeSentinel := True;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

procedure TTestTls12DualVersion.CheckExchangesData(const AClient, AServer: ITlsEngine;
  const AMsg: string);
var
  LFromClient, LFromServer: TBytes;
begin
  CheckFalse(AClient.IsHandshaking, AMsg + ': client completed');
  CheckFalse(AServer.IsHandshaking, AMsg + ': server completed');
  CheckFalse(AClient.IsTerminal, AMsg + ': client did not fail');
  CheckFalse(AServer.IsTerminal, AMsg + ': server did not fail');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes(AMsg + ': server reads client data', LFromClient,
    ReadAllApp(AServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  AServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(AServer, AClient);
  CheckEqualBytes(AMsg + ': client reads server data', LFromServer,
    ReadAllApp(AClient));
end;

procedure TTestTls12DualVersion.TestDualClientDualServerNegotiates13;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12));
  RunHandshake(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client + dual server');
end;

procedure TTestTls12DualVersion.TestDualClientTls13OnlyServerNegotiates13;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls13));
  RunHandshake(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client + 1.3-only server');
end;

procedure TTestTls12DualVersion.TestDualClientTls12OnlyServerNegotiates12;
var
  LClient, LServer: ITlsEngine;
begin
  // the server supports only 1.2, so the client's dispatcher must hand off to its 1.2
  // machine; a 1.2-only server never stamps the downgrade sentinel
  LClient := NewDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls12));
  RunHandshake(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client + 1.2-only server');
end;

procedure TTestTls12DualVersion.TestDualClientOfferingHybridExcludesItOnTls12;
var
  LClient, LServer: ITlsEngine;
  LClientInfo: TTlsConnectionInfo;
begin
  // the dual client lists X25519MLKEM768 in supported_groups, but a 1.2-only server must
  // negotiate a classical ECDHE group - a KEM hybrid is never selected on TLS 1.2 (RFC 10024)
  LClient := NewHybridOfferingDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls12));
  RunHandshake(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client offering hybrid + 1.2-only server');
  LClientInfo := LClient.ConnectionInfo;
  CheckEquals(Integer(TlsWireVersionTls12), Integer(LClientInfo.NegotiatedVersion.WireValue),
    'the connection negotiated TLS 1.2');
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClientInfo.NamedGroup),
    'a classical group (not the X25519MLKEM768 hybrid) was selected on 1.2');
end;

procedure TTestTls12DualVersion.TestForcedDowngradeIsDetectedAndAborts;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewDualClient;
  LServer := NewDowngradeAttacker;
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal,
    'the client aborts a 1.2 downgrade that carries the 1.3-capable sentinel');
  // RFC 9846 4.2.3
  CheckEquals(Ord(TTlsAlertDescription.IllegalParameter),
    Ord(LClient.LastError.Alert.Description), 'with illegal_parameter');
end;

procedure TTestTls12DualVersion.TestCompatiblePresetEngineLoopback;
var
  LClient, LServer: ITlsEngine;
begin
  // the whole public stack: the Compatible preset (dual-version) + the engine factory
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix)
    .Server.WithCredential(ServerCredential).Build);
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix)
    .Client.WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .Build, 'localhost');
  RunHandshake(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'Compatible preset engine');
end;

procedure TTestTls12DualVersion.TestCompatiblePresetMutualTlsCompletes;
var
  LClient, LServer: ITlsEngine;
  LClientCred: TTlsCredential;
  LClientRoot: TBytes;
begin
  // mutual TLS through the preset/config surface: the server requires and trusts the
  // client certificate, the client presents its credential. The client presents a
  // dual-EKU (clientAuth) leaf so it satisfies the server's extendedKeyUsage check.
  LClientCred := ClientAuthCredential(LClientRoot);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix)
    .Server.WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(LClientRoot).Build).Build);
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix)
    .Client.WithCredential(LClientCred)
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .Build, 'localhost');
  RunHandshake(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'Compatible preset mutual TLS');
end;

procedure TTestTls12DualVersion.TestGarbageFirstRecordAbortsWithoutRaising;
var
  LServer: ITlsEngine;
begin
  // a malformed first ClientHello on the dual-version path must surface as a fatal alert
  // from the dispatch machine, never as an unhandled exception out of ProcessInput. The
  // record frames a complete but truncated client_hello (a 3-byte body over-reads)
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12));
  Feed(LServer, DecodeHex('160303000701000003AABBCC'));
  CheckTrue(LServer.IsTerminal, 'a garbage ClientHello aborts the dual-version server');
  CheckFalse(LServer.IsHandshaking, 'the server did not stay handshaking');
end;

procedure TTestTls12DualVersion.TestFirstMessageOfTheWrongTypeIsUnexpectedMessage;
var
  LServer, LClient: ITlsEngine;
begin
  // the dispatchers judge the first message's type before decoding its body as a hello, so
  // another message is unexpected_message, not a decode_error from a body of the wrong shape
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12));
  Feed(LServer, DecodeHex('160303000414000000')); // an empty Finished where a ClientHello belongs
  CheckTrue(LServer.IsTerminal, 'the dual-version server aborts');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.UnexpectedMessage,
    'a Finished as the first message is unexpected_message (server dispatcher)');

  LClient := NewDualClient;
  LClient.StartHandshake;
  Feed(LClient, DecodeHex('160303000408000000')); // an empty EncryptedExtensions before any hello
  CheckTrue(LClient.IsTerminal, 'the dual-version client aborts');
  CheckTrue(LClient.LastError.Alert.Description = TTlsAlertDescription.UnexpectedMessage,
    'an EncryptedExtensions before the ServerHello is unexpected_message (client dispatcher)');
end;

procedure TTestTls12DualVersion.TestTls12ServerHelloWithTls13ExtensionIsRefused;
var
  LClient: ITlsEngine;
  LSh: TTlsServerHello;
  LVec: TExtensionVector;
  LMsg, LWire: TBytes;
begin
  // the unified hello offered key_share, so the codec alone accepts the echo; a 1.2 server that
  // answers with a TLS 1.3 construct is refused (unsupported_extension) once 1.2 is selected
  LClient := NewDualClient;
  LClient.StartHandshake;
  Drain(LClient);
  LSh.LegacyVersion := TlsWireVersionTls12;
  LSh.Random := Filled($22, 32);
  LSh.LegacySessionIdEcho := nil;
  LSh.CipherSuite := TCipherSuites12.EcdheEcdsaAes128GcmSha256;
  LVec := TExtensionVector.Empty;
  // a well-formed key_share: x25519 and a 32-byte share
  LVec.Append(TExtensionEntry.Create(TExtensionTypes.KeyShare,
    ConcatBytes(DecodeHex('001D0020'), Filled($33, 32))));
  LSh.Extensions := LVec.Encode;
  LMsg := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LSh));
  LWire := ConcatBytes(DecodeHex('160303'),
    ConcatBytes(TBytes.Create(Byte(System.Length(LMsg) shr 8), Byte(System.Length(LMsg))), LMsg));
  Feed(LClient, LWire);
  CheckTrue(LClient.IsTerminal, 'the dual-version client aborts');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedExtension),
    Ord(LClient.LastError.Alert.Description),
    'a key_share in a 1.2 ServerHello is unsupported_extension');
end;

procedure TTestTls12DualVersion.TestServerHelloTls13LegacyVersionWithoutSupportedVersionsIsProtocolVersion;
var
  LClient: ITlsEngine;
  LSh: TTlsServerHello;
  LVec: TExtensionVector;
  LMsg, LWire: TBytes;
begin
  // TLS 1.3 is selected only through supported_versions (RFC 9846 4.3.1; E.1 for the alert): the
  // dispatcher routes legacy_version 0x0304 to the 1.3 machine, which refuses it
  LClient := NewDualClient;
  LClient.StartHandshake;
  Drain(LClient);
  LSh.Random := Filled($22, 32);
  LSh.LegacySessionIdEcho := nil;
  LSh.CipherSuite := TCipherSuites13.Aes128GcmSha256;
  LVec := TExtensionVector.Empty;
  LVec.Append(TExtensionEntry.Create(TExtensionTypes.KeyShare,
    ConcatBytes(DecodeHex('001D0020'), Filled($33, 32))));
  LSh.Extensions := LVec.Encode;
  LMsg := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LSh));
  // the encoder writes legacy_version 0x0303; patch it to 0x0304 behind the 4-byte handshake header
  LMsg[5] := $04;
  LWire := ConcatBytes(DecodeHex('160303'),
    ConcatBytes(TBytes.Create(Byte(System.Length(LMsg) shr 8), Byte(System.Length(LMsg))), LMsg));
  Feed(LClient, LWire);
  CheckTrue(LClient.IsTerminal, 'the dual-version client aborts');
  CheckEquals(Ord(TTlsAlertDescription.ProtocolVersion),
    Ord(LClient.LastError.Alert.Description),
    'legacy_version 0x0304 without supported_versions is protocol_version');
end;

procedure TTestTls12DualVersion.TestServerHelloSelectingAnUnofferedVersionIsProtocolVersion;
var
  LClient: ITlsEngine;
  LSh: TTlsServerHello;
  LVec: TExtensionVector;
  LMsg, LWire: TBytes;
  LVersion: UInt16;
  LI: Int32;
begin
  // a supported_versions selection above 1.3 (a future version or a GREASE value) is a version
  // this client never offered: protocol_version, not a handshake that silently falls to 1.2
  for LI := 0 to 1 do
  begin
    if LI = 0 then
      LVersion := $0305
    else
      LVersion := $7A7A;
    LClient := NewDualClient;
    LClient.StartHandshake;
    Drain(LClient);
    LSh.LegacyVersion := TlsWireVersionTls12;
    LSh.Random := Filled($22, 32);
    LSh.LegacySessionIdEcho := nil;
    LSh.CipherSuite := TCipherSuites13.Aes128GcmSha256;
    LVec := TExtensionVector.Empty;
    LVec.Append(TExtensionEntry.Create(TExtensionTypes.SupportedVersions,
      TBytes.Create(Byte(LVersion shr 8), Byte(LVersion))));
    LSh.Extensions := LVec.Encode;
    LMsg := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
      THandshakeMessages.EncodeServerHello(LSh));
    LWire := ConcatBytes(DecodeHex('160303'),
      ConcatBytes(TBytes.Create(Byte(System.Length(LMsg) shr 8), Byte(System.Length(LMsg))), LMsg));
    Feed(LClient, LWire);
    CheckTrue(LClient.IsTerminal, 'the client aborts');
    CheckEquals(Ord(TTlsAlertDescription.ProtocolVersion),
      Ord(LClient.LastError.Alert.Description),
      Format('selecting version %x is protocol_version', [LVersion]));
  end;
end;

procedure TTestTls12DualVersion.TestServerHelloSelectingPreTls13VersionIsRefusedByTheDispatcher;
var
  LClient: ITlsEngine;
  LSh: TTlsServerHello;
  LVec: TExtensionVector;
  LMsg, LWire: TBytes;
  LVersion: string;
  LI: Int32;
begin
  // 0x0000 must not read as absent and fall through to the 1.2 machine; 0x0303 is the exact upper
  // edge of the pre-1.3 values. The dispatcher's own reason is pinned, since the 1.2 machine's
  // guard raises the same alert
  for LI := 0 to 1 do
  begin
    if LI = 0 then
      LVersion := '0000'
    else
      LVersion := '0303';
    LClient := NewDualClient;
    LClient.StartHandshake;
    Drain(LClient);
    LSh.Random := Filled($22, 32);
    LSh.LegacySessionIdEcho := nil;
    LSh.CipherSuite := TCipherSuites12.EcdheEcdsaAes128GcmSha256;
    LVec := TExtensionVector.Empty;
    LVec.Append(TExtensionEntry.Create(TExtensionTypes.SupportedVersions, DecodeHex(LVersion)));
    LSh.Extensions := LVec.Encode;
    LMsg := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
      THandshakeMessages.EncodeServerHello(LSh));
    LWire := ConcatBytes(DecodeHex('160303'),
      ConcatBytes(TBytes.Create(Byte(System.Length(LMsg) shr 8), Byte(System.Length(LMsg))), LMsg));
    Feed(LClient, LWire);
    CheckTrue(LClient.IsTerminal, 'the client aborts on ' + LVersion);
    CheckEquals(Ord(TTlsAlertDescription.UnsupportedExtension),
      Ord(LClient.LastError.Alert.Description),
      'supported_versions = ' + LVersion + ' is unsupported_extension');
    CheckTrue(Pos('selecting a version below TLS 1.3', LClient.LastError.Message) > 0,
      'the dispatcher refused supported_versions = ' + LVersion + ': ' + LClient.LastError.Message);
  end;
end;

procedure TTestTls12DualVersion.TestServerHelloSelectingTls13ReachesTheTls13Machine;
var
  LClient: ITlsEngine;
  LSh: TTlsServerHello;
  LVec: TExtensionVector;
  LMsg, LWire, LSent: TBytes;
begin
  // the exact value 0x0304 passes the version gate: with no key_share the 1.3 machine then
  // refuses with missing_extension, not a version alert
  LClient := NewDualClient;
  LClient.StartHandshake;
  LSent := Drain(LClient);
  // record header 5 + handshake header 4 + legacy_version 2 + random 32, then the session id
  LSh.Random := Filled($22, 32);
  LSh.LegacySessionIdEcho := System.Copy(LSent, 44, LSent[43]);
  LSh.CipherSuite := TCipherSuites13.Aes128GcmSha256;
  LVec := TExtensionVector.Empty;
  LVec.Append(TExtensionEntry.Create(TExtensionTypes.SupportedVersions, DecodeHex('0304')));
  LSh.Extensions := LVec.Encode;
  LMsg := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LSh));
  LWire := ConcatBytes(DecodeHex('160303'),
    ConcatBytes(TBytes.Create(Byte(System.Length(LMsg) shr 8), Byte(System.Length(LMsg))), LMsg));
  Feed(LClient, LWire);
  CheckTrue(LClient.IsTerminal, 'the client aborts');
  CheckEquals(Ord(TTlsAlertDescription.MissingExtension),
    Ord(LClient.LastError.Alert.Description),
    'supported_versions = 0x0304 passes the version gate and fails on the missing key_share');
end;

function TTestTls12DualVersion.MakeClientHello(const ACipherSuites: TArray<UInt16>;
  const AExtensions: TBytes): TTlsHandshakeMessage;
var
  LHello: TTlsClientHello;
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
begin
  LHello.Random := Filled($11, 32);
  LHello.LegacySessionId := nil;
  LHello.CipherSuites := ACipherSuites;
  LHello.Extensions := AExtensions;
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

function TTestTls12DualVersion.HasAnyFail(
  const AEffects: TArray<THandshakeEffect>): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.Fail then
      Result := True;
end;

function TTestTls12DualVersion.RealClientHello(
  ALegacyVersion: UInt16): TTlsHandshakeMessage;
var
  LClient: IHandshakeMachine;
  LEffect: THandshakeEffect;
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
begin
  LFramed := nil;
  LClient := TClientVersionDispatchMachine.Create(Client13Params, Client12Params)
    as IHandshakeMachine;
  for LEffect in LClient.Start do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
      LFramed := LEffect.Bytes;
  CheckTrue(System.Length(LFramed) > 0, 'the client emitted a ClientHello');
  // legacy_version follows the 4-byte handshake header
  LFramed[4] := Byte(ALegacyVersion shr 8);
  LFramed[5] := Byte(ALegacyVersion);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

function TTestTls12DualVersion.AbortsProtocolVersion(const AServer: IHandshakeMachine;
  ALegacyVersion: UInt16): Boolean;
begin
  Result := HasFailAlert(AServer.ProcessMessage(RealClientHello(ALegacyVersion)),
    TTlsAlertDescription.ProtocolVersion);
end;

procedure TTestTls12DualVersion.TestDispatcherAcceptsLegacyVersion0303;
var
  LServer: IHandshakeMachine;
begin
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckFalse(HasAnyFail(LServer.ProcessMessage(RealClientHello(TlsWireVersionTls12))),
    'a conformant ClientHello proceeds');
end;

procedure TTestTls12DualVersion.TestDispatcherRejectsLegacyVersion0302WithSupportedVersions;
var
  LServer: IHandshakeMachine;
begin
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(AbortsProtocolVersion(LServer, TlsWireVersionTls11),
    'legacy_version 0x0302 with supported_versions aborts protocol_version (RFC 9846 4.2.2)');
end;

procedure TTestTls12DualVersion.TestDispatcherRejectsLegacyVersion0304WithSupportedVersions;
var
  LServer: IHandshakeMachine;
begin
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(AbortsProtocolVersion(LServer, TlsWireVersionTls13),
    'legacy_version 0x0304 with supported_versions aborts protocol_version (RFC 9846 4.2.2)');
end;

procedure TTestTls12DualVersion.TestDispatcherRejectsLegacyVersion0300WithSupportedVersions;
var
  LServer: IHandshakeMachine;
  LSsl3: UInt16;
begin
  LSsl3 := $0300;
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(AbortsProtocolVersion(LServer, LSsl3),
    'legacy_version 0x0300 with supported_versions aborts protocol_version (RFC 9846 E.5)');
end;

procedure TTestTls12DualVersion.TestDispatcherRejectsLegacyVersion0000WithSupportedVersions;
var
  LServer: IHandshakeMachine;
  LZero: UInt16;
begin
  LZero := 0;
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(AbortsProtocolVersion(LServer, LZero),
    'legacy_version 0x0000 with supported_versions aborts protocol_version');
end;

procedure TTestTls12DualVersion.TestDispatcherRejectsLegacyVersion0302WithTls12OnlySupportedVersions;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  // supported_versions [1.2] alone would route to the TLS 1.2 machine; the legacy_version rule
  // still applies on a 1.3-capable server
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0007002B0003020303'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $02;
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello), TTlsAlertDescription.ProtocolVersion),
    'legacy_version 0x0302 with supported_versions [1.2] aborts protocol_version');
end;

procedure TTestTls12DualVersion.TestDispatcherWithoutSupportedVersionsKeepsLegacyVersionHandling;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  // without supported_versions the client tops out at 1.2 whatever legacy_version says
  // (RFC 9846 4.3.1): no protocol_version, whatever else the bare hello later fails on.
  // A guard, not a mutation target: the unchanged path is what it pins.
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $04;
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckFalse(HasFailAlert(LServer.ProcessMessage(LHello), TTlsAlertDescription.ProtocolVersion),
    'legacy_version 0x0304 without supported_versions is not protocol_version');
end;

procedure TTestTls12DualVersion.TestTls12OnlyDispatcherRejectsLegacyVersion0302WithSupportedVersions;
var
  LServer: IHandshakeMachine;
begin
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(AbortsProtocolVersion(LServer, TlsWireVersionTls11),
    'a TLS 1.2-only dispatcher aborts protocol_version on legacy_version 0x0302 with supported_versions');
end;

procedure TTestTls12DualVersion.TestStandaloneTls12ServerRejectsLegacyVersion0300WithSupportedVersions;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0007002B0003020303'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $00;
  LServer := TTls12ServerStateMachine.Create(Server12Params) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello), TTlsAlertDescription.ProtocolVersion),
    'legacy_version 0x0300 with supported_versions [1.2] aborts protocol_version (RFC 9846 E.5)');
end;

procedure TTestTls12DualVersion.TestScsvOutranksLegacyVersionRejection;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  // the fallback verdict comes first, so the spurious-fallback signal is not masked
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0007002B0003020303'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $02;
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello),
    TTlsAlertDescription.InappropriateFallback),
    'SCSV with a bad legacy_version aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestStandaloneTls13ServerAcceptsLegacyVersion0303;
var
  LServer: IHandshakeMachine;
begin
  LServer := TTls13ServerStateMachine.Create(Server13Params) as IHandshakeMachine;
  CheckFalse(HasAnyFail(LServer.ProcessMessage(RealClientHello(TlsWireVersionTls12))),
    'a conformant ClientHello proceeds');
end;

procedure TTestTls12DualVersion.TestStandaloneTls13ServerRejectsLegacyVersion0304;
var
  LServer: IHandshakeMachine;
begin
  LServer := TTls13ServerStateMachine.Create(Server13Params) as IHandshakeMachine;
  CheckTrue(AbortsProtocolVersion(LServer, TlsWireVersionTls13),
    'legacy_version 0x0304 aborts protocol_version at a 1.3 server');
end;

procedure TTestTls12DualVersion.TestStandaloneTls13ServerRejectsLegacyVersion0300;
var
  LServer: IHandshakeMachine;
  LSsl3: UInt16;
begin
  LSsl3 := $0300;
  LServer := TTls13ServerStateMachine.Create(Server13Params) as IHandshakeMachine;
  CheckTrue(AbortsProtocolVersion(LServer, LSsl3),
    'legacy_version 0x0300 aborts protocol_version at a 1.3 server');
end;

procedure TTestTls12DualVersion.TestServerRejectsSupportedVersionsWithoutCommonVersion;
var
  LServer: IHandshakeMachine;
begin
  // a client that offers only 0x1111 in supported_versions shares no version with a
  // 1.3+1.2 server: protocol_version, not a 1.2 handshake (RFC 9846 4.3.1)
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256),
    DecodeHex('0007002B0003021111'))), TTlsAlertDescription.ProtocolVersion),
    'no common version aborts protocol_version');
end;

procedure TTestTls12DualVersion.TestLegacyEchHelloWithoutKeyStoreStaysOnTls12;
var
  LServer: IHandshakeMachine;
  LEffects: TArray<THandshakeEffect>;
begin
  // a hello with no supported_versions that carries an ech extension is only routed to the 1.3
  // machine when the server holds ECH keys; otherwise it is a 1.2 client GREASE-ing ech, which is
  // not offering ECH (RFC 9849 sec. 6.2.1). The 1.2 machine's own verdict (no signature_algorithms
  // is handshake_failure here) proves the routing, where the 1.3 route would say protocol_version
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  LEffects := LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0004FE0D0000')));
  CheckFalse(HasFailAlert(LEffects, TTlsAlertDescription.ProtocolVersion),
    'a GREASE ech without keys is not routed to the TLS 1.3 machine');
  CheckTrue(HasFailAlert(LEffects, TTlsAlertDescription.HandshakeFailure),
    'the TLS 1.2 machine judged the hello');
end;

procedure TTestTls12DualVersion.TestServerWithoutSignatureAlgorithmsIsHandshakeFailure;
var
  LServer: IHandshakeMachine;
begin
  // RFC 5246 7.4.1.4.1 makes omitting signature_algorithms legal in TLS 1.2 (it implies SHA-1);
  // our hardened server refuses it, and the refusal is handshake_failure (a policy choice), not
  // the TLS 1.3 missing_extension. Extensions: supported_versions [1.2] + supported_groups
  // [X25519, secp256r1] (the ECDSA leaf's curve gate), and NO signature_algorithms.
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0011002b0003020303000a00060004001d0017'))),
    TTlsAlertDescription.HandshakeFailure),
    'a TLS 1.2 ClientHello without signature_algorithms aborts handshake_failure');
end;

procedure TTestTls12DualVersion.TestEmptySupportedVersionsAtDispatchIsDecodeError;
var
  LServer: IHandshakeMachine;
begin
  // the version dispatcher's supported_versions pre-scan rejects an empty list as decode_error
  // rather than treating it as absent and negotiating legacy (RFC 9846 4.3.1). Extensions =
  // one supported_versions extension carrying an empty versions list.
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0005002b000100'))), TTlsAlertDescription.DecodeError),
    'an empty supported_versions list at dispatch is decode_error');
end;

procedure TTestTls12DualVersion.TestTls13OnlyDispatcherRejectsTls12OnlyOffer;
var
  LServer: IHandshakeMachine;
begin
  // a 1.3-only server reached by a client offering only 1.2 in supported_versions shares no
  // version: protocol_version
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0007002B0003020303'))), TTlsAlertDescription.ProtocolVersion),
    'a 1.2-only offer to a 1.3-only server aborts protocol_version');
end;

procedure TTestTls12DualVersion.TestTls12OnlyServerRejectsTls13OnlyOffer;
var
  LServer: IHandshakeMachine;
begin
  // the 1.2-only server machine, reached directly, rejects a client that offers only 1.3 in
  // supported_versions: it shares no version with it (RFC 9846 4.3.1)
  LServer := TTls12ServerStateMachine.Create(Server12Params) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0007002B0003020304'))), TTlsAlertDescription.ProtocolVersion),
    'a 1.3-only offer to a 1.2-only server aborts protocol_version');
end;

procedure TTestTls12DualVersion.TestScsvFromLowerClientAborts;
var
  LServer: IHandshakeMachine;
begin
  // a client that fell back to 1.2 (no supported_versions, so it tops out at 1.2) yet
  // signals TLS_FALLBACK_SCSV, reaching a 1.3-capable server, is an inappropriate
  // fallback: the server could have done 1.3 (RFC 7507)
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'))), TTlsAlertDescription.InappropriateFallback),
    'SCSV from a fallen-back client to a 1.3-capable server aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestSpuriousFallbackSaysWhy;
var
  LServer: IHandshakeMachine;
  LEffect: THandshakeEffect;
  LReason: string;
begin
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  LReason := '';
  for LEffect in LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'))) do
    if LEffect.Kind = THandshakeEffectKind.Fail then
      LReason := LEffect.Reason;
  CheckEquals('the client signalled a fallback below the highest version this server supports',
    LReason, 'the dispatcher names the inappropriate fallback');
end;

procedure TTestTls12DualVersion.TestScsvToStandaloneTls13ServerAborts;
var
  LServer: IHandshakeMachine;
begin
  // the factory builds a single-version 1.3 server directly, bypassing the dispatcher. A client that
  // fell back to 1.2 (no supported_versions) yet signals TLS_FALLBACK_SCSV must still get
  // inappropriate_fallback here - the 1.3 server could have done better (RFC 7507)
  LServer := TTls13ServerStateMachine.Create(Server13Params) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites13.Aes128GcmSha256),
    DecodeHex('0000'))), TTlsAlertDescription.InappropriateFallback),
    'SCSV from a fallen-back client to a standalone 1.3 server aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestScsvWithTls13OfferToStandaloneServerIsNotFallback;
var
  LServer: IHandshakeMachine;
begin
  // a client that offers 1.3 in supported_versions and also carries SCSV is not a spurious fallback
  // at a standalone 1.3 server (server_max = client_max), so the fallback check must not fire (the
  // ClientHello still aborts later on its absent supported_groups/key_share - just not with
  // inappropriate_fallback)
  LServer := TTls13ServerStateMachine.Create(Server13Params) as IHandshakeMachine;
  CheckFalse(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites13.Aes128GcmSha256),
    DecodeHex('0009002B00050403040303'))),
    TTlsAlertDescription.InappropriateFallback),
    'SCSV with a current 1.3 offer is not treated as a fallback at a standalone 1.3 server');
end;

procedure TTestTls12DualVersion.TestScsvFromCurrentClientDoesNotAbort;
var
  LServer: IHandshakeMachine;
begin
  // a normal 1.3 client lists 1.3 in supported_versions and may still carry SCSV;
  // server_max = client_max, so it is not a fallback and must not fire. Extensions =
  // supported_versions [1.3, 1.2]
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckFalse(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites13.Aes128GcmSha256),
    DecodeHex('0009002B00050403040303'))),
    TTlsAlertDescription.InappropriateFallback),
    'SCSV with a current 1.3 offer is not a fallback');
end;

procedure TTestTls12DualVersion.TestScsvFromPre12ClientToStandaloneTls12ServerAborts;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  // reached without the dispatcher, as the factory builds a single-version server
  LServer := TTls12ServerStateMachine.Create(Server12Params) as IHandshakeMachine;
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $01;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello),
    TTlsAlertDescription.InappropriateFallback),
    'SCSV from a pre-1.2 client to a standalone 1.2 server aborts inappropriate_fallback (RFC 7507 3)');
end;

procedure TTestTls12DualVersion.TestScsvWithGreaseAndPre12VersionToStandaloneTls12ServerAborts;
var
  LServer: IHandshakeMachine;
begin
  LServer := TTls12ServerStateMachine.Create(Server12Params) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0009002B0005040A0A0302'))),
    TTlsAlertDescription.InappropriateFallback),
    'supported_versions [GREASE, 1.1] with SCSV aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestScsvWithGreaseOnlyVersionsIsNotFallbackAtStandaloneServers;
var
  LServer: IHandshakeMachine;
  LEffects: TArray<THandshakeEffect>;
begin
  LServer := TTls12ServerStateMachine.Create(Server12Params) as IHandshakeMachine;
  LEffects := LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0007002B0003020A0A')));
  CheckTrue(HasFailAlert(LEffects, TTlsAlertDescription.ProtocolVersion),
    'a GREASE-only list aborts protocol_version at a 1.2 server');
  CheckFalse(HasFailAlert(LEffects, TTlsAlertDescription.InappropriateFallback),
    'and is no fallback signal');
  LServer := TTls13ServerStateMachine.Create(Server13Params) as IHandshakeMachine;
  CheckFalse(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites13.Aes128GcmSha256),
    DecodeHex('0007002B0003020A0A'))),
    TTlsAlertDescription.InappropriateFallback), 'nor at a 1.3 server');
end;

procedure TTestTls12DualVersion.TestPre12ClientWithoutScsvToStandaloneTls12ServerIsProtocolVersion;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  LServer := TTls12ServerStateMachine.Create(Server12Params) as IHandshakeMachine;
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256), DecodeHex('0000'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $01;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello), TTlsAlertDescription.ProtocolVersion),
    'a pre-1.2 client without SCSV aborts protocol_version');
end;

procedure TTestTls12DualVersion.TestScsvToLegacyOnlyServerDoesNotAbort;
var
  LServer: IHandshakeMachine;
begin
  // a 1.2-only server (1.3 not in its supported set) reached by a 1.2 client that carries
  // SCSV: server_max = client_max = 1.2, a legitimate 1.2 handshake, not a fallback
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls12)) as IHandshakeMachine;
  CheckFalse(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'))), TTlsAlertDescription.InappropriateFallback),
    'SCSV to a 1.2-only server is not a fallback');
end;

procedure TTestTls12DualVersion.TestScsvWithFutureLegacyVersionAndNoExtensionIsFallbackAtDispatcher;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  // without supported_versions the client tops out at 1.2 whatever legacy_version says (RFC 9846 4.3.1)
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $04;
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello),
    TTlsAlertDescription.InappropriateFallback),
    'the dual-version dispatcher aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestScsvWithFutureLegacyVersionAndNoExtensionIsFallbackAtStandaloneTls13Server;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'));
  // the 1.3 server decodes the framed bytes, so patch legacy_version behind the 4-byte header
  LHello.Raw[4] := $03;
  LHello.Raw[5] := $04;
  LServer := TTls13ServerStateMachine.Create(Server13Params) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello),
    TTlsAlertDescription.InappropriateFallback),
    'the standalone 1.3 server aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestScsvFromPre12ClientToTls12OnlyDispatcherAborts;
var
  LServer: IHandshakeMachine;
  LHello: TTlsHandshakeMessage;
begin
  // a pre-1.2 legacy_version is the client's version (RFC 7507 3)
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls12)) as IHandshakeMachine;
  LHello := MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000'));
  LHello.Body[0] := $03;
  LHello.Body[1] := $01;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(LHello),
    TTlsAlertDescription.InappropriateFallback),
    'SCSV from a pre-1.2 client to a 1.2-only dispatcher aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestScsvWithGreaseVersionStillDetectsFallback;
var
  LServer: IHandshakeMachine;
begin
  // a GREASE codepoint (RFC 8701 3.1; a server must not negotiate it, 3.2) in supported_versions
  // is not an offered version: a
  // client that lists [GREASE, 1.2] and carries SCSV against a 1.3-capable server still
  // fell back spuriously (RFC 7507). Extensions = supported_versions [0x0A0A, 0x0303]
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0009002B0005040A0A0303'))),
    TTlsAlertDescription.InappropriateFallback),
    'SCSV with a GREASE-padded 1.2-only offer is still an inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestScsvWithGreaseAndCurrentVersionDoesNotAbort;
var
  LServer: IHandshakeMachine;
begin
  // the GREASE value must not disturb a genuine 1.3 offer either: [GREASE, 1.3, 1.2] + SCSV
  // is a current client, not a fallback. Extensions = supported_versions [0x0A0A, 1.3, 1.2]
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckFalse(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites13.Aes128GcmSha256),
    DecodeHex('000B002B0007060A0A03040303'))),
    TTlsAlertDescription.InappropriateFallback),
    'SCSV with a GREASE-padded current offer is not a fallback');
end;

procedure TTestTls12DualVersion.TestGreaseOnlySupportedVersionsRejected;
var
  LServer: IHandshakeMachine;
begin
  // a supported_versions that lists only a GREASE codepoint offers no version at all:
  // protocol_version (RFC 9846 4.3.1)
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasFailAlert(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256),
    DecodeHex('0007002B0003020A0A'))), TTlsAlertDescription.ProtocolVersion),
    'a GREASE-only supported_versions aborts protocol_version');
end;

procedure TTestTls12DualVersion.TestClientEngineWithoutHostFailsClosed;
var
  LRaised: Boolean;
begin
  // fail-closed: name checking is on by default, so creating a client engine with no host
  // to verify the certificate against must raise rather than silently skip RFC 9525.
  LRaised := False;
  try
    TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix)
      .Client.WithServerVerification(TServerVerification.WebPki(
        TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
      .Build, '');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client engine with name-check on and no host fails closed');

  // opting out with WithDangerousDisableServerNameCheck allows an empty host (chain-only trust, no SNI)
  TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix)
    .Client.WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithDangerousDisableServerNameCheck.Build, '');
  CheckTrue(True, 'with name-check off, an empty host is allowed');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12DualVersion);
{$ELSE}
  RegisterTest(TTestTls12DualVersion.Suite);
{$ENDIF FPC}

end.
