{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HostExtensionTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpISecretBuffer,
  TlpExtensionVector,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpCoreExtensions,
  TlpITlsHostExtension,
  TlpHostExtensions,
  TlpISession,
  TlpInMemorySessionCache,
  TlpEchConfig,
  TlpEchClient,
  TlpInMemoryEchKeyStore,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpCertificateVerifierSource,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlsLibTestHandshakeDecoder,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  /// <summary>
  /// Host extensions on the record engine: data a host supplies, carried by the registry and
  /// read back from the peer, driven through the factory over two engines.
  /// </summary>
  TTestHostExtension = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
    HostType = UInt16($FC01);
    OtherType = UInt16($FC02);
    function ClientBuilder(const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
    function Client13: ITlsClientConfig;
    function Client13Resuming: ITlsClientConfig;
    function Server13: ITlsServerConfig;
    function Client12Capable: ITlsClientConfig;
    function Server12Only: ITlsServerConfig;
    function Server12Capable: ITlsServerConfig;
    function MtlsClient13: ITlsClientConfig;
    function MtlsServer13: ITlsServerConfig;
    /// <summary>A client preferring X25519 then secp256r1 and a secp256r1-only server, so the
    /// server answers with a HelloRetryRequest.</summary>
    function ClientRetry: ITlsClientConfig;
    function ServerRetry: ITlsServerConfig;
    function PeerBody(const AEngine: ITlsEngine; AType: UInt16; out ABody: TBytes): Boolean;
    function EchConfigList(AConfigId: Byte; const APublicName: string;
      out APrivateKey: ISecretBuffer): TBytes;
    function EchClient(const AConfigList: TBytes; AOriginNameCheck: Boolean): ITlsClientConfig;
    function EchServer(const AConfigList: TBytes; const APrivateKey: ISecretBuffer): ITlsServerConfig;
    procedure CheckFailedWith(const AEngine: ITlsEngine; AAlert: TTlsAlertDescription;
      const AMessage: string);
    function MakeRaises(AType: UInt16; ASendIn: TTlsExtensionContexts;
      const ABody: TBytes; ARequiredIn: TTlsExtensionContexts): Boolean;
    function ClientCreationRaises(const AConfig: ITlsClientConfig;
      const AExtensions: TArray<ITlsHostExtension>): Boolean;
    function ServerCreationRaises(const AConfig: ITlsServerConfig;
      const AExtensions: TArray<ITlsHostExtension>): Boolean;
    function NewCodec(const AExtension: ITlsHostExtension; ARole: TTlsHostExtensionRole;
      out AResults: ITlsHostExtensionResults): IExtensionBlockCodec;
    /// <summary>The alert ABlock draws when the codec consumes it as AKind (close_notify when none),
    /// with HostType already offered in the ClientHello when AMarkOffered.</summary>
    function ConsumeAlert(const ACodec: IExtensionBlockCodec; AKind: TTlsExtensionContextKind;
      const ABlock: TBytes; AMarkOffered: Boolean): TTlsAlertDescription;
    function BlockWith(const ABody: TBytes): TBytes;
  published
    procedure TestMakeRejectsAGreaseType;
    procedure TestMakeRejectsEchOuterExtensionsAsAType;
    procedure TestMakeRejectsAServerHelloKind;
    procedure TestMakeRejectsACertificateKind;
    procedure TestMakeRejectsAnOversizedBody;
    procedure TestMakeCopiesTheBody;
    procedure TestAnImplementerIsReadOnceAndValidatedAsRead;
    procedure TestEngineCreationRejectsATypeTheCoreRegistryHolds;
    procedure TestEngineCreationRejectsPreSharedKeyAndEchTypes;
    procedure TestEngineCreationRejectsATypeListedTwice;
    procedure TestEngineCreationRejectsANilExtension;
    procedure TestEngineCreationRejectsAConfigWithoutTls13;
    procedure TestClientRefusesToSendOutsideTheClientHello;
    procedure TestClientRefusesToRequireInTheClientHello;
    procedure TestServerRefusesToSendInTheClientHello;
    procedure TestServerRefusesToRequireOutsideTheClientHello;
    procedure TestHostExtensionsGoBothWaysAndAreReadBack;
    procedure TestPeerBodyIsReadableOnceTheClientHelloIsProcessed;
    procedure TestRequiredExtensionMissingFromEncryptedExtensionsFailsTheClient;
    procedure TestRequiredExtensionMissingFromTheClientHelloFailsTheServer;
    procedure TestServerAnswersOnlyAnOfferedType;
    procedure TestHostExtensionRidesTheNewSessionTicket;
    procedure TestRequiredExtensionMissingFromTheNewSessionTicketFailsTheClient;
    procedure TestHostExtensionRidesTheCertificateRequest;
    procedure TestPeerCopyInAServerHelloIsIllegalParameter;
    procedure TestAnAnswerInAnUndeclaredMessageFailsTheClient;
    procedure TestALaterUndeclaredCopyFailsTheClient;
    procedure TestASecondBlockOfAKindReplacesTheFirst;
    procedure TestTheEarliestCopyIsKept;
    procedure TestTls12HandshakeCarriesNoHostExtension;
    procedure TestDualVersionServerDoesNotEnforceRequirementsOverTls12;
    procedure TestSecondClientHelloCarriesTheSameExtensionBytes;
    procedure TestHostExtensionRidesTheHelloRetryRequestAndTheAnswer;
    procedure TestUnsolicitedResponseIsUnsupportedExtension;
    procedure TestOfferedResponseIsAcceptedAndRead;
    procedure TestEchAcceptCarriesTheExtensionInOuterAndInner;
    procedure TestEchRejectShowsTheServerTheOuterCopy;
    procedure TestExistingEnginesAnswerNoHostExtensionResults;
  end;

implementation

const
  AtClientHello: TTlsExtensionContexts = [TTlsExtensionContextKind.ClientHello];
  AtRetry: TTlsExtensionContexts = [TTlsExtensionContextKind.HelloRetryRequest];
  AtEncrypted: TTlsExtensionContexts = [TTlsExtensionContextKind.EncryptedExtensions];
  AtRequest: TTlsExtensionContexts = [TTlsExtensionContextKind.CertificateRequest];
  AtTicket: TTlsExtensionContexts = [TTlsExtensionContextKind.NewSessionTicket];
  Nowhere: TTlsExtensionContexts = [];

type
  /// <summary>An implementer whose answers change on every read, to prove the engine reads it once.</summary>
  TShiftingHostExtension = class sealed(TInterfacedObject, ITlsHostExtension)
  strict private
  var
    FReads: Int32;
  public
    function ExtensionType: UInt16;
    function SendIn: TTlsExtensionContexts;
    function Body: TBytes;
    function RequiredIn: TTlsExtensionContexts;
  end;

function TShiftingHostExtension.ExtensionType: UInt16;
begin
  Result := UInt16($FC10);
end;

function TShiftingHostExtension.SendIn: TTlsExtensionContexts;
begin
  // the first read is the ClientHello a client may send, later ones a message it never sends
  Inc(FReads);
  if FReads = 1 then
    Result := AtClientHello
  else
    Result := AtEncrypted;
end;

function TShiftingHostExtension.Body: TBytes;
begin
  Result := nil;
end;

function TShiftingHostExtension.RequiredIn: TTlsExtensionContexts;
begin
  Result := Nowhere;
end;

{ TTestHostExtension }

function TTestHostExtension.ClientBuilder(
  const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(AVersions)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build);
end;

function TTestHostExtension.Client13: ITlsClientConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build;
end;

function TTestHostExtension.Client13Resuming: ITlsClientConfig;
begin
  // a server issues tickets only to a client that holds a cache for them
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumption(True).WithSessionCache(TInMemorySessionCache.Create as ISessionCache).Build;
end;

function TTestHostExtension.Server13: ITlsServerConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential).Build;
end;

function TTestHostExtension.Client12Capable: ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build;
end;

function TTestHostExtension.Server12Only: ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCredential(ServerCredential).Build;
end;

function TTestHostExtension.Server12Capable: ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(ServerCredential).Build;
end;

function TTestHostExtension.MtlsClient13: ITlsClientConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key'))).Build;
end;

function TTestHostExtension.MtlsServer13: ITlsServerConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')))
    .WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithPeerAuth(TClientAuthMode.Required).Build;
end;

function TTestHostExtension.ClientRetry: ITlsClientConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
      TNamedGroupCatalog.Secp256r1))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build;
end;

function TTestHostExtension.ServerRetry: ITlsServerConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1))
    .WithCredential(ServerCredential).Build;
end;

function TTestHostExtension.PeerBody(const AEngine: ITlsEngine; AType: UInt16;
  out ABody: TBytes): Boolean;
var
  LResults: ITlsHostExtensionResults;
begin
  CheckTrue(Supports(AEngine, ITlsHostExtensionResults, LResults),
    'the engine class lists the results interface');
  Result := LResults.TryGetPeerExtension(AType, ABody);
end;

function TTestHostExtension.EchConfigList(AConfigId: Byte; const APublicName: string;
  out APrivateKey: ISecretBuffer): TBytes;
var
  LPublicKey: TBytes;
  LSuites: TArray<TEchCipherSuite>;
  LConfig: TEchConfig;
begin
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey, APrivateKey);
  SetLength(LSuites, 1);
  LSuites[0].KdfId := THpkeKdf.HKDF_SHA256;
  LSuites[0].AeadId := THpkeAead.AES_128_GCM;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, AConfigId,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, LPublicKey, LSuites, 0,
    TEncoding.ASCII.GetBytes(APublicName), nil);
  Result := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));
end;

function TTestHostExtension.EchClient(const AConfigList: TBytes;
  AOriginNameCheck: Boolean): ITlsClientConfig;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build);
  if not AOriginNameCheck then
    LBuilder.WithDangerousDisableServerNameCheck;
  Result := LBuilder.Tls13.WithEch(TEchClientModes.Enable(AConfigList)).Build;
end;

function TTestHostExtension.EchServer(const AConfigList: TBytes;
  const APrivateKey: ISecretBuffer): ITlsServerConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .Tls13.WithEchKeyStore(TInMemoryEchKeyStore.FromConfig(AConfigList, APrivateKey,
    Crypto)).Build;
end;

procedure TTestHostExtension.CheckFailedWith(const AEngine: ITlsEngine;
  AAlert: TTlsAlertDescription; const AMessage: string);
begin
  CheckTrue(AEngine.IsTerminal, AMessage + ': the engine failed');
  CheckEquals(Ord(AAlert), Ord(AEngine.LastError.Alert.Description),
    AMessage + ': the alert');
end;

function TTestHostExtension.MakeRaises(AType: UInt16; ASendIn: TTlsExtensionContexts;
  const ABody: TBytes; ARequiredIn: TTlsExtensionContexts): Boolean;
begin
  Result := False;
  try
    TTlsHostExtensions.Make(AType, ASendIn, ABody, ARequiredIn);
  except
    on E: EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestHostExtension.ClientCreationRaises(const AConfig: ITlsClientConfig;
  const AExtensions: TArray<ITlsHostExtension>): Boolean;
begin
  Result := False;
  try
    TTlsEngineFactory.CreateClientEngine(AConfig, ServerHost, AExtensions);
  except
    on E: EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestHostExtension.ServerCreationRaises(const AConfig: ITlsServerConfig;
  const AExtensions: TArray<ITlsHostExtension>): Boolean;
begin
  Result := False;
  try
    TTlsEngineFactory.CreateServerEngine(AConfig, AExtensions);
  except
    on E: EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestHostExtension.NewCodec(const AExtension: ITlsHostExtension;
  ARole: TTlsHostExtensionRole;
  out AResults: ITlsHostExtensionResults): IExtensionBlockCodec;
begin
  Result := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry(
    TTlsHostExtensions.Adapt(TArray<ITlsHostExtension>.Create(AExtension), ARole,
    AResults))) as IExtensionBlockCodec;
end;

function TTestHostExtension.ConsumeAlert(const ACodec: IExtensionBlockCodec;
  AKind: TTlsExtensionContextKind; const ABlock: TBytes;
  AMarkOffered: Boolean): TTlsAlertDescription;
var
  LContext: TExtensionContext;
begin
  Result := TTlsAlertDescription.CloseNotify;
  LContext := TExtensionContext.Create;
  try
    if AMarkOffered then
      LContext.MarkOffered(HostType);
    try
      ACodec.ConsumeBlock(LContext, AKind, ABlock);
    except
      on E: EFatalAlertTlsLibException do
        Result := E.AlertDescription;
    end;
  finally
    LContext.Free;
  end;
end;

function TTestHostExtension.BlockWith(const ABody: TBytes): TBytes;
var
  LVector: TExtensionVector;
begin
  LVector := TExtensionVector.Empty;
  LVector.Append(TExtensionEntry.Create(HostType, ABody));
  Result := LVector.Encode;
end;

procedure TTestHostExtension.TestMakeRejectsAGreaseType;
begin
  CheckTrue(MakeRaises($0A0A, AtClientHello, nil, Nowhere),
    'a GREASE value is refused at creation');
  CheckTrue(MakeRaises($FAFA, AtClientHello, nil, Nowhere), 'every GREASE value is refused');
  CheckFalse(MakeRaises($0A0B, AtClientHello, nil, Nowhere),
    'a value next to a GREASE one is not');
end;

procedure TTestHostExtension.TestMakeRejectsEchOuterExtensionsAsAType;
begin
  CheckTrue(MakeRaises(TExtensionTypes.EchOuterExtensions, AtClientHello, nil, Nowhere),
    'ech_outer_extensions is refused at creation');
end;

procedure TTestHostExtension.TestMakeRejectsAServerHelloKind;
begin
  CheckTrue(MakeRaises(HostType, [TTlsExtensionContextKind.ServerHello], nil, Nowhere),
    'a ServerHello send kind is refused');
  CheckTrue(MakeRaises(HostType, Nowhere, nil, [TTlsExtensionContextKind.ServerHello]),
    'a ServerHello required kind is refused');
end;

procedure TTestHostExtension.TestMakeRejectsACertificateKind;
begin
  CheckTrue(MakeRaises(HostType, [TTlsExtensionContextKind.Certificate], nil, Nowhere),
    'a Certificate send kind is refused: no codec path reads it');
  CheckTrue(MakeRaises(HostType, Nowhere, nil, [TTlsExtensionContextKind.Certificate]),
    'a Certificate required kind is refused');
end;

procedure TTestHostExtension.TestMakeRejectsAnOversizedBody;
begin
  CheckFalse(MakeRaises(HostType, AtClientHello, Filled($11, 65535), Nowhere),
    'control: a 65535-byte body is allowed');
  CheckTrue(MakeRaises(HostType, AtClientHello, Filled($11, 65536), Nowhere),
    'a body beyond 65535 bytes is refused');
end;

procedure TTestHostExtension.TestMakeCopiesTheBody;
var
  LBody, LRead: TBytes;
  LExt: ITlsHostExtension;
begin
  LBody := Filled($22, 4);
  LExt := TTlsHostExtensions.Make(HostType, AtClientHello, LBody, Nowhere);
  LBody[0] := $99;
  LRead := LExt.Body;
  LRead[1] := $99;
  CheckEqualBytes('neither the caller''s array nor a returned copy reaches the extension',
    Filled($22, 4), LExt.Body);
end;

procedure TTestHostExtension.TestAnImplementerIsReadOnceAndValidatedAsRead;
var
  LResults: ITlsHostExtensionResults;
  LEntries: TArray<ITlsExtension>;
begin
  // later reads of this implementer name another message, so only a single read keeps what was validated
  LEntries := TTlsHostExtensions.Adapt(TArray<ITlsHostExtension>.Create(
    TShiftingHostExtension.Create as ITlsHostExtension), TTlsHostExtensionRole.Client, LResults);
  CheckEquals(1, System.Length(LEntries), 'the implementer is carried');
  CheckTrue(LEntries[0].ValidContexts = AtClientHello, 'as the first read declared it');
end;

procedure TTestHostExtension.TestEngineCreationRejectsATypeTheCoreRegistryHolds;
begin
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(TExtensionTypes.Alpn, AtClientHello, nil, Nowhere))),
    'application_layer_protocol_negotiation is a core type');
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(TExtensionTypes.ServerName, AtClientHello, nil, Nowhere))),
    'server_name is a core type');
end;

procedure TTestHostExtension.TestEngineCreationRejectsPreSharedKeyAndEchTypes;
begin
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(TExtensionTypes.PreSharedKey, AtClientHello, nil, Nowhere))),
    'pre_shared_key is a core type, though it is registered after the host entries');
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(TExtensionTypes.EncryptedClientHello, AtClientHello, nil, Nowhere))),
    'encrypted_client_hello is a core type, though it is registered after the host entries');
end;

procedure TTestHostExtension.TestEngineCreationRejectsATypeListedTwice;
begin
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, AtClientHello, nil, Nowhere),
    TTlsHostExtensions.Make(HostType, AtClientHello, nil, AtEncrypted))),
    'one type listed twice is refused');
  CheckFalse(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, AtClientHello, nil, Nowhere),
    TTlsHostExtensions.Make(OtherType, AtClientHello, nil, Nowhere))),
    'control: two types are fine');
end;

procedure TTestHostExtension.TestEngineCreationRejectsANilExtension;
begin
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(nil)),
    'a nil entry is refused');
end;

procedure TTestHostExtension.TestEngineCreationRejectsAConfigWithoutTls13;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := ClientBuilder(TArray<UInt16>.Create(TlsWireVersionTls12)).Build;
  CheckTrue(ClientCreationRaises(LConfig, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, AtClientHello, nil, Nowhere))),
    'host extensions ride TLS 1.3 only, so a TLS 1.2-only client is refused them');
  CheckFalse(ClientCreationRaises(LConfig, nil), 'control: no extensions, no refusal');
end;

procedure TTestHostExtension.TestClientRefusesToSendOutsideTheClientHello;
begin
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, AtEncrypted, nil, Nowhere))),
    'a client never sends EncryptedExtensions');
end;

procedure TTestHostExtension.TestClientRefusesToRequireInTheClientHello;
begin
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, AtClientHello, nil, AtClientHello))),
    'a client never receives a ClientHello, so it cannot require one');
end;

procedure TTestHostExtension.TestServerRefusesToSendInTheClientHello;
begin
  CheckTrue(ServerCreationRaises(Server13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, AtClientHello, nil, Nowhere))),
    'a server never sends a ClientHello');
end;

procedure TTestHostExtension.TestServerRefusesToRequireOutsideTheClientHello;
begin
  CheckTrue(ServerCreationRaises(Server13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, Nowhere, nil, AtEncrypted))),
    'a server never receives EncryptedExtensions, so it cannot require one');
  CheckFalse(ServerCreationRaises(Server13, TArray<ITlsHostExtension>.Create(
    TTlsHostExtensions.Make(HostType, AtEncrypted, nil, AtClientHello))),
    'control: the declaration a server may make');
end;

procedure TTestHostExtension.TestHostExtensionsGoBothWaysAndAreReadBack;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello,
    DecodeHex('c1c2c3'), AtEncrypted)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtEncrypted,
    DecodeHex('5e5f'), AtClientHello)));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client completed');
  CheckFalse(LServer.IsHandshaking, 'the server completed');
  CheckTrue(PeerBody(LServer, HostType, LBody), 'the server read the client''s extension');
  CheckEqualBytes('the ClientHello body', DecodeHex('c1c2c3'), LBody);
  CheckTrue(PeerBody(LClient, HostType, LBody), 'the client read the server''s extension');
  CheckEqualBytes('the EncryptedExtensions body', DecodeHex('5e5f'), LBody);
  CheckFalse(PeerBody(LClient, OtherType, LBody), 'a type nobody configured reads as absent');
end;

procedure TTestHostExtension.TestPeerBodyIsReadableOnceTheClientHelloIsProcessed;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello,
    DecodeHex('c1c2c3'), Nowhere)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, Nowhere, nil,
    AtClientHello)));
  CheckFalse(PeerBody(LServer, HostType, LBody), 'nothing is read before any input');
  LClient.StartHandshake;
  Pump(LClient, LServer);
  CheckTrue(LServer.IsHandshaking, 'the server is still mid-handshake');
  CheckTrue(PeerBody(LServer, HostType, LBody),
    'the body is readable as soon as the carrying message is processed');
  CheckEqualBytes('the ClientHello body', DecodeHex('c1c2c3'), LBody);
end;

procedure TTestHostExtension.TestRequiredExtensionMissingFromEncryptedExtensionsFailsTheClient;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    AtEncrypted)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13);
  RunHandshake(LClient, LServer);
  CheckFailedWith(LClient, TTlsAlertDescription.MissingExtension,
    'a server that sends no copy of a required extension');
end;

procedure TTestHostExtension.TestRequiredExtensionMissingFromTheClientHelloFailsTheServer;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtEncrypted, nil,
    AtClientHello)));
  RunHandshake(LClient, LServer);
  CheckFailedWith(LServer, TTlsAlertDescription.MissingExtension,
    'a client that sends no copy of a required extension');
end;

procedure TTestHostExtension.TestServerAnswersOnlyAnOfferedType;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtEncrypted,
    DecodeHex('5e5f'), Nowhere)));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client was not sent an extension it never offered');
  CheckFalse(LClient.IsHandshaking, 'and completed');
  CheckFalse(PeerBody(LServer, HostType, LBody), 'the server saw no copy to answer');
end;

procedure TTestHostExtension.TestHostExtensionRidesTheNewSessionTicket;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13Resuming, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    AtTicket)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtTicket,
    DecodeHex('7001'), Nowhere)));
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckFalse(LClient.IsTerminal, 'the client accepted the ticket carrying the extension');
  CheckTrue(PeerBody(LClient, HostType, LBody), 'the client read the ticket''s copy');
  CheckEqualBytes('the NewSessionTicket body', DecodeHex('7001'), LBody);
end;

procedure TTestHostExtension.TestRequiredExtensionMissingFromTheNewSessionTicketFailsTheClient;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13Resuming, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    AtTicket)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13);
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckFailedWith(LClient, TTlsAlertDescription.MissingExtension,
    'a ticket without the required extension');
end;

procedure TTestHostExtension.TestHostExtensionRidesTheCertificateRequest;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(MtlsClient13, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    AtRequest)));
  LServer := TTlsEngineFactory.CreateServerEngine(MtlsServer13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtRequest,
    DecodeHex('c4'), Nowhere)));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client accepted the CertificateRequest');
  CheckFalse(LClient.IsHandshaking, 'and completed');
  CheckTrue(PeerBody(LClient, HostType, LBody), 'the client read the request''s copy');
  CheckEqualBytes('the CertificateRequest body', DecodeHex('c4'), LBody);
end;

procedure TTestHostExtension.TestPeerCopyInAServerHelloIsIllegalParameter;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
begin
  LCodec := NewCodec(TTlsHostExtensions.Make(HostType, AtClientHello, nil, Nowhere),
    TTlsHostExtensionRole.Client, LResults);
  // offered, so only the placement rule can refuse it
  CheckEquals(Ord(TTlsAlertDescription.IllegalParameter),
    Ord(ConsumeAlert(LCodec, TTlsExtensionContextKind.ServerHello, BlockWith(DecodeHex('aa')),
    True)), 'a copy in a message no host extension rides is illegal_parameter');
end;

procedure TTestHostExtension.TestAnAnswerInAnUndeclaredMessageFailsTheClient;
var
  LClient, LServer: ITlsEngine;
begin
  // the client requires nothing, so the server's EncryptedExtensions copy is in a message it never declared
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello,
    DecodeHex('c1c2c3'), Nowhere)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtEncrypted,
    DecodeHex('5e5f'), Nowhere)));
  RunHandshake(LClient, LServer);
  CheckFailedWith(LClient, TTlsAlertDescription.IllegalParameter,
    'an answer in a message the client did not declare');
end;

procedure TTestHostExtension.TestALaterUndeclaredCopyFailsTheClient;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  // the server also puts a copy in its ticket: a message the client did not declare, so it can
  // never replace the EncryptedExtensions copy the host already read
  LClient := TTlsEngineFactory.CreateClientEngine(Client13Resuming, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    AtEncrypted)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType,
    [TTlsExtensionContextKind.EncryptedExtensions, TTlsExtensionContextKind.NewSessionTicket],
    DecodeHex('5e5f'), Nowhere)));
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckFailedWith(LClient, TTlsAlertDescription.IllegalParameter, 'a copy in an undeclared ticket');
  CheckTrue(PeerBody(LClient, HostType, LBody), 'the read copy is still there');
  CheckEqualBytes('unchanged', DecodeHex('5e5f'), LBody);
end;

procedure TTestHostExtension.TestASecondBlockOfAKindReplacesTheFirst;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
  LEmpty: TExtensionVector;
  LBody: TBytes;
begin
  LEmpty := TExtensionVector.Empty;
  LCodec := NewCodec(TTlsHostExtensions.Make(HostType, Nowhere, nil, AtClientHello),
    TTlsHostExtensionRole.Server, LResults);
  CheckEquals(Ord(TTlsAlertDescription.CloseNotify),
    Ord(ConsumeAlert(LCodec, TTlsExtensionContextKind.ClientHello, BlockWith(DecodeHex('aa')),
    False)), 'control: the first ClientHello carries it');
  CheckTrue(LResults.TryGetPeerExtension(HostType, LBody), 'the first copy is read');
  // a retried ClientHello without it is a missing required copy, and the first body is gone
  CheckEquals(Ord(TTlsAlertDescription.MissingExtension),
    Ord(ConsumeAlert(LCodec, TTlsExtensionContextKind.ClientHello, LEmpty.Encode, False)),
    'the second ClientHello lacks it');
  CheckFalse(LResults.TryGetPeerExtension(HostType, LBody), 'nothing of the first copy remains');
end;

procedure TTestHostExtension.TestTheEarliestCopyIsKept;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
  LBody: TBytes;
begin
  LCodec := NewCodec(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    [TTlsExtensionContextKind.EncryptedExtensions, TTlsExtensionContextKind.NewSessionTicket]),
    TTlsHostExtensionRole.Client, LResults);
  ConsumeAlert(LCodec, TTlsExtensionContextKind.EncryptedExtensions, BlockWith(DecodeHex('aa')),
    True);
  ConsumeAlert(LCodec, TTlsExtensionContextKind.NewSessionTicket, BlockWith(DecodeHex('bb')),
    True);
  CheckTrue(LResults.TryGetPeerExtension(HostType, LBody), 'a copy is read');
  CheckEqualBytes('the earlier message''s, which a later one never replaces', DecodeHex('aa'),
    LBody);
end;

procedure TTestHostExtension.TestTls12HandshakeCarriesNoHostExtension;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  // the 1.2-only server ignores the dual-version client's offer, and the handshake requires none
  LClient := TTlsEngineFactory.CreateClientEngine(Client12Capable, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    AtEncrypted)));
  LServer := TTlsEngineFactory.CreateServerEngine(Server12Only);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LClient.IsHandshaking, 'the TLS 1.2 handshake completed');
  CheckEquals(Integer(TlsWireVersionTls12), Integer(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
    'it negotiated TLS 1.2');
  CheckFalse(PeerBody(LClient, HostType, LBody), 'no peer copy is reported');
  CheckFalse(PeerBody(LServer, HostType, LBody), 'the server reports none either');
end;

procedure TTestHostExtension.TestDualVersionServerDoesNotEnforceRequirementsOverTls12;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(
    ClientBuilder(TArray<UInt16>.Create(TlsWireVersionTls12)).Build, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(Server12Capable,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtEncrypted, nil,
    AtClientHello)));
  RunHandshake(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server did not fail the 1.2 client for the missing copy');
  CheckFalse(LServer.IsHandshaking, 'and completed');
  CheckEquals(Integer(TlsWireVersionTls12), Integer(LServer.ConnectionInfo.NegotiatedVersion.WireValue),
    'it negotiated TLS 1.2');
  CheckFalse(PeerBody(LServer, HostType, LBody), 'no copy is reported');
end;

procedure TTestHostExtension.TestSecondClientHelloCarriesTheSameExtensionBytes;
var
  LClient, LServer: ITlsEngine;
  LFirst, LSecond: TBytes;
  LFirstExt, LSecondExt: TExtensionEntry;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(ClientRetry, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello,
    DecodeHex('0102030405'), Nowhere)));
  LServer := TTlsEngineFactory.CreateServerEngine(ServerRetry,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, Nowhere, nil,
    AtClientHello)));
  LClient.StartHandshake;
  LFirst := Drain(LClient);
  Feed(LServer, LFirst);
  Pump(LServer, LClient);
  LSecond := Drain(LClient);
  CheckTrue(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LFirst).TryFind(HostType, LFirstExt),
    'the first ClientHello carries the extension');
  CheckTrue(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LSecond).TryFind(HostType, LSecondExt),
    'the second ClientHello carries it too');
  CheckEqualBytes('the same body', LFirstExt.Data, LSecondExt.Data);
  Feed(LServer, LSecond);
  ExchangeFlights(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.HelloRetryRequest, 'a HelloRetryRequest was answered');
  CheckFalse(LClient.IsHandshaking, 'the client completed');
  CheckFalse(LServer.IsHandshaking, 'the server completed');
end;

procedure TTestHostExtension.TestHostExtensionRidesTheHelloRetryRequestAndTheAnswer;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(ClientRetry, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello, nil,
    [TTlsExtensionContextKind.HelloRetryRequest, TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := TTlsEngineFactory.CreateServerEngine(ServerRetry,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType,
    [TTlsExtensionContextKind.HelloRetryRequest, TTlsExtensionContextKind.EncryptedExtensions],
    DecodeHex('77'), Nowhere)));
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.HelloRetryRequest, 'a HelloRetryRequest was sent');
  CheckFalse(LClient.IsTerminal, 'the client found both required copies');
  CheckFalse(LClient.IsHandshaking, 'and completed');
  CheckTrue(PeerBody(LClient, HostType, LBody), 'the client read the copy');
  CheckEqualBytes('the answer''s body', DecodeHex('77'), LBody);
end;

procedure TTestHostExtension.TestUnsolicitedResponseIsUnsupportedExtension;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
begin
  // the codec's response rule holds for a host extension: an unoffered type cannot come back
  LCodec := NewCodec(TTlsHostExtensions.Make(HostType, Nowhere, nil, AtEncrypted),
    TTlsHostExtensionRole.Client, LResults);
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedExtension),
    Ord(ConsumeAlert(LCodec, TTlsExtensionContextKind.EncryptedExtensions,
    BlockWith(DecodeHex('aa')), False)), 'an unsolicited response is unsupported_extension');
end;

procedure TTestHostExtension.TestOfferedResponseIsAcceptedAndRead;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
  LBody: TBytes;
begin
  LCodec := NewCodec(TTlsHostExtensions.Make(HostType, Nowhere, nil, AtEncrypted),
    TTlsHostExtensionRole.Client, LResults);
  CheckEquals(Ord(TTlsAlertDescription.CloseNotify),
    Ord(ConsumeAlert(LCodec, TTlsExtensionContextKind.EncryptedExtensions,
    BlockWith(DecodeHex('aa')), True)), 'an offered type is accepted');
  CheckTrue(LResults.TryGetPeerExtension(HostType, LBody), 'the body is read back');
  CheckEqualBytes('the body', DecodeHex('aa'), LBody);
end;

procedure TTestHostExtension.TestEchAcceptCarriesTheExtensionInOuterAndInner;
var
  LClient, LServer: ITlsEngine;
  LList, LOuter, LBody: TBytes;
  LSk: ISecretBuffer;
  LEntry: TExtensionEntry;
begin
  LList := EchConfigList($D7, 'cover.example', LSk);
  LClient := TTlsEngineFactory.CreateClientEngine(EchClient(LList, True), ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello,
    DecodeHex('c1c2c3'), AtEncrypted)));
  LServer := TTlsEngineFactory.CreateServerEngine(EchServer(LList, LSk),
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtEncrypted,
    DecodeHex('5e5f'), AtClientHello)));
  LClient.StartHandshake;
  LOuter := Drain(LClient);
  CheckTrue(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(LOuter).TryFind(HostType, LEntry),
    'the outer ClientHello carries the extension');
  CheckEqualBytes('with the inner''s body', DecodeHex('c1c2c3'), LEntry.Data);
  Feed(LServer, LOuter);
  ExchangeFlights(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'ECH was accepted');
  CheckFalse(LServer.IsHandshaking, 'the server completed');
  CheckTrue(PeerBody(LServer, HostType, LBody), 'the server read the extension from the inner hello');
  CheckEqualBytes('the ClientHello body', DecodeHex('c1c2c3'), LBody);
  CheckTrue(PeerBody(LClient, HostType, LBody), 'the client read the server''s extension');
  CheckEqualBytes('the EncryptedExtensions body', DecodeHex('5e5f'), LBody);
end;

procedure TTestHostExtension.TestEchRejectShowsTheServerTheOuterCopy;
var
  LClient, LServer: ITlsEngine;
  LClientList, LServerList, LBody: TBytes;
  LClientSk, LServerSk: ISecretBuffer;
begin
  // the server holds another config id, so it cannot decrypt the offer and serves the outer hello
  LClientList := EchConfigList($D8, 'localhost', LClientSk);
  LServerList := EchConfigList($D9, 'localhost', LServerSk);
  LClient := TTlsEngineFactory.CreateClientEngine(EchClient(LClientList, False), ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, AtClientHello,
    DecodeHex('c1c2c3'), Nowhere)));
  LServer := TTlsEngineFactory.CreateServerEngine(EchServer(LServerList, LServerSk),
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType, Nowhere, nil,
    AtClientHello)));
  RunHandshake(LClient, LServer);
  CheckTrue(PeerBody(LServer, HostType, LBody), 'the server read the outer ClientHello''s copy');
  CheckEqualBytes('the same body', DecodeHex('c1c2c3'), LBody);
  CheckEquals(Ord(TTlsAlertDescription.EchRequired), Ord(LClient.LastError.Alert.Description),
    'the client rejected ECH');
end;

procedure TTestHostExtension.TestExistingEnginesAnswerNoHostExtensionResults;
var
  LClient: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost);
  CheckFalse(PeerBody(LClient, HostType, LBody),
    'an engine made without host extensions still answers the interface, with nothing');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHostExtension);
{$ELSE}
  RegisterTest(TTestHostExtension.Suite);
{$ENDIF FPC}

end.
