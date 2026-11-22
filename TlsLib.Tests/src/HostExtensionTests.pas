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
    /// <summary>A client preferring X25519 then secp256r1 and a secp256r1-only server, so the
    /// server answers with a HelloRetryRequest.</summary>
    function ClientRetry: ITlsClientConfig;
    function ServerRetry: ITlsServerConfig;
    function Ext(AType: UInt16; ASendIn: TTlsExtensionContexts; const ABody: TBytes;
      ARequiredIn: TTlsExtensionContexts): ITlsHostExtension;
    function Only(const AExtension: ITlsHostExtension): TArray<ITlsHostExtension>;
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
    function NewCodec(const AExtension: ITlsHostExtension;
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
    procedure TestEngineCreationRejectsATypeTheCoreRegistryHolds;
    procedure TestEngineCreationRejectsPreSharedKeyAndEchTypes;
    procedure TestEngineCreationRejectsATypeListedTwice;
    procedure TestEngineCreationRejectsANilExtension;
    procedure TestEngineCreationRejectsAConfigWithoutTls13;
    procedure TestHostExtensionsGoBothWaysAndAreReadBack;
    procedure TestPeerBodyIsReadableOnceTheClientHelloIsProcessed;
    procedure TestRequiredExtensionMissingFromEncryptedExtensionsFailsTheClient;
    procedure TestRequiredExtensionMissingFromTheClientHelloFailsTheServer;
    procedure TestServerAnswersOnlyAnOfferedType;
    procedure TestHostExtensionRidesTheNewSessionTicket;
    procedure TestRequiredExtensionMissingFromTheNewSessionTicketFailsTheClient;
    procedure TestPeerCopyInAServerHelloIsIllegalParameter;
    procedure TestAnOfferedTypeMayBeAnsweredWithoutBeingRequired;
    procedure TestASecondBlockOfAKindReplacesTheFirst;
    procedure TestTheLatestMessagesCopyIsRead;
    procedure TestTls12HandshakeCarriesNoHostExtension;
    procedure TestSecondClientHelloCarriesTheSameExtensionBytes;
    procedure TestHostExtensionRidesTheHelloRetryRequest;
    procedure TestUnsolicitedResponseIsUnsupportedExtension;
    procedure TestOfferedResponseIsAcceptedAndRead;
    procedure TestEchAcceptCarriesTheExtensionInOuterAndInner;
    procedure TestEchRejectShowsTheServerTheOuterCopy;
    procedure TestExistingEnginesAnswerNoHostExtensionResults;
  end;

implementation

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

function TTestHostExtension.Ext(AType: UInt16; ASendIn: TTlsExtensionContexts;
  const ABody: TBytes; ARequiredIn: TTlsExtensionContexts): ITlsHostExtension;
begin
  Result := TTlsHostExtensions.Make(AType, ASendIn, ABody, ARequiredIn);
end;

function TTestHostExtension.Only(
  const AExtension: ITlsHostExtension): TArray<ITlsHostExtension>;
begin
  Result := TArray<ITlsHostExtension>.Create(AExtension);
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

procedure TTestHostExtension.TestMakeRejectsAGreaseType;
begin
  CheckTrue(MakeRaises($0A0A, [TTlsExtensionContextKind.ClientHello], nil, []),
    'a GREASE value is refused at creation');
  CheckTrue(MakeRaises($FAFA, [TTlsExtensionContextKind.ClientHello], nil, []),
    'every GREASE value is refused');
  CheckFalse(MakeRaises($0A0B, [TTlsExtensionContextKind.ClientHello], nil, []),
    'a value next to a GREASE one is not');
end;

procedure TTestHostExtension.TestMakeRejectsEchOuterExtensionsAsAType;
begin
  CheckTrue(MakeRaises(TExtensionTypes.EchOuterExtensions,
    [TTlsExtensionContextKind.ClientHello], nil, []),
    'ech_outer_extensions is refused at creation');
end;

procedure TTestHostExtension.TestMakeRejectsAServerHelloKind;
begin
  CheckTrue(MakeRaises(HostType, [TTlsExtensionContextKind.ServerHello], nil, []),
    'a ServerHello send kind is refused');
  CheckTrue(MakeRaises(HostType, [], nil, [TTlsExtensionContextKind.ServerHello]),
    'a ServerHello required kind is refused');
end;

procedure TTestHostExtension.TestMakeRejectsACertificateKind;
begin
  CheckTrue(MakeRaises(HostType, [TTlsExtensionContextKind.Certificate], nil, []),
    'a Certificate send kind is refused: no codec path reads it');
  CheckTrue(MakeRaises(HostType, [], nil, [TTlsExtensionContextKind.Certificate]),
    'a Certificate required kind is refused');
end;

procedure TTestHostExtension.TestMakeRejectsAnOversizedBody;
begin
  CheckFalse(MakeRaises(HostType, [TTlsExtensionContextKind.ClientHello],
    Filled($11, 65535), []), 'control: a 65535-byte body is allowed');
  CheckTrue(MakeRaises(HostType, [TTlsExtensionContextKind.ClientHello],
    Filled($11, 65536), []), 'a body beyond 65535 bytes is refused');
end;

procedure TTestHostExtension.TestMakeCopiesTheBody;
var
  LBody: TBytes;
  LExt: ITlsHostExtension;
  LRead: TBytes;
begin
  LBody := Filled($22, 4);
  LExt := Ext(HostType, [TTlsExtensionContextKind.ClientHello], LBody, []);
  LBody[0] := $99;
  LRead := LExt.Body;
  LRead[1] := $99;
  CheckEqualBytes('neither the caller''s array nor a returned copy reaches the extension',
    Filled($22, 4), LExt.Body);
end;

procedure TTestHostExtension.TestEngineCreationRejectsATypeTheCoreRegistryHolds;
begin
  CheckTrue(ClientCreationRaises(Client13, Only(Ext(TExtensionTypes.Alpn,
    [TTlsExtensionContextKind.ClientHello], nil, []))),
    'application_layer_protocol_negotiation is a core type');
  CheckTrue(ClientCreationRaises(Client13, Only(Ext(TExtensionTypes.ServerName,
    [TTlsExtensionContextKind.ClientHello], nil, []))), 'server_name is a core type');
end;

procedure TTestHostExtension.TestEngineCreationRejectsPreSharedKeyAndEchTypes;
begin
  CheckTrue(ClientCreationRaises(Client13, Only(Ext(TExtensionTypes.PreSharedKey,
    [TTlsExtensionContextKind.ClientHello], nil, []))),
    'pre_shared_key is a core type, though it is registered after the host entries');
  CheckTrue(ClientCreationRaises(Client13, Only(Ext(TExtensionTypes.EncryptedClientHello,
    [TTlsExtensionContextKind.ClientHello], nil, []))),
    'encrypted_client_hello is a core type, though it is registered after the host entries');
end;

procedure TTestHostExtension.TestEngineCreationRejectsATypeListedTwice;
begin
  CheckTrue(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil, []),
    Ext(HostType, [TTlsExtensionContextKind.EncryptedExtensions], nil, []))),
    'one type listed twice is refused');
  CheckFalse(ClientCreationRaises(Client13, TArray<ITlsHostExtension>.Create(
    Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil, []),
    Ext(OtherType, [TTlsExtensionContextKind.ClientHello], nil, []))),
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
  CheckTrue(ClientCreationRaises(LConfig, Only(Ext(HostType,
    [TTlsExtensionContextKind.ClientHello], nil, []))),
    'host extensions ride TLS 1.3 only, so a TLS 1.2-only client is refused them');
  CheckFalse(ClientCreationRaises(LConfig, nil),
    'control: no extensions, no refusal');
end;

procedure TTestHostExtension.TestHostExtensionsGoBothWaysAndAreReadBack;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost,
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], DecodeHex('c1c2c3'),
    [TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    Only(Ext(HostType, [TTlsExtensionContextKind.EncryptedExtensions], DecodeHex('5e5f'),
    [TTlsExtensionContextKind.ClientHello])));
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
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], DecodeHex('c1c2c3'), [])));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    Only(Ext(HostType, [], nil, [TTlsExtensionContextKind.ClientHello])));
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
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil,
    [TTlsExtensionContextKind.EncryptedExtensions])));
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
    Only(Ext(HostType, [TTlsExtensionContextKind.EncryptedExtensions], nil,
    [TTlsExtensionContextKind.ClientHello])));
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
    Only(Ext(HostType, [TTlsExtensionContextKind.EncryptedExtensions], DecodeHex('5e5f'), [])));
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
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil,
    [TTlsExtensionContextKind.NewSessionTicket])));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    Only(Ext(HostType, [TTlsExtensionContextKind.NewSessionTicket], DecodeHex('7001'), [])));
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
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil,
    [TTlsExtensionContextKind.NewSessionTicket])));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13);
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckFailedWith(LClient, TTlsAlertDescription.MissingExtension,
    'a ticket without the required extension');
end;

function TTestHostExtension.NewCodec(const AExtension: ITlsHostExtension;
  out AResults: ITlsHostExtensionResults): IExtensionBlockCodec;
begin
  Result := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry(
    TTlsHostExtensions.Adapt(Only(AExtension), AResults))) as IExtensionBlockCodec;
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

procedure TTestHostExtension.TestPeerCopyInAServerHelloIsIllegalParameter;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
begin
  LCodec := NewCodec(Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil, []), LResults);
  // offered, so only the placement rule can refuse it
  CheckEquals(Ord(TTlsAlertDescription.IllegalParameter),
    Ord(ConsumeAlert(LCodec, TTlsExtensionContextKind.ServerHello, BlockWith(DecodeHex('aa')),
    True)), 'a copy in a message no host extension rides is illegal_parameter');
end;

procedure TTestHostExtension.TestAnOfferedTypeMayBeAnsweredWithoutBeingRequired;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(Client13, ServerHost,
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], DecodeHex('c1c2c3'), [])));
  LServer := TTlsEngineFactory.CreateServerEngine(Server13,
    Only(Ext(HostType, [TTlsExtensionContextKind.EncryptedExtensions], DecodeHex('5e5f'), [])));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client accepted the answer');
  CheckFalse(LServer.IsTerminal, 'the server accepted the offer');
  CheckTrue(PeerBody(LClient, HostType, LBody), 'the client read the answer');
  CheckEqualBytes('the EncryptedExtensions body', DecodeHex('5e5f'), LBody);
  CheckTrue(PeerBody(LServer, HostType, LBody), 'the server read the offer');
  CheckEqualBytes('the ClientHello body', DecodeHex('c1c2c3'), LBody);
end;

procedure TTestHostExtension.TestASecondBlockOfAKindReplacesTheFirst;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
  LEmpty: TExtensionVector;
  LBody: TBytes;
begin
  LEmpty := TExtensionVector.Empty;
  LCodec := NewCodec(Ext(HostType, [], nil, [TTlsExtensionContextKind.ClientHello]), LResults);
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

procedure TTestHostExtension.TestTheLatestMessagesCopyIsRead;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
  LBody: TBytes;
begin
  LCodec := NewCodec(Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil, []), LResults);
  ConsumeAlert(LCodec, TTlsExtensionContextKind.EncryptedExtensions, BlockWith(DecodeHex('aa')),
    True);
  ConsumeAlert(LCodec, TTlsExtensionContextKind.NewSessionTicket, BlockWith(DecodeHex('bb')),
    True);
  CheckTrue(LResults.TryGetPeerExtension(HostType, LBody), 'a copy is read');
  CheckEqualBytes('the ticket''s, the latest message that carried it', DecodeHex('bb'), LBody);
end;

procedure TTestHostExtension.TestTls12HandshakeCarriesNoHostExtension;
var
  LClient, LServer: ITlsEngine;
  LBody: TBytes;
begin
  // the 1.2-only server ignores the dual-version client's offer, and the handshake requires none
  LClient := TTlsEngineFactory.CreateClientEngine(Client12Capable, ServerHost,
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil,
    [TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := TTlsEngineFactory.CreateServerEngine(Server12Only);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LClient.IsHandshaking, 'the TLS 1.2 handshake completed');
  CheckEquals(Integer(TlsWireVersionTls12), Integer(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
    'it negotiated TLS 1.2');
  CheckFalse(PeerBody(LClient, HostType, LBody), 'no peer copy is reported');
  CheckFalse(PeerBody(LServer, HostType, LBody), 'the server reports none either');
end;

procedure TTestHostExtension.TestSecondClientHelloCarriesTheSameExtensionBytes;
var
  LClient, LServer: ITlsEngine;
  LFirst, LSecond: TBytes;
  LFirstExt, LSecondExt: TExtensionEntry;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(ClientRetry, ServerHost,
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], DecodeHex('0102030405'), [])));
  LServer := TTlsEngineFactory.CreateServerEngine(ServerRetry,
    Only(Ext(HostType, [], nil, [TTlsExtensionContextKind.ClientHello])));
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

procedure TTestHostExtension.TestHostExtensionRidesTheHelloRetryRequest;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(ClientRetry, ServerHost,
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], nil,
    [TTlsExtensionContextKind.HelloRetryRequest])));
  LServer := TTlsEngineFactory.CreateServerEngine(ServerRetry,
    Only(Ext(HostType, [TTlsExtensionContextKind.HelloRetryRequest], DecodeHex('77'), [])));
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.HelloRetryRequest, 'a HelloRetryRequest was sent');
  CheckFalse(LClient.IsTerminal, 'the client found the required copy in it');
  CheckFalse(LClient.IsHandshaking, 'and completed');
end;

procedure TTestHostExtension.TestUnsolicitedResponseIsUnsupportedExtension;
var
  LResults: ITlsHostExtensionResults;
  LCodec: IExtensionBlockCodec;
begin
  // the codec's response rule holds for a host extension: an unoffered type cannot come back
  LCodec := NewCodec(Ext(HostType, [], nil, [TTlsExtensionContextKind.EncryptedExtensions]),
    LResults);
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
  LCodec := NewCodec(Ext(HostType, [], nil, [TTlsExtensionContextKind.EncryptedExtensions]),
    LResults);
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
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], DecodeHex('c1c2c3'),
    [TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := TTlsEngineFactory.CreateServerEngine(EchServer(LList, LSk),
    Only(Ext(HostType, [TTlsExtensionContextKind.EncryptedExtensions], DecodeHex('5e5f'),
    [TTlsExtensionContextKind.ClientHello])));
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
    Only(Ext(HostType, [TTlsExtensionContextKind.ClientHello], DecodeHex('c1c2c3'), [])));
  LServer := TTlsEngineFactory.CreateServerEngine(EchServer(LServerList, LServerSk),
    Only(Ext(HostType, [], nil, [TTlsExtensionContextKind.ClientHello])));
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
