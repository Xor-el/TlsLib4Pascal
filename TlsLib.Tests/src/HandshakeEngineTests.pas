{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HandshakeEngineTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Generics.Collections,
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
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpArrayUtilities,
  TlpIKeyLog,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpIKeySchedule,
  TlpExtensionVector,
  TlpExtensionContext,
  TlpCoreExtensions,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpITlsHostExtension,
  TlpHostExtensions,
  TlpTicketBinding,
  TlpISession,
  TlpSession,
  TlpClientSessionPolicy,
  TlpInMemorySessionCache,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlpSystemTimeUtilities,
  TlpEchConfig,
  TlpEchClient,
  TlpInMemoryEchKeyStore,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpCertificateVerifierSource,
  TlpSystemCryptoBase,
  TlpComplianceTypes,
  TlpICryptoBackendReport,
  MockCompliance,
  TlpComplianceExceptions,
  TlpCompliancePresets,
  TlpComplianceCryptoProvider,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpITlsHandshakeEngine,
  TlpHandshakeOutput,
  MockKeyLog,
  TlsLibTestHandshakeDecoder,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  /// <summary>What one side's host was handed, in order.</summary>
  THandshakeLog = TList<THandshakeOutput>;

  /// <summary>
  /// The handshake-only engine, driven over two engines whose hosts exchange handshake bytes per
  /// level and take the traffic secrets: what each side produces and in which order, what stays off
  /// the wire, how a ticket is bound to the engine kind, and how every local failure is reported.
  /// </summary>
  TTestHandshakeEngine = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
    TicketLimit = UInt32($FFFFFFFF);
    HostType = UInt16($FC01);
  var
    FStek: ISessionTicketKeyManager;
    FAntiReplay: IAntiReplayStrategy;
    FScope: TBytes;
    // zero each secret the host takes, as a host does once it has keyed its protection
    FWipeSecrets: Boolean;
    FClientLog: THandshakeLog;
    FServerLog: THandshakeLog;
    function ClientBuilder: ITlsClientConfigBuilder;
    function ClientConfig: ITlsClientConfig;
    function ClientResuming(const ACache: ISessionCache; AEarlyData: Boolean): ITlsClientConfig;
    function ServerBuilder: ITlsServerConfigBuilder;
    function ServerConfig: ITlsServerConfig;
    function ServerResuming(AEarlyData: Boolean): ITlsServerConfig;
    function EchResumingClient(const ACache: ISessionCache;
      const AConfigList: TBytes): ITlsClientConfig;
    function EchResumingServer(const AConfigList: TBytes;
      const APrivateKey: ISecretBuffer): ITlsServerConfig;
    function NewClient(const AConfig: ITlsClientConfig): ITlsHandshakeEngine;
    function NewServer(const AConfig: ITlsServerConfig): ITlsHandshakeEngine;
    /// <summary>Moves everything ASrc has queued to ADst (handshake bytes at their level), logging
    /// it; returns how many items moved.</summary>
    function Deliver(const ASrc, ADst: ITlsHandshakeEngine;
      const ALog: THandshakeLog): Int32;
    procedure Run(const AClient, AServer: ITlsHandshakeEngine);
    function Describe(const ALog: THandshakeLog): string;
    function SecretOf(const ALog: THandshakeLog; AKind: THandshakeOutputKind;
      ALevel: TTlsEpoch): TBytes;
    function HasOutput(const ALog: THandshakeLog; AKind: THandshakeOutputKind;
      ALevel: TTlsEpoch): Boolean;
    function MessageTypes(const ALog: THandshakeLog): TBytes;
    function FirstData(const ALog: THandshakeLog; ALevel: TTlsEpoch): TBytes;
    function Cached(const ACache: ISessionCache; ABinding: TTicketBinding;
      out ASession: ITls13ResumableSession): Boolean;
    function Rebuilt(const ASession: ITls13ResumableSession;
      ABinding: TTicketBinding): IResumableSession;
    procedure Seed(const ACache: ISessionCache);
    procedure CheckFailedWith(const AEngine: ITlsHandshakeEngine; AAlert: TTlsAlertDescription;
      const AMessage: string);
    procedure CheckLocalWithoutAlert(const AEngine: ITlsHandshakeEngine;
      const AMessage: string);
    function EventSeen(const AEngine: ITlsHandshakeEngine; AKind: TTlsEventKind): Boolean;
    function EchConfigList(AConfigId: Byte; const APublicName: string;
      out APrivateKey: ISecretBuffer): TBytes;
    function CreationRaises(const AConfig: ITlsClientConfig): Boolean; overload;
    function CreationRaises(const AConfig: ITlsServerConfig): Boolean; overload;
  protected
    procedure SetUp; override;
  published
    procedure TestFullHandshakeAgreesOnEverySecretPerLevel;
    procedure TestOutputOrderIsPinned;
    procedure TestServerReadsApplicationSecretOnlyAfterTheClientFinished;
    procedure TestNothingRecordShapedIsOnTheWire;
    procedure TestRecordSizeLimitIsNotOffered;
    procedure TestServerRefusesAClientHelloWithASessionId;
    procedure TestKeyUpdateIsUnexpected;
    procedure TestEndOfEarlyDataIsUnexpected;
    procedure TestZeroRttDeclinedWithoutRetryCompletes;
    procedure TestPostHandshakeCertificateRequestIsUnexpected;
    procedure TestProvideHandshakeDataReportsProgress;
    procedure TestTicketsAreNotCappedAcrossDeliveries;
    procedure TestTicketWithAnExplicitZeroLimitFails;
    procedure TestHostWipingItsSecretsLeavesTheHandshakeIntact;
    procedure TestZeroRttWithEchIsAccepted;
    procedure TestComplianceGatedProviderRefusesWhatItsRulesRefuse;
    procedure TestInputAtAnotherLevelFails;
    procedure TestMessageStraddlingAKeyChangeFails;
    procedure TestRfc9001ClientHelloIsServedWithItsLimitIgnored;
    procedure TestAlpnIsVisibleBeforeAnythingIsPulled;
    procedure TestTicketCarriesTheFixedEarlyDataLimit;
    procedure TestMismatchedTicketLimitFailsWithoutAnAlert;
    procedure TestResumptionUsesTheTicketOfItsOwnKind;
    procedure TestZeroRttIsAcceptedAndKeysAgree;
    procedure TestZeroRttIsRejectedAfterARetry;
    procedure TestHelloRetryRequestCompletes;
    procedure TestMutualAuthentication;
    procedure TestHostExtensionsGoBothWays;
    procedure TestEchAccepted;
    procedure TestEchRejectedFailsTheClientWithEchRequired;
    procedure TestAsyncVerdictParksAndResumes;
    procedure TestAsyncVerdictRejectIsReported;
    procedure TestKeyLogReceivesTheHandshakeSecrets;
    procedure TestExportersAgree;
    procedure TestCreationRefusesAConfigWithoutTls13Alone;
    procedure TestRecordEngineTicketIsNotOfferedToTheHandshakeEngine;
    procedure TestHandshakeEngineTicketIsNotOfferedToTheRecordEngine;
    procedure TestServerDeclinesARecordEngineTicket;
    procedure TestCryptoOverlayDerivesTheKeys;
    procedure TestTransportFailureIsReportedWithoutAlert;
    procedure TestNothingIsPulledOnceTerminal;
    procedure TestLocalWithoutAlertCarriesNoAlertToAStream;
  end;

implementation

type
  // primitives that count the key derivations asked of them
  TCountingPrimitives = class sealed(TForwardingCryptoPrimitives)
  strict private
  var
    FHkdfs: Int32;
  public
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf; override;
    property Hkdfs: Int32 read FHkdfs;
  end;

{ TCountingPrimitives }

function TCountingPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Inc(FHkdfs);
  Result := inherited CreateHkdf(AAlgorithm);
end;

{ TTestHandshakeEngine }

procedure TTestHandshakeEngine.SetUp;
begin
  inherited SetUp;
  FStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager;
  FAntiReplay := TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy;
  FScope := Filled($5C, 16);
  FClientLog := Own<THandshakeLog>(THandshakeLog.Create);
  FServerLog := Own<THandshakeLog>(THandshakeLog.Create);
end;

function TTestHandshakeEngine.ClientBuilder: ITlsClientConfigBuilder;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build);
end;

function TTestHandshakeEngine.ClientConfig: ITlsClientConfig;
begin
  Result := ClientBuilder.Build;
end;

function TTestHandshakeEngine.ClientResuming(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsClientConfig;
begin
  Result := ClientBuilder.WithResumption(True).WithSessionCache(ACache)
    .WithResumptionScope(FScope).Tls13.WithEarlyData(AEarlyData).Build;
end;

function TTestHandshakeEngine.ServerBuilder: ITlsServerConfigBuilder;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential);
end;

function TTestHandshakeEngine.ServerConfig: ITlsServerConfig;
begin
  Result := ServerBuilder.Build;
end;

function TTestHandshakeEngine.ServerResuming(AEarlyData: Boolean): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := ServerBuilder.WithResumption(True).WithSessionTicketKeys(FStek);
  LBuilder.Tls13.WithTicketCount(1);
  if AEarlyData then
    LBuilder.Tls13.WithEarlyData(16384).WithAntiReplay(FAntiReplay);
  Result := LBuilder.Build;
end;

function TTestHandshakeEngine.EchResumingClient(const ACache: ISessionCache;
  const AConfigList: TBytes): ITlsClientConfig;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  LBuilder := ClientBuilder.WithResumption(True).WithSessionCache(ACache)
    .WithResumptionScope(FScope);
  Result := LBuilder.Tls13.WithEarlyData(True).WithEch(TEchClientModes.Enable(AConfigList)).Build;
end;

function TTestHandshakeEngine.EchResumingServer(const AConfigList: TBytes;
  const APrivateKey: ISecretBuffer): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := ServerBuilder.WithResumption(True).WithSessionTicketKeys(FStek);
  Result := LBuilder.Tls13.WithTicketCount(1).WithEarlyData(16384).WithAntiReplay(FAntiReplay)
    .WithEchKeyStore(TInMemoryEchKeyStore.FromConfig(AConfigList, APrivateKey, Crypto)).Build;
end;

function TTestHandshakeEngine.NewClient(const AConfig: ITlsClientConfig): ITlsHandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateHandshakeClientEngine(AConfig, ServerHost, nil, TicketLimit);
end;

function TTestHandshakeEngine.NewServer(const AConfig: ITlsServerConfig): ITlsHandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateHandshakeServerEngine(AConfig, nil, TicketLimit, nil);
end;

function TTestHandshakeEngine.Deliver(const ASrc, ADst: ITlsHandshakeEngine;
  const ALog: THandshakeLog): Int32;
var
  LOutput: THandshakeOutput;
begin
  Result := 0;
  while ASrc.NextOutput(LOutput) do
  begin
    Inc(Result);
    ALog.Add(LOutput);
    if LOutput.Kind = THandshakeOutputKind.HandshakeData then
      ADst.ProvideHandshakeData(LOutput.Level, LOutput.Data, 0, System.Length(LOutput.Data))
    else if FWipeSecrets and (LOutput.Secret <> nil) then
      FillChar(LOutput.Secret.Secret.DataPtr^, LOutput.Secret.Secret.Len, 0);
  end;
end;

procedure TTestHandshakeEngine.Run(const AClient, AServer: ITlsHandshakeEngine);
var
  LRound: Int32;
begin
  AClient.StartHandshake;
  for LRound := 1 to 16 do
    if Deliver(AClient, AServer, FClientLog) + Deliver(AServer, AClient, FServerLog) = 0 then
      Break;
end;

function TTestHandshakeEngine.Describe(const ALog: THandshakeLog): string;
var
  LOutput: THandshakeOutput;
  LKind: string;
begin
  Result := '';
  for LOutput in ALog do
  begin
    case LOutput.Kind of
      THandshakeOutputKind.HandshakeData:
        LKind := 'D' + IntToStr(Ord(LOutput.Level));
      THandshakeOutputKind.ReadSecret:
        LKind := 'R' + IntToStr(Ord(LOutput.Level));
      THandshakeOutputKind.WriteSecret:
        LKind := 'W' + IntToStr(Ord(LOutput.Level));
    else
      LKind := 'C';
    end;
    if Result <> '' then
      Result := Result + ' ';
    Result := Result + LKind;
  end;
end;

function TTestHandshakeEngine.SecretOf(const ALog: THandshakeLog;
  AKind: THandshakeOutputKind; ALevel: TTlsEpoch): TBytes;
var
  LOutput: THandshakeOutput;
begin
  for LOutput in ALog do
    if (LOutput.Kind = AKind) and (LOutput.Level = ALevel) then
      Exit(LOutput.Secret.Secret.ToBytes);
  Fail('the secret was not produced');
  Result := nil;
end;

function TTestHandshakeEngine.HasOutput(const ALog: THandshakeLog;
  AKind: THandshakeOutputKind; ALevel: TTlsEpoch): Boolean;
var
  LOutput: THandshakeOutput;
begin
  Result := False;
  for LOutput in ALog do
    if (LOutput.Kind = AKind) and (LOutput.Level = ALevel) then
      Exit(True);
end;

function TTestHandshakeEngine.MessageTypes(const ALog: THandshakeLog): TBytes;
var
  LOutput: THandshakeOutput;
  LPos, LLength: Int32;
begin
  Result := nil;
  for LOutput in ALog do
    if LOutput.Kind = THandshakeOutputKind.HandshakeData then
    begin
      LPos := 0;
      while LPos + 4 <= System.Length(LOutput.Data) do
      begin
        SetLength(Result, System.Length(Result) + 1);
        Result[High(Result)] := LOutput.Data[LPos];
        LLength := (LOutput.Data[LPos + 1] shl 16) or (LOutput.Data[LPos + 2] shl 8) or
          LOutput.Data[LPos + 3];
        Inc(LPos, 4 + LLength);
      end;
    end;
end;

function TTestHandshakeEngine.FirstData(const ALog: THandshakeLog;
  ALevel: TTlsEpoch): TBytes;
var
  LOutput: THandshakeOutput;
begin
  for LOutput in ALog do
    if (LOutput.Kind = THandshakeOutputKind.HandshakeData) and (LOutput.Level = ALevel) then
      Exit(LOutput.Data);
  Fail('no handshake bytes at the level');
  Result := nil;
end;

function TTestHandshakeEngine.Cached(const ACache: ISessionCache; ABinding: TTicketBinding;
  out ASession: ITls13ResumableSession): Boolean;
var
  LSession: IResumableSession;
begin
  Result := ACache.Take(TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope, ABinding),
    ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs), LSession) and
    Supports(LSession, ITls13ResumableSession, ASession);
end;

function TTestHandshakeEngine.Rebuilt(const ASession: ITls13ResumableSession;
  ABinding: TTicketBinding): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(ASession.CipherSuite, ASession.Hash,
    ASession.ResumptionSecret, ASession.Alpn, ASession.ServerName, ASession.TicketIdentity,
    ASession.TicketLifetime, ASession.TicketAgeAdd, ASession.IssuedAtMillis,
    ASession.MaxEarlyData, ASession.PeerCertificates, ASession.ResumptionScope,
    ASession.PskIdentity, ASession.PskBinding, ASession.PeerSignatureScheme,
    ASession.AuthenticatedAtMillis, ASession.EarlyDataContext, ASession.ApplicationData,
    ABinding) as IResumableSession;
end;

procedure TTestHandshakeEngine.Seed(const ACache: ISessionCache);
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientResuming(ACache, False));
  LServer := NewServer(ServerResuming(True));
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the seeding handshake did not fail');
  CheckTrue(ACache.Count > 0, 'a ticket was cached');
  FClientLog.Clear;
  FServerLog.Clear;
end;

procedure TTestHandshakeEngine.CheckFailedWith(const AEngine: ITlsHandshakeEngine;
  AAlert: TTlsAlertDescription; const AMessage: string);
begin
  CheckTrue(AEngine.IsTerminal, AMessage + ': the engine failed');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(AEngine.LastError.Origin),
    AMessage + ': reported, not sent');
  CheckEquals(Ord(AAlert), Ord(AEngine.LastError.Alert.Description), AMessage + ': the alert');
end;

procedure TTestHandshakeEngine.CheckLocalWithoutAlert(const AEngine: ITlsHandshakeEngine;
  const AMessage: string);
begin
  CheckTrue(AEngine.IsTerminal, AMessage + ': the engine failed');
  CheckEquals(Ord(TTlsErrorOrigin.LocalWithoutAlert), Ord(AEngine.LastError.Origin),
    AMessage + ': no alert exists for it');
end;

function TTestHandshakeEngine.EventSeen(const AEngine: ITlsHandshakeEngine;
  AKind: TTlsEventKind): Boolean;
var
  LEvent: ITlsEvent;
begin
  Result := False;
  while AEngine.NextEvent(LEvent) do
    if LEvent.Kind = AKind then
      Result := True;
end;

function TTestHandshakeEngine.EchConfigList(AConfigId: Byte; const APublicName: string;
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

function TTestHandshakeEngine.CreationRaises(const AConfig: ITlsClientConfig): Boolean;
begin
  Result := False;
  try
    NewClient(AConfig);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestHandshakeEngine.CreationRaises(const AConfig: ITlsServerConfig): Boolean;
begin
  Result := False;
  try
    NewServer(AConfig);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

procedure TTestHandshakeEngine.TestFullHandshakeAgreesOnEverySecretPerLevel;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckFalse(LClient.IsHandshaking, 'the client completed');
  CheckFalse(LServer.IsHandshaking, 'the server completed');
  CheckEqualBytes('client handshake write is the server''s read',
    SecretOf(FClientLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.Handshake),
    SecretOf(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.Handshake));
  CheckEqualBytes('server handshake write is the client''s read',
    SecretOf(FServerLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.Handshake),
    SecretOf(FClientLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.Handshake));
  CheckEqualBytes('client application write is the server''s read',
    SecretOf(FClientLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.Application),
    SecretOf(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.Application));
  CheckEqualBytes('server application write is the client''s read',
    SecretOf(FServerLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.Application),
    SecretOf(FClientLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.Application));
  CheckFalse(TArrayUtilities.AreEqual(
    SecretOf(FClientLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.Application),
    SecretOf(FClientLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.Handshake)),
    'the levels carry different secrets');
  CheckEquals(TlsWireVersionTls13, LClient.ConnectionInfo.NegotiatedVersion.WireValue,
    'the client negotiated TLS 1.3');
  CheckEquals(LServer.ConnectionInfo.CipherSuite, LClient.ConnectionInfo.CipherSuite,
    'both name the same suite');
end;

procedure TTestHandshakeEngine.TestOutputOrderIsPinned;
begin
  Run(NewClient(ClientConfig), NewServer(ServerConfig));
  CheckEquals('D0 R2 W2 D2 W3 R3 C', Describe(FClientLog), 'the client''s order');
  CheckEquals('D0 W2 R2 D2 W3 R3 C', Describe(FServerLog), 'the server''s order');
end;

procedure TTestHandshakeEngine.TestServerReadsApplicationSecretOnlyAfterTheClientFinished;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  LClient.StartHandshake;
  Deliver(LClient, LServer, FClientLog);
  Deliver(LServer, LClient, FServerLog);
  CheckTrue(HasOutput(FServerLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.Application),
    'the server writes at the application level from its Finished');
  CheckFalse(HasOutput(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.Application),
    'but reads there only once the client Finished verified');
  Deliver(LClient, LServer, FClientLog);
  Deliver(LServer, LClient, FServerLog);
  CheckTrue(HasOutput(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.Application),
    'the client Finished unlocked it');
end;

procedure TTestHandshakeEngine.TestNothingRecordShapedIsOnTheWire;
var
  LTypes: TBytes;
  LType: Byte;
  LHello: TTlsClientHello;
  LServerHello: TTlsServerHello;
begin
  Run(NewClient(ClientConfig), NewServer(ServerConfig));
  LHello := THandshakeMessages.DecodeClientHello(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstData(FClientLog, TTlsEpoch.Plaintext)).Body);
  CheckEquals(0, System.Length(LHello.LegacySessionId), 'the ClientHello has an empty session id');
  LServerHello := THandshakeMessages.DecodeServerHello(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstData(FServerLog, TTlsEpoch.Plaintext)).Body);
  CheckEquals(0, System.Length(LServerHello.LegacySessionIdEcho), 'and so does the echo');
  LTypes := MessageTypes(FClientLog);
  for LType in LTypes do
    CheckFalse(LType in [5, 24], 'the client sent neither EndOfEarlyData nor KeyUpdate');
  LTypes := MessageTypes(FServerLog);
  for LType in LTypes do
    CheckFalse(LType in [5, 24], 'nor did the server');
end;

procedure TTestHandshakeEngine.TestRecordSizeLimitIsNotOffered;
var
  LClient: ITlsHandshakeEngine;
  LHello: TTlsClientHello;
begin
  LClient := NewClient(ClientBuilder.WithRecordSizeLimit(4000).Build);
  LClient.StartHandshake;
  Deliver(LClient, NewServer(ServerConfig), FClientLog);
  LHello := THandshakeMessages.DecodeClientHello(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstData(FClientLog, TTlsEpoch.Plaintext)).Body);
  CheckFalse(TExtensionVector.Parse(LHello.Extensions).Contains(28),
    'record sizing is the host''s, so the extension is not offered');
end;

procedure TTestHandshakeEngine.TestServerRefusesAClientHelloWithASessionId;
var
  LTcpClient: ITlsEngine;
  LWire, LHandshake: TBytes;
  LServer: ITlsHandshakeEngine;
  LOutput: THandshakeOutput;
begin
  // a record engine's ClientHello carries the compatibility session id
  LTcpClient := TTlsEngineFactory.CreateClientEngine(ClientConfig, ServerHost);
  LTcpClient.StartHandshake;
  LWire := Drain(LTcpClient);
  LHandshake := System.Copy(LWire, 5, System.Length(LWire) - 5);
  LServer := NewServer(ServerConfig);
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHandshake, 0,
    System.Length(LHandshake))), 'the hello is refused');
  CheckLocalWithoutAlert(LServer, 'a session id');
  CheckFalse(LServer.NextOutput(LOutput), 'nothing is produced');
end;

procedure TTestHandshakeEngine.TestKeyUpdateIsUnexpected;
var
  LClient, LServer: ITlsHandshakeEngine;
  LKeyUpdate: TBytes;
begin
  LKeyUpdate := TBytes.Create(24, 0, 0, 1, 0);
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  Run(LClient, LServer);
  LClient.ProvideHandshakeData(TTlsEpoch.Application, LKeyUpdate, 0, 5);
  CheckFailedWith(LClient, TTlsAlertDescription.UnexpectedMessage, 'a KeyUpdate at the client');
  LServer.ProvideHandshakeData(TTlsEpoch.Application, LKeyUpdate, 0, 5);
  CheckFailedWith(LServer, TTlsAlertDescription.UnexpectedMessage, 'a KeyUpdate at the server');
end;

procedure TTestHandshakeEngine.TestEndOfEarlyDataIsUnexpected;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
  LOutput: THandshakeOutput;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache);
  LClient := NewClient(ClientResuming(LCache, True));
  LServer := NewServer(ServerResuming(True));
  LClient.StartHandshake;
  Deliver(LClient, LServer, FClientLog);
  while LServer.NextOutput(LOutput) do
    FServerLog.Add(LOutput);
  CheckTrue(HasOutput(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.EarlyData),
    'the server accepted 0-RTT');
  // the host delimits early data, so the server reads its client's Finished next
  LServer.ProvideHandshakeData(TTlsEpoch.Handshake, TBytes.Create(5, 0, 0, 0), 0, 4);
  CheckFailedWith(LServer, TTlsAlertDescription.UnexpectedMessage, 'an EndOfEarlyData');
end;

procedure TTestHandshakeEngine.TestZeroRttDeclinedWithoutRetryCompletes;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache);
  LClient := NewClient(ClientResuming(LCache, True));
  LServer := NewServer(ServerResuming(False));
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.IsTerminal, 'the server completed');
  CheckTrue(EventSeen(LClient, TTlsEventKind.EarlyDataRejected), 'the early data was declined');
  CheckFalse(LServer.ConnectionInfo.EarlyDataAccepted, 'the server did not accept it');
  CheckFalse(HasOutput(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.EarlyData),
    'and keyed no early read');
end;

procedure TTestHandshakeEngine.TestPostHandshakeCertificateRequestIsUnexpected;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  Run(LClient, LServer);
  LClient.ProvideHandshakeData(TTlsEpoch.Application, TBytes.Create(13, 0, 0, 0), 0, 4);
  CheckFailedWith(LClient, TTlsAlertDescription.UnexpectedMessage, 'a CertificateRequest');
end;

procedure TTestHandshakeEngine.TestProvideHandshakeDataReportsProgress;
var
  LClient, LServer: ITlsHandshakeEngine;
  LOutput: THandshakeOutput;
begin
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  LClient.StartHandshake;
  CheckTrue(LClient.NextOutput(LOutput), 'the ClientHello');
  CheckEquals(Ord(TTlsOutcome.Advanced),
    Ord(LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LOutput.Data, 0,
    System.Length(LOutput.Data))), 'a flight was queued');
  CheckTrue(LServer.NextOutput(LOutput), 'the ServerHello');
  CheckEquals(Ord(TTlsOutcome.NeedMoreInput),
    Ord(LClient.ProvideHandshakeData(TTlsEpoch.Plaintext, LOutput.Data, 0, 3)),
    'a partial message needs more');
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LClient.ProvideHandshakeData(TTlsEpoch.Application, LOutput.Data, 0, 3)),
    'a wrong level fails');
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LClient.ProvideHandshakeData(TTlsEpoch.Plaintext, LOutput.Data, 0, 3)),
    'and the engine stays failed');
end;

procedure TTestHandshakeEngine.TestTicketsAreNotCappedAcrossDeliveries;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
  LOutput: THandshakeOutput;
  LTicket: TBytes;
  LIndex: Int32;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(ClientResuming(LCache, False));
  LServer := NewServer(ServerResuming(True));
  Run(LClient, LServer);
  for LOutput in FServerLog do
    if (LOutput.Kind = THandshakeOutputKind.HandshakeData) and
      (LOutput.Level = TTlsEpoch.Application) then
      LTicket := LOutput.Data;
  CheckTrue(System.Length(LTicket) > 0, 'the server sent a ticket');
  for LIndex := 1 to 40 do
    LClient.ProvideHandshakeData(TTlsEpoch.Application, LTicket, 0, System.Length(LTicket));
  CheckFalse(LClient.IsTerminal, 'forty tickets over separate deliveries are accepted');
end;

procedure TTestHandshakeEngine.TestTicketWithAnExplicitZeroLimitFails;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
  LNewSessionTicket: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(ClientResuming(LCache, False));
  LServer := NewServer(ServerResuming(True));
  Run(LClient, LServer);
  // lifetime, age_add, empty nonce, a 4-byte ticket and an early_data extension carrying 0
  LNewSessionTicket := DecodeHex('04000019' + '00000e10' + '00000000' + '00' + '0004' +
    '01020304' + '0008' + '002a' + '0004' + '00000000');
  LClient.ProvideHandshakeData(TTlsEpoch.Application, LNewSessionTicket, 0,
    System.Length(LNewSessionTicket));
  CheckLocalWithoutAlert(LClient, 'an early_data of 0 where the host fixed another limit');
end;

procedure TTestHandshakeEngine.TestHostWipingItsSecretsLeavesTheHandshakeIntact;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  FWipeSecrets := True;
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed with its copies zeroed');
  CheckFalse(LServer.IsTerminal, 'and so did the server');
  CheckFalse(LClient.IsHandshaking, 'the client finished');
end;

procedure TTestHandshakeEngine.TestZeroRttWithEchIsAccepted;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
  LList: TBytes;
  LSk: ISecretBuffer;
begin
  LList := EchConfigList($D7, 'cover.example', LSk);
  LCache := TInMemorySessionCache.Create;
  Run(NewClient(EchResumingClient(LCache, LList)), NewServer(EchResumingServer(LList, LSk)));
  CheckTrue(LCache.Count > 0, 'a ticket was cached');
  FClientLog.Clear;
  FServerLog.Clear;
  LClient := NewClient(EchResumingClient(LCache, LList));
  LServer := NewServer(EchResumingServer(LList, LSk));
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'ECH was accepted');
  CheckTrue(LServer.ConnectionInfo.EarlyDataAccepted, 'with early data');
  CheckEqualBytes('the early secret agrees',
    SecretOf(FClientLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.EarlyData),
    SecretOf(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.EarlyData));
end;

procedure TTestHandshakeEngine.TestComplianceGatedProviderRefusesWhatItsRulesRefuse;
var
  LGated: ICryptoProvider;
  LRefused: Boolean;
begin
  LGated := TComplianceCryptoProvider.Compose(
    TOverlayCryptoProvider.Create(Crypto, Crypto.Primitives, nil,
    TFakeBackendReport.Create([]) as ICryptoBackendReport, nil) as ICryptoProvider,
    TCompliancePresets.Fips140_3, TComplianceEnforcement.Relaxed);
  // the default group is one the rules refuse, and the engine does not get round the gate
  LRefused := False;
  try
    NewClient(TTlsPresets.Hardened(LGated, Pkix).Client
      .WithServerVerification(
        TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build);
  except
    on EComplianceRefusedTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a group the rules refuse is refused');
end;

procedure TTestHandshakeEngine.TestInputAtAnotherLevelFails;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LServer := NewServer(ServerConfig);
  LServer.ProvideHandshakeData(TTlsEpoch.Handshake, TBytes.Create(1, 0, 0, 0), 0, 4);
  CheckFailedWith(LServer, TTlsAlertDescription.UnexpectedMessage, 'handshake level too early');
  LClient := NewClient(ClientConfig);
  LClient.StartHandshake;
  LClient.ProvideHandshakeData(TTlsEpoch.Application, TBytes.Create(2, 0, 0, 0), 0, 4);
  CheckFailedWith(LClient, TTlsAlertDescription.UnexpectedMessage, 'application level too early');
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LClient.ProvideHandshakeData(TTlsEpoch.Plaintext, TBytes.Create(2), 0, 1)),
    'a terminal engine takes nothing');
end;

procedure TTestHandshakeEngine.TestMessageStraddlingAKeyChangeFails;
var
  LClient, LServer: ITlsHandshakeEngine;
  LOutput: THandshakeOutput;
  LBytes: TBytes;
begin
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  LClient.StartHandshake;
  Deliver(LClient, LServer, FClientLog);
  CheckTrue(LServer.NextOutput(LOutput), 'the ServerHello');
  // the ServerHello changes the read level, so a byte of the next message behind it is excess
  LBytes := ConcatBytes(LOutput.Data, TBytes.Create(8));
  LClient.ProvideHandshakeData(TTlsEpoch.Plaintext, LBytes, 0, System.Length(LBytes));
  CheckFailedWith(LClient, TTlsAlertDescription.UnexpectedMessage, 'a partial message');
end;

procedure TTestHandshakeEngine.TestRfc9001ClientHelloIsServedWithItsLimitIgnored;
var
  LServer: ITlsHandshakeEngine;
  LHello: TBytes;
  LOutput: THandshakeOutput;
  LSeen: Boolean;
begin
  // a recorded hello: empty session id, record_size_limit and an extension type the core does not know
  LHello := TTlsLibTestCertificates.Field('Handshake/ClientHelloRfc9001.txt', 'client_hello');
  LServer := NewServer(ServerBuilder.WithAlpnProtocols(
    TArray<TBytes>.Create(TEncoding.ASCII.GetBytes('alpn'))).Build);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFalse(LServer.IsTerminal, 'the server accepted the hello');
  LSeen := False;
  while LServer.NextOutput(LOutput) do
  begin
    FServerLog.Add(LOutput);
    if (LOutput.Kind = THandshakeOutputKind.HandshakeData) and
      (LOutput.Level = TTlsEpoch.Handshake) then
    begin
      CheckFalse(TExtensionVector.Parse(THandshakeMessages.DecodeEncryptedExtensions(
        TTlsLibTestHandshakeDecoder.HandshakeMessage(LOutput.Data).Body)).Contains(28),
        'the offered record_size_limit is not echoed');
      LSeen := True;
    end;
  end;
  CheckTrue(LSeen, 'the server flight was produced');
  CheckEquals('D0 W2 R2 D2 W3', Describe(FServerLog), 'up to its Finished');
end;

procedure TTestHandshakeEngine.TestAlpnIsVisibleBeforeAnythingIsPulled;
var
  LServer: ITlsHandshakeEngine;
  LHello: TBytes;
begin
  LHello := TTlsLibTestCertificates.Field('Handshake/ClientHelloRfc9001.txt', 'client_hello');
  LServer := NewServer(ServerBuilder.WithAlpnProtocols(
    TArray<TBytes>.Create(TEncoding.ASCII.GetBytes('alpn'))).Build);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckEquals('alpn', TEncoding.ASCII.GetString(LServer.ConnectionInfo.AlpnProtocol),
    'the selected protocol is readable straight after the input, before any output is taken');
end;

procedure TTestHandshakeEngine.TestTicketCarriesTheFixedEarlyDataLimit;
var
  LCache: ISessionCache;
  LSession: ITls13ResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache);
  CheckTrue(Cached(LCache, TTicketBinding.HandshakeEngine, LSession),
    'the ticket is cached under the engine kind');
  CheckEquals(Int64(TicketLimit), Int64(LSession.MaxEarlyData),
    'the server wrote the host''s limit, not the config''s');
  CheckEquals(Ord(TTicketBinding.HandshakeEngine), Ord(LSession.TicketBinding),
    'and stamped its kind');
end;

procedure TTestHandshakeEngine.TestMismatchedTicketLimitFailsWithoutAnAlert;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := TTlsEngineFactory.CreateHandshakeClientEngine(ClientResuming(LCache, False),
    ServerHost, nil, 1234);
  LServer := NewServer(ServerResuming(True));
  Run(LClient, LServer);
  CheckLocalWithoutAlert(LClient, 'a limit the host did not fix');
  CheckEquals(0, LCache.Count, 'the ticket was not cached');
end;

procedure TTestHandshakeEngine.TestResumptionUsesTheTicketOfItsOwnKind;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache);
  LClient := NewClient(ClientResuming(LCache, False));
  LServer := NewServer(ServerResuming(True));
  Run(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the client resumed');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed');
end;

procedure TTestHandshakeEngine.TestZeroRttIsAcceptedAndKeysAgree;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
  LClientExport, LServerExport: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache);
  LClient := NewClient(ClientResuming(LCache, True));
  LServer := NewServer(ServerResuming(True));
  Run(LClient, LServer);
  CheckEquals('D0 W1 R2 W2 D2 W3 R3 C', Describe(FClientLog), 'the client''s order');
  CheckEquals('D0 W2 R1 R2 D2 W3 R3 D3 C', Describe(FServerLog), 'the server''s order');
  CheckTrue(LServer.ConnectionInfo.EarlyDataAccepted, 'the server accepted 0-RTT');
  CheckEqualBytes('the early secret agrees',
    SecretOf(FClientLog, THandshakeOutputKind.WriteSecret, TTlsEpoch.EarlyData),
    SecretOf(FServerLog, THandshakeOutputKind.ReadSecret, TTlsEpoch.EarlyData));
  CheckTrue(EventSeen(LClient, TTlsEventKind.EarlyDataAccepted), 'the client saw the accept');
  CheckEquals(2, System.Length(MessageTypes(FClientLog)),
    'the client sent its hello and its Finished only, no EndOfEarlyData');
  LClientExport := LClient.ExportEarlyKeyingMaterial('early label', nil, 32);
  LServerExport := LServer.ExportEarlyKeyingMaterial('early label', nil, 32);
  CheckEquals(32, System.Length(LClientExport), 'an early export exists');
  CheckEqualBytes('and agrees', LClientExport, LServerExport);
end;

procedure TTestHandshakeEngine.TestZeroRttIsRejectedAfterARetry;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsHandshakeEngine;
  LServerBuilder: ITlsServerConfigBuilder;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache);
  // the client leads with the group it last used; this server accepts another one
  LServerBuilder := ServerBuilder.WithResumption(True).WithSessionTicketKeys(FStek)
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1));
  LServerBuilder.Tls13.WithTicketCount(1).WithEarlyData(16384).WithAntiReplay(FAntiReplay);
  LClient := NewClient(ClientResuming(LCache, True));
  LServer := NewServer(LServerBuilder.Build);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckTrue(LClient.ConnectionInfo.HelloRetryRequest, 'a retry happened');
  CheckTrue(EventSeen(LClient, TTlsEventKind.EarlyDataRejected), 'the early data was rejected');
  CheckFalse(LServer.ConnectionInfo.EarlyDataAccepted, 'the server did not accept it');
end;

procedure TTestHandshakeEngine.TestHelloRetryRequestCompletes;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientBuilder.WithPreferredGroups(
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1)).Build);
  LServer := NewServer(ServerBuilder.WithPreferredGroups(
    TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1)).Build);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.IsTerminal, 'the server completed');
  CheckTrue(LClient.ConnectionInfo.HelloRetryRequest, 'the client saw a retry');
  CheckTrue(LServer.ConnectionInfo.HelloRetryRequest, 'the server sent one');
  CheckEquals('D0 D0 R2 W2 D2 W3 R3 C', Describe(FClientLog), 'two hellos from the client');
end;

procedure TTestHandshakeEngine.TestMutualAuthentication;
var
  LClient, LServer: ITlsHandshakeEngine;
  LLeaf, LKey, LRoot: TBytes;
begin
  LLeaf := TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert');
  LKey := TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key');
  LRoot := TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert');
  LClient := NewClient(TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(LRoot).Build)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix, LLeaf, LKey)).Build);
  LServer := NewServer(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix, LLeaf, LKey))
    .WithClientVerification(TClientVerification.WebPki(LRoot).Build)
    .WithPeerAuth(TClientAuthMode.Required).Build);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.IsTerminal, 'the server completed');
  CheckTrue(System.Length(LServer.ConnectionInfo.PeerCertificates) > 0,
    'the server saw the client certificate');
end;

procedure TTestHandshakeEngine.TestHostExtensionsGoBothWays;
var
  LClient, LServer: ITlsHandshakeEngine;
  LClientResults, LServerResults: ITlsHostExtensionResults;
  LBody: TBytes;
begin
  LClient := TTlsEngineFactory.CreateHandshakeClientEngine(ClientConfig, ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType,
    [TTlsExtensionContextKind.ClientHello], DecodeHex('c1c2c3'),
    [TTlsExtensionContextKind.EncryptedExtensions])), TicketLimit);
  LServer := TTlsEngineFactory.CreateHandshakeServerEngine(ServerConfig,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make(HostType,
    [TTlsExtensionContextKind.EncryptedExtensions], DecodeHex('5e5f'),
    [TTlsExtensionContextKind.ClientHello])), TicketLimit, nil);
  CheckTrue(Supports(LClient, ITlsHostExtensionResults, LClientResults),
    'the client engine answers the results');
  CheckTrue(Supports(LServer, ITlsHostExtensionResults, LServerResults),
    'so does the server engine');
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckTrue(LServerResults.TryGetPeerExtension(HostType, LBody), 'the server read the client''s');
  CheckEqualBytes('its body', DecodeHex('c1c2c3'), LBody);
  CheckTrue(LClientResults.TryGetPeerExtension(HostType, LBody), 'the client read the server''s');
  CheckEqualBytes('its body', DecodeHex('5e5f'), LBody);
end;

procedure TTestHandshakeEngine.TestEchAccepted;
var
  LClient, LServer: ITlsHandshakeEngine;
  LList: TBytes;
  LSk: ISecretBuffer;
  LHello: TTlsClientHello;
begin
  LList := EchConfigList($D7, 'cover.example', LSk);
  LClient := NewClient(TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Tls13.WithEch(TEchClientModes.Enable(LList)).Build);
  LServer := NewServer(TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .Tls13.WithEchKeyStore(TInMemoryEchKeyStore.FromConfig(LList, LSk, Crypto)).Build);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.IsTerminal, 'the server completed');
  CheckTrue(LClient.ConnectionInfo.EchStatus = TEchStatus.Accepted, 'ECH was accepted');
  LHello := THandshakeMessages.DecodeClientHello(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstData(FClientLog, TTlsEpoch.Plaintext)).Body);
  CheckEquals(0, System.Length(LHello.LegacySessionId), 'the outer hello has no session id');
end;

procedure TTestHandshakeEngine.TestEchRejectedFailsTheClientWithEchRequired;
var
  LClient, LServer: ITlsHandshakeEngine;
  LClientList, LServerList: TBytes;
  LClientSk, LServerSk: ISecretBuffer;
  LBuilder: ITlsClientConfigBuilder;
begin
  // the server holds another config id, so it cannot decrypt the offer and serves the outer hello
  LClientList := EchConfigList($D8, 'localhost', LClientSk);
  LServerList := EchConfigList($D9, 'localhost', LServerSk);
  LBuilder := ClientBuilder;
  LBuilder.WithDangerousDisableServerNameCheck;
  LClient := NewClient(LBuilder.Tls13.WithEch(TEchClientModes.Enable(LClientList)).Build);
  LServer := NewServer(TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .Tls13.WithEchKeyStore(TInMemoryEchKeyStore.FromConfig(LServerList, LServerSk, Crypto)).Build);
  Run(LClient, LServer);
  CheckFailedWith(LClient, TTlsAlertDescription.EchRequired, 'a rejected offer');
  CheckTrue(LClient.ConnectionInfo.EchRejectAborted, 'the facts say the client aborted');
end;

procedure TTestHandshakeEngine.TestAsyncVerdictParksAndResumes;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientBuilder.WithAsyncCertificateVerdict(0).Build);
  LServer := NewServer(ServerConfig);
  LClient.StartHandshake;
  Deliver(LClient, LServer, FClientLog);
  Deliver(LServer, LClient, FServerLog);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client parked on the verdict');
  CheckTrue(EventSeen(LClient, TTlsEventKind.CertificateReceived), 'and raised the event');
  CheckTrue(LClient.IsHandshaking, 'nothing completed while parked');
  LClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  CheckFalse(LClient.AwaitingCertificateVerdict, 'the verdict resumed it');
  Deliver(LClient, LServer, FClientLog);
  Deliver(LServer, LClient, FServerLog);
  CheckFalse(LClient.IsHandshaking, 'the client completed');
  CheckFalse(LServer.IsHandshaking, 'the server completed');
end;

procedure TTestHandshakeEngine.TestAsyncVerdictRejectIsReported;
var
  LClient, LServer: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientBuilder.WithAsyncCertificateVerdict(0).Build);
  LServer := NewServer(ServerConfig);
  LClient.StartHandshake;
  Deliver(LClient, LServer, FClientLog);
  Deliver(LServer, LClient, FServerLog);
  LClient.SetCertificateVerdict(False, TTlsAlertDescription.CertificateRevoked);
  CheckFailedWith(LClient, TTlsAlertDescription.CertificateRevoked, 'a rejected verdict');
end;

procedure TTestHandshakeEngine.TestKeyLogReceivesTheHandshakeSecrets;
var
  LLog: TMockKeyLog;
  LRef: IKeyLog;
  LIndex: Int32;
  LSeen: Boolean;
begin
  LLog := TMockKeyLog.Create;
  LRef := LLog as IKeyLog;
  Run(NewClient(ClientBuilder.WithDangerousKeyLog(LRef).Build), NewServer(ServerConfig));
  LSeen := False;
  for LIndex := 0 to LLog.Count - 1 do
    if LLog[LIndex].Lbl = 'CLIENT_HANDSHAKE_TRAFFIC_SECRET' then
      LSeen := True;
  CheckTrue(LSeen, 'the key log received the handshake traffic secret');
end;

procedure TTestHandshakeEngine.TestExportersAgree;
var
  LClient, LServer: ITlsHandshakeEngine;
  LClientExport: TBytes;
begin
  LClient := NewClient(ClientConfig);
  LServer := NewServer(ServerConfig);
  CheckEquals(0, System.Length(LClient.ExportKeyingMaterial('label', 32)),
    'nothing is exported before the secret exists');
  Run(LClient, LServer);
  LClientExport := LClient.ExportKeyingMaterial('label', DecodeHex('0102'), 32);
  CheckEquals(32, System.Length(LClientExport), 'the client exports');
  CheckEqualBytes('the server''s export agrees', LClientExport,
    LServer.ExportKeyingMaterial('label', DecodeHex('0102'), 32));
end;

procedure TTestHandshakeEngine.TestCreationRefusesAConfigWithoutTls13Alone;
begin
  CheckTrue(CreationRaises(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build),
    'a client that also offers TLS 1.2');
  CheckTrue(CreationRaises(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build), 'a server that also offers TLS 1.2');
  CheckTrue(CreationRaises(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build),
    'a TLS 1.2-only client');
  CheckTrue(CreationRaises(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCredential(ServerCredential).Build), 'a TLS 1.2-only server');
  CheckFalse(CreationRaises(ClientConfig), 'a TLS 1.3 client is accepted');
  CheckFalse(CreationRaises(ServerConfig), 'a TLS 1.3 server is accepted');
end;

procedure TTestHandshakeEngine.TestRecordEngineTicketIsNotOfferedToTheHandshakeEngine;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LHandshakeClient: ITlsHandshakeEngine;
  LOutput: THandshakeOutput;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := TTlsEngineFactory.CreateClientEngine(ClientResuming(LCache, False), ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerResuming(False));
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckTrue(LCache.Count > 0, 'the record engine cached its ticket');
  LHandshakeClient := NewClient(ClientResuming(LCache, False));
  LHandshakeClient.StartHandshake;
  CheckTrue(LHandshakeClient.NextOutput(LOutput), 'the ClientHello');
  CheckFalse(TExtensionVector.Parse(THandshakeMessages.DecodeClientHello(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(LOutput.Data).Body).Extensions).Contains(
    TExtensionTypes.PreSharedKey), 'it does not offer the other kind''s ticket');
end;

procedure TTestHandshakeEngine.TestHandshakeEngineTicketIsNotOfferedToTheRecordEngine;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache);
  LClient := TTlsEngineFactory.CreateClientEngine(ClientResuming(LCache, False), ServerHost);
  LClient.StartHandshake;
  CheckFalse(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(Drain(LClient)).Contains(
    TExtensionTypes.PreSharedKey), 'the record engine does not offer the other kind''s ticket');
end;

procedure TTestHandshakeEngine.TestServerDeclinesARecordEngineTicket;
var
  LCache, LOther: ISessionCache;
  LClient, LServer: ITlsEngine;
  LTaken: IResumableSession;
  LSession: ITls13ResumableSession;
  LHandshakeClient: ITlsHandshakeEngine;
  LHandshakeServer: ITlsHandshakeEngine;
begin
  // a ticket the record engine's server sealed, presented by a handshake client as its own
  LOther := TInMemorySessionCache.Create;
  LClient := TTlsEngineFactory.CreateClientEngine(ClientResuming(LOther, False), ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerResuming(False));
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckTrue(LOther.Take(TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope),
    ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs), LTaken), 'the record ticket');
  CheckTrue(Supports(LTaken, ITls13ResumableSession, LSession), 'a TLS 1.3 session');
  LCache := TInMemorySessionCache.Create;
  LCache.Store(TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope,
    TTicketBinding.HandshakeEngine), ServerHost, Rebuilt(LSession, TTicketBinding.HandshakeEngine));
  LHandshakeClient := NewClient(ClientResuming(LCache, False));
  LHandshakeServer := NewServer(ServerResuming(False));
  Run(LHandshakeClient, LHandshakeServer);
  CheckFalse(LHandshakeServer.IsTerminal, 'the server did not fail');
  CheckFalse(LHandshakeServer.ConnectionInfo.Resumed, 'it declined the ticket, and ran in full');
  CheckFalse(LHandshakeClient.IsTerminal, 'the client completed');
end;

procedure TTestHandshakeEngine.TestCryptoOverlayDerivesTheKeys;
var
  LCounting: TCountingPrimitives;
  LRef: ICryptoPrimitives;
  LOverlay: ICryptoProvider;
  LClient, LServer: ITlsHandshakeEngine;
begin
  LCounting := TCountingPrimitives.Create(Crypto.Primitives);
  LRef := LCounting;
  LOverlay := TOverlayCryptoProvider.Create(Crypto, LRef, nil, nil, nil);
  LClient := NewClient(TTlsPresets.Hardened(LOverlay, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build).Build);
  LServer := NewServer(TTlsPresets.Hardened(LOverlay, Pkix).Server
    .WithCredential(ServerCredential(LOverlay)).Build);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the handshake completed over the overlay');
  CheckTrue(LCounting.Hkdfs > 0, 'the key schedule ran through the overlay''s HKDF');
end;

procedure TTestHandshakeEngine.TestTransportFailureIsReportedWithoutAlert;
var
  LClient: ITlsHandshakeEngine;
begin
  LClient := NewClient(ClientConfig);
  LClient.LatchTransportFailure('the path died');
  CheckTrue(LClient.IsTerminal, 'the engine ended');
  CheckEquals(Ord(TTlsErrorOrigin.Transport), Ord(LClient.LastError.Origin), 'a transport failure');
end;

procedure TTestHandshakeEngine.TestNothingIsPulledOnceTerminal;
var
  LClient: ITlsHandshakeEngine;
  LOutput: THandshakeOutput;
begin
  LClient := NewClient(ClientConfig);
  LClient.StartHandshake;
  LClient.LatchTransportFailure('gone');
  CheckFalse(LClient.NextOutput(LOutput), 'the queued hello is not handed out');
end;

procedure TTestHandshakeEngine.TestLocalWithoutAlertCarriesNoAlertToAStream;
var
  LError: ETlsStreamError;
begin
  LError := ETlsStreamError.Create(TTlsError.CreateFatal(TTlsAlertDescription.InternalError,
    'no alert', TTlsErrorOrigin.LocalWithoutAlert));
  try
    CheckFalse(LError.HasAlert, 'the stream error says no alert was involved');
  finally
    LError.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHandshakeEngine);
{$ELSE}
  RegisterTest(TTestHandshakeEngine.Suite);
{$ENDIF FPC}

end.
