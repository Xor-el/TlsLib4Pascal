{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClientHelloPauseTests;

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
  TlpTlsError,
  TlpTlsLibExceptions,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpIKeySchedule,
  TlpExtensionVector,
  TlpExtensionContext,
  TlpCoreExtensions,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpITlsHostExtension,
  TlpHostExtensions,
  TlpISession,
  TlpInMemorySessionCache,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlpSystemTimeUtilities,
  TlpEchConfig,
  TlpEchClient,
  TlpInMemoryEchKeyStore,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpCertificateVerifierSource,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpNegotiationTypes,
  TlpIClock,
  TlpITlsEngine,
  TlpITls13HandshakeEngine,
  TlpTls13HandshakeOutput,
  MockClock,
  MockCredentialResolvers,
  SupportCertificates,
  TlsLibHandshakeTestBase;

type
  /// <summary>
  /// The ClientHello pause of a TLS 1.3 handshake-only server: it parks once the first ClientHello
  /// is validated and before anything is selected, so the host reads what the client offered, then
  /// chooses its host extensions' reply bodies and the engine's resumption scope when it continues.
  /// </summary>
  TTestClientHelloPause = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
    TicketLimit = UInt32($FFFFFFFF);
    HostType = UInt16($FC01);
    OtherType = UInt16($FC02);
    UnknownType = UInt16($FC09);
  type
    /// <summary>How a server engine of a scope test is created and continued.</summary>
    TServerSetup = record
      Creation: TBytes;
      Continuation: TBytes;
      Pause: Boolean;
    end;
    TRewrite = (ChangeBody, DropType, AddType);
  var
    FStek: ISessionTicketKeyManager;
    FAntiReplay: IAntiReplayStrategy;
    FLog: string;
    FReentrantServer: ITls13HandshakeEngine;
    FReentryRaised: Boolean;
    function ClientBuilder: ITlsClientConfigBuilder;
    function ServerBuilder: ITlsServerConfigBuilder;
    function ClientConfig(ARetry: Boolean): ITlsClientConfig;
    function ServerConfig(ARetry: Boolean): ITlsServerConfig;
    function ClientResuming(const ACache: ISessionCache; AEarlyData: Boolean): ITlsClientConfig;
    function ServerResuming(AEarlyData: Boolean; const AClock: ITlsClock): ITlsServerConfig;
    function ClientExt(const ABody: TBytes; ARequiredIn: TTlsExtensionContexts): ITlsHostExtension;
    function ServerExt(ASendIn: TTlsExtensionContexts; ARequiredIn: TTlsExtensionContexts;
      AType: UInt16): ITlsHostExtension;
    function Reply(AType: UInt16; const ABody: TBytes): TTlsHostExtensionReply;
    function NewClient(const AConfig: ITlsClientConfig;
      const AExtensions: TArray<ITlsHostExtension>): ITls13HandshakeEngine;
    function NewServer(const AConfig: ITlsServerConfig;
      const AExtensions: TArray<ITlsHostExtension>; APause: Boolean): ITls13HandshakeEngine;
    function ServerAs(const ACreation, AContinuation: TBytes; APause: Boolean): TServerSetup;
    /// <summary>Moves everything ASrc has queued to ADst, noting each item under ATag in the log;
    /// returns how many items moved.</summary>
    function Deliver(const ASrc, ADst: ITls13HandshakeEngine; const ATag: string): Int32;
    procedure Exchange(const AClient, AServer: ITls13HandshakeEngine);
    /// <summary>Starts AClient and exchanges flights until neither engine has anything to send.</summary>
    procedure Run(const AClient, AServer: ITls13HandshakeEngine);
    /// <summary>Takes everything ASrc has queued and returns its handshake bytes.</summary>
    function TakeData(const ASrc: ITls13HandshakeEngine): TBytes;
    /// <summary>Starts AClient and feeds its ClientHello to AServer, which must park.</summary>
    procedure Park(const AClient, AServer: ITls13HandshakeEngine);
    function Rewritten(const AFramedHello: TBytes; AType: UInt16; const ABody: TBytes;
      ARewrite: TRewrite): TBytes;
    function EventCount(const AEngine: ITls13HandshakeEngine; AKind: TTlsEventKind): Int32;
    function HasEarlyReadSecret(const AEngine: ITls13HandshakeEngine): Boolean;
    procedure CheckFailedWith(const AEngine: ITls13HandshakeEngine; AAlert: TTlsAlertDescription;
      const AMessage: string);
    function ContinueRaisesArgument(const AEngine: ITls13HandshakeEngine;
      const AReplies: TArray<TTlsHostExtensionReply>; const AScope: TBytes): Boolean;
    function EchConfigList(AConfigId: Byte; const APublicName: string;
      out APrivateKey: ISecretBuffer): TBytes;
    /// <summary>A pausing server and a client over a retry-forcing configuration, parked, whose
    /// first answer is a HelloRetryRequest the client has read; returns the client's second
    /// ClientHello.</summary>
    function SecondHello(const AClientExts, AServerExts: TArray<ITlsHostExtension>;
      const AReplies: TArray<TTlsHostExtensionReply>; out AClient,
      AServer: ITls13HandshakeEngine): TBytes;
    /// <summary>Connects a client with ACache to a server made as ASetup says, to completion;
    /// returns the client.</summary>
    function Connect(const ACache: ISessionCache; const ASetup: TServerSetup): ITls13HandshakeEngine;
    function ResumesAfter(const ASeal, AAccept: TServerSetup): Boolean;
    /// <summary>Whether the server of a replayed early-data ClientHello accepts the early data,
    /// after a first server saw the same ClientHello and either continued or was refused.</summary>
    function ReplayAcceptsEarlyData(AFirstContinues: Boolean): Boolean;
    /// <summary>Runs a first handshake against AConfig to cache a ticket, then returns a client
    /// that resumes it and offers early data.</summary>
    function EarlyDataClient(const AConfig: ITlsServerConfig): ITls13HandshakeEngine;
    function ReceivedWithTrailingByte(APause: Boolean): ITls13HandshakeEngine;
    procedure ReenterTheEngine;
  protected
    procedure SetUp; override;
  published
    procedure TestParkReturnsAdvancedAndRaisesTheEvent;
    procedure TestParkQueuesNothingAndKeepsHandshaking;
    procedure TestOfferedServerNameIsWhatTheClientOffered;
    procedure TestNothingIsOfferedOutsideThePark;
    procedure TestReplyChosenFromTheOfferedBodyIsSentInEncryptedExtensions;
    procedure TestUnansweredOfferedExtensionIsNotSent;
    procedure TestWithoutThePauseTheCreationBodyIsSent;
    procedure TestHandshakeShapeIsTheSameWithAnImmediateContinue;
    procedure TestHelloRetryRequestFollowsTheContinue;
    procedure TestSecondClientHelloDoesNotPause;
    procedure TestHandshakeCompletesAcrossARetryWithTheChosenReply;
    procedure TestSecondClientHelloWithAChangedBodyFails;
    procedure TestSecondClientHelloWithAnAddedTypeFails;
    procedure TestSecondClientHelloWithADroppedTypeFails;
    procedure TestSecondClientHelloDroppingARequiredTypeIsIllegalParameter;
    procedure TestTypeTheRetryCarriedMayChangeInTheSecondClientHello;
    procedure TestEchAcceptedShowsTheInnerValues;
    procedure TestEchRejectedShowsTheOuterServerName;
    procedure TestFailingValidationNeverPauses;
    procedure TestSelectionFailureAfterTheContinueIsInBand;
    procedure TestScopeSetAtContinueGovernsAcceptance;
    procedure TestScopeSetAtContinueGovernsSealing;
    procedure TestEmptyScopeAtContinueKeepsTheCreationScope;
    procedure TestScopeAtContinueReplacesTheCreationScope;
    procedure TestPauseLongerThanTheFreshnessWindowStillAcceptsZeroRtt;
    procedure TestPauseOutlastingTheReplayWindowDeclinesZeroRtt;
    procedure TestPauseOutlastingTheReplayWindowStillResumes;
    procedure TestReplayContinuedAfterAnUnrelatedPruneIsRefused;
    procedure TestRefusedParkedConnectionLeavesTheAntiReplaySlotUnused;
    procedure TestContinuedConnectionIsAReplayForAnotherEngine;
    procedure TestReplyForAnExtensionTheClientDidNotOfferIsRefused;
    procedure TestReplyForARegisteredExtensionTheClientDidNotOfferIsRefused;
    procedure TestTwoRepliesForOneExtensionAreRefused;
    procedure TestReplyBodyOverTheLimitIsRefused;
    procedure TestReplyBodyAtTheLimitIsNotRefused;
    procedure TestScopeOverTheLimitIsRefusedAtContinue;
    procedure TestScopeAtTheLimitIsNotRefusedAtContinue;
    procedure TestEngineStaysParkedAfterAMisuse;
    procedure TestValidContinueSucceedsAfterAMisuse;
    procedure TestContinueBeforeAnyClientHelloIsANoOp;
    procedure TestContinueOnAClientIsANoOp;
    procedure TestContinueOnAServerWithoutThePauseIsANoOp;
    procedure TestSecondContinueIsANoOp;
    procedure TestContinueFromAResolverRaises;
    procedure TestLatchTransportFailureWhileParkedEndsTheEngine;
    procedure TestDestroyingAParkedEngineIsClean;
    procedure TestContinuingFreesTheParkedState;
    procedure TestClientHelloWithTrailingBytesFailsAsWithoutThePause;
    procedure TestInputWhileParkedIsBufferedUntilTheContinue;
    procedure TestEngineWithoutThePauseNeverParks;
  end;

implementation

{ TTestClientHelloPause }

procedure TTestClientHelloPause.SetUp;
begin
  inherited SetUp;
  FStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager;
  FAntiReplay := TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy;
  FLog := '';
  FReentrantServer := nil;
  FReentryRaised := False;
end;

function TTestClientHelloPause.ClientBuilder: ITlsClientConfigBuilder;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TSupportCertificates.EcP256RootStore).Build);
end;

function TTestClientHelloPause.ServerBuilder: ITlsServerConfigBuilder;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential);
end;

function TTestClientHelloPause.ClientConfig(ARetry: Boolean): ITlsClientConfig;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  LBuilder := ClientBuilder;
  // the client leads with a group the server does not prefer, so the server answers with a retry
  if ARetry then
    LBuilder.WithPreferredGroups(
      TArray<UInt16>.Create(TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1));
  Result := LBuilder.Build;
end;

function TTestClientHelloPause.ServerConfig(ARetry: Boolean): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := ServerBuilder;
  if ARetry then
    LBuilder.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1));
  Result := LBuilder.Build;
end;

function TTestClientHelloPause.ClientResuming(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsClientConfig;
begin
  Result := ClientBuilder.WithResumption(True).WithSessionCache(ACache)
    .WithResumptionScope(Filled($5C, 16)).Tls13.WithEarlyData(AEarlyData).Build;
end;

function TTestClientHelloPause.ServerResuming(AEarlyData: Boolean;
  const AClock: ITlsClock): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := ServerBuilder.WithResumption(True).WithSessionTicketKeys(FStek);
  if AClock <> nil then
    LBuilder.WithClock(AClock);
  LBuilder.Tls13.WithTicketCount(1);
  if AEarlyData then
    LBuilder.Tls13.WithEarlyData(16384).WithAntiReplay(FAntiReplay);
  Result := LBuilder.Build;
end;

function TTestClientHelloPause.ClientExt(const ABody: TBytes;
  ARequiredIn: TTlsExtensionContexts): ITlsHostExtension;
begin
  Result := TTlsHostExtensions.Make(HostType, [TTlsExtensionContextKind.ClientHello], ABody,
    ARequiredIn);
end;

function TTestClientHelloPause.ServerExt(ASendIn: TTlsExtensionContexts;
  ARequiredIn: TTlsExtensionContexts; AType: UInt16): ITlsHostExtension;
begin
  // the body given at registration is a placeholder: a pausing engine never sends it
  Result := TTlsHostExtensions.Make(AType, ASendIn, DecodeHex('00'), ARequiredIn);
end;

function TTestClientHelloPause.Reply(AType: UInt16; const ABody: TBytes): TTlsHostExtensionReply;
begin
  Result.ExtensionType := AType;
  Result.Body := ABody;
end;

function TTestClientHelloPause.NewClient(const AConfig: ITlsClientConfig;
  const AExtensions: TArray<ITlsHostExtension>): ITls13HandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateTls13HandshakeClientEngine(AConfig, ServerHost, AExtensions,
    TicketLimit);
end;

function TTestClientHelloPause.NewServer(const AConfig: ITlsServerConfig;
  const AExtensions: TArray<ITlsHostExtension>; APause: Boolean): ITls13HandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateTls13HandshakeServerEngine(AConfig, AExtensions, TicketLimit,
    nil, nil, APause);
end;

function TTestClientHelloPause.ServerAs(const ACreation, AContinuation: TBytes;
  APause: Boolean): TServerSetup;
begin
  Result.Creation := ACreation;
  Result.Continuation := AContinuation;
  Result.Pause := APause;
end;

function TTestClientHelloPause.Deliver(const ASrc, ADst: ITls13HandshakeEngine;
  const ATag: string): Int32;
var
  LOutput: TTls13HandshakeOutput;
begin
  Result := 0;
  while ASrc.NextOutput(LOutput) do
  begin
    Inc(Result);
    FLog := FLog + ATag + IntToStr(Ord(LOutput.Kind)) + IntToStr(Ord(LOutput.Level)) + ' ';
    if LOutput.Kind = TTls13HandshakeOutputKind.HandshakeData then
      ADst.ProvideHandshakeData(LOutput.Level, LOutput.Data, 0, System.Length(LOutput.Data));
  end;
end;

procedure TTestClientHelloPause.Exchange(const AClient, AServer: ITls13HandshakeEngine);
var
  LRound: Int32;
begin
  for LRound := 1 to 16 do
    if Deliver(AClient, AServer, 'c') + Deliver(AServer, AClient, 's') = 0 then
      Break;
end;

procedure TTestClientHelloPause.Run(const AClient, AServer: ITls13HandshakeEngine);
begin
  AClient.StartHandshake;
  Exchange(AClient, AServer);
end;

function TTestClientHelloPause.TakeData(const ASrc: ITls13HandshakeEngine): TBytes;
var
  LOutput: TTls13HandshakeOutput;
begin
  Result := nil;
  while ASrc.NextOutput(LOutput) do
    if LOutput.Kind = TTls13HandshakeOutputKind.HandshakeData then
      Result := ConcatBytes(Result, LOutput.Data);
end;

procedure TTestClientHelloPause.Park(const AClient, AServer: ITls13HandshakeEngine);
var
  LHello: TBytes;
begin
  AClient.StartHandshake;
  LHello := TakeData(AClient);
  AServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckTrue(AServer.AwaitingClientHello, 'the server parked at the ClientHello');
end;

function TTestClientHelloPause.Rewritten(const AFramedHello: TBytes; AType: UInt16;
  const ABody: TBytes; ARewrite: TRewrite): TBytes;
var
  LHello: TTlsClientHello;
  LVector: TExtensionVector;
begin
  LHello := THandshakeMessages.DecodeClientHello(
    System.Copy(AFramedHello, 4, System.Length(AFramedHello) - 4));
  LVector := TExtensionVector.Parse(LHello.Extensions);
  case ARewrite of
    TRewrite.ChangeBody:
      LVector.SetData(LVector.IndexOf(AType), ABody);
    TRewrite.DropType:
      LVector.Delete(LVector.IndexOf(AType));
    TRewrite.AddType:
      LVector.Append(TExtensionEntry.Create(AType, ABody));
  end;
  LHello.Extensions := LVector.Encode;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
end;

function TTestClientHelloPause.EventCount(const AEngine: ITls13HandshakeEngine;
  AKind: TTlsEventKind): Int32;
var
  LEvent: ITlsEvent;
begin
  Result := 0;
  while AEngine.NextEvent(LEvent) do
    if LEvent.Kind = AKind then
      Inc(Result);
end;

function TTestClientHelloPause.HasEarlyReadSecret(const AEngine: ITls13HandshakeEngine): Boolean;
var
  LOutput: TTls13HandshakeOutput;
begin
  Result := False;
  while AEngine.NextOutput(LOutput) do
    if (LOutput.Kind = TTls13HandshakeOutputKind.ReadSecret) and
      (LOutput.Level = TTlsEpoch.EarlyData) then
      Result := True;
end;

procedure TTestClientHelloPause.CheckFailedWith(const AEngine: ITls13HandshakeEngine;
  AAlert: TTlsAlertDescription; const AMessage: string);
begin
  CheckTrue(AEngine.IsTerminal, AMessage + ': the engine failed');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(AEngine.LastError.Origin),
    AMessage + ': reported, not sent');
  CheckEquals(Ord(AAlert), Ord(AEngine.LastError.Alert.Description), AMessage + ': the alert');
end;

function TTestClientHelloPause.ContinueRaisesArgument(const AEngine: ITls13HandshakeEngine;
  const AReplies: TArray<TTlsHostExtensionReply>; const AScope: TBytes): Boolean;
begin
  Result := False;
  try
    AEngine.ContinueAfterClientHello(AReplies, AScope);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestClientHelloPause.EchConfigList(AConfigId: Byte; const APublicName: string;
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

function TTestClientHelloPause.SecondHello(const AClientExts,
  AServerExts: TArray<ITlsHostExtension>; const AReplies: TArray<TTlsHostExtensionReply>;
  out AClient, AServer: ITls13HandshakeEngine): TBytes;
begin
  AClient := NewClient(ClientConfig(True), AClientExts);
  AServer := NewServer(ServerConfig(True), AServerExts, True);
  Park(AClient, AServer);
  AServer.ContinueAfterClientHello(AReplies, nil);
  Deliver(AServer, AClient, 's');
  Result := TakeData(AClient);
  CheckTrue(System.Length(Result) > 0, 'the client sent its second ClientHello');
end;

function TTestClientHelloPause.Connect(const ACache: ISessionCache;
  const ASetup: TServerSetup): ITls13HandshakeEngine;
var
  LServer: ITls13HandshakeEngine;
begin
  Result := NewClient(ClientResuming(ACache, False), nil);
  LServer := TTlsEngineFactory.CreateTls13HandshakeServerEngine(
    ServerResuming(False, nil), nil, TicketLimit, nil, ASetup.Creation, ASetup.Pause);
  if ASetup.Pause then
  begin
    Park(Result, LServer);
    LServer.ContinueAfterClientHello(nil, ASetup.Continuation);
  end
  else
    Result.StartHandshake;
  Exchange(Result, LServer);
  CheckFalse(Result.IsTerminal, 'the handshake completed');
end;

function TTestClientHelloPause.ResumesAfter(const ASeal, AAccept: TServerSetup): Boolean;
var
  LCache: ISessionCache;
begin
  LCache := TInMemorySessionCache.Create;
  Connect(LCache, ASeal);
  CheckEquals(1, LCache.Count, 'a ticket was cached');
  Result := Connect(LCache, AAccept).ConnectionInfo.Resumed;
end;

function TTestClientHelloPause.ReplayAcceptsEarlyData(AFirstContinues: Boolean): Boolean;
var
  LCache: ISessionCache;
  LClient, LFirst, LSecond: ITls13HandshakeEngine;
  LClock: TMockClock;
  LClockRef: ITlsClock;
  LConfig: ITlsServerConfig;
  LHello: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  LClock := TMockClock.Create(UInt64(TSystemTimeUtilities.UtcUnixMs));
  LClockRef := LClock as ITlsClock;
  LConfig := ServerResuming(True, LClockRef);
  Run(NewClient(ClientResuming(LCache, False), nil), NewServer(LConfig, nil, False));
  CheckEquals(1, LCache.Count, 'a ticket was cached');
  LClient := NewClient(ClientResuming(LCache, True), nil);
  LClient.StartHandshake;
  LHello := TakeData(LClient);
  LFirst := NewServer(LConfig, nil, True);
  LFirst.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckTrue(LFirst.AwaitingClientHello, 'the first server parked');
  if AFirstContinues then
  begin
    LFirst.ContinueAfterClientHello(nil, nil);
    CheckTrue(HasEarlyReadSecret(LFirst), 'the first server accepted the early data');
  end
  else
    LFirst.LatchTransportFailure('the host refused the connection');
  LSecond := NewServer(LConfig, nil, True);
  LSecond.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  LSecond.ContinueAfterClientHello(nil, nil);
  Result := HasEarlyReadSecret(LSecond);
end;

function TTestClientHelloPause.EarlyDataClient(
  const AConfig: ITlsServerConfig): ITls13HandshakeEngine;
var
  LCache: ISessionCache;
begin
  LCache := TInMemorySessionCache.Create;
  Run(NewClient(ClientResuming(LCache, False), nil), NewServer(AConfig, nil, False));
  CheckEquals(1, LCache.Count, 'a ticket was cached');
  Result := NewClient(ClientResuming(LCache, True), nil);
end;

function TTestClientHelloPause.ReceivedWithTrailingByte(APause: Boolean): ITls13HandshakeEngine;
var
  LClient: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LClient := NewClient(ClientConfig(False), nil);
  Result := NewServer(ServerConfig(False), nil, APause);
  LClient.StartHandshake;
  LHello := ConcatBytes(TakeData(LClient), TBytes.Create(8));
  Result.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  Result.ContinueAfterClientHello(nil, nil);
end;

procedure TTestClientHelloPause.ReenterTheEngine;
begin
  try
    FReentrantServer.ContinueAfterClientHello(nil, nil);
  except
    on EInvalidOperationTlsLibException do
      FReentryRaised := True;
  end;
end;

procedure TTestClientHelloPause.TestParkReturnsAdvancedAndRaisesTheEvent;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  LClient.StartHandshake;
  LHello := TakeData(LClient);
  CheckEquals(Ord(TTlsOutcome.Advanced),
    Ord(LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello))),
    'parking is progress, not a wait for input');
  CheckEquals(1, EventCount(LServer, TTlsEventKind.ClientHelloReceived), 'one event says so');
end;

procedure TTestClientHelloPause.TestParkQueuesNothingAndKeepsHandshaking;
var
  LClient, LServer: ITls13HandshakeEngine;
  LOutput: TTls13HandshakeOutput;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  CheckFalse(LServer.NextOutput(LOutput), 'nothing is queued while parked');
  CheckTrue(LServer.IsHandshaking, 'the handshake is still going');
  CheckFalse(LServer.IsTerminal, 'and has not failed');
end;

procedure TTestClientHelloPause.TestOfferedServerNameIsWhatTheClientOffered;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  CheckEquals(ServerHost, LServer.OfferedServerName, 'the host name of the ClientHello');
end;

procedure TTestClientHelloPause.TestNothingIsOfferedOutsideThePark;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  CheckEquals('', LServer.OfferedServerName, 'before the ClientHello');
  Park(LClient, LServer);
  LServer.ContinueAfterClientHello(nil, nil);
  CheckEquals('', LServer.OfferedServerName, 'after the continue');
  CheckFalse(LServer.AwaitingClientHello, 'no longer parked');
end;

procedure TTestClientHelloPause.TestReplyChosenFromTheOfferedBodyIsSentInEncryptedExtensions;
var
  LClient, LServer: ITls13HandshakeEngine;
  LServerResults, LClientResults: ITlsHostExtensionResults;
  LOffered, LReply, LRead: TBytes;
begin
  LClient := NewClient(ClientConfig(False), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1c2c3'), [TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions],
    [TTlsExtensionContextKind.ClientHello], HostType)), True);
  Park(LClient, LServer);
  CheckTrue(Supports(LServer, ITlsHostExtensionResults, LServerResults), 'the server reads results');
  CheckTrue(LServerResults.TryGetPeerExtension(HostType, LOffered), 'the offer is readable');
  CheckEqualBytes('the offered body', DecodeHex('c1c2c3'), LOffered);
  LReply := ConcatBytes(LOffered, DecodeHex('ff'));
  LServer.ContinueAfterClientHello(TArray<TTlsHostExtensionReply>.Create(
    Reply(HostType, LReply)), nil);
  Exchange(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckTrue(Supports(LClient, ITlsHostExtensionResults, LClientResults), 'the client reads results');
  CheckTrue(LClientResults.TryGetPeerExtension(HostType, LRead), 'the client received the reply');
  CheckEqualBytes('the reply body', LReply, LRead);
end;

procedure TTestClientHelloPause.TestUnansweredOfferedExtensionIsNotSent;
var
  LClient, LServer: ITls13HandshakeEngine;
  LClientResults: ITlsHostExtensionResults;
  LRead: TBytes;
begin
  LClient := NewClient(ClientConfig(False), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1c2c3'), [])));
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), True);
  Park(LClient, LServer);
  LServer.ContinueAfterClientHello(nil, nil);
  Exchange(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckTrue(Supports(LClient, ITlsHostExtensionResults, LClientResults), 'the client reads results');
  CheckFalse(LClientResults.TryGetPeerExtension(HostType, LRead),
    'the registration body was not sent in its place');
end;

procedure TTestClientHelloPause.TestWithoutThePauseTheCreationBodyIsSent;
var
  LClient, LServer: ITls13HandshakeEngine;
  LClientResults: ITlsHostExtensionResults;
  LRead: TBytes;
begin
  LClient := NewClient(ClientConfig(False), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1c2c3'), [TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), False);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckTrue(Supports(LClient, ITlsHostExtensionResults, LClientResults), 'the client reads results');
  CheckTrue(LClientResults.TryGetPeerExtension(HostType, LRead), 'the extension was sent');
  CheckEqualBytes('with the body it was registered with', DecodeHex('00'), LRead);
end;

procedure TTestClientHelloPause.TestHandshakeShapeIsTheSameWithAnImmediateContinue;
var
  LClient, LServer: ITls13HandshakeEngine;
  LPlain, LPaused: string;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, False);
  FLog := '';
  Run(LClient, LServer);
  LPlain := FLog;
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  FLog := '';
  LClient.StartHandshake;
  Deliver(LClient, LServer, 'c');
  CheckTrue(LServer.AwaitingClientHello, 'the server parked');
  LServer.ContinueAfterClientHello(nil, nil);
  Exchange(LClient, LServer);
  LPaused := FLog;
  CheckFalse(LClient.IsTerminal, 'the paused handshake completed');
  CheckEquals(LPlain, LPaused, 'the same outputs in the same order at the same levels');
end;

procedure TTestClientHelloPause.TestHelloRetryRequestFollowsTheContinue;
var
  LClient, LServer: ITls13HandshakeEngine;
  LOutput: TTls13HandshakeOutput;
begin
  LClient := NewClient(ClientConfig(True), nil);
  LServer := NewServer(ServerConfig(True), nil, True);
  Park(LClient, LServer);
  CheckFalse(LServer.NextOutput(LOutput), 'no retry is sent while parked');
  LServer.ContinueAfterClientHello(nil, nil);
  Exchange(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckTrue(LServer.ConnectionInfo.HelloRetryRequest, 'the retry came after the continue');
end;

procedure TTestClientHelloPause.TestSecondClientHelloDoesNotPause;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LClient := NewClient(ClientConfig(True), nil);
  LServer := NewServer(ServerConfig(True), nil, True);
  Park(LClient, LServer);
  LServer.ContinueAfterClientHello(nil, nil);
  Deliver(LServer, LClient, 's');
  LHello := TakeData(LClient);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFalse(LServer.AwaitingClientHello, 'the retry ClientHello is answered, not parked on');
  CheckFalse(LServer.IsTerminal, 'and it was accepted');
  CheckEquals(1, EventCount(LServer, TTlsEventKind.ClientHelloReceived),
    'one pause for the whole handshake');
end;

procedure TTestClientHelloPause.TestHandshakeCompletesAcrossARetryWithTheChosenReply;
var
  LClient, LServer: ITls13HandshakeEngine;
  LClientResults: ITlsHostExtensionResults;
  LRead: TBytes;
begin
  LClient := NewClient(ClientConfig(True), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1c2c3'), [TTlsExtensionContextKind.HelloRetryRequest,
    TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := NewServer(ServerConfig(True), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.HelloRetryRequest,
    TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), True);
  Park(LClient, LServer);
  LServer.ContinueAfterClientHello(TArray<TTlsHostExtensionReply>.Create(
    Reply(HostType, DecodeHex('aabb'))), nil);
  Exchange(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.IsTerminal, 'the server completed');
  CheckTrue(Supports(LClient, ITlsHostExtensionResults, LClientResults), 'the client reads results');
  CheckTrue(LClientResults.TryGetPeerExtension(HostType, LRead), 'the reply arrived');
  CheckEqualBytes('as chosen, in the retry and after it', DecodeHex('aabb'), LRead);
end;

procedure TTestClientHelloPause.TestSecondClientHelloWithAChangedBodyFails;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LHello := SecondHello(TArray<ITlsHostExtension>.Create(ClientExt(DecodeHex('c1c2c3'), [])),
    TArray<ITlsHostExtension>.Create(ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [],
    HostType)), TArray<TTlsHostExtensionReply>.Create(Reply(HostType, DecodeHex('aa'))),
    LClient, LServer);
  LHello := Rewritten(LHello, HostType, DecodeHex('c1c2c4'), TRewrite.ChangeBody);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFailedWith(LServer, TTlsAlertDescription.IllegalParameter, 'a changed body');
end;

procedure TTestClientHelloPause.TestSecondClientHelloWithAnAddedTypeFails;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LHello := SecondHello(nil, TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), nil,
    LClient, LServer);
  LHello := Rewritten(LHello, HostType, DecodeHex('c1c2c3'), TRewrite.AddType);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFailedWith(LServer, TTlsAlertDescription.IllegalParameter, 'an added type');
end;

procedure TTestClientHelloPause.TestSecondClientHelloWithADroppedTypeFails;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LHello := SecondHello(TArray<ITlsHostExtension>.Create(ClientExt(DecodeHex('c1c2c3'), [])),
    TArray<ITlsHostExtension>.Create(ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [],
    HostType)), TArray<TTlsHostExtensionReply>.Create(Reply(HostType, DecodeHex('aa'))),
    LClient, LServer);
  LHello := Rewritten(LHello, HostType, nil, TRewrite.DropType);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFailedWith(LServer, TTlsAlertDescription.IllegalParameter, 'a dropped type');
end;

procedure TTestClientHelloPause.TestSecondClientHelloDroppingARequiredTypeIsIllegalParameter;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LHello := SecondHello(TArray<ITlsHostExtension>.Create(ClientExt(DecodeHex('c1c2c3'), [])),
    TArray<ITlsHostExtension>.Create(ServerExt([TTlsExtensionContextKind.EncryptedExtensions],
    [TTlsExtensionContextKind.ClientHello], HostType)),
    TArray<TTlsHostExtensionReply>.Create(Reply(HostType, DecodeHex('aa'))), LClient, LServer);
  LHello := Rewritten(LHello, HostType, nil, TRewrite.DropType);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFailedWith(LServer, TTlsAlertDescription.IllegalParameter,
    'the change, not the missing required type');
end;

procedure TTestClientHelloPause.TestTypeTheRetryCarriedMayChangeInTheSecondClientHello;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TBytes;
begin
  LHello := SecondHello(TArray<ITlsHostExtension>.Create(ClientExt(DecodeHex('c1c2c3'),
    [TTlsExtensionContextKind.HelloRetryRequest])),
    TArray<ITlsHostExtension>.Create(ServerExt([TTlsExtensionContextKind.HelloRetryRequest,
    TTlsExtensionContextKind.EncryptedExtensions], [], HostType)),
    TArray<TTlsHostExtensionReply>.Create(Reply(HostType, DecodeHex('aa'))), LClient, LServer);
  LHello := Rewritten(LHello, HostType, DecodeHex('c1c2c4'), TRewrite.ChangeBody);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFalse(LServer.IsTerminal, 'a type the retry carried may change');
  CheckTrue(System.Length(TakeData(LServer)) > 0, 'the server answered with its flight');
end;

procedure TTestClientHelloPause.TestEchAcceptedShowsTheInnerValues;
var
  LClient, LServer: ITls13HandshakeEngine;
  LList: TBytes;
  LSk: ISecretBuffer;
  LResults: ITlsHostExtensionResults;
  LBody: TBytes;
begin
  LList := EchConfigList($D7, 'cover.example', LSk);
  LClient := NewClient(ClientBuilder.Tls13.WithEch(TEchClientModes.Enable(LList)).Build,
    TArray<ITlsHostExtension>.Create(ClientExt(DecodeHex('c1c2c3'), [])));
  LServer := NewServer(ServerBuilder.Tls13.WithEchKeyStore(
    TInMemoryEchKeyStore.FromConfig(LList, LSk, Crypto)).Build,
    TArray<ITlsHostExtension>.Create(ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [],
    HostType)), True);
  Park(LClient, LServer);
  CheckEquals(ServerHost, LServer.OfferedServerName, 'the inner ClientHello''s name, not the public one');
  CheckTrue(Supports(LServer, ITlsHostExtensionResults, LResults), 'the server reads results');
  CheckTrue(LResults.TryGetPeerExtension(HostType, LBody), 'the inner offer is readable');
  CheckEqualBytes('the inner body', DecodeHex('c1c2c3'), LBody);
end;

procedure TTestClientHelloPause.TestEchRejectedShowsTheOuterServerName;
var
  LClient, LServer: ITls13HandshakeEngine;
  LClientList, LServerList: TBytes;
  LClientSk, LServerSk: ISecretBuffer;
  LBuilder: ITlsClientConfigBuilder;
begin
  // the server holds another config id, so it cannot decrypt the offer and serves the outer hello
  LClientList := EchConfigList($D8, 'cover.example', LClientSk);
  LServerList := EchConfigList($D9, 'cover.example', LServerSk);
  LBuilder := ClientBuilder;
  LBuilder.WithDangerousDisableServerNameCheck;
  LClient := NewClient(LBuilder.Tls13.WithEch(TEchClientModes.Enable(LClientList)).Build, nil);
  LServer := NewServer(ServerBuilder.Tls13.WithEchKeyStore(
    TInMemoryEchKeyStore.FromConfig(LServerList, LServerSk, Crypto)).Build, nil, True);
  Park(LClient, LServer);
  CheckEquals('cover.example', LServer.OfferedServerName, 'the outer ClientHello''s name');
end;

procedure TTestClientHelloPause.TestFailingValidationNeverPauses;
var
  LClient, LServer: ITls13HandshakeEngine;
  LHello: TTlsClientHello;
  LFramed: TBytes;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  LClient.StartHandshake;
  LFramed := TakeData(LClient);
  LHello := THandshakeMessages.DecodeClientHello(
    System.Copy(LFramed, 4, System.Length(LFramed) - 4));
  // a host that owns record protection has no use for a compatibility session id
  LHello.LegacySessionId := Filled($01, 32);
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LFramed, 0, System.Length(LFramed))),
    'the ClientHello failed validation');
  CheckFalse(LServer.AwaitingClientHello, 'so the server did not park');
  CheckEquals(0, EventCount(LServer, TTlsEventKind.ClientHelloReceived), 'and raised no event');
  CheckEquals(Ord(TTlsErrorOrigin.LocalWithoutAlert), Ord(LServer.LastError.Origin),
    'it ended the connection as without the pause');
end;

procedure TTestClientHelloPause.TestSelectionFailureAfterTheContinueIsInBand;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientBuilder.WithAlpnProtocols(
    TArray<TBytes>.Create(TEncoding.ASCII.GetBytes('http/1.1'))).Build, nil);
  LServer := NewServer(ServerBuilder.WithAlpnProtocols(
    TArray<TBytes>.Create(TEncoding.ASCII.GetBytes('h2'))).Build, nil, True);
  Park(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the offer is not judged while parked');
  LServer.ContinueAfterClientHello(nil, nil);
  CheckFailedWith(LServer, TTlsAlertDescription.NoApplicationProtocol, 'no common protocol');
end;

procedure TTestClientHelloPause.TestScopeSetAtContinueGovernsAcceptance;
begin
  CheckTrue(ResumesAfter(ServerAs(nil, TBytes.Create($0A), True), ServerAs(nil, TBytes.Create($0A), True)),
    'the same scope at the continue resumes');
  CheckFalse(ResumesAfter(ServerAs(nil, TBytes.Create($0A), True),
    ServerAs(nil, TBytes.Create($0B), True)), 'another scope at the continue does not');
end;

procedure TTestClientHelloPause.TestScopeSetAtContinueGovernsSealing;
begin
  CheckTrue(ResumesAfter(ServerAs(nil, TBytes.Create($0A), True),
    ServerAs(TBytes.Create($0A), nil, False)), 'a server created with the scope accepts the ticket');
  CheckFalse(ResumesAfter(ServerAs(nil, TBytes.Create($0A), True),
    ServerAs(TBytes.Create($0B), nil, False)), 'one created with another scope does not');
end;

procedure TTestClientHelloPause.TestEmptyScopeAtContinueKeepsTheCreationScope;
begin
  CheckTrue(ResumesAfter(ServerAs(TBytes.Create($0A), nil, False),
    ServerAs(TBytes.Create($0A), nil, True)), 'the creation scope stands');
end;

procedure TTestClientHelloPause.TestScopeAtContinueReplacesTheCreationScope;
begin
  CheckTrue(ResumesAfter(ServerAs(TBytes.Create($0A), TBytes.Create($0B), True),
    ServerAs(TBytes.Create($0B), nil, False)), 'the ticket carries the scope of the continue');
  CheckFalse(ResumesAfter(ServerAs(TBytes.Create($0A), TBytes.Create($0B), True),
    ServerAs(TBytes.Create($0A), nil, False)), 'and not that of the creation');
end;

procedure TTestClientHelloPause.TestPauseLongerThanTheFreshnessWindowStillAcceptsZeroRtt;
var
  LClient, LServer: ITls13HandshakeEngine;
  LClock: TMockClock;
  LClockRef: ITlsClock;
  LConfig: ITlsServerConfig;
begin
  LClock := TMockClock.Create(UInt64(TSystemTimeUtilities.UtcUnixMs));
  LClockRef := LClock as ITlsClock;
  LConfig := ServerResuming(True, LClockRef);
  LClient := EarlyDataClient(LConfig);
  LServer := NewServer(LConfig, nil, True);
  Park(LClient, LServer);
  // past the tolerated skew between the ages the two sides measure, inside the replay window
  LClock.Advance(61000);
  LServer.ContinueAfterClientHello(nil, nil);
  CheckTrue(HasEarlyReadSecret(LServer), 'the early data is judged as of the ClientHello');
end;

procedure TTestClientHelloPause.TestPauseOutlastingTheReplayWindowDeclinesZeroRtt;
var
  LClient, LServer: ITls13HandshakeEngine;
  LClock: TMockClock;
  LClockRef: ITlsClock;
  LConfig: ITlsServerConfig;
begin
  LClock := TMockClock.Create(UInt64(TSystemTimeUtilities.UtcUnixMs));
  LClockRef := LClock as ITlsClock;
  LConfig := ServerResuming(True, LClockRef);
  LClient := EarlyDataClient(LConfig);
  LServer := NewServer(LConfig, nil, True);
  Park(LClient, LServer);
  LClock.Advance(121000);
  LServer.ContinueAfterClientHello(nil, nil);
  CheckFalse(HasEarlyReadSecret(LServer), 'the strike would already have lapsed');
end;

procedure TTestClientHelloPause.TestPauseOutlastingTheReplayWindowStillResumes;
var
  LClient, LServer: ITls13HandshakeEngine;
  LClock: TMockClock;
  LClockRef: ITlsClock;
  LConfig: ITlsServerConfig;
begin
  LClock := TMockClock.Create(UInt64(TSystemTimeUtilities.UtcUnixMs));
  LClockRef := LClock as ITlsClock;
  LConfig := ServerResuming(True, LClockRef);
  LClient := EarlyDataClient(LConfig);
  LServer := NewServer(LConfig, nil, True);
  Park(LClient, LServer);
  LClock.Advance(121000);
  LServer.ContinueAfterClientHello(nil, nil);
  Exchange(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the resumption goes ahead without the early data');
end;

procedure TTestClientHelloPause.TestReplayContinuedAfterAnUnrelatedPruneIsRefused;
var
  LClient, LFirst, LSecond: ITls13HandshakeEngine;
  LClock: TMockClock;
  LClockRef: ITlsClock;
  LConfig: ITlsServerConfig;
  LHello, LUnrelated: TBytes;
  LNow: UInt64;
begin
  LClock := TMockClock.Create(UInt64(TSystemTimeUtilities.UtcUnixMs));
  LClockRef := LClock as ITlsClock;
  LConfig := ServerResuming(True, LClockRef);
  LClient := EarlyDataClient(LConfig);
  LClient.StartHandshake;
  LHello := TakeData(LClient);
  LFirst := NewServer(LConfig, nil, True);
  LFirst.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  LFirst.ContinueAfterClientHello(nil, nil);
  CheckTrue(HasEarlyReadSecret(LFirst), 'the first server accepted the early data');
  LSecond := NewServer(LConfig, nil, True);
  LSecond.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckTrue(LSecond.AwaitingClientHello, 'the replay parked');
  LClock.Advance(130000);
  LNow := LClock.NowUnixMillis;
  LUnrelated := Filled($E7, 32);
  CheckTrue(FAntiReplay.CheckAndRecord(LUnrelated, LNow, LNow + 1000), 'an unrelated value pruned');
  LSecond.ContinueAfterClientHello(nil, nil);
  CheckFalse(HasEarlyReadSecret(LSecond), 'the replay is not accepted once its strike lapsed');
end;

procedure TTestClientHelloPause.TestRefusedParkedConnectionLeavesTheAntiReplaySlotUnused;
begin
  CheckTrue(ReplayAcceptsEarlyData(False), 'the refused connection used no slot');
end;

procedure TTestClientHelloPause.TestContinuedConnectionIsAReplayForAnotherEngine;
begin
  CheckFalse(ReplayAcceptsEarlyData(True), 'a continued connection used its slot');
end;

procedure TTestClientHelloPause.TestReplyForAnExtensionTheClientDidNotOfferIsRefused;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  CheckTrue(ContinueRaisesArgument(LServer, TArray<TTlsHostExtensionReply>.Create(
    Reply(UnknownType, DecodeHex('aa'))), nil), 'an unregistered extension');
end;

procedure TTestClientHelloPause.TestReplyForARegisteredExtensionTheClientDidNotOfferIsRefused;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], OtherType)), True);
  Park(LClient, LServer);
  CheckTrue(ContinueRaisesArgument(LServer, TArray<TTlsHostExtensionReply>.Create(
    Reply(OtherType, DecodeHex('aa'))), nil), 'a registered extension the client left out');
end;

procedure TTestClientHelloPause.TestTwoRepliesForOneExtensionAreRefused;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1'), [])));
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), True);
  Park(LClient, LServer);
  CheckTrue(ContinueRaisesArgument(LServer, TArray<TTlsHostExtensionReply>.Create(
    Reply(HostType, DecodeHex('aa')), Reply(HostType, DecodeHex('bb'))), nil), 'two replies');
end;

procedure TTestClientHelloPause.TestReplyBodyOverTheLimitIsRefused;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1'), [])));
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), True);
  Park(LClient, LServer);
  CheckTrue(ContinueRaisesArgument(LServer, TArray<TTlsHostExtensionReply>.Create(
    Reply(HostType, Filled($01, 65536))), nil), 'a 65536-byte body');
end;

procedure TTestClientHelloPause.TestReplyBodyAtTheLimitIsNotRefused;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1'), [])));
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), True);
  Park(LClient, LServer);
  CheckFalse(ContinueRaisesArgument(LServer, TArray<TTlsHostExtensionReply>.Create(
    Reply(HostType, Filled($01, 65535))), nil), 'a 65535-byte body');
end;

procedure TTestClientHelloPause.TestScopeOverTheLimitIsRefusedAtContinue;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  CheckTrue(ContinueRaisesArgument(LServer, nil, Filled($0A, 33)), 'a 33-byte scope');
end;

procedure TTestClientHelloPause.TestScopeAtTheLimitIsNotRefusedAtContinue;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  CheckFalse(ContinueRaisesArgument(LServer, nil, Filled($0A, 32)), 'a 32-byte scope');
  CheckFalse(LServer.AwaitingClientHello, 'and the engine went on');
end;

procedure TTestClientHelloPause.TestEngineStaysParkedAfterAMisuse;
var
  LClient, LServer: ITls13HandshakeEngine;
  LOutput: TTls13HandshakeOutput;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  CheckTrue(ContinueRaisesArgument(LServer, nil, Filled($0A, 33)), 'the misuse raised');
  CheckTrue(LServer.AwaitingClientHello, 'the engine is still parked');
  CheckFalse(LServer.IsTerminal, 'and usable');
  CheckFalse(LServer.NextOutput(LOutput), 'it queued nothing');
end;

procedure TTestClientHelloPause.TestValidContinueSucceedsAfterAMisuse;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), TArray<ITlsHostExtension>.Create(
    ClientExt(DecodeHex('c1'), [TTlsExtensionContextKind.EncryptedExtensions])));
  LServer := NewServer(ServerConfig(False), TArray<ITlsHostExtension>.Create(
    ServerExt([TTlsExtensionContextKind.EncryptedExtensions], [], HostType)), True);
  Park(LClient, LServer);
  CheckTrue(ContinueRaisesArgument(LServer, TArray<TTlsHostExtensionReply>.Create(
    Reply(HostType, DecodeHex('aa')), Reply(UnknownType, DecodeHex('bb'))), nil), 'the misuse raised');
  LServer.ContinueAfterClientHello(TArray<TTlsHostExtensionReply>.Create(
    Reply(HostType, DecodeHex('aa'))), nil);
  Exchange(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.IsTerminal, 'the server completed');
end;

procedure TTestClientHelloPause.TestContinueBeforeAnyClientHelloIsANoOp;
var
  LServer: ITls13HandshakeEngine;
begin
  LServer := NewServer(ServerConfig(False), nil, True);
  LServer.ContinueAfterClientHello(TArray<TTlsHostExtensionReply>.Create(
    Reply(UnknownType, DecodeHex('aa'))), Filled($0A, 33));
  CheckFalse(LServer.IsTerminal, 'nothing happened');
  CheckFalse(LServer.AwaitingClientHello, 'and nothing is parked');
end;

procedure TTestClientHelloPause.TestContinueOnAClientIsANoOp;
var
  LClient: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LClient.StartHandshake;
  CheckFalse(LClient.AwaitingClientHello, 'a client never awaits a ClientHello');
  CheckEquals('', LClient.OfferedServerName, 'and offers no name');
  LClient.ContinueAfterClientHello(nil, nil);
  CheckFalse(LClient.IsTerminal, 'the call changed nothing');
end;

procedure TTestClientHelloPause.TestContinueOnAServerWithoutThePauseIsANoOp;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, False);
  LClient.StartHandshake;
  Deliver(LClient, LServer, 'c');
  CheckFalse(LServer.AwaitingClientHello, 'it answered at once');
  LServer.ContinueAfterClientHello(nil, nil);
  Exchange(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the call changed nothing');
  CheckFalse(LClient.IsTerminal, 'and the handshake completed');
end;

procedure TTestClientHelloPause.TestSecondContinueIsANoOp;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  LServer.ContinueAfterClientHello(nil, nil);
  LServer.ContinueAfterClientHello(nil, Filled($0A, 33));
  Exchange(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the second call changed nothing');
  CheckFalse(LClient.IsTerminal, 'and the handshake completed');
end;

procedure TTestClientHelloPause.TestContinueFromAResolverRaises;
var
  LClient: ITls13HandshakeEngine;
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredentialResolver(
    TCallbackCredentialResolver.Create(ServerCredential, ReenterTheEngine)
    as ITlsServerCredentialResolver).Build;
  LClient := NewClient(ClientConfig(False), nil);
  FReentrantServer := NewServer(LConfig, nil, True);
  Park(LClient, FReentrantServer);
  FReentrantServer.ContinueAfterClientHello(nil, nil);
  CheckTrue(FReentryRaised, 'a call from inside the resolver raised');
  FReentrantServer := nil;
end;

procedure TTestClientHelloPause.TestLatchTransportFailureWhileParkedEndsTheEngine;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  LServer.LatchTransportFailure('the host refused the connection');
  CheckTrue(LServer.IsTerminal, 'the engine ended');
  CheckEquals(Ord(TTlsErrorOrigin.Transport), Ord(LServer.LastError.Origin), 'as a transport failure');
  CheckFalse(LServer.AwaitingClientHello, 'it no longer waits');
  LServer.ContinueAfterClientHello(nil, nil);
  CheckTrue(LServer.IsTerminal, 'a continue changes nothing');
end;

procedure TTestClientHelloPause.TestDestroyingAParkedEngineIsClean;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  CheckTrue(LServer.IsHandshaking, 'the engine is parked');
  // the parked extension context is released with the engine
  LServer := nil;
end;

procedure TTestClientHelloPause.TestContinuingFreesTheParkedState;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  Park(LClient, LServer);
  LServer.ContinueAfterClientHello(nil, nil);
  Exchange(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the handshake completed');
  // the context the park held was released at the continue, and the destruction frees nothing more
  LServer := nil;
end;

procedure TTestClientHelloPause.TestClientHelloWithTrailingBytesFailsAsWithoutThePause;
var
  LPlain, LPaused: ITls13HandshakeEngine;
begin
  LPlain := ReceivedWithTrailingByte(False);
  LPaused := ReceivedWithTrailingByte(True);
  CheckFailedWith(LPlain, TTlsAlertDescription.UnexpectedMessage, 'without the pause');
  CheckFailedWith(LPaused, TTlsAlertDescription.UnexpectedMessage, 'with the pause');
  CheckEquals(Ord(TTlsErrorCause.DataAfterReadLevelChange), Ord(LPlain.LastError.Cause),
    'the cause without the pause');
  CheckEquals(Ord(LPlain.LastError.Cause), Ord(LPaused.LastError.Cause), 'the same cause');
end;

procedure TTestClientHelloPause.TestInputWhileParkedIsBufferedUntilTheContinue;
var
  LClient, LServer: ITls13HandshakeEngine;
  LOutput: TTls13HandshakeOutput;
  LHello: TBytes;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, True);
  LClient.StartHandshake;
  LHello := TakeData(LClient);
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckTrue(LServer.AwaitingClientHello, 'the server parked');
  // a whole message, which the machine would judge at once if it were delivered
  LServer.ProvideHandshakeData(TTlsEpoch.Plaintext, LHello, 0, System.Length(LHello));
  CheckFalse(LServer.IsTerminal, 'input is held, not judged');
  CheckFalse(LServer.NextOutput(LOutput), 'and nothing was produced');
  LServer.ContinueAfterClientHello(nil, nil);
  CheckTrue(LServer.IsTerminal, 'the held message past the flight ends the handshake at the continue');
end;

procedure TTestClientHelloPause.TestEngineWithoutThePauseNeverParks;
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ClientConfig(False), nil);
  LServer := NewServer(ServerConfig(False), nil, False);
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.AwaitingClientHello, 'the server never awaited');
  CheckEquals(0, EventCount(LServer, TTlsEventKind.ClientHelloReceived), 'and raised no event');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestClientHelloPause);
{$ELSE}
  RegisterTest(TTestClientHelloPause.Suite);
{$ENDIF FPC}

end.
