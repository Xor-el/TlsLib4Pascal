{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ResumptionFeatureTests;

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
  TlpTlsLibExceptions,
  TlpClientSessionPolicy,
  TlpExtensionVector,
  TlpExtensionContext,
  TlpITlsHostExtension,
  TlpHostExtensions,
  TlpCoreExtensions,
  TlpTicketBinding,
  TlpISession,
  TlpSession,
  TlpISessionApplicationData,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlpSystemTimeUtilities,
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
  TlsLibTestTicketRewriter,
  TlsLibHandshakeTestBase;

type
  /// <summary>
  /// The early-data context, the session application data and the ticket's engine kind, driven
  /// through the factory over two engines: what a server seals into a ticket, what a client keeps
  /// with it, and how a ticket from another engine kind or an older format is treated.
  /// </summary>
  TTestResumptionFeatures = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
  var
    FStek: ISessionTicketKeyManager;
    FAntiReplay: IAntiReplayStrategy;
    FScope: TBytes;
    FEarly: TBytes;
    function CacheKey: string;
    function ClientConfig(const ACache: ISessionCache; AEarlyData: Boolean): ITlsClientConfig;
    function ServerConfig(const AContext: TBytes; const AStore: ISessionStore): ITlsServerConfig;
    function NewClient(const ACache: ISessionCache; AEarlyData: Boolean): ITlsEngine;
    function NewServer(const AContext: TBytes): ITlsEngine;
    function NewStoreServer(const AStore: ISessionStore): ITlsEngine;
    procedure Establish(const AClient, AServer: ITlsEngine);
    /// <summary>A seed connection through a store-backed server holding ASeedContext, then a 0-RTT
    /// resumption through a server over the same store holding AResumeContext.</summary>
    procedure ResumeThroughAStore(const ASeedContext, AResumeContext: TBytes;
      out AClient, AServer: ITlsEngine);
    /// <summary>A first connection that leaves a ticket in ACache, minted under AServerContext and
    /// carrying the application data AData when it is not empty.</summary>
    procedure Seed(const ACache: ISessionCache; const AServerContext, AData: TBytes);
    /// <summary>Resumes the cached ticket against a server holding AContext, the client writing
    /// early data.</summary>
    procedure ResumeWithEarlyData(const ACache: ISessionCache; const AContext: TBytes;
      out AClient, AServer: ITlsEngine);
    function TakeCached(const ACache: ISessionCache): ITls13ResumableSession;
    function Rebuilt(const ASession: ITls13ResumableSession; const ATicket: TBytes;
      ABinding: TTicketBinding): IResumableSession;
    function OtherEngineKind: TTicketBinding;
    function ClientData(const AEngine: ITlsEngine): ITlsSessionApplicationData;
    function ServerBuilderWithEarlyData: ITlsServerConfigBuilder;
  protected
    procedure SetUp; override;
  published
    procedure TestEarlyDataContextReachesTheFrozenConfig;
    procedure TestEarlyDataContextIsCopiedIntoTheBuilder;
    procedure TestEarlyDataContextOf255BytesIsAccepted;
    procedure TestEarlyDataContextBeyond255BytesIsRefused;
    procedure TestEarlyDataContextWithoutEarlyDataIsRefusedAtBuild;
    procedure TestEarlyDataWithoutResumptionIsRefusedAtBuild;
    procedure TestStoreServerAcceptsEarlyDataUnderTheSameContext;
    procedure TestStoreServerRefusesEarlyDataUnderAnotherContext;
    procedure TestMatchingContextAcceptsEarlyData;
    procedure TestMismatchedContextRefusesEarlyDataButResumes;
    procedure TestTicketWithoutAContextRefusesEarlyDataUnderAConfiguredOne;
    procedure TestTicketWithAContextRefusesEarlyDataWhenNoneIsConfigured;
    procedure TestUnconfiguredServerKeepsEarlyData;
    procedure TestSessionApplicationDataAttachesToReceivedTickets;
    procedure TestOfferedSessionApplicationDataIsTheTicketsBytes;
    procedure TestNoApplicationDataStaysEmpty;
    procedure TestApplicationDataSetAfterTheTicketLeavesItAlone;
    procedure TestApplicationDataIsCopiedWhenSet;
    procedure TestAResumedConnectionAttachesItsOwnApplicationData;
    procedure TestServerEngineDoesNotAnswerSessionApplicationData;
    procedure TestEngineKindsKeepTheirCachedTicketsApart;
    procedure TestClientDoesNotOfferATicketOfAnotherEngineKind;
    procedure TestClientOffersTheTicketItself;
    procedure TestPreSharedKeyStaysLastBesideAHostExtension;
    procedure TestServerDeclinesATicketOfAnotherEngineKind;
    procedure TestServerResumesATicketOfItsOwnEngineKind;
    procedure TestFormat11TicketDrawsAFullHandshake;
    procedure TestCurrentFormatTicketResumes;
  end;

implementation

{ TTestResumptionFeatures }

procedure TTestResumptionFeatures.SetUp;
begin
  inherited SetUp;
  FStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager;
  FAntiReplay := TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy;
  FScope := Filled($5C, 16);
  FEarly := DecodeHex('30525454206561726c792064617461');
end;

function TTestResumptionFeatures.CacheKey: string;
begin
  Result := TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope);
end;

function TTestResumptionFeatures.ClientConfig(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsClientConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumption(True).WithSessionCache(ACache).WithResumptionScope(FScope)
    .Tls13.WithEarlyData(AEarlyData).Build;
end;

function TTestResumptionFeatures.ServerBuilderWithEarlyData: ITlsServerConfigBuilder;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .WithResumption(True).WithSessionTicketKeys(FStek);
  Result.Tls13.WithEarlyData(16384).WithAntiReplay(FAntiReplay).WithTicketCount(2);
end;

function TTestResumptionFeatures.ServerConfig(const AContext: TBytes;
  const AStore: ISessionStore): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := ServerBuilderWithEarlyData;
  if AStore <> nil then
    LBuilder.WithSessionStore(AStore);
  if System.Length(AContext) > 0 then
    LBuilder.Tls13.WithEarlyDataContext(AContext);
  Result := LBuilder.Build;
end;

function TTestResumptionFeatures.NewClient(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateClientEngine(ClientConfig(ACache, AEarlyData), ServerHost);
end;

function TTestResumptionFeatures.NewServer(const AContext: TBytes): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateServerEngine(ServerConfig(AContext, nil));
end;

function TTestResumptionFeatures.NewStoreServer(const AStore: ISessionStore): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateServerEngine(ServerConfig(nil, AStore));
end;

procedure TTestResumptionFeatures.Establish(const AClient, AServer: ITlsEngine);
begin
  RunHandshake(AClient, AServer);
  // the server's NewSessionTickets follow its Finished
  Pump(AServer, AClient);
end;

function TTestResumptionFeatures.ClientData(
  const AEngine: ITlsEngine): ITlsSessionApplicationData;
begin
  CheckTrue(Supports(AEngine, ITlsSessionApplicationData, Result),
    'the engine class lists the session application data interface');
end;

procedure TTestResumptionFeatures.Seed(const ACache: ISessionCache;
  const AServerContext, AData: TBytes);
var
  LClient: ITlsEngine;
begin
  LClient := NewClient(ACache, False);
  if System.Length(AData) > 0 then
    ClientData(LClient).SetSessionApplicationData(AData);
  Establish(LClient, NewServer(AServerContext));
  CheckFalse(LClient.IsTerminal, 'the seeding handshake did not fail');
  CheckTrue(ACache.Count > 0, 'a ticket was cached');
end;

procedure TTestResumptionFeatures.ResumeWithEarlyData(const ACache: ISessionCache;
  const AContext: TBytes; out AClient, AServer: ITlsEngine);
begin
  AClient := NewClient(ACache, True);
  AServer := NewServer(AContext);
  AClient.StartHandshake;
  AClient.WriteEarlyData(FEarly, 0, System.Length(FEarly));
  ExchangeFlights(AClient, AServer);
  Pump(AServer, AClient);
end;

function TTestResumptionFeatures.TakeCached(
  const ACache: ISessionCache): ITls13ResumableSession;
var
  LSession: IResumableSession;
begin
  CheckTrue(ACache.Take(CacheKey, ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs),
    LSession), 'the ticket is cached');
  CheckTrue(Supports(LSession, ITls13ResumableSession, Result), 'it is a 1.3 session');
end;

function TTestResumptionFeatures.Rebuilt(const ASession: ITls13ResumableSession;
  const ATicket: TBytes; ABinding: TTicketBinding): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(ASession.CipherSuite, ASession.Hash,
    ASession.ResumptionSecret, ASession.Alpn, ASession.ServerName, ATicket,
    ASession.TicketLifetime, ASession.TicketAgeAdd, ASession.IssuedAtMillis,
    ASession.MaxEarlyData, ASession.PeerCertificates, ASession.ResumptionScope,
    ASession.PskIdentity, ASession.PskBinding, ASession.PeerSignatureScheme,
    ASession.AuthenticatedAtMillis, ASession.EarlyDataContext, ASession.ApplicationData,
    ABinding) as IResumableSession;
end;

function TTestResumptionFeatures.OtherEngineKind: TTicketBinding;
begin
  Result := TTicketBinding.HandshakeEngine;
end;

procedure TTestResumptionFeatures.TestEarlyDataContextReachesTheFrozenConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := ServerBuilderWithEarlyData;
  LBuilder.Tls13.WithEarlyDataContext(DecodeHex('c0ffee'));
  CheckEqualBytes('the frozen config carries the context', DecodeHex('c0ffee'),
    LBuilder.Build.EarlyDataContext);
  CheckEquals(0, System.Length(ServerBuilderWithEarlyData.Build.EarlyDataContext),
    'an unset context is empty');
end;

procedure TTestResumptionFeatures.TestEarlyDataContextIsCopiedIntoTheBuilder;
var
  LBuilder: ITlsServerConfigBuilder;
  LContext: TBytes;
begin
  LContext := DecodeHex('c0ffee');
  LBuilder := ServerBuilderWithEarlyData;
  LBuilder.Tls13.WithEarlyDataContext(LContext);
  LContext[0] := $00;
  CheckEqualBytes('a later change to the caller''s array does not reach the config',
    DecodeHex('c0ffee'), LBuilder.Build.EarlyDataContext);
end;

procedure TTestResumptionFeatures.TestEarlyDataContextOf255BytesIsAccepted;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := ServerBuilderWithEarlyData;
  LBuilder.Tls13.WithEarlyDataContext(Filled($C7, 255));
  CheckEquals(255, System.Length(LBuilder.Build.EarlyDataContext), 'the longest context builds');
end;

procedure TTestResumptionFeatures.TestEarlyDataContextBeyond255BytesIsRefused;
var
  LBuilder: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := ServerBuilderWithEarlyData;
  LRaised := False;
  try
    LBuilder.Tls13.WithEarlyDataContext(Filled($C7, 256));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a 256-byte context is refused');
end;

procedure TTestResumptionFeatures.TestEarlyDataContextWithoutEarlyDataIsRefusedAtBuild;
var
  LBuilder: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential);
  LBuilder.Tls13.WithEarlyDataContext(DecodeHex('c0ffee'));
  LRaised := False;
  try
    LBuilder.Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a context no 0-RTT consults is refused');
end;

procedure TTestResumptionFeatures.TestEarlyDataWithoutResumptionIsRefusedAtBuild;
var
  LBuilder: ITlsServerConfigBuilder;
  LRaised: Boolean;
begin
  LBuilder := ServerBuilderWithEarlyData.WithResumption(False);
  LRaised := False;
  try
    LBuilder.Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'early data with resumption off is refused');
end;

procedure TTestResumptionFeatures.ResumeThroughAStore(const ASeedContext, AResumeContext: TBytes;
  out AClient, AServer: ITlsEngine);
var
  LCache: ISessionCache;
  LStore: ISessionStore;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  AClient := NewClient(LCache, False);
  Establish(AClient, TTlsEngineFactory.CreateServerEngine(ServerConfig(ASeedContext, LStore)));
  CheckTrue(LCache.Count > 0, 'a ticket was cached');
  AClient := NewClient(LCache, True);
  AServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(AResumeContext, LStore));
  AClient.StartHandshake;
  AClient.WriteEarlyData(FEarly, 0, System.Length(FEarly));
  ExchangeFlights(AClient, AServer);
  Pump(AServer, AClient);
end;

procedure TTestResumptionFeatures.TestStoreServerAcceptsEarlyDataUnderTheSameContext;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeThroughAStore(DecodeHex('c0ffee'), DecodeHex('c0ffee'), LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the store server resumed');
  CheckTrue(LServer.ConnectionInfo.EarlyDataAccepted, 'and accepted 0-RTT');
end;

procedure TTestResumptionFeatures.TestStoreServerRefusesEarlyDataUnderAnotherContext;
var
  LClient, LServer: ITlsEngine;
begin
  ResumeThroughAStore(DecodeHex('c0ffee'), DecodeHex('c0ffef'), LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the store server still resumed');
  CheckEquals(Ord(TEarlyDataReason.ContextMismatch),
    Ord(LServer.ConnectionInfo.EarlyDataReason), 'but declined 0-RTT for the context');
end;

procedure TTestResumptionFeatures.TestMatchingContextAcceptsEarlyData;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, DecodeHex('c0ffee'), nil);
  ResumeWithEarlyData(LCache, DecodeHex('c0ffee'), LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed');
  CheckTrue(LServer.ConnectionInfo.EarlyDataAccepted, 'the server accepted 0-RTT');
  CheckEquals(Ord(TEarlyDataReason.Accepted), Ord(LServer.ConnectionInfo.EarlyDataReason),
    'the server''s reason');
  CheckEqualBytes('the early data arrives', FEarly, ReadAllEarly(LServer));
  CheckEquals(1, FAntiReplay.Count, 'the accepted offer was recorded');
end;

procedure TTestResumptionFeatures.TestMismatchedContextRefusesEarlyDataButResumes;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, DecodeHex('c0ffee'), nil);
  ResumeWithEarlyData(LCache, DecodeHex('c0ffef'), LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckFalse(LServer.IsHandshaking, 'the handshake completed');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the resumption itself succeeded on the server');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'and on the client');
  CheckFalse(LServer.ConnectionInfo.EarlyDataAccepted, 'the server refused 0-RTT');
  CheckEquals(Ord(TEarlyDataReason.ContextMismatch),
    Ord(LServer.ConnectionInfo.EarlyDataReason), 'for the context');
  CheckEquals(Ord(TEarlyDataReason.PeerDeclined), Ord(LClient.ConnectionInfo.EarlyDataReason),
    'which the client sees as a decline');
  CheckEquals(0, System.Length(ReadAllEarly(LServer)), 'no early data was delivered');
  CheckEquals(0, FAntiReplay.Count, 'the refused offer used no anti-replay slot');
end;

procedure TTestResumptionFeatures.TestTicketWithoutAContextRefusesEarlyDataUnderAConfiguredOne;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, nil);
  ResumeWithEarlyData(LCache, DecodeHex('c0ffee'), LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed');
  CheckEquals(Ord(TEarlyDataReason.ContextMismatch),
    Ord(LServer.ConnectionInfo.EarlyDataReason), 'an absent context is a mismatch');
  CheckEquals(0, System.Length(ReadAllEarly(LServer)), 'no early data was delivered');
end;

procedure TTestResumptionFeatures.TestTicketWithAContextRefusesEarlyDataWhenNoneIsConfigured;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, DecodeHex('c0ffee'), nil);
  ResumeWithEarlyData(LCache, nil, LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed');
  CheckEquals(Ord(TEarlyDataReason.ContextMismatch),
    Ord(LServer.ConnectionInfo.EarlyDataReason), 'a dropped context is a mismatch');
  CheckFalse(LServer.ConnectionInfo.EarlyDataAccepted, 'the server refused 0-RTT');
  CheckEquals(0, System.Length(ReadAllEarly(LServer)), 'no early data was delivered');
end;

procedure TTestResumptionFeatures.TestUnconfiguredServerKeepsEarlyData;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, nil);
  ResumeWithEarlyData(LCache, nil, LClient, LServer);
  CheckEquals(Ord(TEarlyDataReason.Accepted), Ord(LServer.ConnectionInfo.EarlyDataReason),
    'a server that never set a context accepts 0-RTT as before');
  CheckEqualBytes('the early data arrives', FEarly, ReadAllEarly(LServer));
end;

procedure TTestResumptionFeatures.TestSessionApplicationDataAttachesToReceivedTickets;
var
  LCache: ISessionCache;
  LSession: ITls13ResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, DecodeHex('a1a2a3'));
  CheckTrue(LCache.Count > 1, 'the server issued several tickets');
  repeat
    LSession := TakeCached(LCache);
    CheckEqualBytes('every ticket received carries the bytes', DecodeHex('a1a2a3'),
      LSession.ApplicationData);
  until LCache.Count = 0;
end;

procedure TTestResumptionFeatures.TestOfferedSessionApplicationDataIsTheTicketsBytes;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, DecodeHex('a1a2a3'));
  LClient := NewClient(LCache, False);
  CheckEquals(0, System.Length(ClientData(LClient).OfferedSessionApplicationData),
    'nothing is offered before the handshake starts');
  LClient.StartHandshake;
  CheckEqualBytes('right after StartHandshake the offered ticket''s bytes are available',
    DecodeHex('a1a2a3'), ClientData(LClient).OfferedSessionApplicationData);
end;

procedure TTestResumptionFeatures.TestNoApplicationDataStaysEmpty;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
  LSession: ITls13ResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LClient.StartHandshake;
  CheckEquals(0, System.Length(ClientData(LClient).OfferedSessionApplicationData),
    'no ticket offered, no bytes');
  LClient := NewClient(LCache, False);
  Establish(LClient, NewServer(nil));
  LSession := TakeCached(LCache);
  CheckEquals(0, System.Length(LSession.ApplicationData), 'a ticket carries none when none were set');
  LCache.Store(CacheKey, ServerHost, LSession as IResumableSession);
  LClient := NewClient(LCache, False);
  LClient.StartHandshake;
  CheckEquals(0, System.Length(ClientData(LClient).OfferedSessionApplicationData),
    'an offered ticket with none reports none');
end;

procedure TTestResumptionFeatures.TestApplicationDataSetAfterTheTicketLeavesItAlone;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
  LSession: ITls13ResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  Establish(LClient, NewServer(nil));
  ClientData(LClient).SetSessionApplicationData(DecodeHex('a1a2a3'));
  LSession := TakeCached(LCache);
  CheckEquals(0, System.Length(LSession.ApplicationData),
    'a ticket already received keeps what it had');
end;

procedure TTestResumptionFeatures.TestApplicationDataIsCopiedWhenSet;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
  LData: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  LData := DecodeHex('a1a2a3');
  ClientData(LClient).SetSessionApplicationData(LData);
  LData[0] := $00;
  Establish(LClient, NewServer(nil));
  CheckEqualBytes('a later change to the caller''s array does not reach the ticket',
    DecodeHex('a1a2a3'), TakeCached(LCache).ApplicationData);
end;

procedure TTestResumptionFeatures.TestAResumedConnectionAttachesItsOwnApplicationData;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, DecodeHex('a1a2a3'));
  LClient := NewClient(LCache, False);
  ClientData(LClient).SetSessionApplicationData(DecodeHex('b1b2'));
  Establish(LClient, NewServer(nil));
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the second connection resumed');
  CheckEqualBytes('its tickets carry the bytes set on it', DecodeHex('b1b2'),
    TakeCached(LCache).ApplicationData);
end;

procedure TTestResumptionFeatures.TestServerEngineDoesNotAnswerSessionApplicationData;
var
  LData: ITlsSessionApplicationData;
begin
  CheckFalse(Supports(NewServer(nil), ITlsSessionApplicationData, LData),
    'a server has no ticket to attach them to, so it does not claim the interface');
end;

procedure TTestResumptionFeatures.TestEngineKindsKeepTheirCachedTicketsApart;
begin
  CheckEquals(TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope),
    TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope,
    TTicketBinding.RecordEngine), 'the record engine keeps its key');
  CheckFalse(TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope) =
    TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope, OtherEngineKind),
    'another engine kind has a key of its own');
end;

procedure TTestResumptionFeatures.TestClientDoesNotOfferATicketOfAnotherEngineKind;
var
  LCache: ISessionCache;
  LSession: ITls13ResumableSession;
  LClient: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, DecodeHex('a1a2a3'));
  LSession := TakeCached(LCache);
  LCache.Store(CacheKey, ServerHost,
    Rebuilt(LSession, LSession.TicketIdentity, OtherEngineKind));
  LClient := NewClient(LCache, False);
  LClient.StartHandshake;
  CheckFalse(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(Drain(LClient)).Contains(
    TExtensionTypes.PreSharedKey), 'no pre_shared_key is offered');
  CheckEquals(0, System.Length(ClientData(LClient).OfferedSessionApplicationData),
    'and no offered bytes are reported');
end;

procedure TTestResumptionFeatures.TestClientOffersTheTicketItself;
var
  LCache: ISessionCache;
  LSession: ITls13ResumableSession;
  LClient: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, DecodeHex('a1a2a3'));
  LSession := TakeCached(LCache);
  LCache.Store(CacheKey, ServerHost,
    Rebuilt(LSession, LSession.TicketIdentity, LSession.TicketBinding));
  LClient := NewClient(LCache, False);
  LClient.StartHandshake;
  CheckTrue(TTlsLibTestHandshakeDecoder.ClientHelloExtensions(Drain(LClient)).Contains(
    TExtensionTypes.PreSharedKey), 'control: the rebuilt ticket of its own kind is offered');
end;

procedure TTestResumptionFeatures.TestPreSharedKeyStaysLastBesideAHostExtension;
var
  LCache: ISessionCache;
  LClient: ITlsEngine;
  LExtensions: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, nil);
  LClient := TTlsEngineFactory.CreateClientEngine(ClientConfig(LCache, False), ServerHost,
    TArray<ITlsHostExtension>.Create(TTlsHostExtensions.Make($FC01,
    [TTlsExtensionContextKind.ClientHello], DecodeHex('c1c2c3'), [])));
  LClient.StartHandshake;
  LExtensions := TTlsLibTestHandshakeDecoder.ClientHelloExtensions(Drain(LClient));
  CheckTrue(LExtensions.TryFind($FC01, LEntry), 'the host extension is offered');
  CheckTrue(LExtensions.Contains(TExtensionTypes.PreSharedKey), 'and so is the ticket');
  CheckTrue(LExtensions.IsLast(TExtensionTypes.PreSharedKey),
    'pre_shared_key stays the last extension (RFC 9846 4.3.11)');
end;

procedure TTestResumptionFeatures.TestServerDeclinesATicketOfAnotherEngineKind;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LSession, LStored: ITls13ResumableSession;
  LServerSession: IResumableSession;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LClient := NewClient(LCache, False);
  LServer := NewStoreServer(LStore);
  Establish(LClient, LServer);
  LSession := TakeCached(LCache);
  // the server's copy of the session, restamped as minted by another engine kind
  CheckTrue(LStore.Take(LSession.TicketIdentity, LServerSession), 'the server stored the session');
  CheckTrue(Supports(LServerSession, ITls13ResumableSession, LStored), 'it is a 1.3 session');
  LCache.Store(CacheKey, ServerHost, Rebuilt(LSession, LStore.Put(
    Rebuilt(LStored, nil, OtherEngineKind)), LSession.TicketBinding));
  LClient := NewClient(LCache, False);
  LServer := NewStoreServer(LStore);
  Establish(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckFalse(LServer.IsHandshaking, 'the handshake completed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'it ran in full, not as a resumption');
end;

procedure TTestResumptionFeatures.TestServerResumesATicketOfItsOwnEngineKind;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LSession, LStored: ITls13ResumableSession;
  LServerSession: IResumableSession;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LClient := NewClient(LCache, False);
  Establish(LClient, NewStoreServer(LStore));
  LSession := TakeCached(LCache);
  CheckTrue(LStore.Take(LSession.TicketIdentity, LServerSession), 'the server stored the session');
  CheckTrue(Supports(LServerSession, ITls13ResumableSession, LStored), 'it is a 1.3 session');
  LCache.Store(CacheKey, ServerHost, Rebuilt(LSession, LStore.Put(
    Rebuilt(LStored, nil, LStored.TicketBinding)), LSession.TicketBinding));
  LClient := NewClient(LCache, False);
  LServer := NewStoreServer(LStore);
  Establish(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed,
    'control: the same restamping with its own kind resumes');
end;

procedure TTestResumptionFeatures.TestFormat11TicketDrawsAFullHandshake;
var
  LCache: ISessionCache;
  LSession: ITls13ResumableSession;
  LPlain: TBytes;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, nil);
  LSession := TakeCached(LCache);
  LPlain := TTlsLibTestTicketRewriter.Plaintext(Crypto, FStek, LSession.TicketIdentity);
  CheckEquals(12, Integer(LPlain[3]), 'the ticket is the current format');
  // format 11 is format 12 without its tail (the empty context's length byte, the engine kind)
  LPlain[3] := 11;
  SetLength(LPlain, System.Length(LPlain) - 2);
  LCache.Store(CacheKey, ServerHost, Rebuilt(LSession,
    TTlsLibTestTicketRewriter.Resealed(Crypto, FStek, LSession.TicketIdentity, LPlain),
    LSession.TicketBinding));
  LClient := NewClient(LCache, False);
  LServer := NewServer(nil);
  Establish(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckFalse(LServer.IsHandshaking, 'the handshake completed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'it ran in full, not as a resumption');
end;

procedure TTestResumptionFeatures.TestCurrentFormatTicketResumes;
var
  LCache: ISessionCache;
  LSession: ITls13ResumableSession;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil, nil);
  LSession := TakeCached(LCache);
  LCache.Store(CacheKey, ServerHost, Rebuilt(LSession,
    TTlsLibTestTicketRewriter.Resealed(Crypto, FStek, LSession.TicketIdentity,
    TTlsLibTestTicketRewriter.Plaintext(Crypto, FStek, LSession.TicketIdentity)),
    LSession.TicketBinding));
  LClient := NewClient(LCache, False);
  LServer := NewServer(nil);
  Establish(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed,
    'control: the same resealing without the format change resumes');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestResumptionFeatures);
{$ELSE}
  RegisterTest(TTestResumptionFeatures.Suite);
{$ENDIF FPC}

end.
