{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ResumptionPartitionTests;

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
  TlpIKeySchedule,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpTicketBinding,
  TlpISession,
  TlpSession,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpClientSessionPolicy,
  TlpInMemorySessionCache,
  TlpSessionTicketKeys,
  TlpSystemTimeUtilities,
  TlpCertificateVerifierSource,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITls13HandshakeEngine,
  TlpITlsResumptionPartition,
  TlpTls13HandshakeOutput,
  SupportCertificates,
  TlsLibHandshakeTestBase;

type
  /// <summary>
  /// The per-engine resumption partition of a TLS 1.3 handshake-only client: a ticket is offered
  /// from the partition the engine was created with and stored under the partition current when it
  /// arrives, each stored ticket remembers its key for the withdrawal on a fatal failure, and
  /// the partition key cannot collide with the scope or the engine kind.
  /// </summary>
  TTestResumptionPartition = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
    TicketLimit = UInt32($FFFFFFFF);
  var
    FStek: ISessionTicketKeyManager;
    FScope: TBytes;
    function ClientConfig(const ACache: ISessionCache): ITlsClientConfig;
    function ServerConfig: ITlsServerConfig;
    function NewClient(const ACache: ISessionCache;
      const APartition: TBytes): ITls13HandshakeEngine;
    function NewServer: ITls13HandshakeEngine;
    /// <summary>Moves everything ASrc has queued to ADst; returns how many items moved.</summary>
    function Deliver(const ASrc, ADst: ITls13HandshakeEngine): Int32;
    procedure Exchange(const AClient, AServer: ITls13HandshakeEngine);
    procedure Run(const AClient, AServer: ITls13HandshakeEngine);
    /// <summary>Runs a handshake up to the point where the server has queued its tickets and the
    /// client has not yet read them.</summary>
    procedure RunUntilTicketsAreQueued(const AClient, AServer: ITls13HandshakeEngine);
    function KeyOf(const APartition: TBytes): string;
    /// <summary>Whether the cache holds a ticket stored under APartition (the ticket is taken).</summary>
    function Holds(const ACache: ISessionCache; const APartition: TBytes): Boolean;
    /// <summary>Caches one ticket under APartition by running a handshake of a client created with it.</summary>
    procedure Seed(const ACache: ISessionCache; const APartition: TBytes);
    function TicketWithEarlyDataLimit(ALimit: UInt32): TBytes;
    function CreationRaises(const APartition: TBytes): Boolean;
    function SetRaises(const AClient: ITls13HandshakeEngine; const APartition: TBytes): Boolean;
    procedure SetPartition(const AClient: ITls13HandshakeEngine; const APartition: TBytes);
  protected
    procedure SetUp; override;
  published
    procedure TestTicketIsNotOfferedInAnotherPartition;
    procedure TestTicketIsResumedInItsOwnPartition;
    procedure TestEmptyPartitionStoresUnderThePlainKey;
    procedure TestEngineWithoutAPartitionStoresUnderThePlainKey;
    procedure TestTicketArrivingAfterASetIsStoredUnderTheNewPartition;
    procedure TestTicketArrivingAfterASetIsNotStoredUnderTheCreationPartition;
    procedure TestEngineCreatedWithTheNewPartitionResumesTheTicket;
    procedure TestOfferedTicketIsThatOfTheCreationPartition;
    procedure TestFatalFailureRemovesTheTicketUnderItsStoredKey;
    procedure TestFatalFailureRemovesTheTicketStoredUnderALaterPartition;
    procedure TestKeyExchangeHintIsKeptUnderTheCreationPartition;
    procedure TestCreationRefusesAPartitionOverTheLimit;
    procedure TestCreationAcceptsAPartitionAtTheLimit;
    procedure TestSetRefusesAPartitionOverTheLimit;
    procedure TestSetAcceptsAPartitionAtTheLimit;
    procedure TestRefusedSetKeepsTheCurrentPartition;
    procedure TestClientEngineAnswersTheResumptionPartition;
    procedure TestServerEngineDoesNotAnswerTheResumptionPartition;
    procedure TestEmptyPartitionKeyEqualsTheKeyWithoutOne;
    procedure TestPartitionsHaveKeysOfTheirOwn;
    procedure TestPartitionKeyDiffersFromTheSameBytesAsScope;
    procedure TestPartitionKeyDiffersFromTheEngineKind;
    procedure TestScopeAndPartitionSplitsDoNotCollide;
  end;

  /// <summary>
  /// The per-engine resumption scope of a TLS 1.3 handshake-only server: tickets are accepted and
  /// sealed under the configuration's scope combined with the engine's own, a combination no
  /// configuration scope can equal, so engines with different scopes, and configurations with
  /// different scopes, never resume each other's tickets.
  /// </summary>
  TTestServerResumptionScope = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
    TicketLimit = UInt32($FFFFFFFF);
  var
    FStek: ISessionTicketKeyManager;
    function ClientConfig(const ACache: ISessionCache; AMutual: Boolean): ITlsClientConfig;
    function ServerConfig(const AConfigScope: TBytes): ITlsServerConfig;
    function MutualServerConfig(const AConfigScope: TBytes): ITlsServerConfig;
    function NewClient(const ACache: ISessionCache; AMutual: Boolean): ITls13HandshakeEngine;
    function NewServer(const AConfig: ITlsServerConfig;
      const AEngineScope: TBytes): ITls13HandshakeEngine;
    /// <summary>Moves everything ASrc has queued to ADst; returns how many items moved.</summary>
    function Deliver(const ASrc, ADst: ITls13HandshakeEngine): Int32;
    procedure Run(const AClient, AServer: ITls13HandshakeEngine);
    /// <summary>Whether a ticket a server of ASealingConfig and ASealingScope issued is resumed by
    /// a server of AAcceptingConfig and AAcceptingScope: a client caches the first server's ticket,
    /// then connects to the second.</summary>
    function ResumesAcross(const ASealingConfig: ITlsServerConfig; const ASealingScope: TBytes;
      const AAcceptingConfig: ITlsServerConfig; const AAcceptingScope: TBytes;
      AMutual: Boolean): Boolean;
    function CreationRaises(const AEngineScope: TBytes): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestTicketIsNotAcceptedUnderAnotherEngineScope;
    procedure TestTicketIsAcceptedUnderItsOwnEngineScope;
    procedure TestTicketWithoutAnEngineScopeIsNotAcceptedUnderOne;
    procedure TestTicketUnderAnEngineScopeIsNotAcceptedWithout;
    procedure TestEmptyEngineScopeKeepsTheConfigurationScope;
    procedure TestEngineScopeKeepsTheConfigurationScopeApart;
    procedure TestNaivelyConcatenatedScopesDoNotCollide;
    procedure TestMutualConfigurationsWithDifferentScopesNeverResumeUnderOneEngineScope;
    procedure TestConfigurationsWithTheSameScopeResumeUnderOneEngineScope;
    procedure TestCreationRefusesAnEngineScopeOverTheLimit;
    procedure TestCreationAcceptsAnEngineScopeAtTheLimit;
    procedure TestCombinedScopeHasTheDocumentedShape;
    procedure TestCombinedScopeStaysInsideTheTicketScopeLimit;
  end;

implementation

{ TTestResumptionPartition }

procedure TTestResumptionPartition.SetUp;
begin
  inherited SetUp;
  FStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager;
  FScope := Filled($5C, 16);
end;

function TTestResumptionPartition.ClientConfig(const ACache: ISessionCache): ITlsClientConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(TSupportCertificates.EcP256RootStore).Build)
    .WithResumption(True).WithSessionCache(ACache).WithResumptionScope(FScope).Build;
end;

function TTestResumptionPartition.ServerConfig: ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .WithResumption(True).WithSessionTicketKeys(FStek);
  LBuilder.Tls13.WithTicketCount(1);
  Result := LBuilder.Build;
end;

function TTestResumptionPartition.NewClient(const ACache: ISessionCache;
  const APartition: TBytes): ITls13HandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateTls13HandshakeClientEngine(ClientConfig(ACache), ServerHost,
    nil, TicketLimit, APartition);
end;

function TTestResumptionPartition.NewServer: ITls13HandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateTls13HandshakeServerEngine(ServerConfig, nil, TicketLimit, nil);
end;

function TTestResumptionPartition.Deliver(const ASrc, ADst: ITls13HandshakeEngine): Int32;
var
  LOutput: TTls13HandshakeOutput;
begin
  Result := 0;
  while ASrc.NextOutput(LOutput) do
  begin
    Inc(Result);
    if LOutput.Kind = TTls13HandshakeOutputKind.HandshakeData then
      ADst.ProvideHandshakeData(LOutput.Level, LOutput.Data, 0, System.Length(LOutput.Data));
  end;
end;

procedure TTestResumptionPartition.Exchange(const AClient, AServer: ITls13HandshakeEngine);
var
  LRound: Int32;
begin
  for LRound := 1 to 16 do
    if Deliver(AClient, AServer) + Deliver(AServer, AClient) = 0 then
      Break;
end;

procedure TTestResumptionPartition.Run(const AClient, AServer: ITls13HandshakeEngine);
begin
  AClient.StartHandshake;
  Exchange(AClient, AServer);
end;

procedure TTestResumptionPartition.RunUntilTicketsAreQueued(const AClient,
  AServer: ITls13HandshakeEngine);
begin
  AClient.StartHandshake;
  Deliver(AClient, AServer);
  Deliver(AServer, AClient);
  Deliver(AClient, AServer);
end;

function TTestResumptionPartition.KeyOf(const APartition: TBytes): string;
begin
  Result := TClientSessionPolicy.CacheIdentity(ServerHost, ServerHost, FScope, APartition,
    TTicketBinding.HandshakeEngine);
end;

function TTestResumptionPartition.Holds(const ACache: ISessionCache;
  const APartition: TBytes): Boolean;
var
  LSession: IResumableSession;
begin
  Result := ACache.Take(KeyOf(APartition), ServerHost, UInt64(TSystemTimeUtilities.UtcUnixMs),
    LSession);
end;

procedure TTestResumptionPartition.Seed(const ACache: ISessionCache; const APartition: TBytes);
var
  LClient, LServer: ITls13HandshakeEngine;
begin
  LClient := NewClient(ACache, APartition);
  LServer := NewServer;
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the seeding handshake did not fail');
end;

function TTestResumptionPartition.TicketWithEarlyDataLimit(ALimit: UInt32): TBytes;
var
  LNst: TTlsNewSessionTicket;
begin
  LNst.TicketLifetime := 3600;
  LNst.TicketAgeAdd := 0;
  LNst.TicketNonce := Filled($01, 8);
  LNst.Ticket := Filled($7A, 16);
  // an extension vector holding early_data (42) with max_early_data_size
  LNst.Extensions := TBytes.Create(0, 8, 0, 42, 0, 4, Byte(ALimit shr 24), Byte(ALimit shr 16),
    Byte(ALimit shr 8), Byte(ALimit));
  Result := THandshakeFraming.Frame(TTlsHandshakeType.NewSessionTicket,
    THandshakeMessages.EncodeNewSessionTicket(LNst));
end;

function TTestResumptionPartition.CreationRaises(const APartition: TBytes): Boolean;
var
  LCache: ISessionCache;
begin
  Result := False;
  LCache := TInMemorySessionCache.Create;
  try
    NewClient(LCache, APartition);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestResumptionPartition.SetRaises(const AClient: ITls13HandshakeEngine;
  const APartition: TBytes): Boolean;
begin
  Result := False;
  try
    SetPartition(AClient, APartition);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

procedure TTestResumptionPartition.SetPartition(const AClient: ITls13HandshakeEngine;
  const APartition: TBytes);
var
  LPartition: ITlsResumptionPartition;
begin
  CheckTrue(Supports(AClient, ITlsResumptionPartition, LPartition),
    'the client engine answers the partition interface');
  LPartition.SetResumptionPartition(APartition);
end;

procedure TTestResumptionPartition.TestTicketIsNotOfferedInAnotherPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, TBytes.Create($0A));
  LClient := NewClient(LCache, TBytes.Create($0B));
  LServer := NewServer;
  Run(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'it ran in full: the ticket is of another partition');
end;

procedure TTestResumptionPartition.TestTicketIsResumedInItsOwnPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, TBytes.Create($0A));
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  Run(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the client resumed its own partition''s ticket');
end;

procedure TTestResumptionPartition.TestEmptyPartitionStoresUnderThePlainKey;
var
  LCache: ISessionCache;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, nil);
  CheckTrue(Holds(LCache, nil), 'the ticket is under the key without a partition');
end;

procedure TTestResumptionPartition.TestEngineWithoutAPartitionStoresUnderThePlainKey;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := TTlsEngineFactory.CreateTls13HandshakeClientEngine(ClientConfig(LCache), ServerHost,
    nil, TicketLimit);
  LServer := NewServer;
  Run(LClient, LServer);
  CheckTrue(Holds(LCache, nil), 'the overload without a partition keeps the plain key');
end;

procedure TTestResumptionPartition.TestTicketArrivingAfterASetIsStoredUnderTheNewPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  RunUntilTicketsAreQueued(LClient, LServer);
  SetPartition(LClient, TBytes.Create($0B));
  Deliver(LServer, LClient);
  CheckTrue(Holds(LCache, TBytes.Create($0B)), 'the ticket is under the partition current on arrival');
end;

procedure TTestResumptionPartition.TestTicketArrivingAfterASetIsNotStoredUnderTheCreationPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  RunUntilTicketsAreQueued(LClient, LServer);
  SetPartition(LClient, TBytes.Create($0B));
  Deliver(LServer, LClient);
  CheckFalse(Holds(LCache, TBytes.Create($0A)), 'nothing is under the creation partition');
end;

procedure TTestResumptionPartition.TestEngineCreatedWithTheNewPartitionResumesTheTicket;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  RunUntilTicketsAreQueued(LClient, LServer);
  SetPartition(LClient, TBytes.Create($0B));
  Deliver(LServer, LClient);
  LClient := NewClient(LCache, TBytes.Create($0B));
  LServer := NewServer;
  Run(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'a later engine of the new partition resumes it');
end;

procedure TTestResumptionPartition.TestOfferedTicketIsThatOfTheCreationPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  Seed(LCache, TBytes.Create($0A));
  LClient := NewClient(LCache, TBytes.Create($0A));
  SetPartition(LClient, TBytes.Create($0B));
  LServer := NewServer;
  Run(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the offer follows the creation partition, not the set one');
end;

procedure TTestResumptionPartition.TestFatalFailureRemovesTheTicketUnderItsStoredKey;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
  LTicket: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  Run(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the ticket was cached');
  SetPartition(LClient, TBytes.Create($0B));
  // the host fixed the early-data limit, and this ticket carries another value
  LTicket := TicketWithEarlyDataLimit(1234);
  LClient.ProvideHandshakeData(TTlsEpoch.Application, LTicket, 0, System.Length(LTicket));
  CheckTrue(LClient.IsTerminal, 'the client failed');
  CheckEquals(0, LCache.Count, 'the failure withdrew the ticket it had stored');
end;

procedure TTestResumptionPartition.TestFatalFailureRemovesTheTicketStoredUnderALaterPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
  LTicket: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  RunUntilTicketsAreQueued(LClient, LServer);
  SetPartition(LClient, TBytes.Create($0B));
  Deliver(LServer, LClient);
  CheckEquals(1, LCache.Count, 'the ticket was cached');
  LTicket := TicketWithEarlyDataLimit(1234);
  LClient.ProvideHandshakeData(TTlsEpoch.Application, LTicket, 0, System.Length(LTicket));
  CheckTrue(LClient.IsTerminal, 'the client failed');
  CheckEquals(0, LCache.Count, 'the failure withdrew the ticket under the key it was stored with');
end;

procedure TTestResumptionPartition.TestKeyExchangeHintIsKeptUnderTheCreationPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  LClient.StartHandshake;
  SetPartition(LClient, TBytes.Create($0B));
  Exchange(LClient, LServer);
  CheckTrue(LCache.KxHint(KeyOf(TBytes.Create($0A)), ServerHost) <> 0,
    'the hint is under the creation partition');
  CheckEquals(0, Int32(LCache.KxHint(KeyOf(TBytes.Create($0B)), ServerHost)),
    'and none under the set one');
end;

procedure TTestResumptionPartition.TestCreationRefusesAPartitionOverTheLimit;
begin
  CheckTrue(CreationRaises(Filled($0A, 33)), 'a 33-byte partition');
end;

procedure TTestResumptionPartition.TestCreationAcceptsAPartitionAtTheLimit;
begin
  CheckFalse(CreationRaises(Filled($0A, 32)), 'a 32-byte partition');
end;

procedure TTestResumptionPartition.TestSetRefusesAPartitionOverTheLimit;
var
  LCache: ISessionCache;
begin
  LCache := TInMemorySessionCache.Create;
  CheckTrue(SetRaises(NewClient(LCache, nil), Filled($0A, 33)), 'a 33-byte partition');
end;

procedure TTestResumptionPartition.TestSetAcceptsAPartitionAtTheLimit;
var
  LCache: ISessionCache;
begin
  LCache := TInMemorySessionCache.Create;
  CheckFalse(SetRaises(NewClient(LCache, nil), Filled($0A, 32)), 'a 32-byte partition');
end;

procedure TTestResumptionPartition.TestRefusedSetKeepsTheCurrentPartition;
var
  LCache: ISessionCache;
  LClient, LServer: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, TBytes.Create($0A));
  LServer := NewServer;
  CheckTrue(SetRaises(LClient, Filled($0B, 33)), 'the partition was refused');
  Run(LClient, LServer);
  CheckTrue(Holds(LCache, TBytes.Create($0A)), 'tickets still go under the partition it kept');
end;

procedure TTestResumptionPartition.TestClientEngineAnswersTheResumptionPartition;
var
  LCache: ISessionCache;
  LPartition: ITlsResumptionPartition;
begin
  LCache := TInMemorySessionCache.Create;
  CheckTrue(Supports(NewClient(LCache, nil), ITlsResumptionPartition, LPartition),
    'a client engine answers it');
end;

procedure TTestResumptionPartition.TestServerEngineDoesNotAnswerTheResumptionPartition;
var
  LPartition: ITlsResumptionPartition;
begin
  CheckFalse(Supports(NewServer, ITlsResumptionPartition, LPartition),
    'a server engine does not');
end;

procedure TTestResumptionPartition.TestEmptyPartitionKeyEqualsTheKeyWithoutOne;
begin
  CheckEquals(TClientSessionPolicy.CacheIdentity('id', 'sni', FScope),
    TClientSessionPolicy.CacheIdentity('id', 'sni', FScope, nil, TTicketBinding.RecordEngine),
    'the record engine key');
  CheckEquals(TClientSessionPolicy.CacheIdentity('id', 'sni', FScope) + #30 + '1',
    TClientSessionPolicy.CacheIdentity('id', 'sni', FScope, nil, TTicketBinding.HandshakeEngine),
    'the handshake engine key');
end;

procedure TTestResumptionPartition.TestPartitionsHaveKeysOfTheirOwn;
begin
  CheckFalse(TClientSessionPolicy.CacheIdentity('id', 'sni', FScope, TBytes.Create($0A),
    TTicketBinding.HandshakeEngine) = TClientSessionPolicy.CacheIdentity('id', 'sni', FScope,
    TBytes.Create($0B), TTicketBinding.HandshakeEngine), 'two partitions');
  CheckFalse(TClientSessionPolicy.CacheIdentity('id', 'sni', FScope, TBytes.Create($0A),
    TTicketBinding.HandshakeEngine) = TClientSessionPolicy.CacheIdentity('id', 'sni', FScope, nil,
    TTicketBinding.HandshakeEngine), 'a partition and none');
end;

procedure TTestResumptionPartition.TestPartitionKeyDiffersFromTheSameBytesAsScope;
begin
  CheckFalse(TClientSessionPolicy.CacheIdentity('id', 'sni', TBytes.Create($0A), nil,
    TTicketBinding.HandshakeEngine) = TClientSessionPolicy.CacheIdentity('id', 'sni', nil,
    TBytes.Create($0A), TTicketBinding.HandshakeEngine), 'bytes as scope or as partition');
end;

procedure TTestResumptionPartition.TestPartitionKeyDiffersFromTheEngineKind;
begin
  CheckFalse(TClientSessionPolicy.CacheIdentity('id', 'sni', nil, TBytes.Create($01),
    TTicketBinding.RecordEngine) = TClientSessionPolicy.CacheIdentity('id', 'sni', nil, nil,
    TTicketBinding.HandshakeEngine), 'a partition or the engine kind');
end;

procedure TTestResumptionPartition.TestScopeAndPartitionSplitsDoNotCollide;
begin
  CheckFalse(TClientSessionPolicy.CacheIdentity('id', 'sni', TBytes.Create(1, 2),
    TBytes.Create(3), TTicketBinding.HandshakeEngine) =
    TClientSessionPolicy.CacheIdentity('id', 'sni', TBytes.Create(1),
    TBytes.Create(2, 3), TTicketBinding.HandshakeEngine), 'the same bytes split differently');
end;

{ TTestServerResumptionScope }

procedure TTestServerResumptionScope.SetUp;
begin
  inherited SetUp;
  FStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager;
end;

function TTestServerResumptionScope.ClientConfig(const ACache: ISessionCache;
  AMutual: Boolean): ITlsClientConfig;
var
  LBuilder: ITlsClientConfigBuilder;
  LRoot: TBytes;
  LCredential: TTlsCredential;
begin
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix).Client;
  if AMutual then
  begin
    LCredential := ClientAuthCredential(LRoot);
    LBuilder.WithServerVerification(TServerVerification.WebPki(LRoot).Build)
      .WithCredential(LCredential);
  end
  else
    LBuilder.WithServerVerification(
      TServerVerification.WebPki(TSupportCertificates.EcP256RootStore).Build);
  Result := LBuilder.WithResumption(True).WithSessionCache(ACache)
    .WithResumptionScope(Filled($5C, 16)).Build;
end;

function TTestServerResumptionScope.ServerConfig(const AConfigScope: TBytes): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .WithResumption(True).WithSessionTicketKeys(FStek);
  if System.Length(AConfigScope) > 0 then
    LBuilder.WithResumptionScope(AConfigScope);
  LBuilder.Tls13.WithTicketCount(1);
  Result := LBuilder.Build;
end;

function TTestServerResumptionScope.MutualServerConfig(
  const AConfigScope: TBytes): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
  LRoot: TBytes;
begin
  LBuilder := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ClientAuthCredential(LRoot)).WithResumption(True)
    .WithSessionTicketKeys(FStek).WithResumptionScope(AConfigScope)
    .WithClientVerification(TClientVerification.WebPki(LRoot).Build)
    .WithPeerAuth(TClientAuthMode.Required);
  LBuilder.Tls13.WithTicketCount(1);
  Result := LBuilder.Build;
end;

function TTestServerResumptionScope.NewClient(const ACache: ISessionCache;
  AMutual: Boolean): ITls13HandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateTls13HandshakeClientEngine(ClientConfig(ACache, AMutual),
    ServerHost, nil, TicketLimit);
end;

function TTestServerResumptionScope.NewServer(const AConfig: ITlsServerConfig;
  const AEngineScope: TBytes): ITls13HandshakeEngine;
begin
  Result := TTlsEngineFactory.CreateTls13HandshakeServerEngine(AConfig, nil, TicketLimit, nil,
    AEngineScope, False);
end;

function TTestServerResumptionScope.Deliver(const ASrc, ADst: ITls13HandshakeEngine): Int32;
var
  LOutput: TTls13HandshakeOutput;
begin
  Result := 0;
  while ASrc.NextOutput(LOutput) do
  begin
    Inc(Result);
    if LOutput.Kind = TTls13HandshakeOutputKind.HandshakeData then
      ADst.ProvideHandshakeData(LOutput.Level, LOutput.Data, 0, System.Length(LOutput.Data));
  end;
end;

procedure TTestServerResumptionScope.Run(const AClient, AServer: ITls13HandshakeEngine);
var
  LRound: Int32;
begin
  AClient.StartHandshake;
  for LRound := 1 to 16 do
    if Deliver(AClient, AServer) + Deliver(AServer, AClient) = 0 then
      Break;
end;

function TTestServerResumptionScope.ResumesAcross(const ASealingConfig: ITlsServerConfig;
  const ASealingScope: TBytes; const AAcceptingConfig: ITlsServerConfig;
  const AAcceptingScope: TBytes; AMutual: Boolean): Boolean;
var
  LCache: ISessionCache;
  LClient: ITls13HandshakeEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, AMutual);
  Run(LClient, NewServer(ASealingConfig, ASealingScope));
  CheckFalse(LClient.IsTerminal, 'the sealing handshake completed');
  CheckEquals(1, LCache.Count, 'a ticket was cached');
  LClient := NewClient(LCache, AMutual);
  Run(LClient, NewServer(AAcceptingConfig, AAcceptingScope));
  CheckFalse(LClient.IsTerminal, 'the second handshake completed');
  Result := LClient.ConnectionInfo.Resumed;
end;

function TTestServerResumptionScope.CreationRaises(const AEngineScope: TBytes): Boolean;
begin
  Result := False;
  try
    NewServer(ServerConfig(nil), AEngineScope);
  except
    on EArgumentTlsLibException do
      Result := True;
  end;
end;

procedure TTestServerResumptionScope.TestTicketIsNotAcceptedUnderAnotherEngineScope;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ServerConfig(nil);
  CheckFalse(ResumesAcross(LConfig, TBytes.Create($0A), LConfig, TBytes.Create($0B), False),
    'a ticket of scope A is refused under scope B');
end;

procedure TTestServerResumptionScope.TestTicketIsAcceptedUnderItsOwnEngineScope;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ServerConfig(nil);
  CheckTrue(ResumesAcross(LConfig, TBytes.Create($0A), LConfig, TBytes.Create($0A), False),
    'a ticket of scope A is accepted under scope A');
end;

procedure TTestServerResumptionScope.TestTicketWithoutAnEngineScopeIsNotAcceptedUnderOne;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ServerConfig(nil);
  CheckFalse(ResumesAcross(LConfig, nil, LConfig, TBytes.Create($0A), False),
    'an unscoped ticket is refused under a scope');
end;

procedure TTestServerResumptionScope.TestTicketUnderAnEngineScopeIsNotAcceptedWithout;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ServerConfig(nil);
  CheckFalse(ResumesAcross(LConfig, TBytes.Create($0A), LConfig, nil, False),
    'a scoped ticket is refused without one');
end;

procedure TTestServerResumptionScope.TestEmptyEngineScopeKeepsTheConfigurationScope;
var
  LConfig: ITlsServerConfig;
  LCache: ISessionCache;
  LClient: ITls13HandshakeEngine;
begin
  LConfig := ServerConfig(Filled($5C, 16));
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, False);
  // the overload without an engine scope seals under the configuration's scope alone
  Run(LClient, TTlsEngineFactory.CreateTls13HandshakeServerEngine(LConfig, nil, TicketLimit, nil));
  LClient := NewClient(LCache, False);
  Run(LClient, NewServer(LConfig, nil));
  CheckTrue(LClient.ConnectionInfo.Resumed, 'an empty engine scope is the plain configuration scope');
end;

procedure TTestServerResumptionScope.TestEngineScopeKeepsTheConfigurationScopeApart;
begin
  CheckFalse(ResumesAcross(ServerConfig(TBytes.Create($01)), TBytes.Create($0A),
    ServerConfig(TBytes.Create($02)), TBytes.Create($0A), False),
    'one engine scope under two configuration scopes');
end;

procedure TTestServerResumptionScope.TestNaivelyConcatenatedScopesDoNotCollide;
var
  LPlain, LCombined: ITlsServerConfig;
begin
  // length-prefixed bytes 01 61 01 62 are what 61 and 62 would give if they were simply joined
  LPlain := ServerConfig(TBytes.Create($01, $61, $01, $62));
  LCombined := ServerConfig(TBytes.Create($61));
  CheckFalse(ResumesAcross(LPlain, nil, LCombined, TBytes.Create($62), False),
    'a plain scope is refused by the combination it imitates');
  CheckFalse(ResumesAcross(LCombined, TBytes.Create($62), LPlain, nil, False),
    'and the combination by the plain scope');
end;

procedure TTestServerResumptionScope.TestMutualConfigurationsWithDifferentScopesNeverResumeUnderOneEngineScope;
begin
  CheckFalse(ResumesAcross(MutualServerConfig(TBytes.Create($01)), TBytes.Create($0A),
    MutualServerConfig(TBytes.Create($02)), TBytes.Create($0A), True),
    'two client-authenticating configurations of different scopes sharing a ticket key');
end;

procedure TTestServerResumptionScope.TestConfigurationsWithTheSameScopeResumeUnderOneEngineScope;
begin
  CheckTrue(ResumesAcross(MutualServerConfig(TBytes.Create($01)), TBytes.Create($0A),
    MutualServerConfig(TBytes.Create($01)), TBytes.Create($0A), True),
    'the same client-authenticating configuration resumes');
end;

procedure TTestServerResumptionScope.TestCreationRefusesAnEngineScopeOverTheLimit;
begin
  CheckTrue(CreationRaises(Filled($0A, 33)), 'a 33-byte engine scope');
end;

procedure TTestServerResumptionScope.TestCreationAcceptsAnEngineScopeAtTheLimit;
begin
  CheckFalse(CreationRaises(Filled($0A, 32)), 'a 32-byte engine scope');
end;

procedure TTestServerResumptionScope.TestCombinedScopeHasTheDocumentedShape;
var
  LExpected, LCombined: TBytes;
begin
  LCombined := TSessionScope.Combine(TBytes.Create($61), TBytes.Create($62));
  LExpected := Filled($00, 35);
  LExpected[0] := 1;
  LExpected[1] := $61;
  LExpected[33] := 1;
  LExpected[34] := $62;
  CheckEqualBytes('length, scope padded to 32, length, engine scope', LExpected, LCombined);
  CheckEqualBytes('an empty engine scope leaves the scope alone', TBytes.Create($61),
    TSessionScope.Combine(TBytes.Create($61), nil));
end;

procedure TTestServerResumptionScope.TestCombinedScopeStaysInsideTheTicketScopeLimit;
var
  LLongest: Int32;
begin
  CheckEquals(35, System.Length(TSessionScope.Combine(nil, TBytes.Create($01))), 'the shortest');
  LLongest := System.Length(TSessionScope.Combine(Filled($01, 32), Filled($02, 32)));
  CheckEquals(66, LLongest, 'the longest');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestResumptionPartition);
  RegisterTest(TTestServerResumptionScope);
{$ELSE}
  RegisterTest(TTestResumptionPartition.Suite);
  RegisterTest(TTestServerResumptionScope.Suite);
{$ENDIF FPC}

end.
