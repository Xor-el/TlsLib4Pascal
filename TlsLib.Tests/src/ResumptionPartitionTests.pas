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

initialization

{$IFDEF FPC}
  RegisterTest(TTestResumptionPartition);
{$ELSE}
  RegisterTest(TTestResumptionPartition.Suite);
{$ENDIF FPC}

end.
