{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsStreamLoopbackTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  SyncObjs,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpAlpnProtocols,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpTlsContentType,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpHkdfLabel,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpIKeyLog,
  TlpKeyLog,
  TlpHandshakeMessages,
  TlpICryptoProvider,
  TlpTrustPolicy,
  TlpTlsConnectionInfo,
  TlpRecordHeader,
  TlpINegotiation,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlpTlsCredential,
  TlpITlsEngine,
  TlpITlsEngineInbound,
  TlpITlsEngineOutbound,
  TlpTlsError,
  TlpISession,
  TlpInMemorySessionCache,
  TlpTlsEngineFactory,
  TlpITlsTransport,
  TlpTlsStreamPump,
  TlpTlsLibExceptions,
  TlpIClock,
  TlpTlsConnection,
  TlpTlsStream,
  MockClock,
  MockKeyLog,
  MockTransport,
  MockVerifyHooks,
  MockCryptoProvider,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>What the loopback server thread does after its handshake.</summary>
  TServerBehavior = (
    EchoThenClose,     // echo one client message, then a clean close_notify
    TruncateAfterHandshake, // drop the transport with no close_notify (truncation)
    BulkEcho); // echo a fixed byte count back (heavy throughput), then a clean close_notify

  /// <summary>Runs the server side of a loopback on its own thread so the client (main
  /// thread) can block on a real duplex. Captures the negotiated info and any error.</summary>
  TServerRunner = class(TLoopbackServerThread)
  strict private
  var
    FBehavior: TServerBehavior;
    FError: string;
    FNegotiatedVersion: UInt16;
    FAlpn: TBytes;
    FExported: TBytes;
    FBulkBytes: Int32;
  protected
    procedure Execute; override;
  public
    constructor Create(const AStream: TTlsStream; const ATransport,
      AClientTransport: TMemoryTransport; ABehavior: TServerBehavior);
    property Error: string read FError;
    property NegotiatedVersion: UInt16 read FNegotiatedVersion;
    property Alpn: TBytes read FAlpn;
    // what the server's stream exported once its handshake finished
    property Exported: TBytes read FExported;
    // total bytes a BulkEcho server echoes back before closing
    property BulkBytes: Int32 read FBulkBytes write FBulkBytes;
  end;

  TTestTlsStreamLoopback = class(TTlsLibAlgorithmTestCase)
  strict private
    function ClientConfig(AInsecureSkipVerify: Boolean;
      const AVerify: TTlsCertificateVerifyCallback): ITlsClientConfig;
    function ServerConfig: ITlsServerConfig;
    function NewClientStream(const ATransport: ITlsTransport;
      const AConfig: ITlsClientConfig): TTlsStream;
    function NewServerStream(const ATransport: ITlsTransport): TTlsStream;
    procedure RunLoopback(const AClientConfig: ITlsClientConfig;
      AServerBehavior: TServerBehavior; out AClient: TTlsStream;
      out AServer: TServerRunner; out AClientTransport: TMemoryTransport);
    function AlwaysReject(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
    /// <summary>The verdict-resolver form (the seam's context signature): a live-revocation-style
    /// resolver reporting the reject alert. Reuses AlwaysReject for the decision.</summary>
    function ResolverReject(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    function ResolverRaises(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    /// <summary>A client config with the async peer-certificate verdict enabled.</summary>
    function AsyncClientConfig: ITlsClientConfig;
    /// <summary>Moves everything AFrom has queued into ATo, returning the byte count.</summary>
    function PassOutgoing(const AFrom, ATo: ITlsEngine): Int32;
    /// <summary>Everything AEngine has queued, as one wire.</summary>
    function TakeAll(const AEngine: ITlsEngine): TBytes;
    /// <summary>A pump over AEngine and ATransport, freed with the test; terminal sends are
    /// unbounded.</summary>
    function NewPump(const AEngine: ITlsEngine; const ATransport: ITlsTransport): TTlsStreamPump;
    procedure HandshakeEngines(out AClient, AServer: ITlsEngine);
    /// <summary>A handshake whose client caches the server's ticket in ACache.</summary>
    procedure HandshakeCachingATicket(const ACache: ISessionCache;
      out AClient, AServer: ITlsEngine);
    procedure HandshakeEnginesWith(const AClientConfig: ITlsClientConfig;
      const AServerConfig: ITlsServerConfig; out AClient, AServer: ITlsEngine);
    procedure HandshakeTls12WithAlpn(out AClient, AServer: ITlsEngine);
    /// <summary>TLS 1.2 configs whose AEAD hits its usage limit on the first application record.</summary>
    procedure CappedTls12Configs(out AClientConfig: ITlsClientConfig;
      out AServerConfig: ITlsServerConfig);
    /// <summary>The server's two-byte reply followed by an application_data record that cannot
    /// authenticate, so the drain behind the read of the reply queues bad_record_mac.</summary>
    function DataThenBadRecord(const AServer: ITlsEngine): TBytes;
    /// <summary>The server's two-byte reply followed by a KeyUpdate asking the client to rekey.</summary>
    function DataThenKeyUpdateRequest(const AServer: ITlsEngine): TBytes;
    /// <summary>Reads data through a socket that dies under the send of the alert a bad record
    /// made owed.</summary>
    procedure ReadWithAnAlertLostToADeadSocket(out AClient: ITlsEngine;
      out AWriteAttempts: Int32);
    /// <summary>Fails a write over a dead socket, leaving AClient latched.</summary>
    procedure FailAWriteOverADeadSocket(out AClient: ITlsEngine);
    /// <summary>Aborts an engine whose queue holds more than one transport chunk, over a dead
    /// socket that refuses the first chunk.</summary>
    procedure AbortWithAnOversizedQueueOverADeadSocket(out AClient: ITlsEngine);
    /// <summary>A loopback whose client transport counts what the client writes.</summary>
    procedure RunCountedLoopback(AServerBehavior: TServerBehavior; out AClient: TTlsStream;
      out AServer: TServerRunner; out ACounter: TCountingTransport);
    /// <summary>A client stream and a server stream over timed pipe transports; the server
    /// echoes one message on its own thread, then closes cleanly.</summary>
    procedure StartTimedEchoPair(out AClient: TTlsStream;
      out AClientTransport: TPipeTimedTransport);
    // the verify callback that parks the handshake until the test releases it
    function ClosingVerify(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
    function BlockingVerify(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
    /// <summary>A client whose handshake parks in ParkedResolver, a server that echoes one message,
    /// and the events the handshake tests share; the client is FQueried.</summary>
    procedure StartParkedHandshake(out AServer: TServerRunner);
    // the resolver that parks the handshake with the engine lock free until the test releases it
    function ParkedResolver(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    function Tls13Aes128Registry: ICipherSuiteRegistry;
    function PinnedClientConfig(const AKeyLog: IKeyLog): ITlsClientConfig;
    function PinnedServerConfig: ITlsServerConfig;
    /// <summary>Engines handshaken on TLS 1.3 with AES-128-GCM, the client logging its secrets to
    /// AKeyLog, and nothing left queued.</summary>
    procedure PinnedEngines(const AKeyLog: IKeyLog; out AClient, AServer: ITlsEngine);
    /// <summary>The client's first application traffic secret, as AKeyLog saw it.</summary>
    function ClientTraffic0(const AKeyLog: TMockKeyLog): TBytes;
    // thread bodies
    procedure HandshakeQueried;
    procedure HandshakeCapped;
    procedure HandshakeThenSignal;
    procedure HandshakeRepeated;
    procedure QueryQueried;
    procedure ReadQueried;
    procedure WriteQueried;
    procedure TimedReadQueried;
    procedure ShortTimedReadQueried;
    procedure ServeTimedEcho;
    procedure ServeConnection;
    procedure WritePumped;
    procedure ReadPumped;
    procedure ClosePumped;
    procedure KeyUpdatePumped;
    procedure ProbeQueried;
    procedure ExportQueried;
    procedure QueryPumped;
  var
    FVerifyEntered: TEvent;
    FVerifyRelease: TEvent;
    FQueryDone: TEvent;
    FReaderDone: TEvent;
    FSecondDone: TEvent;
    FPause: TEvent;
    FQueried: TTlsStream;
    FPingBytes: TBytes;
    FReadBuffer: TBytes;
    FReadCount: Int32;
    FReadTimeoutMs: Int32;
    FQueriedVersion: UInt16;
    FQueriedPending: Int32;
    FQueriedComplete: Boolean;
    FServing: TTlsStream;
    FServerConnection: TTlsConnection;
    FServerExported: TBytes;
    FPumped: TTlsStreamPump;
    FPumpedByte: TBytes;
    FPumpedBuffer: TBytes;
  published
    procedure TestClientServerLoopbackExchangesAppDataAndClosesCleanly;
    procedure TestBulkWriteIsSealedInBoundedSlices;
    procedure TestTerminalEngineSurfacesAlertInsteadOfBlockingRead;
    procedure TestPostHandshakeFatalAlertReachesPeer;
    procedure TestRecordLimitCloseNotifyReachesPeerOverPump;
    procedure TestApplicationReadTimeoutIsRetryableNotTruncation;
    procedure TestNegotiatedVersionAndAlpnSurfaced;
    procedure TestTruncationWithoutCloseNotifyIsSurfaced;
    procedure TestTruncationIsRaisedAgainOnALaterRead;
    procedure TestUntrustedChainFailsThroughOurPipeline;
    procedure TestHandshakeFailureIsLatchedOnRetry;
    procedure TestNonTerminalHandshakeFailureIsLatched;
    procedure TestForeignHandshakeFailureIsReraisedAsStreamError;
    procedure TestStreamRefusesANilEngineOrTransport;
    procedure TestHandshakeReadTimeoutIsLatchedAsHandshakeTimeout;
    procedure TestInsecureSkipVerifyAcceptsUntrustedChain;
    procedure TestVerifyCallbackCanOnlyAdditionallyReject;
    procedure TestPinnedSelfSignedChainStillFullyVerified;
    procedure TestAsyncVerdictResolverAcceptCompletesOverPump;
    procedure TestAsyncVerdictResolverRejectFailsClosedOverPump;
    procedure TestAsyncVerdictResolverThatRaisesFailsClosedWithAnAlert;
    procedure TestBulkThroughputRoundTripDoesNotWedge;
    procedure TestWriteAfterPreHandshakeCloseNotifyRaises;
    procedure TestWriteAfterPreHandshakeSendAlertRaises;
    procedure TestPeerCloseNotifyDuringHandshakeRaises;
    procedure TestTls12ClientReportsTheSelectedAlpn;
    procedure TestTls12ServerReportsItsSelectedAlpn;
    procedure TestWriteOnTerminalEngineFlushesQueuedAlertBeforeRaising;
    procedure TestReadReturningDataFlushesAlertQueuedByTheDrain;
    procedure TestReadReturningBufferedDataSurvivesADeadTransport;
    procedure TestPumpSendsAndReadsThroughItsOwnBuffers;
    procedure TestPumpReusesItsBuffers;
    procedure TestFailedAlertSendBehindBufferedDataDropsTheAlert;
    procedure TestTransportWriteFailureKeepsTheCachedTickets;
    procedure TestProtocolFatalAlertAtThePumpDropsTheCachedTickets;
    procedure TestLatchedEngineWritesNothingToTheTransport;
    procedure TestLatchDropsPendingOutboundBytes;
    procedure TestLatchAfterAFatalAlertDropsTheQueuedAlertAndKeepsTheReason;
    procedure TestFailedAlertSendBehindReadKeepsTheTlsReason;
    procedure TestWriteAfterAFailedAlertSendBehindReadRaisesTheAlert;
    procedure TestBadRecordBehindTransportDataRaisesWithTheAlertSent;
    procedure TestKeyUpdateRequestBehindTransportDataIsAnsweredByTheNextWrite;
    procedure TestFailedWriteFlushLatchesTheEngine;
    procedure TestWriteAfterAFailedWriteFlushSendsNothing;
    procedure TestFailedCloseFlushKeepsTheCachedTickets;
    procedure TestFailedHandshakeFlushLatchesTheEngine;
    procedure TestWriteAfterAFailedWriteFlushRaisesNoAlert;
    procedure TestStreamHandshakeReplayAfterADeadSocketRaisesNoAlert;
    procedure TestCloseAfterAFailedWriteFlushSendsNothing;
    procedure TestSealLimitOverADeadSocketStillRaisesTheLimitError;
    procedure TestFailedHandshakeStartOverADeadSocketRaisesTheTlsError;
    procedure TestFailedFlushOnATerminalEngineDropsTheTail;
    procedure TestTerminalEngineSendsNothingAfterAFailedFlush;
    procedure TestRequestKeyUpdateThroughTheStreamReachesThePeer;
    procedure TestExportKeyingMaterialThroughTheStreamMatchesThePeer;
    procedure TestQueriesAnswerAtOnceWhileTheHandshakeRuns;
    procedure TestInfoOfAFailedHandshakeIsTheEnginesNotZero;
    procedure TestTerminalSendOnAStalledSocketIsBoundedByTheCloseGrace;
    procedure TestCloseNotifyOnAStalledSocketRaisesAWriteTimeout;
    procedure TestReaderDoesNotWaitForTheWriteSide;
    procedure TestCloseDoesNotWaitForTheWriteSide;
    procedure TestApplicationReadCapIsArmedInsideTheReadSideAndCleared;
    procedure TestHandshakeReadCapIsArmedAndClearedAroundTheHandshake;
    procedure TestReadTimeoutNeedsATimedTransport;
    procedure TestConnectionForwardsKeyUpdateAndExporter;
    procedure TestReaderThatDroveTheHandshakeDoesNotBlockAWriter;
    procedure TestHandshakeCallDoesNotWaitForABlockedReader;
    procedure TestCloseNotifyDuringTheHandshakeIsSentAsItCompletes;
    procedure TestSendAlertDuringTheHandshakeRefusesTheConnection;
    procedure TestRequestKeyUpdateAfterCloseNotifyRaises;
    procedure TestRequestKeyUpdateAfterAPreHandshakeCloseNotifyRefusesWithoutHandshaking;
    procedure TestRepeatedPumpHandshakeKeepsTheStateComplete;
    procedure TestReleaseWriteSendsWhatWasSealedAfterTheLastCheck;
    procedure TestReadCapsAreArmedAndClearedInsideTheReadSide;
    procedure TestPlainReadAfterTheHandshakeDoesNotInheritItsCap;
    procedure TestHandshakeCallbackMayQueryAndCloseItsOwnConnection;
    procedure TestRequestKeyUpdateWaitsForTheWriteSide;
    procedure TestQueriesAndAWriteCompleteWhileAReadIsParked;
    procedure TestReadAndQueriesProceedWhileAWriterIsBlockedInASend;
    procedure TestExporterAnswersWhileAVerdictResolverIsParked;
    procedure TestRecheckThatFindsADeadSocketDoesNotMaskTheWritersError;
    procedure TestTerminalSendThatFindsTooLittleRoomIsBoundedByTheCloseGrace;
    procedure TestSeveralKeyUpdatesInOneRecordAreFatalWithOneAlert;
    procedure TestSeveralKeyUpdatesInOneRecordFailTheStreamAndTheAlertReachesThePeer;
    procedure TestKeyUpdateRecordsInOneReadAreAnsweredByOneReply;
  end;

implementation

const
  // "ping from the client" / "pong from the server"
  PingHex = '70696e672066726f6d2074686520636c69656e74';
  ExporterLabel = 'EXPERIMENTAL tlslib stream test';
  // an application_data record that cannot authenticate
  BadRecordHex = '170303001000112233445566778899aabbccddeeff';

type
  /// <summary>A session cache whose Take raises, failing a resuming client's StartHandshake.</summary>
  TFailingSessionCache = class sealed(TInterfacedObject, ISessionCache)
  public
    procedure Store(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    procedure Remove(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    function Take(const AServerIdentity, AServerName: string; ANowMillis: UInt64;
      out ASession: IResumableSession): Boolean;
    procedure SetKxHint(const AServerIdentity, AServerName: string; AGroup: UInt16);
    function KxHint(const AServerIdentity, AServerName: string): UInt16;
    procedure Clear;
    function Count: Int32;
  end;

  /// <summary>An engine over a real one that plays another thread's Close: on the first
  /// IsTerminal call after WantsWrite answered False it seals close_notify, which is how a record
  /// is sealed after a writer's last check and before it lets go of the write side. It can also
  /// owe one more byte once the transport has failed, like a record sealed behind a failed send.</summary>
  TSealAfterDrainEngine = class sealed(TInterfacedObject, ITlsEngine, ITlsEngineInbound,
    ITlsEngineOutbound)
  strict private
  var
    FInner: ITlsEngine;
    FDrained: Boolean;
    FSealed: Boolean;
    FOwesAfterLatch: Boolean;
    FOwed: Boolean;
  public
    constructor Create(const AInner: ITlsEngine);
    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    function WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32): Int32;
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    procedure SendClose;
    procedure SendAlert(ADescription: TTlsAlertDescription); overload;
    procedure SendAlert(ADescription: TTlsAlertDescription; const AReason: string); overload;
    procedure LatchTransportFailure(const AReason: string);
    procedure StartHandshake;
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingAppData: Int32;
    function ReadEarlyData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingEarlyData: Int32;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    function ConnectionInfo: TTlsConnectionInfo;
    function WantsRead: Boolean;
    function WantsWrite: Boolean;
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function IsTerminal: Boolean;
    function IsClosed: Boolean;
    function IsInboundClosed: Boolean;
    function WriteClosed: Boolean;
    function LastError: TTlsError;
    function ExportKeyingMaterial(const ALabel: string; ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
    /// <summary>Whether it sealed the close_notify.</summary>
    property Sealed: Boolean read FSealed;
    /// <summary>Whether a latch leaves one byte owed.</summary>
    property OwesAfterLatch: Boolean read FOwesAfterLatch write FOwesAfterLatch;
  end;

  /// <summary>Seals records under a TLS 1.3 client's first application traffic secret from outside
  /// its engine (AES-128-GCM, SHA-256), so a peer can be handed records no engine would send.</summary>
  TTrafficForger = class sealed(TObject)
  strict private
  var
    FCrypto: ICryptoProvider;
    FHkdf: IHkdf;
    FSecret: ISecretBuffer;
  public
    constructor Create(const ACrypto: ICryptoProvider; const ASecret: TBytes);
    /// <summary>One record holding APlaintext, sealed at sequence 0 under the current keys.</summary>
    function Seal(AContentType: TTlsContentType; const APlaintext: TBytes): TBytes;
    /// <summary>Moves to the next generation of keys, as the KeyUpdate just sealed does.</summary>
    procedure Advance;
  end;

  TTestAction = procedure of object;

  /// <summary>Runs one action of a test on its own thread, keeping the exception it ended with.</summary>
  TActionThread = class(TThread)
  strict private
  var
    FAction: TTestAction;
    FError: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const AAction: TTestAction);
    property Error: string read FError;
  end;

{ TFailingSessionCache }

procedure TFailingSessionCache.Store(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
end;

procedure TFailingSessionCache.Remove(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
end;

function TFailingSessionCache.Take(const AServerIdentity, AServerName: string;
  ANowMillis: UInt64; out ASession: IResumableSession): Boolean;
begin
  raise EInvalidOperation.Create('the session cache failed');
end;

procedure TFailingSessionCache.SetKxHint(const AServerIdentity, AServerName: string;
  AGroup: UInt16);
begin
end;

function TFailingSessionCache.KxHint(const AServerIdentity, AServerName: string): UInt16;
begin
  Result := 0;
end;

procedure TFailingSessionCache.Clear;
begin
end;

function TFailingSessionCache.Count: Int32;
begin
  Result := 0;
end;

{ TSealAfterDrainEngine }

constructor TSealAfterDrainEngine.Create(const AInner: ITlsEngine);
begin
  inherited Create;
  FInner := AInner;
end;

function TSealAfterDrainEngine.ProcessInput(const AWire: TBytes; AOffset,
  ALength: Int32): TTlsOutcome;
begin
  Result := FInner.ProcessInput(AWire, AOffset, ALength);
end;

procedure TSealAfterDrainEngine.Write(const AData: TBytes; AOffset, ALength: Int32);
begin
  FInner.Write(AData, AOffset, ALength);
end;

function TSealAfterDrainEngine.WriteEarlyData(const AData: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  Result := FInner.WriteEarlyData(AData, AOffset, ALength);
end;

procedure TSealAfterDrainEngine.RequestKeyUpdate(ARequest: TKeyUpdateRequest);
begin
  FInner.RequestKeyUpdate(ARequest);
end;

procedure TSealAfterDrainEngine.SendClose;
begin
  FInner.SendClose;
end;

procedure TSealAfterDrainEngine.SendAlert(ADescription: TTlsAlertDescription);
begin
  FInner.SendAlert(ADescription);
end;

procedure TSealAfterDrainEngine.SendAlert(ADescription: TTlsAlertDescription;
  const AReason: string);
begin
  FInner.SendAlert(ADescription, AReason);
end;

procedure TSealAfterDrainEngine.LatchTransportFailure(const AReason: string);
begin
  FInner.LatchTransportFailure(AReason);
  FOwed := FOwesAfterLatch;
  // owed once, so the recheck that fails to send it is not owed it again
  FOwesAfterLatch := False;
end;

procedure TSealAfterDrainEngine.StartHandshake;
begin
  FInner.StartHandshake;
end;

procedure TSealAfterDrainEngine.SetCertificateVerdict(AAccept: Boolean;
  AAlert: TTlsAlertDescription);
begin
  FInner.SetCertificateVerdict(AAccept, AAlert);
end;

function TSealAfterDrainEngine.TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
begin
  Result := FInner.TakeOutgoing(ADest, ADestOffset);
  if FOwed and (Result = 0) then
  begin
    FOwed := False;
    ADest[ADestOffset] := 0;
    Result := 1;
  end;
end;

function TSealAfterDrainEngine.ReadAppData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FInner.ReadAppData(ADest, ADestOffset, AMaxLength);
end;

function TSealAfterDrainEngine.PendingAppData: Int32;
begin
  Result := FInner.PendingAppData;
end;

function TSealAfterDrainEngine.ReadEarlyData(var ADest: TBytes; ADestOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FInner.ReadEarlyData(ADest, ADestOffset, AMaxLength);
end;

function TSealAfterDrainEngine.PendingEarlyData: Int32;
begin
  Result := FInner.PendingEarlyData;
end;

function TSealAfterDrainEngine.NextEvent(out AEvent: ITlsEvent): Boolean;
begin
  Result := FInner.NextEvent(AEvent);
end;

function TSealAfterDrainEngine.ConnectionInfo: TTlsConnectionInfo;
begin
  Result := FInner.ConnectionInfo;
end;

function TSealAfterDrainEngine.WantsRead: Boolean;
begin
  Result := FInner.WantsRead;
end;

function TSealAfterDrainEngine.WantsWrite: Boolean;
begin
  Result := FInner.WantsWrite or FOwed;
  if not Result then
    FDrained := True;
end;

function TSealAfterDrainEngine.IsHandshaking: Boolean;
begin
  Result := FInner.IsHandshaking;
end;

function TSealAfterDrainEngine.AwaitingCertificateVerdict: Boolean;
begin
  Result := FInner.AwaitingCertificateVerdict;
end;

function TSealAfterDrainEngine.IsTerminal: Boolean;
begin
  if FDrained and not FSealed then
  begin
    FSealed := True;
    FInner.SendClose;
  end;
  Result := FInner.IsTerminal;
end;

function TSealAfterDrainEngine.IsClosed: Boolean;
begin
  Result := FInner.IsClosed;
end;

function TSealAfterDrainEngine.IsInboundClosed: Boolean;
begin
  Result := FInner.IsInboundClosed;
end;

function TSealAfterDrainEngine.WriteClosed: Boolean;
begin
  Result := FInner.WriteClosed;
end;

function TSealAfterDrainEngine.LastError: TTlsError;
begin
  Result := FInner.LastError;
end;

function TSealAfterDrainEngine.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  Result := FInner.ExportKeyingMaterial(ALabel, ALength);
end;

function TSealAfterDrainEngine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := FInner.ExportKeyingMaterial(ALabel, AContext, ALength);
end;

function TSealAfterDrainEngine.ExportEarlyKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := FInner.ExportEarlyKeyingMaterial(ALabel, AContext, ALength);
end;

{ TServerRunner }

constructor TServerRunner.Create(const AStream: TTlsStream;
  const ATransport, AClientTransport: TMemoryTransport; ABehavior: TServerBehavior);
begin
  inherited Create(AStream, ATransport, AClientTransport);
  FBehavior := ABehavior;
end;

procedure TServerRunner.Execute;
var
  LChunk: TBytes;
  LGot, LEchoed: Int32;
begin
  try
    FStream.Handshake;
    FNegotiatedVersion := FStream.ConnectionInfo.NegotiatedVersion.WireValue;
    FAlpn := FStream.ConnectionInfo.AlpnProtocol;
    FExported := FStream.ExportKeyingMaterial(ExporterLabel, 32);
    if FBehavior = TServerBehavior.TruncateAfterHandshake then
    begin
      FTransport.CloseWrite; // drop the write side with no close_notify
      Exit;
    end;
    if FBehavior = TServerBehavior.BulkEcho then
    begin
      // echo exactly FBulkBytes back, reading in small chunks so the outbound side keeps
      // re-filling and draining under sustained load, then close cleanly
      SetLength(LChunk, 4096);
      LEchoed := 0;
      while LEchoed < FBulkBytes do
      begin
        LGot := FStream.Read(LChunk[0], System.Length(LChunk));
        if LGot <= 0 then
          Break; // peer closed early
        FStream.Write(LChunk[0], LGot);
        Inc(LEchoed, LGot);
      end;
      FStream.CloseNotify;
      Exit;
    end;
    // echo one client message back, then shut down cleanly
    SetLength(LChunk, 4096);
    LGot := FStream.Read(LChunk[0], System.Length(LChunk));
    if LGot > 0 then
      FStream.Write(LChunk[0], LGot);
    FStream.CloseNotify;
  except
    on E: Exception do
    begin
      FError := E.ClassName + ': ' + E.Message;
      // a server that failed has nothing more to send: release a client blocked on its read so
      // the failure surfaces there (as whatever the server flushed first) rather than a hang
      FTransport.CloseWrite;
    end;
  end;
end;

{ TActionThread }

constructor TActionThread.Create(const AAction: TTestAction);
begin
  inherited Create(True);
  FAction := AAction;
  FreeOnTerminate := False;
end;

procedure TActionThread.Execute;
begin
  try
    FAction;
  except
    on E: Exception do
      FError := E.ClassName + ': ' + E.Message;
  end;
end;

{ TTrafficForger }

constructor TTrafficForger.Create(const ACrypto: ICryptoProvider; const ASecret: TBytes);
begin
  inherited Create;
  FCrypto := ACrypto;
  FHkdf := ACrypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
  FSecret := TSecretBuffer.From(ASecret);
end;

function TTrafficForger.Seal(AContentType: TTlsContentType; const APlaintext: TBytes): TBytes;
var
  LProtection: IRecordProtection;
begin
  LProtection := TTls13RecordProtection.Create(
    THkdfLabel.HkdfExpandLabel(FHkdf, FSecret, 'key', nil, 16),
    THkdfLabel.HkdfExpandLabel(FHkdf, FSecret, 'iv', nil, 12),
    FCrypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
  Result := LProtection.Protect(AContentType, APlaintext, 0, System.Length(APlaintext));
end;

procedure TTrafficForger.Advance;
begin
  FSecret := THkdfLabel.HkdfExpandLabel(FHkdf, FSecret, 'traffic upd', nil, 32);
end;

{ TTestTlsStreamLoopback }

function TTestTlsStreamLoopback.ClientConfig(AInsecureSkipVerify: Boolean;
  const AVerify: TTlsCertificateVerifyCallback): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11));
  if AInsecureSkipVerify then
    LClient.WithServerVerification(TServerVerification.DangerousSkip)
  else
    LClient.WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build);
  if Assigned(AVerify) then
    LClient.WithCertificateVerifyCallback(AVerify);
  Result := LClient.Build;
end;

function TTestTlsStreamLoopback.ServerConfig: ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11))
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key'))).Build;
end;

function TTestTlsStreamLoopback.NewClientStream(const ATransport: ITlsTransport;
  const AConfig: ITlsClientConfig): TTlsStream;
begin
  Result := TTlsStream.Create(ATransport,
    TTlsEngineFactory.CreateClientEngine(AConfig, 'localhost'), True, 'localhost');
end;

function TTestTlsStreamLoopback.NewServerStream(
  const ATransport: ITlsTransport): TTlsStream;
begin
  Result := TTlsStream.Create(ATransport,
    TTlsEngineFactory.CreateServerEngine(ServerConfig), False, '');
end;

procedure TTestTlsStreamLoopback.TestWriteAfterPreHandshakeCloseNotifyRaises;
var
  LC2S, LS2C: TMemoryPipe;
  LClientT, LServerT: ITlsTransport;
  LClient: TTlsStream;
  LByte: Byte;
  LRaised: Boolean;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  // both paired transports are held so each frees one pipe exactly once (no peer thread needed:
  // the guard fires before any handshake or transport I/O)
  LClientT := TMemoryTransport.Create(LS2C, LC2S) as ITlsTransport;
  LServerT := TMemoryTransport.Create(LC2S, LS2C) as ITlsTransport;
  LClient := NewClientStream(LClientT, ClientConfig(False, nil));
  try
    LClient.CloseNotify; // before any handshake: latches the write-closed flag, sends nothing
    LByte := $41;
    LRaised := False;
    try
      LClient.Write(LByte, 1);
    except
      on E: EInvalidOperationTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised,
      'a write after a pre-handshake CloseNotify raises rather than silently handshaking');
  finally
    LClient.Free;
  end;
  LServerT := nil;
end;

procedure TTestTlsStreamLoopback.TestWriteAfterPreHandshakeSendAlertRaises;
var
  LC2S, LS2C: TMemoryPipe;
  LClientT, LServerT: ITlsTransport;
  LClient: TTlsStream;
  LByte: Byte;
  LRaised: Boolean;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientT := TMemoryTransport.Create(LS2C, LC2S) as ITlsTransport;
  LServerT := TMemoryTransport.Create(LC2S, LS2C) as ITlsTransport;
  LClient := NewClientStream(LClientT, ClientConfig(False, nil));
  try
    // before any handshake there is no peer to alert: latch the closed flag and send nothing; a
    // repeat is a no-op
    LClient.SendAlert(TTlsAlertDescription.BadCertificate);
    LClient.SendAlert(TTlsAlertDescription.BadCertificate);
    LByte := $41;
    LRaised := False;
    try
      LClient.Write(LByte, 1);
    except
      on E: EInvalidOperationTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a write after SendAlert raises rather than silently handshaking');
  finally
    LClient.Free;
  end;
  LServerT := nil;
end;

procedure TTestTlsStreamLoopback.TestPeerCloseNotifyDuringHandshakeRaises;
var
  LC2S, LS2C: TMemoryPipe;
  LClientT, LServerT: ITlsTransport;
  LClient: TTlsStream;
  LRaised: Boolean;
begin
  // the peer sends a plaintext close_notify (15 03 03 00 02 01 00) in place of its ServerHello: the
  // handshake is abandoned, so Handshake must raise promptly rather than block or misreport, and
  // not loop back into a read that never returns
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientT := TMemoryTransport.Create(LS2C, LC2S) as ITlsTransport;
  LServerT := TMemoryTransport.Create(LC2S, LS2C) as ITlsTransport;
  // preload the server->client pipe so the client reads the close_notify when it awaits ServerHello
  LS2C.Write(DecodeHex('15030300020100'), 0, 7);
  // closed, so a regression fails the test instead of blocking on a read
  LS2C.Close;
  LClient := NewClientStream(LClientT, ClientConfig(False, nil));
  try
    LRaised := False;
    try
      LClient.Handshake;
    except
      on E: ETlsTransportTruncated do
        LRaised := True;
    end;
    CheckTrue(LRaised,
      'a close_notify received during the handshake aborts rather than blocking or misreporting');
    // the failure is latched as the same class on a later call
    LRaised := False;
    try
      LClient.Handshake;
    except
      on E: ETlsTransportTruncated do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a later call raises the same truncation');
  finally
    LClient.Free;
  end;
  LServerT := nil;
end;

procedure TTestTlsStreamLoopback.RunLoopback(const AClientConfig: ITlsClientConfig;
  AServerBehavior: TServerBehavior; out AClient: TTlsStream;
  out AServer: TServerRunner; out AClientTransport: TMemoryTransport);
var
  LC2S, LS2C: TMemoryPipe;
  LServerTransport: TMemoryTransport;
  LClientT, LServerT: ITlsTransport;
  LServerStream: TTlsStream;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  // client reads server->client, writes client->server; server mirrored
  AClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LClientT := AClientTransport;
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LServerT := LServerTransport;
  AClient := NewClientStream(LClientT, AClientConfig);
  LServerStream := NewServerStream(LServerT);
  AServer := TServerRunner.Create(LServerStream, LServerTransport, AClientTransport,
    AServerBehavior);
  AServer.Start;
end;

function TTestTlsStreamLoopback.AlwaysReject(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := False;
end;

function TTestTlsStreamLoopback.ResolverReject(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := AlwaysReject(ACtx.Chain, ACtx.ValidatedPath, ACtx.HostName);
end;

function TTestTlsStreamLoopback.AsyncClientConfig: ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithAsyncCertificateVerdict(0).Build;
end;

procedure TTestTlsStreamLoopback.TestClientServerLoopbackExchangesAppDataAndClosesCleanly;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LPing, LEcho: TBytes;
  LGot: Int32;
begin
  RunLoopback(ClientConfig(False, nil), TServerBehavior.EchoThenClose, LClient,
    LServer, LTransport);
  try
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete, 'the client completed the handshake');
    // the presented server chain is what the peer put on the wire: a leaf-only credential
    CheckEquals(1, System.Length(LClient.ConnectionInfo.PeerCertificates),
      'connection info carries the presented server chain');
    CheckEqualBytes('the leaf is the first chain entry',
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      LClient.ConnectionInfo.PeerCertificates[0]);
    // the validated path is what the pipeline built here: leaf, assembled issuer, up to the anchor
    CheckTrue(System.Length(LClient.ConnectionInfo.ValidatedPath) >= 2,
      'the validated path assembles the issuer beyond the presented leaf');
    CheckEqualBytes('the validated path leaf is the server leaf',
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      LClient.ConnectionInfo.ValidatedPath[0]);
    CheckEqualBytes('the validated path terminates at the trust anchor',
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'),
      LClient.ConnectionInfo.ValidatedPath[System.High(LClient.ConnectionInfo.ValidatedPath)]);

    LPing := DecodeHex(PingHex);
    LClient.Write(LPing[0], System.Length(LPing));

    SetLength(LEcho, 4096);
    LGot := LClient.Read(LEcho[0], System.Length(LEcho));
    CheckEqualBytes('the server echoed the client message', LPing,
      System.Copy(LEcho, 0, LGot));

    LClient.CloseNotify;
    // the server's close_notify arrives as a clean EOF, never a truncation
    LGot := LClient.Read(LEcho[0], System.Length(LEcho));
    CheckEquals(0, LGot, 'the client reads EOF after the server close_notify');
    CheckFalse(LClient.TransportTruncated, 'a clean close_notify is not a truncation');

    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestBulkWriteIsSealedInBoundedSlices;
const
  BULK = 512 * 1024;
  // the largest ciphertext one slice can queue: the slice plus each of its four records' framing
  // and AEAD expansion
  PEAK_BOUND = TTlsStreamPump.WriteChunk + 4 * (TRecordLimits.HeaderLength +
    TRecordLimits.MaxCipherTextTls13 - TRecordLimits.MaxPlaintext);
var
  LC2S, LS2C: TMemoryPipe;
  LInner, LServerTransport: TMemoryTransport;
  LProbe: TPeakProbeTransport;
  LEngine: ITlsEngine;
  LClient, LServerStream: TTlsStream;
  LServer: TServerRunner;
  LTx, LRx: TBytes;
  LTotal, LGot, I: Int32;
begin
  SetLength(LTx, BULK);
  for I := 0 to BULK - 1 do
    LTx[I] := Byte(I + (I shr 8));
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LInner := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LEngine := TTlsEngineFactory.CreateClientEngine(ClientConfig(True, nil), 'localhost');
  // the probe sits between the pump and the pipe and sees exactly what the engine had queued
  // at each transport write
  LProbe := TPeakProbeTransport.Create(LInner as ITlsTransport, LEngine);
  LClient := TTlsStream.Create(LProbe as ITlsTransport, LEngine, True, 'localhost');
  LServerStream := NewServerStream(LServerTransport as ITlsTransport);
  LServer := TServerRunner.Create(LServerStream, LServerTransport, LInner,
    TServerBehavior.BulkEcho);
  LServer.BulkBytes := BULK;
  LServer.Start;
  try
    LClient.Handshake;
    LProbe.Arm;
    LClient.Write(LTx[0], BULK);
    // a bulk write is sealed and drained a slice at a time, never queued whole
    CheckTrue(LProbe.PeakPending <= PEAK_BOUND,
      Format('at most one slice of ciphertext is queued ahead of a send (peak %d, bound %d)',
      [LProbe.PeakPending, PEAK_BOUND]));
    SetLength(LRx, BULK);
    LTotal := 0;
    while LTotal < BULK do
    begin
      LGot := LClient.Read(LRx[LTotal], BULK - LTotal);
      if LGot <= 0 then
        Break;
      Inc(LTotal, LGot);
    end;
    CheckEquals(BULK, LTotal, 'the full payload round-tripped');
    CheckEqualBytes('the sliced write reaches the peer intact and in order', LTx, LRx);
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestTerminalEngineSurfacesAlertInsteadOfBlockingRead;
var
  LC2S, LS2C: TMemoryPipe;
  LClientTransport: TMemoryTransport;
  LServerTransport: TMemoryTransport;
  LEngine: ITlsEngine;
  LClient: TTlsStream;
  LServer: TServerRunner;
  LWatch: TWedgeWatchdog;
  LBuf: TBytes;
  LRaised, LTruncated: Boolean;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LEngine := TTlsEngineFactory.CreateClientEngine(ClientConfig(False, nil), 'localhost');
  LClient := TTlsStream.Create(LClientTransport as ITlsTransport, LEngine, True, 'localhost');
  LServer := TServerRunner.Create(NewServerStream(LServerTransport as ITlsTransport),
    LServerTransport, LClientTransport, TServerBehavior.EchoThenClose);
  LWatch := TWedgeWatchdog.Create(LC2S, LS2C, 60000);
  LWatch.Start;
  LServer.Start;
  try
    LClient.Handshake;
    // a locally sent fatal alert leaves the engine terminal with the alert unflushed; the next
    // read must send it and raise rather than park on a transport read that never returns
    LEngine.SendAlert(TTlsAlertDescription.InternalError);
    SetLength(LBuf, 16);
    LRaised := False;
    LTruncated := False;
    try
      LClient.Read(LBuf[0], 16);
    except
      on E: ETlsTransportTruncated do
        LTruncated := True;
      on E: ETlsStreamError do
        LRaised := E.HasAlert and (E.Alert = TTlsAlertDescription.InternalError);
    end;
    CheckFalse(LTruncated, 'the failure is the alert, not a truncation');
    CheckTrue(LRaised, 'a read on a terminal engine raises its alert');
    LServer.Finish;
    LWatch.Disarm;
    CheckFalse(LWatch.Fired, 'the read did not leave both sides blocked');
    CheckTrue(Pos('ETlsStreamError:', LServer.Error) = 1,
      'the unflushed alert reached the peer');
  finally
    LWatch.Disarm;
    LWatch.WaitFor;
    LWatch.Free;
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestPostHandshakeFatalAlertReachesPeer;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LGarbage, LBuf: TBytes;
  LAlerted, LTruncated: Boolean;
  LAlert: TTlsAlertDescription;
begin
  RunLoopback(ClientConfig(False, nil), TServerBehavior.EchoThenClose, LClient,
    LServer, LTransport);
  try
    LClient.Handshake;
    // an application_data record that cannot authenticate: the server's read fails fatally and
    // queues bad_record_mac, which must be flushed to us before the server's error surfaces
    LGarbage := DecodeHex('170303001000112233445566778899aabbccddeeff');
    LTransport.Write(LGarbage, 0, System.Length(LGarbage));
    SetLength(LBuf, 4096);
    LAlerted := False;
    LTruncated := False;
    LAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Read(LBuf[0], System.Length(LBuf));
    except
      on E: ETlsTransportTruncated do
        LTruncated := True;
      on E: ETlsStreamError do
      begin
        LAlerted := E.HasAlert;
        if E.HasAlert then
          LAlert := E.Alert;
      end;
    end;
    CheckFalse(LTruncated, 'the peer''s fatal alert arrives before its transport goes away');
    CheckTrue(LAlerted, 'the client read surfaces the peer''s fatal alert');
    CheckEquals(Ord(TTlsAlertDescription.BadRecordMac), Ord(LAlert),
      'the alert is the bad_record_mac the server queued');
    LServer.Finish;
    CheckTrue(LServer.Error <> '', 'the server side failed on the bad record');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.CappedTls12Configs(out AClientConfig: ITlsClientConfig;
  out AServerConfig: ITlsServerConfig);
var
  LCapped: ICryptoProvider;
  LSuites: ICipherSuiteRegistryBuilder;
begin
  // a capped AEAD whose usage limit is one past the rekey lead (17 = lead 16 + 1) puts the write
  // epoch at its soft threshold on the very first application record (the Finished consumed
  // sequence 0). TLS 1.2 has no KeyUpdate, so that first write seals a close_notify and refuses,
  // exercising the limit path without sealing millions of records.
  LCapped := TCappedAeadProvider.Create(Crypto, 17) as ICryptoProvider;
  LSuites := TCipherSuiteRegistry.CreateDualVersion(LCapped).ToBuilder;
  LSuites.Prune(TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256);
  LSuites.Prune(TCipherSuites12.EcdheRsaChaCha20Poly1305Sha256);
  AClientConfig := TTlsPresets.Compatible(LCapped, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCipherSuites(LSuites.Build).Build;
  AServerConfig := TTlsPresets.Compatible(LCapped, Pkix).Server
    .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11))
    .WithCredential(TTlsCredential.Load(LCapped, Pkix,
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key'))).Build;
end;

procedure TTestTlsStreamLoopback.TestRecordLimitCloseNotifyReachesPeerOverPump;
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LC2S, LS2C: TMemoryPipe;
  LClientTransport, LServerTransport: TMemoryTransport;
  LClientEngine, LServerEngine: ITlsEngine;
  LClient, LServerStream: TTlsStream;
  LServer: TServerRunner;
  LWatch: TWedgeWatchdog;
  LByte: TBytes;
  LRaised: Boolean;
begin
  CappedTls12Configs(LClientConfig, LServerConfig);
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LClientEngine := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServerEngine := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient := TTlsStream.Create(LClientTransport as ITlsTransport, LClientEngine, True,
    'localhost');
  LServerStream := TTlsStream.Create(LServerTransport as ITlsTransport, LServerEngine, False,
    '');
  LServer := TServerRunner.Create(LServerStream, LServerTransport, LClientTransport,
    TServerBehavior.EchoThenClose);
  // a close_notify that never reaches the server leaves it blocked in its read forever; the
  // watchdog turns that into a surfaced EOF (a server error) instead of a hung run
  LWatch := TWedgeWatchdog.Create(LC2S, LS2C, 60000);
  LWatch.Start;
  LServer.Start;
  try
    LClient.Handshake;
    CheckEquals(Integer(TlsWireVersionTls12),
      Integer(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
      'the client negotiated TLS 1.2, which has no KeyUpdate to rekey with');
    LByte := DecodeHex('00');
    LRaised := False;
    try
      LClient.Write(LByte[0], 1);
    except
      on ERecordLimitTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a write at the usage limit raises ERecordLimitTlsLibException');
    // the server reads the close_notify the engine queued at the limit as a clean EOF and
    // closes cleanly itself; a truncation would be an error on its side
    LServer.Finish;
    LWatch.Disarm;
    CheckFalse(LWatch.Fired, 'the server was not left blocked on its read');
    CheckEquals('', LServer.Error, 'the server saw a clean close_notify, not a truncation');
  finally
    LWatch.Disarm;
    LWatch.WaitFor;
    LWatch.Free;
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestApplicationReadTimeoutIsRetryableNotTruncation;
var
  LC2S, LS2C: TMemoryPipe;
  LInner, LServerTransport: TMemoryTransport;
  LTimeout: TTimeoutOnceTransport;
  LClient, LServerStream: TTlsStream;
  LServer: TServerRunner;
  LPing, LEcho: TBytes;
  LGot: Int32;
  LTimedOut: Boolean;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LInner := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LTimeout := TTimeoutOnceTransport.Create(LInner as ITlsTransport);
  LClient := NewClientStream(LTimeout as ITlsTransport, ClientConfig(False, nil));
  LServerStream := NewServerStream(LServerTransport as ITlsTransport);
  LServer := TServerRunner.Create(LServerStream, LServerTransport, LInner,
    TServerBehavior.EchoThenClose);
  LServer.Start;
  try
    LClient.Handshake;
    LPing := DecodeHex(PingHex);
    LClient.Write(LPing[0], System.Length(LPing));
    // the host socket's receive timeout fires on the first application read: it surfaces as the
    // retryable timeout and leaves the stream intact, so the retry reads the echo
    LTimeout.Arm;
    SetLength(LEcho, 4096);
    LTimedOut := False;
    try
      LClient.Read(LEcho[0], System.Length(LEcho));
    except
      on E: ETlsReadTimeout do
        LTimedOut := True;
    end;
    CheckTrue(LTimedOut, 'an application read timeout raises ETlsReadTimeout');
    CheckFalse(LClient.TransportTruncated, 'a read timeout is not a truncation');
    LGot := LClient.Read(LEcho[0], System.Length(LEcho));
    CheckEqualBytes('the retried read returns the echo', LPing, System.Copy(LEcho, 0, LGot));
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestNegotiatedVersionAndAlpnSurfaced;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LInfo: TTlsConnectionInfo;
begin
  RunLoopback(ClientConfig(False, nil), TServerBehavior.EchoThenClose, LClient,
    LServer, LTransport);
  try
    LClient.Handshake;
    LInfo := LClient.ConnectionInfo;
    CheckEquals(Integer(TlsWireVersionTls13), Integer(LInfo.NegotiatedVersion.WireValue),
      'the client negotiated TLS 1.3');
    CheckEqualBytes('the client negotiated the h2 ALPN protocol', TAlpnProtocols.H2,
      LInfo.AlpnProtocol);
    CheckEquals('localhost', LInfo.ServerName, 'the connection info carries the SNI host');
    // the negotiated suite and (EC)DHE group are surfaced; a fresh handshake is not resumed
    CheckTrue(LInfo.CipherSuite <> 0, 'the connection info carries the negotiated cipher suite');
    CheckTrue(LInfo.NamedGroup <> 0, 'a TLS 1.3 handshake carries a negotiated named group');
    CheckFalse(LInfo.Resumed, 'a fresh handshake is not marked resumed');

    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
    CheckEquals(Integer(TlsWireVersionTls13), Integer(LServer.NegotiatedVersion),
      'the server negotiated TLS 1.3');
    CheckEqualBytes('the server selected the h2 ALPN protocol', TAlpnProtocols.H2,
      LServer.Alpn);
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestTruncationWithoutCloseNotifyIsSurfaced;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LBuf: TBytes;
  LRaised: Boolean;
begin
  RunLoopback(ClientConfig(False, nil), TServerBehavior.TruncateAfterHandshake,
    LClient, LServer, LTransport);
  try
    LClient.Handshake;
    SetLength(LBuf, 4096);
    LRaised := False;
    // the server dropped the transport without close_notify: the read fails fatally
    // (truncation attack), not a silent clean EOF
    try
      LClient.Read(LBuf[0], System.Length(LBuf));
    except
      on E: ETlsTransportTruncated do
        LRaised := True;
    end;
    CheckTrue(LRaised,
      'a close without close_notify raises a fatal truncation, not a graceful EOF');
    CheckTrue(LClient.TransportTruncated,
      'the truncation accessor stays set for a host that catches and tolerates');
    LServer.Finish;
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestTruncationIsRaisedAgainOnALaterRead;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LBuf: TBytes;
  LRaised: Boolean;
begin
  RunLoopback(ClientConfig(False, nil), TServerBehavior.TruncateAfterHandshake,
    LClient, LServer, LTransport);
  try
    LClient.Handshake;
    SetLength(LBuf, 4096);
    LRaised := False;
    try
      LClient.Read(LBuf[0], System.Length(LBuf));
    except
      on E: ETlsTransportTruncated do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'the first read raises the truncation');
    LRaised := False;
    try
      LClient.Read(LBuf[0], System.Length(LBuf));
    except
      on E: ETlsTransportTruncated do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a read after a swallowed truncation raises again, not a clean EOF');
    LServer.Finish;
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestUntrustedChainFailsThroughOurPipeline;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LConfig: ITlsClientConfig;
  LPlain: Boolean;
  LAlert: TTlsAlertDescription;
begin
  // a client that trusts an unrelated anchor (the leaf's own cert, not its issuer) must
  // reject the server chain through PKIX - no dangerous flag is set
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert')).Build).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  try
    LPlain := False;
    LAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
      begin
        LPlain := E.ClassType = ETlsStreamError;
        if E.HasAlert then
          LAlert := E.Alert;
      end;
    end;
    CheckTrue(LPlain, 'an untrusted server chain fails with a plain stream error');
    CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
      'the untrusted chain is refused with unknown_ca');
    LServer.Finish;
    CheckTrue(Pos('ETlsStreamError:', LServer.Error) = 1,
      'the rejection alert reached the server');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestHandshakeFailureIsLatchedOnRetry;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LConfig: ITlsClientConfig;
  LBuf: TBytes;
  LFirst, LSecond: Boolean;
  LFirstAlert, LSecondAlert: TTlsAlertDescription;
begin
  // a failed handshake is permanent for a stream: a second Read must re-raise the same failure,
  // never silently re-drive (which would emit a second ClientHello) or read as a truncation
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert')).Build).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  SetLength(LBuf, 16);
  try
    LFirst := False;
    LFirstAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
      begin
        LFirst := E.ClassType = ETlsStreamError;
        if E.HasAlert then
          LFirstAlert := E.Alert;
      end;
    end;
    CheckTrue(LFirst, 'the untrusted chain fails the handshake with a plain stream error');
    CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LFirstAlert),
      'the handshake failure carries unknown_ca');
    CheckFalse(LClient.IsHandshakeComplete, 'the handshake did not complete');
    LSecond := False;
    LSecondAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Read(LBuf[0], 16);
    except
      on E: ETlsStreamError do
      begin
        LSecond := E.ClassType = ETlsStreamError;
        if E.HasAlert then
          LSecondAlert := E.Alert;
      end;
    end;
    CheckTrue(LSecond, 'a read after the failed handshake re-raises the plain stream error');
    CheckEquals(Ord(LFirstAlert), Ord(LSecondAlert), 'the re-raise carries the same alert');
    CheckFalse(LClient.TransportTruncated,
      'the failure is reported as itself, not masked as a truncation');
    LServer.Finish;
    CheckTrue(Pos('ETlsStreamError:', LServer.Error) = 1,
      'the rejection alert reached the server');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestNonTerminalHandshakeFailureIsLatched;
var
  LS2C, LC2S: TMemoryPipe;
  LTransport: TMemoryTransport;
  LEngine: ITlsEngine;
  LClient: TTlsStream;
  LBuf: TBytes;
  LFirst, LSecond: Boolean;
begin
  // a transport truncation during the handshake (the peer is gone before its flight) fails the
  // engine WITHOUT making it terminal, so the re-raise takes the latched-exception path rather than
  // the terminal-alert one; a second call must re-raise the same class, never re-drive.
  LS2C := TMemoryPipe.Create;
  LC2S := TMemoryPipe.Create;
  LS2C.Close; // the client's read for the ServerHello hits EOF at once
  LTransport := TMemoryTransport.Create(LS2C, LC2S);
  LEngine := TTlsEngineFactory.CreateClientEngine(ClientConfig(False, nil), 'localhost');
  LClient := TTlsStream.Create(LTransport as ITlsTransport, LEngine, True, 'localhost');
  SetLength(LBuf, 16);
  try
    LFirst := False;
    try
      LClient.Handshake;
    except
      on E: ETlsTransportTruncated do
        LFirst := True;
    end;
    CheckTrue(LFirst, 'a pre-flight truncation fails the handshake');
    LSecond := False;
    try
      LClient.Read(LBuf[0], 16);
    except
      on E: ETlsTransportTruncated do
        LSecond := True;
    end;
    CheckTrue(LSecond, 'the non-terminal failure is latched and re-raised as the same class');
    CheckFalse(LClient.IsHandshakeComplete, 'the handshake did not complete');
  finally
    LClient.Free; // frees the stream, the transport, and the transport-owned write pipe (LC2S)
    LS2C.Free;    // the read pipe is not owned by the single transport
  end;
end;

procedure TTestTlsStreamLoopback.TestStreamRefusesANilEngineOrTransport;
var
  LEngine: ITlsEngine;
  LStream: TTlsStream;
  LRaised: Boolean;
begin
  // a missing argument is a typed error, not an access violation on first use
  LRaised := False;
  try
    LStream := TTlsStream.Create(TFailingReadTransport.Create as ITlsTransport, nil, True,
      'localhost');
    LStream.Free;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a stream with no engine is refused');
  LEngine := TTlsEngineFactory.CreateClientEngine(ClientConfig(False, nil), 'localhost');
  LRaised := False;
  try
    LStream := TTlsStream.Create(nil, LEngine, True, 'localhost');
    LStream.Free;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a stream with no transport is refused');
end;

procedure TTestTlsStreamLoopback.TestForeignHandshakeFailureIsReraisedAsStreamError;
var
  LEngine: ITlsEngine;
  LClient: TTlsStream;
  LBuf: TBytes;
  LFirst, LSecond: string;
begin
  LEngine := TTlsEngineFactory.CreateClientEngine(ClientConfig(False, nil), 'localhost');
  LClient := TTlsStream.Create(TFailingReadTransport.Create as ITlsTransport, LEngine, True,
    'localhost');
  SetLength(LBuf, 16);
  try
    LFirst := '';
    try
      LClient.Handshake;
    except
      on E: EInOutError do
        LFirst := E.Message;
    end;
    CheckTrue(LFirst <> '', 'the transport failure surfaces as itself the first time');
    LSecond := '';
    try
      LClient.Read(LBuf[0], 16);
    except
      on E: ETlsStreamError do
        LSecond := E.Message;
    end;
    CheckEquals(LFirst, LSecond, 'the latched failure re-raises as a stream error, same message');
  finally
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestHandshakeReadTimeoutIsLatchedAsHandshakeTimeout;
var
  LC2S, LS2C: TMemoryPipe;
  LTimeout: TTimeoutOnceTransport;
  LClient: TTlsStream;
  LBuf: TBytes;
  LFirst, LSecond: Boolean;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LTimeout := TTimeoutOnceTransport.Create(TMemoryTransport.Create(LS2C, LC2S) as ITlsTransport);
  LTimeout.Arm;
  LClient := NewClientStream(LTimeout as ITlsTransport, ClientConfig(False, nil));
  SetLength(LBuf, 16);
  try
    LFirst := False;
    try
      LClient.Handshake;
    except
      on E: ETlsReadTimeout do
        LFirst := True;
    end;
    CheckTrue(LFirst, 'the timed-out handshake read surfaces as the read timeout');
    LSecond := False;
    try
      LClient.Read(LBuf[0], 16);
    except
      on E: ETlsHandshakeTimeout do
        LSecond := True;
    end;
    CheckTrue(LSecond, 'the permanent failure is not a retryable read timeout');
  finally
    LClient.Free;
    LS2C.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestInsecureSkipVerifyAcceptsUntrustedChain;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LConfig: ITlsClientConfig;
begin
  // the same otherwise-untrusted anchor, but InsecureSkipVerify bypasses the pipeline so
  // the handshake completes (test-only; never production)
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.DangerousSkip).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  try
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete,
      'InsecureSkipVerify makes an otherwise-untrusted chain pass');
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestVerifyCallbackCanOnlyAdditionallyReject;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LPlain: Boolean;
  LAlert: TTlsAlertDescription;
begin
  // the chain would pass the built-in pipeline (trusted root), but an augment callback
  // additionally rejects it: the handshake must fail
  RunLoopback(ClientConfig(False, AlwaysReject), TServerBehavior.EchoThenClose, LClient,
    LServer, LTransport);
  try
    LPlain := False;
    LAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
      begin
        LPlain := E.ClassType = ETlsStreamError;
        if E.HasAlert then
          LAlert := E.Alert;
      end;
    end;
    CheckTrue(LPlain, 'the augment callback rejects an otherwise-valid chain with a stream error');
    CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
      'the callback rejection is refused with certificate_unknown');
    LServer.Finish;
    CheckTrue(Pos('ETlsStreamError:', LServer.Error) = 1,
      'the rejection alert reached the server');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestPinnedSelfSignedChainStillFullyVerified;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LConfig: ITlsClientConfig;
begin
  // a private root trusted via WebPki plus an SPKI pin on the leaf: the chain is
  // still fully verified (PKIX + pinning both hold), so the handshake completes
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithCertificatePinning(TArray<TBytes>.Create(
      TTlsLibTestCertificates.SpkiSha256(Crypto, Pkix,
        TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert')))).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  try
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete,
      'a trusted-anchor chain that also matches its SPKI pin verifies');
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestAsyncVerdictResolverAcceptCompletesOverPump;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LPing, LEcho: TBytes;
  LGot: Int32;
  LSpy: TVerdictResolverSpy;
begin
  // async verdict enabled end-to-end over the blocking pump: the pump parks, calls the
  // resolver (which accepts), and the handshake completes and exchanges app data
  LSpy := Own<TVerdictResolverSpy>(TVerdictResolverSpy.Create);
  RunLoopback(AsyncClientConfig, TServerBehavior.EchoThenClose, LClient, LServer,
    LTransport);
  try
    LClient.SetCertificateVerdictResolver(LSpy.Resolve);
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete,
      'an accepted async verdict completes the handshake over the pump');
    CheckEquals(Ord(TPeerRole.Server), Ord(LSpy.PeerRole),
      'a client park attributes the parked chain to the server role');
    LPing := DecodeHex(PingHex);
    LClient.Write(LPing[0], System.Length(LPing));
    SetLength(LEcho, 4096);
    LGot := LClient.Read(LEcho[0], System.Length(LEcho));
    CheckEqualBytes('the server echoed the client message', LPing,
      System.Copy(LEcho, 0, LGot));
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestAsyncVerdictResolverRejectFailsClosedOverPump;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LPlain: Boolean;
  LAlert: TTlsAlertDescription;
begin
  // a resolver that rejects a chain the pipeline already accepted still aborts the handshake
  // (augment-only, fail-closed) - the pump raises
  RunLoopback(AsyncClientConfig, TServerBehavior.EchoThenClose, LClient, LServer,
    LTransport);
  try
    LClient.SetCertificateVerdictResolver(ResolverReject);
    LPlain := False;
    LAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
      begin
        LPlain := E.ClassType = ETlsStreamError;
        if E.HasAlert then
          LAlert := E.Alert;
      end;
    end;
    CheckTrue(LPlain, 'a rejected async verdict fails closed with a plain stream error');
    CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
      'the rejection carries the resolver''s bad_certificate');
    LServer.Finish;
    CheckTrue(Pos('ETlsStreamError:', LServer.Error) = 1,
      'the rejection alert reached the server');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

function TTestTlsStreamLoopback.ResolverRaises(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  raise EInvalidOperationTlsLibException.Create('the live check blew up');
end;

procedure TTestTlsStreamLoopback.TestAsyncVerdictResolverThatRaisesFailsClosedWithAnAlert;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LAlert: TTlsAlertDescription;
  LFailed: Boolean;
begin
  // a resolver that raises must not leave the handshake parked with no verdict and no alert: the
  // peer gets an internal_error and the caller sees that failure
  RunLoopback(AsyncClientConfig, TServerBehavior.EchoThenClose, LClient, LServer,
    LTransport);
  try
    LClient.SetCertificateVerdictResolver(ResolverRaises);
    LFailed := False;
    LAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
      begin
        LFailed := True;
        if E.HasAlert then
          LAlert := E.Alert;
      end;
    end;
    CheckTrue(LFailed, 'a raising resolver fails the handshake closed');
    CheckTrue(LAlert = TTlsAlertDescription.InternalError, 'with internal_error');
    LServer.Finish;
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestBulkThroughputRoundTripDoesNotWedge;
const
  // several megabytes: one Write queues many records into the outbound buffer, and the pump
  // then drains them in TransportChunk-sized takes - the path the cursor buffer governs. Both
  // directions are exercised (the client's Write and the server's echo).
  BULK = 4 * 1024 * 1024;
var
  LC2S, LS2C: TMemoryPipe;
  LClientTransport, LServerTransport: TMemoryTransport;
  LClient, LServerStream: TTlsStream;
  LServer: TServerRunner;
  LWatch: TWedgeWatchdog;
  LTx, LRx: TBytes;
  LTotal, LGot, I: Int32;
begin
  SetLength(LTx, BULK);
  for I := 0 to BULK - 1 do
    LTx[I] := Byte(I + (I shr 8)); // a position-dependent pattern so any misorder/truncation shows

  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LClient := NewClientStream(LClientTransport as ITlsTransport, ClientConfig(True, nil));
  LServerStream := NewServerStream(LServerTransport as ITlsTransport);
  LServer := TServerRunner.Create(LServerStream, LServerTransport, LClientTransport,
    TServerBehavior.BulkEcho);
  LServer.BulkBytes := BULK;
  // a wedge would block a pump read forever; the watchdog closes both pipes after the deadline
  // so the read returns EOF and the test fails loudly instead of hanging the run
  LWatch := TWedgeWatchdog.Create(LC2S, LS2C, 60000);
  LWatch.Start;
  LServer.Start;
  try
    LClient.Handshake;
    LClient.Write(LTx[0], BULK); // one large write -> the whole payload queues before the drain
    SetLength(LRx, BULK);
    LTotal := 0;
    while LTotal < BULK do
    begin
      LGot := LClient.Read(LRx[LTotal], BULK - LTotal);
      if LGot <= 0 then
        Break;
      Inc(LTotal, LGot);
    end;
    LWatch.Disarm;
    CheckFalse(LWatch.Fired, 'the exchange completed without tripping the wedge watchdog');
    CheckEquals(BULK, LTotal, 'the full payload round-tripped');
    CheckEqualBytes('the echoed stream matches byte-for-byte', LTx, LRx);
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LWatch.Disarm; // on any failure path too, so the watchdog thread can exit
    LWatch.WaitFor;
    LWatch.Free;
    LServer.Free;
    LClient.Free;
  end;
end;

function TTestTlsStreamLoopback.PassOutgoing(const AFrom, ATo: ITlsEngine): Int32;
var
  LBuf: TBytes;
  LGot: Int32;
begin
  Result := 0;
  LBuf := nil;
  System.SetLength(LBuf, 16384);
  repeat
    LGot := AFrom.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
    begin
      ATo.ProcessInput(LBuf, 0, LGot);
      System.Inc(Result, LGot);
    end;
  until LGot = 0;
end;

function TTestTlsStreamLoopback.TakeAll(const AEngine: ITlsEngine): TBytes;
begin
  Result := nil;
  System.SetLength(Result, 65536);
  System.SetLength(Result, AEngine.TakeOutgoing(Result, 0));
end;

function TTestTlsStreamLoopback.NewPump(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport): TTlsStreamPump;
begin
  Result := Own<TTlsStreamPump>(TTlsStreamPump.Create(AEngine, ATransport, 0));
end;

procedure TTestTlsStreamLoopback.HandshakeEngines(out AClient, AServer: ITlsEngine);
begin
  HandshakeEnginesWith(ClientConfig(False, nil), ServerConfig, AClient, AServer);
end;

procedure TTestTlsStreamLoopback.TestTls12ClientReportsTheSelectedAlpn;
var
  LClient, LServer: ITlsEngine;
begin
  HandshakeTls12WithAlpn(LClient, LServer);
  CheckEqualBytes('the client reports the protocol the server selected', TAlpnProtocols.Http11,
    LClient.ConnectionInfo.AlpnProtocol);
end;

procedure TTestTlsStreamLoopback.TestTls12ServerReportsItsSelectedAlpn;
var
  LClient, LServer: ITlsEngine;
begin
  HandshakeTls12WithAlpn(LClient, LServer);
  CheckEqualBytes('the TLS 1.2 server reports the protocol it selected', TAlpnProtocols.Http11,
    LServer.ConnectionInfo.AlpnProtocol);
end;

procedure TTestTlsStreamLoopback.HandshakeTls12WithAlpn(out AClient, AServer: ITlsEngine);
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
begin
  LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.H2, TAlpnProtocols.Http11))
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12)).Build;
  LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithAlpnProtocols(TArray<TBytes>.Create(TAlpnProtocols.Http11))
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key')))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12)).Build;
  HandshakeEnginesWith(LClientConfig, LServerConfig, AClient, AServer);
  CheckEquals(Integer(TlsWireVersionTls12), Integer(AServer.ConnectionInfo.NegotiatedVersion.WireValue),
    'a TLS 1.2 connection');
end;

procedure TTestTlsStreamLoopback.HandshakeEnginesWith(const AClientConfig: ITlsClientConfig;
  const AServerConfig: ITlsServerConfig; out AClient, AServer: ITlsEngine);
begin
  AClient := TTlsEngineFactory.CreateClientEngine(AClientConfig, 'localhost');
  AServer := TTlsEngineFactory.CreateServerEngine(AServerConfig);
  AClient.StartHandshake;
  while AClient.IsHandshaking or AServer.IsHandshaking do
    if (PassOutgoing(AClient, AServer) = 0) and (PassOutgoing(AServer, AClient) = 0) then
      Break;
  CheckFalse(AClient.IsHandshaking, 'the in-memory handshake completed');
end;

procedure TTestTlsStreamLoopback.TestWriteOnTerminalEngineFlushesQueuedAlertBeforeRaising;
var
  LClient, LServer: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LData: TBytes;
  LRaised: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  // a locally sent fatal alert leaves the engine terminal with the alert still queued
  LClient.SendAlert(TTlsAlertDescription.InternalError);
  LData := DecodeHex('00');
  LRaised := False;
  try
    NewPump(LClient, LTransport).WriteApp(LData[0], 1);
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a write on a terminal engine raises its alert');
  CheckTrue(LRecorder.Written > 0, 'the queued alert reached the transport before the raise');
end;

procedure TTestTlsStreamLoopback.TestReadReturningDataFlushesAlertQueuedByTheDrain;
var
  LClient, LServer: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LDest: TBytes;
  LWire: TBytes;
  LStatus: TTlsReadStatus;
  LGot: Int32;
begin
  HandshakeEngines(LClient, LServer);
  LWire := DataThenBadRecord(LServer);
  LClient.ProcessInput(LWire, 0, System.Length(LWire));
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  System.SetLength(LDest, 16);
  LGot := NewPump(LClient, LTransport).ReadApp(LDest, 16, LStatus);
  CheckEquals(2, LGot, 'the buffered data is returned');
  CheckTrue(LRecorder.Written > 0, 'the alert the drain queued was flushed with the data');
end;

function TTestTlsStreamLoopback.DataThenBadRecord(const AServer: ITlsEngine): TBytes;
var
  LData, LGarbage: TBytes;
  LTaken: Int32;
begin
  LData := DecodeHex('0102');
  AServer.Write(LData, 0, 2);
  Result := nil;
  System.SetLength(Result, 16384);
  LTaken := AServer.TakeOutgoing(Result, 0);
  // an unauthenticatable record behind the real one: the drain after the read queues bad_record_mac
  LGarbage := DecodeHex('170303001000112233445566778899aabbccddeeff');
  System.SetLength(Result, LTaken + System.Length(LGarbage));
  System.Move(LGarbage[0], Result[LTaken], System.Length(LGarbage));
end;

function TTestTlsStreamLoopback.DataThenKeyUpdateRequest(const AServer: ITlsEngine): TBytes;
var
  LData: TBytes;
begin
  LData := DecodeHex('0102');
  AServer.Write(LData, 0, 2);
  AServer.RequestKeyUpdate(TKeyUpdateRequest.UpdateRequested);
  Result := nil;
  System.SetLength(Result, 16384);
  System.SetLength(Result, AServer.TakeOutgoing(Result, 0));
end;

procedure TTestTlsStreamLoopback.TestBadRecordBehindTransportDataRaisesWithTheAlertSent;
var
  LClient, LServer: ITlsEngine;
  LScripted: TScriptedTransport;
  LTransport: ITlsTransport;
  LDest: TBytes;
  LStatus: TTlsReadStatus;
  LRaised: Boolean;
begin
  // ProcessInput fails the engine on the bad record before the data is read, so the read raises first
  HandshakeEngines(LClient, LServer);
  LScripted := TScriptedTransport.Create(DataThenBadRecord(LServer), False);
  LTransport := LScripted as ITlsTransport;
  System.SetLength(LDest, 16);
  LRaised := False;
  try
    NewPump(LClient, LTransport).ReadApp(LDest, 16, LStatus);
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the read raises the bad record');
  CheckTrue(LScripted.Written > 0, 'after sending bad_record_mac');
end;

procedure TTestTlsStreamLoopback.TestKeyUpdateRequestBehindTransportDataIsAnsweredByTheNextWrite;
var
  LClient, LServer: ITlsEngine;
  LS2C, LC2S: TMemoryPipe;
  LTransport: ITlsTransport;
  LEvent: ITlsEvent;
  LDest, LReply, LWritten, LWire: TBytes;
  LPump: TTlsStreamPump;
  LStatus: TTlsReadStatus;
  LGot, LKeyUpdates: Int32;
begin
  // the reply to a KeyUpdate is owed, not queued, when the read returns: nothing is left to flush
  HandshakeEngines(LClient, LServer);
  LS2C := TMemoryPipe.Create;
  LC2S := TMemoryPipe.Create;
  LTransport := TMemoryTransport.Create(LS2C, LC2S) as ITlsTransport;
  LPump := NewPump(LClient, LTransport);
  try
    LWire := DataThenKeyUpdateRequest(LServer);
    LS2C.Write(LWire, 0, System.Length(LWire));
    LS2C.Close;
    LC2S.Close; // closed so the drains below read what was written, never block on an empty pipe
    System.SetLength(LDest, 16);
    CheckEquals(2, LPump.ReadApp(LDest, 16, LStatus), 'the data');
    System.SetLength(LWritten, 16384);
    CheckEquals(0, LC2S.Read(LWritten, 0, System.Length(LWritten)),
      'no reply was queued by the read');
    LReply := DecodeHex('03');
    LPump.WriteApp(LReply[0], 1);
    LGot := LC2S.Read(LWritten, 0, System.Length(LWritten));
    CheckTrue(LGot > 0, 'the next write reached the transport');
    LServer.ProcessInput(LWritten, 0, LGot);
    LKeyUpdates := 0;
    while LServer.NextEvent(LEvent) do
      if LEvent.Kind = TTlsEventKind.KeyUpdateReceived then
        System.Inc(LKeyUpdates);
    CheckEquals(1, LKeyUpdates, 'the next write carried the owed KeyUpdate reply');
    CheckEquals(1, LServer.PendingAppData,
      'the data record behind the reply decrypts under the new keys');
  finally
    LS2C.Free;
  end;
end;

procedure TTestTlsStreamLoopback.ReadWithAnAlertLostToADeadSocket(out AClient: ITlsEngine;
  out AWriteAttempts: Int32);
var
  LServer: ITlsEngine;
  LDead: TDeadWriteTransport;
  LDeadT: ITlsTransport;
  LDest, LWire, LQueued: TBytes;
  LStatus: TTlsReadStatus;
begin
  HandshakeEngines(AClient, LServer);
  LDead := TDeadWriteTransport.Create;
  LDeadT := LDead;
  // two chunks of ciphertext ahead of the alert: the dead socket refuses the first, and only the
  // latch stops the send of the rest
  System.SetLength(LQueued, 2 * TTlsStreamPump.TransportChunk);
  AClient.Write(LQueued, 0, System.Length(LQueued));
  LWire := DataThenBadRecord(LServer);
  AClient.ProcessInput(LWire, 0, System.Length(LWire));
  System.SetLength(LDest, 16);
  // the bad record made the engine terminal with bad_record_mac owed; the socket dies under its send
  NewPump(AClient, LDeadT).ReadApp(LDest, 16, LStatus);
  AWriteAttempts := LDead.Attempts;
end;

procedure TTestTlsStreamLoopback.HandshakeCachingATicket(const ACache: ISessionCache;
  out AClient, AServer: ITlsEngine);
var
  LClientConfig: ITlsClientConfig;
begin
  LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithResumption(True)
    .WithSessionCache(ACache).Build;
  HandshakeEnginesWith(LClientConfig, ServerConfig, AClient, AServer);
  // the server's post-handshake NewSessionTicket
  PassOutgoing(AServer, AClient);
  CheckTrue(ACache.Count > 0, 'the client cached the server''s ticket');
end;

procedure TTestTlsStreamLoopback.TestTransportWriteFailureKeepsTheCachedTickets;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LData: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  HandshakeCachingATicket(LCache, LClient, LServer);
  LData := DecodeHex('00');
  try
    // the socket dies under the send: the engine latches, but a broken transport is no TLS fatal alert
    NewPump(LClient, TDeadWriteTransport.Create as ITlsTransport).WriteApp(LData[0], 1);
  except
    on EInOutError do
      ;
  end;
  CheckTrue(LClient.IsTerminal, 'the lost send latched the engine');
  CheckTrue(LCache.Count > 0, 'the cached tickets stay resumable');
end;

procedure TTestTlsStreamLoopback.TestProtocolFatalAlertAtThePumpDropsTheCachedTickets;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  HandshakeCachingATicket(LCache, LClient, LServer);
  NewPump(LClient, TRecordingTransport.Create as ITlsTransport).Abort(
    TTlsAlertDescription.InternalError);
  CheckTrue(LClient.IsTerminal, 'the abort ended the connection');
  CheckEquals(0, LCache.Count, 'a fatal alert withdraws the tickets');
end;

procedure TTestTlsStreamLoopback.TestLatchedEngineWritesNothingToTheTransport;
var
  LClient, LServer: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LData: TBytes;
  LRaised: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  CheckFalse(LClient.WantsWrite, 'the handshake left nothing pending');
  LClient.LatchTransportFailure('the socket failed');
  CheckFalse(LClient.WantsWrite, 'the latch queued no alert');
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LData := DecodeHex('00');
  LRaised := False;
  try
    NewPump(LClient, LTransport).WriteApp(LData[0], 1);
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a write on the latched engine raises');
  CheckEquals(0, LRecorder.Written, 'nothing reached the transport after the latch');
end;

procedure TTestTlsStreamLoopback.TestLatchDropsPendingOutboundBytes;
var
  LClient, LServer: ITlsEngine;
  LData: TBytes;
begin
  HandshakeEngines(LClient, LServer);
  LData := DecodeHex('00');
  LClient.Write(LData, 0, 1);
  CheckTrue(LClient.WantsWrite, 'the sealed record is pending');
  LClient.LatchTransportFailure('the socket failed');
  CheckFalse(LClient.WantsWrite, 'the latch dropped the bytes a broken transport cannot carry');
  CheckEquals(Ord(TTlsErrorOrigin.Transport), Ord(LClient.LastError.Origin),
    'the latched failure is a transport failure, not an alert');
end;

procedure TTestTlsStreamLoopback.TestLatchAfterAFatalAlertDropsTheQueuedAlertAndKeepsTheReason;
var
  LClient, LServer: ITlsEngine;
begin
  HandshakeEngines(LClient, LServer);
  LClient.SendAlert(TTlsAlertDescription.DecodeError);
  LClient.LatchTransportFailure('x');
  CheckFalse(LClient.WantsWrite, 'the latch drops the alert a broken transport cannot carry');
  CheckEquals(Ord(TTlsAlertDescription.DecodeError), Ord(LClient.LastError.Alert.Description),
    'the first error stands');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LClient.LastError.Origin),
    'the first error stays our own');
end;

procedure TTestTlsStreamLoopback.TestFailedAlertSendBehindBufferedDataDropsTheAlert;
var
  LClient: ITlsEngine;
  LAttempts: Int32;
begin
  ReadWithAnAlertLostToADeadSocket(LClient, LAttempts);
  CheckTrue(LClient.IsTerminal, 'the bad record ended the connection');
  CheckFalse(LClient.WantsWrite, 'the alert and the ciphertext behind the chunk were dropped');
  CheckEquals(1, LAttempts, 'the refused send latched the engine, so no later chunk was tried');
end;

procedure TTestTlsStreamLoopback.TestFailedAlertSendBehindReadKeepsTheTlsReason;
var
  LClient: ITlsEngine;
  LAttempts: Int32;
begin
  ReadWithAnAlertLostToADeadSocket(LClient, LAttempts);
  CheckEquals(Ord(TTlsAlertDescription.BadRecordMac), Ord(LClient.LastError.Alert.Description),
    'the first error stands');
  CheckTrue(LClient.LastError.Origin <> TTlsErrorOrigin.Transport,
    'the failed send does not replace the TLS reason with the transport failure');
end;

procedure TTestTlsStreamLoopback.TestWriteAfterAFailedAlertSendBehindReadRaisesTheAlert;
var
  LClient: ITlsEngine;
  LRecorder: TRecordingTransport;
  LData: TBytes;
  LRaised: Boolean;
  LAttempts: Int32;
begin
  ReadWithAnAlertLostToADeadSocket(LClient, LAttempts);
  LData := DecodeHex('00');
  LRecorder := TRecordingTransport.Create;
  LRaised := False;
  try
    NewPump(LClient, LRecorder as ITlsTransport).WriteApp(LData[0], 1);
  except
    on E: ETlsStreamError do
      LRaised := E.Alert = TTlsAlertDescription.BadRecordMac;
  end;
  CheckTrue(LRaised, 'the write raises the recorded bad_record_mac');
  CheckEquals(0, LRecorder.Written,
    'neither the alert nor the ciphertext behind it is sent after the failed send');
  CheckEquals(1, LAttempts, 'the failed send was the only one tried');
end;

procedure TTestTlsStreamLoopback.TestPumpSendsAndReadsThroughItsOwnBuffers;
var
  LClient, LServer: ITlsEngine;
  LCounter: TCountingTransport;
  LPump: TTlsStreamPump;
  LData, LDest: TBytes;
  LStatus: TTlsReadStatus;
begin
  HandshakeEngines(LClient, LServer);
  LData := DecodeHex('0102');
  LServer.Write(LData, 0, 2);
  LCounter := TCountingTransport.Create(
    TScriptedTransport.Create(TakeAll(LServer), False) as ITlsTransport);
  LPump := NewPump(LClient, LCounter as ITlsTransport);
  LPump.WriteApp(LData[0], 1);
  System.SetLength(LDest, 16);
  CheckEquals(2, LPump.ReadApp(LDest, 16, LStatus), 'the scripted record was read');
  CheckTrue(LCounter.LastWriteBuffer <> nil, 'the write reached the transport');
  CheckTrue(LCounter.LastReadBuffer <> nil, 'the read reached the transport');
  CheckTrue(LCounter.LastWriteBuffer <> LCounter.LastReadBuffer,
    'a read and a write never share a transport buffer');
end;

procedure TTestTlsStreamLoopback.TestPumpReusesItsBuffers;
var
  LClient, LServer: ITlsEngine;
  LCounter: TCountingTransport;
  LPump: TTlsStreamPump;
  LData: TBytes;
  LFirst: Pointer;
begin
  HandshakeEngines(LClient, LServer);
  LCounter := TCountingTransport.Create(TRecordingTransport.Create as ITlsTransport);
  LPump := NewPump(LClient, LCounter as ITlsTransport);
  LData := DecodeHex('00');
  LPump.WriteApp(LData[0], 1);
  LFirst := LCounter.LastWriteBuffer;
  CheckTrue(LFirst <> nil, 'the first send allocated the send buffer');
  LPump.WriteApp(LData[0], 1);
  CheckTrue(LFirst = LCounter.LastWriteBuffer, 'the second send reused the buffer');
end;

procedure TTestTlsStreamLoopback.TestReadReturningBufferedDataSurvivesADeadTransport;
var
  LClient, LServer: ITlsEngine;
  LDest, LWire: TBytes;
  LStatus: TTlsReadStatus;
  LGot: Int32;
begin
  HandshakeEngines(LClient, LServer);
  // the engine owes an alert that a dead socket cannot take, beside the data it read
  LWire := DataThenBadRecord(LServer);
  LClient.ProcessInput(LWire, 0, System.Length(LWire));
  System.SetLength(LDest, 16);
  LGot := NewPump(LClient, TDeadWriteTransport.Create as ITlsTransport).ReadApp(LDest, 16,
    LStatus);
  CheckEquals(2, LGot, 'the plaintext already taken from the engine is returned');
end;

procedure TTestTlsStreamLoopback.TestFailedWriteFlushLatchesTheEngine;
var
  LClient, LServer: ITlsEngine;
  LData: TBytes;
  LRaised: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LData := DecodeHex('00');
  LRaised := False;
  try
    NewPump(LClient, TDeadWriteTransport.Create as ITlsTransport).WriteApp(LData[0], 1);
  except
    on E: EInOutError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the transport''s own exception is re-raised');
  CheckTrue(LClient.IsTerminal, 'the failed flush latched the engine');
end;

procedure TTestTlsStreamLoopback.FailAWriteOverADeadSocket(out AClient: ITlsEngine);
var
  LServer: ITlsEngine;
  LData: TBytes;
begin
  HandshakeEngines(AClient, LServer);
  LData := DecodeHex('00');
  try
    NewPump(AClient, TDeadWriteTransport.Create as ITlsTransport).WriteApp(LData[0], 1);
  except
    on E: EInOutError do
      ;
  end;
end;

procedure TTestTlsStreamLoopback.TestWriteAfterAFailedWriteFlushSendsNothing;
var
  LClient: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LData: TBytes;
  LRaised: Boolean;
begin
  FailAWriteOverADeadSocket(LClient);
  LData := DecodeHex('00');
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LRaised := False;
  try
    NewPump(LClient, LTransport).WriteApp(LData[0], 1);
  except
    on E: ETlsStreamError do
      LRaised := Pos('the mock socket failed', E.Message) > 0;
  end;
  CheckTrue(LRaised, 'the retry raises the latched transport failure');
  CheckEquals(0, LRecorder.Written, 'nothing follows the torn write');
end;

procedure TTestTlsStreamLoopback.TestWriteAfterAFailedWriteFlushRaisesNoAlert;
var
  LClient: ITlsEngine;
  LTransport: ITlsTransport;
  LData: TBytes;
  LRaised, LHasAlert: Boolean;
  LMessage: string;
begin
  FailAWriteOverADeadSocket(LClient);
  LData := DecodeHex('00');
  LTransport := TRecordingTransport.Create as ITlsTransport;
  LRaised := False;
  LHasAlert := True;
  LMessage := '';
  try
    NewPump(LClient, LTransport).WriteApp(LData[0], 1);
  except
    on E: ETlsStreamError do
    begin
      LRaised := True;
      LHasAlert := E.HasAlert;
      LMessage := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'the retry raises a stream error');
  CheckFalse(LHasAlert, 'a transport failure is not reported as a TLS alert');
  CheckTrue(Pos('the mock socket failed', LMessage) > 0, 'the error names the transport failure');
end;

procedure TTestTlsStreamLoopback.TestStreamHandshakeReplayAfterADeadSocketRaisesNoAlert;
var
  LClient: TTlsStream;
  LFirst, LRaised, LHasAlert, LExactClass: Boolean;
  LMessage: string;
begin
  LClient := NewClientStream(TDeadWriteTransport.Create as ITlsTransport,
    ClientConfig(False, nil));
  try
    LFirst := False;
    try
      LClient.Handshake;
    except
      on E: EInOutError do
        LFirst := True;
    end;
    CheckTrue(LFirst, 'the first handshake raises the transport''s own exception');
    LRaised := False;
    LHasAlert := True;
    LExactClass := False;
    LMessage := '';
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
      begin
        LRaised := True;
        LHasAlert := E.HasAlert;
        LExactClass := E.ClassType = ETlsStreamError;
        LMessage := E.Message;
      end;
    end;
    CheckTrue(LRaised, 'the replay raises a stream error');
    CheckTrue(LExactClass, 'the replay is a plain stream error');
    CheckFalse(LHasAlert, 'the replay carries no alert, as the first failure did');
    CheckTrue(Pos('the mock socket failed', LMessage) > 0, 'the replay names the failure');
  finally
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestCloseAfterAFailedWriteFlushSendsNothing;
var
  LClient: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
begin
  FailAWriteOverADeadSocket(LClient);
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  NewPump(LClient, LTransport).Close;
  CheckEquals(0, LRecorder.Written, 'no close_notify follows the torn write');
end;

procedure TTestTlsStreamLoopback.TestSealLimitOverADeadSocketStillRaisesTheLimitError;
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LData: TBytes;
  LRaised: Boolean;
begin
  CappedTls12Configs(LClientConfig, LServerConfig);
  HandshakeEnginesWith(LClientConfig, LServerConfig, LClient, LServer);
  LData := DecodeHex('00');
  LRaised := False;
  try
    NewPump(LClient, TDeadWriteTransport.Create as ITlsTransport).WriteApp(LData[0], 1);
  except
    on ERecordLimitTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the seal error, not the transport error, reaches the caller');
  CheckTrue(LClient.IsTerminal, 'the lost close_notify latched the engine');
end;

procedure TTestTlsStreamLoopback.TestFailedHandshakeStartOverADeadSocketRaisesTheTlsError;
var
  LCache: ISessionCache;
  LConfig: ITlsClientConfig;
  LClient: ITlsEngine;
  LRaised: Boolean;
begin
  LCache := TFailingSessionCache.Create;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithResumption(True)
    .WithSessionCache(LCache).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LConfig, 'localhost');
  LRaised := False;
  try
    NewPump(LClient, TDeadWriteTransport.Create as ITlsTransport).DriveHandshake(True);
  except
    on ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the start failure outranks the transport error on its alert');
end;

procedure TTestTlsStreamLoopback.TestFailedCloseFlushKeepsTheCachedTickets;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LRaised: Boolean;
begin
  LCache := TInMemorySessionCache.Create;
  HandshakeCachingATicket(LCache, LClient, LServer);
  LRaised := False;
  try
    NewPump(LClient, TDeadWriteTransport.Create as ITlsTransport).Close;
  except
    on E: EInOutError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the transport''s own exception is re-raised');
  CheckTrue(LClient.IsTerminal, 'the failed close_notify flush latched the engine');
  CheckTrue(LCache.Count > 0, 'a transport failure is no fatal alert: the tickets stay');
end;

procedure TTestTlsStreamLoopback.TestFailedHandshakeFlushLatchesTheEngine;
var
  LConfig: ITlsClientConfig;
  LClient: ITlsEngine;
  LRaised: Boolean;
begin
  LConfig := ClientConfig(False, nil);
  LClient := TTlsEngineFactory.CreateClientEngine(LConfig, 'localhost');
  LRaised := False;
  try
    NewPump(LClient, TDeadWriteTransport.Create as ITlsTransport).DriveHandshake(True);
  except
    on E: EInOutError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the ClientHello write failure is re-raised unchanged');
  CheckTrue(LClient.IsTerminal, 'the failed first flight latched the engine');
end;

procedure TTestTlsStreamLoopback.AbortWithAnOversizedQueueOverADeadSocket(out AClient: ITlsEngine);
var
  LServer: ITlsEngine;
  LData: TBytes;
begin
  HandshakeEngines(AClient, LServer);
  System.SetLength(LData, 2 * TTlsStreamPump.TransportChunk);
  AClient.Write(LData, 0, System.Length(LData));
  NewPump(AClient, TDeadWriteTransport.Create as ITlsTransport).Abort(
    TTlsAlertDescription.DecodeError);
end;

procedure TTestTlsStreamLoopback.TestFailedFlushOnATerminalEngineDropsTheTail;
var
  LClient: ITlsEngine;
begin
  AbortWithAnOversizedQueueOverADeadSocket(LClient);
  CheckTrue(LClient.IsTerminal, 'the abort ended the connection');
  CheckFalse(LClient.WantsWrite, 'the alert tail the transport refused was dropped');
  CheckEquals(Ord(TTlsAlertDescription.DecodeError), Ord(LClient.LastError.Alert.Description),
    'the first error stands');
end;

procedure TTestTlsStreamLoopback.TestTerminalEngineSendsNothingAfterAFailedFlush;
var
  LClient: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LData: TBytes;
  LRaised: Boolean;
begin
  AbortWithAnOversizedQueueOverADeadSocket(LClient);
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LData := DecodeHex('00');
  LRaised := False;
  try
    NewPump(LClient, LTransport).WriteApp(LData[0], 1);
  except
    on E: ETlsStreamError do
      LRaised := E.Alert = TTlsAlertDescription.DecodeError;
  end;
  CheckTrue(LRaised, 'the write raises the recorded decode_error');
  CheckEquals(0, LRecorder.Written, 'the alert is not resent after a failed flush');
end;

procedure TTestTlsStreamLoopback.RunCountedLoopback(AServerBehavior: TServerBehavior;
  out AClient: TTlsStream; out AServer: TServerRunner; out ACounter: TCountingTransport);
var
  LC2S, LS2C: TMemoryPipe;
  LInner, LServerTransport: TMemoryTransport;
  LInnerT, LServerT: ITlsTransport;
  LConfig: ITlsClientConfig;
begin
  LConfig := ClientConfig(False, nil);
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LInner := TMemoryTransport.Create(LS2C, LC2S);
  LInnerT := LInner;
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LServerT := LServerTransport;
  ACounter := TCountingTransport.Create(LInnerT);
  AClient := NewClientStream(ACounter as ITlsTransport, LConfig);
  AServer := TServerRunner.Create(NewServerStream(LServerT), LServerTransport, LInner,
    AServerBehavior);
  AServer.Start;
end;

procedure TTestTlsStreamLoopback.TestRequestKeyUpdateThroughTheStreamReachesThePeer;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LCounter: TCountingTransport;
  LPing, LEcho: TBytes;
  LBefore, LGot: Int32;
begin
  RunCountedLoopback(TServerBehavior.EchoThenClose, LClient, LServer, LCounter);
  try
    LClient.Handshake;
    LBefore := LCounter.Written;
    LClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateRequested);
    CheckTrue(LCounter.Written > LBefore, 'the KeyUpdate record reached the transport');
    LPing := DecodeHex(PingHex);
    LClient.Write(LPing[0], System.Length(LPing));
    SetLength(LEcho, 4096);
    LGot := LClient.Read(LEcho[0], System.Length(LEcho));
    CheckEqualBytes('both directions follow the rekey: the peer decrypted and answered under it',
      LPing, System.Copy(LEcho, 0, LGot));
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestExportKeyingMaterialThroughTheStreamMatchesThePeer;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LExported, LWithContext: TBytes;
begin
  RunLoopback(ClientConfig(False, nil), TServerBehavior.EchoThenClose, LClient, LServer,
    LTransport);
  try
    LClient.Handshake;
    LExported := LClient.ExportKeyingMaterial(ExporterLabel, 32);
    LWithContext := LClient.ExportKeyingMaterial(ExporterLabel, DecodeHex('0a0b'), 32);
    LClient.CloseNotify;
    LServer.Finish;
    CheckEquals(32, System.Length(LExported), 'the exporter produced the requested length');
    CheckEqualBytes('both ends derive the same secret', LServer.Exported, LExported);
    CheckEquals(32, System.Length(LWithContext), 'the context form produced the length too');
    CheckFalse(AreEqual(LExported, LWithContext), 'a context changes the secret');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

function TTestTlsStreamLoopback.BlockingVerify(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  FVerifyEntered.SetEvent;
  // bounded so a failing test cannot hang the run
  FVerifyRelease.WaitFor(20000);
  Result := True;
end;

procedure TTestTlsStreamLoopback.HandshakeQueried;
begin
  FQueried.Handshake;
end;

procedure TTestTlsStreamLoopback.HandshakeCapped;
begin
  FQueried.Handshake(30000);
end;

procedure TTestTlsStreamLoopback.HandshakeThenSignal;
begin
  try
    FQueried.Handshake;
  finally
    FQueryDone.SetEvent;
  end;
end;

function TTestTlsStreamLoopback.ClosingVerify(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  FQueriedVersion := FQueried.ConnectionInfo.NegotiatedVersion.WireValue;
  FQueriedPending := FQueried.PendingReadBytes;
  FQueried.CloseNotify;
  Result := True;
end;

procedure TTestTlsStreamLoopback.TestHandshakeCallbackMayQueryAndCloseItsOwnConnection;
var
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LHandshaker: TActionThread;
  LReturned, LRaised: Boolean;
begin
  FQueryDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPingBytes := DecodeHex(PingHex);
  RunLoopback(ClientConfig(False, ClosingVerify), TServerBehavior.EchoThenClose, FQueried,
    LServer, LTransport);
  Own<TTlsStream>(FQueried);
  LHandshaker := Own<TActionThread>(TActionThread.Create(HandshakeThenSignal));
  try
    LHandshaker.Start;
    LReturned := FQueryDone.WaitFor(20000) = wrSignaled;
  finally
    LServer.Finish;
  end;
  LHandshaker.WaitFor;
  CheckTrue(LReturned, 'the handshake returned although its callback called back');
  CheckEquals('', LHandshaker.Error, 'and raised nothing');
  CheckEquals(0, Integer(FQueriedVersion), 'the callback saw the zero facts of a running handshake');
  CheckEquals(0, FQueriedPending, 'and no pending bytes');
  LRaised := False;
  try
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the close the callback asked for took effect: a write raises');
  LServer.Free;
end;

procedure TTestTlsStreamLoopback.QueryQueried;
begin
  FQueriedVersion := FQueried.ConnectionInfo.NegotiatedVersion.WireValue;
  FQueriedPending := FQueried.PendingReadBytes;
  FQueriedComplete := FQueried.IsHandshakeComplete;
  FQueryDone.SetEvent;
end;

procedure TTestTlsStreamLoopback.TestQueriesAnswerAtOnceWhileTheHandshakeRuns;
var
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LHandshaker, LQuerier: TActionThread;
  LAnswered, LStarted: Boolean;
begin
  FVerifyEntered := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FVerifyRelease := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FQueryDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  RunLoopback(ClientConfig(False, BlockingVerify), TServerBehavior.EchoThenClose, FQueried,
    LServer, LTransport);
  Own<TTlsStream>(FQueried);
  LHandshaker := Own<TActionThread>(TActionThread.Create(HandshakeQueried));
  LQuerier := Own<TActionThread>(TActionThread.Create(QueryQueried));
  LStarted := False;
  try
    LHandshaker.Start;
    LStarted := True;
    CheckTrue(FVerifyEntered.WaitFor(20000) = wrSignaled,
      'the handshake reached the host''s certificate callback');
    // the handshake now sits inside the callback holding the engine
    LQuerier.Start;
    LAnswered := FQueryDone.WaitFor(5000) = wrSignaled;
    FVerifyRelease.SetEvent;
    LQuerier.WaitFor;
    LHandshaker.WaitFor;
    CheckTrue(LAnswered, 'the queries returned while the handshake was parked in the callback');
    CheckEquals(0, Integer(FQueriedVersion), 'a running handshake reports no negotiated version');
    CheckEquals(0, FQueriedPending, 'and no pending bytes');
    CheckFalse(FQueriedComplete, 'and is not complete');
    CheckEquals('', LHandshaker.Error, 'the handshake finished once released');
    CheckTrue(FQueried.IsHandshakeComplete, 'and reports complete afterwards');
    CheckTrue(FQueried.ConnectionInfo.NegotiatedVersion.WireValue <> 0,
      'the facts are the engine''s once it has finished');
    FQueried.CloseNotify;
    LServer.Finish;
  finally
    FVerifyRelease.SetEvent;
    // the handshake thread is joined before the stream it uses is freed
    if LStarted then
      LHandshaker.WaitFor;
    LServer.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestInfoOfAFailedHandshakeIsTheEnginesNotZero;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LConfig: ITlsClientConfig;
  LRaised: Boolean;
begin
  // a client that trusts an unrelated anchor rejects the chain after the version was negotiated
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert')).Build).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  try
    LRaised := False;
    try
      LClient.Handshake;
    except
      on ETlsStreamError do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'the untrusted chain fails the handshake');
    CheckTrue(LClient.ConnectionInfo.NegotiatedVersion.WireValue <> 0,
      'after a failed handshake the facts are the engine''s, not the zero values of a running one');
    LServer.Finish;
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestTerminalSendOnAStalledSocketIsBoundedByTheCloseGrace;
var
  LClient, LServer: ITlsEngine;
  LClock: ITlsMonotonicClock;
  LStalled: TStalledTransport;
  LPump: TTlsStreamPump;
  LDest, LByte: TBytes;
  LStatus: TTlsReadStatus;
  LStart: Int64;
  LRaisedAlert: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  // the clock moves 100 ms per reading, so a 500 ms grace is spent without waiting
  LClock := TMockMonotonicClock.Create(1000, 100) as ITlsMonotonicClock;
  LStalled := TStalledTransport.Create(DecodeHex(BadRecordHex), LClock);
  LPump := Own<TTlsStreamPump>(TTlsStreamPump.Create(LClient, LStalled as ITlsTransport, 500));
  System.SetLength(LDest, 16);
  LStart := LClock.NowMonotonicMillis;
  LRaisedAlert := False;
  try
    LPump.ReadApp(LDest, 16, LStatus);
  except
    on E: ETlsStreamError do
      LRaisedAlert := E.HasAlert and (E.Alert = TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaisedAlert, 'the read raises the bad record, not the failed send');
  CheckEquals(0, LStalled.Sends, 'the alert never reached the stalled socket');
  CheckTrue(LClock.NowMonotonicMillis - LStart >= 500, 'the send waited out the grace');
  CheckTrue(LClient.LastError.Origin <> TTlsErrorOrigin.Transport,
    'the expired send does not replace the TLS reason');
  CheckFalse(LClient.WantsWrite, 'the alert that could not be sent was dropped');
  LByte := DecodeHex('00');
  LStalled.Write(LByte, 0, 1);
  CheckEquals(1, LStalled.Sends, 'the write deadline was cleared when the send ended');
end;

procedure TTestTlsStreamLoopback.TestCloseNotifyOnAStalledSocketRaisesAWriteTimeout;
var
  LClient, LServer: ITlsEngine;
  LClock: ITlsMonotonicClock;
  LStalled: TStalledTransport;
  LByte: TBytes;
  LRaised: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LClock := TMockMonotonicClock.Create(1000, 100) as ITlsMonotonicClock;
  LStalled := TStalledTransport.Create(nil, LClock);
  LRaised := False;
  try
    Own<TTlsStreamPump>(TTlsStreamPump.Create(LClient, LStalled as ITlsTransport, 500)).Close;
  except
    on ETlsWriteTimeout do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a close_notify the socket will not take raises the write timeout');
  CheckEquals(0, LStalled.Sends, 'and never reached the socket');
  CheckTrue(LClient.IsTerminal, 'the connection is latched failed');
  LByte := DecodeHex('00');
  LStalled.Write(LByte, 0, 1);
  CheckEquals(1, LStalled.Sends, 'the write deadline was cleared when the send ended');
end;

procedure TTestTlsStreamLoopback.WritePumped;
begin
  FPumped.WriteApp(FPumpedByte[0], 1);
end;

procedure TTestTlsStreamLoopback.ReadPumped;
var
  LStatus: TTlsReadStatus;
begin
  try
    FPumped.ReadApp(FPumpedBuffer, System.Length(FPumpedBuffer), LStatus);
  finally
    FReaderDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.ClosePumped;
begin
  try
    FPumped.Close;
  finally
    FReaderDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.TestReaderDoesNotWaitForTheWriteSide;
var
  LClient, LServer: ITlsEngine;
  LGated: TGatedTransport;
  LWriter, LReader: TActionThread;
  LReturned: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LGated := TGatedTransport.Create(DecodeHex(BadRecordHex));
  FPumped := NewPump(LClient, LGated as ITlsTransport);
  FPumpedByte := DecodeHex('00');
  System.SetLength(FPumpedBuffer, 16);
  FReaderDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  LWriter := Own<TActionThread>(TActionThread.Create(WritePumped));
  LReader := Own<TActionThread>(TActionThread.Create(ReadPumped));
  LWriter.Start;
  try
    CheckTrue(LGated.WaitEntered(20000), 'the writer is inside its send, holding the write side');
    LReader.Start;
    // the bad record makes the engine terminal while the writer holds the write side: the reader
    // leaves the alert to that writer rather than wait for it
    LReturned := FReaderDone.WaitFor(5000) = wrSignaled;
  finally
    LGated.Open;
  end;
  LWriter.WaitFor;
  LReader.WaitFor;
  CheckTrue(LReturned, 'the read returned without waiting for the writer');
  CheckTrue(Pos('ETlsStreamError', LReader.Error) = 1, 'the read raised the bad record');
  CheckEquals(Ord(TTlsAlertDescription.BadRecordMac), Ord(LClient.LastError.Alert.Description),
    'the engine recorded the bad record');
  CheckTrue(Pos('ETlsStreamError', LWriter.Error) = 1, 'the write fails with the recorded alert');
  CheckTrue(LGated.Writes >= 2, 'the writer sent the alert the reader left owed');
end;

procedure TTestTlsStreamLoopback.TestCloseDoesNotWaitForTheWriteSide;
var
  LClient, LServer: ITlsEngine;
  LGated: TGatedTransport;
  LWriter, LCloser: TActionThread;
  LReturned: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LGated := TGatedTransport.Create(nil);
  FPumped := NewPump(LClient, LGated as ITlsTransport);
  FPumpedByte := DecodeHex('00');
  FReaderDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  LWriter := Own<TActionThread>(TActionThread.Create(WritePumped));
  LCloser := Own<TActionThread>(TActionThread.Create(ClosePumped));
  LWriter.Start;
  try
    CheckTrue(LGated.WaitEntered(20000), 'the writer is inside its send, holding the write side');
    LCloser.Start;
    LReturned := FReaderDone.WaitFor(5000) = wrSignaled;
  finally
    LGated.Open;
  end;
  LWriter.WaitFor;
  LCloser.WaitFor;
  CheckTrue(LReturned, 'close_notify returned without waiting for the writer');
  CheckEquals('', LCloser.Error, 'and raised nothing');
  CheckEquals('', LWriter.Error, 'the writer finished its message');
  CheckTrue(LGated.Writes >= 2, 'the writer sent the close_notify the closer left owed');
end;

procedure TTestTlsStreamLoopback.StartTimedEchoPair(out AClient: TTlsStream;
  out AClientTransport: TPipeTimedTransport);
var
  LC2S, LS2C: TMemoryPipe;
  LClientT, LServerT: ITlsTransport;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  AClientTransport := TPipeTimedTransport.Create(LS2C, LC2S);
  LClientT := AClientTransport as ITlsTransport;
  LServerT := TMemoryTransport.Create(LC2S, LS2C) as ITlsTransport;
  AClient := NewClientStream(LClientT, ClientConfig(False, nil));
  FServing := Own<TTlsStream>(NewServerStream(LServerT));
end;

procedure TTestTlsStreamLoopback.ServeTimedEcho;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  FServing.Handshake;
  System.SetLength(LChunk, 4096);
  LGot := FServing.Read(LChunk[0], System.Length(LChunk));
  if LGot > 0 then
    FServing.Write(LChunk[0], LGot);
  FServing.CloseNotify;
end;

procedure TTestTlsStreamLoopback.TestApplicationReadCapIsArmedInsideTheReadSideAndCleared;
var
  LClient: TTlsStream;
  LTransport: TPipeTimedTransport;
  LServing: TActionThread;
  LBuf, LPing: TBytes;
  LGot: Int32;
  LTimedOut: Boolean;
begin
  StartTimedEchoPair(LClient, LTransport);
  LServing := Own<TActionThread>(TActionThread.Create(ServeTimedEcho));
  LServing.Start;
  try
    LClient.Handshake;
    System.SetLength(LBuf, 4096);
    LTimedOut := False;
    try
      LClient.ReadTimed(LBuf[0], System.Length(LBuf), 150);
    except
      on ETlsReadTimeout do
        LTimedOut := True;
    end;
    CheckTrue(LTimedOut, 'a silent peer under the application cap raises the retryable timeout');
    CheckEquals(0, LTransport.ArmedReadTimeoutMs, 'the cap is cleared although the read raised');
    LPing := DecodeHex(PingHex);
    LClient.Write(LPing[0], System.Length(LPing));
    LGot := LClient.ReadTimed(LBuf[0], System.Length(LBuf), 20000);
    CheckEqualBytes('the retried read returns the echo', LPing, System.Copy(LBuf, 0, LGot));
    CheckEquals(0, LTransport.ArmedReadTimeoutMs, 'the cap is cleared after a read that returned');
    LClient.CloseNotify;
  finally
    // ends a server still waiting for the message
    LTransport.CloseWrite;
    LServing.WaitFor;
    LClient.Free;
  end;
  CheckEquals('', LServing.Error, 'the server side ran without error');
end;

procedure TTestTlsStreamLoopback.TestHandshakeReadCapIsArmedAndClearedAroundTheHandshake;
var
  LC2S, LS2C: TMemoryPipe;
  LTransport: TPipeTimedTransport;
  LClient: TTlsStream;
  LFirst, LSecond: Boolean;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LTransport := TPipeTimedTransport.Create(LS2C, LC2S);
  LClient := NewClientStream(LTransport as ITlsTransport, ClientConfig(False, nil));
  try
    LFirst := False;
    try
      LClient.Handshake(150);
    except
      on ETlsHandshakeTimeout do
        LFirst := True;
    end;
    CheckTrue(LFirst, 'a silent peer under the handshake cap raises the handshake timeout');
    CheckEquals(0, LTransport.ArmedReadTimeoutMs, 'the cap is cleared although the handshake raised');
    LSecond := False;
    try
      LClient.Handshake(150);
    except
      on ETlsHandshakeTimeout do
        LSecond := True;
    end;
    CheckTrue(LSecond, 'the failure is latched, not retried');
  finally
    LClient.Free;
    LS2C.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestReadTimeoutNeedsATimedTransport;
var
  LClient: TTlsStream;
  LBuf: TBytes;
  LReadRaised, LHandshakeRaised: Boolean;
begin
  LClient := NewClientStream(TRecordingTransport.Create as ITlsTransport,
    ClientConfig(False, nil));
  try
    System.SetLength(LBuf, 16);
    LReadRaised := False;
    try
      LClient.ReadTimed(LBuf[0], 16, 100);
    except
      on EInvalidOperationTlsLibException do
        LReadRaised := True;
    end;
    LHandshakeRaised := False;
    try
      LClient.Handshake(100);
    except
      on EInvalidOperationTlsLibException do
        LHandshakeRaised := True;
    end;
    CheckTrue(LReadRaised, 'a read timeout on a plain transport is refused, not ignored');
    CheckTrue(LHandshakeRaised, 'so is a handshake timeout');
  finally
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.ServeConnection;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  FServerConnection.Handshake(0);
  FServerExported := FServerConnection.ExportKeyingMaterial(ExporterLabel, 32);
  System.SetLength(LChunk, 4096);
  LGot := FServerConnection.Read(LChunk[0], System.Length(LChunk));
  if LGot > 0 then
    FServerConnection.Write(LChunk[0], LGot);
  FServerConnection.CloseNotify;
end;

procedure TTestTlsStreamLoopback.TestConnectionForwardsKeyUpdateAndExporter;
var
  LC2S, LS2C: TMemoryPipe;
  LClientTransport: TPipeTimedTransport;
  LClientT, LServerT: ITlsTimedTransport;
  LClient: TTlsConnection;
  LServing: TActionThread;
  LPing, LEcho, LExported, LWithContext: TBytes;
  LGot: Int32;
begin
  CheckEquals(5000, TTlsConnection.DefaultCloseGraceMs, 'terminal sends are bounded by 5 s');
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientTransport := TPipeTimedTransport.Create(LS2C, LC2S);
  LClientT := LClientTransport as ITlsTimedTransport;
  LServerT := TPipeTimedTransport.Create(LC2S, LS2C) as ITlsTimedTransport;
  LClient := Own<TTlsConnection>(TTlsConnection.CreateClient(ClientConfig(False, nil),
    'localhost', LClientT, nil, 0));
  FServerConnection := Own<TTlsConnection>(TTlsConnection.CreateServer(ServerConfig, LServerT,
    nil, 0));
  LServing := Own<TActionThread>(TActionThread.Create(ServeConnection));
  LServing.Start;
  try
    LClient.Handshake(0);
    LClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateRequested);
    LExported := LClient.ExportKeyingMaterial(ExporterLabel, 32);
    LWithContext := LClient.ExportKeyingMaterial(ExporterLabel, DecodeHex('0a0b'), 32);
    LPing := DecodeHex(PingHex);
    LClient.Write(LPing[0], System.Length(LPing));
    System.SetLength(LEcho, 4096);
    LGot := LClient.Read(LEcho[0], System.Length(LEcho));
    CheckEqualBytes('the peer follows the rekey and echoes', LPing, System.Copy(LEcho, 0, LGot));
    LClient.CloseNotify;
  finally
    LClientTransport.CloseWrite;
    LServing.WaitFor;
  end;
  CheckEquals('', LServing.Error, 'the server side ran without error');
  CheckEquals(32, System.Length(LExported), 'the exporter produced the requested length');
  CheckEqualBytes('both ends derive the same secret', FServerExported, LExported);
  CheckFalse(AreEqual(LExported, LWithContext), 'a context changes the secret');
end;

function TTestTlsStreamLoopback.ParkedResolver(const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  FVerifyEntered.SetEvent;
  // bounded so a failing test cannot hang the run
  FVerifyRelease.WaitFor(20000);
  Result := True;
end;

procedure TTestTlsStreamLoopback.StartParkedHandshake(out AServer: TServerRunner);
var
  LTransport: TMemoryTransport;
begin
  FVerifyEntered := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FVerifyRelease := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FReaderDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FSecondDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPause := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPingBytes := DecodeHex(PingHex);
  System.SetLength(FReadBuffer, 4096);
  RunLoopback(AsyncClientConfig, TServerBehavior.EchoThenClose, FQueried, AServer, LTransport);
  // the client is registered first, so the server (which uses its transport) is freed before it
  Own<TTlsStream>(FQueried);
  Own<TServerRunner>(AServer);
  FQueried.SetCertificateVerdictResolver(ParkedResolver);
end;

procedure TTestTlsStreamLoopback.HandshakeRepeated;
begin
  try
    FQueried.Handshake;
    FQueried.Handshake(150);
  finally
    FSecondDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.ReadQueried;
begin
  try
    FReadCount := FQueried.Read(FReadBuffer[0], System.Length(FReadBuffer));
  finally
    FReaderDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.WriteQueried;
begin
  try
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
  finally
    FSecondDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.TimedReadQueried;
begin
  try
    FReadCount := FQueried.ReadTimed(FReadBuffer[0], System.Length(FReadBuffer), 20000);
  finally
    FReaderDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.ShortTimedReadQueried;
var
  LBuffer: TBytes;
begin
  try
    System.SetLength(LBuffer, 4096);
    FQueried.ReadTimed(LBuffer[0], System.Length(LBuffer), 150);
  finally
    FSecondDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.KeyUpdatePumped;
begin
  try
    FPumped.RequestKeyUpdate(TKeyUpdateRequest.UpdateRequested);
  finally
    FSecondDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.TestReaderThatDroveTheHandshakeDoesNotBlockAWriter;
var
  LServer: TServerRunner;
  LReader, LWriter: TActionThread;
  LWrote, LRead: Boolean;
begin
  StartParkedHandshake(LServer);
  LReader := Own<TActionThread>(TActionThread.Create(ReadQueried));
  LWriter := Own<TActionThread>(TActionThread.Create(WriteQueried));
  try
    LReader.Start;
    CheckTrue(FVerifyEntered.WaitFor(20000) = wrSignaled, 'the reader is driving the handshake');
    LWriter.Start;
    // the write has to be waiting for the handshake when it completes
    FPause.WaitFor(300);
    FVerifyRelease.SetEvent;
    LWrote := FSecondDone.WaitFor(10000) = wrSignaled;
    LRead := FReaderDone.WaitFor(10000) = wrSignaled;
  finally
    FVerifyRelease.SetEvent;
    // ends a server still waiting for the request, and with it a reader blocked on the server
    LServer.Finish;
  end;
  LWriter.WaitFor;
  LReader.WaitFor;
  CheckTrue(LWrote, 'the write was not stuck behind the reader that ran the handshake');
  CheckTrue(LRead, 'the reader got the echo of that write');
  CheckEquals('', LReader.Error, 'the read ran without error');
  CheckEquals('', LWriter.Error, 'the write ran without error');
  CheckEqualBytes('the echo', FPingBytes, System.Copy(FReadBuffer, 0, FReadCount));
end;

procedure TTestTlsStreamLoopback.TestHandshakeCallDoesNotWaitForABlockedReader;
var
  LServer: TServerRunner;
  LReader, LRepeater: TActionThread;
  LReturned: Boolean;
begin
  StartParkedHandshake(LServer);
  FVerifyRelease.SetEvent;
  FQueried.Handshake;
  LReader := Own<TActionThread>(TActionThread.Create(ReadQueried));
  LRepeater := Own<TActionThread>(TActionThread.Create(HandshakeRepeated));
  try
    LReader.Start;
    // the reader is blocked on the server, which waits for a request
    FPause.WaitFor(300);
    LRepeater.Start;
    LReturned := FSecondDone.WaitFor(5000) = wrSignaled;
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
    FReaderDone.WaitFor(10000);
  finally
    LServer.Finish;
  end;
  LRepeater.WaitFor;
  LReader.WaitFor;
  CheckTrue(LReturned, 'a repeated Handshake is a no-op that does not wait for the reader');
  CheckEquals('', LRepeater.Error, 'and raises nothing');
  CheckEqualBytes('the blocked reader still got its echo', FPingBytes,
    System.Copy(FReadBuffer, 0, FReadCount));
end;

procedure TTestTlsStreamLoopback.TestCloseNotifyDuringTheHandshakeIsSentAsItCompletes;
var
  LServer: TServerRunner;
  LHandshaker, LReader: TActionThread;
  LEnded, LRaised: Boolean;
begin
  StartParkedHandshake(LServer);
  LHandshaker := Own<TActionThread>(TActionThread.Create(HandshakeQueried));
  LReader := Own<TActionThread>(TActionThread.Create(ReadQueried));
  try
    LHandshaker.Start;
    CheckTrue(FVerifyEntered.WaitFor(20000) = wrSignaled, 'the handshake is parked');
    FQueried.CloseNotify;
    FVerifyRelease.SetEvent;
    LHandshaker.WaitFor;
    CheckEquals('', LHandshaker.Error, 'the handshake completed');
    LReader.Start;
    // the server read our close_notify and answered with its own: a clean end of stream
    LEnded := FReaderDone.WaitFor(10000) = wrSignaled;
  finally
    FVerifyRelease.SetEvent;
    LServer.Finish;
  end;
  LReader.WaitFor;
  CheckTrue(LEnded, 'the close_notify requested during the handshake reached the peer');
  CheckEquals(0, FReadCount, 'and the peer ended the stream cleanly');
  CheckEquals('', LServer.Error, 'the server saw a clean close, not a truncation');
  LRaised := False;
  try
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the write side stayed closed');
end;

procedure TTestTlsStreamLoopback.TestSendAlertDuringTheHandshakeRefusesTheConnection;
var
  LServer: TServerRunner;
  LHandshaker: TActionThread;
  LRefused: Boolean;
begin
  StartParkedHandshake(LServer);
  LHandshaker := Own<TActionThread>(TActionThread.Create(HandshakeQueried));
  try
    LHandshaker.Start;
    CheckTrue(FVerifyEntered.WaitFor(20000) = wrSignaled, 'the handshake is parked');
    FQueried.SendAlert(TTlsAlertDescription.BadCertificate);
    FVerifyRelease.SetEvent;
    LHandshaker.WaitFor;
  finally
    FVerifyRelease.SetEvent;
    // the refused server fails on the alert; a lost alert would leave it waiting for this end
    LServer.Finish;
  end;
  CheckEquals('', LHandshaker.Error, 'the handshake itself completed');
  CheckTrue(Pos('the peer sent a fatal alert', LServer.Error) > 0,
    'the alert requested during the handshake reached the peer');
  LRefused := False;
  try
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
  except
    on E: ETlsStreamError do
      LRefused := E.HasAlert and (E.Alert = TTlsAlertDescription.BadCertificate);
  end;
  CheckTrue(LRefused, 'the connection never went live: a write raises the refusal');
end;

procedure TTestTlsStreamLoopback.TestRequestKeyUpdateAfterCloseNotifyRaises;
var
  LClient: TTlsStream;
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LRaised: Boolean;
begin
  RunLoopback(ClientConfig(False, nil), TServerBehavior.EchoThenClose, LClient, LServer,
    LTransport);
  try
    LClient.Handshake;
    LClient.CloseNotify;
    LRaised := False;
    try
      LClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateRequested);
    except
      on EInvalidOperationTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a rekey on a closed write side raises, as a write does');
    LServer.Finish;
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestRequestKeyUpdateAfterAPreHandshakeCloseNotifyRefusesWithoutHandshaking;
var
  LClient: TTlsStream;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LRaised: Boolean;
begin
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LClient := NewClientStream(LTransport, ClientConfig(False, nil));
  try
    LClient.CloseNotify;
    LRaised := False;
    try
      LClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateRequested);
    except
      on EInvalidOperationTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a rekey after a pre-handshake close raises, as a write does');
    CheckEquals(0, LRecorder.Written, 'and ran no handshake');
  finally
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestRepeatedPumpHandshakeKeepsTheStateComplete;
var
  LC2S, LS2C: TMemoryPipe;
  LClientTransport, LServerTransport: TMemoryTransport;
  LClientT, LServerT: ITlsTransport;
  LConfig: ITlsClientConfig;
  LPump: TTlsStreamPump;
  LServer: TServerRunner;
begin
  LConfig := ClientConfig(False, nil);
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LClientT := LClientTransport;
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LServerT := LServerTransport;
  // the pump is registered before the server, which uses the client transport, so it outlives it
  LPump := NewPump(TTlsEngineFactory.CreateClientEngine(LConfig, 'localhost'), LClientT);
  LServer := Own<TServerRunner>(TServerRunner.Create(NewServerStream(LServerT),
    LServerTransport, LClientTransport, TServerBehavior.EchoThenClose));
  LServer.Start;
  try
    LPump.DriveHandshake(True);
    CheckTrue(LPump.IsHandshakeComplete, 'the handshake completed');
    LPump.DriveHandshake(True);
    CheckTrue(LPump.IsHandshakeComplete, 'a second call leaves it complete');
    CheckTrue(LPump.CloseWriteSide, 'so a close still owes its close_notify');
  finally
    LServer.Finish;
  end;
end;

procedure TTestTlsStreamLoopback.TestReleaseWriteSendsWhatWasSealedAfterTheLastCheck;
var
  LClient, LServer, LEngine: ITlsEngine;
  LDouble: TSealAfterDrainEngine;
  LGated: TGatedTransport;
  LGatedT: ITlsTransport;
  LByte, LWire: TBytes;
begin
  HandshakeEngines(LClient, LServer);
  LDouble := TSealAfterDrainEngine.Create(LClient);
  LEngine := LDouble;
  LGated := TGatedTransport.Create(nil);
  LGatedT := LGated;
  LGated.Open;
  FPumped := NewPump(LEngine, LGatedT);
  LByte := DecodeHex('00');
  FPumped.WriteApp(LByte[0], 1);
  CheckTrue(LDouble.Sealed, 'close_notify was sealed after the writer''s last check');
  LWire := LGated.Captured;
  LServer.ProcessInput(LWire, 0, System.Length(LWire));
  CheckEquals(1, LServer.PendingAppData, 'the write reached the peer');
  CheckTrue(LServer.IsInboundClosed, 'and so did the close_notify sealed behind it');
end;

procedure TTestTlsStreamLoopback.TestReadCapsAreArmedAndClearedInsideTheReadSide;
var
  LC2S, LS2C: TMemoryPipe;
  LInner: TPipeTimedTransport;
  LServerTransport: TMemoryTransport;
  LInnerT: ITlsTimedTransport;
  LLog: TCapLogTransport;
  LLogT, LServerT: ITlsTransport;
  LConfig: ITlsClientConfig;
  LServing, LLong, LShort: TActionThread;
  LWaited: Int32;
begin
  FReaderDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FSecondDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPause := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPingBytes := DecodeHex(PingHex);
  System.SetLength(FReadBuffer, 4096);
  LConfig := ClientConfig(False, nil);
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LInner := TPipeTimedTransport.Create(LS2C, LC2S);
  LInnerT := LInner;
  LLog := TCapLogTransport.Create(LInnerT);
  LLogT := LLog;
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LServerT := LServerTransport;
  FQueried := Own<TTlsStream>(NewClientStream(LLogT, LConfig));
  FServing := Own<TTlsStream>(NewServerStream(LServerT));
  LServing := Own<TActionThread>(TActionThread.Create(ServeTimedEcho));
  LLong := Own<TActionThread>(TActionThread.Create(TimedReadQueried));
  LShort := Own<TActionThread>(TActionThread.Create(ShortTimedReadQueried));
  LServing.Start;
  try
    FQueried.Handshake;
    LLong.Start;
    LWaited := 0;
    while (LLog.Log = '') and (LWaited < 5000) do
    begin
      FPause.WaitFor(10);
      System.Inc(LWaited, 10);
    end;
    LShort.Start;
    FPause.WaitFor(300);
    CheckEquals('a20000;', LLog.Log,
      'a reader waiting for the read side has armed nothing on the transport');
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
    CheckTrue(FReaderDone.WaitFor(10000) = wrSignaled, 'the first reader got the echo');
    CheckTrue(FSecondDone.WaitFor(10000) = wrSignaled, 'and then the second reader ran');
  finally
    // ends a server still waiting for the message, and with it any read still blocked on it
    LInner.CloseWrite;
    LServerTransport.CloseWrite;
  end;
  LServing.WaitFor;
  LLong.WaitFor;
  LShort.WaitFor;
  CheckEquals('', LLong.Error, 'the first reader was not bounded by the other one''s cap');
  CheckEquals('', LShort.Error, 'the second read ended cleanly');
  CheckEqualBytes('the echo', FPingBytes, System.Copy(FReadBuffer, 0, FReadCount));
  CheckEquals('a20000;c;a150;c;', LLog.Log,
    'each cap was armed and cleared inside the read side that used it');
end;

procedure TTestTlsStreamLoopback.TestPlainReadAfterTheHandshakeDoesNotInheritItsCap;
var
  LC2S, LS2C: TMemoryPipe;
  LInner: TPipeTimedTransport;
  LServerTransport: TMemoryTransport;
  LInnerT: ITlsTimedTransport;
  LLog: TCapLogTransport;
  LLogT, LServerT: ITlsTransport;
  LClock: TMockMonotonicClock;
  LClockRef: ITlsMonotonicClock;
  LServing, LHandshaker, LReader: TActionThread;
  LWaited: Int32;
  LEnded: Boolean;
begin
  FReaderDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPause := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPingBytes := DecodeHex(PingHex);
  System.SetLength(FReadBuffer, 4096);
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClock := TMockMonotonicClock.Create(0);
  LClockRef := LClock;
  LInner := TPipeTimedTransport.Create(LS2C, LC2S);
  LInnerT := LInner;
  LInnerT.UseClock(LClockRef);
  LLog := TCapLogTransport.Create(LInnerT);
  LLogT := LLog;
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LServerT := LServerTransport;
  FQueried := Own<TTlsStream>(NewClientStream(LLogT, ClientConfig(False, nil)));
  FServing := Own<TTlsStream>(NewServerStream(LServerT));
  LServing := Own<TActionThread>(TActionThread.Create(ServeTimedEcho));
  LHandshaker := Own<TActionThread>(TActionThread.Create(HandshakeCapped));
  LReader := Own<TActionThread>(TActionThread.Create(ReadQueried));
  LServing.Start;
  LHandshaker.Start;
  try
    // the log holds the handshake thread in the clearing of its cap, which comes after the
    // handshake completed
    LWaited := 0;
    while (not FQueried.IsHandshakeComplete) and (LWaited < 20000) do
    begin
      FPause.WaitFor(5);
      System.Inc(LWaited, 5);
    end;
    CheckTrue(FQueried.IsHandshakeComplete, 'the handshake completed');
    // the handshake cap has run out, as it does for a connection that was quiet that long
    LClock.Advance(60000);
    LReader.Start;
    LEnded := FReaderDone.WaitFor(700) = wrSignaled;
    if LEnded then
    begin
      LReader.WaitFor;
      Fail('a plain read waits for data under no cap, but ended with ' + LReader.Error);
    end;
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
    CheckTrue(FReaderDone.WaitFor(10000) = wrSignaled, 'the read got the echo');
  finally
    // ends a server still waiting for the message, and with it any read still blocked on it
    LInner.CloseWrite;
    LServerTransport.CloseWrite;
  end;
  LServing.WaitFor;
  LHandshaker.WaitFor;
  LReader.WaitFor;
  CheckEquals('', LHandshaker.Error, 'the handshake completed');
  CheckEquals('', LReader.Error, 'the read was not bounded by the cap of the handshake');
  CheckEqualBytes('the echo', FPingBytes, System.Copy(FReadBuffer, 0, FReadCount));
  CheckEquals('h30000;c;', LLog.Log, 'the read armed no cap of its own');
end;

procedure TTestTlsStreamLoopback.TestRequestKeyUpdateWaitsForTheWriteSide;
var
  LClient, LServer: ITlsEngine;
  LGated: TGatedTransport;
  LGatedT: ITlsTransport;
  LWriter, LRekeyer: TActionThread;
  LReturned: Boolean;
  LWire: TBytes;
  LEvent: ITlsEvent;
  LKeyUpdates: Int32;
begin
  HandshakeEngines(LClient, LServer);
  LGated := TGatedTransport.Create(nil);
  LGatedT := LGated;
  FPumped := NewPump(LClient, LGatedT);
  FPumpedByte := DecodeHex('00');
  FSecondDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  LWriter := Own<TActionThread>(TActionThread.Create(WritePumped));
  LRekeyer := Own<TActionThread>(TActionThread.Create(KeyUpdatePumped));
  LWriter.Start;
  try
    CheckTrue(LGated.WaitEntered(20000), 'the writer is inside its send, holding the write side');
    LRekeyer.Start;
    LReturned := FSecondDone.WaitFor(500) = wrSignaled;
  finally
    LGated.Open;
  end;
  LWriter.WaitFor;
  LRekeyer.WaitFor;
  CheckFalse(LReturned, 'the rekey waited for the writer to let go of the write side');
  CheckEquals('', LRekeyer.Error, 'and then ran without error');
  LWire := LGated.Captured;
  LServer.ProcessInput(LWire, 0, System.Length(LWire));
  LKeyUpdates := 0;
  while LServer.NextEvent(LEvent) do
    if LEvent.Kind = TTlsEventKind.KeyUpdateReceived then
      System.Inc(LKeyUpdates);
  CheckEquals(1, LKeyUpdates, 'the KeyUpdate reached the peer');
  CheckEquals(1, LServer.PendingAppData, 'behind the writer''s record, which the old keys sealed');
  CheckFalse(LServer.IsTerminal, 'in an order the peer could decrypt');
end;

procedure TTestTlsStreamLoopback.ProbeQueried;
begin
  try
    FQueriedVersion := FQueried.ConnectionInfo.NegotiatedVersion.WireValue;
    FQueriedPending := FQueried.PendingReadBytes;
    FServerExported := FQueried.ExportKeyingMaterial(ExporterLabel, 32);
    FQueried.Write(FPingBytes[0], System.Length(FPingBytes));
  finally
    FQueryDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.ExportQueried;
begin
  try
    FServerExported := FQueried.ExportKeyingMaterial(ExporterLabel, 32);
  finally
    FQueryDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.QueryPumped;
begin
  try
    FQueriedVersion := FPumped.ConnectionInfo.NegotiatedVersion.WireValue;
    FQueriedPending := FPumped.PendingAppData;
  finally
    FSecondDone.SetEvent;
  end;
end;

procedure TTestTlsStreamLoopback.TestQueriesAndAWriteCompleteWhileAReadIsParked;
var
  LServer: TServerRunner;
  LTransport: TMemoryTransport;
  LReader, LProbe: TActionThread;
  LAnswered: Boolean;
begin
  FQueryDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FReaderDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FPingBytes := DecodeHex(PingHex);
  System.SetLength(FReadBuffer, 4096);
  RunLoopback(ClientConfig(False, nil), TServerBehavior.EchoThenClose, FQueried, LServer,
    LTransport);
  Own<TTlsStream>(FQueried);
  Own<TServerRunner>(LServer);
  LReader := Own<TActionThread>(TActionThread.Create(ReadQueried));
  LProbe := Own<TActionThread>(TActionThread.Create(ProbeQueried));
  try
    FQueried.Handshake;
    // the server waits for a request, so this read stays parked inside the transport
    LReader.Start;
    CheckTrue(LTransport.WaitReadParked(20000), 'the reader is waiting for data in the transport');
    LProbe.Start;
    LAnswered := FQueryDone.WaitFor(5000) = wrSignaled;
  finally
    // ends a server still waiting for the request, and with it the parked read
    LServer.Finish;
  end;
  LProbe.WaitFor;
  LReader.WaitFor;
  CheckTrue(LAnswered, 'the queries and a write returned while a read was parked in the transport');
  CheckEquals('', LProbe.Error, 'and raised nothing');
  CheckTrue(FQueriedVersion <> 0, 'the facts were the engine''s');
  CheckEquals(32, System.Length(FServerExported), 'the exporter answered');
  CheckEquals('', LReader.Error, 'the parked read got the echo of that write');
  CheckEqualBytes('the echo', FPingBytes, System.Copy(FReadBuffer, 0, FReadCount));
end;

procedure TTestTlsStreamLoopback.TestReadAndQueriesProceedWhileAWriterIsBlockedInASend;
var
  LClient, LServer: ITlsEngine;
  LGated: TGatedTransport;
  LWriter, LReader, LQuerier: TActionThread;
  LData: TBytes;
  LRead, LQueried: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LData := DecodeHex('0102');
  LServer.Write(LData, 0, 2);
  LGated := TGatedTransport.Create(TakeAll(LServer));
  FPumped := NewPump(LClient, LGated as ITlsTransport);
  FPumpedByte := DecodeHex('00');
  System.SetLength(FPumpedBuffer, 16);
  FReaderDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  FSecondDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  LWriter := Own<TActionThread>(TActionThread.Create(WritePumped));
  LReader := Own<TActionThread>(TActionThread.Create(ReadPumped));
  LQuerier := Own<TActionThread>(TActionThread.Create(QueryPumped));
  LWriter.Start;
  try
    CheckTrue(LGated.WaitEntered(20000), 'the writer is inside its send, holding the write side');
    LReader.Start;
    LQuerier.Start;
    LRead := FReaderDone.WaitFor(5000) = wrSignaled;
    LQueried := FSecondDone.WaitFor(5000) = wrSignaled;
  finally
    LGated.Open;
  end;
  LWriter.WaitFor;
  LReader.WaitFor;
  LQuerier.WaitFor;
  CheckTrue(LRead, 'the read returned inbound data while a send was blocked');
  CheckTrue(LQueried, 'and so did the queries');
  CheckEquals('', LReader.Error, 'the read raised nothing');
  CheckEquals(1, Integer(FPumpedBuffer[0]), 'it returned the record the peer sent');
  CheckTrue(FQueriedVersion <> 0, 'the facts were the engine''s');
end;

procedure TTestTlsStreamLoopback.TestExporterAnswersWhileAVerdictResolverIsParked;
var
  LServer: TServerRunner;
  LHandshaker, LExporter: TActionThread;
  LAnswered: Boolean;
begin
  StartParkedHandshake(LServer);
  FQueryDone := Own<TEvent>(TEvent.Create(nil, True, False, ''));
  LHandshaker := Own<TActionThread>(TActionThread.Create(HandshakeQueried));
  LExporter := Own<TActionThread>(TActionThread.Create(ExportQueried));
  try
    LHandshaker.Start;
    CheckTrue(FVerifyEntered.WaitFor(20000) = wrSignaled, 'the handshake is parked in the resolver');
    // the resolver runs with the engine lock free, so the exporter, which needs it, is answered
    LExporter.Start;
    LAnswered := FQueryDone.WaitFor(5000) = wrSignaled;
    FVerifyRelease.SetEvent;
    LHandshaker.WaitFor;
    LExporter.WaitFor;
  finally
    FVerifyRelease.SetEvent;
    LServer.Finish;
  end;
  CheckTrue(LAnswered, 'the exporter returned while the resolver was parked');
  CheckEquals('', LExporter.Error, 'with an answer, not an error');
  CheckEquals('', LHandshaker.Error, 'the handshake finished once released');
end;

procedure TTestTlsStreamLoopback.TestRecheckThatFindsADeadSocketDoesNotMaskTheWritersError;
var
  LClient, LServer, LEngine: ITlsEngine;
  LDouble: TSealAfterDrainEngine;
  LDead: TDeadWriteTransport;
  LDeadT: ITlsTransport;
  LByte: TBytes;
  LMessage: string;
begin
  HandshakeEngines(LClient, LServer);
  LDouble := TSealAfterDrainEngine.Create(LClient);
  LEngine := LDouble;
  LDouble.OwesAfterLatch := True;
  LDead := TDeadWriteTransport.Create;
  LDeadT := LDead;
  LByte := DecodeHex('00');
  LMessage := '';
  try
    // the write fails on the dead socket, and the recheck behind it finds a record owed
    NewPump(LEngine, LDeadT).WriteApp(LByte[0], 1);
  except
    on E: EInOutError do
      LMessage := E.Message;
  end;
  CheckEquals(2, LDead.Attempts, 'the recheck tried to send the record that was owed');
  CheckTrue(Pos('(write 1)', LMessage) > 0, 'the caller sees the failed write, not the recheck');
end;

procedure TTestTlsStreamLoopback.TestTerminalSendThatFindsTooLittleRoomIsBoundedByTheCloseGrace;
var
  LClient, LServer: ITlsEngine;
  LIn, LOut: TMemoryPipe;
  LTransport: TPipeTimedTransport;
  LTransportT: ITlsTransport;
  LWatch: TWedgeWatchdog;
  LJunk: TBytes;
  LRaised: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LIn := Own<TMemoryPipe>(TMemoryPipe.Create);
  // the transport owns the pipe it writes
  LOut := TMemoryPipe.Create(256);
  LTransport := TPipeTimedTransport.Create(LIn, LOut);
  LTransportT := LTransport;
  SetLength(LJunk, 246);
  // 10 bytes of room: the pipe is writable, but a close_notify record (24 bytes) does not fit
  CheckEquals(246, LOut.TryWrite(LJunk, 0, 246), 'nobody reads the pipe');
  LWatch := TWedgeWatchdog.Create(LIn, LOut, 20000);
  LWatch.Start;
  LRaised := False;
  try
    try
      Own<TTlsStreamPump>(TTlsStreamPump.Create(LClient, LTransportT, 300)).Close;
    except
      on ETlsWriteTimeout do
        LRaised := True;
    end;
  finally
    LWatch.Disarm;
    LWatch.WaitFor;
    CheckFalse(LWatch.Fired, 'the send ended on its own deadline, not the watchdog');
    LWatch.Free;
  end;
  CheckTrue(LRaised, 'a close_notify the pipe has no room for raises the write timeout');
end;

function TTestTlsStreamLoopback.Tls13Aes128Registry: ICipherSuiteRegistry;
var
  LBuilder: ICipherSuiteRegistryBuilder;
begin
  // the suite fixes the key length and hash the forger derives with
  LBuilder := TCipherSuiteRegistry.CreateDefault(Crypto).ToBuilder;
  LBuilder.Prune(TCipherSuites13.ChaCha20Poly1305Sha256);
  LBuilder.Prune(TCipherSuites13.Aes256GcmSha384);
  Result := LBuilder.Build;
end;

function TTestTlsStreamLoopback.PinnedClientConfig(const AKeyLog: IKeyLog): ITlsClientConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    .WithCipherSuites(Tls13Aes128Registry).WithDangerousKeyLog(AKeyLog).Build;
end;

function TTestTlsStreamLoopback.PinnedServerConfig: ITlsServerConfig;
begin
  Result := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key')))
    .WithCipherSuites(Tls13Aes128Registry).Build;
end;

procedure TTestTlsStreamLoopback.PinnedEngines(const AKeyLog: IKeyLog; out AClient,
  AServer: ITlsEngine);
begin
  HandshakeEnginesWith(PinnedClientConfig(AKeyLog), PinnedServerConfig, AClient, AServer);
  // the server's session tickets, if any, reach the client now
  PassOutgoing(AServer, AClient);
  PassOutgoing(AClient, AServer);
end;

function TTestTlsStreamLoopback.ClientTraffic0(const AKeyLog: TMockKeyLog): TBytes;
var
  LIndex: Int32;
begin
  Result := nil;
  for LIndex := 0 to AKeyLog.Count - 1 do
    if AKeyLog[LIndex].Lbl = KeyLogLabelClientTraffic0 then
      Result := AKeyLog[LIndex].Secret;
  CheckTrue(System.Length(Result) = 32, 'the key log holds the client''s first traffic secret');
end;

procedure TTestTlsStreamLoopback.TestSeveralKeyUpdatesInOneRecordAreFatalWithOneAlert;
var
  LKeyLog: TMockKeyLog;
  LKeyLogT: IKeyLog;
  LClient, LServer: ITlsEngine;
  LForger: TTrafficForger;
  LWire, LAlert: TBytes;
begin
  LKeyLog := TMockKeyLog.Create;
  LKeyLogT := LKeyLog;
  PinnedEngines(LKeyLogT, LClient, LServer);
  LForger := Own<TTrafficForger>(TTrafficForger.Create(Crypto, ClientTraffic0(LKeyLog)));
  // two KeyUpdate messages in one record: nothing may follow a read-key change within a record
  LWire := LForger.Seal(TTlsContentType.Handshake, DecodeHex('1800000101' + '1800000101'));
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LServer.ProcessInput(LWire, 0, System.Length(LWire))),
    'a record of two KeyUpdates is fatal');
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage),
    Ord(LServer.LastError.Alert.Description), 'with unexpected_message');
  LAlert := TakeAll(LServer);
  // header 5, alert 2, inner type 1, tag 16
  CheckEquals(24, System.Length(LAlert), 'exactly one alert record is owed');
  CheckEquals(0, System.Length(TakeAll(LServer)), 'and nothing else');
  LClient.ProcessInput(LAlert, 0, System.Length(LAlert));
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage),
    Ord(LClient.LastError.Alert.Description), 'the client reads the same alert');
end;

procedure TTestTlsStreamLoopback.TestSeveralKeyUpdatesInOneRecordFailTheStreamAndTheAlertReachesThePeer;
var
  LKeyLog: TMockKeyLog;
  LKeyLogT: IKeyLog;
  LC2S, LS2C: TMemoryPipe;
  LClientTransport, LServerTransport: TMemoryTransport;
  LClientT, LServerT: ITlsTransport;
  LClient: TTlsStream;
  LServer: TServerRunner;
  LWatch: TWedgeWatchdog;
  LForger: TTrafficForger;
  LWire, LBuf: TBytes;
  LAlert: TTlsAlertDescription;
  LAlerted: Boolean;
begin
  LKeyLog := TMockKeyLog.Create;
  LKeyLogT := LKeyLog;
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LClientT := LClientTransport;
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LServerT := LServerTransport;
  LClient := Own<TTlsStream>(NewClientStream(LClientT, PinnedClientConfig(LKeyLogT)));
  LServer := Own<TServerRunner>(TServerRunner.Create(
    TTlsStream.Create(LServerT, TTlsEngineFactory.CreateServerEngine(PinnedServerConfig), False,
    ''), LServerTransport, LClientTransport, TServerBehavior.EchoThenClose));
  LWatch := TWedgeWatchdog.Create(LC2S, LS2C, 20000);
  LWatch.Start;
  LServer.Start;
  try
    LClient.Handshake;
    LForger := Own<TTrafficForger>(TTrafficForger.Create(Crypto, ClientTraffic0(LKeyLog)));
    LWire := LForger.Seal(TTlsContentType.Handshake, DecodeHex('1800000101' + '1800000101'));
    LClientTransport.Write(LWire, 0, System.Length(LWire));
    SetLength(LBuf, 16);
    LAlerted := False;
    LAlert := TTlsAlertDescription.CloseNotify;
    try
      LClient.Read(LBuf[0], System.Length(LBuf));
    except
      on E: ETlsStreamError do
      begin
        LAlerted := E.HasAlert;
        LAlert := E.Alert;
      end;
    end;
    LServer.Finish;
  finally
    LWatch.Disarm;
    LWatch.WaitFor;
    CheckFalse(LWatch.Fired, 'neither side was left waiting on the other');
    LWatch.Free;
  end;
  CheckTrue(LAlerted, 'the client''s read raised the peer''s alert');
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage), Ord(LAlert), 'unexpected_message');
  CheckTrue(Pos('ETlsStreamError:', LServer.Error) = 1, 'the server''s read failed');
end;

procedure TTestTlsStreamLoopback.TestKeyUpdateRecordsInOneReadAreAnsweredByOneReply;
var
  LKeyLog: TMockKeyLog;
  LKeyLogT: IKeyLog;
  LClient, LServer: ITlsEngine;
  LForger: TTrafficForger;
  LWire, LReply, LPong: TBytes;
  LEvent: ITlsEvent;
  LIndex, LUpdates: Int32;
begin
  LKeyLog := TMockKeyLog.Create;
  LKeyLogT := LKeyLog;
  PinnedEngines(LKeyLogT, LClient, LServer);
  LForger := Own<TTrafficForger>(TTrafficForger.Create(Crypto, ClientTraffic0(LKeyLog)));
  // three update_requested records, each under the keys its predecessor installed, then data
  LWire := nil;
  for LIndex := 1 to 3 do
  begin
    LWire := ConcatBytes(LWire, LForger.Seal(TTlsContentType.Handshake, DecodeHex('1800000101')));
    LForger.Advance;
  end;
  LWire := ConcatBytes(LWire, LForger.Seal(TTlsContentType.ApplicationData, DecodeHex('70696e67')));
  CheckEquals(Ord(TTlsOutcome.Advanced), Ord(LServer.ProcessInput(LWire, 0, System.Length(LWire))),
    'one read carrying three KeyUpdates and a record behind them is accepted');
  CheckFalse(LServer.IsTerminal, 'the server stayed healthy');
  CheckEquals(4, LServer.PendingAppData, 'the data behind the KeyUpdates was decrypted');
  CheckFalse(LServer.WantsWrite, 'a read sends nothing, even with replies owed');
  LPong := DecodeHex('706f6e67');
  LServer.Write(LPong, 0, System.Length(LPong));
  LReply := TakeAll(LServer);
  // one KeyUpdate record (5 + 5 + 1 + 16) and the data record (5 + 4 + 1 + 16)
  CheckEquals(27 + 26, System.Length(LReply), 'the next write sent one KeyUpdate and the data');
  LClient.ProcessInput(LReply, 0, System.Length(LReply));
  LUpdates := 0;
  while LClient.NextEvent(LEvent) do
    if LEvent.Kind = TTlsEventKind.KeyUpdateReceived then
      System.Inc(LUpdates);
  CheckEquals(1, LUpdates, 'the client saw one KeyUpdate');
  CheckEquals(4, LClient.PendingAppData, 'and read the data behind it');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTlsStreamLoopback);
{$ELSE}
  RegisterTest(TTestTlsStreamLoopback.Suite);
{$ENDIF FPC}

end.
