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
  TlpTlsError,
  TlpISession,
  TlpInMemorySessionCache,
  TlpTlsEngineFactory,
  TlpITlsTransport,
  TlpTlsStreamPump,
  TlpTlsLibExceptions,
  TlpTlsStream,
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
    FBulkBytes: Int32;
  protected
    procedure Execute; override;
  public
    constructor Create(const AStream: TTlsStream; const ATransport,
      AClientTransport: TMemoryTransport; ABehavior: TServerBehavior);
    property Error: string read FError;
    property NegotiatedVersion: UInt16 read FNegotiatedVersion;
    property Alpn: TBytes read FAlpn;
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
    /// <summary>Reads data through a socket that dies under the flush of a queued KeyUpdate.</summary>
    procedure ReadWithAKeyUpdateLostToADeadSocket(out AClient: ITlsEngine;
      out ATransport: ITlsTransport);
    /// <summary>Fails a write over a dead socket, leaving AClient latched.</summary>
    procedure FailAWriteOverADeadSocket(out AClient: ITlsEngine);
    /// <summary>Aborts an engine whose queue holds more than one transport chunk, over a dead
    /// socket that refuses the first chunk.</summary>
    procedure AbortWithAnOversizedQueueOverADeadSocket(out AClient: ITlsEngine);
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
    procedure TestPumpFillsTheCallersTransportBuffer;
    procedure TestPumpReusesTheCallersTransportBuffer;
    procedure TestFailedFlushBehindBufferedDataLatchesTheEngine;
    procedure TestTransportWriteFailureKeepsTheCachedTickets;
    procedure TestProtocolFatalAlertAtThePumpDropsTheCachedTickets;
    procedure TestLatchedEngineWritesNothingToTheTransport;
    procedure TestLatchDropsPendingOutboundBytes;
    procedure TestLatchAfterAFatalAlertKeepsTheQueuedAlert;
    procedure TestFailedFlushBehindReadKeepsTheTransportMessage;
    procedure TestWriteAfterAFailedFlushBehindReadRaises;
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
  end;

implementation

const
  // "ping from the client" / "pong from the server"
  PingHex = '70696e672066726f6d2074686520636c69656e74';

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

  /// <summary>Force-closes both loopback pipes after a deadline so a pump that wedges fails as
  /// a surfaced EOF rather than hanging the run. Disarmed once the exchange completes.</summary>
  TWedgeWatchdog = class(TThread)
  strict private
  var
    FPipeA, FPipeB: TMemoryPipe;
    FDeadlineMs: UInt32;
    FDone: TEvent;
    FFired: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const APipeA, APipeB: TMemoryPipe; ADeadlineMs: UInt32);
    destructor Destroy; override;
    procedure Disarm; // the exchange finished in time; stop before the deadline
    property Fired: Boolean read FFired;
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

{ TWedgeWatchdog }

constructor TWedgeWatchdog.Create(const APipeA, APipeB: TMemoryPipe;
  ADeadlineMs: UInt32);
begin
  inherited Create(True);
  FPipeA := APipeA;
  FPipeB := APipeB;
  FDeadlineMs := ADeadlineMs;
  FDone := TEvent.Create(nil, True, False, '');
  FFired := False;
  FreeOnTerminate := False;
end;

destructor TWedgeWatchdog.Destroy;
begin
  inherited Destroy;
  FDone.Free;
end;

procedure TWedgeWatchdog.Execute;
begin
  // wait for the exchange to disarm us; if the deadline passes first the pump has wedged,
  // so close both pipes to unblock its reads and let the test surface the failure
  if FDone.WaitFor(FDeadlineMs) = wrTimeout then
  begin
    FFired := True;
    FPipeA.Close;
    FPipeB.Close;
  end;
end;

procedure TWedgeWatchdog.Disarm;
begin
  FDone.SetEvent;
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
  LServerStream: TTlsStream;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  // client reads server->client, writes client->server; server mirrored
  AClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  AClient := NewClientStream(AClientTransport as ITlsTransport, AClientConfig);
  LServerStream := NewServerStream(LServerTransport as ITlsTransport);
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
  LData, LTransportBuffer: TBytes;
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
    TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
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
  LTransportBuffer: TBytes;
  LStatus: TTlsReadStatus;
  LGot: Int32;
begin
  HandshakeEngines(LClient, LServer);
  LWire := DataThenBadRecord(LServer);
  LClient.ProcessInput(LWire, 0, System.Length(LWire));
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  System.SetLength(LDest, 16);
  LGot := TTlsStreamPump.ReadApp(LClient, LTransport, LTransportBuffer, LDest, 16, LStatus);
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
  LDest, LTransportBuffer: TBytes;
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
    TTlsStreamPump.ReadApp(LClient, LTransport, LTransportBuffer, LDest, 16, LStatus);
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
  LDest, LReply, LTransportBuffer, LWritten, LWire: TBytes;
  LStatus: TTlsReadStatus;
  LGot, LKeyUpdates: Int32;
begin
  // the reply to a KeyUpdate is owed, not queued, when the read returns: nothing is left to flush
  HandshakeEngines(LClient, LServer);
  LS2C := TMemoryPipe.Create;
  LC2S := TMemoryPipe.Create;
  LTransport := TMemoryTransport.Create(LS2C, LC2S) as ITlsTransport;
  try
    LWire := DataThenKeyUpdateRequest(LServer);
    LS2C.Write(LWire, 0, System.Length(LWire));
    LS2C.Close;
    LC2S.Close; // closed so the drains below read what was written, never block on an empty pipe
    System.SetLength(LDest, 16);
    CheckEquals(2, TTlsStreamPump.ReadApp(LClient, LTransport, LTransportBuffer, LDest, 16,
      LStatus), 'the data');
    System.SetLength(LWritten, 16384);
    CheckEquals(0, LC2S.Read(LWritten, 0, System.Length(LWritten)),
      'no reply was queued by the read');
    LReply := DecodeHex('03');
    TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LReply, 0, 1);
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

procedure TTestTlsStreamLoopback.ReadWithAKeyUpdateLostToADeadSocket(out AClient: ITlsEngine;
  out ATransport: ITlsTransport);
var
  LServer: ITlsEngine;
  LDest, LWire, LTransportBuffer: TBytes;
  LStatus: TTlsReadStatus;
begin
  HandshakeEngines(AClient, LServer);
  LWire := DataThenKeyUpdateRequest(LServer);
  AClient.ProcessInput(LWire, 0, System.Length(LWire));
  // our own KeyUpdate is queued, and rotates the write keys, when the socket dies under the flush
  AClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateNotRequested);
  ATransport := TDeadWriteTransport.Create as ITlsTransport;
  System.SetLength(LDest, 16);
  TTlsStreamPump.ReadApp(AClient, ATransport, LTransportBuffer, LDest, 16, LStatus);
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
  LDest, LWire, LTransportBuffer: TBytes;
  LStatus: TTlsReadStatus;
begin
  LCache := TInMemorySessionCache.Create;
  HandshakeCachingATicket(LCache, LClient, LServer);
  LWire := DataThenKeyUpdateRequest(LServer);
  LClient.ProcessInput(LWire, 0, System.Length(LWire));
  LClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateNotRequested);
  System.SetLength(LDest, 16);
  // the socket dies under the flush: the engine latches, but a broken transport is no TLS fatal alert
  TTlsStreamPump.ReadApp(LClient, TDeadWriteTransport.Create as ITlsTransport,
    LTransportBuffer, LDest, 16, LStatus);
  CheckTrue(LClient.IsTerminal, 'the lost flush latched the engine');
  CheckTrue(LCache.Count > 0, 'the cached tickets stay resumable');
end;

procedure TTestTlsStreamLoopback.TestProtocolFatalAlertAtThePumpDropsTheCachedTickets;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LTransportBuffer: TBytes;
begin
  LCache := TInMemorySessionCache.Create;
  HandshakeCachingATicket(LCache, LClient, LServer);
  TTlsStreamPump.Abort(LClient, TRecordingTransport.Create as ITlsTransport,
    LTransportBuffer, TTlsAlertDescription.InternalError);
  CheckTrue(LClient.IsTerminal, 'the abort ended the connection');
  CheckEquals(0, LCache.Count, 'a fatal alert withdraws the tickets');
end;

procedure TTestTlsStreamLoopback.TestLatchedEngineWritesNothingToTheTransport;
var
  LClient, LServer: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LData, LTransportBuffer: TBytes;
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
    TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
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

procedure TTestTlsStreamLoopback.TestLatchAfterAFatalAlertKeepsTheQueuedAlert;
var
  LClient, LServer: ITlsEngine;
begin
  HandshakeEngines(LClient, LServer);
  LClient.SendAlert(TTlsAlertDescription.DecodeError);
  LClient.LatchTransportFailure('x');
  CheckTrue(LClient.WantsWrite, 'the already-terminal engine keeps its queued alert');
  CheckEquals(Ord(TTlsAlertDescription.DecodeError), Ord(LClient.LastError.Alert.Description),
    'the first error stands');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LClient.LastError.Origin),
    'the first error stays our own');
end;

procedure TTestTlsStreamLoopback.TestFailedFlushBehindBufferedDataLatchesTheEngine;
var
  LClient: ITlsEngine;
  LTransport: ITlsTransport;
begin
  ReadWithAKeyUpdateLostToADeadSocket(LClient, LTransport);
  CheckTrue(LClient.IsTerminal, 'the lost KeyUpdate latched the engine');
end;

procedure TTestTlsStreamLoopback.TestFailedFlushBehindReadKeepsTheTransportMessage;
var
  LClient: ITlsEngine;
  LTransport: ITlsTransport;
begin
  ReadWithAKeyUpdateLostToADeadSocket(LClient, LTransport);
  CheckTrue(Pos('the mock socket failed', LClient.LastError.Message) > 0,
    'the latched error names the transport failure');
end;

procedure TTestTlsStreamLoopback.TestWriteAfterAFailedFlushBehindReadRaises;
var
  LClient: ITlsEngine;
  LTransport: ITlsTransport;
  LData, LTransportBuffer: TBytes;
  LRaised: Boolean;
begin
  ReadWithAKeyUpdateLostToADeadSocket(LClient, LTransport);
  LData := DecodeHex('00');
  LRaised := False;
  try
    TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'no record is written under keys the peer never received');
end;

procedure TTestTlsStreamLoopback.TestPumpFillsTheCallersTransportBuffer;
var
  LClient, LServer: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LData, LTransportBuffer: TBytes;
begin
  HandshakeEngines(LClient, LServer);
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LData := DecodeHex('00');
  TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
  CheckTrue(LRecorder.Written > 0, 'the record reached the transport');
  CheckEquals(TTlsStreamPump.TransportChunk, System.Length(LTransportBuffer),
    'the flush grew the caller''s buffer to the transport chunk');
end;

procedure TTestTlsStreamLoopback.TestPumpReusesTheCallersTransportBuffer;
var
  LClient, LServer: ITlsEngine;
  LRecorder: TRecordingTransport;
  LTransport: ITlsTransport;
  LData, LTransportBuffer, LFirst: TBytes;
begin
  HandshakeEngines(LClient, LServer);
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LData := DecodeHex('00');
  TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
  // holding the first array alive means a reallocation cannot land on the same address
  LFirst := LTransportBuffer;
  CheckTrue(LFirst <> nil, 'the first flush allocated the caller''s buffer');
  TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
  CheckTrue(Pointer(LFirst) = Pointer(LTransportBuffer), 'the second flush reused the buffer');
end;

procedure TTestTlsStreamLoopback.TestReadReturningBufferedDataSurvivesADeadTransport;
var
  LClient, LServer: ITlsEngine;
  LTransport: ITlsTransport;
  LDest, LWire, LData, LTransportBuffer: TBytes;
  LStatus: TTlsReadStatus;
  LGot: Int32;
begin
  HandshakeEngines(LClient, LServer);
  // the engine holds a queued KeyUpdate that a dead socket cannot take, beside the data it read
  LData := DecodeHex('0102');
  LServer.Write(LData, 0, 2);
  System.SetLength(LWire, 16384);
  System.SetLength(LWire, LServer.TakeOutgoing(LWire, 0));
  LClient.ProcessInput(LWire, 0, System.Length(LWire));
  LClient.RequestKeyUpdate(TKeyUpdateRequest.UpdateNotRequested);
  LTransport := TDeadWriteTransport.Create as ITlsTransport;
  System.SetLength(LDest, 16);
  LGot := TTlsStreamPump.ReadApp(LClient, LTransport, LTransportBuffer, LDest, 16, LStatus);
  CheckEquals(2, LGot, 'the plaintext already taken from the engine is returned');
end;

procedure TTestTlsStreamLoopback.TestFailedWriteFlushLatchesTheEngine;
var
  LClient, LServer: ITlsEngine;
  LData, LTransportBuffer: TBytes;
  LRaised: Boolean;
begin
  HandshakeEngines(LClient, LServer);
  LData := DecodeHex('00');
  LRaised := False;
  try
    TTlsStreamPump.WriteApp(LClient, TDeadWriteTransport.Create as ITlsTransport,
      LTransportBuffer, LData, 0, 1);
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
  LData, LTransportBuffer: TBytes;
begin
  HandshakeEngines(AClient, LServer);
  LData := DecodeHex('00');
  try
    TTlsStreamPump.WriteApp(AClient, TDeadWriteTransport.Create as ITlsTransport,
      LTransportBuffer, LData, 0, 1);
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
  LData, LTransportBuffer: TBytes;
  LRaised: Boolean;
begin
  FailAWriteOverADeadSocket(LClient);
  LData := DecodeHex('00');
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LRaised := False;
  try
    TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
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
  LData, LTransportBuffer: TBytes;
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
    TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
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
  LTransportBuffer: TBytes;
begin
  FailAWriteOverADeadSocket(LClient);
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  TTlsStreamPump.Close(LClient, LTransport, LTransportBuffer);
  CheckEquals(0, LRecorder.Written, 'no close_notify follows the torn write');
end;

procedure TTestTlsStreamLoopback.TestSealLimitOverADeadSocketStillRaisesTheLimitError;
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LData, LTransportBuffer: TBytes;
  LRaised: Boolean;
begin
  CappedTls12Configs(LClientConfig, LServerConfig);
  HandshakeEnginesWith(LClientConfig, LServerConfig, LClient, LServer);
  LData := DecodeHex('00');
  LRaised := False;
  try
    TTlsStreamPump.WriteApp(LClient, TDeadWriteTransport.Create as ITlsTransport,
      LTransportBuffer, LData, 0, 1);
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
  LTransportBuffer: TBytes;
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
    TTlsStreamPump.DriveHandshake(LClient, TDeadWriteTransport.Create as ITlsTransport,
      LTransportBuffer, True);
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
  LTransportBuffer: TBytes;
  LRaised: Boolean;
begin
  LCache := TInMemorySessionCache.Create;
  HandshakeCachingATicket(LCache, LClient, LServer);
  LRaised := False;
  try
    TTlsStreamPump.Close(LClient, TDeadWriteTransport.Create as ITlsTransport,
      LTransportBuffer);
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
  LTransportBuffer: TBytes;
  LRaised: Boolean;
begin
  LConfig := ClientConfig(False, nil);
  LClient := TTlsEngineFactory.CreateClientEngine(LConfig, 'localhost');
  LRaised := False;
  try
    TTlsStreamPump.DriveHandshake(LClient, TDeadWriteTransport.Create as ITlsTransport,
      LTransportBuffer, True);
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
  LData, LTransportBuffer: TBytes;
begin
  HandshakeEngines(AClient, LServer);
  System.SetLength(LData, 2 * TTlsStreamPump.TransportChunk);
  AClient.Write(LData, 0, System.Length(LData));
  TTlsStreamPump.Abort(AClient, TDeadWriteTransport.Create as ITlsTransport,
    LTransportBuffer, TTlsAlertDescription.DecodeError);
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
  LData, LTransportBuffer: TBytes;
  LRaised: Boolean;
begin
  AbortWithAnOversizedQueueOverADeadSocket(LClient);
  LRecorder := TRecordingTransport.Create;
  LTransport := LRecorder as ITlsTransport;
  LData := DecodeHex('00');
  LRaised := False;
  try
    TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, LData, 0, 1);
  except
    on E: ETlsStreamError do
      LRaised := E.Alert = TTlsAlertDescription.DecodeError;
  end;
  CheckTrue(LRaised, 'the write raises the recorded decode_error');
  CheckEquals(0, LRecorder.Written, 'the alert is not resent after a failed flush');
end;


initialization

{$IFDEF FPC}
  RegisterTest(TTestTlsStreamLoopback);
{$ELSE}
  RegisterTest(TTestTlsStreamLoopback.Suite);
{$ENDIF FPC}

end.
