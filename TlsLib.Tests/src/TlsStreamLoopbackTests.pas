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
  TlpTlsVersion,
  TlpTlsAlert,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpTrustPolicy,
  TlpTlsConnectionInfo,
  TlpRecordHeader,
  TlpINegotiation,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpITlsTransport,
  TlpTlsStreamPump,
  TlpTlsLibExceptions,
  TlpTlsStream,
  MockTransport,
  TlsLibTestBase;

type
  /// <summary>What the loopback server thread does after its handshake.</summary>
  TServerBehavior = (
    EchoThenClose,     // echo one client message, then a clean close_notify
    TruncateAfterHandshake, // drop the transport with no close_notify (truncation)
    BulkEcho); // echo a fixed byte count back (heavy throughput), then a clean close_notify

  /// <summary>Runs the server side of a loopback on its own thread so the client (main
  /// thread) can block on a real duplex. Captures the negotiated info and any error.</summary>
  TServerRunner = class(TThread)
  strict private
  var
    FStream: TTlsStream;
    FTransport: TMemoryTransport;
    FBehavior: TServerBehavior;
    FError: string;
    FNegotiatedVersion: UInt16;
    FAlpn: string;
    FBulkBytes: Int32;
  protected
    procedure Execute; override;
  public
    constructor Create(const AStream: TTlsStream; const ATransport: TMemoryTransport;
      ABehavior: TServerBehavior);
    destructor Destroy; override;
    property Error: string read FError;
    property NegotiatedVersion: UInt16 read FNegotiatedVersion;
    property Alpn: string read FAlpn;
    // total bytes a BulkEcho server echoes back before closing
    property BulkBytes: Int32 read FBulkBytes write FBulkBytes;
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

  TTestTlsStreamLoopback = class(TTlsLibAlgorithmTestCase)
  strict private
    FCapturedPeerRole: TPeerRole; // the role the pump handed the resolver at the park
    function TrustRoot: TBytes;
    function LeafCert: TBytes;
    function LeafKey: TBytes;
    function ClientConfig(AInsecureSkipVerify: Boolean;
      const AVerify: TTlsCertificateVerifyCallback): ITlsClientConfig;
    function ServerConfig: ITlsServerConfig;
    function NewClientStream(const ATransport: ITlsTransport;
      const AConfig: ITlsClientConfig): TTlsStream;
    function NewServerStream(const ATransport: ITlsTransport): TTlsStream;
    procedure RunLoopback(const AClientConfig: ITlsClientConfig;
      AServerBehavior: TServerBehavior; out AClient: TTlsStream;
      out AServer: TServerRunner; out AClientTransport: TMemoryTransport);
    function AlwaysReject(const AChain: TArray<TBytes>;
      const AHostName: string): Boolean;
    function AlwaysAccept(const AChain: TArray<TBytes>;
      const AHostName: string): Boolean;
    /// <summary>The verdict-resolver form (the seam's context signature): a live-revocation-style
    /// resolver reporting the reject alert. Reuses AlwaysAccept/AlwaysReject for the decision.</summary>
    function ResolverAccept(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    function ResolverReject(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    function SpkiSha256(const ACertDer: TBytes): TBytes;
    /// <summary>A client config with the async peer-certificate verdict enabled.</summary>
    function AsyncClientConfig: ITlsClientConfig;
    /// <summary>A TLS 1.2-only client pinned to the AES-GCM suites, whose AEAD usage limit is a
    /// fixed record count (ChaCha20 is bounded only by the sequence space and never hits it).</summary>
    function Tls12AesGcmClientConfig: ITlsClientConfig;
  published
    procedure TestClientServerLoopbackExchangesAppDataAndClosesCleanly;
    procedure TestBulkWriteIsSealedInBoundedSlices;
    procedure TestPostHandshakeFatalAlertReachesPeer;
    procedure TestRecordLimitCloseNotifyReachesPeerOverPump;
    procedure TestNegotiatedVersionAndAlpnSurfaced;
    procedure TestTruncationWithoutCloseNotifyIsSurfaced;
    procedure TestUntrustedChainFailsThroughOurPipeline;
    procedure TestInsecureSkipVerifyAcceptsUntrustedChain;
    procedure TestVerifyCallbackCanOnlyAdditionallyReject;
    procedure TestPinnedSelfSignedChainStillFullyVerified;
    procedure TestAsyncVerdictResolverAcceptCompletesOverPump;
    procedure TestAsyncVerdictResolverRejectFailsClosedOverPump;
    procedure TestBulkThroughputRoundTripDoesNotWedge;
  end;

implementation

const
  // "ping from the client" / "pong from the server"
  PingHex = '70696e672066726f6d2074686520636c69656e74';

{ TServerRunner }

constructor TServerRunner.Create(const AStream: TTlsStream;
  const ATransport: TMemoryTransport; ABehavior: TServerBehavior);
begin
  inherited Create(True);
  FStream := AStream;
  FTransport := ATransport;
  FBehavior := ABehavior;
  FreeOnTerminate := False;
end;

destructor TServerRunner.Destroy;
begin
  // stop the thread first (Execute has finished by the WaitFor the callers do), then free
  // the server stream we own; that releases its engine and its ITlsTransport (the transport)
  inherited Destroy;
  FStream.Free;
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

function TTestTlsStreamLoopback.TrustRoot: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LV.Values['root_cert']);
  finally
    LV.Free;
  end;
end;

function TTestTlsStreamLoopback.LeafCert: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LV.Values['leaf_cert']);
  finally
    LV.Free;
  end;
end;

function TTestTlsStreamLoopback.LeafKey: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LV.Values['leaf_key']);
  finally
    LV.Free;
  end;
end;

function TTestTlsStreamLoopback.ClientConfig(AInsecureSkipVerify: Boolean;
  const AVerify: TTlsCertificateVerifyCallback): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithAlpnProtocols(TArray<string>.Create('h2', 'http/1.1'));
  if AInsecureSkipVerify then
    LClient.WithDangerousInsecureSkipVerify(True)
      .WithTrustAnchors(TrustRoot) // a trust source is still required by build
  else
    LClient.WithTrustAnchors(TrustRoot);
  if Assigned(AVerify) then
    LClient.WithCertificateVerifyCallback(AVerify);
  Result := LClient.Build;
end;

function TTestTlsStreamLoopback.ServerConfig: ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithAlpnProtocols(TArray<string>.Create('h2', 'http/1.1'))
    .WithCredential(LeafCert, LeafKey).Build;
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
  AServer := TServerRunner.Create(LServerStream, LServerTransport, AServerBehavior);
  AServer.Start;
end;

function TTestTlsStreamLoopback.AlwaysReject(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := False;
end;

function TTestTlsStreamLoopback.AlwaysAccept(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := System.Length(AChain) > 0;
end;

function TTestTlsStreamLoopback.ResolverAccept(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  FCapturedPeerRole := ACtx.PeerRole; // record the role the pump attributed to the parked chain
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := AlwaysAccept(ACtx.Chain, ACtx.HostName);
end;

function TTestTlsStreamLoopback.ResolverReject(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := AlwaysReject(ACtx.Chain, ACtx.HostName);
end;

function TTestTlsStreamLoopback.AsyncClientConfig: ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustAnchors(TrustRoot)
    .WithAsyncCertificateVerdict(0).Build;
end;

function TTestTlsStreamLoopback.Tls12AesGcmClientConfig: ITlsClientConfig;
var
  LSuites: ICipherSuiteRegistry;
begin
  LSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LSuites.Prune(TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256);
  LSuites.Prune(TCipherSuites12.EcdheRsaChaCha20Poly1305Sha256);
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustAnchors(TrustRoot)
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCipherSuites(LSuites).Build;
end;

function TTestTlsStreamLoopback.SpkiSha256(const ACertDer: TBytes): TBytes;
var
  LHash: IHash;
  LSpki: TBytes;
begin
  LSpki := Pkix.Certificates.PublicKeyInfo(ACertDer);
  LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LSpki, 0, System.Length(LSpki));
  Result := LHash.DoFinal;
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
    CheckEqualBytes('the leaf is the first chain entry', LeafCert,
      LClient.ConnectionInfo.PeerCertificates[0]);
    // the validated path is what the pipeline built here: leaf, assembled issuer, up to the anchor
    CheckTrue(System.Length(LClient.ConnectionInfo.ValidatedPath) >= 2,
      'the validated path assembles the issuer beyond the presented leaf');
    CheckEqualBytes('the validated path leaf is the server leaf', LeafCert,
      LClient.ConnectionInfo.ValidatedPath[0]);
    CheckEqualBytes('the validated path terminates at the trust anchor', TrustRoot,
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

    LServer.WaitFor;
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
  LServer := TServerRunner.Create(LServerStream, LServerTransport, TServerBehavior.BulkEcho);
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
    LServer.WaitFor;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
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
    LServer.WaitFor;
    CheckTrue(LServer.Error <> '', 'the server side failed on the bad record');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestTlsStreamLoopback.TestRecordLimitCloseNotifyReachesPeerOverPump;
const
  // the AES-GCM usage limit the engine enforces: 2^24.5 records (RFC 8446 5.5)
  AES_GCM_RECORD_LIMIT = UInt64(23726566);
var
  LC2S, LS2C: TMemoryPipe;
  LClientTransport, LServerTransport: TMemoryTransport;
  LClientEngine, LServerEngine: ITlsEngine;
  LClientSeq, LServerSeq: IEngineRecordSequenceControl;
  LClient, LServerStream: TTlsStream;
  LServer: TServerRunner;
  LWatch: TWedgeWatchdog;
  LByte: TBytes;
  LRaised: Boolean;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  LClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  LClientEngine := TTlsEngineFactory.CreateClientEngine(Tls12AesGcmClientConfig, 'localhost');
  LServerEngine := TTlsEngineFactory.CreateServerEngine(ServerConfig);
  LClient := TTlsStream.Create(LClientTransport as ITlsTransport, LClientEngine, True,
    'localhost');
  LServerStream := TTlsStream.Create(LServerTransport as ITlsTransport, LServerEngine, False,
    '');
  LServer := TServerRunner.Create(LServerStream, LServerTransport,
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
    CheckTrue(Supports(LClientEngine, IEngineRecordSequenceControl, LClientSeq),
      'client sequence control present');
    CheckTrue(Supports(LServerEngine, IEngineRecordSequenceControl, LServerSeq),
      'server sequence control present');
    // park both epochs at the last legal sequence: the next application write cannot rekey, so
    // the engine seals a close_notify there and refuses. The server thread is blocked in its
    // transport read once the client's handshake completes, so moving its read counter here
    // races nothing.
    LClientSeq.SetWriteSequenceNumber(AES_GCM_RECORD_LIMIT - 1);
    LServerSeq.SetReadSequenceNumber(AES_GCM_RECORD_LIMIT - 1);
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
    LServer.WaitFor;
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
    CheckEquals('h2', LInfo.AlpnProtocol, 'the client negotiated the h2 ALPN protocol');
    CheckEquals('localhost', LInfo.ServerName, 'the connection info carries the SNI host');
    // the negotiated suite and (EC)DHE group are surfaced; a fresh handshake is not resumed
    CheckTrue(LInfo.CipherSuite <> 0, 'the connection info carries the negotiated cipher suite');
    CheckTrue(LInfo.NamedGroup <> 0, 'a TLS 1.3 handshake carries a negotiated named group');
    CheckFalse(LInfo.Resumed, 'a fresh handshake is not marked resumed');

    LClient.CloseNotify;
    LServer.WaitFor;
    CheckEquals('', LServer.Error, 'the server side ran without error');
    CheckEquals(Integer(TlsWireVersionTls13), Integer(LServer.NegotiatedVersion),
      'the server negotiated TLS 1.3');
    CheckEquals('h2', LServer.Alpn, 'the server selected the h2 ALPN protocol');
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
    LServer.WaitFor;
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
  LFailed: Boolean;
begin
  // a client that trusts an unrelated anchor (the leaf's own cert, not its issuer) must
  // reject the server chain through PKIX - no dangerous flag is set
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustAnchors(LeafCert).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  try
    LFailed := False;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
        LFailed := True;
    end;
    CheckTrue(LFailed, 'an untrusted server chain fails the handshake through our pipeline');
    LServer.WaitFor;
  finally
    LServer.Free;
    LClient.Free;
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
    .WithDangerousInsecureSkipVerify(True)
    .WithTrustAnchors(LeafCert).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  try
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete,
      'InsecureSkipVerify makes an otherwise-untrusted chain pass');
    LClient.CloseNotify;
    LServer.WaitFor;
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
  LFailed: Boolean;
begin
  // the chain would pass the built-in pipeline (trusted root), but an augment callback
  // additionally rejects it: the handshake must fail
  RunLoopback(ClientConfig(False, AlwaysReject), TServerBehavior.EchoThenClose, LClient,
    LServer, LTransport);
  try
    LFailed := False;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
        LFailed := True;
    end;
    CheckTrue(LFailed, 'the augment callback additionally rejects an otherwise-valid chain');
    LServer.WaitFor;
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
  // a private root trusted via WithTrustAnchors plus an SPKI pin on the leaf: the chain is
  // still fully verified (PKIX + pinning both hold), so the handshake completes
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustAnchors(TrustRoot)
    .WithCertificatePinning(TArray<TBytes>.Create(
      SpkiSha256(LeafCert))).Build;
  RunLoopback(LConfig, TServerBehavior.EchoThenClose, LClient, LServer, LTransport);
  try
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete,
      'a trusted-anchor chain that also matches its SPKI pin verifies');
    LClient.CloseNotify;
    LServer.WaitFor;
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
begin
  // async verdict enabled end-to-end over the blocking pump: the pump parks, calls the
  // resolver (which accepts), and the handshake completes and exchanges app data
  RunLoopback(AsyncClientConfig, TServerBehavior.EchoThenClose, LClient, LServer,
    LTransport);
  try
    FCapturedPeerRole := TPeerRole.Unknown; // seed with the unset value so the assert is meaningful
    LClient.SetCertificateVerdictResolver(ResolverAccept);
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete,
      'an accepted async verdict completes the handshake over the pump');
    CheckEquals(Ord(TPeerRole.Server), Ord(FCapturedPeerRole),
      'a client park attributes the parked chain to the server role');
    LPing := DecodeHex(PingHex);
    LClient.Write(LPing[0], System.Length(LPing));
    SetLength(LEcho, 4096);
    LGot := LClient.Read(LEcho[0], System.Length(LEcho));
    CheckEqualBytes('the server echoed the client message', LPing,
      System.Copy(LEcho, 0, LGot));
    LClient.CloseNotify;
    LServer.WaitFor;
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
  LFailed: Boolean;
begin
  // a resolver that rejects a chain the pipeline already accepted still aborts the handshake
  // (augment-only, fail-closed) - the pump raises
  RunLoopback(AsyncClientConfig, TServerBehavior.EchoThenClose, LClient, LServer,
    LTransport);
  try
    LClient.SetCertificateVerdictResolver(ResolverReject);
    LFailed := False;
    try
      LClient.Handshake;
    except
      on E: ETlsStreamError do
        LFailed := True;
    end;
    CheckTrue(LFailed, 'a rejected async verdict fails the handshake closed over the pump');
    LServer.WaitFor;
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
  LServer := TServerRunner.Create(LServerStream, LServerTransport, TServerBehavior.BulkEcho);
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
    LServer.WaitFor;
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LWatch.Disarm; // on any failure path too, so the watchdog thread can exit
    LWatch.WaitFor;
    LWatch.Free;
    LServer.Free;
    LClient.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTlsStreamLoopback);
{$ELSE}
  RegisterTest(TTestTlsStreamLoopback.Suite);
{$ENDIF FPC}

end.
