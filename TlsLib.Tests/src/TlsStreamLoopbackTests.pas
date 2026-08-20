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
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpTrustPolicy,
  TlpTlsConnectionInfo,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITlsTransport,
  TlpTlsStreamPump,
  TlpTlsLibExceptions,
  TlpTlsStream,
  TlsLibTestBase;

type
  /// <summary>One-directional blocking byte channel between two threads: a Write appends,
  /// a Read blocks for data or an orderly close (returns 0). The shared boundary the two
  /// single-threaded engines synchronize across in a loopback.</summary>
  TMemoryPipe = class sealed(TObject)
  strict private
  var
    FLock: TCriticalSection;
    FEvent: TEvent;
    FBuffer: TBytes;
    FHead: Int32;
    FClosed: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    function Read(var ADest: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Close;
  end;

  /// <summary>An ITlsTransport over a read pipe and a write pipe (the two directions of a
  /// duplex). CloseWrite drops the transport without a close_notify (a truncation).</summary>
  TMemoryTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FRead: TMemoryPipe;
    FWrite: TMemoryPipe;
  public
    constructor Create(const ARead, AWrite: TMemoryPipe);
    destructor Destroy; override;
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    procedure CloseWrite;
  end;

  /// <summary>What the loopback server thread does after its handshake.</summary>
  TServerBehavior = (
    EchoThenClose,     // echo one client message, then a clean close_notify
    TruncateAfterHandshake); // drop the transport with no close_notify (truncation)

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
  protected
    procedure Execute; override;
  public
    constructor Create(const AStream: TTlsStream; const ATransport: TMemoryTransport;
      ABehavior: TServerBehavior);
    destructor Destroy; override;
    property Error: string read FError;
    property NegotiatedVersion: UInt16 read FNegotiatedVersion;
    property Alpn: string read FAlpn;
  end;

  TTestTlsStreamLoopback = class(TTlsLibAlgorithmTestCase)
  strict private
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
    /// <summary>The verdict-resolver form (the seam's 3-arg signature): a live-revocation-style
    /// resolver reporting the reject alert. Reuses AlwaysAccept/AlwaysReject for the decision.</summary>
    function ResolverAccept(const AChain: TArray<TBytes>;
      const AHostName: string; out ARejectAlert: TTlsAlertDescription): Boolean;
    function ResolverReject(const AChain: TArray<TBytes>;
      const AHostName: string; out ARejectAlert: TTlsAlertDescription): Boolean;
    function SpkiSha256(const ACertDer: TBytes): TBytes;
    /// <summary>A client config with the async peer-certificate verdict enabled.</summary>
    function AsyncClientConfig: ITlsClientConfig;
  published
    procedure TestClientServerLoopbackExchangesAppDataAndClosesCleanly;
    procedure TestNegotiatedVersionAndAlpnSurfaced;
    procedure TestTruncationWithoutCloseNotifyIsSurfaced;
    procedure TestUntrustedChainFailsThroughOurPipeline;
    procedure TestInsecureSkipVerifyAcceptsUntrustedChain;
    procedure TestVerifyCallbackCanOnlyAdditionallyReject;
    procedure TestPinnedSelfSignedChainStillFullyVerified;
    procedure TestAsyncVerdictResolverAcceptCompletesOverPump;
    procedure TestAsyncVerdictResolverRejectFailsClosedOverPump;
  end;

implementation

const
  // "ping from the client" / "pong from the server"
  PingHex = '70696e672066726f6d2074686520636c69656e74';

{ TMemoryPipe }

constructor TMemoryPipe.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  // manual-reset: stays signaled while bytes are buffered or the pipe is closed
  FEvent := TEvent.Create(nil, True, False, '');
  FHead := 0;
  FClosed := False;
end;

destructor TMemoryPipe.Destroy;
begin
  FEvent.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TMemoryPipe.Write(const AData: TBytes; AOffset, ALength: Int32);
var
  LOld: Int32;
begin
  if ALength <= 0 then
    Exit;
  FLock.Acquire;
  try
    LOld := System.Length(FBuffer);
    SetLength(FBuffer, LOld + ALength);
    Move(AData[AOffset], FBuffer[LOld], ALength);
    FEvent.SetEvent;
  finally
    FLock.Release;
  end;
end;

function TMemoryPipe.Read(var ADest: TBytes; AOffset, AMaxLength: Int32): Int32;
var
  LAvail: Int32;
begin
  repeat
    FLock.Acquire;
    try
      LAvail := System.Length(FBuffer) - FHead;
      if LAvail > 0 then
      begin
        Result := LAvail;
        if Result > AMaxLength then
          Result := AMaxLength;
        Move(FBuffer[FHead], ADest[AOffset], Result);
        Inc(FHead, Result);
        if FHead >= System.Length(FBuffer) then
        begin
          FBuffer := nil;
          FHead := 0;
          FEvent.ResetEvent; // drained: block the next reader until more arrives
        end;
        Exit;
      end;
      if FClosed then
        Exit(0);
    finally
      FLock.Release;
    end;
    FEvent.WaitFor(INFINITE);
  until False;
end;

procedure TMemoryPipe.Close;
begin
  FLock.Acquire;
  try
    FClosed := True;
    FEvent.SetEvent;
  finally
    FLock.Release;
  end;
end;

{ TMemoryTransport }

constructor TMemoryTransport.Create(const ARead, AWrite: TMemoryPipe);
begin
  inherited Create;
  FRead := ARead;
  FWrite := AWrite;
end;

destructor TMemoryTransport.Destroy;
begin
  // each transport owns its write pipe; the paired transports free both pipes exactly once
  FWrite.Free;
  inherited Destroy;
end;

function TMemoryTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FRead.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TMemoryTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  FWrite.Write(ABuffer, AOffset, ALength);
end;

procedure TMemoryTransport.CloseWrite;
begin
  FWrite.Close;
end;

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
  LGot: Int32;
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
    // echo one client message back, then shut down cleanly
    SetLength(LChunk, 4096);
    LGot := FStream.Read(LChunk[0], System.Length(LChunk));
    if LGot > 0 then
      FStream.Write(LChunk[0], LGot);
    FStream.CloseNotify;
  except
    on E: Exception do
      FError := E.ClassName + ': ' + E.Message;
  end;
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
  LClient := TTlsPresets.Compatible(Provider).Client
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
  Result := TTlsPresets.Compatible(Provider).Server
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

function TTestTlsStreamLoopback.ResolverAccept(const AChain: TArray<TBytes>;
  const AHostName: string; out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := AlwaysAccept(AChain, AHostName);
end;

function TTestTlsStreamLoopback.ResolverReject(const AChain: TArray<TBytes>;
  const AHostName: string; out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := AlwaysReject(AChain, AHostName);
end;

function TTestTlsStreamLoopback.AsyncClientConfig: ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(Provider).Client
    .WithTrustAnchors(TrustRoot)
    .WithAsyncCertificateVerdict(True, 0).Build;
end;

function TTestTlsStreamLoopback.SpkiSha256(const ACertDer: TBytes): TBytes;
var
  LHash: IHash;
  LSpki: TBytes;
begin
  LSpki := Provider.CertificatePublicKeyInfo(ACertDer);
  LHash := Provider.CreateHash(THashAlgorithm.SHA_256);
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
    // connection info surfaces the validated peer chain (backlog #3 enrichment)
    CheckTrue(System.Length(LClient.ConnectionInfo.PeerCertificates) >= 1,
      'connection info carries the validated server chain');
    CheckEqualBytes('the leaf is the first chain entry', LeafCert,
      LClient.ConnectionInfo.PeerCertificates[0]);

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
  LConfig := TTlsPresets.Compatible(Provider).Client
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
  LConfig := TTlsPresets.Compatible(Provider).Client
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
  LConfig := TTlsPresets.Compatible(Provider).Client
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
    LClient.SetCertificateVerdictResolver(ResolverAccept);
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete,
      'an accepted async verdict completes the handshake over the pump');
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestTlsStreamLoopback);
{$ELSE}
  RegisterTest(TTestTlsStreamLoopback.Suite);
{$ENDIF FPC}

end.
