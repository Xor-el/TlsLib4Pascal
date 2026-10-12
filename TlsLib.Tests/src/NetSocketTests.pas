{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit NetSocketTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpIClock,
  TlpClock,
  TlpITlsConfig,
  TlpTlsPresets,
  TlpTlsCredential,
  TlpITlsTransport,
  TlpINetSocket,
  TlpNetExceptions,
  TlpNetSocket,
  TlpTlsConnection,
  TlpTlsLibExceptions,
  TlsLibTestBase;

type
  /// <summary>
  /// The TCP connector and listener: a round trip on an ephemeral port, a bounded accept, a refused
  /// connect, the handshake and application read caps, an orderly close, and a TTlsConnection over
  /// the streams on both ends.
  /// </summary>
  TTestNetSocket = class(TTlsLibAlgorithmTestCase)
  strict private
    function ClientConfig: ITlsClientConfig;
    function ServerConfig: ITlsServerConfig;
    function Listener: ITcpListener;
    function Connector: ITcpConnector;
    procedure ConnectPair(const AListener: ITcpListener; out AClient, AServer: ITlsTimedTransport);
  published
    procedure TestBytesRoundTripOnAnEphemeralPort;
    procedure TestTryAcceptWithNoClientReturnsWithinItsBound;
    procedure TestConnectToAClosedPortRaisesConnectError;
    procedure TestNonPositiveConnectTimeoutIsRefused;
    procedure TestConnectTimeoutBelowASecondConnects;
    procedure TestConnectToAnEmptyHostRaisesConnectError;
    procedure TestListenerRefusesAnAddressThatIsNotAnIpv4Literal;
    procedure TestConnectorResolvesNamesThroughItsResolver;
    procedure TestConnectorRefusesAHostTheResolverCannotFind;
    procedure TestNilResolverIsRefused;
    procedure TestSystemResolverFindsLiteralsAndLocalhost;
    procedure TestSystemResolverRefusesEmptyNonAsciiAndUnknownNames;
    procedure TestSocketsPastTheSelectLimitStillWork;
    procedure TestHandshakeReadCapRaisesHandshakeTimeout;
    procedure TestApplicationReadCapRaisesRetryableReadTimeout;
    procedure TestPeerCloseReadsAsEndOfStream;
    procedure TestServerHandshakeFailsFastWhenTheClientClosesFirst;
    procedure TestTlsConnectionRunsOverTheStreamsOnBothEnds;
  end;

implementation

type
  // answers one name with the loopback address and counts the questions
  TFakeResolver = class sealed(TInterfacedObject, IHostResolver)
  strict private
    FName: string;
    FAsked: Int32;
  public
    constructor Create(const AName: string);
    function TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
    property Asked: Int32 read FAsked;
  end;

  // accepts one connection, runs the TLS server handshake over it and echoes one message
  TEchoServer = class(TThread)
  strict private
  const
    AcceptPollMs = 100;
  var
    FListener: ITcpListener;
    FConfig: ITlsServerConfig;
    FError: string;
    FEchoed: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AListener: ITcpListener; const AConfig: ITlsServerConfig);
    property Error: string read FError;
    property Echoed: Boolean read FEchoed;
  end;

{ TEchoServer }

constructor TEchoServer.Create(const AListener: ITcpListener; const AConfig: ITlsServerConfig);
begin
  FListener := AListener;
  FConfig := AConfig;
  inherited Create(False);
end;

procedure TEchoServer.Execute;
var
  LStream: ITlsTimedTransport;
  LConnection: TTlsConnection;
  LBuffer: TBytes;
  LCount: Int32;
begin
  try
    while (LStream = nil) and not Terminated do
      FListener.TryAccept(AcceptPollMs, LStream);
    if LStream = nil then
      Exit;
    LConnection := TTlsConnection.CreateServer(FConfig, LStream, nil, 0);
    try
      LConnection.Handshake(30000);
      SetLength(LBuffer, 64);
      LCount := LConnection.Read(LBuffer[0], System.Length(LBuffer));
      if LCount > 0 then
      begin
        LConnection.Write(LBuffer[0], LCount);
        FEchoed := True;
      end;
      LConnection.CloseNotifyQuietly;
    finally
      LConnection.Free;
    end;
  except
    on E: Exception do
      FError := E.ClassName + ': ' + E.Message;
  end;
end;

{ TFakeResolver }

constructor TFakeResolver.Create(const AName: string);
begin
  inherited Create;
  FName := AName;
end;

function TFakeResolver.TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
begin
  Inc(FAsked);
  Result := AHost = FName;
  if Result then
    AAddress := TBytes.Create(127, 0, 0, 1)
  else
    AAddress := nil;
end;

{ TTestNetSocket }

function TTestNetSocket.ClientConfig: ITlsClientConfig;
var
  LVectors: TStringList;
begin
  LVectors := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(WebPkiServer(DecodeHex(LVectors.Values['root_cert']))).Build;
  finally
    LVectors.Free;
  end;
end;

function TTestNetSocket.ServerConfig: ITlsServerConfig;
var
  LVectors: TStringList;
begin
  LVectors := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithCredential(TTlsCredential.Load(Crypto, Pkix, DecodeHex(LVectors.Values['leaf_cert']),
        DecodeHex(LVectors.Values['leaf_key']))).Build;
  finally
    LVectors.Free;
  end;
end;

function TTestNetSocket.Listener: ITcpListener;
begin
  Result := TTcpListener.Create('127.0.0.1', 0) as ITcpListener;
end;

function TTestNetSocket.Connector: ITcpConnector;
begin
  Result := TTcpConnector.Create(5000) as ITcpConnector;
end;

procedure TTestNetSocket.ConnectPair(const AListener: ITcpListener;
  out AClient, AServer: ITlsTimedTransport);
var
  LLeft: Int32;
begin
  AClient := Connector.Connect('127.0.0.1', AListener.Port);
  AServer := nil;
  LLeft := 50;
  while (AServer = nil) and (LLeft > 0) do
  begin
    AListener.TryAccept(100, AServer);
    Dec(LLeft);
  end;
  CheckTrue(AServer <> nil, 'the listener accepted the connection');
end;

procedure TTestNetSocket.TestBytesRoundTripOnAnEphemeralPort;
var
  LListener: ITcpListener;
  LClient, LServer: ITlsTimedTransport;
  LSent, LGot: TBytes;
  LCount: Int32;
begin
  LListener := Listener;
  CheckTrue(LListener.Port <> 0, 'port 0 binds an ephemeral port');
  ConnectPair(LListener, LClient, LServer);
  LSent := TBytes.Create(1, 2, 3, 4, 5);
  LClient.Write(LSent, 0, System.Length(LSent));
  SetLength(LGot, 16);
  LCount := LServer.Read(LGot, 0, System.Length(LGot));
  CheckEquals(5, LCount, 'the server reads what the client wrote');
  CheckEquals(3, LGot[2], 'the bytes arrive in order');
  LServer.Write(LGot, 0, LCount);
  SetLength(LGot, 16);
  CheckEquals(5, LClient.Read(LGot, 0, System.Length(LGot)), 'and the client reads the reply');
end;

procedure TTestNetSocket.TestTryAcceptWithNoClientReturnsWithinItsBound;
var
  LListener: ITcpListener;
  LStream: ITlsTimedTransport;
  LClock: ITlsMonotonicClock;
  LStart, LElapsed: Int64;
begin
  LListener := Listener;
  LClock := TSystemMonotonicClock.Create;
  LStart := LClock.NowMonotonicMillis;
  CheckFalse(LListener.TryAccept(150, LStream), 'no client, no connection');
  LElapsed := LClock.NowMonotonicMillis - LStart;
  CheckTrue(LStream = nil, 'no transport is returned');
  CheckTrue(LElapsed < 1500, 'the wait ends near its bound, not when a client arrives');
end;

procedure TTestNetSocket.TestConnectToAClosedPortRaisesConnectError;
var
  LListener: ITcpListener;
  LConnector: ITcpConnector;
  LPort: Word;
  LRaised: Boolean;
begin
  LListener := Listener;
  LPort := LListener.Port;
  LListener := nil; // released, so nothing listens on the port
  LConnector := TTcpConnector.Create(1000) as ITcpConnector;
  LRaised := False;
  try
    LConnector.Connect('127.0.0.1', LPort);
  except
    on E: ENetConnectError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a refused connect raises ENetConnectError');
end;

procedure TTestNetSocket.TestNonPositiveConnectTimeoutIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TTcpConnector.Create(0);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a zero connect timeout is refused');
end;

procedure TTestNetSocket.TestConnectTimeoutBelowASecondConnects;
var
  LListener: ITcpListener;
  LConnector: ITcpConnector;
  LStream: ITlsTimedTransport;
begin
  // a timeout counted in whole seconds would round 50 ms down to none
  LListener := Listener;
  LConnector := TTcpConnector.Create(50) as ITcpConnector;
  LStream := LConnector.Connect('127.0.0.1', LListener.Port);
  CheckTrue(LStream <> nil, 'a connect with a 50 ms timeout still connects');
end;

procedure TTestNetSocket.TestConnectToAnEmptyHostRaisesConnectError;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Connector.Connect('', 80);
  except
    on E: ENetConnectError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty host is not dialled');
end;

procedure TTestNetSocket.TestListenerRefusesAnAddressThatIsNotAnIpv4Literal;
var
  LRaisedName, LRaisedEmpty: Boolean;
begin
  // a name may resolve to all interfaces on some targets; a loopback-only listener must never do that
  LRaisedName := False;
  try
    TTcpListener.Create('localhost', 0);
  except
    on E: ENetSocketError do
      LRaisedName := True;
  end;
  CheckTrue(LRaisedName, 'a host name is refused');
  LRaisedEmpty := False;
  try
    TTcpListener.Create('', 0);
  except
    on E: ENetSocketError do
      LRaisedEmpty := True;
  end;
  CheckTrue(LRaisedEmpty, 'an empty address is refused');
end;

procedure TTestNetSocket.TestConnectorResolvesNamesThroughItsResolver;
var
  LListener: ITcpListener;
  LFake: TFakeResolver;
  LResolver: IHostResolver;
  LConnector: ITcpConnector;
  LClient, LServer: ITlsTimedTransport;
  LLeft: Int32;
begin
  LListener := Listener;
  LFake := TFakeResolver.Create('peer.test');
  LResolver := LFake as IHostResolver;
  LConnector := TTcpConnector.Create(5000, LResolver) as ITcpConnector;
  LClient := LConnector.Connect('peer.test', LListener.Port);
  LLeft := 50;
  while (LServer = nil) and (LLeft > 0) do
  begin
    LListener.TryAccept(100, LServer);
    Dec(LLeft);
  end;
  CheckTrue((LClient <> nil) and (LServer <> nil), 'the name reached the listener');
  CheckEquals(1, LFake.Asked, 'the resolver was asked once');
end;

procedure TTestNetSocket.TestConnectorRefusesAHostTheResolverCannotFind;
var
  LRaised: Boolean;
  LResolver: IHostResolver;
  LConnector: ITcpConnector;
begin
  LRaised := False;
  LResolver := TFakeResolver.Create('peer.test') as IHostResolver;
  LConnector := TTcpConnector.Create(1000, LResolver) as ITcpConnector;
  try
    LConnector.Connect('other.test', 80);
  except
    on E: ENetConnectError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a host the resolver does not know raises a connect error');
end;

procedure TTestNetSocket.TestNilResolverIsRefused;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TTcpConnector.Create(1000, nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil resolver raises');
end;

procedure TTestNetSocket.TestSystemResolverFindsLiteralsAndLocalhost;
var
  LResolver: IHostResolver;
  LAddress: TBytes;
begin
  LResolver := TSystemHostResolver.Create as IHostResolver;
  CheckTrue(LResolver.TryResolveIPv4('10.1.2.3', LAddress), 'a literal needs no lookup');
  CheckEquals(4, System.Length(LAddress), 'four octets');
  CheckEquals(10, LAddress[0], 'in network order');
  CheckEquals(3, LAddress[3], 'to the last octet');
  // the layout of the system's address list differs by OS, so a wrong reading shows here
  CheckTrue(LResolver.TryResolveIPv4('localhost', LAddress), 'localhost resolves');
  CheckEquals(127, LAddress[0], 'to the loopback network');
end;

procedure TTestNetSocket.TestSystemResolverRefusesEmptyNonAsciiAndUnknownNames;
var
  LResolver: IHostResolver;
  LAddress: TBytes;
begin
  LResolver := TSystemHostResolver.Create as IHostResolver;
  CheckFalse(LResolver.TryResolveIPv4('', LAddress), 'an empty host has no address');
  CheckFalse(LResolver.TryResolveIPv4('b' + Char($FC) + 'cher.example', LAddress),
    'a non-ASCII name is refused before any lookup');
  CheckFalse(LResolver.TryResolveIPv4('name.invalid', LAddress),
    'a name under .invalid never resolves (RFC 6761)');
end;

procedure TTestNetSocket.TestSocketsPastTheSelectLimitStillWork;
const
  HeldSockets = 1100;
  // descriptors given back after the climb, for the listener, client and server below
  Headroom = 8;
var
  LHeld: array of ITcpListener;
  LCount: Int32;
  LListener: ITcpListener;
  LClient, LServer: ITlsTimedTransport;
  LBuffer: TBytes;
  LCapRaised, LLimitReached: Boolean;
begin
  // a select set names no descriptor past 1024, so a socket opened after this many must still be
  // waited on, connected, accepted and read
  SetLength(LHeld, HeldSockets + Headroom);
  LCount := 0;
  LLimitReached := False;
  try
    try
      while LCount < HeldSockets + Headroom do
      begin
        LHeld[LCount] := Listener;
        Inc(LCount);
      end;
    except
      on E: ENetSocketError do
        LLimitReached := True;
    end;
    // a process that cannot hold this many sockets cannot take a descriptor past the limit
    if LLimitReached then
      Exit;
    SetLength(LHeld, HeldSockets);
    LListener := Listener;
    ConnectPair(LListener, LClient, LServer);
    LClient.Write(TBytes.Create(7), 0, 1);
    SetLength(LBuffer, 4);
    CheckEquals(1, LServer.Read(LBuffer, 0, System.Length(LBuffer)), 'a byte crosses');
    LServer.SetReadTimeout(100);
    LCapRaised := False;
    try
      LServer.Read(LBuffer, 0, System.Length(LBuffer));
    except
      on E: ETlsHandshakeTimeout do
        LCapRaised := True;
    end;
    CheckTrue(LCapRaised, 'the read cap holds on a high descriptor');
  finally
    LHeld := nil;
  end;
end;

procedure TTestNetSocket.TestHandshakeReadCapRaisesHandshakeTimeout;
var
  LListener: ITcpListener;
  LClient, LServer: ITlsTimedTransport;
  LClock: ITlsMonotonicClock;
  LBuffer: TBytes;
  LStart: Int64;
  LRaised: Boolean;
begin
  LListener := Listener;
  ConnectPair(LListener, LClient, LServer);
  LClock := TSystemMonotonicClock.Create;
  LClient.UseClock(LClock);
  LClient.SetReadTimeout(300);
  SetLength(LBuffer, 16);
  LStart := LClock.NowMonotonicMillis;
  LRaised := False;
  try
    LClient.Read(LBuffer, 0, System.Length(LBuffer));
  except
    on E: ETlsHandshakeTimeout do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a silent peer ends the capped read with ETlsHandshakeTimeout');
  CheckTrue(LClock.NowMonotonicMillis - LStart < 4000, 'and within about the cap');
end;

procedure TTestNetSocket.TestApplicationReadCapRaisesRetryableReadTimeout;
var
  LListener: ITcpListener;
  LClient, LServer: ITlsTimedTransport;
  LBuffer: TBytes;
  LRaised: Boolean;
begin
  LListener := Listener;
  ConnectPair(LListener, LClient, LServer);
  LClient.UseClock(TSystemMonotonicClock.Create as ITlsMonotonicClock);
  LClient.SetApplicationReadTimeout(300);
  SetLength(LBuffer, 16);
  LRaised := False;
  try
    LClient.Read(LBuffer, 0, System.Length(LBuffer));
  except
    on E: ETlsReadTimeout do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an application read cap raises the retryable ETlsReadTimeout');
end;

procedure TTestNetSocket.TestPeerCloseReadsAsEndOfStream;
var
  LListener: ITcpListener;
  LClient, LServer: ITlsTimedTransport;
  LBuffer: TBytes;
begin
  LListener := Listener;
  ConnectPair(LListener, LClient, LServer);
  LServer := nil;
  SetLength(LBuffer, 16);
  CheckEquals(0, LClient.Read(LBuffer, 0, System.Length(LBuffer)),
    'an orderly peer close reads as 0');
end;

procedure TTestNetSocket.TestServerHandshakeFailsFastWhenTheClientClosesFirst;
var
  LListener: ITcpListener;
  LClient, LServer: ITlsTimedTransport;
  LConnection: TTlsConnection;
  LClock: ITlsMonotonicClock;
  LStart: Int64;
  LRaised: Boolean;
begin
  LListener := Listener;
  ConnectPair(LListener, LClient, LServer);
  LClient := nil; // closes before sending a ClientHello
  LClock := TSystemMonotonicClock.Create;
  LConnection := TTlsConnection.CreateServer(ServerConfig, LServer, nil, 0);
  try
    LStart := LClock.NowMonotonicMillis;
    LRaised := False;
    try
      LConnection.Handshake(30000);
    except
      on E: Exception do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'the handshake does not complete');
    CheckTrue(LClock.NowMonotonicMillis - LStart < 2000,
      'the server notices the close at once instead of waiting out its handshake cap');
  finally
    LConnection.Free;
  end;
end;

procedure TTestNetSocket.TestTlsConnectionRunsOverTheStreamsOnBothEnds;
var
  LListener: ITcpListener;
  LServerThread: TEchoServer;
  LConnection: TTlsConnection;
  LSent, LGot: TBytes;
  LCount: Int32;
begin
  LListener := Listener;
  LServerThread := TEchoServer.Create(LListener, ServerConfig);
  try
    LConnection := TTlsConnection.CreateClient(ClientConfig, 'localhost',
      Connector.Connect('127.0.0.1', LListener.Port), nil, 0);
    try
      LConnection.Handshake(30000);
      LSent := TBytes.Create(Ord('p'), Ord('i'), Ord('n'), Ord('g'));
      LConnection.Write(LSent[0], System.Length(LSent));
      SetLength(LGot, 16);
      LCount := LConnection.Read(LGot[0], System.Length(LGot));
      CheckEquals(4, LCount, 'the echo comes back through the record layer');
      CheckEquals(Ord('g'), LGot[3], 'with the bytes sent');
    finally
      LConnection.Free;
    end;
    LServerThread.WaitFor;
    CheckEquals('', LServerThread.Error, 'the server side ran clean');
    CheckTrue(LServerThread.Echoed, 'the server read and echoed the message');
  finally
    LServerThread.Terminate;
    LServerThread.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestNetSocket);
{$ELSE}
  RegisterTest(TTestNetSocket.Suite);
{$ENDIF FPC}

end.
