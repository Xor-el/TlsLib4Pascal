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
    procedure TestHandshakeReadCapRaisesHandshakeTimeout;
    procedure TestApplicationReadCapRaisesRetryableReadTimeout;
    procedure TestPeerCloseReadsAsEndOfStream;
    procedure TestServerHandshakeFailsFastWhenTheClientClosesFirst;
    procedure TestTlsConnectionRunsOverTheStreamsOnBothEnds;
  end;

implementation

type
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

{ TTestNetSocket }

function TTestNetSocket.ClientConfig: ITlsClientConfig;
var
  LVectors: TStringList;
begin
  LVectors := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithTrustAnchors(DecodeHex(LVectors.Values['root_cert'])).Build;
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
