{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpNetSocket;

{ Reference ITcpConnector and ITcpListener over the RTL socket classes (Free Pascal ssockets,
  Delphi System.Net.Socket), OUTSIDE the sans-IO core package like TlpSocketHttpFetcher. This is the
  one unit that knows which socket library the compiler brings; callers hold the interfaces.
  The sockets are IPv4. A connect timeout is honoured in whole seconds, rounded up, on both. A send
  is not bounded: ITlsTransport.Write blocks until the bytes are handed over. }

{$I ..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
{$IFDEF UNIX}
  BaseUnix,
{$ELSE}
  Winsock2,
{$ENDIF UNIX}
  ssockets,
  Sockets,
{$ELSE}
{$IFDEF MSWINDOWS}
  Winsock2,
{$ELSE}
  Posix.SysSocket,
  Posix.NetinetIn,
  Posix.Fcntl,
  Posix.Errno,
{$ENDIF MSWINDOWS}
  SyncObjs,
  System.Net.Socket,
{$ENDIF FPC}
  TlpITlsTransport,
  TlpINetSocket,
  TlpNetExceptions,
  TlpTlsLibExceptions,
  TlpTlsConnection;

type
{$IFDEF FPC}
  // reaches the protected idle loop and accept
  TNetFpcServer = class(TInetServer)
  public
    /// <summary>Waits at most AMs ms for a connection and accepts it into AHandle.</summary>
    function WaitAndAccept(AMs: Int32; out AHandle: Longint): Boolean;
  end;

  /// <summary>The wait for a socket to become readable, by select. The kernel's socket receive
  /// timeout is not settable on every CPU, and a read that depends on it then blocks for good.</summary>
  TNetReadiness = class sealed(TObject)
  public
    /// <summary>True when AHandle has data, or has failed, within AMs ms; a failure counts as
    /// readable so the read that follows reports it.</summary>
    class function WaitReadable(AHandle: Longint; AMs: Int32): Boolean; static;
  end;

  TNetStreamSocket = TSocketStream;
  TNetServerSocket = TNetFpcServer;
{$ELSE}
  // reaches the protected handle constructor and the readiness wait
  TNetRtlSocket = class(TSocket)
  protected
    function GetClientSocket(Handle: TSocketHandle; const Addr: sockaddr_in): TSocket; override;
  public
    constructor CreateFromHandle(AHandle: TSocketHandle; const AAddr: sockaddr_in);
    function WaitReadable(AMs: Int32): Boolean;
  end;

  TNetStreamSocket = TNetRtlSocket;
  TNetServerSocket = TNetRtlSocket;
{$ENDIF FPC}

  /// <summary>An ITcpConnector over the RTL sockets. The streams it returns bound a read with the
  /// connection's handshake and application-read caps, and block otherwise.</summary>
  TTcpConnector = class sealed(TInterfacedObject, ITcpConnector)
  strict private
    FConnectTimeoutMs: Int32;
  public
    /// <summary>AConnectTimeoutMs must be positive; it is rounded up to whole seconds.</summary>
    constructor Create(AConnectTimeoutMs: Int32);
    function Connect(const AHost: string; APort: Word): ITlsTimedTransport;
  end;

  /// <summary>An ITcpListener over the RTL sockets, bound to an IPv4 address and listening.</summary>
  TTcpListener = class sealed(TInterfacedObject, ITcpListener)
  strict private
  var
    FServer: TNetServerSocket;
    FPort: Word;
  public
    /// <summary>AAddress is an IPv4 literal; APort 0 picks an ephemeral port.</summary>
    constructor Create(const AAddress: string; APort: Word);
    destructor Destroy; override;
    function Port: Word;
    function TryAccept(ATimeoutMs: Int32; out ATransport: ITlsTimedTransport): Boolean;
  end;

implementation

const
  LISTEN_BACKLOG = 8;
  // a send to a peer that has gone must not kill the process with SIGPIPE: MSG_NOSIGNAL per send
  // where it exists, else the SO_NOSIGPIPE option (Darwin)
{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}
  SEND_FLAGS = 0;
  NOSIGPIPE_SOCKOPT = SO_NOSIGPIPE;
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID)}
  SEND_FLAGS = $4000;
  NOSIGPIPE_SOCKOPT = 0;
{$ELSEIF DEFINED(TLSLIB_BSD)}
  SEND_FLAGS = MSG_NOSIGNAL;
  NOSIGPIPE_SOCKOPT = 0;
{$ELSE}
  SEND_FLAGS = 0;
  NOSIGPIPE_SOCKOPT = 0;
{$IFEND}

resourcestring
  SNetConnectFailed = 'could not connect to %s:%d: %s';
  SNetConnectTimedOut = 'the connect timeout elapsed';
  SNetListenFailed = 'could not listen on %s:%d: %s';
  SNetAcceptFailed = 'accepting a connection failed: %s';
  SNetNonPositiveTimeout = 'the connect timeout must be positive';
  SNetReceiveTimedOut = 'the socket receive timeout elapsed with no data from the peer';
  SNetSendFailed = 'the socket made no progress sending';

type
  // the socket operations: one declaration, with a body per compiler further down
  TNetSocketOps = class sealed(TObject)
  strict private
    class procedure ArmAgainstSigPipe(ASocket: TNetStreamSocket); static;
  public
    /// <summary>Raises ENetConnectError.</summary>
    class function Connect(const AHost: string; APort: Word;
      AConnectTimeoutMs: Int32): TNetStreamSocket; static;
    /// <summary>The count read, 0 at an orderly close, -1 on a socket error. Raises
    /// ENetReceiveTimeout when ATimeoutMs > 0 passes with no byte (0 blocks).</summary>
    class function Receive(ASocket: TNetStreamSocket; var ABuffer: TBytes;
      AOffset, AMaxLength, ATimeoutMs: Int32): Int32; static;
    /// <summary>The count sent, or -1 on a socket error.</summary>
    class function Send(ASocket: TNetStreamSocket; const ABuffer: TBytes;
      AOffset, ALength: Int32): Int32; static;
    class procedure CloseStream(ASocket: TNetStreamSocket); static;
    /// <summary>Raises ENetSocketError.</summary>
    class function Listen(const AAddress: string; APort: Word): TNetServerSocket; static;
    class function BoundPort(AServer: TNetServerSocket): Word; static;
    /// <summary>A connected socket, or nil when ATimeoutMs passes with no client.</summary>
    class function TryAccept(AServer: TNetServerSocket;
      ATimeoutMs: Int32): TNetStreamSocket; static;
    class procedure CloseServer(AServer: TNetServerSocket); static;
  end;

  TTcpStream = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FSocket: TNetStreamSocket;
  strict protected
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    /// <summary>Takes ownership of ASocket.</summary>
    constructor Create(ASocket: TNetStreamSocket);
    destructor Destroy; override;
  end;

{$IFDEF FPC}

{ TNetReadiness }

class function TNetReadiness.WaitReadable(AHandle: Longint; AMs: Int32): Boolean;
var
  LSet: TFDSet;
  LTime: TTimeVal;
  LReady: Longint;
begin
{$IFDEF UNIX}
  // a descriptor this high does not fit a select set: skip the wait and let the read block
  if AHandle >= FD_MAXFDSET then
    Exit(True);
{$ENDIF UNIX}
  LTime.tv_sec := AMs div 1000;
  LTime.tv_usec := (AMs mod 1000) * 1000;
  repeat
{$IFDEF UNIX}
    LSet := Default(TFDSet);
    fpFD_ZERO(LSet);
    fpFD_SET(AHandle, LSet);
    LReady := fpSelect(AHandle + 1, @LSet, nil, nil, @LTime);
{$ELSE}
    FD_ZERO(LSet);
    FD_SET(AHandle, LSet);
    LReady := Select(AHandle + 1, @LSet, nil, nil, @LTime);
{$ENDIF UNIX}
  until (LReady >= 0) or (SocketError <> EsockEINTR);
  // an error counts as readable, so the read that follows reports it
  Result := LReady <> 0;
end;

{ TNetFpcServer }

function TNetFpcServer.WaitAndAccept(AMs: Int32; out AHandle: Longint): Boolean;
var
  LLen: Longint;
begin
  AHandle := -1;
  AcceptIdleTimeOut := Cardinal(AMs);
  // not accepting, so the idle loop makes the one bounded wait and returns
  Result := RunIdleLoop;
  if Result then
  begin
    // the inherited Accept closes the connection it takes when the server is not accepting
    repeat
      LLen := SizeOf(FAddr);
      AHandle := fpAccept(Socket, @FAddr, @LLen);
    until (AHandle >= 0) or (SocketError <> EsockEINTR);
    if AHandle < 0 then
      raise ENetSocketError.Create(Format(SNetAcceptFailed, [IntToStr(SocketError)]));
  end;
end;

{ TNetSocketOps }

class procedure TNetSocketOps.ArmAgainstSigPipe(ASocket: TNetStreamSocket);
var
  LOn: Integer;
begin
  ASocket.WriteFlags := SEND_FLAGS;
  if NOSIGPIPE_SOCKOPT <> 0 then
  begin
    LOn := 1;
    fpSetSockOpt(ASocket.Handle, SOL_SOCKET, NOSIGPIPE_SOCKOPT, @LOn, SizeOf(LOn));
  end;
end;

class function TNetSocketOps.Connect(const AHost: string; APort: Word;
  AConnectTimeoutMs: Int32): TNetStreamSocket;
begin
  try
    Result := TInetSocket.Create(AHost, APort, AConnectTimeoutMs);
  except
    on E: ESocketError do
      raise ENetConnectError.Create(Format(SNetConnectFailed, [AHost, APort, E.Message]));
  end;
  ArmAgainstSigPipe(Result);
end;

class function TNetSocketOps.Receive(ASocket: TNetStreamSocket; var ABuffer: TBytes;
  AOffset, AMaxLength, ATimeoutMs: Int32): Int32;
begin
  if (ATimeoutMs > 0) and not TNetReadiness.WaitReadable(ASocket.Handle, ATimeoutMs) then
    raise ENetReceiveTimeout.Create(SNetReceiveTimedOut);
  Result := ASocket.Read(ABuffer[AOffset], AMaxLength);
  if Result < 0 then
    Result := -1;
end;

class function TNetSocketOps.Send(ASocket: TNetStreamSocket; const ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  Result := ASocket.Write(ABuffer[AOffset], ALength);
end;

class procedure TNetSocketOps.CloseStream(ASocket: TNetStreamSocket);
begin
  ASocket.Free;
end;

class function TNetSocketOps.Listen(const AAddress: string; APort: Word): TNetServerSocket;
begin
  Result := TNetFpcServer.Create(AAddress, APort);
  try
    Result.ReuseAddress := True;
    Result.QueueSize := LISTEN_BACKLOG;
    Result.Listen;
  except
    on E: ESocketError do
    begin
      Result.Free;
      Result := nil;
      raise ENetSocketError.Create(Format(SNetListenFailed, [AAddress, APort, E.Message]));
    end;
  end;
end;

class function TNetSocketOps.BoundPort(AServer: TNetServerSocket): Word;
var
  LAddr: TInetSockAddr;
  LLen: TSockLen;
begin
  LAddr := Default(TInetSockAddr);
  LLen := SizeOf(LAddr);
  fpGetSockName(AServer.Socket, @LAddr, @LLen);
  Result := NToHs(LAddr.sin_port);
end;

class function TNetSocketOps.TryAccept(AServer: TNetServerSocket;
  ATimeoutMs: Int32): TNetStreamSocket;
var
  LHandle: Longint;
begin
  Result := nil;
  if AServer.WaitAndAccept(ATimeoutMs, LHandle) then
  begin
    Result := TSocketStream.Create(LHandle);
    ArmAgainstSigPipe(Result);
  end;
end;

class procedure TNetSocketOps.CloseServer(AServer: TNetServerSocket);
begin
  AServer.Free;
end;

{$ELSE}

type
  // the OS calls the RTL socket class does not expose
  TNetOs = class sealed(TObject)
  public
    class function OpenStreamSocket: TSocketHandle; static;
    class procedure SetBlocking(AHandle: TSocketHandle; ABlocking: Boolean); static;
    /// <summary>False when the connect failed outright; True when it is made or under way.</summary>
    class function BeginConnect(AHandle: TSocketHandle; var AAddr: sockaddr_in): Boolean; static;
    /// <summary>The pending error of the socket's connect, 0 when it succeeded.</summary>
    class function ConnectError(AHandle: TSocketHandle): Integer; static;
    class procedure SuppressSigPipe(AHandle: TSocketHandle); static;
    /// <summary>Straight to the OS: the RTL overloads take a byte for the buffer as a
    /// one-element open array.</summary>
    class function ReadBytes(AHandle: TSocketHandle; var ABuffer: TBytes;
      AOffset, ALength: Int32): Int32; static;
    class function WriteBytes(AHandle: TSocketHandle; const ABuffer: TBytes;
      AOffset, ALength: Int32): Int32; static;
  end;

{ TNetRtlSocket }

constructor TNetRtlSocket.CreateFromHandle(AHandle: TSocketHandle; const AAddr: sockaddr_in);
begin
  inherited Create(AHandle, AAddr, nil);
end;

function TNetRtlSocket.GetClientSocket(Handle: TSocketHandle;
  const Addr: sockaddr_in): TSocket;
begin
  Result := TNetRtlSocket.CreateFromHandle(Handle, Addr);
end;

function TNetRtlSocket.WaitReadable(AMs: Int32): Boolean;
begin
  Result := WaitForData(Cardinal(AMs)) = TWaitResult.wrSignaled;
end;

{ TNetOs }

class function TNetOs.OpenStreamSocket: TSocketHandle;
begin
  Result := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if Result = InvalidSocket then
    raise ENetSocketError.Create(SysErrorMessage(GetLastError));
end;

class procedure TNetOs.SetBlocking(AHandle: TSocketHandle; ABlocking: Boolean);
{$IFDEF MSWINDOWS}
var
  LMode: u_long;
begin
  LMode := Ord(not ABlocking);
  if ioctlsocket(AHandle, FIONBIO, LMode) <> 0 then
    raise ENetSocketError.Create(SysErrorMessage(WSAGetLastError));
end;
{$ELSE}
var
  LFlags: Integer;
begin
  LFlags := fcntl(AHandle, F_GETFL, 0);
  if ABlocking then
    LFlags := LFlags and (not O_NONBLOCK)
  else
    LFlags := LFlags or O_NONBLOCK;
  if (LFlags < 0) or (fcntl(AHandle, F_SETFL, LFlags) < 0) then
    raise ENetSocketError.Create(SysErrorMessage(GetLastError));
end;
{$ENDIF MSWINDOWS}

class function TNetOs.BeginConnect(AHandle: TSocketHandle; var AAddr: sockaddr_in): Boolean;
begin
  Result := connect(AHandle, sockaddr(AAddr), SizeOf(AAddr)) = 0;
{$IFDEF MSWINDOWS}
  Result := Result or (WSAGetLastError = WSAEWOULDBLOCK);
{$ELSE}
  Result := Result or (GetLastError = EINPROGRESS) or (GetLastError = EINTR);
{$ENDIF MSWINDOWS}
end;

class function TNetOs.ConnectError(AHandle: TSocketHandle): Integer;
{$IFDEF MSWINDOWS}
var
  LLen: Integer;
begin
  Result := 0;
  LLen := SizeOf(Result);
  if getsockopt(AHandle, SOL_SOCKET, SO_ERROR, PAnsiChar(@Result), LLen) <> 0 then
    Result := WSAGetLastError;
end;
{$ELSE}
var
  LLen: socklen_t;
begin
  Result := 0;
  LLen := SizeOf(Result);
  if getsockopt(AHandle, SOL_SOCKET, SO_ERROR, Result, LLen) <> 0 then
    Result := GetLastError;
end;
{$ENDIF MSWINDOWS}

class procedure TNetOs.SuppressSigPipe(AHandle: TSocketHandle);
{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}
var
  LOn: Integer;
begin
  LOn := 1;
  setsockopt(AHandle, SOL_SOCKET, NOSIGPIPE_SOCKOPT, LOn, SizeOf(LOn));
end;
{$ELSE}
begin
end;
{$IFEND}

class function TNetOs.ReadBytes(AHandle: TSocketHandle; var ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  Result := recv(AHandle, ABuffer[AOffset], ALength, 0);
end;

class function TNetOs.WriteBytes(AHandle: TSocketHandle; const ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  Result := send(AHandle, ABuffer[AOffset], ALength, SEND_FLAGS);
end;

{ TNetSocketOps }

class procedure TNetSocketOps.ArmAgainstSigPipe(ASocket: TNetStreamSocket);
begin
  TNetOs.SuppressSigPipe(ASocket.Handle);
end;

class function TNetSocketOps.Connect(const AHost: string; APort: Word;
  AConnectTimeoutMs: Int32): TNetStreamSocket;
var
  LAddr: sockaddr_in;
  LWrite, LError: TFDSet;
  LWait: TWaitResult;
  LConnectError, LMicroseconds: Integer;
begin
  try
    LAddr := TNetEndpoint.Create(TIPAddress.Create(AHost), APort);
  except
    on E: ESocketError do
      raise ENetConnectError.Create(Format(SNetConnectFailed, [AHost, APort, E.Message]));
  end;
  // the socket object owns the handle from here, so every refusal below closes it
  Result := TNetRtlSocket.CreateFromHandle(TNetOs.OpenStreamSocket, LAddr);
  try
    try
      TNetOs.SetBlocking(Result.Handle, False);
      if not TNetOs.BeginConnect(Result.Handle, LAddr) then
        raise ENetConnectError.Create(Format(SNetConnectFailed,
          [AHost, APort, SysErrorMessage(GetLastError)]));
      // a refused connect shows in the write set on POSIX and the error set on Windows
      LWrite := TFDSet.Create(Result);
      LError := TFDSet.Create(Result);
      if AConnectTimeoutMs > High(Integer) div 1000 then
        LMicroseconds := High(Integer)
      else
        LMicroseconds := AConnectTimeoutMs * 1000;
      LWait := TSocket.Select(nil, @LWrite, @LError, LMicroseconds);
      if LWait <> TWaitResult.wrSignaled then
        raise ENetConnectError.Create(Format(SNetConnectFailed,
          [AHost, APort, SNetConnectTimedOut]));
      LConnectError := TNetOs.ConnectError(Result.Handle);
      if LConnectError <> 0 then
        raise ENetConnectError.Create(Format(SNetConnectFailed,
          [AHost, APort, SysErrorMessage(LConnectError)]));
      TNetOs.SetBlocking(Result.Handle, True);
    except
      on E: ESocketError do
        raise ENetConnectError.Create(Format(SNetConnectFailed, [AHost, APort, E.Message]));
    end;
  except
    CloseStream(Result);
    Result := nil;
    raise;
  end;
  ArmAgainstSigPipe(Result);
end;

class function TNetSocketOps.Receive(ASocket: TNetStreamSocket; var ABuffer: TBytes;
  AOffset, AMaxLength, ATimeoutMs: Int32): Int32;
begin
  if ATimeoutMs > 0 then
  begin
    try
      if not ASocket.WaitReadable(ATimeoutMs) then
        raise ENetReceiveTimeout.Create(SNetReceiveTimedOut);
    except
      on ESocketError do
        Exit(-1);
    end;
  end;
  Result := TNetOs.ReadBytes(ASocket.Handle, ABuffer, AOffset, AMaxLength);
  if Result < 0 then
    Result := -1;
end;

class function TNetSocketOps.Send(ASocket: TNetStreamSocket; const ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  Result := TNetOs.WriteBytes(ASocket.Handle, ABuffer, AOffset, ALength);
  if Result < 0 then
    Result := -1;
end;

class procedure TNetSocketOps.CloseStream(ASocket: TNetStreamSocket);
begin
  // a graceful close drains the peer's remaining bytes, which blocks on a peer that stays silent
  if TSocketState.Connected in ASocket.State then
    ASocket.Close(True);
  ASocket.Free;
end;

class function TNetSocketOps.Listen(const AAddress: string; APort: Word): TNetServerSocket;
begin
  Result := TNetRtlSocket.Create(TSocketType.TCP);
  try
    Result.Listen(AAddress, '', APort, LISTEN_BACKLOG);
  except
    on E: ESocketError do
    begin
      Result.Free;
      Result := nil;
      raise ENetSocketError.Create(Format(SNetListenFailed, [AAddress, APort, E.Message]));
    end;
  end;
end;

class function TNetSocketOps.BoundPort(AServer: TNetServerSocket): Word;
begin
  Result := AServer.LocalEndpoint.Port;
end;

class function TNetSocketOps.TryAccept(AServer: TNetServerSocket;
  ATimeoutMs: Int32): TNetStreamSocket;
var
  LClient: TSocket;
begin
  try
    LClient := AServer.Accept(Cardinal(ATimeoutMs));
  except
    on E: ESocketError do
      raise ENetSocketError.Create(Format(SNetAcceptFailed, [E.Message]));
  end;
  Result := TNetRtlSocket(LClient);
  if Result <> nil then
    ArmAgainstSigPipe(Result);
end;

class procedure TNetSocketOps.CloseServer(AServer: TNetServerSocket);
begin
  CloseStream(AServer);
end;

{$ENDIF FPC}

{ TTcpStream }

constructor TTcpStream.Create(ASocket: TNetStreamSocket);
begin
  inherited Create;
  FSocket := ASocket;
end;

destructor TTcpStream.Destroy;
begin
  TNetSocketOps.CloseStream(FSocket);
  inherited Destroy;
end;

function TTcpStream.ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  repeat
    try
      Exit(TNetSocketOps.Receive(FSocket, ABuffer, AOffset, AMaxLength, ReadTimeoutMs));
    except
      on ENetReceiveTimeout do
        CheckReadCap;
    end;
  until False;
end;

function TTcpStream.SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32;
begin
  Result := TNetSocketOps.Send(FSocket, ABuffer, AOffset, ALength);
  if Result <= 0 then
    raise ETlsStreamError.CreateRes(@SNetSendFailed);
end;

{ TTcpConnector }

constructor TTcpConnector.Create(AConnectTimeoutMs: Int32);
begin
  inherited Create;
  if AConnectTimeoutMs <= 0 then
    raise EArgumentTlsLibException.CreateRes(@SNetNonPositiveTimeout);
  FConnectTimeoutMs := ((AConnectTimeoutMs + 999) div 1000) * 1000;
end;

function TTcpConnector.Connect(const AHost: string; APort: Word): ITlsTimedTransport;
begin
  Result := TTcpStream.Create(TNetSocketOps.Connect(AHost, APort, FConnectTimeoutMs))
    as ITlsTimedTransport;
end;

{ TTcpListener }

constructor TTcpListener.Create(const AAddress: string; APort: Word);
begin
  inherited Create;
  FServer := TNetSocketOps.Listen(AAddress, APort);
  FPort := TNetSocketOps.BoundPort(FServer);
end;

destructor TTcpListener.Destroy;
begin
  if FServer <> nil then
    TNetSocketOps.CloseServer(FServer);
  inherited Destroy;
end;

function TTcpListener.Port: Word;
begin
  Result := FPort;
end;

function TTcpListener.TryAccept(ATimeoutMs: Int32; out ATransport: ITlsTimedTransport): Boolean;
var
  LSocket: TNetStreamSocket;
begin
  ATransport := nil;
  LSocket := TNetSocketOps.TryAccept(FServer, ATimeoutMs);
  Result := LSocket <> nil;
  if Result then
    ATransport := TTcpStream.Create(LSocket) as ITlsTimedTransport;
end;

end.
