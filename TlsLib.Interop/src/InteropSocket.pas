{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit InteropSocket;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Sockets;

type
  /// <summary>A blocking-socket transport failure in the interop harness.</summary>
  EInteropSocket = class(Exception);

  TSocketHandle = LongInt;

  /// <summary>
  /// A minimal blocking TCP endpoint over the FPC Sockets API: send-all,
  /// receive-some, and half-close. The interop harness drives the sans-IO engine
  /// through this in place of a peer engine (socket -> ProcessInput, TakeOutgoing
  /// -> socket). Not thread-safe; the caller serializes.
  /// </summary>
  TInteropSocket = class(TObject)
  strict private
  var
    FHandle: TSocketHandle;
    /// <summary>
    /// Half-closes the send side then reads until the peer's FIN, so the close does
    /// not reset a connection whose receive buffer still holds unread bytes.
    /// </summary>
    procedure DrainAndClose;
  public
    /// <summary>Wraps an already-connected/accepted socket handle.</summary>
    constructor Create(AHandle: TSocketHandle);
    /// <summary>Connects to AHost:APort (AHost is a dotted IPv4 or "localhost").</summary>
    class function Connect(const AHost: string; APort: Word): TInteropSocket; static;
    destructor Destroy; override;
    /// <summary>Sends every byte of the slice, looping over short writes.</summary>
    procedure SendAll(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>Receives up to AMaxLength bytes into ABuf; 0 means the peer closed.</summary>
    function Recv(var ABuf: TBytes; AMaxLength: Int32): Int32;
    /// <summary>Half-closes the send direction (sends a TCP FIN).</summary>
    procedure ShutdownWrite;
  end;

  /// <summary>
  /// A blocking TCP listener that accepts one connection at a time. Used by the
  /// openssl matrix / loopback drivers when the harness plays the TCP server; the
  /// BoGo shim never needs it (it always dials out to the runner).
  /// </summary>
  TInteropListener = class(TObject)
  strict private
  var
    FHandle: TSocketHandle;
    FPort: Word;
  public
    /// <summary>Binds AHost:APort and listens; APort = 0 takes an ephemeral port.</summary>
    class function Bind(const AHost: string; APort: Word): TInteropListener; static;
    destructor Destroy; override;
    /// <summary>Blocks until a peer connects and returns the accepted socket.</summary>
    function Accept: TInteropSocket;
    /// <summary>The actual bound port (resolved when an ephemeral port was requested).</summary>
    property Port: Word read FPort;
  end;

implementation

resourcestring
  SSocketCreate = 'interop socket: could not create a socket';
  SSocketConnect = 'interop socket: could not connect to %s:%d';
  SSocketBind = 'interop socket: could not bind %s:%d';
  SSocketListen = 'interop socket: could not listen';
  SSocketAccept = 'interop socket: accept failed';
  SSocketSend = 'interop socket: send failed';
  SSocketRecv = 'interop socket: receive failed';
  SSocketAddress = 'interop socket: not a dotted IPv4 address: %s';

const
  // "localhost" is resolved to the IPv4 loopback; the harness only ever talks to a
  // loopback peer (the BoGo runner, openssl s_server/s_client, or another engine)
  LoopbackIp = '127.0.0.1';

function ResolveIp(const AHost: string): string;
begin
  if SameText(AHost, 'localhost') or (AHost = '') then
    Result := LoopbackIp
  else
    Result := AHost;
end;

function IsIpv6(const AHost: string): Boolean;
begin
  Result := Pos(':', AHost) > 0;
end;

function MakeSockAddr(const AHost: string; APort: Word;
  out AAddr: TInetSockAddr): Boolean;
var
  LNetAddr: TInAddr;
begin
  LNetAddr := StrToNetAddr(ResolveIp(AHost));
  // StrToNetAddr yields 0.0.0.0 only for the unspecified address or a parse failure
  Result := LNetAddr.s_addr <> 0;
  if not Result then
    Exit;
  FillChar(AAddr, SizeOf(AAddr), 0);
  AAddr.sin_family := AF_INET;
  AAddr.sin_port := htons(APort);
  AAddr.sin_addr := LNetAddr;
end;

function ConnectIpv6(const AHost: string; APort: Word): TSocketHandle;
var
  LAddr: TInetSockAddr6;
begin
  FillChar(LAddr, SizeOf(LAddr), 0);
  LAddr.sin6_family := AF_INET6;
  LAddr.sin6_port := htons(APort);
  LAddr.sin6_addr := StrToHostAddr6(AHost);
  Result := fpSocket(AF_INET6, SOCK_STREAM, 0);
  if Result < 0 then
    raise EInteropSocket.CreateRes(@SSocketCreate);
  if fpConnect(Result, @LAddr, SizeOf(LAddr)) <> 0 then
  begin
    CloseSocket(Result);
    raise EInteropSocket.CreateResFmt(@SSocketConnect, [AHost, APort]);
  end;
end;

{ TInteropSocket }

constructor TInteropSocket.Create(AHandle: TSocketHandle);
begin
  inherited Create;
  FHandle := AHandle;
end;

class function TInteropSocket.Connect(const AHost: string;
  APort: Word): TInteropSocket;
var
  LHandle: TSocketHandle;
  LAddr: TInetSockAddr;
begin
  // the BoGo runner may listen on the IPv6 loopback (-ipv6); dial ::1 in that case
  if IsIpv6(AHost) then
    Exit(TInteropSocket.Create(ConnectIpv6(AHost, APort)));
  if not MakeSockAddr(AHost, APort, LAddr) then
    raise EInteropSocket.CreateResFmt(@SSocketAddress, [AHost]);
  LHandle := fpSocket(AF_INET, SOCK_STREAM, 0);
  if LHandle < 0 then
    raise EInteropSocket.CreateRes(@SSocketCreate);
  if fpConnect(LHandle, @LAddr, SizeOf(LAddr)) <> 0 then
  begin
    CloseSocket(LHandle);
    raise EInteropSocket.CreateResFmt(@SSocketConnect, [ResolveIp(AHost), APort]);
  end;
  Result := TInteropSocket.Create(LHandle);
end;

destructor TInteropSocket.Destroy;
begin
  if FHandle >= 0 then
  begin
    DrainAndClose;
    FHandle := -1;
  end;
  inherited Destroy;
end;

procedure TInteropSocket.DrainAndClose;
const
  // an overall wall-clock backstop so a peer that floods without ever closing cannot spin
  // this loop forever; a well-behaved peer reaches its FIN in well under this
  DrainDeadlineMs = 5000;
var
  LScratch: array [0 .. 4095] of Byte;
  LStart: QWord;
begin
  // On Windows a closesocket() with data still unread in the receive buffer - or still
  // arriving - resets the connection, and an incoming reset discards the peer's receive
  // queue, including a fatal alert we sent that the peer has not read yet. Half-close our
  // send side (our FIN follows our final bytes), then drain to the peer's FIN before
  // closing, so the close cannot reset. The drain runs to the FIN, not a fixed read count:
  // a peer that fragments one byte per record (BoGo's SplitHandshakeRecords) delivers its
  // residual flight as hundreds of tiny segments, and any read-count cap abandons the
  // drain mid-flight, closing with data still unread - which is the reset this prevents.
  fpShutdown(FHandle, 1);
  LStart := GetTickCount64;
  repeat
    // 0 = the peer's FIN: the receive queue is empty and no more data can arrive, so the
    // close below is graceful. < 0 = the peer is gone; nothing left to protect either way.
    if fpRecv(FHandle, @LScratch[0], SizeOf(LScratch), 0) <= 0 then
      Break;
  until GetTickCount64 - LStart >= DrainDeadlineMs;
  CloseSocket(FHandle);
end;

procedure TInteropSocket.SendAll(const AData: TBytes; AOffset, ALength: Int32);
var
  LSent: NativeInt;
  LPos: Int32;
begin
  LPos := AOffset;
  while LPos < AOffset + ALength do
  begin
    LSent := fpSend(FHandle, @AData[LPos], (AOffset + ALength) - LPos, 0);
    if LSent <= 0 then
      raise EInteropSocket.CreateRes(@SSocketSend);
    Inc(LPos, LSent);
  end;
end;

function TInteropSocket.Recv(var ABuf: TBytes; AMaxLength: Int32): Int32;
var
  LGot: NativeInt;
begin
  LGot := fpRecv(FHandle, @ABuf[0], AMaxLength, 0);
  if LGot < 0 then
    raise EInteropSocket.CreateRes(@SSocketRecv);
  Result := LGot;
end;

procedure TInteropSocket.ShutdownWrite;
begin
  fpShutdown(FHandle, 1);
end;

{ TInteropListener }

class function TInteropListener.Bind(const AHost: string;
  APort: Word): TInteropListener;
var
  LHandle: TSocketHandle;
  LAddr: TInetSockAddr;
  LBound: TInetSockAddr;
  LLen: TSockLen;
  LReuse: LongInt;
begin
  if not MakeSockAddr(AHost, APort, LAddr) then
    raise EInteropSocket.CreateResFmt(@SSocketAddress, [AHost]);
  LHandle := fpSocket(AF_INET, SOCK_STREAM, 0);
  if LHandle < 0 then
    raise EInteropSocket.CreateRes(@SSocketCreate);
  LReuse := 1;
  fpSetSockOpt(LHandle, SOL_SOCKET, SO_REUSEADDR, @LReuse, SizeOf(LReuse));
  if fpBind(LHandle, @LAddr, SizeOf(LAddr)) <> 0 then
  begin
    CloseSocket(LHandle);
    raise EInteropSocket.CreateResFmt(@SSocketBind, [ResolveIp(AHost), APort]);
  end;
  if fpListen(LHandle, 1) <> 0 then
  begin
    CloseSocket(LHandle);
    raise EInteropSocket.CreateRes(@SSocketListen);
  end;
  Result := TInteropListener.Create;
  Result.FHandle := LHandle;
  LLen := SizeOf(LBound);
  FillChar(LBound, SizeOf(LBound), 0);
  if fpGetSockName(LHandle, @LBound, @LLen) = 0 then
    Result.FPort := NToHs(LBound.sin_port)
  else
    Result.FPort := APort;
end;

destructor TInteropListener.Destroy;
begin
  if FHandle >= 0 then
    CloseSocket(FHandle);
  inherited Destroy;
end;

function TInteropListener.Accept: TInteropSocket;
var
  LPeer: TSocketHandle;
  LAddr: TInetSockAddr;
  LLen: TSockLen;
begin
  LLen := SizeOf(LAddr);
  LPeer := fpAccept(FHandle, @LAddr, @LLen);
  if LPeer < 0 then
    raise EInteropSocket.CreateRes(@SSocketAccept);
  Result := TInteropSocket.Create(LPeer);
end;

end.
