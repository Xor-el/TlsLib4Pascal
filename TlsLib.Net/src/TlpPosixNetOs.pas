{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPosixNetOs;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IF DEFINED(TLSLIB_UNIXLIKE)}

uses
  SysUtils,
{$IFDEF FPC}
  BaseUnix,
  Sockets,
  initc,
{$ELSE}
  Posix.SysSocket,
  Posix.NetinetIn,
  Posix.NetDB,
  Posix.Fcntl,
  Posix.Errno,
  Posix.Unistd,
{$ENDIF}
  TlpDynamicLibrary,
  TlpSystemTimeUtilities;

type
  /// <summary>A POSIX socket is a file descriptor, an int on every target.</summary>
  TPosixSocketHandle = Integer;

  /// <summary>What a wait is for: data to read, or room to write (a connect under way).</summary>
  TPosixNetWait = (Readable, Writable);

  /// <summary>The IPv4 TCP socket calls on a POSIX target, by file descriptor. Every call returns
  /// the OS error code (0 for none) or a plain result, and raises nothing: the caller decides how
  /// an error is reported. Each compiler makes the calls through its own RTL and reads that RTL's
  /// errno; accept4, which neither RTL declares, and on Free Pascal getaddrinfo come from the C
  /// library at run time. A socket is close-on-exec from birth where the system can do that; on
  /// Darwin, or a kernel that refuses the flag, it is marked just after, so a process forked on
  /// another thread in that instant can inherit it. Linux on MIPS and SPARC and Android on MIPS
  /// are not supported while the Free Pascal RTL gives those CPUs the socket numbers (on SPARC64
  /// also the errno numbers) of other CPUs: listening and connecting fail there. A Unix this unit
  /// does not name does not compile.</summary>
  TPosixNetOs = class sealed(TObject)
  strict private
  type
{$IFDEF FPC}
    TSockAddrIn = TInetSockAddr;
    TNetSockLen = TSockLen;
    // the C struct addrinfo; Linux and OpenBSD put ai_addr first
    TNetAddrInfo = record
      ai_flags, ai_family, ai_socktype, ai_protocol: Int32;
      ai_addrlen: NativeUInt;
{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_OPENBSD)}
      ai_addr: Pointer;
      ai_canonname: PAnsiChar;
{$ELSE}
      ai_canonname: PAnsiChar;
      ai_addr: Pointer;
{$IFEND}
      ai_next: Pointer;
    end;
    PNetAddrInfo = ^TNetAddrInfo;
    TGetAddrInfoFunc = function(ANode, AService: PAnsiChar; AHints: PNetAddrInfo;
      out AList: PNetAddrInfo): Int32; cdecl;
    TFreeAddrInfoProc = procedure(AList: PNetAddrInfo); cdecl;
{$ELSE}
    TSockAddrIn = sockaddr_in;
    TNetSockLen = socklen_t;
    TNetAddrInfo = addrinfo;
    PNetAddrInfo = Paddrinfo;
    // poll(2), taken from the C library at run time
    TPollFunc = function(AFds: Pointer; ACount: NativeUInt; ATimeoutMs: Integer): Integer; cdecl;
    TPollFd = record
      fd: Integer;
      events: SmallInt;
      revents: SmallInt;
    end;
{$ENDIF}
    TAccept4Func = function(AListener: Integer; AAddr, ALen: Pointer;
      AFlags: Integer): Integer; cdecl;
  const
    // a send to a peer that has gone must not raise SIGPIPE: a flag per send, or on Darwin the
    // per-socket option ArmAgainstSigPipe sets
{$IF DEFINED(TLSLIB_NETBSD) OR DEFINED(TLSLIB_OPENBSD) OR DEFINED(TLSLIB_DRAGONFLY)}
    // these kernels define MSG_NOSIGNAL as $400
    SendFlags = $0400;
{$ELSEIF DECLARED(SO_NOSIGPIPE)}
    SendFlags = 0;
{$ELSEIF DECLARED(MSG_NOSIGNAL)}
    SendFlags = MSG_NOSIGNAL;
{$ELSEIF DEFINED(TLSLIB_SOLARIS)}
    // Solaris 11.4 and illumos define MSG_NOSIGNAL as $200
    SendFlags = $0200;
{$IFEND}
  class var
{$IFDEF FPC}
    FGetAddrInfo: TGetAddrInfoFunc;
    FFreeAddrInfo: TFreeAddrInfoProc;
{$ELSE}
    FPoll: TPollFunc;
{$ENDIF}
    FAccept4: TAccept4Func;
  strict private
    class procedure FillAddress(const AAddress: TBytes; APort: Word;
      out AAddr: TSockAddrIn); static;
  private
    class procedure ResolveDynamicImports; static;
  public
  const
    InvalidHandle = -1;
  public
    /// <summary>A blocking IPv4 TCP socket, armed against SIGPIPE. Returns 0 or the OS error.</summary>
    class function OpenStream(out AHandle: TPosixSocketHandle): Integer; static;
    class procedure Close(AHandle: TPosixSocketHandle); static;
    class function SetBlocking(AHandle: TPosixSocketHandle; ABlocking: Boolean): Integer; static;
    /// <summary>0 when connected or under way, else the OS error. AAddress is the four octets.</summary>
    class function BeginConnect(AHandle: TPosixSocketHandle; const AAddress: TBytes;
      APort: Word): Integer; static;
    /// <summary>The outcome of a connect once the socket is writable: 0, or the OS error.</summary>
    class function ConnectResult(AHandle: TPosixSocketHandle): Integer; static;
    /// <summary>Lets a restarted server rebind its port while old connections sit in TIME_WAIT,
    /// then binds and listens. Returns 0 or the OS error.</summary>
    class function BindAndListen(AHandle: TPosixSocketHandle; const AAddress: TBytes;
      APort: Word; ABacklog: Int32): Integer; static;
    class function LocalPort(AHandle: TPosixSocketHandle): Word; static;
    /// <summary>The next waiting connection: 0 with AHandle set, or the OS error.</summary>
    class function AcceptConnection(AListener: TPosixSocketHandle;
      out AHandle: TPosixSocketHandle): Integer; static;
    /// <summary>True for an accept error that is the peer's doing or only a retry: nothing to take
    /// yet, a signal, a connection that went before it was taken.</summary>
    class function IsTransientAcceptError(AError: Integer): Boolean; static;
    /// <summary>True when AHandle is ready for AKind, or failed, within AMs ms; a failure counts as
    /// ready so the call that follows reports it. A signal never extends the wait.</summary>
    class function Wait(AHandle: TPosixSocketHandle; AKind: TPosixNetWait;
      AMs: Int32): Boolean; static;
    /// <summary>The count read, 0 at an orderly close, -1 on an error; a signal is retried.</summary>
    class function ReceiveBytes(AHandle: TPosixSocketHandle; var ABuffer: TBytes;
      AOffset, ALength: Int32): Int32; static;
    /// <summary>The count sent, -1 on an error; never raises SIGPIPE, and a signal is retried.</summary>
    class function SendBytes(AHandle: TPosixSocketHandle; const ABuffer: TBytes;
      AOffset, ALength: Int32): Int32; static;
    /// <summary>For a socket opened elsewhere: sets the per-socket option where the platform has no
    /// send flag.</summary>
    class procedure ArmAgainstSigPipe(AHandle: TPosixSocketHandle); static;
    /// <summary>The first IPv4 address the system resolver gives AHost, as four octets in network
    /// order; False when it has none. Blocks for as long as the system resolver does.</summary>
    class function LookupIPv4(const AHost: AnsiString; out AAddress: TBytes): Boolean; static;
    /// <summary>The errno of the last call on this thread.</summary>
    class function LastError: Integer; static;
  end;

{$IFEND}

implementation

{$IF DEFINED(TLSLIB_UNIXLIKE)}

const
  // poll(2) events and the close-on-exec flag, the same on every POSIX target
  PollIn = $0001;
  PollOut = $0004;
  CloseOnExec = 1;
  // SOCK_CLOEXEC; Darwin has none, so fcntl marks its sockets
{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID) OR DEFINED(TLSLIB_SOLARIS)}
  SocketCloseOnExec = $80000;
{$ELSEIF DEFINED(TLSLIB_OPENBSD)}
  SocketCloseOnExec = $8000;
{$ELSEIF DEFINED(TLSLIB_BSD)}
  SocketCloseOnExec = $10000000;
{$ELSEIF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}
  SocketCloseOnExec = 0;
{$IFEND}
{$IFDEF FPC}
  ErrInterrupted = ESysEINTR;
  ErrAgain = ESysEAGAIN;
  ErrWouldBlock = ESysEWOULDBLOCK;
  ErrConnAborted = ESysECONNABORTED;
  // where EPROTO is undeclared, a connection that went before it was taken is ECONNABORTED
{$IF DECLARED(ESysEPROTO)}
  ErrProtocol = ESysEPROTO;
{$ELSE}
  ErrProtocol = -1;
{$IFEND}
  ErrInProgress = ESysEINPROGRESS;
{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID)}
  // accept(2) passes a pending network error of the new connection on like EAGAIN
  ErrNetDown = ESysENETDOWN;
  ErrNoProtocolOption = ESysENOPROTOOPT;
  ErrHostDown = ESysEHOSTDOWN;
  ErrNoNet = ESysENONET;
  ErrHostUnreachable = ESysEHOSTUNREACH;
  ErrNotSupported = ESysEOPNOTSUPP;
  ErrNetUnreachable = ESysENETUNREACH;
{$IFEND}
{$ELSE}
  ErrInterrupted = EINTR;
  ErrAgain = EAGAIN;
  ErrWouldBlock = EWOULDBLOCK;
  ErrConnAborted = ECONNABORTED;
  ErrProtocol = EPROTO;
  ErrInProgress = EINPROGRESS;
{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID)}
  // accept(2) passes a pending network error of the new connection on like EAGAIN
  ErrNetDown = ENETDOWN;
  ErrNoProtocolOption = ENOPROTOOPT;
  ErrHostDown = EHOSTDOWN;
  ErrNoNet = ENONET;
  ErrHostUnreachable = EHOSTUNREACH;
  ErrNotSupported = EOPNOTSUPP;
  ErrNetUnreachable = ENETUNREACH;
{$IFEND}
{$ENDIF}

{ TPosixNetOs }

class procedure TPosixNetOs.ResolveDynamicImports;
var
  LLibrary: NativeUInt;
begin
  // the global namespace handle stays open for the process lifetime
  LLibrary := TDynamicLibrary.Open('');
{$IFDEF FPC}
  FGetAddrInfo := TGetAddrInfoFunc(TDynamicLibrary.Resolve(LLibrary, 'getaddrinfo'));
  FFreeAddrInfo := TFreeAddrInfoProc(TDynamicLibrary.Resolve(LLibrary, 'freeaddrinfo'));
{$ELSE}
  FPoll := TPollFunc(TDynamicLibrary.Resolve(LLibrary, 'poll'));
{$ENDIF}
  if SocketCloseOnExec <> 0 then
    FAccept4 := TAccept4Func(TDynamicLibrary.Resolve(LLibrary, 'accept4'));
end;

class function TPosixNetOs.LastError: Integer;
begin
{$IFDEF FPC}
  Result := fpGetErrno;
{$ELSE}
  Result := GetLastError;
{$ENDIF}
end;

class procedure TPosixNetOs.ArmAgainstSigPipe(AHandle: TPosixSocketHandle);
{$IF DECLARED(SO_NOSIGPIPE)}
var
  LOn: Integer;
begin
  LOn := 1;
{$IFDEF FPC}
  fpSetSockOpt(AHandle, SOL_SOCKET, SO_NOSIGPIPE, @LOn, SizeOf(LOn));
{$ELSE}
  setsockopt(AHandle, SOL_SOCKET, SO_NOSIGPIPE, LOn, SizeOf(LOn));
{$ENDIF}
{$ELSE}
begin
{$IFEND}
end;

class procedure TPosixNetOs.FillAddress(const AAddress: TBytes; APort: Word;
  out AAddr: TSockAddrIn);
begin
  AAddr := Default(TSockAddrIn);
  AAddr.sin_family := AF_INET;
  Move(AAddress[0], AAddr.sin_addr, 4);
  // the port goes out in network order whatever the byte order of the CPU
  PByte(@AAddr.sin_port)[0] := APort shr 8;
  PByte(@AAddr.sin_port)[1] := APort and $FF;
end;

class function TPosixNetOs.Wait(AHandle: TPosixSocketHandle; AKind: TPosixNetWait;
  AMs: Int32): Boolean;
var
  LFd: TPollFd;
  LEndsAt, LLeft: Int64;
  LReady: Integer;
begin
  // poll waits for ever on a negative time
  if AMs < 0 then
    AMs := 0;
  LFd.fd := AHandle;
  if AKind = TPosixNetWait.Readable then
    LFd.events := PollIn
  else
    LFd.events := PollOut;
  LEndsAt := TSystemTimeUtilities.MonotonicMs + AMs;
  LLeft := AMs;
  repeat
    LFd.revents := 0;
{$IFDEF FPC}
    LReady := fpPoll(@LFd, 1, Int32(LLeft));
{$ELSE}
    // a C library without poll cannot be waited on, which reads as a timeout
    if Assigned(FPoll) then
      LReady := FPoll(@LFd, 1, Int32(LLeft))
    else
      LReady := 0;
{$ENDIF}
    if (LReady <> -1) or (LastError <> ErrInterrupted) then
      Break;
    // a signal ends the wait early, and the retry waits only for what is left
    LLeft := LEndsAt - TSystemTimeUtilities.MonotonicMs;
    if LLeft < 0 then
      LLeft := 0;
  until False;
  Result := LReady <> 0;
end;

class function TPosixNetOs.OpenStream(out AHandle: TPosixSocketHandle): Integer;
var
  LFlags: Integer;
begin
  LFlags := SocketCloseOnExec;
  repeat
{$IFDEF FPC}
    AHandle := fpSocket(AF_INET, SOCK_STREAM or LFlags, 0);
{$ELSE}
    AHandle := socket(PF_INET, SOCK_STREAM or LFlags, IPPROTO_TCP);
{$ENDIF}
    // a kernel older than the flag refuses it; a real failure repeats without it
    if (AHandle >= 0) or (LFlags = 0) then
      Break;
    LFlags := 0;
  until False;
  if AHandle < 0 then
  begin
    AHandle := InvalidHandle;
    Exit(LastError);
  end;
  // a child process this one starts must not inherit the socket
  if LFlags = 0 then
{$IFDEF FPC}
    fpFcntl(AHandle, F_SETFD, CloseOnExec);
{$ELSE}
    fcntl(AHandle, F_SETFD, CloseOnExec);
{$ENDIF}
  ArmAgainstSigPipe(AHandle);
  Result := 0;
end;

class procedure TPosixNetOs.Close(AHandle: TPosixSocketHandle);
begin
{$IFDEF FPC}
  fpClose(AHandle);
{$ELSE}
  __close(AHandle);
{$ENDIF}
end;

class function TPosixNetOs.SetBlocking(AHandle: TPosixSocketHandle; ABlocking: Boolean): Integer;
var
  LFlags: Integer;
begin
{$IFDEF FPC}
  LFlags := fpFcntl(AHandle, F_GETFL, 0);
{$ELSE}
  LFlags := fcntl(AHandle, F_GETFL, 0);
{$ENDIF}
  if LFlags >= 0 then
  begin
    if ABlocking then
      LFlags := LFlags and (not O_NONBLOCK)
    else
      LFlags := LFlags or O_NONBLOCK;
{$IFDEF FPC}
    LFlags := fpFcntl(AHandle, F_SETFL, LFlags);
{$ELSE}
    LFlags := fcntl(AHandle, F_SETFL, LFlags);
{$ENDIF}
  end;
  if LFlags < 0 then
    Result := LastError
  else
    Result := 0;
end;

class function TPosixNetOs.BeginConnect(AHandle: TPosixSocketHandle; const AAddress: TBytes;
  APort: Word): Integer;
var
  LAddr: TSockAddrIn;
  LFailed: Boolean;
begin
  FillAddress(AAddress, APort, LAddr);
{$IFDEF FPC}
  LFailed := fpConnect(AHandle, PSockAddr(@LAddr), SizeOf(LAddr)) <> 0;
{$ELSE}
  LFailed := connect(AHandle, sockaddr(LAddr), SizeOf(LAddr)) <> 0;
{$ENDIF}
  Result := 0;
  if LFailed then
    Result := LastError;
  // a connect that is under way, or that a signal interrupted, carries on in the background
  if (Result = ErrInProgress) or (Result = ErrInterrupted) then
    Result := 0;
end;

class function TPosixNetOs.ConnectResult(AHandle: TPosixSocketHandle): Integer;
var
  LError: Integer;
  LLen: TNetSockLen;
  LFailed: Boolean;
begin
  LError := 0;
  LLen := SizeOf(LError);
{$IFDEF FPC}
  LFailed := fpGetSockOpt(AHandle, SOL_SOCKET, SO_ERROR, @LError, @LLen) <> 0;
{$ELSE}
  LFailed := getsockopt(AHandle, SOL_SOCKET, SO_ERROR, LError, LLen) <> 0;
{$ENDIF}
  if LFailed then
    Exit(LastError);
  Result := LError;
end;

class function TPosixNetOs.BindAndListen(AHandle: TPosixSocketHandle; const AAddress: TBytes;
  APort: Word; ABacklog: Int32): Integer;
var
  LAddr: TSockAddrIn;
  LOn: Integer;
  LFailed: Boolean;
begin
  FillAddress(AAddress, APort, LAddr);
  LOn := 1;
{$IFDEF FPC}
  LFailed := (fpSetSockOpt(AHandle, SOL_SOCKET, SO_REUSEADDR, @LOn, SizeOf(LOn)) <> 0) or
    (fpBind(AHandle, PSockAddr(@LAddr), SizeOf(LAddr)) <> 0) or
    (fpListen(AHandle, ABacklog) <> 0);
{$ELSE}
  LFailed := (setsockopt(AHandle, SOL_SOCKET, SO_REUSEADDR, LOn, SizeOf(LOn)) <> 0) or
    (bind(AHandle, sockaddr(LAddr), SizeOf(LAddr)) <> 0) or (listen(AHandle, ABacklog) <> 0);
{$ENDIF}
  if LFailed then
    Result := LastError
  else
    Result := 0;
end;

class function TPosixNetOs.LocalPort(AHandle: TPosixSocketHandle): Word;
var
  LAddr: TSockAddrIn;
  LLen: TNetSockLen;
  LFailed: Boolean;
begin
  LAddr := Default(TSockAddrIn);
  LLen := SizeOf(LAddr);
{$IFDEF FPC}
  LFailed := fpGetSockName(AHandle, PSockAddr(@LAddr), @LLen) <> 0;
{$ELSE}
  LFailed := getsockname(AHandle, sockaddr(LAddr), LLen) <> 0;
{$ENDIF}
  if LFailed then
    Exit(0);
  Result := Word(PByte(@LAddr.sin_port)[0]) shl 8 or PByte(@LAddr.sin_port)[1];
end;

class function TPosixNetOs.AcceptConnection(AListener: TPosixSocketHandle;
  out AHandle: TPosixSocketHandle): Integer;
var
  LAddr: TSockAddrIn;
  LLen: TNetSockLen;
  LError: Integer;
begin
  if Assigned(FAccept4) then
  begin
    LAddr := Default(TSockAddrIn);
    LLen := SizeOf(LAddr);
    AHandle := FAccept4(AListener, @LAddr, @LLen, SocketCloseOnExec);
    if AHandle >= 0 then
      Exit(0);
{$IFDEF FPC}
    // accept4 sets the C library's errno, not the one LastError reads
    LError := fpgetCerrno;
{$ELSE}
    LError := LastError;
{$ENDIF}
    if IsTransientAcceptError(LError) then
    begin
      AHandle := InvalidHandle;
      Exit(LError);
    end;
  end;
  // without accept4, or when a kernel refuses it; a real failure repeats here
  LAddr := Default(TSockAddrIn);
  LLen := SizeOf(LAddr);
{$IFDEF FPC}
  AHandle := fpAccept(AListener, PSockAddr(@LAddr), @LLen);
{$ELSE}
  AHandle := accept(AListener, sockaddr(LAddr), LLen);
{$ENDIF}
  if AHandle < 0 then
  begin
    AHandle := InvalidHandle;
    Exit(LastError);
  end;
  // a child process this one starts must not inherit the connection
{$IFDEF FPC}
  fpFcntl(AHandle, F_SETFD, CloseOnExec);
{$ELSE}
  fcntl(AHandle, F_SETFD, CloseOnExec);
{$ENDIF}
  Result := 0;
end;

class function TPosixNetOs.IsTransientAcceptError(AError: Integer): Boolean;
begin
  Result := (AError = ErrAgain) or (AError = ErrWouldBlock) or (AError = ErrInterrupted) or
    (AError = ErrConnAborted) or (AError = ErrProtocol);
{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID)}
  Result := Result or (AError = ErrNetDown) or (AError = ErrNoProtocolOption) or
    (AError = ErrHostDown) or (AError = ErrNoNet) or (AError = ErrHostUnreachable) or
    (AError = ErrNotSupported) or (AError = ErrNetUnreachable);
{$IFEND}
end;

class function TPosixNetOs.ReceiveBytes(AHandle: TPosixSocketHandle; var ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  repeat
{$IFDEF FPC}
    Result := fpRecv(AHandle, @ABuffer[AOffset], ALength, 0);
{$ELSE}
    Result := recv(AHandle, ABuffer[AOffset], ALength, 0);
{$ENDIF}
  until (Result >= 0) or (LastError <> ErrInterrupted);
  if Result < 0 then
    Result := -1;
end;

class function TPosixNetOs.SendBytes(AHandle: TPosixSocketHandle; const ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  repeat
{$IFDEF FPC}
    Result := fpSend(AHandle, @ABuffer[AOffset], ALength, SendFlags);
{$ELSE}
    Result := send(AHandle, ABuffer[AOffset], ALength, SendFlags);
{$ENDIF}
  until (Result >= 0) or (LastError <> ErrInterrupted);
  if Result < 0 then
    Result := -1;
end;

class function TPosixNetOs.LookupIPv4(const AHost: AnsiString; out AAddress: TBytes): Boolean;
var
  LHints: TNetAddrInfo;
  LList, LEntry: PNetAddrInfo;
begin
  AAddress := nil;
  Result := False;
{$IFDEF FPC}
  if not (Assigned(FGetAddrInfo) and Assigned(FFreeAddrInfo)) then
    Exit;
{$ENDIF}
  // a hint for IPv4 stops the resolver asking for AAAA records; the socket type is left unset,
  // because SOCK_STREAM is not 1 on every target
  LHints := Default(TNetAddrInfo);
  LHints.ai_family := AF_INET;
  LList := nil;
{$IFDEF FPC}
  if FGetAddrInfo(PAnsiChar(AHost), nil, @LHints, LList) <> 0 then
{$ELSE}
  if getaddrinfo(PAnsiChar(AHost), nil, LHints, LList) <> 0 then
{$ENDIF}
    Exit;
  try
    LEntry := LList;
    while LEntry <> nil do
    begin
      if (LEntry^.ai_family = AF_INET) and (LEntry^.ai_addr <> nil) then
      begin
        // the address is at offset 4 of the sockaddr on every layout, already in network order
        SetLength(AAddress, 4);
        Move((PByte(LEntry^.ai_addr) + 4)^, AAddress[0], 4);
        Exit(True);
      end;
      LEntry := LEntry^.ai_next;
    end;
  finally
{$IFDEF FPC}
    FFreeAddrInfo(LList);
{$ELSE}
    freeaddrinfo(LList^);
{$ENDIF}
  end;
end;

initialization
  TPosixNetOs.ResolveDynamicImports;

{$IFEND}

end.
