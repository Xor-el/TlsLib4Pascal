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
{$ELSE}
  Posix.SysSocket,
  Posix.NetinetIn,
  Posix.Fcntl,
  Posix.Errno,
  Posix.Unistd,
{$ENDIF}
  TlpDynamicLibrary,
  TlpSystemTimeUtilities;

type
  /// <summary>A POSIX socket is a file descriptor, an int on every target. It is not the RTL's
  /// THandle, which is pointer-sized on Delphi.</summary>
  TPosixSocketHandle = Integer;

  /// <summary>What a wait is for: data to read, or room to write (a connect under way).</summary>
  TPosixNetWait = (Readable, Writable);

  /// <summary>The IPv4 TCP socket calls on a POSIX target, by file descriptor. Every call returns
  /// the OS error code (0 for none) or a plain result, and raises nothing: the caller decides how
  /// an error is reported. Each compiler makes the calls through its own RTL declarations, which
  /// know the names and layouts of the target, and reads the errno of the same RTL. Linux on MIPS
  /// and SPARC is not supported: the Free Pascal RTL gives SOL_SOCKET, SO_REUSEADDR and SO_ERROR
  /// the values of the other CPUs, which those kernels number differently.</summary>
  TPosixNetOs = class sealed(TObject)
  strict private
  type
{$IFDEF FPC}
    TSockAddrIn = TInetSockAddr;
    TNetSockLen = TSockLen;
{$ELSE}
    TSockAddrIn = sockaddr_in;
    TNetSockLen = socklen_t;
    // the RTL declares no poll, so Delphi takes it from the C library
    TPollFunc = function(AFds: Pointer; ACount: NativeUInt; ATimeoutMs: Integer): Integer; cdecl;
    TPollFd = record
      fd: Integer;
      events: SmallInt;
      revents: SmallInt;
    end;
{$ENDIF}
    TGetAddrInfoFunc = function(ANode, AService: PAnsiChar; AHints: Pointer;
      out AList: Pointer): Int32; cdecl;
    TFreeAddrInfoProc = procedure(AList: Pointer); cdecl;
    // the C struct addrinfo up to ai_next; the two pointer slots are ai_addr and ai_canonname in
    // the order the target's netdb.h gives them, and ai_addrlen is never read
    TAddrInfoView = record
      Flags, Family, SockType, Protocol: Int32;
      AddrLen: NativeUInt;
      Slots: array [0 .. 1] of Pointer;
      Next: Pointer;
    end;
    PAddrInfoView = ^TAddrInfoView;
  class var
{$IFNDEF FPC}
    FPoll: TPollFunc;
{$ENDIF}
    FGetAddrInfo: TGetAddrInfoFunc;
    FFreeAddrInfo: TFreeAddrInfoProc;
  strict private
    class procedure FillAddress(const AAddress: TBytes; APort: Word;
      out AAddr: TSockAddrIn); static;
  private
    class procedure ResolveDynamicImports; static;
  public
  const
    InvalidHandle = -1;
    // a send to a peer that has gone must not kill the process with SIGPIPE: MSG_NOSIGNAL per send
    // where the target has it (the flags every sender that is not SendBytes must pass), else the
    // per-socket SO_NOSIGPIPE option, which only Darwin has
{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}
    SendFlags = 0;
    NoSigPipeOption = $1022;
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID)}
    SendFlags = $4000;
    NoSigPipeOption = 0;
{$ELSEIF DEFINED(FREEBSD)}
    SendFlags = $20000;
    NoSigPipeOption = 0;
{$ELSEIF DEFINED(NETBSD) OR DEFINED(OPENBSD) OR DEFINED(DRAGONFLY)}
    SendFlags = $400;
    NoSigPipeOption = 0;
{$ELSEIF DEFINED(TLSLIB_SOLARIS)}
    SendFlags = $200;
    NoSigPipeOption = 0;
{$IFEND}
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
  // poll(2) events, and the close-on-exec descriptor flag, the same on every POSIX target
  PollIn = $0001;
  PollOut = $0004;
  CloseOnExec = 1;
  // netdb.h orders ai_addr and ai_canonname differently
{$IF (DEFINED(TLSLIB_LINUX) AND NOT DEFINED(TLSLIB_ANDROID)) OR DEFINED(OPENBSD)}
  AddrInfoAddrSlot = 0;
{$ELSE}
  AddrInfoAddrSlot = 1;
{$IFEND}
{$IFDEF FPC}
  ErrInterrupted = ESysEINTR;
  ErrAgain = ESysEAGAIN;
  ErrWouldBlock = ESysEWOULDBLOCK;
  ErrConnAborted = ESysECONNABORTED;
  // the FreeBSD, DragonFly and OpenBSD RTLs name no EPROTO, and their kernels report a connection
  // that went before it was taken as ECONNABORTED
{$IF DECLARED(ESysEPROTO)}
  ErrProtocol = ESysEPROTO;
{$ELSE}
  ErrProtocol = -1;
{$IFEND}
  ErrInProgress = ESysEINPROGRESS;
{$ELSE}
  ErrInterrupted = EINTR;
  ErrAgain = EAGAIN;
  ErrWouldBlock = EWOULDBLOCK;
  ErrConnAborted = ECONNABORTED;
  ErrProtocol = EPROTO;
  ErrInProgress = EINPROGRESS;
{$ENDIF}

{ TPosixNetOs }

class procedure TPosixNetOs.ResolveDynamicImports;
var
  LLibrary: NativeUInt;
begin
  // the global namespace handle stays open for the process lifetime
  LLibrary := TDynamicLibrary.Open('');
{$IFNDEF FPC}
  FPoll := TPollFunc(TDynamicLibrary.Resolve(LLibrary, 'poll'));
{$ENDIF}
  FGetAddrInfo := TGetAddrInfoFunc(TDynamicLibrary.Resolve(LLibrary, 'getaddrinfo'));
  FFreeAddrInfo := TFreeAddrInfoProc(TDynamicLibrary.Resolve(LLibrary, 'freeaddrinfo'));
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
var
  LOn: Integer;
begin
  if NoSigPipeOption = 0 then
    Exit;
  LOn := 1;
{$IFDEF FPC}
  fpSetSockOpt(AHandle, SOL_SOCKET, NoSigPipeOption, @LOn, SizeOf(LOn));
{$ELSE}
  setsockopt(AHandle, SOL_SOCKET, NoSigPipeOption, LOn, SizeOf(LOn));
{$ENDIF}
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
begin
{$IFDEF FPC}
  AHandle := fpSocket(AF_INET, SOCK_STREAM, 0);
{$ELSE}
  AHandle := socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
{$ENDIF}
  if AHandle < 0 then
  begin
    AHandle := InvalidHandle;
    Exit(LastError);
  end;
  // a child process this one starts must not inherit the socket
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
begin
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
  LHints: TAddrInfoView;
  LList, LNode: Pointer;
  LEntry: PAddrInfoView;
begin
  AAddress := nil;
  Result := False;
  if not (Assigned(FGetAddrInfo) and Assigned(FFreeAddrInfo)) then
    Exit;
  // a hint for IPv4 stops the resolver asking for AAAA records; the socket type is left unset,
  // because SOCK_STREAM is not 1 on every target
  LHints := Default(TAddrInfoView);
  LHints.Family := AF_INET;
  LList := nil;
  if FGetAddrInfo(PAnsiChar(AHost), nil, @LHints, LList) <> 0 then
    Exit;
  try
    LNode := LList;
    while LNode <> nil do
    begin
      LEntry := PAddrInfoView(LNode);
      if (LEntry^.Family = AF_INET) and (LEntry^.Slots[AddrInfoAddrSlot] <> nil) then
      begin
        // the address is at offset 4 of the sockaddr on every layout, already in network order
        SetLength(AAddress, 4);
        Move((PByte(LEntry^.Slots[AddrInfoAddrSlot]) + 4)^, AAddress[0], 4);
        Exit(True);
      end;
      LNode := LEntry^.Next;
    end;
  finally
    FFreeAddrInfo(LList);
  end;
end;

initialization
  TPosixNetOs.ResolveDynamicImports;

{$IFEND}

end.
