{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWindowsNetOs;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IFDEF TLSLIB_MSWINDOWS}

uses
  SysUtils,
  Windows,
  Winsock2,
  TlpDynamicLibrary;

type
  /// <summary>A Winsock SOCKET: an unsigned integer as wide as a pointer.</summary>
  TWindowsSocketHandle = NativeUInt;

  /// <summary>What a wait is for: data to read, or room to write (a connect under way).</summary>
  TWindowsNetWait = (Readable, Writable);

  /// <summary>The IPv4 TCP socket calls on Windows, by socket handle. Every call returns the OS
  /// error code (0 for none) or a plain result, and raises nothing: the caller decides how an error
  /// is reported.</summary>
  TWindowsNetOs = class sealed(TObject)
  strict private
  type
    TGetAddrInfoFunc = function(ANode, AService: PAnsiChar; AHints: Pointer;
      out AList: Pointer): Int32; stdcall;
    TFreeAddrInfoProc = procedure(AList: Pointer); stdcall;
    // the C struct ADDRINFOA up to ai_next; ai_addrlen is a SIZE_T here and is never read
    TAddrInfoView = record
      Flags, Family, SockType, Protocol: Int32;
      AddrLen: NativeUInt;
      CanonName: Pointer;
      Addr: Pointer;
      Next: Pointer;
    end;
    PAddrInfoView = ^TAddrInfoView;
  class var
    FGetAddrInfo: TGetAddrInfoFunc;
    FFreeAddrInfo: TFreeAddrInfoProc;
  strict private
    class procedure FillAddress(const AAddress: TBytes; APort: Word;
      out AAddr: TSockAddrIn); static;
  private
    class procedure Startup; static;
    class procedure Shutdown; static;
  public
  const
    InvalidHandle = High(NativeUInt);
  public
    /// <summary>A blocking IPv4 TCP socket. Returns 0 or the OS error.</summary>
    class function OpenStream(out AHandle: TWindowsSocketHandle): Integer; static;
    class procedure Close(AHandle: TWindowsSocketHandle); static;
    class function SetBlocking(AHandle: TWindowsSocketHandle; ABlocking: Boolean): Integer; static;
    /// <summary>0 when connected or under way, else the OS error. AAddress is the four octets.</summary>
    class function BeginConnect(AHandle: TWindowsSocketHandle; const AAddress: TBytes;
      APort: Word): Integer; static;
    /// <summary>The outcome of a connect once the socket is writable: 0, or the OS error.</summary>
    class function ConnectResult(AHandle: TWindowsSocketHandle): Integer; static;
    /// <summary>Keeps another process from binding the same port, then binds and listens. Returns
    /// 0 or the OS error.</summary>
    class function BindAndListen(AHandle: TWindowsSocketHandle; const AAddress: TBytes; APort: Word;
      ABacklog: Int32): Integer; static;
    class function LocalPort(AHandle: TWindowsSocketHandle): Word; static;
    /// <summary>The next waiting connection: 0 with AHandle set, or the OS error.</summary>
    class function AcceptConnection(AListener: TWindowsSocketHandle;
      out AHandle: TWindowsSocketHandle): Integer; static;
    /// <summary>True for an accept error that is the peer's doing or only a retry: nothing to take
    /// yet, a signal, a connection that went before it was taken.</summary>
    class function IsTransientAcceptError(AError: Integer): Boolean; static;
    /// <summary>True when AHandle is ready for AKind, or failed, within AMs ms; a failure counts as
    /// ready so the call that follows reports it.</summary>
    class function Wait(AHandle: TWindowsSocketHandle; AKind: TWindowsNetWait;
      AMs: Int32): Boolean; static;
    /// <summary>The count read, 0 at an orderly close, -1 on an error.</summary>
    class function ReceiveBytes(AHandle: TWindowsSocketHandle; var ABuffer: TBytes;
      AOffset, ALength: Int32): Int32; static;
    /// <summary>The count sent, -1 on an error.</summary>
    class function SendBytes(AHandle: TWindowsSocketHandle; const ABuffer: TBytes;
      AOffset, ALength: Int32): Int32; static;
    /// <summary>A send on Windows never raises a signal, so there is nothing to arm.</summary>
    class procedure ArmAgainstSigPipe(AHandle: TWindowsSocketHandle); static;
    /// <summary>The first IPv4 address the system resolver gives AHost, as four octets in network
    /// order; False when it has none. Blocks for as long as the system resolver does.</summary>
    class function LookupIPv4(const AHost: AnsiString; out AAddress: TBytes): Boolean; static;
    class function LastError: Integer; static;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

const
  // Winsock 2.2
  WinsockVersion = $0202;
  // refuses the same port to every other process, which SO_REUSEADDR would allow on Windows
  SoExclusiveAddrUse = not SO_REUSEADDR;
  // WSA_FLAG_NO_HANDLE_INHERIT
  WsaFlagNoHandleInherit = $80;

{ TWindowsNetOs }

class procedure TWindowsNetOs.Startup;
var
  LData: TWSAData;
  LLibrary: NativeUInt;
begin
  WSAStartup(WinsockVersion, LData);
  // ws2_32 is mapped into every process that started Winsock, so the handle is not closed
  LLibrary := TDynamicLibrary.Open('ws2_32.dll');
  FGetAddrInfo := TGetAddrInfoFunc(TDynamicLibrary.Resolve(LLibrary, 'getaddrinfo'));
  FFreeAddrInfo := TFreeAddrInfoProc(TDynamicLibrary.Resolve(LLibrary, 'freeaddrinfo'));
end;

class function TWindowsNetOs.LookupIPv4(const AHost: AnsiString; out AAddress: TBytes): Boolean;
var
  LHints: TAddrInfoView;
  LList, LNode: Pointer;
  LEntry: PAddrInfoView;
begin
  AAddress := nil;
  Result := False;
  if not (Assigned(FGetAddrInfo) and Assigned(FFreeAddrInfo)) then
    Exit;
  // a hint for IPv4 keeps the resolver from returning only AAAA records
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
      if (LEntry^.Family = AF_INET) and (LEntry^.Addr <> nil) then
      begin
        // the address is at offset 4 of the sockaddr, already in network order
        SetLength(AAddress, 4);
        Move((PByte(LEntry^.Addr) + 4)^, AAddress[0], 4);
        Exit(True);
      end;
      LNode := LEntry^.Next;
    end;
  finally
    FFreeAddrInfo(LList);
  end;
end;

class procedure TWindowsNetOs.Shutdown;
begin
  WSACleanup;
end;

class function TWindowsNetOs.LastError: Integer;
begin
  Result := WSAGetLastError;
end;

class procedure TWindowsNetOs.ArmAgainstSigPipe(AHandle: TWindowsSocketHandle);
begin
end;

class procedure TWindowsNetOs.FillAddress(const AAddress: TBytes; APort: Word;
  out AAddr: TSockAddrIn);
begin
  AAddr := Default(TSockAddrIn);
  AAddr.sin_family := AF_INET;
  Move(AAddress[0], AAddr.sin_addr, 4);
  // the port goes out in network order whatever the byte order of the CPU
  PByte(@AAddr.sin_port)[0] := APort shr 8;
  PByte(@AAddr.sin_port)[1] := APort and $FF;
end;

class function TWindowsNetOs.Wait(AHandle: TWindowsSocketHandle; AKind: TWindowsNetWait;
  AMs: Int32): Boolean;
var
  LSet, LFailed: TFDSet;
  LTime: TTimeVal;
begin
  // select fails on a negative time
  if AMs < 0 then
    AMs := 0;
  LSet := Default(TFDSet);
  LSet.fd_count := 1;
  LSet.fd_array[0] := AHandle;
  LFailed := LSet;
  LTime.tv_sec := AMs div 1000;
  LTime.tv_usec := (AMs mod 1000) * 1000;
  // an error counts as ready, so the call that follows reports it; a refused connect shows in
  // the error set
  if AKind = TWindowsNetWait.Writable then
    Result := select(0, nil, @LSet, @LFailed, @LTime) <> 0
  else
    Result := select(0, @LSet, nil, nil, @LTime) <> 0;
end;

class function TWindowsNetOs.OpenStream(out AHandle: TWindowsSocketHandle): Integer;
begin
  // created not inheritable, so no child can take it before it is marked
  AHandle := WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nil, 0,
    WSA_FLAG_OVERLAPPED or WsaFlagNoHandleInherit);
  // a Windows without the flag refuses it, so the handle is marked after the fact
  if AHandle = InvalidHandle then
  begin
    AHandle := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if AHandle = InvalidHandle then
      Exit(LastError);
    SetHandleInformation(AHandle, HANDLE_FLAG_INHERIT, 0);
  end;
  Result := 0;
end;

class procedure TWindowsNetOs.Close(AHandle: TWindowsSocketHandle);
begin
  closesocket(AHandle);
end;

class function TWindowsNetOs.SetBlocking(AHandle: TWindowsSocketHandle; ABlocking: Boolean): Integer;
var
  LMode: u_long;
begin
  LMode := Ord(not ABlocking);
  if ioctlsocket(AHandle, FIONBIO, LMode) <> 0 then
    Result := LastError
  else
    Result := 0;
end;

class function TWindowsNetOs.BeginConnect(AHandle: TWindowsSocketHandle; const AAddress: TBytes;
  APort: Word): Integer;
var
  LAddr: TSockAddrIn;
begin
  FillAddress(AAddress, APort, LAddr);
  Result := 0;
  if connect(AHandle, TSockAddr(LAddr), SizeOf(LAddr)) <> 0 then
    Result := LastError;
  if Result = WSAEWOULDBLOCK then
    Result := 0;
end;

class function TWindowsNetOs.ConnectResult(AHandle: TWindowsSocketHandle): Integer;
var
  LError, LLen: Integer;
begin
  LError := 0;
  LLen := SizeOf(LError);
  if getsockopt(AHandle, SOL_SOCKET, SO_ERROR, PAnsiChar(@LError), LLen) <> 0 then
    Exit(LastError);
  Result := LError;
end;

class function TWindowsNetOs.BindAndListen(AHandle: TWindowsSocketHandle; const AAddress: TBytes;
  APort: Word; ABacklog: Int32): Integer;
var
  LAddr: TSockAddrIn;
  LOn: Integer;
begin
  FillAddress(AAddress, APort, LAddr);
  LOn := 1;
  if (setsockopt(AHandle, SOL_SOCKET, SoExclusiveAddrUse, PAnsiChar(@LOn), SizeOf(LOn)) <> 0) or
    (bind(AHandle, TSockAddr(LAddr), SizeOf(LAddr)) <> 0) or
    (listen(AHandle, ABacklog) <> 0) then
    Result := LastError
  else
    Result := 0;
end;

class function TWindowsNetOs.LocalPort(AHandle: TWindowsSocketHandle): Word;
var
  LAddr: TSockAddrIn;
  LLen: Integer;
begin
  LAddr := Default(TSockAddrIn);
  LLen := SizeOf(LAddr);
  if getsockname(AHandle, TSockAddr(LAddr), LLen) <> 0 then
    Exit(0);
  Result := Word(PByte(@LAddr.sin_port)[0]) shl 8 or PByte(@LAddr.sin_port)[1];
end;

class function TWindowsNetOs.AcceptConnection(AListener: TWindowsSocketHandle;
  out AHandle: TWindowsSocketHandle): Integer;
var
  LAddr: TSockAddrIn;
  LLen: Integer;
begin
  LAddr := Default(TSockAddrIn);
  LLen := SizeOf(LAddr);
  AHandle := accept(AListener, PSockAddr(@LAddr), @LLen);
  if AHandle = InvalidHandle then
    Exit(LastError);
  // accept takes no flag, so the accepted handle is marked here
  SetHandleInformation(AHandle, HANDLE_FLAG_INHERIT, 0);
  Result := 0;
end;

class function TWindowsNetOs.IsTransientAcceptError(AError: Integer): Boolean;
begin
  Result := (AError = WSAEWOULDBLOCK) or (AError = WSAEINTR) or
    (AError = WSAECONNRESET) or (AError = WSAECONNABORTED);
end;

class function TWindowsNetOs.ReceiveBytes(AHandle: TWindowsSocketHandle; var ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  Result := recv(AHandle, ABuffer[AOffset], ALength, 0);
  if Result < 0 then
    Result := -1;
end;

class function TWindowsNetOs.SendBytes(AHandle: TWindowsSocketHandle; const ABuffer: TBytes;
  AOffset, ALength: Int32): Int32;
begin
  Result := send(AHandle, ABuffer[AOffset], ALength, 0);
  if Result < 0 then
    Result := -1;
end;

initialization
  TWindowsNetOs.Startup;

finalization
  TWindowsNetOs.Shutdown;

{$ENDIF}

end.
