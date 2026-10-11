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

{ Reference ITcpConnector and ITcpListener over the OS socket calls, OUTSIDE the sans-IO core
  package like TlpSocketHttpFetcher. The sockets are IPv4. Every wait for a socket is made by the
  OS layer (poll on POSIX, select on Windows), so no descriptor number can overrun a select set
  and no wait depends on a kernel socket timeout option. A send is not bounded: ITlsTransport.Write
  blocks until the bytes are handed over. }

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
{$IFDEF TLSLIB_MSWINDOWS}
  TlpWindowsNetOs,
{$ELSE}
  TlpPosixNetOs,
{$ENDIF}
  TlpITlsTransport,
  TlpINetSocket,
  TlpNetExceptions,
  TlpTlsLibExceptions,
  TlpTlsConnection,
  TlpIpLiteral;

type
  /// <summary>The OS socket layer every TlsLib.Net socket and the fcl-net adapter go through.</summary>
{$IFDEF TLSLIB_MSWINDOWS}
  TNetOs = TWindowsNetOs;
  TNetHandle = TWindowsSocketHandle;
  TNetWait = TWindowsNetWait;
{$ELSE}
  TNetOs = TPosixNetOs;
  TNetHandle = TPosixSocketHandle;
  TNetWait = TPosixNetWait;
{$ENDIF}

  /// <summary>Resolves with the system's own resolver. An IPv4 literal needs no lookup; a name must
  /// be ASCII, an international name in its A-label form (RFC 5890). The lookup is not bounded: the
  /// system resolver's own timeouts apply.</summary>
  TSystemHostResolver = class sealed(TInterfacedObject, IHostResolver)
  public
    function TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
  end;

  /// <summary>An ITcpConnector over the OS sockets. The streams it returns bound a read with the
  /// connection's handshake and application-read caps, and block otherwise. The connect timeout
  /// starts once the host is resolved.</summary>
  TTcpConnector = class sealed(TInterfacedObject, ITcpConnector)
  strict private
    FConnectTimeoutMs: Int32;
    FResolver: IHostResolver;
  public
    /// <summary>AConnectTimeoutMs must be positive; the system resolver finds the host.</summary>
    constructor Create(AConnectTimeoutMs: Int32); overload;
    /// <summary>AConnectTimeoutMs must be positive; AResolver is required (nil raises).</summary>
    constructor Create(AConnectTimeoutMs: Int32; const AResolver: IHostResolver); overload;
    function Connect(const AHost: string; APort: Word): ITlsTimedTransport;
  end;

  /// <summary>An ITcpListener over the OS sockets, bound to an IPv4 address and listening.</summary>
  TTcpListener = class sealed(TInterfacedObject, ITcpListener)
  strict private
  var
    FHandle: TNetHandle;
    FPort: Word;
  public
    /// <summary>AAddress is an IPv4 literal (a name or an empty text raises); APort 0 picks an
    /// ephemeral port.</summary>
    constructor Create(const AAddress: string; APort: Word);
    destructor Destroy; override;
    function Port: Word;
    function TryAccept(ATimeoutMs: Int32; out ATransport: ITlsTimedTransport): Boolean;
  end;

implementation

const
  LISTEN_BACKLOG = 8;

resourcestring
  SNetConnectFailed = 'could not connect to %s:%d: %s';
  SNetConnectTimedOut = 'the connect timeout elapsed';
  SNetEmptyHost = 'no host to connect to';
  SNetHostNotFound = 'the host name did not resolve to an IPv4 address';
  SNetListenFailed = 'could not listen on %s:%d: %s';
  SNetAddressNotIpv4 = 'the address is not an IPv4 literal';
  SNetAcceptFailed = 'accepting a connection failed: %s';
  SNetNonPositiveTimeout = 'the connect timeout must be positive';
  SNetNilResolver = 'a host resolver is required (pass a resolver, not nil)';
  SNetSendFailed = 'the socket made no progress sending';

type
  TTcpStream = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FHandle: TNetHandle;
  strict protected
    function WaitReadable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    /// <summary>Takes ownership of AHandle.</summary>
    constructor Create(AHandle: TNetHandle);
    destructor Destroy; override;
  end;

{ TSystemHostResolver }

function TSystemHostResolver.TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
var
  LChar: Char;
begin
  if TIpLiteral.TryParseIPv4(AHost, AAddress) then
    Exit(True);
  AAddress := nil;
  Result := False;
  if AHost = '' then
    Exit;
  for LChar in AHost do
    if Ord(LChar) > 127 then
      Exit;
  Result := TNetOs.LookupIPv4(AnsiString(AHost), AAddress);
end;

{ TTcpStream }

constructor TTcpStream.Create(AHandle: TNetHandle);
begin
  inherited Create;
  FHandle := AHandle;
end;

destructor TTcpStream.Destroy;
begin
  TNetOs.Close(FHandle);
  inherited Destroy;
end;

function TTcpStream.WaitReadable(AMs: Int32): Boolean;
begin
  Result := TNetOs.Wait(FHandle, TNetWait.Readable, AMs);
end;

function TTcpStream.ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := TNetOs.ReceiveBytes(FHandle, ABuffer, AOffset, AMaxLength);
end;

function TTcpStream.SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32;
begin
  Result := TNetOs.SendBytes(FHandle, ABuffer, AOffset, ALength);
  if Result <= 0 then
    raise ETlsStreamError.CreateRes(@SNetSendFailed);
end;

{ TTcpConnector }

constructor TTcpConnector.Create(AConnectTimeoutMs: Int32);
begin
  Create(AConnectTimeoutMs, TSystemHostResolver.Create as IHostResolver);
end;

constructor TTcpConnector.Create(AConnectTimeoutMs: Int32; const AResolver: IHostResolver);
begin
  inherited Create;
  if AConnectTimeoutMs <= 0 then
    raise EArgumentTlsLibException.CreateRes(@SNetNonPositiveTimeout);
  if AResolver = nil then
    raise EArgumentTlsLibException.CreateRes(@SNetNilResolver);
  FConnectTimeoutMs := AConnectTimeoutMs;
  FResolver := AResolver;
end;

function TTcpConnector.Connect(const AHost: string; APort: Word): ITlsTimedTransport;
var
  LAddress: TBytes;
  LHandle: TNetHandle;
  LError: Integer;
  LReason: string;
begin
  if AHost = '' then
    raise ENetConnectError.Create(Format(SNetConnectFailed, [AHost, APort, SNetEmptyHost]));
  if not FResolver.TryResolveIPv4(AHost, LAddress) then
    raise ENetConnectError.Create(Format(SNetConnectFailed, [AHost, APort, SNetHostNotFound]));
  LError := TNetOs.OpenStream(LHandle);
  if LError <> 0 then
    raise ENetConnectError.Create(Format(SNetConnectFailed,
      [AHost, APort, SysErrorMessage(LError)]));
  LReason := '';
  LError := TNetOs.SetBlocking(LHandle, False);
  if LError = 0 then
    LError := TNetOs.BeginConnect(LHandle, LAddress, APort);
  if LError = 0 then
  begin
    if TNetOs.Wait(LHandle, TNetWait.Writable, FConnectTimeoutMs) then
    begin
      LError := TNetOs.ConnectResult(LHandle);
      if LError = 0 then
        LError := TNetOs.SetBlocking(LHandle, True);
    end
    else
      LReason := SNetConnectTimedOut;
  end;
  if (LError <> 0) or (LReason <> '') then
  begin
    TNetOs.Close(LHandle);
    if LReason = '' then
      LReason := SysErrorMessage(LError);
    raise ENetConnectError.Create(Format(SNetConnectFailed, [AHost, APort, LReason]));
  end;
  Result := TTcpStream.Create(LHandle) as ITlsTimedTransport;
end;

{ TTcpListener }

constructor TTcpListener.Create(const AAddress: string; APort: Word);
var
  LOctets: TBytes;
  LError: Integer;
begin
  inherited Create;
  // Destroy closes whatever was opened when a step below raises
  FHandle := TNetOs.InvalidHandle;
  if not TIpLiteral.TryParseIPv4(AAddress, LOctets) then
    raise ENetSocketError.Create(Format(SNetListenFailed, [AAddress, APort, SNetAddressNotIpv4]));
  LError := TNetOs.OpenStream(FHandle);
  if LError = 0 then
    LError := TNetOs.BindAndListen(FHandle, LOctets, APort, LISTEN_BACKLOG);
  // a connection can go between the readiness wait and the accept, which must then not block
  if LError = 0 then
    LError := TNetOs.SetBlocking(FHandle, False);
  if LError <> 0 then
    raise ENetSocketError.Create(Format(SNetListenFailed,
      [AAddress, APort, SysErrorMessage(LError)]));
  FPort := TNetOs.LocalPort(FHandle);
end;

destructor TTcpListener.Destroy;
begin
  if FHandle <> TNetOs.InvalidHandle then
    TNetOs.Close(FHandle);
  inherited Destroy;
end;

function TTcpListener.Port: Word;
begin
  Result := FPort;
end;

function TTcpListener.TryAccept(ATimeoutMs: Int32; out ATransport: ITlsTimedTransport): Boolean;
var
  LHandle: TNetHandle;
  LError: Integer;
begin
  ATransport := nil;
  Result := False;
  if not TNetOs.Wait(FHandle, TNetWait.Readable, ATimeoutMs) then
    Exit;
  LError := TNetOs.AcceptConnection(FHandle, LHandle);
  if LError <> 0 then
  begin
    if TNetOs.IsTransientAcceptError(LError) then
      Exit;
    raise ENetSocketError.Create(Format(SNetAcceptFailed, [SysErrorMessage(LError)]));
  end;
  TNetOs.ArmAgainstSigPipe(LHandle);
  // some systems hand the accepted socket the listener's non-blocking mode
  LError := TNetOs.SetBlocking(LHandle, True);
  if LError <> 0 then
  begin
    TNetOs.Close(LHandle);
    raise ENetSocketError.Create(Format(SNetAcceptFailed, [SysErrorMessage(LError)]));
  end;
  ATransport := TTcpStream.Create(LHandle) as ITlsTimedTransport;
  Result := True;
end;

end.
