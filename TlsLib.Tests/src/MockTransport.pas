{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockTransport;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  SyncObjs,
  TlpTlsLibExceptions,
  TlpITlsEngine,
  TlpITlsTransport,
  TlpINetSocket,
  TlpTlsStream;

type
  /// <summary>A single-direction in-memory byte pipe with blocking reads. Write appends;
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

  /// <summary>A transport decorator that measures how much ciphertext the engine had queued when
  /// a write reached the transport: while armed, each Write drains the rest of the engine's
  /// outbound itself (forwarding all of it to the inner transport) and keeps the largest
  /// written-plus-drained total. A bulk write sealed whole shows as one peak of the whole
  /// payload; a sliced one as at most a slice.</summary>
  TPeakProbeTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FInner: ITlsTransport;
    FEngine: ITlsEngine;
    FArmed: Boolean;
    FPeakPending: Int32;
  public
    constructor Create(const AInner: ITlsTransport; const AEngine: ITlsEngine);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    procedure Arm;
    property PeakPending: Int32 read FPeakPending;
  end;

  /// <summary>A transport decorator that models a host socket's receive timeout: once armed, the
  /// next Read raises ETlsReadTimeout (nothing consumed) and every later Read forwards to the
  /// inner transport as usual.</summary>
  TTimeoutOnceTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FInner: ITlsTransport;
    FArmed: Boolean;
  public
    constructor Create(const AInner: ITlsTransport);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    procedure Arm;
  end;

  /// <summary>A transport that swallows writes and fails every Read with a non-TLS exception,
  /// like a socket layer reporting its own error class.</summary>
  TFailingReadTransport = class sealed(TInterfacedObject, ITlsTransport)
  public
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>A transport that counts the bytes written to it and reads as a closed peer.</summary>
  TRecordingTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FWritten: Int32;
  public
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    property Written: Int32 read FWritten;
  end;

  /// <summary>A transport that hands out one scripted wire on the first Read, then reads as a closed
  /// peer; it counts its writes, or fails them like a dead socket when so built.</summary>
  TScriptedTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FWire: TBytes;
    FServed: Boolean;
    FWritesFail: Boolean;
    FWritten: Int32;
  public
    constructor Create(const AWire: TBytes; AWritesFail: Boolean);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
    property Written: Int32 read FWritten;
  end;

  /// <summary>A transport whose socket died: every Write fails like a reset connection and a Read
  /// reads as a closed peer.</summary>
  TDeadWriteTransport = class sealed(TInterfacedObject, ITlsTransport)
  public
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>A host resolver that answers one name, any case, with 127.0.0.1 and refuses the
  /// rest, counting the lookups.</summary>
  TMockHostResolver = class sealed(TInterfacedObject, IHostResolver)
  strict private
  var
    FName: string;
    FAsked: Int32;
  public
    constructor Create(const AName: string);
    function TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
    property Asked: Int32 read FAsked;
  end;

  /// <summary>The server half of a loopback on its own thread; owns the server stream.</summary>
  TLoopbackServerThread = class abstract(TThread)
  strict protected
  var
    FStream: TTlsStream;
    FTransport: TMemoryTransport;
    FClientTransport: TMemoryTransport;
  public
    constructor Create(const AStream: TTlsStream; const ATransport,
      AClientTransport: TMemoryTransport);
    destructor Destroy; override;
    /// <summary>Ends the client's write side so a waiting server fails, then joins.</summary>
    procedure Finish;
  end;

implementation

resourcestring
  SMockReceiveTimedOut = 'the mock socket receive timeout elapsed';
  SMockSocketFailed = 'the mock socket failed';

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

{ TPeakProbeTransport }

constructor TPeakProbeTransport.Create(const AInner: ITlsTransport;
  const AEngine: ITlsEngine);
begin
  inherited Create;
  FInner := AInner;
  FEngine := AEngine;
  FArmed := False;
  FPeakPending := 0;
end;

function TPeakProbeTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  Result := FInner.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TPeakProbeTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
var
  LBuf: TBytes;
  LGot, LTotal: Int32;
begin
  FInner.Write(ABuffer, AOffset, ALength);
  if not FArmed then
    Exit;
  // what the engine still holds after this write is what was sealed ahead of it
  LTotal := ALength;
  SetLength(LBuf, 65536);
  repeat
    LGot := FEngine.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
    begin
      FInner.Write(LBuf, 0, LGot);
      Inc(LTotal, LGot);
    end;
  until LGot = 0;
  if LTotal > FPeakPending then
    FPeakPending := LTotal;
end;

procedure TPeakProbeTransport.Arm;
begin
  FArmed := True;
  FPeakPending := 0;
end;

{ TTimeoutOnceTransport }

constructor TTimeoutOnceTransport.Create(const AInner: ITlsTransport);
begin
  inherited Create;
  FInner := AInner;
  FArmed := False;
end;

function TTimeoutOnceTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  if FArmed then
  begin
    FArmed := False;
    raise ETlsReadTimeout.CreateRes(@SMockReceiveTimedOut);
  end;
  Result := FInner.Read(ABuffer, AOffset, AMaxLength);
end;

procedure TTimeoutOnceTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  FInner.Write(ABuffer, AOffset, ALength);
end;

procedure TTimeoutOnceTransport.Arm;
begin
  FArmed := True;
end;

{ TFailingReadTransport }

function TFailingReadTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  raise EInOutError.CreateRes(@SMockSocketFailed);
end;

procedure TFailingReadTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
end;

{ TRecordingTransport }

function TRecordingTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := 0;
end;

procedure TRecordingTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  System.Inc(FWritten, ALength);
end;

{ TScriptedTransport }

constructor TScriptedTransport.Create(const AWire: TBytes; AWritesFail: Boolean);
begin
  inherited Create;
  FWire := System.Copy(AWire);
  FWritesFail := AWritesFail;
end;

function TScriptedTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := 0;
  if FServed then
    Exit;
  FServed := True;
  Result := System.Length(FWire);
  if Result > AMaxLength then
    Result := AMaxLength;
  System.Move(FWire[0], ABuffer[AOffset], Result);
end;

procedure TScriptedTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  if FWritesFail then
    raise EInOutError.CreateRes(@SMockSocketFailed);
  System.Inc(FWritten, ALength);
end;

{ TDeadWriteTransport }

function TDeadWriteTransport.Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
begin
  Result := 0;
end;

procedure TDeadWriteTransport.Write(const ABuffer: TBytes; AOffset, ALength: Int32);
begin
  raise EInOutError.CreateRes(@SMockSocketFailed);
end;

{ TMockHostResolver }

constructor TMockHostResolver.Create(const AName: string);
begin
  inherited Create;
  FName := AName;
end;

function TMockHostResolver.TryResolveIPv4(const AHost: string; out AAddress: TBytes): Boolean;
begin
  System.Inc(FAsked);
  AAddress := nil;
  Result := SameText(AHost, FName);
  if Result then
    AAddress := TBytes.Create(127, 0, 0, 1);
end;

{ TLoopbackServerThread }

constructor TLoopbackServerThread.Create(const AStream: TTlsStream;
  const ATransport, AClientTransport: TMemoryTransport);
begin
  inherited Create(True);
  FStream := AStream;
  FTransport := ATransport;
  FClientTransport := AClientTransport;
  FreeOnTerminate := False;
end;

destructor TLoopbackServerThread.Destroy;
begin
  // EOF the client so a server parked in a read exits and the join cannot hang the run
  FClientTransport.CloseWrite;
  inherited Destroy;
  FStream.Free;
end;

procedure TLoopbackServerThread.Finish;
begin
  FClientTransport.CloseWrite;
  WaitFor;
end;

end.
