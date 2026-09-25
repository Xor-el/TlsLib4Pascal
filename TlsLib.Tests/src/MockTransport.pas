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
  SyncObjs,
  TlpITlsEngine,
  TlpITlsTransport;

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

implementation

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

end.
