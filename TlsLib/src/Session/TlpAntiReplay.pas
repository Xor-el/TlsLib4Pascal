{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpAntiReplay;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  TlpDataEncoding,
  TlpISession;

type
  /// <summary>
  /// The default <see cref="IAntiReplayStrategy" />: a bounded strike register of
  /// recently-seen 0-RTT unique values, each held until its freshness window
  /// lapses. A value seen while still live is a replay and is rejected; the cap
  /// bounds memory, evicting the oldest entries first. Guarded by an internal
  /// lock, so one instance is safe to share across connections/threads.
  /// </summary>
  TStrikeRegisterAntiReplay = class sealed(TInterfacedObject, IAntiReplayStrategy)
  strict private
  var
    FByKey: TDictionary<string, UInt64>; // value -> expiry (ms)
    FOrder: TQueue<string>;
    FCapacity: Int32;
    FLock: TCriticalSection;
    class function KeyOf(const AValue: TBytes): string; static;
    procedure PruneExpired(ANowMillis: UInt64);
  public
    /// <summary>A register holding up to ACapacity live values (default when 0 or less).</summary>
    constructor Create(ACapacity: Int32 = 0);
    destructor Destroy; override;

    function CheckAndRecord(const AUniqueValue: TBytes;
      ANowMillis, AExpiryMillis: UInt64): Boolean;
    procedure Clear;
    function Count: Int32;
  end;

implementation

const
  DefaultStrikeCapacity = Int32(65536);

{ TStrikeRegisterAntiReplay }

constructor TStrikeRegisterAntiReplay.Create(ACapacity: Int32);
begin
  inherited Create;
  if ACapacity > 0 then
    FCapacity := ACapacity
  else
    FCapacity := DefaultStrikeCapacity;
  FByKey := TDictionary<string, UInt64>.Create;
  FOrder := TQueue<string>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TStrikeRegisterAntiReplay.Destroy;
begin
  FByKey.Free;
  FOrder.Free;
  FLock.Free;
  inherited Destroy;
end;

class function TStrikeRegisterAntiReplay.KeyOf(const AValue: TBytes): string;
begin
  // a lossless, encoding-independent text key over the binary unique value
  Result := TDataEncoding.HexEncode(AValue);
end;

procedure TStrikeRegisterAntiReplay.PruneExpired(ANowMillis: UInt64);
var
  LKey: string;
  LExpiry: UInt64;
begin
  // insertion order tracks expiry order (all entries share one window length),
  // so expired entries cluster at the front
  while FOrder.Count > 0 do
  begin
    LKey := FOrder.Peek;
    if not FByKey.TryGetValue(LKey, LExpiry) then
    begin
      FOrder.Dequeue; // already taken out; drop the stale order entry
      Continue;
    end;
    if LExpiry > ANowMillis then
      Break; // front is still live
    FOrder.Dequeue;
    FByKey.Remove(LKey);
  end;
end;

function TStrikeRegisterAntiReplay.CheckAndRecord(const AUniqueValue: TBytes;
  ANowMillis, AExpiryMillis: UInt64): Boolean;
var
  LKey: string;
  LExpiry: UInt64;
  LEvict: string;
begin
  Result := False;
  if System.Length(AUniqueValue) = 0 then
    Exit; // nothing to bind replay protection to
  LKey := KeyOf(AUniqueValue);
  FLock.Enter;
  try
    PruneExpired(ANowMillis);
    if FByKey.TryGetValue(LKey, LExpiry) and (LExpiry > ANowMillis) then
      Exit; // a still-live value: this is a replay
    // at capacity, evict the oldest entries to admit the new one. Under a flood of unique
    // values this can drop a still-live entry, which could then be replayed within its
    // window - the inherent limit of a bounded strike register that RFC 8446 8 permits.
    while (FByKey.Count >= FCapacity) and (FOrder.Count > 0) do
    begin
      LEvict := FOrder.Dequeue;
      FByKey.Remove(LEvict);
    end;
    FByKey.AddOrSetValue(LKey, AExpiryMillis);
    FOrder.Enqueue(LKey);
    Result := True;
  finally
    FLock.Leave;
  end;
end;

procedure TStrikeRegisterAntiReplay.Clear;
begin
  FLock.Enter;
  try
    FByKey.Clear;
    FOrder.Clear;
  finally
    FLock.Leave;
  end;
end;

function TStrikeRegisterAntiReplay.Count: Int32;
begin
  FLock.Enter;
  try
    Result := FByKey.Count;
  finally
    FLock.Leave;
  end;
end;

end.
