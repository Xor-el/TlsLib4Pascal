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
  TStrikeEntry = TPair<string, UInt64>;

  /// <summary>
  /// The default <see cref="IAntiReplayStrategy" />: a bounded strike register of
  /// recently-seen 0-RTT unique values, each held until its freshness window
  /// lapses. A value seen while still live is a replay and is rejected; the cap
  /// bounds memory, and a value arriving at capacity is declined (fail-closed) rather
  /// than evicting a live entry. Guarded by an internal lock, so one instance is safe
  /// to share across connections/threads.
  /// </summary>
  TStrikeRegisterAntiReplay = class sealed(TInterfacedObject, IAntiReplayStrategy)
  strict private
  var
    FByKey: TDictionary<string, UInt64>; // value -> expiry (ms)
    // (value, expiry) in insertion order; the expiry is carried so a re-recorded value's stale
    // earlier entry is recognized and dropped without evicting its live current entry
    FOrder: TQueue<TStrikeEntry>;
    FCapacity: Int32;
    FLock: TCriticalSection;
    class function KeyOf(const AValue: TBytes): string; static;
    procedure PruneExpired(ANowMillis: UInt64);
    procedure CompactOrder;
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
  FOrder := TQueue<TStrikeEntry>.Create;
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
  LFront: TStrikeEntry;
  LCurrent: UInt64;
begin
  // insertion order tracks expiry order (all entries share one window length), so the earliest
  // expiry is at the front
  while FOrder.Count > 0 do
  begin
    LFront := FOrder.Peek;
    if LFront.Value > ANowMillis then
      Break; // front is still live
    FOrder.Dequeue;
    // remove from the dictionary only when it still holds THIS entry; a later expiry means the value
    // was re-recorded, so this is a stale order entry to drop without evicting the live current one
    if FByKey.TryGetValue(LFront.Key, LCurrent) and (LCurrent = LFront.Value) then
      FByKey.Remove(LFront.Key);
  end;
end;

procedure TStrikeRegisterAntiReplay.CompactOrder;
var
  LKept: TQueue<TStrikeEntry>;
  LEntry: TStrikeEntry;
  LCurrent: UInt64;
begin
  // re-recording leaves stale order entries; keep only each value's current one
  LKept := TQueue<TStrikeEntry>.Create;
  try
    while FOrder.Count > 0 do
    begin
      LEntry := FOrder.Dequeue;
      if FByKey.TryGetValue(LEntry.Key, LCurrent) and (LCurrent = LEntry.Value) then
        LKept.Enqueue(LEntry);
    end;
    while LKept.Count > 0 do
      FOrder.Enqueue(LKept.Dequeue);
  finally
    LKept.Free;
  end;
end;

function TStrikeRegisterAntiReplay.CheckAndRecord(const AUniqueValue: TBytes;
  ANowMillis, AExpiryMillis: UInt64): Boolean;
var
  LKey: string;
  LExpiry: UInt64;
begin
  Result := False;
  if System.Length(AUniqueValue) = 0 then
    Exit; // nothing to bind replay protection to
  if AExpiryMillis <= ANowMillis then
    Exit; // an already-lapsed entry protects nothing and would defeat queue compaction
  LKey := KeyOf(AUniqueValue);
  FLock.Enter;
  try
    PruneExpired(ANowMillis);
    if FByKey.TryGetValue(LKey, LExpiry) and (LExpiry > ANowMillis) then
      Exit; // a still-live value: this is a replay
    // at capacity a new value is declined rather than evicting a live strike: dropping one would let
    // its captured 0-RTT flight replay inside its window (RFC 8446 8)
    if (not FByKey.ContainsKey(LKey)) and (FByKey.Count >= FCapacity) then
      Exit;
    if FOrder.Count >= 2 * FCapacity then
      CompactOrder;
    FByKey.AddOrSetValue(LKey, AExpiryMillis);
    FOrder.Enqueue(TStrikeEntry.Create(LKey, AExpiryMillis));
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
