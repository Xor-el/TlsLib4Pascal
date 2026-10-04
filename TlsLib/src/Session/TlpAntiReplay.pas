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
  // (value, expiry-ms) pair; named so the nested generic TQueue<...> specialization parses
  TStrikeEntry = TPair<string, UInt64>;

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
    // (value, expiry) in insertion order; the expiry is carried so a re-recorded value's stale
    // earlier entry is recognized and dropped without evicting its live current entry
    FOrder: TQueue<TStrikeEntry>;
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

function TStrikeRegisterAntiReplay.CheckAndRecord(const AUniqueValue: TBytes;
  ANowMillis, AExpiryMillis: UInt64): Boolean;
var
  LKey: string;
  LExpiry, LCurrent: UInt64;
  LEvict: TStrikeEntry;
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
    // at capacity, evict the oldest LIVE entries to admit the new one. Under a flood of unique
    // values this can drop a still-live entry, which could then be replayed within its window - the
    // inherent limit of a bounded strike register that RFC 8446 8 permits. A stale order entry (its
    // value was re-recorded with a later expiry) is skipped without reducing the count.
    while (FByKey.Count >= FCapacity) and (FOrder.Count > 0) do
    begin
      LEvict := FOrder.Dequeue;
      if FByKey.TryGetValue(LEvict.Key, LCurrent) and (LCurrent = LEvict.Value) then
        FByKey.Remove(LEvict.Key);
    end;
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
