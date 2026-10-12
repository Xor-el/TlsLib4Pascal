{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpInMemorySessionStore;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  TlpDataEncoding,
  TlpICryptoProvider,
  TlpISession;

type
  /// <summary>
  /// The default in-memory <see cref="ISessionStore" />: a bounded, stateful
  /// server store. A stored session is addressed by an opaque handle (a fresh
  /// random blob from <see cref="Put" />, or a caller id via
  /// <see cref="PutWithId" />); Take removes it (single-use) and Peek reads it without removing.
  /// When the cap is reached the oldest entry is evicted. Guarded by an internal
  /// lock, so one instance is safe to share across connections/threads.
  /// </summary>
  TInMemorySessionStore = class sealed(TInterfacedObject, ISessionStore)
  strict private
  type
    // Seq ties an order slot to the Put that made it, so a re-put id's stale slot cannot evict it
    TEntry = record
      Session: IResumableSession;
      Seq: UInt64;
    end;
    TOrderSlot = record
      Key: string;
      Seq: UInt64;
    end;
  var
    FRandom: IRandom;
    FByKey: TDictionary<string, TEntry>;
    FOrder: TQueue<TOrderSlot>;
    FNextSeq: UInt64;
    FCapacity: Int32;
    FLock: TCriticalSection;
    class function KeyOf(const AId: TBytes): string; static;
    procedure EvictToCapacity;
    /// <summary>Rebuilds FOrder from its own still-live, de-duplicated entries (keeping
    /// insertion order) so the ordering structure can never grow without bound even when
    /// single-use consumption keeps FByKey small and EvictToCapacity rarely fires. The
    /// bound holds by construction: this runs whenever FOrder exceeds OrderSlackFactor x
    /// FCapacity and reduces it to the live count (<= FCapacity).</summary>
    procedure CompactOrder;
  public
    /// <summary>A store holding up to ACapacity sessions (default when 0 or less).</summary>
    constructor Create(const ARandom: IRandom); overload;
    constructor Create(const ARandom: IRandom; ACapacity: Int32); overload;
    destructor Destroy; override;

    function Put(const ASession: IResumableSession): TBytes;
    procedure PutWithId(const AId: TBytes; const ASession: IResumableSession);
    function Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
    function Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
    procedure Remove(const AId: TBytes);
    procedure Clear;
    function Count: Int32;
  end;

implementation

const
  DefaultSessionStoreCapacity = Int32(4096);
  HandleLength = Int32(32);
  // compact FOrder once it holds more than this multiple of the live capacity in (mostly
  // dead) entries; keeps the ordering structure bounded at O(FCapacity)
  OrderSlackFactor = Int32(2);

{ TInMemorySessionStore }

constructor TInMemorySessionStore.Create(const ARandom: IRandom);
begin
  Create(ARandom, 0);
end;

constructor TInMemorySessionStore.Create(const ARandom: IRandom; ACapacity: Int32);
begin
  inherited Create;
  FRandom := ARandom;
  if ACapacity > 0 then
    FCapacity := ACapacity
  else
    FCapacity := DefaultSessionStoreCapacity;
  FByKey := TDictionary<string, TEntry>.Create;
  FOrder := TQueue<TOrderSlot>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TInMemorySessionStore.Destroy;
begin
  FByKey.Free;
  FOrder.Free;
  FLock.Free;
  inherited Destroy;
end;

class function TInMemorySessionStore.KeyOf(const AId: TBytes): string;
begin
  // a lossless, encoding-independent text key over the binary handle
  Result := TDataEncoding.HexEncode(AId);
end;

procedure TInMemorySessionStore.EvictToCapacity;
var
  LSlot: TOrderSlot;
  LEntry: TEntry;
begin
  while (FByKey.Count > FCapacity) and (FOrder.Count > 0) do
  begin
    LSlot := FOrder.Dequeue;
    // a slot left by a taken or re-put entry no longer matches and drops harmlessly
    if FByKey.TryGetValue(LSlot.Key, LEntry) and (LEntry.Seq = LSlot.Seq) then
      FByKey.Remove(LSlot.Key);
  end;
end;

procedure TInMemorySessionStore.CompactOrder;
var
  LSlot: TOrderSlot;
  LEntry: TEntry;
  LKept: TQueue<TOrderSlot>;
begin
  LKept := TQueue<TOrderSlot>.Create;
  try
    while FOrder.Count > 0 do
    begin
      LSlot := FOrder.Dequeue;
      if FByKey.TryGetValue(LSlot.Key, LEntry) and (LEntry.Seq = LSlot.Seq) then
        LKept.Enqueue(LSlot);
    end;
    while LKept.Count > 0 do
      FOrder.Enqueue(LKept.Dequeue);
  finally
    LKept.Free;
  end;
end;

function TInMemorySessionStore.Put(const ASession: IResumableSession): TBytes;
begin
  Result := nil;
  if ASession = nil then
    Exit;
  Result := FRandom.GenerateBytes(HandleLength);
  PutWithId(Result, ASession); // locks internally
end;

procedure TInMemorySessionStore.PutWithId(const AId: TBytes;
  const ASession: IResumableSession);
var
  LKey: string;
  LEntry: TEntry;
  LSlot: TOrderSlot;
begin
  if ASession = nil then
    Exit;
  LKey := KeyOf(AId);
  FLock.Enter;
  try
    Inc(FNextSeq);
    LEntry.Session := ASession;
    LEntry.Seq := FNextSeq;
    LSlot.Key := LKey;
    LSlot.Seq := FNextSeq;
    FByKey.AddOrSetValue(LKey, LEntry);
    FOrder.Enqueue(LSlot);
    EvictToCapacity;
    // FOrder gains a (possibly soon-dead) entry per Put; single-use Take keeps FByKey small
    // so EvictToCapacity may never fire - bound FOrder by compacting away dead/dup entries
    if Int64(FOrder.Count) > Int64(FCapacity) * OrderSlackFactor then
      CompactOrder;
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionStore.Peek(const AId: TBytes;
  out ASession: IResumableSession): Boolean;
var
  LEntry: TEntry;
begin
  ASession := nil;
  FLock.Enter;
  try
    Result := FByKey.TryGetValue(KeyOf(AId), LEntry);
    if Result then
      ASession := LEntry.Session;
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionStore.Take(const AId: TBytes;
  out ASession: IResumableSession): Boolean;
var
  LKey: string;
  LEntry: TEntry;
begin
  ASession := nil;
  LKey := KeyOf(AId);
  FLock.Enter;
  try
    Result := FByKey.TryGetValue(LKey, LEntry);
    if Result then
    begin
      ASession := LEntry.Session;
      FByKey.Remove(LKey);
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TInMemorySessionStore.Remove(const AId: TBytes);
var
  LKey: string;
begin
  LKey := KeyOf(AId);
  FLock.Enter;
  try
    FByKey.Remove(LKey);
  finally
    FLock.Leave;
  end;
end;

procedure TInMemorySessionStore.Clear;
begin
  FLock.Enter;
  try
    FByKey.Clear;
    FOrder.Clear;
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionStore.Count: Int32;
begin
  FLock.Enter;
  try
    Result := FByKey.Count;
  finally
    FLock.Leave;
  end;
end;

end.
