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
  var
    FRandom: IRandom;
    FByKey: TDictionary<string, IResumableSession>;
    FOrder: TQueue<string>;
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
    constructor Create(const ARandom: IRandom; ACapacity: Int32 = 0);
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

constructor TInMemorySessionStore.Create(const ARandom: IRandom; ACapacity: Int32);
begin
  inherited Create;
  FRandom := ARandom;
  if ACapacity > 0 then
    FCapacity := ACapacity
  else
    FCapacity := DefaultSessionStoreCapacity;
  FByKey := TDictionary<string, IResumableSession>.Create;
  FOrder := TQueue<string>.Create;
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
  LKey: string;
begin
  while (FByKey.Count > FCapacity) and (FOrder.Count > 0) do
  begin
    LKey := FOrder.Dequeue;
    FByKey.Remove(LKey); // stale order entries (already taken) drop harmlessly
  end;
end;

procedure TInMemorySessionStore.CompactOrder;
var
  LKey: string;
  LKept: TQueue<string>;
  LSeen: TDictionary<string, Boolean>;
begin
  LKept := TQueue<string>.Create;
  LSeen := TDictionary<string, Boolean>.Create;
  try
    while FOrder.Count > 0 do
    begin
      LKey := FOrder.Dequeue;
      if FByKey.ContainsKey(LKey) and not LSeen.ContainsKey(LKey) then
      begin
        LKept.Enqueue(LKey);
        LSeen.Add(LKey, True);
      end;
    end;
    while LKept.Count > 0 do
      FOrder.Enqueue(LKept.Dequeue);
  finally
    LKept.Free;
    LSeen.Free;
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
begin
  if ASession = nil then
    Exit;
  LKey := KeyOf(AId);
  FLock.Enter;
  try
    FByKey.AddOrSetValue(LKey, ASession);
    FOrder.Enqueue(LKey);
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
begin
  ASession := nil;
  FLock.Enter;
  try
    Result := FByKey.TryGetValue(KeyOf(AId), ASession);
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionStore.Take(const AId: TBytes;
  out ASession: IResumableSession): Boolean;
var
  LKey: string;
begin
  ASession := nil;
  LKey := KeyOf(AId);
  FLock.Enter;
  try
    Result := FByKey.TryGetValue(LKey, ASession);
    if Result then
      FByKey.Remove(LKey);
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
