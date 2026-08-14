{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpInMemorySessionCache;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  TlpTlsVersion,
  TlpISession;

type
  /// <summary>
  /// The default in-memory <see cref="ISessionCache" />: a bounded client cache
  /// keyed by (server identity, SNI). Retrieval is single-use (a ticket is popped
  /// on use); when the cap is reached the oldest entry is evicted. Guarded by an
  /// internal lock, so one instance is safe to share across connections/threads.
  /// </summary>
  TInMemorySessionCache = class sealed(TInterfacedObject, ISessionCache)
  strict private
  type
    TEntry = record
      Key: string;
      Session: IResumableSession;
    end;
  var
    FEntries: TList<TEntry>;
    FKxHints: TDictionary<string, UInt16>;
    FCapacity: Int32;
    FLock: TCriticalSection;
    class function KeyFor(const AServerIdentity, AServerName: string): string; static;
  class var
    FShared: ISessionCache;
    FSharedLock: TCriticalSection;
  public
    class constructor Create;
    class destructor Destroy;
    /// <summary>A process-wide, lazily-created session cache - the default client resumption
    /// store for the adapters, stable for the process so a ticket cached on one connection is
    /// offered on a reconnect. Keyed by (server identity, SNI), so it never cross-resumes hosts.</summary>
    class function Shared: ISessionCache; static;
    /// <summary>A cache holding up to ACapacity sessions (default when 0 or less).</summary>
    constructor Create(ACapacity: Int32 = 0);
    destructor Destroy; override;

    procedure Store(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    function Take(const AServerIdentity, AServerName: string;
      out ASession: IResumableSession): Boolean;
    procedure SetKxHint(const AServerIdentity, AServerName: string; AGroup: UInt16);
    function KxHint(const AServerIdentity, AServerName: string): UInt16;
    procedure Clear;
    function Count: Int32;
  end;

implementation

const
  DefaultSessionCacheCapacity = Int32(256);
  KeySeparator = Char(#0);

{ TInMemorySessionCache }

class constructor TInMemorySessionCache.Create;
begin
  FSharedLock := TCriticalSection.Create;
end;

class destructor TInMemorySessionCache.Destroy;
begin
  FShared := nil;
  FSharedLock.Free;
end;

class function TInMemorySessionCache.Shared: ISessionCache;
begin
  FSharedLock.Acquire;
  try
    if FShared = nil then
      FShared := TInMemorySessionCache.Create as ISessionCache;
    Result := FShared;
  finally
    FSharedLock.Release;
  end;
end;

constructor TInMemorySessionCache.Create(ACapacity: Int32);
begin
  inherited Create;
  if ACapacity > 0 then
    FCapacity := ACapacity
  else
    FCapacity := DefaultSessionCacheCapacity;
  FEntries := TList<TEntry>.Create;
  FKxHints := TDictionary<string, UInt16>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TInMemorySessionCache.Destroy;
begin
  if FEntries <> nil then
  begin
    FEntries.Clear;
    FEntries.Free;
  end;
  FKxHints.Free;
  FLock.Free;
  inherited Destroy;
end;

class function TInMemorySessionCache.KeyFor(const AServerIdentity,
  AServerName: string): string;
begin
  Result := AServerIdentity + KeySeparator + AServerName;
end;

procedure TInMemorySessionCache.Store(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
var
  LEntry: TEntry;
begin
  if ASession = nil then
    Exit;
  LEntry.Key := KeyFor(AServerIdentity, AServerName);
  LEntry.Session := ASession;
  FLock.Enter;
  try
    FEntries.Add(LEntry);
    while FEntries.Count > FCapacity do
      FEntries.Delete(0);
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionCache.Take(const AServerIdentity, AServerName: string;
  out ASession: IResumableSession): Boolean;
var
  LKey: string;
  LIndex: Int32;
begin
  ASession := nil;
  Result := False;
  LKey := KeyFor(AServerIdentity, AServerName);
  FLock.Enter;
  try
    // prefer a TLS 1.3 session over a 1.2 one so a dual-version client does not downgrade
    // on resumption; within a version, newest-first so the freshest ticket resumes. Pass 1
    // scans for the newest 1.3 session, pass 2 falls back to the newest of any version.
    for LIndex := FEntries.Count - 1 downto 0 do
      if (FEntries[LIndex].Key = LKey) and
        (FEntries[LIndex].Session.Version.WireValue = TlsWireVersionTls13) then
      begin
        ASession := FEntries[LIndex].Session;
        FEntries.Delete(LIndex);
        Exit(True);
      end;
    for LIndex := FEntries.Count - 1 downto 0 do
      if FEntries[LIndex].Key = LKey then
      begin
        ASession := FEntries[LIndex].Session;
        FEntries.Delete(LIndex);
        Exit(True);
      end;
  finally
    FLock.Leave;
  end;
end;

procedure TInMemorySessionCache.SetKxHint(const AServerIdentity,
  AServerName: string; AGroup: UInt16);
begin
  FLock.Enter;
  try
    FKxHints.AddOrSetValue(KeyFor(AServerIdentity, AServerName), AGroup);
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionCache.KxHint(const AServerIdentity,
  AServerName: string): UInt16;
begin
  FLock.Enter;
  try
    if not FKxHints.TryGetValue(KeyFor(AServerIdentity, AServerName), Result) then
      Result := 0;
  finally
    FLock.Leave;
  end;
end;

procedure TInMemorySessionCache.Clear;
begin
  FLock.Enter;
  try
    FEntries.Clear;
    FKxHints.Clear;
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionCache.Count: Int32;
begin
  FLock.Enter;
  try
    Result := FEntries.Count;
  finally
    FLock.Leave;
  end;
end;

end.
