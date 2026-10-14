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
  TlpHandshakeMessages,
  TlpClientSessionPolicy,
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
    FKxHintOrder: TList<string>;
    FCapacity: Int32;
    FLock: TCriticalSection;
    class function KeyFor(const AServerIdentity, AServerName: string): string; static;
    class function IsExpired(const ASession: IResumableSession;
      ANowMillis: UInt64): Boolean; static;
  public
    /// <summary>A cache holding up to ACapacity sessions (default when 0 or less).</summary>
    constructor Create; overload;
    constructor Create(ACapacity: Int32); overload;
    destructor Destroy; override;

    procedure Store(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    procedure Remove(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    function Take(const AServerIdentity, AServerName: string; ANowMillis: UInt64;
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

constructor TInMemorySessionCache.Create;
begin
  Create(0);
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
  FKxHintOrder := TList<string>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TInMemorySessionCache.Destroy;
begin
  FEntries.Free;
  FKxHints.Free;
  FKxHintOrder.Free;
  FLock.Free;
  inherited Destroy;
end;

class function TInMemorySessionCache.KeyFor(const AServerIdentity,
  AServerName: string): string;
begin
  Result := AServerIdentity + KeySeparator + AServerName;
end;

class function TInMemorySessionCache.IsExpired(const ASession: IResumableSession;
  ANowMillis: UInt64): Boolean;
var
  LLifetime: UInt32;
begin
  // an unspecified lifetime (a 1.2 hint of 0, RFC 5077 3.3) is held to the 7-day client ceiling
  // (RFC 9846 4.7.1); a backwards clock underflows the UInt64 subtraction to "expired",
  // matching the offer policy
  LLifetime := ASession.TicketLifetime;
  if (LLifetime = 0) or (LLifetime > MaxTicketLifetimeSeconds) then
    LLifetime := MaxTicketLifetimeSeconds;
  Result := ((ANowMillis - ASession.IssuedAtMillis) > (UInt64(LLifetime) * 1000)) or
    TClientSessionPolicy.AuthenticationLapsed(ASession.AuthenticatedAtMillis, ANowMillis);
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

procedure TInMemorySessionCache.Remove(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
var
  LKey: string;
  LIndex: Int32;
begin
  LKey := KeyFor(AServerIdentity, AServerName);
  FLock.Enter;
  try
    for LIndex := FEntries.Count - 1 downto 0 do
      if (FEntries[LIndex].Key = LKey) and (FEntries[LIndex].Session = ASession) then
      begin
        FEntries.Delete(LIndex);
        Exit;
      end;
  finally
    FLock.Leave;
  end;
end;

function TInMemorySessionCache.Take(const AServerIdentity, AServerName: string;
  ANowMillis: UInt64; out ASession: IResumableSession): Boolean;
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
    // scans for the newest 1.3 session, pass 2 falls back to the newest of any version. An
    // expired entry is dropped as it is passed rather than returned, so a stale head cannot
    // shadow a live ticket behind it (downto keeps the running index valid after a Delete).
    for LIndex := FEntries.Count - 1 downto 0 do
      if (FEntries[LIndex].Key = LKey) and
        (FEntries[LIndex].Session.Version.WireValue = TlsWireVersionTls13) then
      begin
        if IsExpired(FEntries[LIndex].Session, ANowMillis) then
        begin
          FEntries.Delete(LIndex);
          Continue;
        end;
        ASession := FEntries[LIndex].Session;
        FEntries.Delete(LIndex);
        Exit(True);
      end;
    for LIndex := FEntries.Count - 1 downto 0 do
      if FEntries[LIndex].Key = LKey then
      begin
        if IsExpired(FEntries[LIndex].Session, ANowMillis) then
        begin
          FEntries.Delete(LIndex);
          Continue;
        end;
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
var
  LKey: string;
begin
  LKey := KeyFor(AServerIdentity, AServerName);
  FLock.Enter;
  try
    if FKxHints.ContainsKey(LKey) then
      FKxHints[LKey] := AGroup
    else
    begin
      FKxHints.Add(LKey, AGroup);
      FKxHintOrder.Add(LKey);
      while FKxHintOrder.Count > FCapacity do
      begin
        FKxHints.Remove(FKxHintOrder[0]);
        FKxHintOrder.Delete(0);
      end;
    end;
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
    FKxHintOrder.Clear;
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
