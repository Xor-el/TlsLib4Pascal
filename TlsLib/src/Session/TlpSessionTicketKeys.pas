{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSessionTicketKeys;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  TlpArrayUtilities,
  TlpICryptoProvider,
  TlpIClock,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlpTlsLibExceptions,
  TlpISession;

type
  /// <summary>
  /// The default <see cref="ISessionTicketKeyManager" />: a rotating STEK ring
  /// holding the current encrypt key plus a bounded window of recent keys still
  /// accepted for decrypt. Keys are AES-256 sized and each is tagged by a random
  /// fixed-length name carried in the clear at the front of a ticket. Rotation
  /// promotes a fresh current key and retires the oldest beyond the window; with
  /// a clock, a key also retires once it ages past the window, and the current
  /// key rotates after a per-key seal cap. Guarded by an internal lock, so one
  /// instance is safe to share across connections/threads.
  /// </summary>
  TStekTicketKeyManager = class sealed(TInterfacedObject, ISessionTicketKeyManager)
  strict private
  type
    TStekKey = record
      Name: TBytes;
      Key: ISecretBuffer;
      CreatedAt: UInt64; // unix millis on the manager's clock; 0 when there is no clock
      Seals: UInt32;
    end;
  var
    FRandom: IRandom;
    FKeys: TList<TStekKey>; // oldest .. current (the last entry is current)
    FWindow: Int32;
    FLock: TCriticalSection;
    // optional time-based auto-rotation: when a clock and interval are set, the current key is
    // promoted to a fresh one once the interval elapses, on the encrypt path (no timers/threads)
    FClock: ITlsClock;
    FRotateIntervalMillis: UInt64;
    FNextRotateMillis: UInt64;
    FAgeBoundMillis: UInt64; // window x interval, saturated; the age past which a key is retired
    FMaxSealsPerKey: UInt32;
    // set once a caller installs a key: the manager then never mints, auto-rotates, or time-retires
    // keys, the fleet coordinates them out of band
    FKeysInstalled: Boolean;
    function StampNow: UInt64;
    procedure TrimToWindowLocked;
    procedure PruneExpiredLocked; // drops keys past their age bound; caller holds FLock
    procedure RotateLocked; // adds a fresh current key + trims; caller holds FLock
    procedure MaybeRotateLocked; // rotates if the auto-rotation interval has elapsed; FLock held
  public
    /// <summary>A default STEK manager built from a caller-supplied provider's RNG and clock: a
    /// fresh current key, a current-plus-previous decrypt window, and time-based auto-rotation on
    /// the advertised ticket lifetime, so a ticket stays openable for its whole lifetime and a key
    /// older than twice the lifetime cannot back any live ticket. Honors whatever provider and clock
    /// the caller injected, with no tie to any concrete default provider. Tickets are scoped to this
    /// manager's lifetime; share a STEK across servers/a fleet with InstallKey.</summary>
    class function CreateDefault(const ACryptoProvider: ICryptoProvider;
      const AClock: ITlsClock; ALifetimeSeconds: UInt32): ISessionTicketKeyManager; static;
    /// <summary>A manager with a fresh current key and an AWindowSize decrypt window (a default
    /// applies when 0 or less). Never auto-rotates.</summary>
    constructor Create(const ARandom: IRandom; AWindowSize: Int32 = 0); overload;
    /// <summary>As above, plus time-based auto-rotation: a fresh current key is promoted once
    /// ARotateIntervalSeconds elapse on AClock (lazily, on the encrypt path - no timers), and a key
    /// is retired once it ages past AWindowSize intervals on either the seal or the open path.
    /// AMaxSealsPerKey caps how many tickets one key may seal before it rotates (a default applies
    /// when 0).</summary>
    constructor Create(const ARandom: IRandom; AWindowSize: Int32;
      const AClock: ITlsClock; ARotateIntervalSeconds: UInt32;
      AMaxSealsPerKey: UInt32 = 0); overload;
    destructor Destroy; override;

    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    procedure Rotate;
    function KeyNameLength: Int32;

    /// <summary>Installs a caller-supplied key as the current key (e.g. a shared STEK across a
    /// server fleet); it also enters the decrypt window. The name and key must be the manager's
    /// fixed lengths (KeyNameLength / an AES-256 key) or this raises. Installing hands the ring's
    /// whole lifecycle to the caller: the manager thereafter neither mints, auto-rotates, nor
    /// time-retires keys - the fleet coordinates rotation and pushes old keys out of the window by
    /// installing newer ones.</summary>
    procedure InstallKey(const AName: TBytes; const AKey: ISecretBuffer);
  end;

implementation

const
  StekKeyNameLength = Int32(16);
  StekKeyLength = Int32(32); // AES-256-GCM
  DefaultDecryptWindow = Int32(3);
  // current + previous: a ticket sealed at the very end of a key's tenure is still openable for
  // its whole advertised lifetime, and a key older than twice the lifetime cannot back a live ticket
  DefaultStekLifetimeWindow = Int32(2);
  // fallback rotation interval when no ticket lifetime is advertised
  DefaultStekRotateSeconds = UInt32(7200);
  // half the random-nonce invocation ceiling for a 96-bit GCM nonce (NIST SP 800-38D 8.3); any
  // real ticket lifetime rotates a key long before this, so the cap only bites on keys nobody
  // rotates (a manual manager, or an exhausted installed fleet key)
  MaxSealsPerKeyDefault = UInt32(2147483648);

resourcestring
  SStekKeyNameLength = 'a session-ticket key name must be %d bytes (got %d)';
  SStekKeyLength = 'a session-ticket key must be %d bytes (got %d)';
  SStekKeyNil = 'a session-ticket key must not be nil';

{ TStekTicketKeyManager }

class function TStekTicketKeyManager.CreateDefault(const ACryptoProvider: ICryptoProvider;
  const AClock: ITlsClock; ALifetimeSeconds: UInt32): ISessionTicketKeyManager;
var
  LInterval: UInt32;
begin
  // a zero (unadvertised) lifetime would switch rotation off, so fall back to the default interval
  LInterval := ALifetimeSeconds;
  if LInterval = 0 then
    LInterval := DefaultStekRotateSeconds;
  Result := TStekTicketKeyManager.Create(ACryptoProvider.Primitives.GetRandom,
    DefaultStekLifetimeWindow, AClock, LInterval) as ISessionTicketKeyManager;
end;

constructor TStekTicketKeyManager.Create(const ARandom: IRandom;
  AWindowSize: Int32);
begin
  Create(ARandom, AWindowSize, nil, 0);
end;

constructor TStekTicketKeyManager.Create(const ARandom: IRandom;
  AWindowSize: Int32; const AClock: ITlsClock; ARotateIntervalSeconds: UInt32;
  AMaxSealsPerKey: UInt32);
begin
  inherited Create;
  FRandom := ARandom;
  if AWindowSize > 0 then
    FWindow := AWindowSize
  else
    FWindow := DefaultDecryptWindow;
  FClock := AClock;
  FRotateIntervalMillis := UInt64(ARotateIntervalSeconds) * 1000;
  // window x interval, saturated: an extreme caller-supplied window/interval must not wrap the
  // product to a small age bound that would expire every key at once (overflow checks are off)
  if (FRotateIntervalMillis > 0) and
    (UInt64(FWindow) > High(UInt64) div FRotateIntervalMillis) then
    FAgeBoundMillis := High(UInt64)
  else
    FAgeBoundMillis := UInt64(FWindow) * FRotateIntervalMillis;
  if AMaxSealsPerKey > 0 then
    FMaxSealsPerKey := AMaxSealsPerKey
  else
    FMaxSealsPerKey := MaxSealsPerKeyDefault;
  FKeys := TList<TStekKey>.Create;
  FLock := TCriticalSection.Create;
  Rotate; // start with one fresh current key (which also schedules the first timed rotation)
end;

destructor TStekTicketKeyManager.Destroy;
begin
  FKeys.Free;
  FLock.Free;
  inherited Destroy;
end;

function TStekTicketKeyManager.StampNow: UInt64;
begin
  if FClock <> nil then
    Result := FClock.NowUnixMillis
  else
    Result := 0;
end;

procedure TStekTicketKeyManager.TrimToWindowLocked;
begin
  while FKeys.Count > FWindow do
    FKeys.Delete(0);
end;

procedure TStekTicketKeyManager.PruneExpiredLocked;
var
  LNow: UInt64;
begin
  // only a clock-driven, non-fleet manager expires keys by time; a manual or installed ring is the
  // caller's to retire
  if FKeysInstalled or (FClock = nil) or (FRotateIntervalMillis = 0) then
    Exit;
  LNow := FClock.NowUnixMillis;
  // the oldest keys are at the front; compare by addition so a backwards clock step cannot underflow
  while (FKeys.Count > 0) and (LNow >= FKeys[0].CreatedAt + FAgeBoundMillis) do
    FKeys.Delete(0);
end;

function TStekTicketKeyManager.CurrentKey(out AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
var
  LEntry: TStekKey;
begin
  AKeyName := nil;
  AKey := nil;
  FLock.Enter;
  try
    PruneExpiredLocked;
    MaybeRotateLocked;
    // rotate before the current key overuses its nonce space; an installed fleet key is the
    // operator's to replace, so an exhausted one stops sealing rather than being silently reminted
    if (FKeys.Count > 0) and (FKeys[FKeys.Count - 1].Seals >= FMaxSealsPerKey) then
    begin
      if FKeysInstalled then
        Exit(False);
      RotateLocked;
    end;
    // guards a clock that stepped back between the compare and the stamp: re-mint so a non-fleet
    // server keeps issuing tickets rather than going dark
    if (FKeys.Count = 0) and (not FKeysInstalled) then
      RotateLocked;
    Result := FKeys.Count > 0;
    if not Result then
      Exit;
    LEntry := FKeys[FKeys.Count - 1];
    Inc(LEntry.Seals);
    FKeys[FKeys.Count - 1] := LEntry;
    AKeyName := System.Copy(LEntry.Name, 0, System.Length(LEntry.Name));
    AKey := LEntry.Key;
  finally
    FLock.Leave;
  end;
end;

function TStekTicketKeyManager.KeyByName(const AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
var
  LIndex: Int32;
begin
  AKey := nil;
  Result := False;
  FLock.Enter;
  try
    PruneExpiredLocked; // an aged-out key must not open a ticket even on a quiet, seal-idle server
    // the key name is public (it rides the ticket in the clear); a plain compare is fine
    for LIndex := FKeys.Count - 1 downto 0 do
      if TArrayUtilities.AreEqual(FKeys[LIndex].Name, AKeyName) then
      begin
        AKey := FKeys[LIndex].Key;
        Result := True;
        Exit;
      end;
  finally
    FLock.Leave;
  end;
end;

procedure TStekTicketKeyManager.RotateLocked;
var
  LEntry: TStekKey;
  LRaw: TBytes;
begin
  LEntry.Name := FRandom.GenerateBytes(StekKeyNameLength);
  // wrap the fresh key material in the secret buffer (which copies it), then wipe the
  // transient plaintext TBytes so the raw key does not linger on the heap
  LRaw := FRandom.GenerateBytes(StekKeyLength);
  try
    LEntry.Key := TSecretBuffer.From(LRaw);
  finally
    TSecureMemory.WipeBytes(LRaw);
  end;
  LEntry.CreatedAt := StampNow;
  LEntry.Seals := 0;
  FKeys.Add(LEntry);
  // schedule the next timed rotation from this key's birth, so an out-of-schedule rotation (a seal
  // cap or an explicit Rotate) does not leave the timer poised to evict a key while its tickets live
  if (FClock <> nil) and (FRotateIntervalMillis > 0) then
    FNextRotateMillis := LEntry.CreatedAt + FRotateIntervalMillis;
  TrimToWindowLocked;
end;

procedure TStekTicketKeyManager.MaybeRotateLocked;
begin
  // an installed key freezes auto-rotation: the fleet owns the schedule out of band
  if FKeysInstalled or (FClock = nil) or (FRotateIntervalMillis = 0) then
    Exit;
  if FClock.NowUnixMillis >= FNextRotateMillis then
    RotateLocked; // RotateLocked reschedules FNextRotateMillis
end;

procedure TStekTicketKeyManager.Rotate;
begin
  FLock.Enter;
  try
    RotateLocked;
  finally
    FLock.Leave;
  end;
end;

procedure TStekTicketKeyManager.InstallKey(const AName: TBytes;
  const AKey: ISecretBuffer);
var
  LEntry: TStekKey;
begin
  // a wrong length is a caller mistake that would otherwise surface far away (a bad name as
  // unopenable tickets, a bad key as an exception when sealing); reject it here where it is visible
  if System.Length(AName) <> StekKeyNameLength then
    raise EArgumentTlsLibException.CreateResFmt(@SStekKeyNameLength,
      [StekKeyNameLength, System.Length(AName)]);
  if AKey = nil then
    raise EArgumentTlsLibException.CreateRes(@SStekKeyNil);
  if AKey.Len <> StekKeyLength then
    raise EArgumentTlsLibException.CreateResFmt(@SStekKeyLength, [StekKeyLength, AKey.Len]);
  LEntry.Name := System.Copy(AName, 0, System.Length(AName));
  LEntry.Key := AKey;
  LEntry.CreatedAt := StampNow;
  LEntry.Seals := 0;
  FLock.Enter;
  try
    FKeysInstalled := True;
    FKeys.Add(LEntry);
    TrimToWindowLocked;
  finally
    FLock.Leave;
  end;
end;

function TStekTicketKeyManager.KeyNameLength: Int32;
begin
  Result := StekKeyNameLength;
end;

end.
