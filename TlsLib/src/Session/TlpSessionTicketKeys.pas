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
  /// The key ring both STEK managers share: the current encrypt key (the last entry) plus a
  /// bounded window of recent keys still accepted for decrypt. Keys are AES-256 sized and each is
  /// tagged by a random fixed-length name carried in the clear at the front of a ticket. How keys
  /// arrive is the subclass's: a rotating manager mints them, a fleet manager has them installed.
  /// Guarded by an internal lock, so one instance is safe to share across connections/threads.
  /// </summary>
  TStekKeyRingBase = class abstract(TInterfacedObject, ISessionTicketKeyManager)
  strict protected
  type
    TStekKey = record
      Name: TBytes;
      Key: ISecretBuffer;
      CreatedAt: UInt64; // unix millis on the manager's clock; 0 when there is no clock
      Seals: UInt32;
    end;
  var
    FKeys: TList<TStekKey>; // oldest .. current (the last entry is current)
    FWindow: Int32;
    FLock: TCriticalSection;
    FClock: ITlsClock;
    FAgeBoundMillis: UInt64; // the age past which a key is retired; 0 = keys never age out
    FMaxSealsPerKey: UInt32;
    constructor CreateRing(AWindowSize: Int32; const AClock: ITlsClock;
      AAgeBoundMillis: UInt64; AMaxSealsPerKey: UInt32);
    function StampNow: UInt64;
    /// <summary>Appends a key as the new current one and trims the window; returns its creation
    /// stamp. The caller holds FLock.</summary>
    function AddKeyLocked(const AName: TBytes; const AKey: ISecretBuffer): UInt64;
    procedure PruneExpiredLocked; // drops keys past their age bound; caller holds FLock
    /// <summary>Makes the current key ready to seal (a rotating ring may mint one); False when the
    /// ring has no key with seal headroom. The caller holds FLock.</summary>
    function PrepareCurrentLocked: Boolean; virtual; abstract;
  public
    destructor Destroy; override;
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyNameLength: Int32;
  end;

  /// <summary>
  /// The default <see cref="IRotatingTicketKeyManager" />: a rotating STEK ring that mints its own
  /// keys. Rotation promotes a fresh current key and retires the oldest beyond the window; with a
  /// clock, a key also retires once it ages past the window, and the current key rotates after a
  /// per-key seal cap.
  /// </summary>
  TStekTicketKeyManager = class sealed(TStekKeyRingBase, IRotatingTicketKeyManager)
  strict private
  var
    FRandom: IRandom;
    // optional time-based auto-rotation: when a clock and interval are set, the current key is
    // promoted to a fresh one once the interval elapses, on the encrypt path (no timers/threads)
    FRotateIntervalMillis: UInt64;
    FNextRotateMillis: UInt64;
    procedure RotateLocked; // adds a fresh current key + trims; caller holds FLock
    procedure MaybeRotateLocked; // rotates if the auto-rotation interval has elapsed; FLock held
    class function AgeBoundFor(AWindowSize: Int32; ARotateIntervalSeconds: UInt32): UInt64; static;
  strict protected
    function PrepareCurrentLocked: Boolean; override;
  public
    /// <summary>A default STEK manager built from a caller-supplied provider's RNG and clock: a
    /// fresh current key, a current-plus-previous decrypt window, and time-based auto-rotation on
    /// the advertised ticket lifetime, so a ticket stays openable for its whole lifetime and a key
    /// older than twice the lifetime cannot back any live ticket. Honors whatever provider and clock
    /// the caller injected, with no tie to any concrete default provider. Tickets are scoped to this
    /// manager's lifetime; to share a STEK across servers/a fleet use TFleetTicketKeyManager.</summary>
    class function CreateDefault(const ACryptoProvider: ICryptoProvider;
      const AClock: ITlsClock; ALifetimeSeconds: UInt32): ISessionTicketKeyManager; static;
    /// <summary>A manager with a fresh current key and an AWindowSize decrypt window (a default
    /// applies when 0 or less). Never auto-rotates.</summary>
    constructor Create(const ARandom: IRandom); overload;
    constructor Create(const ARandom: IRandom; AWindowSize: Int32); overload;
    /// <summary>As above, plus time-based auto-rotation: a fresh current key is promoted once
    /// ARotateIntervalSeconds elapse on AClock (lazily, on the encrypt path - no timers), and a key
    /// is retired once it ages past AWindowSize intervals on either the seal or the open path.
    /// AMaxSealsPerKey caps how many tickets one key may seal before it rotates (a default applies
    /// when 0).</summary>
    constructor Create(const ARandom: IRandom; AWindowSize: Int32;
      const AClock: ITlsClock; ARotateIntervalSeconds: UInt32); overload;
    constructor Create(const ARandom: IRandom; AWindowSize: Int32;
      const AClock: ITlsClock; ARotateIntervalSeconds: UInt32;
      AMaxSealsPerKey: UInt32); overload;
    procedure Rotate;
  end;

  /// <summary>
  /// The <see cref="IFleetTicketKeyManager" /> for a shared-key fleet: it mints NO key of its own,
  /// so nothing is sealed under a key the fleet cannot open and no local key lingers in the decrypt
  /// window. It seals nothing (CurrentKey is False) until InstallKey supplies the shared STEK, and
  /// never mints, auto-rotates or time-retires - the fleet coordinates rotation out of band and
  /// pushes old keys out of the window by installing newer ones.
  /// </summary>
  TFleetTicketKeyManager = class sealed(TStekKeyRingBase, IFleetTicketKeyManager)
  strict protected
    function PrepareCurrentLocked: Boolean; override;
  public
    /// <summary>The parameterless form uses the default decrypt window; AWindowSize bounds how many
    /// installed keys stay accepted for decrypt (a default applies when 0 or less).</summary>
    constructor Create; overload;
    constructor Create(AWindowSize: Int32); overload;
    /// <summary>As above, with AMaxSealsPerKey capping how many tickets the current key may seal
    /// before sealing stops (a default applies when 0).</summary>
    constructor Create(AWindowSize: Int32; AMaxSealsPerKey: UInt32); overload;
    /// <summary>Installs a key as the current one (e.g. a shared STEK across a server fleet); it
    /// also enters the decrypt window. The name and key must be the manager's fixed lengths
    /// (KeyNameLength / an AES-256 key) or this raises.</summary>
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

{ TStekKeyRingBase }

constructor TStekKeyRingBase.CreateRing(AWindowSize: Int32; const AClock: ITlsClock;
  AAgeBoundMillis: UInt64; AMaxSealsPerKey: UInt32);
begin
  inherited Create;
  if AWindowSize > 0 then
    FWindow := AWindowSize
  else
    FWindow := DefaultDecryptWindow;
  FClock := AClock;
  FAgeBoundMillis := AAgeBoundMillis;
  if AMaxSealsPerKey > 0 then
    FMaxSealsPerKey := AMaxSealsPerKey
  else
    FMaxSealsPerKey := MaxSealsPerKeyDefault;
  FKeys := TList<TStekKey>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TStekKeyRingBase.Destroy;
begin
  FKeys.Free;
  FLock.Free;
  inherited Destroy;
end;

function TStekKeyRingBase.StampNow: UInt64;
begin
  if FClock <> nil then
    Result := FClock.NowUnixMillis
  else
    Result := 0;
end;

function TStekKeyRingBase.AddKeyLocked(const AName: TBytes; const AKey: ISecretBuffer): UInt64;
var
  LEntry: TStekKey;
begin
  LEntry.Name := AName;
  LEntry.Key := AKey;
  LEntry.CreatedAt := StampNow;
  LEntry.Seals := 0;
  FKeys.Add(LEntry);
  while FKeys.Count > FWindow do
    FKeys.Delete(0);
  Result := LEntry.CreatedAt;
end;

procedure TStekKeyRingBase.PruneExpiredLocked;
var
  LNow: UInt64;
begin
  if (FClock = nil) or (FAgeBoundMillis = 0) then
    Exit;
  LNow := FClock.NowUnixMillis;
  // the oldest keys are at the front; compare by subtraction (guarded against a backwards clock
  // step) so a large age bound cannot wrap the sum and prune every key at once
  while (FKeys.Count > 0) and (LNow >= FKeys[0].CreatedAt) and
    (LNow - FKeys[0].CreatedAt >= FAgeBoundMillis) do
    FKeys.Delete(0);
end;

function TStekKeyRingBase.CurrentKey(out AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
var
  LEntry: TStekKey;
begin
  AKeyName := nil;
  AKey := nil;
  FLock.Enter;
  try
    Result := PrepareCurrentLocked;
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

function TStekKeyRingBase.KeyByName(const AKeyName: TBytes;
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

function TStekKeyRingBase.KeyNameLength: Int32;
begin
  Result := StekKeyNameLength;
end;

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

constructor TStekTicketKeyManager.Create(const ARandom: IRandom);
begin
  Create(ARandom, 0);
end;

constructor TStekTicketKeyManager.Create(const ARandom: IRandom;
  AWindowSize: Int32);
begin
  Create(ARandom, AWindowSize, nil, 0);
end;

constructor TStekTicketKeyManager.Create(const ARandom: IRandom;
  AWindowSize: Int32; const AClock: ITlsClock; ARotateIntervalSeconds: UInt32);
begin
  Create(ARandom, AWindowSize, AClock, ARotateIntervalSeconds, 0);
end;

constructor TStekTicketKeyManager.Create(const ARandom: IRandom;
  AWindowSize: Int32; const AClock: ITlsClock; ARotateIntervalSeconds: UInt32;
  AMaxSealsPerKey: UInt32);
begin
  CreateRing(AWindowSize, AClock, AgeBoundFor(AWindowSize, ARotateIntervalSeconds),
    AMaxSealsPerKey);
  FRandom := ARandom;
  FRotateIntervalMillis := UInt64(ARotateIntervalSeconds) * 1000;
  Rotate; // start with one fresh current key (which also schedules the first timed rotation)
end;

class function TStekTicketKeyManager.AgeBoundFor(AWindowSize: Int32;
  ARotateIntervalSeconds: UInt32): UInt64;
var
  LWindow: UInt64;
  LIntervalMillis: UInt64;
begin
  if AWindowSize > 0 then
    LWindow := UInt64(AWindowSize)
  else
    LWindow := UInt64(DefaultDecryptWindow);
  LIntervalMillis := UInt64(ARotateIntervalSeconds) * 1000;
  // window x interval; an extreme caller-supplied product that would wrap becomes the "never" bound
  // (the subtraction compare can never reach High(UInt64)), rather than a wrapped small residue
  if (LIntervalMillis > 0) and (LWindow > High(UInt64) div LIntervalMillis) then
    Result := High(UInt64)
  else
    Result := LWindow * LIntervalMillis;
end;

function TStekTicketKeyManager.PrepareCurrentLocked: Boolean;
begin
  PruneExpiredLocked;
  MaybeRotateLocked;
  // rotate before the current key overuses its nonce space
  if (FKeys.Count > 0) and (FKeys[FKeys.Count - 1].Seals >= FMaxSealsPerKey) then
    RotateLocked;
  // guards a clock that stepped back between the compare and the stamp: re-mint so the server
  // keeps issuing tickets rather than going dark
  if FKeys.Count = 0 then
    RotateLocked;
  Result := FKeys.Count > 0;
end;

procedure TStekTicketKeyManager.RotateLocked;
var
  LName, LRaw: TBytes;
  LCreatedAt: UInt64;
begin
  LName := FRandom.GenerateBytes(StekKeyNameLength);
  // wrap the fresh key material in the secret buffer (which copies it), then wipe the
  // transient plaintext TBytes so the raw key does not linger on the heap
  LRaw := FRandom.GenerateBytes(StekKeyLength);
  try
    LCreatedAt := AddKeyLocked(LName, TSecretBuffer.From(LRaw));
  finally
    TSecureMemory.WipeBytes(LRaw);
  end;
  // schedule the next timed rotation from this key's birth, so an out-of-schedule rotation (a seal
  // cap or an explicit Rotate) does not leave the timer poised to evict a key while its tickets live
  if (FClock <> nil) and (FRotateIntervalMillis > 0) then
    FNextRotateMillis := LCreatedAt + FRotateIntervalMillis;
end;

procedure TStekTicketKeyManager.MaybeRotateLocked;
begin
  if (FClock = nil) or (FRotateIntervalMillis = 0) then
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

{ TFleetTicketKeyManager }

constructor TFleetTicketKeyManager.Create;
begin
  Create(0);
end;

constructor TFleetTicketKeyManager.Create(AWindowSize: Int32);
begin
  Create(AWindowSize, 0);
end;

constructor TFleetTicketKeyManager.Create(AWindowSize: Int32; AMaxSealsPerKey: UInt32);
begin
  CreateRing(AWindowSize, nil, 0, AMaxSealsPerKey);
end;

function TFleetTicketKeyManager.PrepareCurrentLocked: Boolean;
begin
  // an exhausted installed key is the operator's to replace, so it stops sealing rather than
  // being silently reminted
  Result := (FKeys.Count > 0) and (FKeys[FKeys.Count - 1].Seals < FMaxSealsPerKey);
end;

procedure TFleetTicketKeyManager.InstallKey(const AName: TBytes;
  const AKey: ISecretBuffer);
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
  FLock.Enter;
  try
    AddKeyLocked(System.Copy(AName, 0, System.Length(AName)), AKey);
  finally
    FLock.Leave;
  end;
end;

end.
