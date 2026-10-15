{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockSessionStores;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpArrayUtilities,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpISession;

type
  /// <summary>Runs inside the engine's synchronous Store or Take callback.</summary>
  TSessionCacheEvent = procedure of object;

  /// <summary>
  /// A minimal, user-authored <see cref="ISessionCache" />: it shows that the seam
  /// accepts any implementation, not only the shipped TInMemorySessionCache. Holds a
  /// single entry and counts the calls the engine makes, so a test can assert the
  /// engine actually consulted it.
  /// </summary>
  TMockSessionCache = class sealed(TInterfacedObject, ISessionCache)
  strict private
    FKey: string;
    FSession: IResumableSession;
    FHasEntry: Boolean;
    FTakeCount: Int32;
    FKxHint: UInt16;
    FOnStored: TSessionCacheEvent;
    FOnTake: TSessionCacheEvent;
  public
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
    property TakeCount: Int32 read FTakeCount;
    property OnStored: TSessionCacheEvent read FOnStored write FOnStored;
    property OnTake: TSessionCacheEvent read FOnTake write FOnTake;
  end;

  /// <summary>A cache over an inner cache whose first Remove raises, to show one failing removal
  /// does not keep the engine from withdrawing the rest.</summary>
  TFlakyRemoveSessionCache = class sealed(TInterfacedObject, ISessionCache)
  strict private
    FInner: ISessionCache;
    FFailed: Boolean;
  public
    constructor Create(const AInner: ISessionCache);
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

  /// <summary>
  /// A minimal, user-authored <see cref="ISessionStore" />: a plain list keyed by an
  /// opaque handle, counting the Take calls the engine makes.
  /// </summary>
  TMockSessionStore = class sealed(TInterfacedObject, ISessionStore)
  strict private
    FIds: TArray<TBytes>;
    FSessions: TArray<IResumableSession>;
    FNextHandle: Byte;
    FTakeCount: Int32;
    function IndexOf(const AId: TBytes): Int32;
    procedure RemoveAt(AIndex: Int32);
  public
    function Put(const ASession: IResumableSession): TBytes;
    procedure PutWithId(const AId: TBytes; const ASession: IResumableSession);
    function Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
    function Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
    procedure Remove(const AId: TBytes);
    procedure Clear;
    function Count: Int32;
    property TakeCount: Int32 read FTakeCount;
  end;

  /// <summary>A server-side session store that issues tickets of a fixed length, as a foreign
  /// server with an unbounded ticket would; it holds nothing and resumes nothing.</summary>
  TFixedLengthTicketStore = class sealed(TInterfacedObject, ISessionStore)
  strict private
  var
    FTicketLength: Int32;
    FPuts: Int32;
  public
    constructor Create(ATicketLength: Int32);
    /// <summary>How many tickets the server asked this store to mint.</summary>
    property Puts: Int32 read FPuts;
    function Put(const ASession: IResumableSession): TBytes;
    procedure PutWithId(const AId: TBytes; const ASession: IResumableSession);
    function Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
    function Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
    procedure Remove(const AId: TBytes);
    procedure Clear;
    function Count: Int32;
  end;

  /// <summary>A ticket-key manager whose key name is ANameLength bytes: a nil ASealKey declines
  /// to seal, a nil AOpenKey finds no key by name.</summary>
  TScriptedTicketKeys = class sealed(TInterfacedObject, ISessionTicketKeyManager)
  strict private
  var
    FNameLength: Int32;
    FSealKey: TBytes;
    FOpenKey: TBytes;
    FSeals: Int32;
  public
    constructor Create(ANameLength: Int32; const ASealKey, AOpenKey: TBytes);
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyNameLength: Int32;
    /// <summary>How many times the server asked for a sealing key.</summary>
    property Seals: Int32 read FSeals;
  end;

  /// <summary>A ticket-key manager that opens AInner's tickets but never seals (no renewal).</summary>
  TOpenOnlyTicketKeys = class sealed(TInterfacedObject, ISessionTicketKeyManager)
  strict private
    FInner: ISessionTicketKeyManager;
  public
    constructor Create(const AInner: ISessionTicketKeyManager);
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyNameLength: Int32;
  end;

implementation

{ TFlakyRemoveSessionCache }

constructor TFlakyRemoveSessionCache.Create(const AInner: ISessionCache);
begin
  inherited Create;
  FInner := AInner;
end;

procedure TFlakyRemoveSessionCache.Store(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
  FInner.Store(AServerIdentity, AServerName, ASession);
end;

procedure TFlakyRemoveSessionCache.Remove(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
  if not FFailed then
  begin
    FFailed := True;
    raise Exception.Create('the cache failed to remove a session');
  end;
  FInner.Remove(AServerIdentity, AServerName, ASession);
end;

function TFlakyRemoveSessionCache.Take(const AServerIdentity, AServerName: string;
  ANowMillis: UInt64; out ASession: IResumableSession): Boolean;
begin
  Result := FInner.Take(AServerIdentity, AServerName, ANowMillis, ASession);
end;

procedure TFlakyRemoveSessionCache.SetKxHint(const AServerIdentity, AServerName: string;
  AGroup: UInt16);
begin
  FInner.SetKxHint(AServerIdentity, AServerName, AGroup);
end;

function TFlakyRemoveSessionCache.KxHint(const AServerIdentity, AServerName: string): UInt16;
begin
  Result := FInner.KxHint(AServerIdentity, AServerName);
end;

procedure TFlakyRemoveSessionCache.Clear;
begin
  FInner.Clear;
end;

function TFlakyRemoveSessionCache.Count: Int32;
begin
  Result := FInner.Count;
end;

{ TMockSessionCache }

procedure TMockSessionCache.Store(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
  FKey := AServerIdentity + '|' + AServerName;
  FSession := ASession;
  FHasEntry := True;
  if Assigned(FOnStored) then
    FOnStored;
end;

procedure TMockSessionCache.Remove(const AServerIdentity, AServerName: string;
  const ASession: IResumableSession);
begin
  if FHasEntry and (FKey = AServerIdentity + '|' + AServerName) and (FSession = ASession) then
  begin
    FSession := nil;
    FHasEntry := False;
  end;
end;

function TMockSessionCache.Take(const AServerIdentity, AServerName: string;
  ANowMillis: UInt64; out ASession: IResumableSession): Boolean;
begin
  if Assigned(FOnTake) then
    FOnTake;
  ASession := nil;
  Result := FHasEntry and (FKey = AServerIdentity + '|' + AServerName);
  if Result then
  begin
    Inc(FTakeCount);
    ASession := FSession;
    FSession := nil;
    FHasEntry := False;
  end;
end;

procedure TMockSessionCache.SetKxHint(const AServerIdentity, AServerName: string;
  AGroup: UInt16);
begin
  FKxHint := AGroup;
end;

function TMockSessionCache.KxHint(const AServerIdentity,
  AServerName: string): UInt16;
begin
  Result := FKxHint;
end;

procedure TMockSessionCache.Clear;
begin
  FSession := nil;
  FHasEntry := False;
  FKxHint := 0;
end;

function TMockSessionCache.Count: Int32;
begin
  if FHasEntry then
    Result := 1
  else
    Result := 0;
end;

{ TMockSessionStore }

function TMockSessionStore.IndexOf(const AId: TBytes): Int32;
var
  LI: Int32;
begin
  Result := -1;
  for LI := 0 to System.Length(FIds) - 1 do
    if TArrayUtilities.AreEqual(FIds[LI], AId) then
      Exit(LI);
end;

procedure TMockSessionStore.RemoveAt(AIndex: Int32);
var
  LI: Int32;
begin
  for LI := AIndex to System.Length(FIds) - 2 do
  begin
    FIds[LI] := FIds[LI + 1];
    FSessions[LI] := FSessions[LI + 1];
  end;
  SetLength(FIds, System.Length(FIds) - 1);
  SetLength(FSessions, System.Length(FSessions) - 1);
end;

function TMockSessionStore.Put(const ASession: IResumableSession): TBytes;
begin
  Inc(FNextHandle);
  Result := TBytes.Create(FNextHandle, $DE, $AD, $01);
  PutWithId(Result, ASession);
end;

procedure TMockSessionStore.PutWithId(const AId: TBytes;
  const ASession: IResumableSession);
begin
  TArrayUtilities.Append<TBytes>(FIds, System.Copy(AId, 0, System.Length(AId)));
  TArrayUtilities.Append<IResumableSession>(FSessions, ASession);
end;

function TMockSessionStore.Peek(const AId: TBytes;
  out ASession: IResumableSession): Boolean;
var
  LIndex: Int32;
begin
  ASession := nil;
  LIndex := IndexOf(AId);
  Result := LIndex >= 0;
  if Result then
    ASession := FSessions[LIndex];
end;

function TMockSessionStore.Take(const AId: TBytes;
  out ASession: IResumableSession): Boolean;
var
  LIndex: Int32;
begin
  ASession := nil;
  LIndex := IndexOf(AId);
  Result := LIndex >= 0;
  if Result then
  begin
    Inc(FTakeCount);
    ASession := FSessions[LIndex];
    RemoveAt(LIndex);
  end;
end;

procedure TMockSessionStore.Remove(const AId: TBytes);
var
  LIndex: Int32;
begin
  LIndex := IndexOf(AId);
  if LIndex >= 0 then
    RemoveAt(LIndex);
end;

procedure TMockSessionStore.Clear;
begin
  FIds := nil;
  FSessions := nil;
end;

function TMockSessionStore.Count: Int32;
begin
  Result := System.Length(FIds);
end;

{ TFixedLengthTicketStore }

constructor TFixedLengthTicketStore.Create(ATicketLength: Int32);
begin
  inherited Create;
  FTicketLength := ATicketLength;
end;

function TFixedLengthTicketStore.Put(const ASession: IResumableSession): TBytes;
begin
  Inc(FPuts);
  Result := nil;
  System.SetLength(Result, FTicketLength);
end;

procedure TFixedLengthTicketStore.PutWithId(const AId: TBytes; const ASession: IResumableSession);
begin
end;

function TFixedLengthTicketStore.Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
begin
  ASession := nil;
  Result := False;
end;

function TFixedLengthTicketStore.Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
begin
  ASession := nil;
  Result := False;
end;

procedure TFixedLengthTicketStore.Remove(const AId: TBytes);
begin
end;

procedure TFixedLengthTicketStore.Clear;
begin
end;

function TFixedLengthTicketStore.Count: Int32;
begin
  Result := 0;
end;

{ TScriptedTicketKeys }

constructor TScriptedTicketKeys.Create(ANameLength: Int32; const ASealKey, AOpenKey: TBytes);
begin
  inherited Create;
  FNameLength := ANameLength;
  FSealKey := ASealKey;
  FOpenKey := AOpenKey;
end;

function TScriptedTicketKeys.CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
begin
  Inc(FSeals);
  AKeyName := nil;
  AKey := nil;
  Result := FSealKey <> nil;
  if Result then
  begin
    System.SetLength(AKeyName, FNameLength);
    AKey := TSecretBuffer.From(FSealKey);
  end;
end;

function TScriptedTicketKeys.KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
begin
  AKey := nil;
  Result := FOpenKey <> nil;
  if Result then
    AKey := TSecretBuffer.From(FOpenKey);
end;

function TScriptedTicketKeys.KeyNameLength: Int32;
begin
  Result := FNameLength;
end;

{ TOpenOnlyTicketKeys }

constructor TOpenOnlyTicketKeys.Create(const AInner: ISessionTicketKeyManager);
begin
  inherited Create;
  FInner := AInner;
end;

function TOpenOnlyTicketKeys.CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
begin
  AKeyName := nil;
  AKey := nil;
  Result := False;
end;

function TOpenOnlyTicketKeys.KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
begin
  Result := FInner.KeyByName(AKeyName, AKey);
end;

function TOpenOnlyTicketKeys.KeyNameLength: Int32;
begin
  Result := FInner.KeyNameLength;
end;

end.
