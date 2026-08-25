{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SessionStoreTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpCryptoAlgorithms,
  TlpTlsVersion,
  TlpIClock,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpISession,
  TlpSession,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlsLibTestBase;

type
  TTestSessionStore = class(TTlsLibAlgorithmTestCase)
  private
    function MakeSession(const ATag: TBytes): IResumableSession;
    function MakeTls12Session(const ATag: TBytes): IResumableSession;
    function Tag(AValue: Byte; ALength: Int32): TBytes;
  published
    procedure TestCacheStoreAndTakeSingleUse;
    procedure TestCacheKeyedByServerAndSni;
    procedure TestCacheBoundedEviction;
    procedure TestCachePrefersTls13OverTls12;
    procedure TestKxHintRoundTripsAndIsKeyed;
    procedure TestStorePutTakeSingleUse;
    procedure TestStorePutWithId;
    procedure TestStoreBoundedEviction;
    procedure TestStoreCompactionPreservesLiveEntriesUnderChurn;
    procedure TestStekCurrentAndLookup;
    procedure TestStekRotationChangesCurrent;
    procedure TestStekWindowRetiresOldKeys;
    procedure TestStekInstallKey;
    procedure TestStekAutoRotatesOnInterval;
    procedure TestAntiReplayDetectsReplay;
    procedure TestAntiReplayFreshAfterExpiry;
    procedure TestAntiReplayRejectsEmpty;
    procedure TestAntiReplayBounded;
  end;

implementation

type
  // a clock the test advances by hand, to drive STEK auto-rotation deterministically
  TAdjustableClock = class sealed(TInterfacedObject, ITlsClock)
  strict private
    FNowMillis: UInt64;
  public
    constructor Create(AStartMillis: UInt64);
    function NowUnixMillis: UInt64;
    procedure Advance(AMillis: UInt64);
  end;

constructor TAdjustableClock.Create(AStartMillis: UInt64);
begin
  inherited Create;
  FNowMillis := AStartMillis;
end;

function TAdjustableClock.NowUnixMillis: UInt64;
begin
  Result := FNowMillis;
end;

procedure TAdjustableClock.Advance(AMillis: UInt64);
begin
  Inc(FNowMillis, AMillis);
end;

{ TTestSessionStore }

function TTestSessionStore.Tag(AValue: Byte; ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  if ALength > 0 then
    FillChar(Result[0], ALength, AValue);
end;

function TTestSessionStore.MakeSession(const ATag: TBytes): IResumableSession;
begin
  Result := TResumableSession.CreateTls13($1301, THashAlgorithm.SHA_256,
    TSecretBuffer.From(ATag), $001D, '', '', ATag, 7200, 0, 0, 0);
end;

function TTestSessionStore.MakeTls12Session(const ATag: TBytes): IResumableSession;
begin
  Result := TResumableSession.CreateTls12($C02B, THashAlgorithm.SHA_256,
    TSecretBuffer.From(ATag), ATag, ATag, True, '', '', 7200, 0, 0);
end;

procedure TTestSessionStore.TestCacheStoreAndTakeSingleUse;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LCache.Store('example.com:443', 'example.com', MakeSession(Tag($11, 4)));
  CheckTrue(LCache.Take('example.com:443', 'example.com', LTaken),
    'a stored session is retrievable');
  CheckEqualBytes('the same session comes back', Tag($11, 4), LTaken.TicketIdentity);
  CheckFalse(LCache.Take('example.com:443', 'example.com', LTaken),
    'retrieval is single-use');
end;

procedure TTestSessionStore.TestCacheKeyedByServerAndSni;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LCache.Store('host:443', 'a.example', MakeSession(Tag($01, 4)));
  LCache.Store('host:443', 'b.example', MakeSession(Tag($02, 4)));
  CheckFalse(LCache.Take('host:443', 'c.example', LTaken),
    'a different SNI does not match');
  CheckTrue(LCache.Take('host:443', 'b.example', LTaken), 'the b.example entry resumes');
  CheckEqualBytes('and is the right one', Tag($02, 4), LTaken.TicketIdentity);
end;

procedure TTestSessionStore.TestCacheBoundedEviction;
var
  LCache: ISessionCache;
  LI: Int32;
begin
  LCache := TInMemorySessionCache.Create(2);
  for LI := 0 to 4 do
    LCache.Store('host:443', 'x.example', MakeSession(Tag(Byte(LI), 4)));
  CheckEquals(2, LCache.Count, 'the cache never grows past its cap');
end;

procedure TTestSessionStore.TestCachePrefersTls13OverTls12;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  // store the 1.3 session first, then a newer 1.2 one: preference must beat recency so a
  // dual-version client resumes at 1.3 rather than downgrading
  LCache.Store('host:443', 'x.example', MakeSession(Tag($13, 4)));
  LCache.Store('host:443', 'x.example', MakeTls12Session(Tag($12, 4)));
  CheckTrue(LCache.Take('host:443', 'x.example', LTaken), 'a session is retrievable');
  CheckEquals(TlsWireVersionTls13, LTaken.Version.WireValue,
    'the 1.3 session is preferred over the 1.2 one');
  CheckTrue(LCache.Take('host:443', 'x.example', LTaken), 'the 1.2 session remains');
  CheckEquals(TlsWireVersionTls12, LTaken.Version.WireValue,
    'and is returned once the 1.3 one is consumed');
end;

procedure TTestSessionStore.TestKxHintRoundTripsAndIsKeyed;
var
  LCache: ISessionCache;
begin
  LCache := TInMemorySessionCache.Create;
  CheckEquals(0, LCache.KxHint('host:443', 'x.example'), 'no hint is known initially');
  LCache.SetKxHint('host:443', 'x.example', $001D);
  CheckEquals($001D, LCache.KxHint('host:443', 'x.example'), 'the hint round-trips');
  CheckEquals(0, LCache.KxHint('host:443', 'other.example'),
    'the hint is keyed by server and SNI');
end;

procedure TTestSessionStore.TestStorePutTakeSingleUse;
var
  LStore: ISessionStore;
  LHandle: TBytes;
  LTaken: IResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom);
  LHandle := LStore.Put(MakeSession(Tag($22, 8)));
  CheckTrue(System.Length(LHandle) > 0, 'Put returns an opaque handle');
  CheckTrue(LStore.Take(LHandle, LTaken), 'the handle resolves');
  CheckEqualBytes('to the stored session', Tag($22, 8), LTaken.TicketIdentity);
  CheckFalse(LStore.Take(LHandle, LTaken), 'a stored session is single-use');
end;

procedure TTestSessionStore.TestStorePutWithId;
var
  LStore: ISessionStore;
  LId: TBytes;
  LTaken: IResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom);
  LId := Tag($33, 32);
  LStore.PutWithId(LId, MakeSession(Tag($44, 4)));
  CheckTrue(LStore.Take(LId, LTaken), 'a caller-chosen id resolves');
  CheckEqualBytes('to the stored session', Tag($44, 4), LTaken.TicketIdentity);
end;

procedure TTestSessionStore.TestStoreBoundedEviction;
var
  LStore: ISessionStore;
  LI: Int32;
begin
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom, 3);
  for LI := 0 to 9 do
    LStore.Put(MakeSession(Tag(Byte(LI), 4)));
  CheckEquals(3, LStore.Count, 'the store never grows past its cap');
end;

procedure TTestSessionStore.TestStoreCompactionPreservesLiveEntriesUnderChurn;
var
  LStore: ISessionStore;
  LLive: array [0 .. 4] of TBytes;
  LI: Int32;
  LHandle: TBytes;
  LTaken: IResumableSession;
begin
  // issue+consume far more tickets than capacity to drive the store's internal ordering
  // structure past its compaction threshold many times (FIX: single-use consumption keeps
  // the live count tiny, so ordinary eviction rarely fires and the order structure must be
  // compacted instead of accumulating one dead entry per ticket, RFC 8446 18.6).
  // Compaction must preserve still-live entries and single-use semantics.
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom, 8);
  for LI := 0 to 4 do
    LLive[LI] := LStore.Put(MakeSession(Tag(Byte($A0 + LI), 8)));
  for LI := 0 to 999 do
  begin
    LHandle := LStore.Put(MakeSession(Tag($55, 4)));
    CheckTrue(LStore.Take(LHandle, LTaken), 'each churned ticket is single-use retrievable');
  end;
  // the five long-lived sessions survived every compaction and remain retrievable intact
  for LI := 0 to 4 do
  begin
    CheckTrue(LStore.Take(LLive[LI], LTaken), 'a live session survives repeated compaction');
    CheckEqualBytes('with its identity intact', Tag(Byte($A0 + LI), 8),
      LTaken.TicketIdentity);
  end;
  CheckEquals(0, LStore.Count, 'all sessions were consumed');
end;

procedure TTestSessionStore.TestStekCurrentAndLookup;
var
  LStek: ISessionTicketKeyManager;
  LName: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LStek := TStekTicketKeyManager.Create(Provider.Primitives.GetRandom);
  CheckTrue(LStek.CurrentKey(LName, LKey), 'a fresh manager has a current key');
  CheckEquals(LStek.KeyNameLength, System.Length(LName), 'the key name is fixed length');
  CheckTrue(LStek.KeyByName(LName, LFound), 'the current key is found by name');
  CheckTrue(LKey.ConstantTimeAreEqual(LFound), 'and it is the same key');
end;

procedure TTestSessionStore.TestStekRotationChangesCurrent;
var
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey: ISecretBuffer;
  LOld: ISecretBuffer;
begin
  LStek := TStekTicketKeyManager.Create(Provider.Primitives.GetRandom);
  LStek.CurrentKey(LName1, LKey);
  LStek.Rotate;
  LStek.CurrentKey(LName2, LKey);
  CheckFalse(AreEqual(LName1, LName2), 'rotation promotes a fresh current key');
  CheckTrue(LStek.KeyByName(LName1, LOld),
    'the prior key still opens tickets within the window');
end;

procedure TTestSessionStore.TestStekWindowRetiresOldKeys;
var
  LStek: ISessionTicketKeyManager;
  LName, LFirst: TBytes;
  LKey, LFound: ISecretBuffer;
  LI: Int32;
begin
  LStek := TStekTicketKeyManager.Create(Provider.Primitives.GetRandom, 2);
  LStek.CurrentKey(LFirst, LKey);
  for LI := 0 to 2 do
    LStek.Rotate; // push the first key out of a 2-wide window
  CheckFalse(LStek.KeyByName(LFirst, LFound), 'a retired key is no longer accepted');
  LStek.CurrentKey(LName, LKey);
  CheckTrue(LStek.KeyByName(LName, LFound), 'the current key still opens tickets');
end;

procedure TTestSessionStore.TestStekInstallKey;
var
  LStek: ISessionTicketKeyManager;
  LConcrete: TStekTicketKeyManager;
  LName: TBytes;
  LKey, LCurrent: ISecretBuffer;
begin
  LConcrete := TStekTicketKeyManager.Create(Provider.Primitives.GetRandom);
  LStek := LConcrete; // the interface reference governs lifetime
  LName := Tag($55, 16);
  LKey := TSecretBuffer.From(Tag($66, 32));
  LConcrete.InstallKey(LName, LKey);
  LStek.CurrentKey(LName, LCurrent);
  CheckTrue(LKey.ConstantTimeAreEqual(LCurrent),
    'an installed key becomes the current key');
end;

procedure TTestSessionStore.TestStekAutoRotatesOnInterval;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2, LName3: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj; // the interface reference governs lifetime
  // a 10-second auto-rotation interval driven by the injected clock
  LStek := TStekTicketKeyManager.Create(Provider.Primitives.GetRandom, 0, LClock, 10);
  LStek.CurrentKey(LName1, LKey);
  LClockObj.Advance(5000); // within the interval: the current key is unchanged
  LStek.CurrentKey(LName2, LKey);
  CheckTrue(AreEqual(LName1, LName2), 'no rotation before the interval elapses');
  LClockObj.Advance(6000); // past the interval: a fresh current key is promoted
  LStek.CurrentKey(LName3, LKey);
  CheckFalse(AreEqual(LName1, LName3), 'the elapsed interval rotates the current key');
  CheckTrue(LStek.KeyByName(LName1, LFound),
    'the rotated-out key still opens tickets within the decrypt window');
end;

procedure TTestSessionStore.TestAntiReplayDetectsReplay;
var
  LReplay: IAntiReplayStrategy;
  LValue: TBytes;
begin
  LReplay := TStrikeRegisterAntiReplay.Create;
  LValue := Tag($77, 32);
  CheckTrue(LReplay.CheckAndRecord(LValue, 1000, 5000),
    'a first-seen value is accepted');
  CheckFalse(LReplay.CheckAndRecord(LValue, 1001, 5000),
    'the same value while live is a replay');
end;

procedure TTestSessionStore.TestAntiReplayFreshAfterExpiry;
var
  LReplay: IAntiReplayStrategy;
  LValue: TBytes;
begin
  LReplay := TStrikeRegisterAntiReplay.Create;
  LValue := Tag($88, 32);
  CheckTrue(LReplay.CheckAndRecord(LValue, 1000, 5000), 'accepted at first');
  CheckTrue(LReplay.CheckAndRecord(LValue, 6000, 9000),
    'accepted again once the prior entry expired');
end;

procedure TTestSessionStore.TestAntiReplayRejectsEmpty;
var
  LReplay: IAntiReplayStrategy;
begin
  LReplay := TStrikeRegisterAntiReplay.Create;
  CheckFalse(LReplay.CheckAndRecord(nil, 1000, 5000),
    'an empty unique value cannot anchor replay protection');
end;

procedure TTestSessionStore.TestAntiReplayBounded;
var
  LReplay: IAntiReplayStrategy;
  LI: Int32;
begin
  LReplay := TStrikeRegisterAntiReplay.Create(4);
  for LI := 0 to 19 do
    LReplay.CheckAndRecord(Tag(Byte(LI), 8), 1000, 100000);
  CheckTrue(LReplay.Count <= 4, 'the strike register never grows past its cap');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSessionStore);
{$ELSE}
  RegisterTest(TTestSessionStore.Suite);
{$ENDIF FPC}

end.
