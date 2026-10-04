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
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpIClock,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpISession,
  TlpSession,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpSessionTicketStrategy,
  TlpAntiReplay,
  TlpTlsLibExceptions,
  TlsLibTestBase;

type
  TTestSessionStore = class(TTlsLibAlgorithmTestCase)
  private
    function MakeSession(const ATag: TBytes): IResumableSession; overload;
    function MakeSession(const ATag: TBytes; ALifetime: UInt32;
      AIssuedMillis: UInt64): IResumableSession; overload;
    function MakeTls12Session(const ATag: TBytes): IResumableSession; overload;
    function MakeTls12Session(const ATag: TBytes; ALifetime: UInt32;
      AIssuedMillis: UInt64): IResumableSession; overload;
    function Tag(AValue: Byte; ALength: Int32): TBytes;
  published
    procedure TestCacheStoreAndTakeSingleUse;
    procedure TestCacheKeyedByServerAndSni;
    procedure TestCacheBoundedEviction;
    procedure TestCachePrefersTls13OverTls12;
    procedure TestCacheExpiredHeadDoesNotShadowLiveTicket;
    procedure TestCacheExpiredTls13FallsBackToLiveTls12;
    procedure TestCacheTls12ZeroLifetimeNeverExpires;
    procedure TestCacheExpiryIsInclusiveAtLifetimeBoundary;
    procedure TestKxHintRoundTripsAndIsKeyed;
    procedure TestKxHintBounded;
    procedure TestStorePutTakeSingleUse;
    procedure TestStorePutWithId;
    procedure TestStoreBoundedEviction;
    procedure TestStoreCompactionPreservesLiveEntriesUnderChurn;
    procedure TestStekCurrentAndLookup;
    procedure TestStekRotationChangesCurrent;
    procedure TestStekWindowRetiresOldKeys;
    procedure TestStekInstallKey;
    procedure TestStekFleetMintsNothingUntilInstall;
    procedure TestStekAutoRotatesOnInterval;
    procedure TestStekOpenPathRetiresExpiredKey;
    procedure TestStekCurrentKeyRecoversAfterFullExpiry;
    procedure TestStekManualManagerNeverExpires;
    procedure TestStekSealCapRotates;
    procedure TestStekSealCapInFleetModeStopsSealing;
    procedure TestStekCreateDefaultRotatesOnLifetime;
    procedure TestStekCreateDefaultZeroLifetimeStillRotates;
    procedure TestStekInstallKeyRejectsBadNameLength;
    procedure TestStekInstallKeyRejectsBadKeyLength;
    procedure TestStekInstallKeyRejectsNilKey;
    procedure TestStekInstallKeyDisablesAutoRotation;
    procedure TestStekInstalledKeyDoesNotTimeExpire;
    procedure TestStekRotateDoesNotShortenTimer;
    procedure TestStekBackwardsClockDoesNotExpireOrRaise;
    procedure TestStekOpenWithUnbindableKeyFallsBack;
    procedure TestStekSealOpenRoundTripTls13;
    procedure TestStekSealOpenRoundTripTls12;
    procedure TestStekSealDeclinesBaseOnlySession;
    procedure TestAntiReplayDetectsReplay;
    procedure TestAntiReplayFreshAfterExpiry;
    procedure TestAntiReplayRejectsEmpty;
    procedure TestAntiReplayBounded;
    procedure TestAntiReplayReRecordBehindLiveEntryStaysSound;
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
    procedure Retreat(AMillis: UInt64);
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

procedure TAdjustableClock.Retreat(AMillis: UInt64);
begin
  Dec(FNowMillis, AMillis);
end;

type
  // a key manager that hands the open path a wrong-length key, to prove the strategy falls back to
  // a full handshake rather than letting the AEAD Init exception escape
  TBadKeyManager = class sealed(TInterfacedObject, ISessionTicketKeyManager)
  public
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    procedure Rotate;
    function KeyNameLength: Int32;
  end;

function TBadKeyManager.CurrentKey(out AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
begin
  AKeyName := nil;
  AKey := nil;
  Result := False;
end;

function TBadKeyManager.KeyByName(const AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
var
  LRaw: TBytes;
begin
  LRaw := nil;
  SetLength(LRaw, 16); // too short for AES-256-GCM, so Init must reject it
  FillChar(LRaw[0], 16, $AB);
  AKey := TSecretBuffer.From(LRaw);
  Result := True;
end;

procedure TBadKeyManager.Rotate;
begin
end;

function TBadKeyManager.KeyNameLength: Int32;
begin
  Result := 16;
end;

type
  // a session that implements only the version-agnostic base (neither sub-interface), to prove Seal
  // declines to seal one it cannot classify as 1.3 or 1.2
  TBaseOnlySession = class sealed(TInterfacedObject, IResumableSession)
  public
    function Version: TTlsVersion;
    function CipherSuite: UInt16;
    function Hash: THashAlgorithm;
    function Alpn: string;
    function ServerName: string;
    function TicketLifetime: UInt32;
    function IssuedAtMillis: UInt64;
    function PeerCertificates: TArray<TBytes>;
    function ResumptionScope: TBytes;
  end;

function TBaseOnlySession.Version: TTlsVersion;
begin
  Result := TTlsVersion.Tls13;
end;

function TBaseOnlySession.CipherSuite: UInt16;
begin
  Result := 0;
end;

function TBaseOnlySession.Hash: THashAlgorithm;
begin
  Result := THashAlgorithm.SHA_256;
end;

function TBaseOnlySession.Alpn: string;
begin
  Result := '';
end;

function TBaseOnlySession.ServerName: string;
begin
  Result := '';
end;

function TBaseOnlySession.TicketLifetime: UInt32;
begin
  Result := 0;
end;

function TBaseOnlySession.IssuedAtMillis: UInt64;
begin
  Result := 0;
end;

function TBaseOnlySession.PeerCertificates: TArray<TBytes>;
begin
  Result := nil;
end;

function TBaseOnlySession.ResumptionScope: TBytes;
begin
  Result := nil;
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
  Result := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(ATag),
    '', '', ATag, 7200, 0, 0, 0, nil, nil);
end;

function TTestSessionStore.MakeSession(const ATag: TBytes; ALifetime: UInt32;
  AIssuedMillis: UInt64): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(ATag),
    '', '', ATag, ALifetime, 0, AIssuedMillis, 0, nil, nil);
end;

function TTestSessionStore.MakeTls12Session(const ATag: TBytes): IResumableSession;
begin
  Result := TTls12ResumableSession.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    THashAlgorithm.SHA_256,
    TSecretBuffer.From(ATag), ATag, ATag, True, '', '', 7200, 0, nil, nil);
end;

function TTestSessionStore.MakeTls12Session(const ATag: TBytes; ALifetime: UInt32;
  AIssuedMillis: UInt64): IResumableSession;
begin
  Result := TTls12ResumableSession.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    THashAlgorithm.SHA_256,
    TSecretBuffer.From(ATag), ATag, ATag, True, '', '', ALifetime, AIssuedMillis, nil, nil);
end;

procedure TTestSessionStore.TestCacheStoreAndTakeSingleUse;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LCache.Store('example.com:443', 'example.com', MakeSession(Tag($11, 4)));
  CheckTrue(LCache.Take('example.com:443', 'example.com', 0, LTaken),
    'a stored session is retrievable');
  CheckEqualBytes('the same session comes back', Tag($11, 4),
    (LTaken as ITls13ResumableSession).TicketIdentity);
  CheckFalse(LCache.Take('example.com:443', 'example.com', 0, LTaken),
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
  CheckFalse(LCache.Take('host:443', 'c.example', 0, LTaken),
    'a different SNI does not match');
  CheckTrue(LCache.Take('host:443', 'b.example', 0, LTaken), 'the b.example entry resumes');
  CheckEqualBytes('and is the right one', Tag($02, 4),
    (LTaken as ITls13ResumableSession).TicketIdentity);
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
  CheckTrue(LCache.Take('host:443', 'x.example', 0, LTaken), 'a session is retrievable');
  CheckEquals(TlsWireVersionTls13, LTaken.Version.WireValue,
    'the 1.3 session is preferred over the 1.2 one');
  CheckTrue(LCache.Take('host:443', 'x.example', 0, LTaken), 'the 1.2 session remains');
  CheckEquals(TlsWireVersionTls12, LTaken.Version.WireValue,
    'and is returned once the 1.3 one is consumed');
end;

procedure TTestSessionStore.TestCacheExpiredHeadDoesNotShadowLiveTicket;
const
  NowMs = UInt64(1000000000000);
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  // a live 1.3 ticket sits behind a newer-but-expired one; retrieval must drop the stale head
  // and return the live ticket rather than fail resumption
  LCache.Store('host:443', 'x.example', MakeSession(Tag($AA, 4), 7200, NowMs - 1000));
  LCache.Store('host:443', 'x.example', MakeSession(Tag($BB, 4), 100, NowMs - 200000));
  CheckTrue(LCache.Take('host:443', 'x.example', NowMs, LTaken),
    'the live ticket behind the expired head resumes');
  CheckEqualBytes('and it is the live one, not the stale head', Tag($AA, 4),
    (LTaken as ITls13ResumableSession).TicketIdentity);
  CheckEquals(0, LCache.Count, 'both the stale and the taken entry are gone');
end;

procedure TTestSessionStore.TestCacheExpiredTls13FallsBackToLiveTls12;
const
  NowMs = UInt64(1000000000000);
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  // the only 1.3 ticket is expired; retrieval drops it and falls back to a live 1.2 ticket
  LCache.Store('host:443', 'x.example', MakeTls12Session(Tag($12, 4), 7200, NowMs - 1000));
  LCache.Store('host:443', 'x.example', MakeSession(Tag($13, 4), 100, NowMs - 200000));
  CheckTrue(LCache.Take('host:443', 'x.example', NowMs, LTaken),
    'the live 1.2 ticket resumes when the 1.3 one has expired');
  CheckEquals(TlsWireVersionTls12, LTaken.Version.WireValue,
    'the returned session is the live 1.2 one');
  CheckEquals(0, LCache.Count, 'the expired 1.3 entry was dropped too');
end;

procedure TTestSessionStore.TestCacheTls12ZeroLifetimeNeverExpires;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  // a 1.2 lifetime hint of 0 is unspecified, not expired: the cache leaves the age rule to the
  // caller's version policy and never drops it, however far the clock has advanced
  LCache.Store('host:443', 'x.example', MakeTls12Session(Tag($12, 4), 0, 0));
  CheckTrue(LCache.Take('host:443', 'x.example', UInt64(10000000000000), LTaken),
    'a zero-lifetime 1.2 session is not aged out by the cache');
  CheckEquals(TlsWireVersionTls12, LTaken.Version.WireValue, 'and it is the 1.2 session');
end;

procedure TTestSessionStore.TestCacheExpiryIsInclusiveAtLifetimeBoundary;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  // an age exactly equal to lifetime is still live; one millisecond past it is expired
  LCache := TInMemorySessionCache.Create;
  LCache.Store('host:443', 'x.example', MakeSession(Tag($01, 4), 100, 0));
  CheckTrue(LCache.Take('host:443', 'x.example', UInt64(100000), LTaken),
    'a ticket at exactly its lifetime boundary still resumes');

  LCache := TInMemorySessionCache.Create;
  LCache.Store('host:443', 'x.example', MakeSession(Tag($01, 4), 100, 0));
  CheckFalse(LCache.Take('host:443', 'x.example', UInt64(100001), LTaken),
    'a ticket one millisecond past its lifetime is dropped');
  CheckEquals(0, LCache.Count, 'and the expired entry is evicted, not left behind');
end;

procedure TTestSessionStore.TestKxHintRoundTripsAndIsKeyed;
var
  LCache: ISessionCache;
begin
  LCache := TInMemorySessionCache.Create;
  CheckEquals(0, LCache.KxHint('host:443', 'x.example'), 'no hint is known initially');
  LCache.SetKxHint('host:443', 'x.example', TNamedGroupCatalog.X25519);
  CheckEquals(TNamedGroupCatalog.X25519, LCache.KxHint('host:443', 'x.example'),
    'the hint round-trips');
  CheckEquals(0, LCache.KxHint('host:443', 'other.example'),
    'the hint is keyed by server and SNI');
end;

procedure TTestSessionStore.TestKxHintBounded;
var
  LCache: ISessionCache;
  LI: Int32;
begin
  LCache := TInMemorySessionCache.Create(2);
  for LI := 0 to 4 do
    LCache.SetKxHint('host:443', 'h' + IntToStr(LI) + '.example',
      TNamedGroupCatalog.X25519);
  CheckEquals(0, LCache.KxHint('host:443', 'h0.example'),
    'the oldest hints are evicted past the cap');
  CheckEquals(TNamedGroupCatalog.X25519, LCache.KxHint('host:443', 'h4.example'),
    'the newest hint survives');
  // an in-place update must not re-insert and evict a live hint
  LCache.SetKxHint('host:443', 'h3.example', TNamedGroupCatalog.Secp256r1);
  CheckEquals(TNamedGroupCatalog.Secp256r1, LCache.KxHint('host:443', 'h3.example'),
    'updating a hint keeps its value');
  CheckEquals(TNamedGroupCatalog.X25519, LCache.KxHint('host:443', 'h4.example'),
    'and does not evict another live hint');
end;

procedure TTestSessionStore.TestStorePutTakeSingleUse;
var
  LStore: ISessionStore;
  LHandle: TBytes;
  LTaken: IResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LHandle := LStore.Put(MakeSession(Tag($22, 8)));
  CheckTrue(System.Length(LHandle) > 0, 'Put returns an opaque handle');
  CheckTrue(LStore.Take(LHandle, LTaken), 'the handle resolves');
  CheckEqualBytes('to the stored session', Tag($22, 8),
    (LTaken as ITls13ResumableSession).TicketIdentity);
  CheckFalse(LStore.Take(LHandle, LTaken), 'a stored session is single-use');
end;

procedure TTestSessionStore.TestStorePutWithId;
var
  LStore: ISessionStore;
  LId: TBytes;
  LTaken: IResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LId := Tag($33, 32);
  LStore.PutWithId(LId, MakeSession(Tag($44, 4)));
  CheckTrue(LStore.Take(LId, LTaken), 'a caller-chosen id resolves');
  CheckEqualBytes('to the stored session', Tag($44, 4),
    (LTaken as ITls13ResumableSession).TicketIdentity);
end;

procedure TTestSessionStore.TestStoreBoundedEviction;
var
  LStore: ISessionStore;
  LI: Int32;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom, 3);
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
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom, 8);
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
      (LTaken as ITls13ResumableSession).TicketIdentity);
  end;
  CheckEquals(0, LStore.Count, 'all sessions were consumed');
end;

procedure TTestSessionStore.TestStekCurrentAndLookup;
var
  LStek: ISessionTicketKeyManager;
  LName: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
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
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
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
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 2);
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
  LConcrete := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStek := LConcrete;
  LName := Tag($55, 16);
  LKey := TSecretBuffer.From(Tag($66, 32));
  LConcrete.InstallKey(LName, LKey);
  LStek.CurrentKey(LName, LCurrent);
  CheckTrue(LKey.ConstantTimeAreEqual(LCurrent),
    'an installed key becomes the current key');
end;

procedure TTestSessionStore.TestStekFleetMintsNothingUntilInstall;
var
  LStek: ISessionTicketKeyManager;
  LConcrete: TStekTicketKeyManager;
  LName, LCurrentName: TBytes;
  LKey, LCurrent: ISecretBuffer;
begin
  // a fleet manager mints no local key: it seals nothing until the shared STEK is installed, so a
  // pre-install ticket cannot be sealed under a key the fleet cannot open (SF-AC)
  LConcrete := TStekTicketKeyManager.CreateFleet;
  LStek := LConcrete;
  CheckFalse(LStek.CurrentKey(LCurrentName, LCurrent),
    'a fleet manager seals nothing before InstallKey');
  LName := Tag($55, 16);
  LKey := TSecretBuffer.From(Tag($66, 32));
  LConcrete.InstallKey(LName, LKey);
  CheckTrue(LStek.CurrentKey(LCurrentName, LCurrent),
    'after InstallKey the fleet manager seals under the installed key');
  CheckTrue(LKey.ConstantTimeAreEqual(LCurrent),
    'the installed key is the only current key (no local key was minted)');
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
  LClock := LClockObj;
  // a 10-second auto-rotation interval driven by the injected clock
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 0, LClock, 10);
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

procedure TTestSessionStore.TestStekOpenPathRetiresExpiredKey;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  // window 2, interval 10 s: a key must open tickets for its whole 2x10 s age and no longer, on the
  // open path alone (no seal traffic in between)
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 2, LClock, 10);
  LStek.CurrentKey(LName1, LKey);
  LClockObj.Advance(15000); // t = 15 s: still inside the 20 s age bound
  CheckTrue(LStek.KeyByName(LName1, LFound),
    'a key still within its age bound opens tickets');
  LClockObj.Advance(6000); // t = 21 s: past the age bound, with no intervening seal
  CheckFalse(LStek.KeyByName(LName1, LFound),
    'an aged-out key is retired even on a quiet server');
end;

procedure TTestSessionStore.TestStekCurrentKeyRecoversAfterFullExpiry;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 2, LClock, 10);
  LStek.CurrentKey(LName1, LKey);
  LClockObj.Advance(25000); // every key has aged out
  CheckTrue(LStek.CurrentKey(LName2, LKey),
    'the manager re-mints after the whole ring expires');
  CheckFalse(AreEqual(LName1, LName2), 'and the recovered current key is fresh');
  CheckFalse(LStek.KeyByName(LName1, LKey),
    'the expired key was pruned, not merely rotated behind the window');
end;

procedure TTestSessionStore.TestStekManualManagerNeverExpires;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  // a clockless manager leaves key lifetime to the caller: no key expires by time
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStek.CurrentKey(LName, LKey);
  CheckTrue(LStek.KeyByName(LName, LFound), 'a clockless manager never retires its key');
  // a clock with a zero interval likewise never expires keys (no interval means no age bound)
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 2, LClock, 0);
  LStek.CurrentKey(LName, LKey);
  LClockObj.Advance(UInt64(1000000) * 1000);
  CheckTrue(LStek.KeyByName(LName, LFound),
    'a zero interval leaves the key valid however far the clock advances');
end;

procedure TTestSessionStore.TestStekSealCapRotates;
var
  LStek: ISessionTicketKeyManager;
  LName1, LName2, LName3, LName4: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  // a per-key seal cap of 3: the fourth seal must draw a fresh key
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 0, nil, 0, 3);
  LStek.CurrentKey(LName1, LKey);
  LStek.CurrentKey(LName2, LKey);
  LStek.CurrentKey(LName3, LKey);
  CheckTrue(AreEqual(LName1, LName2), 'the key is reused under its seal cap');
  CheckTrue(AreEqual(LName1, LName3), 'the key is reused under its seal cap');
  LStek.CurrentKey(LName4, LKey);
  CheckFalse(AreEqual(LName1, LName4), 'the key rotates once its seal cap is reached');
  CheckTrue(LStek.KeyByName(LName1, LFound),
    'the capped-out key still opens tickets within the window');
end;

procedure TTestSessionStore.TestStekSealCapInFleetModeStopsSealing;
var
  LConcrete: TStekTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LInstalled, LName: TBytes;
  LKey: ISecretBuffer;
begin
  LConcrete := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 0, nil, 0, 2);
  LStek := LConcrete;
  LInstalled := Tag($55, 16);
  LConcrete.InstallKey(LInstalled, TSecretBuffer.From(Tag($66, 32)));
  CheckTrue(LStek.CurrentKey(LName, LKey), 'the installed key seals a first ticket');
  CheckTrue(AreEqual(LInstalled, LName), 'under the installed name');
  CheckTrue(LStek.CurrentKey(LName, LKey), 'and a second');
  CheckFalse(LStek.CurrentKey(LName, LKey),
    'an exhausted installed key stops sealing rather than being silently reminted');
end;

procedure TTestSessionStore.TestStekCreateDefaultRotatesOnLifetime;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  // the default STEK rotates on the advertised ticket lifetime, not a fixed interval
  LStek := TStekTicketKeyManager.CreateDefault(Crypto, LClock, 100);
  LStek.CurrentKey(LName1, LKey);
  LClockObj.Advance(100000); // one lifetime
  LStek.CurrentKey(LName2, LKey);
  CheckFalse(AreEqual(LName1, LName2), 'a key rotates after one advertised lifetime');
  CheckTrue(LStek.KeyByName(LName1, LFound),
    'the prior key still opens tickets across its lifetime');
  LClockObj.Advance(100000); // two lifetimes since the first key was minted
  CheckFalse(LStek.KeyByName(LName1, LFound),
    'a key older than twice the lifetime cannot back a live ticket');
end;

procedure TTestSessionStore.TestStekCreateDefaultZeroLifetimeStillRotates;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  // an unadvertised (zero) lifetime falls back to a bounded default rather than never rotating
  LStek := TStekTicketKeyManager.CreateDefault(Crypto, LClock, 0);
  LStek.CurrentKey(LName1, LKey);
  LClockObj.Advance(UInt64(7200) * 1000); // the fallback interval
  LStek.CurrentKey(LName2, LKey);
  CheckFalse(AreEqual(LName1, LName2),
    'a zero lifetime still rotates on the fallback interval');
end;

procedure TTestSessionStore.TestStekInstallKeyRejectsBadNameLength;
var
  LConcrete: TStekTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LBefore, LAfter: TBytes;
  LKey: ISecretBuffer;
  LRaised: Boolean;
begin
  LConcrete := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStek := LConcrete;
  LStek.CurrentKey(LBefore, LKey);
  LRaised := False;
  try
    LConcrete.InstallKey(Tag($55, 15), TSecretBuffer.From(Tag($66, 32)));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a wrong-length key name is rejected at install time');
  LStek.CurrentKey(LAfter, LKey);
  CheckTrue(AreEqual(LBefore, LAfter), 'and the ring is left unchanged');
end;

procedure TTestSessionStore.TestStekInstallKeyRejectsBadKeyLength;
var
  LConcrete: TStekTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LBefore, LAfter: TBytes;
  LKey: ISecretBuffer;
  LRaised: Boolean;
begin
  LConcrete := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStek := LConcrete;
  LStek.CurrentKey(LBefore, LKey);
  LRaised := False;
  try
    LConcrete.InstallKey(Tag($55, 16), TSecretBuffer.From(Tag($66, 31)));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a wrong-length key is rejected at install time');
  LStek.CurrentKey(LAfter, LKey);
  CheckTrue(AreEqual(LBefore, LAfter), 'and the ring is left unchanged');
end;

procedure TTestSessionStore.TestStekInstallKeyRejectsNilKey;
var
  LConcrete: TStekTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LBefore, LAfter: TBytes;
  LKey: ISecretBuffer;
  LRaised: Boolean;
begin
  LConcrete := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LStek := LConcrete;
  LStek.CurrentKey(LBefore, LKey);
  LRaised := False;
  try
    LConcrete.InstallKey(Tag($55, 16), nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil key is rejected at install time');
  LStek.CurrentKey(LAfter, LKey);
  CheckTrue(AreEqual(LBefore, LAfter), 'and the ring is left unchanged');
end;

procedure TTestSessionStore.TestStekInstallKeyDisablesAutoRotation;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LConcrete: TStekTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LInstalled, LName: TBytes;
  LKey: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  LConcrete := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 0, LClock, 10);
  LStek := LConcrete;
  LInstalled := Tag($55, 16);
  LConcrete.InstallKey(LInstalled, TSecretBuffer.From(Tag($66, 32)));
  LClockObj.Advance(11000); // past the auto-rotation interval
  LStek.CurrentKey(LName, LKey);
  CheckTrue(AreEqual(LInstalled, LName),
    'installing a key freezes auto-rotation for fleet coordination');
end;

procedure TTestSessionStore.TestStekInstalledKeyDoesNotTimeExpire;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LConcrete: TStekTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LInstalled, LNext, LName: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  LConcrete := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 2, LClock, 10);
  LStek := LConcrete;
  LInstalled := Tag($55, 16);
  LConcrete.InstallKey(LInstalled, TSecretBuffer.From(Tag($66, 32)));
  LClockObj.Advance(1000000); // far past any age bound: the fleet, not the clock, owns retirement
  CheckTrue(LStek.KeyByName(LInstalled, LFound),
    'an installed key is not retired by the local clock (fleet nodes stamp it independently)');
  CheckTrue(LStek.CurrentKey(LName, LKey), 'and it still seals');
  CheckTrue(AreEqual(LInstalled, LName), 'under the installed name');
  // the operator retires an old key by installing newer ones until the window pushes it out
  LNext := Tag($77, 16);
  LConcrete.InstallKey(LNext, TSecretBuffer.From(Tag($88, 32)));
  LConcrete.InstallKey(Tag($99, 16), TSecretBuffer.From(Tag($AA, 32)));
  CheckFalse(LStek.KeyByName(LInstalled, LFound),
    'the first installed key falls out of the window once newer keys arrive');
end;

procedure TTestSessionStore.TestStekRotateDoesNotShortenTimer;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LNameA, LName: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  // window 2, interval 10 s
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 2, LClock, 10);
  LStek.CurrentKey(LNameA, LKey);
  LClockObj.Advance(9000); // just before the interval elapses
  LStek.Rotate; // an out-of-schedule rotation must push the next timed rotation out, not keep it
  LClockObj.Advance(2000); // t = 11 s: past the ORIGINAL interval, before the rescheduled one
  LStek.CurrentKey(LName, LKey); // would fire a second rotation (evicting A by count) if unshifted
  CheckTrue(LStek.KeyByName(LNameA, LFound),
    'a manual rotation reschedules the timer so the prior key is not evicted early');
end;

procedure TTestSessionStore.TestStekBackwardsClockDoesNotExpireOrRaise;
var
  LClockObj: TAdjustableClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LNameA, LName: TBytes;
  LKey, LFound: ISecretBuffer;
  LRaised: Boolean;
begin
  LClockObj := TAdjustableClock.Create(1000000);
  LClock := LClockObj;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 2, LClock, 10);
  LStek.CurrentKey(LNameA, LKey);
  LClockObj.Advance(5000);
  LClockObj.Retreat(8000); // the clock steps back before the key's birth
  LRaised := False;
  try
    CheckTrue(LStek.KeyByName(LNameA, LFound),
      'a backwards clock step does not prematurely expire a live key');
    LStek.CurrentKey(LName, LKey);
  except
    LRaised := True;
  end;
  CheckFalse(LRaised, 'a backwards clock step does not underflow or raise');
end;

procedure TTestSessionStore.TestStekOpenWithUnbindableKeyFallsBack;
var
  LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
  LSession: IResumableSession;
  LOk, LRaised: Boolean;
begin
  // a key the manager cannot bind (here, a wrong-length one) must fall back to a full handshake,
  // not let the AEAD Init exception escape the open path
  LStrategy := TStekTicketStrategy.Create(Crypto, TBadKeyManager.Create as ISessionTicketKeyManager);
  LTicket := Tag($01, 60); // long enough to pass the framing length check and reach the AEAD
  LRaised := False;
  LOk := True;
  try
    LOk := LStrategy.Open(LTicket, LSession);
  except
    LRaised := True;
  end;
  CheckFalse(LRaised, 'opening with an unbindable key does not raise');
  CheckFalse(LOk, 'it falls back to a full handshake');
end;

procedure TTestSessionStore.TestStekSealOpenRoundTripTls13;
var
  LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
  LOriginal, LOpened: IResumableSession;
  L13: ITls13ResumableSession;
  L12: ITls12ResumableSession;
  LChain: TArray<TBytes>;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  LChain := TArray<TBytes>.Create(Tag($C0, 20));
  LOriginal := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(Tag($5E, 32)), 'h2', 'host.example',
    Tag($AB, 4), 3600, $11223344, 1000, 4096, LChain, Tag($5C, 3));
  LTicket := LStrategy.Seal(LOriginal);
  CheckTrue(System.Length(LTicket) > 0, 'a 1.3 session seals to a ticket');
  CheckTrue(LStrategy.Open(LTicket, LOpened), 'the ticket opens');
  CheckTrue(Supports(LOpened, ITls13ResumableSession, L13),
    'the opened session is a 1.3 sub-interface');
  CheckFalse(Supports(LOpened, ITls12ResumableSession, L12),
    'a 1.3 session is not a 1.2 sub-interface');
  CheckEquals(Integer(TCipherSuites13.Aes128GcmSha256), Integer(LOpened.CipherSuite),
    'the suite round-trips');
  CheckEquals('h2', LOpened.Alpn, 'the ALPN round-trips');
  CheckEquals('host.example', LOpened.ServerName, 'the SNI host round-trips');
  CheckEquals(Integer($11223344), Integer(L13.TicketAgeAdd), 'the age_add round-trips');
  CheckEquals(Integer(4096), Integer(L13.MaxEarlyData), 'max_early_data round-trips');
  CheckEqualBytes('the resumption secret round-trips', Tag($5E, 32),
    L13.ResumptionSecret.ToBytes);
  CheckEqualBytes('the resumption scope round-trips', Tag($5C, 3),
    LOpened.ResumptionScope);
  CheckEquals(1, System.Length(LOpened.PeerCertificates), 'the peer chain round-trips');
  CheckEqualBytes('the peer leaf round-trips', Tag($C0, 20),
    LOpened.PeerCertificates[0]);
end;

procedure TTestSessionStore.TestStekSealOpenRoundTripTls12;
var
  LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
  LOpened: IResumableSession;
  L12: ITls12ResumableSession;
  L13: ITls13ResumableSession;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  // the STEK body drops session_id / session_ticket (they are never sealed), so those must open empty
  LTicket := LStrategy.Seal(TTls12ResumableSession.Create(
    TCipherSuites12.EcdheEcdsaAes128GcmSha256, THashAlgorithm.SHA_256,
    TSecretBuffer.From(Tag($4D, 48)), Tag($01, 32), Tag($02, 16), True, '',
    'legacy.example', 1800, 2000, nil, nil) as IResumableSession);
  CheckTrue(System.Length(LTicket) > 0, 'a 1.2 session seals to a ticket');
  CheckTrue(LStrategy.Open(LTicket, LOpened), 'the ticket opens');
  CheckTrue(Supports(LOpened, ITls12ResumableSession, L12),
    'the opened session is a 1.2 sub-interface');
  CheckFalse(Supports(LOpened, ITls13ResumableSession, L13),
    'a 1.2 session is not a 1.3 sub-interface');
  CheckEqualBytes('the master secret round-trips', Tag($4D, 48),
    L12.MasterSecret.ToBytes);
  CheckTrue(L12.ExtendedMasterSecret, 'the EMS flag round-trips');
  CheckEquals('legacy.example', LOpened.ServerName, 'the SNI host round-trips');
  CheckEquals(0, System.Length(L12.SessionId), 'the session id is not carried in a STEK ticket');
  CheckEquals(0, System.Length(L12.SessionTicket),
    'the session ticket is not carried in a STEK ticket');
end;

procedure TTestSessionStore.TestStekSealDeclinesBaseOnlySession;
var
  LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
begin
  // a session that is neither sub-interface cannot be serialized, so Seal declines (empty ticket)
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  LTicket := LStrategy.Seal(TBaseOnlySession.Create as IResumableSession);
  CheckEquals(0, System.Length(LTicket),
    'a session that is neither a 1.3 nor a 1.2 sub-interface does not seal');
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

procedure TTestSessionStore.TestAntiReplayReRecordBehindLiveEntryStaysSound;
var
  LReplay: IAntiReplayStrategy;
  LGuard, LValue, LOther: TBytes;
begin
  // re-recording a value after it expired while a live entry sits ahead of it (so pruning did not
  // reach it first) leaves a stale order entry for that value; the register must stay sound - the
  // re-recorded value is rejected as a replay within its new window, pruning and counting are not
  // corrupted, and a fresh distinct value is still accepted
  LReplay := TStrikeRegisterAntiReplay.Create;
  LGuard := Tag($11, 8);
  LValue := Tag($AA, 8);
  LOther := Tag($22, 8);
  CheckTrue(LReplay.CheckAndRecord(LGuard, 1000, 100000), 'the live guard is recorded');
  CheckTrue(LReplay.CheckAndRecord(LValue, 1000, 2000), 'the value is recorded');
  // at 3000 the value has expired but sits behind the still-live guard; re-record it
  CheckTrue(LReplay.CheckAndRecord(LValue, 3000, 100000), 'the value is re-recorded after expiry');
  CheckFalse(LReplay.CheckAndRecord(LValue, 4000, 100000),
    'the re-recorded value is still live and rejected as a replay');
  CheckFalse(LReplay.CheckAndRecord(LGuard, 4000, 100000), 'the live guard is still a replay');
  CheckTrue(LReplay.CheckAndRecord(LOther, 4000, 100000),
    'a fresh distinct value is still accepted');
  CheckTrue(LReplay.Count <= 3, 'the register count is not inflated by the stale order entry');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSessionStore);
{$ELSE}
  RegisterTest(TTestSessionStore.Suite);
{$ENDIF FPC}

end.
