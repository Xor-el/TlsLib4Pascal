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
  MockClock,
  MockCryptoProvider,
  MockSessionStores,
  TlpICryptoProvider,
  TlpAeadUtilities,
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
    function NewKeys: ISessionTicketKeyManager;
    function NewStore: ISessionStore;
    function SealedTls12WithGroupAndScheme(
      const AStrategy: ISessionTicketStrategy): IResumableSession;
    // whether sealing / opening a ticket lets AFault out when the ticket AEAD raises it
    function SealRaisedFrom(AFault: ExceptClass): Boolean;
    function OpenRaisedFrom(AFault: ExceptClass): Boolean;
  published
    procedure TestCacheStoreAndTakeSingleUse;
    procedure TestCacheKeyedByServerAndSni;
    procedure TestCacheRemoveDropsOnlyTheNamedSession;
    procedure TestCacheRemoveOfAnAbsentSessionIsHarmless;
    procedure TestCacheTakeDropsASessionWhoseAuthenticationLapsed;
    procedure TestCacheBoundedEviction;
    procedure TestCachePrefersTls13OverTls12;
    procedure TestCacheExpiredHeadDoesNotShadowLiveTicket;
    procedure TestCacheExpiredTls13FallsBackToLiveTls12;
    procedure TestCacheTls12ZeroLifetimeIsHeldToTheCeiling;
    procedure TestCacheExpiryIsInclusiveAtLifetimeBoundary;
    procedure TestKxHintRoundTripsAndIsKeyed;
    procedure TestKxHintBounded;
    procedure TestStorePutTakeSingleUse;
    procedure TestStorePeekDoesNotRemove;
    procedure TestTicketsAreSealedWithKeysWhenNoStoreIsSet;
    procedure TestTls13StoreOverridesTicketKeys;
    procedure TestTls12TicketsAreSealedWithKeysBesideAStore;
    procedure TestOnlyTls13LetsAStoreOverrideTheKeys;
    procedure TestNoKeysMeansNoKeySealing;
    procedure TestTls13StoreAloneHoldsTickets;
    procedure TestTls12StoreAloneIssuesNoTickets;
    procedure TestNoStrategyWithoutKeysOrStore;
    procedure TestTicketAeadIsAes256Gcm;
    procedure TestStoreTicketStrategyConsumeIsSingleUse;
    procedure TestStekTicketStrategyConsumeIsAlwaysTrue;
    procedure TestStorePutWithId;
    procedure TestStoreBoundedEviction;
    procedure TestStoreRePutIdIsNotEvictedBeforeOlderEntries;
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
    procedure TestStekFleetKeysRetireOnlyByNewerInstalls;
    procedure TestStekRotateDoesNotShortenTimer;
    procedure TestStekBackwardsClockDoesNotExpireOrRaise;
    procedure TestStekExtremeAgeBoundDoesNotExpireKeys;
    procedure TestStekOpenWithUnbindableKeyFallsBack;
    procedure TestStekSealOpenRoundTripTls13;
    procedure TestStekSealOpenRoundTripTls12;
    procedure TestStekSealDeclinesWhenProviderLacksTicketAead;
    procedure TestStekOpenUnreadableWhenProviderLacksTicketAead;
    procedure TestStekSealDeclinesWhenTicketAeadRaisesATlsLibError;
    procedure TestStekOpenUnreadableWhenTicketAeadRaisesATlsLibError;
    procedure TestStekSealLetsAPlainExceptionThrough;
    procedure TestStekOpenLetsAPlainExceptionThrough;
    procedure TestStekSealOpenCarriesTls12Group;
    procedure TestStekSealOpenCarriesTls12PeerSignatureScheme;
    procedure TestLargestSealedTicketIsTheCachedLimit;
    procedure TestStekSealOpenCarriesTls13PeerSignatureScheme;
    procedure TestStekSealOpenCarriesTls13AuthenticatedAt;
    procedure TestStekSealOpenCarriesTls12AuthenticatedAt;
    procedure TestStekV10TicketIsDeclined;
    procedure TestStekSealDeclinesBaseOnlySession;
    procedure TestAntiReplayDetectsReplay;
    procedure TestAntiReplayFreshAfterExpiry;
    procedure TestAntiReplayRejectsEmpty;
    procedure TestAntiReplayBounded;
    procedure TestAntiReplayReRecordDoesNotEvictLiveValue;
    procedure TestAntiReplayDeclinesAtCapacityWithoutEvicting;
    procedure TestAntiReplayAdmitsAfterExpiryAtCapacity;
    procedure TestAntiReplayAdmitsAfterAnEarlierExpiryBehindALiveFront;
    procedure TestAntiReplayCompactionKeepsLiveEntries;
  end;

implementation

type
  // a session that implements only the version-agnostic base (neither sub-interface), to prove Seal
  // declines to seal one it cannot classify as 1.3 or 1.2
  TBaseOnlySession = class sealed(TInterfacedObject, IResumableSession)
  public
    function Version: TTlsVersion;
    function CipherSuite: UInt16;
    function Hash: THashAlgorithm;
    function Alpn: TBytes;
    function ServerName: string;
    function TicketLifetime: UInt32;
    function IssuedAtMillis: UInt64;
    function AuthenticatedAtMillis: UInt64;
    function PeerCertificates: TArray<TBytes>;
    function ResumptionScope: TBytes;
    function PskIdentity: TBytes;
    function PskBinding: TBytes;
    function PeerSignatureScheme: UInt16;
  end;

function TBaseOnlySession.PeerSignatureScheme: UInt16;
begin
  Result := 0;
end;

function TBaseOnlySession.PskIdentity: TBytes;
begin
  Result := nil;
end;

function TBaseOnlySession.PskBinding: TBytes;
begin
  Result := nil;
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

function TBaseOnlySession.Alpn: TBytes;
begin
  Result := nil;
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

function TBaseOnlySession.AuthenticatedAtMillis: UInt64;
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
    nil, '', ATag, 7200, 0, 0, 0, nil, nil);
end;

function TTestSessionStore.MakeSession(const ATag: TBytes; ALifetime: UInt32;
  AIssuedMillis: UInt64): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(ATag),
    nil, '', ATag, ALifetime, 0, AIssuedMillis, 0, nil, nil);
end;

function TTestSessionStore.MakeTls12Session(const ATag: TBytes): IResumableSession;
begin
  Result := TTls12ResumableSession.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    THashAlgorithm.SHA_256,
    TSecretBuffer.From(ATag), ATag, ATag, True, nil, '', 7200, 0, nil, nil);
end;

function TTestSessionStore.MakeTls12Session(const ATag: TBytes; ALifetime: UInt32;
  AIssuedMillis: UInt64): IResumableSession;
begin
  Result := TTls12ResumableSession.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    THashAlgorithm.SHA_256,
    TSecretBuffer.From(ATag), ATag, ATag, True, nil, '', ALifetime, AIssuedMillis, nil, nil);
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

procedure TTestSessionStore.TestCacheRemoveDropsOnlyTheNamedSession;
var
  LCache: ISessionCache;
  LKept, LDropped, LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LKept := MakeSession(Tag($01, 4));
  LDropped := MakeSession(Tag($02, 4));
  LCache.Store('host:443', 'a.example', LKept);
  LCache.Store('host:443', 'a.example', LDropped);
  LCache.Remove('host:443', 'a.example', LDropped);
  CheckEquals(1, LCache.Count, 'one session is left');
  CheckTrue(LCache.Take('host:443', 'a.example', 0, LTaken), 'the other session is still there');
  CheckTrue(LKept = LTaken, 'the kept session is the one that was not removed');
end;

procedure TTestSessionStore.TestCacheRemoveOfAnAbsentSessionIsHarmless;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  LCache.Store('host:443', 'a.example', MakeSession(Tag($01, 4)));
  // a session stored under another server, or already taken, is not an error and drops nothing
  LCache.Remove('host:443', 'b.example', MakeSession(Tag($02, 4)));
  LCache.Remove('host:443', 'a.example', MakeSession(Tag($03, 4)));
  CheckEquals(1, LCache.Count, 'nothing was removed');
  CheckTrue(LCache.Take('host:443', 'a.example', 0, LTaken), 'the stored session survives');
end;

procedure TTestSessionStore.TestCacheTakeDropsASessionWhoseAuthenticationLapsed;
const
  CapMs = UInt64(604800) * 1000;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  // freshly issued with a long lifetime, but authenticated more than seven days before the take
  LCache.Store('host:443', 'a.example', TTls13ResumableSession.Create(
    TCipherSuites13.Aes128GcmSha256, THashAlgorithm.SHA_256, TSecretBuffer.From(Tag($01, 4)),
    nil, '', Tag($01, 4), 604800, 0, CapMs, 0, nil, nil, nil, nil, 0, 0) as IResumableSession);
  CheckFalse(LCache.Take('host:443', 'a.example', CapMs + 1, LTaken),
    'a lapsed chain is dropped rather than returned');
  CheckEquals(0, LCache.Count, 'and no longer held');
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

procedure TTestSessionStore.TestCacheTls12ZeroLifetimeIsHeldToTheCeiling;
var
  LCache: ISessionCache;
  LTaken: IResumableSession;
begin
  LCache := TInMemorySessionCache.Create;
  // a 1.2 lifetime hint of 0 is unspecified, not expired: it is held to the 7-day client ceiling
  LCache.Store('host:443', 'x.example', MakeTls12Session(Tag($12, 4), 0, 0));
  CheckTrue(LCache.Take('host:443', 'x.example', UInt64(604800) * 1000, LTaken),
    'a zero-lifetime 1.2 session is kept up to the ceiling');
  CheckEquals(TlsWireVersionTls12, LTaken.Version.WireValue, 'and it is the 1.2 session');
  LCache.Store('host:443', 'x.example', MakeTls12Session(Tag($12, 4), 0, 0));
  CheckFalse(LCache.Take('host:443', 'x.example', UInt64(604800) * 1000 + 1, LTaken),
    'and aged out past it');
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

procedure TTestSessionStore.TestStorePeekDoesNotRemove;
var
  LStore: ISessionStore;
  LHandle: TBytes;
  LSeen, LTaken: IResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LHandle := LStore.Put(MakeSession(Tag($22, 8)));
  CheckTrue(LStore.Peek(LHandle, LSeen), 'a stored handle can be looked at');
  CheckTrue(LStore.Peek(LHandle, LSeen), 'and again: peeking uses nothing up');
  CheckEquals(1, LStore.Count, 'the session is still stored');
  CheckFalse(LStore.Peek(Tag($99, 8), LSeen), 'an unknown handle is absent');
  CheckTrue(LStore.Take(LHandle, LTaken), 'the session is still takeable');
  CheckFalse(LStore.Peek(LHandle, LSeen), 'once taken it is gone');
end;

function TTestSessionStore.NewKeys: ISessionTicketKeyManager;
begin
  Result := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager;
end;

function TTestSessionStore.NewStore: ISessionStore;
begin
  Result := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
end;

procedure TTestSessionStore.TestTicketsAreSealedWithKeysWhenNoStoreIsSet;
begin
  CheckTrue(TSessionTicketStrategies.SealsWithKeys(TlsWireVersionTls13, NewKeys, nil),
    'TLS 1.3 with keys and no store');
  CheckTrue(TSessionTicketStrategies.SealsWithKeys(TlsWireVersionTls12, NewKeys, nil),
    'TLS 1.2 with keys and no store');
end;

procedure TTestSessionStore.TestTls13StoreOverridesTicketKeys;
var
  LStore: ISessionStore;
  LStrategy: ISessionTicketStrategy;
  LSeen: IResumableSession;
begin
  LStore := NewStore;
  CheckFalse(TSessionTicketStrategies.SealsWithKeys(TlsWireVersionTls13, NewKeys, LStore),
    'a TLS 1.3 store wins over the keys');
  LStrategy := TSessionTicketStrategies.ForServer(TlsWireVersionTls13, Crypto, NewKeys, LStore);
  CheckTrue(LStore.Peek(LStrategy.Seal(MakeSession(Tag($61, 8))), LSeen),
    'the TLS 1.3 ticket is a handle into the store');
end;

procedure TTestSessionStore.TestTls12TicketsAreSealedWithKeysBesideAStore;
var
  LStore: ISessionStore;
  LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
  LSeen: IResumableSession;
begin
  LStore := NewStore;
  CheckTrue(TSessionTicketStrategies.SealsWithKeys(TlsWireVersionTls12, NewKeys, LStore),
    'TLS 1.2 keeps sealing with the keys beside a store');
  LStrategy := TSessionTicketStrategies.ForServer(TlsWireVersionTls12, Crypto, NewKeys, LStore);
  LTicket := LStrategy.Seal(MakeTls12Session(Tag($62, 48)));
  CheckFalse(LStore.Peek(LTicket, LSeen), 'the TLS 1.2 ticket is not a store handle');
  CheckTrue(LStrategy.Open(LTicket, LSeen), 'it opens from the keys');
end;

procedure TTestSessionStore.TestOnlyTls13LetsAStoreOverrideTheKeys;
begin
  CheckTrue(TSessionTicketStrategies.SealsWithKeys($0301, NewKeys, NewStore),
    'a version that is not TLS 1.3 never hands tickets to a store');
end;

procedure TTestSessionStore.TestNoKeysMeansNoKeySealing;
begin
  CheckFalse(TSessionTicketStrategies.SealsWithKeys(TlsWireVersionTls13, nil, nil),
    'TLS 1.3 with no keys and no store');
  CheckFalse(TSessionTicketStrategies.SealsWithKeys(TlsWireVersionTls12, nil, NewStore),
    'TLS 1.2 with a store but no keys');
  CheckFalse(TSessionTicketStrategies.SealsWithKeys(TlsWireVersionTls13, nil, NewStore),
    'TLS 1.3 with a store but no keys');
end;

procedure TTestSessionStore.TestTls13StoreAloneHoldsTickets;
var
  LStore: ISessionStore;
  LStrategy: ISessionTicketStrategy;
  LSeen: IResumableSession;
begin
  LStore := NewStore;
  LStrategy := TSessionTicketStrategies.ForServer(TlsWireVersionTls13, Crypto, nil, LStore);
  CheckTrue(LStrategy <> nil, 'a TLS 1.3 store alone is enough');
  CheckTrue(LStore.Peek(LStrategy.Seal(MakeSession(Tag($63, 8))), LSeen),
    'the ticket is a handle into the store');
end;

procedure TTestSessionStore.TestTls12StoreAloneIssuesNoTickets;
begin
  CheckTrue(TSessionTicketStrategies.ForServer(TlsWireVersionTls12, Crypto, nil, NewStore) = nil,
    'a TLS 1.2 store serves session ids, not tickets');
end;

procedure TTestSessionStore.TestNoStrategyWithoutKeysOrStore;
begin
  CheckTrue(TSessionTicketStrategies.ForServer(TlsWireVersionTls13, Crypto, nil, nil) = nil,
    'no TLS 1.3 strategy');
  CheckTrue(TSessionTicketStrategies.ForServer(TlsWireVersionTls12, Crypto, nil, nil) = nil,
    'no TLS 1.2 strategy');
end;

procedure TTestSessionStore.TestTicketAeadIsAes256Gcm;
begin
  CheckTrue(TSessionTicketStrategies.TicketAead = TAeadAlgorithm.AES_256_GCM,
    'tickets are sealed with AES-256-GCM');
end;

procedure TTestSessionStore.TestStoreTicketStrategyConsumeIsSingleUse;
var
  LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
  LOpened: IResumableSession;
begin
  LStrategy := TStoreTicketStrategy.Create(
    TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore);
  LTicket := LStrategy.Seal(MakeSession(Tag($44, 8)));
  // recovering the session does not use the ticket up: only a committed resumption does
  CheckTrue(LStrategy.Open(LTicket, LOpened), 'the ticket opens');
  CheckTrue(LStrategy.Open(LTicket, LOpened), 'and opens again before it is consumed');
  CheckTrue(LStrategy.Consume(LTicket), 'the first commit wins');
  CheckFalse(LStrategy.Consume(LTicket), 'a second commit of the same ticket is refused');
  CheckFalse(LStrategy.Open(LTicket, LOpened), 'a consumed ticket no longer opens');
end;

procedure TTestSessionStore.TestStekTicketStrategyConsumeIsAlwaysTrue;
var
  LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  LTicket := LStrategy.Seal(MakeSession(Tag($55, 8)));
  // a stateless ticket holds no server state, so committing it never fails
  CheckTrue(LStrategy.Consume(LTicket), 'a stateless ticket always commits');
  CheckTrue(LStrategy.Consume(LTicket), 'and commits again');
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

procedure TTestSessionStore.TestStoreRePutIdIsNotEvictedBeforeOlderEntries;
var
  LStore: ISessionStore;
  LA, LB, LC: TBytes;
  LGot: IResumableSession;
begin
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom, 2);
  LA := Tag($A1, 8);
  LB := Tag($B2, 8);
  LC := Tag($C3, 8);
  LStore.PutWithId(LA, MakeSession(Tag(1, 4)));
  LStore.PutWithId(LB, MakeSession(Tag(2, 4)));
  LStore.PutWithId(LA, MakeSession(Tag(3, 4)));
  LStore.PutWithId(LC, MakeSession(Tag(4, 4)));
  CheckEquals(2, LStore.Count, 'the store stays at its cap');
  CheckTrue(LStore.Peek(LA, LGot), 'the re-put id is newer than B and survives');
  CheckFalse(LStore.Peek(LB, LGot), 'the oldest live entry is the one evicted');
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
  // compacted instead of accumulating one dead entry per ticket).
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
  LStek: IRotatingTicketKeyManager;
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
  LStek: IRotatingTicketKeyManager;
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
  LConcrete: TFleetTicketKeyManager;
  LName: TBytes;
  LKey, LCurrent: ISecretBuffer;
begin
  LConcrete := TFleetTicketKeyManager.Create;
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
  LConcrete: TFleetTicketKeyManager;
  LName, LCurrentName: TBytes;
  LKey, LCurrent: ISecretBuffer;
begin
  // a fleet manager mints no local key: it seals nothing until the shared STEK is installed, so a
  // pre-install ticket cannot be sealed under a key the fleet cannot open (SF-AC)
  LConcrete := TFleetTicketKeyManager.Create;
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
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2, LName3: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TMockClock.Create(1000000);
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
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TMockClock.Create(1000000);
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
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey: ISecretBuffer;
begin
  LClockObj := TMockClock.Create(1000000);
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
  LClockObj: TMockClock;
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
  LClockObj := TMockClock.Create(1000000);
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
  LConcrete: TFleetTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LInstalled, LName: TBytes;
  LKey: ISecretBuffer;
begin
  LConcrete := TFleetTicketKeyManager.Create(0, 2);
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
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TMockClock.Create(1000000);
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
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey: ISecretBuffer;
begin
  LClockObj := TMockClock.Create(1000000);
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
  LConcrete: TFleetTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LBefore, LAfter: TBytes;
  LKey: ISecretBuffer;
  LRaised: Boolean;
begin
  LConcrete := TFleetTicketKeyManager.Create;
  LStek := LConcrete;
  LConcrete.InstallKey(Tag($11, 16), TSecretBuffer.From(Tag($22, 32)));
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
  LConcrete: TFleetTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LBefore, LAfter: TBytes;
  LKey: ISecretBuffer;
  LRaised: Boolean;
begin
  LConcrete := TFleetTicketKeyManager.Create;
  LStek := LConcrete;
  LConcrete.InstallKey(Tag($11, 16), TSecretBuffer.From(Tag($22, 32)));
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
  LConcrete: TFleetTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LBefore, LAfter: TBytes;
  LKey: ISecretBuffer;
  LRaised: Boolean;
begin
  LConcrete := TFleetTicketKeyManager.Create;
  LStek := LConcrete;
  LConcrete.InstallKey(Tag($11, 16), TSecretBuffer.From(Tag($22, 32)));
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

procedure TTestSessionStore.TestStekFleetKeysRetireOnlyByNewerInstalls;
var
  LConcrete: TFleetTicketKeyManager;
  LStek: ISessionTicketKeyManager;
  LInstalled, LName: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LConcrete := TFleetTicketKeyManager.Create(2);
  LStek := LConcrete;
  LInstalled := Tag($55, 16);
  LConcrete.InstallKey(LInstalled, TSecretBuffer.From(Tag($66, 32)));
  CheckTrue(LStek.CurrentKey(LName, LKey), 'the installed key seals');
  CheckTrue(AreEqual(LInstalled, LName), 'under the installed name');
  // the operator retires an old key by installing newer ones until the window pushes it out
  LConcrete.InstallKey(Tag($77, 16), TSecretBuffer.From(Tag($88, 32)));
  CheckTrue(LStek.KeyByName(LInstalled, LFound), 'the first key is still inside the window');
  LConcrete.InstallKey(Tag($99, 16), TSecretBuffer.From(Tag($AA, 32)));
  CheckFalse(LStek.KeyByName(LInstalled, LFound),
    'the first installed key falls out of the window once newer keys arrive');
end;

procedure TTestSessionStore.TestStekRotateDoesNotShortenTimer;
var
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: IRotatingTicketKeyManager;
  LNameA, LName: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  LClockObj := TMockClock.Create(1000000);
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
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LNameA, LName: TBytes;
  LKey, LFound: ISecretBuffer;
  LRaised: Boolean;
begin
  LClockObj := TMockClock.Create(1000000);
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

procedure TTestSessionStore.TestStekExtremeAgeBoundDoesNotExpireKeys;
var
  LClockObj: TMockClock;
  LClock: ITlsClock;
  LStek: ISessionTicketKeyManager;
  LName1, LName2: TBytes;
  LKey, LFound: ISecretBuffer;
begin
  // an extreme window x interval whose product overflows UInt64 must become the "never expire"
  // bound, not wrap to a tiny (here zero) residue that prunes every key on each call and silently
  // disables resumption. Window 2^30 x interval 2^31 s wraps the raw product to 0.
  LClockObj := TMockClock.Create(1000000);
  LClock := LClockObj;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom, 1073741824, LClock,
    UInt32(2147483648));
  CheckTrue(LStek.CurrentKey(LName1, LKey), 'a key is minted');
  LClockObj.Advance(1000);
  CheckTrue(LStek.CurrentKey(LName2, LKey), 'the key is still current after time passes');
  CheckEqualBytes('the extreme age bound did not expire the key', LName1, LName2);
  CheckTrue(LStek.KeyByName(LName1, LFound), 'the original key is still found by name');
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
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TScriptedTicketKeys.Create(16, nil, Tag($AB, 16)) as ISessionTicketKeyManager);
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
    THashAlgorithm.SHA_256, TSecretBuffer.From(Tag($5E, 32)), TBytes.Create($00, $FF, $B2),
    'host.example', Tag($AB, 4), 3600, $11223344, 1000, 4096, LChain, Tag($5C, 3));
  LTicket := LStrategy.Seal(LOriginal);
  CheckTrue(System.Length(LTicket) > 0, 'a 1.3 session seals to a ticket');
  CheckTrue(LStrategy.Open(LTicket, LOpened), 'the ticket opens');
  CheckTrue(Supports(LOpened, ITls13ResumableSession, L13),
    'the opened session is a 1.3 sub-interface');
  CheckFalse(Supports(LOpened, ITls12ResumableSession, L12),
    'a 1.3 session is not a 1.2 sub-interface');
  CheckEquals(Integer(TCipherSuites13.Aes128GcmSha256), Integer(LOpened.CipherSuite),
    'the suite round-trips');
  CheckEqualBytes('a binary ALPN name round-trips', TBytes.Create($00, $FF, $B2), LOpened.Alpn);
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
    TSecretBuffer.From(Tag($4D, 48)), Tag($01, 32), Tag($02, 16), True, nil,
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

procedure TTestSessionStore.TestStekSealDeclinesWhenProviderLacksTicketAead;
var
  LStrategy: ISessionTicketStrategy;
begin
  LStrategy := TStekTicketStrategy.Create(TMissingAeadProvider.Create(Crypto,
    TAeadAlgorithm.AES_256_GCM) as ICryptoProvider,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  CheckEquals(0, System.Length(LStrategy.Seal(MakeTls12Session(Tag($01, 4)))),
    'no ticket is sealed');
end;

procedure TTestSessionStore.TestStekOpenUnreadableWhenProviderLacksTicketAead;
var
  LKeys: ISessionTicketKeyManager;
  LHealthy, LLacking: ISessionTicketStrategy;
  LTicket: TBytes;
  LOpened: IResumableSession;
begin
  LKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LHealthy := TStekTicketStrategy.Create(Crypto, LKeys);
  LLacking := TStekTicketStrategy.Create(TMissingAeadProvider.Create(Crypto,
    TAeadAlgorithm.AES_256_GCM) as ICryptoProvider, LKeys);
  LTicket := LHealthy.Seal(MakeTls12Session(Tag($01, 4)));
  CheckTrue(System.Length(LTicket) > 0, 'a healthy provider sealed the ticket');
  CheckFalse(LLacking.Open(LTicket, LOpened), 'the ticket is unreadable');
  CheckTrue(LOpened = nil, 'no session is returned');
end;

procedure TTestSessionStore.TestStekSealDeclinesWhenTicketAeadRaisesATlsLibError;
var
  LStrategy: ISessionTicketStrategy;
begin
  LStrategy := TStekTicketStrategy.Create(TMissingAeadProvider.CreateFault(Crypto,
    TAeadAlgorithm.AES_256_GCM, EBaseTlsLibException) as ICryptoProvider,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  CheckEquals(0, System.Length(LStrategy.Seal(MakeTls12Session(Tag($01, 4)))),
    'no ticket is sealed');
end;

procedure TTestSessionStore.TestStekOpenUnreadableWhenTicketAeadRaisesATlsLibError;
var
  LKeys: ISessionTicketKeyManager;
  LHealthy, LFaulting: ISessionTicketStrategy;
  LTicket: TBytes;
  LOpened: IResumableSession;
begin
  LKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LHealthy := TStekTicketStrategy.Create(Crypto, LKeys);
  LFaulting := TStekTicketStrategy.Create(TMissingAeadProvider.CreateFault(Crypto,
    TAeadAlgorithm.AES_256_GCM, EBaseTlsLibException) as ICryptoProvider, LKeys);
  LTicket := LHealthy.Seal(MakeTls12Session(Tag($01, 4)));
  CheckTrue(System.Length(LTicket) > 0, 'a healthy provider sealed the ticket');
  CheckFalse(LFaulting.Open(LTicket, LOpened), 'the ticket is unreadable');
  CheckTrue(LOpened = nil, 'no session is returned');
end;

function TTestSessionStore.SealRaisedFrom(AFault: ExceptClass): Boolean;
var
  LStrategy: ISessionTicketStrategy;
begin
  Result := False;
  LStrategy := TStekTicketStrategy.Create(TMissingAeadProvider.CreateFault(Crypto,
    TAeadAlgorithm.AES_256_GCM, AFault) as ICryptoProvider,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  try
    LStrategy.Seal(MakeTls12Session(Tag($01, 4)));
  except
    on E: Exception do
      Result := E.ClassType = AFault;
  end;
end;

function TTestSessionStore.OpenRaisedFrom(AFault: ExceptClass): Boolean;
var
  LKeys: ISessionTicketKeyManager;
  LHealthy, LStrategy: ISessionTicketStrategy;
  LTicket: TBytes;
  LOpened: IResumableSession;
begin
  Result := False;
  LKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LHealthy := TStekTicketStrategy.Create(Crypto, LKeys);
  LTicket := LHealthy.Seal(MakeTls12Session(Tag($01, 4)));
  LStrategy := TStekTicketStrategy.Create(TMissingAeadProvider.CreateFault(Crypto,
    TAeadAlgorithm.AES_256_GCM, AFault) as ICryptoProvider, LKeys);
  try
    LStrategy.Open(LTicket, LOpened);
  except
    on E: Exception do
      Result := E.ClassType = AFault;
  end;
end;

procedure TTestSessionStore.TestStekSealLetsAPlainExceptionThrough;
begin
  CheckTrue(SealRaisedFrom(Exception), 'a provider programming fault is not a missing AEAD');
end;

procedure TTestSessionStore.TestStekOpenLetsAPlainExceptionThrough;
begin
  CheckTrue(OpenRaisedFrom(Exception), 'a provider programming fault is not a missing AEAD');
end;

function TTestSessionStore.SealedTls12WithGroupAndScheme(
  const AStrategy: ISessionTicketStrategy): IResumableSession;
begin
  CheckTrue(AStrategy.Open(AStrategy.Seal(TTls12ResumableSession.Create(
    TCipherSuites12.EcdheEcdsaAes128GcmSha256, THashAlgorithm.SHA_256,
    TSecretBuffer.From(Tag($4D, 48)), nil, nil, True, nil, 'legacy.example', 1800, 2000, nil,
    nil, nil, nil, $001D, $0403, 1500) as IResumableSession), Result), 'the ticket opens');
end;

procedure TTestSessionStore.TestStekSealOpenCarriesTls12Group;
var
  LStrategy: ISessionTicketStrategy;
  L12: ITls12ResumableSession;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  CheckTrue(Supports(SealedTls12WithGroupAndScheme(LStrategy), ITls12ResumableSession, L12),
    'a 1.2 session');
  CheckEquals($001D, L12.NamedGroup, 'the original handshake''s group round-trips');
end;

procedure TTestSessionStore.TestStekSealOpenCarriesTls12PeerSignatureScheme;
var
  LStrategy: ISessionTicketStrategy;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  CheckEquals($0403, SealedTls12WithGroupAndScheme(LStrategy).PeerSignatureScheme,
    'the peer signature scheme round-trips');
end;

procedure TTestSessionStore.TestLargestSealedTicketIsTheCachedLimit;
var
  LStrategy: ISessionTicketStrategy;
  LTicket, LLargest: TBytes;
  LSize: Int32;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  // grow the peer chain until the sealer declines: the last ticket it made is the largest it can
  LLargest := nil;
  LSize := 15000;
  repeat
    LTicket := LStrategy.Seal(TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
      THashAlgorithm.SHA_256, TSecretBuffer.From(Tag($5E, 32)), nil, 'host.example', Tag($AB, 4),
      3600, 1, 1000, 0, TArray<TBytes>.Create(Tag($C0, LSize)), nil) as IResumableSession);
    if System.Length(LTicket) > 0 then
      LLargest := LTicket;
    System.Inc(LSize);
  until (System.Length(LTicket) = 0) or (LSize > 17000);
  CheckEquals(TSessionTicketLimits.MaxCachedTicketBytes, System.Length(LLargest),
    'the largest ticket the sealer makes is the largest a client caches');
end;

procedure TTestSessionStore.TestStekSealOpenCarriesTls13PeerSignatureScheme;
var
  LStrategy: ISessionTicketStrategy;
  LOpened: IResumableSession;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  CheckTrue(LStrategy.Open(LStrategy.Seal(TTls13ResumableSession.Create(
    TCipherSuites13.Aes128GcmSha256, THashAlgorithm.SHA_256, TSecretBuffer.From(Tag($5E, 32)),
    nil, 'host.example', Tag($AB, 4), 3600, $11223344, 1000, 4096, nil, nil, nil, nil, $0804, 700)
    as IResumableSession), LOpened), 'the ticket opens');
  CheckEquals($0804, LOpened.PeerSignatureScheme, 'the peer signature scheme round-trips');
end;

procedure TTestSessionStore.TestStekSealOpenCarriesTls13AuthenticatedAt;
var
  LStrategy: ISessionTicketStrategy;
  LOpened: IResumableSession;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  // an authentication time beyond 32 bits, apart from the issue time, so neither half can be swapped
  CheckTrue(LStrategy.Open(LStrategy.Seal(TTls13ResumableSession.Create(
    TCipherSuites13.Aes128GcmSha256, THashAlgorithm.SHA_256, TSecretBuffer.From(Tag($5E, 32)),
    nil, 'host.example', Tag($AB, 4), 3600, $11223344, 1000, 4096, nil, nil, nil, nil, $0804,
    UInt64($0000012345678ABC)) as IResumableSession), LOpened), 'the ticket opens');
  CheckTrue(UInt64($0000012345678ABC) = LOpened.AuthenticatedAtMillis,
    'the 1.3 authentication time round-trips');
  CheckTrue(1000 = LOpened.IssuedAtMillis, 'the issue time stays its own field');
end;

procedure TTestSessionStore.TestStekSealOpenCarriesTls12AuthenticatedAt;
var
  LStrategy: ISessionTicketStrategy;
begin
  LStrategy := TStekTicketStrategy.Create(Crypto,
    TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager);
  CheckTrue(1500 = SealedTls12WithGroupAndScheme(LStrategy).AuthenticatedAtMillis,
    'the 1.2 authentication time round-trips');
end;

procedure TTestSessionStore.TestStekV10TicketIsDeclined;
var
  LKeys: ISessionTicketKeyManager;
  LStrategy: ISessionTicketStrategy;
  LTicket, LKeyName, LNonce, LPlain, LCipher: TBytes;
  LKey: ISecretBuffer;
  LAead: IAead;
  LNameLen: Int32;
  LOpened: IResumableSession;
begin
  LKeys := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom) as ISessionTicketKeyManager;
  LStrategy := TStekTicketStrategy.Create(Crypto, LKeys);
  LTicket := LStrategy.Seal(TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(Tag($5E, 32)), nil, 'host.example', Tag($AB, 4),
    3600, 1, 1000, 0, nil, nil) as IResumableSession);
  CheckTrue(LStrategy.Open(LTicket, LOpened), 'control: the current format opens');
  // re-seal the same body under the same key, relabelled as format 10 (the format before the
  // authentication time was added); the version is the leading big-endian uint32
  LNameLen := LKeys.KeyNameLength;
  LKeyName := System.Copy(LTicket, 0, LNameLen);
  LNonce := System.Copy(LTicket, LNameLen, 12);
  CheckTrue(LKeys.KeyByName(LKeyName, LKey), 'the ticket key is held');
  LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
  LAead.Init(LKey);
  LPlain := TAeadUtilities.Open(LAead, LNonce, LKeyName,
    System.Copy(LTicket, LNameLen + 12, System.Length(LTicket) - LNameLen - 12));
  CheckEquals(11, Integer(LPlain[3]), 'the current format is 11');
  LPlain[3] := 10;
  LNonce := Crypto.Primitives.GetRandom.GenerateBytes(12);
  LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
  LAead.Init(LKey);
  LCipher := TAeadUtilities.Seal(LAead, LNonce, LKeyName, LPlain);
  LTicket := ConcatBytes(ConcatBytes(LKeyName, LNonce), LCipher);
  CheckFalse(LStrategy.Open(LTicket, LOpened), 'a format 10 ticket draws a full handshake');
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

procedure TTestSessionStore.TestAntiReplayReRecordDoesNotEvictLiveValue;
var
  LReplay: IAntiReplayStrategy;
  LGuard, LValue, LHold, LFill: TBytes;
begin
  // re-recording a value after it expired, while a live entry recorded between its two records sits
  // ahead of it, leaves a stale order entry; the register at capacity must neither evict the value's
  // live entry nor admit a further value
  LReplay := TStrikeRegisterAntiReplay.Create(3);
  LGuard := Tag($11, 8);
  LValue := Tag($AA, 8);
  LHold := Tag($33, 8);
  LFill := Tag($44, 8);
  CheckTrue(LReplay.CheckAndRecord(LGuard, 1000, 100000), 'guard recorded');
  CheckTrue(LReplay.CheckAndRecord(LValue, 1000, 2000), 'value recorded');
  CheckTrue(LReplay.CheckAndRecord(LHold, 1500, 100000), 'a live entry recorded after the value');
  CheckTrue(LReplay.CheckAndRecord(LValue, 3000, 100000), 'value re-recorded after expiry');
  CheckFalse(LReplay.CheckAndRecord(LFill, 4000, 100000), 'a new value at capacity is declined');
  CheckFalse(LReplay.CheckAndRecord(LValue, 4000, 100000),
    'the re-recorded value is still a replay');
end;

procedure TTestSessionStore.TestAntiReplayDeclinesAtCapacityWithoutEvicting;
var
  LReplay: IAntiReplayStrategy;
  LVictim: TBytes;
  LI: Int32;
begin
  LReplay := TStrikeRegisterAntiReplay.Create(4);
  LVictim := Tag($C0, 8);
  CheckTrue(LReplay.CheckAndRecord(LVictim, 1000, 100000), 'victim recorded');
  for LI := 0 to 19 do
    LReplay.CheckAndRecord(Tag(Byte(LI), 8), 1000, 100000);
  CheckTrue(LReplay.Count <= 4, 'the register never grows past its cap');
  CheckFalse(LReplay.CheckAndRecord(LVictim, 1001, 100000),
    'a flood of unique values does not evict the live victim; its replay is declined');
end;

procedure TTestSessionStore.TestAntiReplayCompactionKeepsLiveEntries;
var
  LReplay: IAntiReplayStrategy;
  LGuard, LValue: TBytes;
  LNow: UInt64;
  LI: Int32;
begin
  LReplay := TStrikeRegisterAntiReplay.Create(2);
  LGuard := Tag($01, 8);
  LValue := Tag($02, 8);
  CheckTrue(LReplay.CheckAndRecord(LGuard, 1000, 100000), 'guard recorded');
  CheckTrue(LReplay.CheckAndRecord(LValue, 1000, 2000), 'value recorded');
  // each re-record after expiry leaves a stale order entry behind the live guard, driving the
  // queue past twice the capacity so it is compacted
  for LI := 1 to 8 do
  begin
    LNow := 2000 + UInt64(LI) * 1000;
    CheckTrue(LReplay.CheckAndRecord(LValue, LNow, LNow + 500), 'value re-recorded');
  end;
  CheckFalse(LReplay.CheckAndRecord(LValue, 10001, 20000), 'value still a replay');
  CheckFalse(LReplay.CheckAndRecord(LGuard, 10001, 100000), 'guard still a replay');
  CheckEquals(2, LReplay.Count, 'count unchanged by compaction');
  CheckFalse(LReplay.CheckAndRecord(Tag($03, 8), 10001, 20000), 'a new value is declined at capacity');
  // the value has lapsed behind the live guard, so compaction left the queue out of expiry order
  // and the next admission must still sweep it
  CheckTrue(LReplay.CheckAndRecord(Tag($04, 8), 11000, 20000),
    'admitted: the lapsed short entry behind the live guard is swept after compaction');
  CheckTrue(LReplay.CheckAndRecord(Tag($03, 8), 100001, 200000), 'admitted once the entries expired');
end;

procedure TTestSessionStore.TestAntiReplayAdmitsAfterExpiryAtCapacity;
var
  LReplay: IAntiReplayStrategy;
  LI: Int32;
begin
  LReplay := TStrikeRegisterAntiReplay.Create(3);
  for LI := 0 to 2 do
    CheckTrue(LReplay.CheckAndRecord(Tag(Byte(LI), 8), 1000, 2000), 'filled');
  CheckFalse(LReplay.CheckAndRecord(Tag($50, 8), 1500, 3000), 'declined while full and live');
  CheckTrue(LReplay.CheckAndRecord(Tag($50, 8), 2500, 4000), 'admitted once the entries expired');
end;

procedure TTestSessionStore.TestAntiReplayAdmitsAfterAnEarlierExpiryBehindALiveFront;
var
  LReplay: IAntiReplayStrategy;
begin
  // callers may pass differing windows, so the queue front (a long window) can be live while a later
  // entry (a short window) has already lapsed: at capacity the lapsed one must not block a new value
  LReplay := TStrikeRegisterAntiReplay.Create(2);
  CheckTrue(LReplay.CheckAndRecord(Tag($01, 8), 1000, 100000), 'long window recorded');
  CheckTrue(LReplay.CheckAndRecord(Tag($02, 8), 1000, 2000), 'short window recorded');
  CheckFalse(LReplay.CheckAndRecord(Tag($03, 8), 1500, 9000), 'declined while both are live');
  CheckTrue(LReplay.CheckAndRecord(Tag($03, 8), 2500, 9000),
    'admitted: the lapsed short-window entry behind the live front is swept');
  CheckFalse(LReplay.CheckAndRecord(Tag($01, 8), 2600, 100000),
    'the live long-window value is still a replay');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSessionStore);
{$ELSE}
  RegisterTest(TTestSessionStore.Suite);
{$ENDIF FPC}

end.
