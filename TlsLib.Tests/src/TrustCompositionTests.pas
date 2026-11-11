{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Exercises the trust-composition rules of the verification policies: the anchors of a
/// WebPki policy UNION (stores and root blobs together), while a whole certificate verifier is a
/// kind of its own that takes no anchors at all - the invariant the OS system-trust sources rely
/// on, now unrepresentable rather than refused at Build.</summary>
unit TrustCompositionTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsLibExceptions,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpServerName,
  TlpTrustTypes,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpILayeredTrustAnchorStore,
  TlpTrustAnchorStore,
  TlpIIssuerLookup,
  TlpICertificateVerifierSource,
  TlpIssuerLookupVerifierSource,
  TlpIssuerResolution,
  TlpIPkixProvider,
  TlpTrustPolicy,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpPkixDomainTypes,
  TlpNegotiationTypes,
  TlpIClock,
  TlpClock,
  TlpISession,
  TlpInMemorySessionCache,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpTlsCredential,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  MockCertificateVerifiers,
  MockPkixProvider,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase,
  TlsLibTestBase;

type
  TTestTrustComposition = class(TTlsLibAlgorithmTestCase)
  private
    FCerts: TStringList;
    function StoreOf(const AFieldName: string): ITrustAnchorStore;
    function UnionOverWatchedStore(AReleased: PBoolean): ITrustAnchorStore;
    function LayeredOverWatchedStore(AReleased: PBoolean): ITrustAnchorStore;
    function Der(const AFieldName: string): TBytes;
  protected
    procedure SetUp; override;
  published
    procedure TestTwoAnchorStoresUnionIntoComposedStore;
    procedure TestDistrustingStoreDropsDistrustedRootsAndIsImmutable;
    procedure TestUnionCarriesAndAppliesDistrustAcrossStores;
    procedure TestBuildFreezesDistrustWithTheComposedStore;
    procedure TestUnionCollapsesDuplicatesAndSkipsNilChildren;
    procedure TestUnionKeepsItsSourceStoresAlive;
    procedure TestAnchorMatchIsExactDer;
    // layered store: a few extra roots over a base that is never copied
    procedure TestLayeredStoreAnswersLikeAUnion;
    procedure TestLayeredStoreRefusesWhatTheBaseDistrusts;
    procedure TestLayeredStoreReturnsItsBaseWhenNothingIsAdded;
    procedure TestLayeredStoreOverNoBaseSitsOnAnEmptyBase;
    procedure TestLayeredStoreOverNoBaseAndNoExtrasIsEmpty;
    procedure TestLayeredStoreOverALayeredStoreIsOneLayer;
    procedure TestLayeredStoreKeepsItsBaseAlive;
    procedure TestBuildRefusesAUnionWhoseDistrustRemovesEveryAnchor;
    procedure TestCertificateVerifierLandsInFrozenConfig;
  end;

  /// <summary>The issuer-lookup seam: the decorators resolve the issuers a peer chain names from a
  /// lookup that records the names it is asked, for each role, and the engine factory applies them
  /// without ever storing them in a config.</summary>
  TTestIssuerLookup = class(TTlsLibHandshakeTestCase)
  strict private
    FLookup: TRecordingIssuerLookup;
    FLookupRef: IIssuerLookup;
    FCapture: TCapturingVerifierSource;
    FCaptureRef: IServerCertificateVerifierSource;
    FRoot, FIssuer, FLeaf, FRootName, FIssuerName, FLeafName: TBytes;
    FUnrelated: ITrustAnchorStore;
    FRule: TBundleAnchorRule;
    function ServerContext(const AStore: ITrustAnchorStore): TServerTrustContext;
    function ClientContext(const AStore: ITrustAnchorStore): TClientTrustContext;
    // the server-role decorator over AInner, as the verifier it builds for AContext
    function ServerVerifier(const AInner: IServerCertificateVerifierSource;
      const AContext: TServerTrustContext): IServerCertificateVerifier;
    function ClientVerifier(const AInner: IClientCertificateVerifierSource;
      const AContext: TClientTrustContext): IClientCertificateVerifier;
    function ServerVerdict(const AVerifier: IServerCertificateVerifier;
      const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
    function ClientVerdict(const AVerifier: IClientCertificateVerifier;
      const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
    function AuthCredential: TTlsCredential;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestLookedUpRootAnchorsAServerChain;
    procedure TestLookedUpRootAnchorsAClientChain;
    procedure TestLookupAloneAnchorsAChainWithNoStaticStore;
    procedure TestOnlyIssuerNamesAreAsked;
    procedure TestEachNameIsAskedOnce;
    procedure TestOverLimitServerChainIsRefusedBeforeAnyLookup;
    procedure TestOverLimitClientChainIsRefusedBeforeAnyLookup;
    procedure TestChainAtTheLimitIsLookedUp;
    procedure TestLookedUpIntermediateAndRootCompleteALeafOnlyChain;
    procedure TestLookedUpIntermediateAloneIsNotAnAnchor;
    procedure TestNonSelfSignedCertificateOfferedAsAnAnchorIsChainMaterialOnly;
    procedure TestCertificateUnderAnotherNameIsIgnored;
    procedure TestWeakLookedUpAnchorIsRefused;
    procedure TestStaticDistrustBeatsALookedUpAnchor;
    procedure TestStaticDistrustKeepsALookedUpAnchorOutOfTheStore;
    procedure TestUnreadableBlobsAreSkipped;
    procedure TestALookupThatRaisesGivesUnknownCa;
    procedure TestALookupWithNoAnswerGivesUnknownCa;
    procedure TestLookedUpAnchorsDoNotLeakIntoTheNextVerification;
    procedure TestNothingFoundHandsTheInnerTheSameStore;
    procedure TestSomethingFoundHandsTheInnerALayeredStoreAndTheIntermediates;
    procedure TestARingOfIssuersTerminatesAndEachNameIsAskedOnce;
    procedure TestTheWalkStopsAtThePathBuildingDepth;
    procedure TestAnIntermediateThePeerSentIsNotFoundAgain;
    procedure TestAConfiguredIntermediateIsNotFoundAgain;
    procedure TestAConfiguredIntermediateOffTheChainIsNotWalked;
    procedure TestAConfiguredIntermediateOnTheChainLeadsToALookedUpRoot;
    procedure TestAnAnswerWhoseNameCannotBeComparedIsIgnored;
    procedure TestServerDecoratorSurfacesTheInnerRefusalAtCreation;
    procedure TestClientDecoratorSurfacesTheInnerRefusalAtCreation;
    procedure TestServerDecoratorRefusesANilLookup;
    procedure TestServerDecoratorRefusesANilSource;
    procedure TestClientDecoratorRefusesANilLookup;
    procedure TestClientDecoratorRefusesANilSource;
    // the anchor rule
    procedure TestAnyCertificateAnchorsALookedUpIntermediate;
    procedure TestSelfSignedOnlyDoesNotAnchorALookedUpIntermediate;
    procedure TestAnyCertificateStillHoldsALookedUpAnchorToTheKeyFloors;
    procedure TestAnyCertificateKeepsStaticDistrust;
  end;

  /// <summary>The issuer lookup as an input of the verification policies, through the role-split
  /// config builders and the engine factory: it is the trust source on its own, works beside any
  /// built-in or source policy, and makes a resuming client re-verify.</summary>
  TTestIssuerLookupConfig = class(TTlsLibHandshakeTestCase)
  strict private
    FLookup: TRecordingIssuerLookup;
    FLookupRef: IIssuerLookup;
    FCapture: TCapturingVerifierSource;
    FCaptureRef: IServerCertificateVerifierSource;
    FUnrelated: ITrustAnchorStore;
    function AuthCredential: TTlsCredential;
    function ClientBuilder: ITlsClientConfigBuilder;
    function ServerBuilder: ITlsServerConfigBuilder;
    function ServerBuildRaises(const ABuilder: ITlsServerConfigBuilder): Boolean;
    function ResumingClient: ITlsClientConfigBuilder;
    // the lookup offers an intermediate as an anchor and the server sends only the leaf under it:
    // True when the client config under ARule completes the handshake
    function HandshakeAnchoredAtTheIssuer(ARule: TBundleAnchorRule): Boolean;
    // the same for a client leaf under an intermediate the lookup offers: True when the server
    // config under ARule accepts the client
    function ServerHandshakeAnchoredAtTheIssuer(ARule: TBundleAnchorRule): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestClientConfigCarriesTheLookupAndTheDefaultRule;
    procedure TestServerConfigCarriesTheLookupAndTheDefaultRule;
    procedure TestClientConfigCarriesAnExplicitRule;
    procedure TestServerConfigCarriesAnExplicitRule;
    procedure TestClientConfigWithoutALookupCarriesNone;
    procedure TestVerificationBuildersDefaultTheRuleToSelfSignedOnly;
    procedure TestServerVerificationBuilderRefusesANilLookup;
    procedure TestClientVerificationBuilderRefusesANilLookup;
    procedure TestServerVerificationFactoryRefusesANilLookup;
    procedure TestClientVerificationFactoryRefusesANilLookup;
    procedure TestWebPkiWithNeitherRootsNorLookupIsRefusedAtBuild;
    procedure TestALookupAloneSatisfiesTheWebPkiTrustSource;
    procedure TestLookupOnlyServerVerificationCarriesPostureFloorsAndIntermediates;
    procedure TestLookupOnlyClientVerificationCarriesPostureFloorsAndIntermediates;
    procedure TestLookupOnlyClientConfigCarriesPostureAndFloors;
    procedure TestLookupAndRootsUnionOnAHandshake;
    procedure TestRootsAloneRefuseWhatTheLookupWouldTrust;
    procedure TestALaterVerificationReplacesTheLookup;
    procedure TestOneLookupServesBothRolesAndEachRoleAppliesItsOwnGuards;
    procedure TestLookupAloneIsAClientTrustSourceAndVerifiesTheServer;
    procedure TestLookupAloneIsAClientAuthTrustSourceAndVerifiesTheClient;
    procedure TestLookupBesideAClientVerifierSourceBuildsAndKeepsTheSource;
    procedure TestLookupBesideAServerVerifierSourceBuildsAndKeepsTheSource;
    procedure TestABuiltInSourceStaysBuiltInWithALookup;
    procedure TestServerLookupWithoutPeerAuthIsRefused;
    procedure TestServerPeerAuthWithAVerifierSourceAndNoRootsBuildsOnALookup;
    procedure TestFactoryPassesAnyCertificateToTheDecorator;
    procedure TestFactoryPassesSelfSignedOnlyToTheDecorator;
    procedure TestServerFactoryPassesAnyCertificateToTheDecorator;
    procedure TestServerFactoryPassesSelfSignedOnlyToTheDecorator;
    procedure TestHardPostureRefusesTheDefaultReverifyAndNamesTheWayOut;
    procedure TestEarlyDataBesideAnAsyncVerdictRefusesTheDefaultReverifyAndNamesTheWayOut;
    procedure TestResumingClientWithALookupDefaultsToReverify;
    procedure TestAnExplicitReuseOriginalBesideALookupIsKept;
    procedure TestResumingClientWithoutALookupKeepsReuseOriginal;
    procedure TestClientLookupWithoutACacheStillBuilds;
  end;

implementation

type
  /// <summary>A one-root store that reports when it is destroyed, to prove what keeps a store
  /// alive.</summary>
  TReleaseWatchStore = class(TInterfacedObject, ITrustAnchorStore)
  strict private
    FRoot: TBytes;
    FReleased: PBoolean;
  public
    constructor Create(const ARoot: TBytes; AReleased: PBoolean);
    destructor Destroy; override;
    function AnchorCount: Int32;
    function RootCertificates: TArray<TBytes>;
    function IsAnchor(const ACertificate: TBytes): Boolean;
    function DistrustedCertificates: TArray<TBytes>;
    function IsDistrusted(const ACertificate: TBytes): Boolean;
  end;

{ TReleaseWatchStore }

constructor TReleaseWatchStore.Create(const ARoot: TBytes; AReleased: PBoolean);
begin
  inherited Create;
  FRoot := ARoot;
  FReleased := AReleased;
end;

destructor TReleaseWatchStore.Destroy;
begin
  FReleased^ := True;
  inherited Destroy;
end;

function TReleaseWatchStore.AnchorCount: Int32;
begin
  Result := 1;
end;

function TReleaseWatchStore.RootCertificates: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(FRoot);
end;

function TReleaseWatchStore.IsAnchor(const ACertificate: TBytes): Boolean;
begin
  Result := (System.Length(ACertificate) = System.Length(FRoot)) and
    CompareMem(PByte(ACertificate), PByte(FRoot), System.Length(FRoot));
end;

function TReleaseWatchStore.DistrustedCertificates: TArray<TBytes>;
begin
  Result := nil;
end;

function TReleaseWatchStore.IsDistrusted(const ACertificate: TBytes): Boolean;
begin
  Result := False;
end;

{ TTestTrustComposition }

procedure TTestTrustComposition.SetUp;
begin
  inherited SetUp;
  FCerts := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
end;

function TTestTrustComposition.StoreOf(const AFieldName: string): ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values[AFieldName]))) as ITrustAnchorStore;
end;

procedure TTestTrustComposition.TestTwoAnchorStoresUnionIntoComposedStore;
var
  LConfig: ITlsClientConfig;
begin
  // two distinct single-anchor stores added separately must both survive into the frozen config
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
    TArray<ITrustAnchorStore>.Create(StoreOf('root_cert'), StoreOf('leaf_cert')), nil).Build)
    .Build;
  CheckEquals(2, System.Length(LConfig.TrustStore.RootCertificates),
    'both anchor sources union into the composed trust store');
  CheckTrue(LConfig.ServerVerifierSource <> nil,
    'no whole-verifier was set, so the built-in verifier source is installed by default');
end;

procedure TTestTrustComposition.TestDistrustingStoreDropsDistrustedRootsAndIsImmutable;
var
  LRoots, LDistrusted: TArray<TBytes>;
  LStore: ITrustAnchorStore;
begin
  LRoots := TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']),
    DecodeHex(FCerts.Values['leaf_cert']));
  LDistrusted := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  LStore := TTrustAnchorStore.Create(LRoots, LDistrusted);
  CheckEquals(1, System.Length(LStore.RootCertificates), 'a distrusted root is not an anchor');
  CheckEquals(1, LStore.AnchorCount, 'the count excludes the distrusted root');
  CheckFalse(LStore.IsAnchor(LDistrusted[0]), 'a distrusted certificate is not an anchor');
  CheckEquals(1, System.Length(LStore.DistrustedCertificates), 'the distrust set is carried');
  CheckTrue(LStore.IsDistrusted(LDistrusted[0]), 'the distrusted certificate matches');
  CheckFalse(LStore.IsDistrusted(LRoots[0]), 'an anchor is not distrusted');
  // the store owns its sets: later changes to the inputs or the returned copies do not reach it
  LDistrusted[0][0] := LDistrusted[0][0] xor $FF;
  LStore.DistrustedCertificates[0][0] := 0;
  CheckTrue(LStore.IsDistrusted(DecodeHex(FCerts.Values['leaf_cert'])),
    'the distrust set is an immutable snapshot');
end;

procedure TTestTrustComposition.TestUnionCarriesAndAppliesDistrustAcrossStores;
var
  LUnion: ITrustAnchorStore;
begin
  // one store distrusts the leaf; another contributes it as an anchor: distrust wins
  LUnion := TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(
    StoreOf('root_cert'), StoreOf('leaf_cert'),
    TTrustAnchorStore.Create(nil,
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']))) as ITrustAnchorStore));
  CheckEquals(1, System.Length(LUnion.RootCertificates),
    'a root distrusted by any store is not an anchor of the union');
  CheckTrue(LUnion.IsDistrusted(DecodeHex(FCerts.Values['leaf_cert'])), 'it carries the child distrust');
  CheckEquals(1, System.Length(LUnion.DistrustedCertificates), 'the union of the distrust sets');
end;

procedure TTestTrustComposition.TestUnionCollapsesDuplicatesAndSkipsNilChildren;
var
  LUnion, LSingle: ITrustAnchorStore;
begin
  LUnion := TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(
    StoreOf('root_cert'), nil, StoreOf('root_cert'), StoreOf('leaf_cert')));
  CheckEquals(2, LUnion.AnchorCount, 'a root contributed twice is one anchor');
  CheckEquals(2, System.Length(LUnion.RootCertificates), 'the copy agrees with the count');
  // a single remaining child is the union itself: its identity is kept for the provider's cache
  LSingle := StoreOf('root_cert');
  CheckTrue(TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(nil, LSingle)) = LSingle,
    'one live child is returned as it is');
  CheckEquals(0, TTrustAnchorStore.Union(nil).AnchorCount, 'no child is an empty store');
end;

function TTestTrustComposition.UnionOverWatchedStore(AReleased: PBoolean): ITrustAnchorStore;
var
  LWatched: ITrustAnchorStore;
begin
  LWatched := TReleaseWatchStore.Create(DecodeHex(FCerts.Values['root_cert']), AReleased);
  Result := TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(LWatched,
    StoreOf('leaf_cert')));
end;

procedure TTestTrustComposition.TestUnionKeepsItsSourceStoresAlive;
var
  LUnion: ITrustAnchorStore;
  LReleased: Boolean;
begin
  // an identity-keyed cache may sign a source store by address; the union must hold it so that
  // address cannot be reused by another store while the union lives. The helper's own references
  // are gone by the time it returns, so only the union can be keeping the store.
  LReleased := False;
  LUnion := UnionOverWatchedStore(@LReleased);
  CheckFalse(LReleased, 'the union still holds the source store');
  LUnion := nil;
  CheckTrue(LReleased, 'the source store is released with the union');
end;

function TTestTrustComposition.Der(const AFieldName: string): TBytes;
begin
  Result := DecodeHex(FCerts.Values[AFieldName]);
end;

function TTestTrustComposition.LayeredOverWatchedStore(AReleased: PBoolean): ITrustAnchorStore;
var
  LWatched: ITrustAnchorStore;
begin
  LWatched := TReleaseWatchStore.Create(Der('root_cert'), AReleased);
  Result := TTrustAnchorStore.Layered(LWatched, TArray<TBytes>.Create(Der('leaf_cert')));
end;

procedure TTestTrustComposition.TestLayeredStoreAnswersLikeAUnion;
var
  LBase, LExtra, LLayered, LUnion: ITrustAnchorStore;
  LProbes, LRoots: TArray<TBytes>;
  LI: Int32;
begin
  // the extras repeat a base anchor, repeat the base distrust, and add two new roots
  LProbes := TArray<TBytes>.Create(Der('root_cert'), Der('root2_cert'), Der('leaf_cert'),
    Der('expired_cert'), Der('wrongname_cert'));
  LBase := TTrustAnchorStore.Create(TArray<TBytes>.Create(LProbes[0], LProbes[1]),
    TArray<TBytes>.Create(LProbes[2]));
  LExtra := TTrustAnchorStore.Create(TArray<TBytes>.Create(LProbes[0], LProbes[2], LProbes[3],
    LProbes[4]));
  LLayered := TTrustAnchorStore.Layered(LBase, LExtra.RootCertificates);
  LUnion := TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(LBase, LExtra));
  CheckEquals(LUnion.AnchorCount, LLayered.AnchorCount, 'the anchor count');
  LRoots := LLayered.RootCertificates;
  CheckEquals(LUnion.AnchorCount, System.Length(LRoots), 'the root copy agrees with the count');
  for LI := 0 to System.High(LRoots) do
    CheckTrue(LUnion.IsAnchor(LRoots[LI]), 'every layered root is a union anchor');
  CheckEquals(System.Length(LUnion.DistrustedCertificates),
    System.Length(LLayered.DistrustedCertificates), 'the distrust set');
  for LI := 0 to System.High(LProbes) do
  begin
    CheckTrue(LUnion.IsAnchor(LProbes[LI]) = LLayered.IsAnchor(LProbes[LI]),
      'IsAnchor of probe ' + IntToStr(LI));
    CheckTrue(LUnion.IsDistrusted(LProbes[LI]) = LLayered.IsDistrusted(LProbes[LI]),
      'IsDistrusted of probe ' + IntToStr(LI));
  end;
end;

procedure TTestTrustComposition.TestLayeredStoreRefusesWhatTheBaseDistrusts;
var
  LBase, LLayered: ITrustAnchorStore;
begin
  LBase := TTrustAnchorStore.Create(TArray<TBytes>.Create(Der('root_cert')),
    TArray<TBytes>.Create(Der('leaf_cert')));
  LLayered := TTrustAnchorStore.Layered(LBase, TArray<TBytes>.Create(Der('leaf_cert')));
  CheckFalse(LLayered.IsAnchor(Der('leaf_cert')), 'an extra the base distrusts is not an anchor');
  CheckTrue(LLayered.IsDistrusted(Der('leaf_cert')), 'and stays distrusted');
  CheckEquals(1, LLayered.AnchorCount, 'the anchor count is the base count');
end;

procedure TTestTrustComposition.TestLayeredStoreReturnsItsBaseWhenNothingIsAdded;
var
  LBase: ITrustAnchorStore;
begin
  // the base identity is what an identity-keyed cache serves from
  LBase := TTrustAnchorStore.Create(TArray<TBytes>.Create(Der('root_cert')),
    TArray<TBytes>.Create(Der('leaf_cert')));
  CheckTrue(TTrustAnchorStore.Layered(LBase, nil) = LBase, 'no extras');
  CheckTrue(TTrustAnchorStore.Layered(LBase, TArray<TBytes>.Create(Der('root_cert'))) = LBase,
    'an extra the base already trusts');
  CheckTrue(TTrustAnchorStore.Layered(LBase, TArray<TBytes>.Create(Der('leaf_cert'))) = LBase,
    'an extra the base distrusts');
end;

procedure TTestTrustComposition.TestLayeredStoreOverNoBaseSitsOnAnEmptyBase;
var
  LStore: ITrustAnchorStore;
  LParts: ILayeredTrustAnchorStore;
begin
  LStore := TTrustAnchorStore.Layered(nil, TArray<TBytes>.Create(Der('root_cert'),
    Der('leaf_cert'), Der('root_cert')));
  CheckEquals(2, LStore.AnchorCount, 'the extras are the anchors, once each');
  CheckTrue(LStore.IsAnchor(Der('leaf_cert')), 'an extra is an anchor');
  CheckTrue(Supports(LStore, ILayeredTrustAnchorStore, LParts), 'the extras sit on a base');
  CheckEquals(0, LParts.BaseStore.AnchorCount, 'which holds no root, so a cache has none to key');
  CheckEquals(2, System.Length(LParts.ExtraRoots), 'and the extras are the anchors');
end;

procedure TTestTrustComposition.TestLayeredStoreOverNoBaseAndNoExtrasIsEmpty;
var
  LStore: ITrustAnchorStore;
begin
  LStore := TTrustAnchorStore.Layered(nil, nil);
  CheckNotNull(LStore, 'an empty store, never nil');
  CheckEquals(0, LStore.AnchorCount, 'with no anchor');
end;

procedure TTestTrustComposition.TestLayeredStoreOverALayeredStoreIsOneLayer;
var
  LBase, LOne, LTwo: ITrustAnchorStore;
  LParts: ILayeredTrustAnchorStore;
begin
  LBase := StoreOf('root_cert');
  LOne := TTrustAnchorStore.Layered(LBase, TArray<TBytes>.Create(Der('leaf_cert')));
  LTwo := TTrustAnchorStore.Layered(LOne, TArray<TBytes>.Create(Der('expired_cert')));
  CheckEquals(3, LTwo.AnchorCount, 'the base and both layers');
  CheckTrue(Supports(LTwo, ILayeredTrustAnchorStore, LParts), 'the result is layered');
  CheckTrue(LParts.BaseStore = LBase, 'its base is the original store, not the first layer');
  CheckEquals(2, System.Length(LParts.ExtraRoots), 'both layers are extras');
end;

procedure TTestTrustComposition.TestLayeredStoreKeepsItsBaseAlive;
var
  LLayered: ITrustAnchorStore;
  LReleased: Boolean;
begin
  // an identity-keyed cache holds the base by address, so the layer must keep that store alive
  LReleased := False;
  LLayered := LayeredOverWatchedStore(@LReleased);
  CheckFalse(LReleased, 'the layered store still holds the base');
  LLayered := nil;
  CheckTrue(LReleased, 'the base is released with the layered store');
end;

procedure TTestTrustComposition.TestAnchorMatchIsExactDer;
var
  LRoot, LOther: TBytes;
  LStore: ITrustAnchorStore;
begin
  LRoot := DecodeHex(FCerts.Values['root_cert']);
  LStore := TTrustAnchorStore.Create(TArray<TBytes>.Create(LRoot));
  CheckTrue(LStore.IsAnchor(System.Copy(LRoot)), 'a byte-equal copy is the anchor');
  LOther := System.Copy(LRoot);
  LOther[High(LOther)] := LOther[High(LOther)] xor $01;
  CheckFalse(LStore.IsAnchor(LOther), 'a one-bit difference is a different certificate');
  CheckFalse(LStore.IsAnchor(nil), 'an empty certificate is not an anchor');
end;

procedure TTestTrustComposition.TestBuildFreezesDistrustWithTheComposedStore;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
    TArray<ITrustAnchorStore>.Create(TTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert'])),
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']))) as ITrustAnchorStore),
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']))).Build)
    .Build;
  CheckTrue(LConfig.TrustStore.IsDistrusted(DecodeHex(FCerts.Values['leaf_cert'])),
    'the distrusted certificate is still distrusted after composition with plain anchors');
end;

procedure TTestTrustComposition.TestBuildRefusesAUnionWhoseDistrustRemovesEveryAnchor;
var
  LRaised: Boolean;
begin
  // one store trusts the root, another distrusts it: the composed store has no anchor left, which
  // fails at Build rather than producing a config that only ever answers unknown_ca
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithServerVerification(TServerVerification.WebPki(TArray<ITrustAnchorStore>.Create(
      StoreOf('root_cert'), TTrustAnchorStore.Create(nil,
      TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']))) as ITrustAnchorStore),
      nil).Build)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a union with no anchor left is refused');
  CheckEquals(1, TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(StoreOf('root_cert')).Build)
    .Build.TrustStore.AnchorCount,
    'control: the root alone builds');
end;

procedure TTestTrustComposition.TestCertificateVerifierLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
  LStub: IServerCertificateVerifier;
  LContext: TServerTrustContext;
begin
  // a whole-verifier is a valid, self-sufficient trust source (no anchors needed); it is wrapped
  // as an instance source that returns it unchanged for every connection
  LStub := TFixedVerdictVerifier.CreateAccepting(False) as IServerCertificateVerifier;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.Custom(LStub))
    .Build;
  LContext := Default(TServerTrustContext);
  CheckTrue(LConfig.ServerVerifierSource.CreateServerVerifier(LContext) = LStub,
    'the injected whole-verifier is returned unchanged by the instance source');
end;

{ TTestIssuerLookup }

const
  TiersFile = 'Certs/IntermediateClientAuthChain.txt';
  AuthFile = 'Certs/ClientAuthChain.txt';
  RingFile = 'Certs/PathBuildFlood.txt';
  DepthFile = 'Certs/IssuerDepthChain.txt';
  WeakFile = 'Certs/WeakAnchorClientChain.txt';
  EcFile = 'Certs/EcP256Chain.txt';
  ChainFile = 'Certs/OcspStapling.txt';
  RenewalFile = 'Certs/IssuerRenewal.txt';

procedure TTestIssuerLookup.SetUp;
begin
  inherited SetUp;
  FLookup := TRecordingIssuerLookup.Create('test-lookup');
  FLookupRef := FLookup;
  FCapture := TCapturingVerifierSource.Create;
  FCaptureRef := FCapture;
  FRoot := TTlsLibTestCertificates.Field(TiersFile, 'root_cert');
  FIssuer := TTlsLibTestCertificates.Field(TiersFile, 'issuer_cert');
  FLeaf := TTlsLibTestCertificates.Field(TiersFile, 'leaf_cert');
  FRootName := Pkix.Certificates.Parse(FRoot).SubjectName;
  FIssuerName := Pkix.Certificates.Parse(FIssuer).SubjectName;
  FLeafName := Pkix.Certificates.Parse(FLeaf).SubjectName;
  FUnrelated := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field(EcFile, 'root2_cert'))) as ITrustAnchorStore;
  FRule := TBundleAnchorRule.SelfSignedOnly;
end;

procedure TTestIssuerLookup.TearDown;
begin
  FUnrelated := nil;
  FCaptureRef := nil;
  FLookupRef := nil;
  inherited TearDown;
end;

function TTestIssuerLookup.ServerContext(const AStore: ITrustAnchorStore): TServerTrustContext;
begin
  Result := Default(TServerTrustContext);
  Result.Pkix := Pkix;
  Result.Clock := TSystemClock.Create;
  Result.TrustStore := AStore;
  Result.CheckHostName := True;
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.RevocationPosture := TRevocationPosture.Soft;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.AdvertisedSignatureSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
end;

function TTestIssuerLookup.ClientContext(const AStore: ITrustAnchorStore): TClientTrustContext;
begin
  Result := Default(TClientTrustContext);
  Result.Pkix := Pkix;
  Result.Clock := TSystemClock.Create;
  Result.TrustStore := AStore;
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.RevocationPosture := TRevocationPosture.Soft;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.AdvertisedSignatureSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
end;

function TTestIssuerLookup.ServerVerifier(const AInner: IServerCertificateVerifierSource;
  const AContext: TServerTrustContext): IServerCertificateVerifier;
var
  LSource: IServerCertificateVerifierSource;
begin
  LSource := TIssuerLookupServerVerifierSource.Create(AInner, FLookupRef, FRule)
    as IServerCertificateVerifierSource;
  Result := LSource.CreateServerVerifier(AContext);
end;

function TTestIssuerLookup.ClientVerifier(const AInner: IClientCertificateVerifierSource;
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LSource: IClientCertificateVerifierSource;
begin
  LSource := TIssuerLookupClientVerifierSource.Create(AInner, FLookupRef, FRule)
    as IClientCertificateVerifierSource;
  Result := LSource.CreateClientVerifier(AContext);
end;

function TTestIssuerLookup.ServerVerdict(const AVerifier: IServerCertificateVerifier;
  const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
var
  LVerified: TVerifiedChain;
begin
  Result := AVerifier.VerifyServerCertificate(AChain, TServerName.DnsName('localhost'), nil,
    LVerified, AAlert);
end;

function TTestIssuerLookup.ClientVerdict(const AVerifier: IClientCertificateVerifier;
  const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
var
  LVerified: TVerifiedChain;
begin
  Result := AVerifier.VerifyClientCertificate(AChain, LVerified, AAlert);
end;

function TTestIssuerLookup.AuthCredential: TTlsCredential;
begin
  Result := TTlsCredential.Load(Crypto, Pkix, TTlsLibTestCertificates.Field(AuthFile, 'leaf_cert'),
    TTlsLibTestCertificates.Field(AuthFile, 'leaf_key'));
end;

procedure TTestIssuerLookup.TestLookedUpRootAnchorsAServerChain;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'the looked-up root anchors the chain');
end;

procedure TTestIssuerLookup.TestLookedUpRootAnchorsAClientChain;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  CheckTrue(ClientVerdict(ClientVerifier(TBuiltInClientVerifierSource.Create
    as IClientCertificateVerifierSource, ClientContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'the looked-up root anchors the chain');
end;

procedure TTestIssuerLookup.TestLookupAloneAnchorsAChainWithNoStaticStore;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(nil)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'no static store, one looked-up root');
end;

procedure TTestIssuerLookup.TestOnlyIssuerNamesAreAsked;
var
  LAlert: TTlsAlertDescription;
begin
  ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert);
  CheckEquals(2, System.Length(FLookup.Asked), 'one ask per issuer name');
  CheckEquals(1, FLookup.TimesAsked(FIssuerName), 'the leaf''s issuer');
  CheckEquals(1, FLookup.TimesAsked(FRootName), 'the issuer''s issuer');
  CheckEquals(0, FLookup.TimesAsked(FLeafName), 'the leaf''s own subject is never asked');
end;

procedure TTestIssuerLookup.TestEachNameIsAskedOnce;
var
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  LContext := ServerContext(FUnrelated);
  LContext.Intermediates := TArray<TBytes>.Create(FIssuer);
  ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext),
    TArray<TBytes>.Create(FLeaf, FLeaf, FIssuer), LAlert);
  CheckEquals(1, FLookup.TimesAsked(FIssuerName), 'the name two leaves share');
  CheckEquals(1, FLookup.TimesAsked(FRootName), 'the name the issuer and the intermediate share');
end;

procedure TTestIssuerLookup.TestOverLimitServerChainIsRefusedBeforeAnyLookup;
var
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  LContext := ServerContext(FUnrelated);
  LContext.ChainLimits.MaxChainCertificates := 1;
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'two certificates over a limit of one');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'bad_certificate');
  CheckEquals(0, System.Length(FLookup.Asked), 'no lookup was made');
end;

procedure TTestIssuerLookup.TestOverLimitClientChainIsRefusedBeforeAnyLookup;
var
  LContext: TClientTrustContext;
  LAlert: TTlsAlertDescription;
begin
  LContext := ClientContext(FUnrelated);
  LContext.ChainLimits.MaxChainCertificates := 1;
  CheckFalse(ClientVerdict(ClientVerifier(TBuiltInClientVerifierSource.Create
    as IClientCertificateVerifierSource, LContext),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'two certificates over a limit of one');
  CheckEquals(0, System.Length(FLookup.Asked), 'no lookup was made');
end;

procedure TTestIssuerLookup.TestChainAtTheLimitIsLookedUp;
var
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  // boundary of the test above: a chain exactly at the limit is looked up
  LContext := ServerContext(FUnrelated);
  LContext.ChainLimits.MaxChainCertificates := 2;
  ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert);
  CheckEquals(2, System.Length(FLookup.Asked), 'the chain is within the limit');
end;

procedure TTestIssuerLookup.TestLookedUpIntermediateAndRootCompleteALeafOnlyChain;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FIssuerName, nil, TArray<TBytes>.Create(FIssuer));
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf), LAlert), 'the peer sent the leaf only');
end;

procedure TTestIssuerLookup.TestLookedUpIntermediateAloneIsNotAnAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FIssuerName, nil, TArray<TBytes>.Create(FIssuer));
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf), LAlert), 'an intermediate with no root behind it');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'unknown_ca');
end;

procedure TTestIssuerLookup.TestNonSelfSignedCertificateOfferedAsAnAnchorIsChainMaterialOnly;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FIssuerName, TArray<TBytes>.Create(FIssuer), nil);
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf), LAlert), 'the offered anchor is not self-signed');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'unknown_ca');
end;

procedure TTestIssuerLookup.TestCertificateUnderAnotherNameIsIgnored;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FIssuerName, TArray<TBytes>.Create(FRoot), nil);
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'the root answers to another name');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'unknown_ca');
end;

procedure TTestIssuerLookup.TestWeakLookedUpAnchorIsRefused;
var
  LRoot, LLeaf: TBytes;
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  LRoot := TTlsLibTestCertificates.Field(WeakFile, 'root_cert');
  LLeaf := TTlsLibTestCertificates.Field(WeakFile, 'leaf_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LRoot).SubjectName, TArray<TBytes>.Create(LRoot), nil);
  LContext := ServerContext(FUnrelated);
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.RsaPkcs1Sha256);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext), TArray<TBytes>.Create(LLeaf), LAlert),
    'control: the 2048-bit root meets the default floors');
  LContext.StrengthPolicy.MinRsaModulusBits := 3072;
  LContext.StrengthPolicy.AnchorKeyFloors := True;
  // the downstream chain policy also refuses a weak root, so the resolver's own check is shown by
  // the store it hands the inner source
  ServerVerdict(ServerVerifier(FCaptureRef, LContext), TArray<TBytes>.Create(LLeaf), LAlert);
  CheckFalse(FCapture.Store.IsAnchor(LRoot), 'the resolver keeps the weak root out of the store');
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext), TArray<TBytes>.Create(LLeaf), LAlert),
    'the root is below the anchor floor');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'it is never an anchor');
end;

procedure TTestIssuerLookup.TestStaticDistrustBeatsALookedUpAnchor;
var
  LSource: IServerCertificateVerifierSource;
  LChain: TArray<TBytes>;
  LDistrusting: ITrustAnchorStore;
  LAlert: TTlsAlertDescription;
begin
  // the inner source trusts exactly the anchors of the store it is given, so only that store can reject
  LSource := TAnchorMembershipVerifierSource.Create as IServerCertificateVerifierSource;
  LChain := TArray<TBytes>.Create(FLeaf, FIssuer, FRoot);
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  CheckTrue(ServerVerdict(ServerVerifier(LSource, ServerContext(FUnrelated)), LChain, LAlert),
    'control: the root is not distrusted');
  LDistrusting := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field(EcFile, 'root2_cert')), TArray<TBytes>.Create(FRoot));
  CheckFalse(ServerVerdict(ServerVerifier(LSource, ServerContext(LDistrusting)), LChain, LAlert),
    'the static distrust wins');
end;

procedure TTestIssuerLookup.TestStaticDistrustKeepsALookedUpAnchorOutOfTheStore;
var
  LDistrusting: ITrustAnchorStore;
  LAlert: TTlsAlertDescription;
begin
  LDistrusting := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field(EcFile, 'root2_cert')), TArray<TBytes>.Create(FRoot));
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  ServerVerdict(ServerVerifier(FCaptureRef, ServerContext(LDistrusting)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert);
  CheckFalse(FCapture.Store.IsAnchor(FRoot), 'the distrusted root is not an anchor');
  CheckTrue(FCapture.Store.IsDistrusted(FRoot), 'and stays distrusted');
end;

procedure TTestIssuerLookup.TestUnreadableBlobsAreSkipped;
var
  LGarbage, LEmpty: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LGarbage := TArray<Byte>.Create(1, 2, 3);
  LEmpty := nil;
  FLookup.Offer(FRootName, TArray<TBytes>.Create(LGarbage, LEmpty, FRoot), nil);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'the root after the unreadable blobs');
end;

procedure TTestIssuerLookup.TestALookupThatRaisesGivesUnknownCa;
var
  LAlert: TTlsAlertDescription;
  LVerdict: Boolean;
begin
  FLookup.RaisesOnAsk := True;
  LVerdict := ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert);
  CheckTrue(System.Length(FLookup.Asked) > 0, 'the lookup was asked');
  CheckFalse(LVerdict, 'nothing anchors the chain');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'unknown_ca');
end;

procedure TTestIssuerLookup.TestALookupWithNoAnswerGivesUnknownCa;
var
  LAlert: TTlsAlertDescription;
begin
  // a guard: a lookup that knows nothing leaves the base store's verdict
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'no anchor');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'unknown_ca');
end;

procedure TTestIssuerLookup.TestLookedUpAnchorsDoNotLeakIntoTheNextVerification;
var
  LVerifier: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
begin
  LVerifier := ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated));
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  CheckTrue(ServerVerdict(LVerifier, TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'first');
  FLookup.Forget;
  CheckFalse(ServerVerdict(LVerifier, TArray<TBytes>.Create(FLeaf, FIssuer), LAlert),
    'the lookup no longer holds the root');
end;

procedure TTestIssuerLookup.TestNothingFoundHandsTheInnerTheSameStore;
var
  LAlert: TTlsAlertDescription;
begin
  ServerVerdict(ServerVerifier(FCaptureRef, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert);
  CheckTrue(FCapture.Store = FUnrelated, 'the inner source sees the base store itself');
  CheckEquals(0, System.Length(FCapture.Intermediates), 'and no intermediate');
end;

procedure TTestIssuerLookup.TestSomethingFoundHandsTheInnerALayeredStoreAndTheIntermediates;
var
  LAlert: TTlsAlertDescription;
  LParts: ILayeredTrustAnchorStore;
begin
  FLookup.Offer(FIssuerName, nil, TArray<TBytes>.Create(FIssuer));
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  ServerVerdict(ServerVerifier(FCaptureRef, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf), LAlert);
  CheckTrue(Supports(FCapture.Store, ILayeredTrustAnchorStore, LParts), 'a layered store');
  CheckTrue(LParts.BaseStore = FUnrelated, 'over the base store itself');
  CheckEquals(1, System.Length(LParts.ExtraRoots), 'with the looked-up root');
  CheckEquals(1, System.Length(FCapture.Intermediates), 'and the looked-up intermediate');
  CheckTrue(AreEqual(FIssuer, FCapture.Intermediates[0]), 'which is the issuer');
  CheckFalse(FUnrelated.IsAnchor(FRoot), 'the base store is left alone');
end;

procedure TTestIssuerLookup.TestARingOfIssuersTerminatesAndEachNameIsAskedOnce;
var
  LRing, LNames: TArray<TBytes>;
  LName: TBytes;
  LAlert: TTlsAlertDescription;
  LI, LJ: Int32;
  LKnown: Boolean;
begin
  LRing := nil;
  LNames := nil;
  for LI := 0 to 15 do
    TArrayUtilities.Append<TBytes>(LRing, TTlsLibTestCertificates.Field(RingFile,
      Format('ring_%.2d', [LI])));
  for LI := 0 to System.High(LRing) do
  begin
    LName := Pkix.Certificates.Parse(LRing[LI]).SubjectName;
    LKnown := False;
    for LJ := 0 to System.High(LNames) do
      LKnown := LKnown or AreEqual(LNames[LJ], LName);
    if not LKnown then
      TArrayUtilities.Append<TBytes>(LNames, LName);
  end;
  CheckEquals(4, System.Length(LNames), 'four subjects in the ring');
  for LI := 0 to System.High(LNames) do
    FLookup.Offer(LNames[LI], nil, LRing);
  ServerVerdict(ServerVerifier(FCaptureRef, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(TTlsLibTestCertificates.Field(RingFile, 'ring_leaf')), LAlert);
  CheckEquals(4, System.Length(FLookup.Asked), 'one ask per name');
  for LI := 0 to System.High(LNames) do
    CheckEquals(1, FLookup.TimesAsked(LNames[LI]), 'name ' + IntToStr(LI));
end;

procedure TTestIssuerLookup.TestTheWalkStopsAtThePathBuildingDepth;
var
  LInter: TBytes;
  LRootName: TBytes;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  for LI := 1 to 5 do
  begin
    LInter := TTlsLibTestCertificates.Field(DepthFile, Format('inter_%d_cert', [LI]));
    FLookup.Offer(Pkix.Certificates.Parse(LInter).SubjectName, nil, TArray<TBytes>.Create(LInter));
  end;
  LRootName := Pkix.Certificates.Parse(TTlsLibTestCertificates.Field(DepthFile,
    'root_cert')).SubjectName;
  ServerVerdict(ServerVerifier(FCaptureRef, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(TTlsLibTestCertificates.Field(DepthFile, 'leaf_cert')), LAlert);
  CheckEquals(TPathBuildLimits.MaxBuiltPathLength + 1, System.Length(FLookup.Asked),
    'one ask per level down to the built-path limit');
  CheckEquals(0, FLookup.TimesAsked(LRootName), 'the root name lies past the limit');
end;

procedure TTestIssuerLookup.TestAnIntermediateThePeerSentIsNotFoundAgain;
var
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FIssuerName, nil, TArray<TBytes>.Create(FIssuer));
  ServerVerdict(ServerVerifier(FCaptureRef, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert);
  CheckEquals(0, System.Length(FCapture.Intermediates), 'the peer already holds the issuer');
end;

procedure TTestIssuerLookup.TestAConfiguredIntermediateIsNotFoundAgain;
var
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FIssuerName, nil, TArray<TBytes>.Create(FIssuer));
  LContext := ServerContext(FUnrelated);
  LContext.Intermediates := TArray<TBytes>.Create(FIssuer);
  ServerVerdict(ServerVerifier(FCaptureRef, LContext), TArray<TBytes>.Create(FLeaf), LAlert);
  CheckEquals(1, System.Length(FCapture.Intermediates), 'the configured issuer, once');
end;

procedure TTestIssuerLookup.TestAConfiguredIntermediateOffTheChainIsNotWalked;
var
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  LContext := ServerContext(FUnrelated);
  LContext.Intermediates := TArray<TBytes>.Create(FIssuer);
  ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext),
    TArray<TBytes>.Create(TTlsLibTestCertificates.Field(EcFile, 'leaf_cert')), LAlert);
  CheckEquals(1, System.Length(FLookup.Asked), 'only the leaf''s issuer is asked');
  CheckEquals(0, FLookup.TimesAsked(FRootName), 'the issuer of an unrelated intermediate is not');
end;

procedure TTestIssuerLookup.TestAConfiguredIntermediateOnTheChainLeadsToALookedUpRoot;
var
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  LContext := ServerContext(FUnrelated);
  LContext.Intermediates := TArray<TBytes>.Create(FIssuer);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext), TArray<TBytes>.Create(FLeaf), LAlert),
    'leaf, configured intermediate, looked-up root');
  CheckEquals(1, FLookup.TimesAsked(FRootName), 'the configured intermediate''s issuer was asked');
end;

procedure TTestIssuerLookup.TestAnAnswerWhoseNameCannotBeComparedIsIgnored;
var
  LInspector: ICertificateInspector;
  LStore: ITrustAnchorStore;
  LFound: TArray<TBytes>;
begin
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), TArray<TBytes>.Create(FRoot));
  LInspector := TScriptedNameInspector.Create(Pkix.Certificates, TCertAnswer.Undetermined)
    as ICertificateInspector;
  TIssuerResolution.Resolve(LInspector, FLookupRef, FRule, TCertificateStrengthPolicy.Defaults,
    FUnrelated, TArray<TBytes>.Create(FIssuer), nil, LStore, LFound);
  CheckFalse(LStore.IsAnchor(FRoot), 'a name that may differ does not select the answer');
  CheckEquals(0, System.Length(LFound), 'nor does it add chain material');
end;

procedure TTestIssuerLookup.TestServerDecoratorSurfacesTheInnerRefusalAtCreation;
var
  LSource: IServerCertificateVerifierSource;
  LRaised: Boolean;
begin
  LSource := TIssuerLookupServerVerifierSource.Create(TFakeHostVerifierSource.Create
    as IServerCertificateVerifierSource, FLookupRef, FRule) as IServerCertificateVerifierSource;
  LRaised := False;
  try
    LSource.CreateServerVerifier(ServerContext(FUnrelated));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the inner source refuses when the verifier is created, not when it is used');
end;

procedure TTestIssuerLookup.TestClientDecoratorSurfacesTheInnerRefusalAtCreation;
var
  LSource: IClientCertificateVerifierSource;
  LRaised: Boolean;
begin
  LSource := TIssuerLookupClientVerifierSource.Create(TFakeHostVerifierSource.Create
    as IClientCertificateVerifierSource, FLookupRef, FRule) as IClientCertificateVerifierSource;
  LRaised := False;
  try
    LSource.CreateClientVerifier(ClientContext(FUnrelated));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the inner source refuses when the verifier is created, not when it is used');
end;

procedure TTestIssuerLookup.TestServerDecoratorRefusesANilLookup;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TIssuerLookupServerVerifierSource.Create(FCaptureRef, nil, FRule);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil lookup is refused');
end;

procedure TTestIssuerLookup.TestServerDecoratorRefusesANilSource;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TIssuerLookupServerVerifierSource.Create(nil, FLookupRef, FRule);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil source is refused');
end;

procedure TTestIssuerLookup.TestClientDecoratorRefusesANilLookup;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TIssuerLookupClientVerifierSource.Create(FCapture as IClientCertificateVerifierSource, nil,
      FRule);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil lookup is refused');
end;

procedure TTestIssuerLookup.TestClientDecoratorRefusesANilSource;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TIssuerLookupClientVerifierSource.Create(nil, FLookupRef, FRule);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil source is refused');
end;

procedure TTestIssuerLookup.TestAnyCertificateAnchorsALookedUpIntermediate;
var
  LAlert: TTlsAlertDescription;
begin
  FRule := TBundleAnchorRule.AnyCertificate;
  FLookup.Offer(FIssuerName, TArray<TBytes>.Create(FIssuer), nil);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf), LAlert), 'the offered intermediate anchors the leaf');
end;

procedure TTestIssuerLookup.TestSelfSignedOnlyDoesNotAnchorALookedUpIntermediate;
var
  LAlert: TTlsAlertDescription;
begin
  FRule := TBundleAnchorRule.SelfSignedOnly;
  FLookup.Offer(FIssuerName, TArray<TBytes>.Create(FIssuer), nil);
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf), LAlert), 'the offered intermediate is chain material only');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'unknown_ca');
end;

procedure TTestIssuerLookup.TestAnyCertificateStillHoldsALookedUpAnchorToTheKeyFloors;
var
  LRoot, LLeaf: TBytes;
  LContext: TServerTrustContext;
  LAlert: TTlsAlertDescription;
begin
  FRule := TBundleAnchorRule.AnyCertificate;
  LRoot := TTlsLibTestCertificates.Field(WeakFile, 'root_cert');
  LLeaf := TTlsLibTestCertificates.Field(WeakFile, 'leaf_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LRoot).SubjectName, TArray<TBytes>.Create(LRoot), nil);
  LContext := ServerContext(FUnrelated);
  LContext.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.RsaPkcs1Sha256);
  LContext.StrengthPolicy.MinRsaModulusBits := 3072;
  LContext.StrengthPolicy.AnchorKeyFloors := True;
  ServerVerdict(ServerVerifier(FCaptureRef, LContext), TArray<TBytes>.Create(LLeaf), LAlert);
  CheckFalse(FCapture.Store.IsAnchor(LRoot), 'the resolver keeps the weak root out of the store');
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext), TArray<TBytes>.Create(LLeaf), LAlert),
    'the root is below the anchor floor');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'it is never an anchor');
end;

procedure TTestIssuerLookup.TestAnyCertificateKeepsStaticDistrust;
var
  LAlert: TTlsAlertDescription;
  LBase: ITrustAnchorStore;
begin
  FRule := TBundleAnchorRule.AnyCertificate;
  LBase := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field(EcFile, 'root2_cert')), TArray<TBytes>.Create(FIssuer))
    as ITrustAnchorStore;
  FLookup.Offer(FIssuerName, TArray<TBytes>.Create(FIssuer), nil);
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(LBase)),
    TArray<TBytes>.Create(FLeaf), LAlert), 'the base store distrusts the offered intermediate');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'unknown_ca');
end;

{ TTestIssuerLookupConfig }

procedure TTestIssuerLookupConfig.SetUp;
begin
  inherited SetUp;
  FLookup := TRecordingIssuerLookup.Create('test-lookup');
  FLookupRef := FLookup;
  FCapture := TCapturingVerifierSource.Create;
  FCaptureRef := FCapture;
  FUnrelated := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field(EcFile, 'root2_cert'))) as ITrustAnchorStore;
end;

procedure TTestIssuerLookupConfig.TearDown;
begin
  FUnrelated := nil;
  FCaptureRef := nil;
  FLookupRef := nil;
  inherited TearDown;
end;

function TTestIssuerLookupConfig.AuthCredential: TTlsCredential;
begin
  Result := TTlsCredential.Load(Crypto, Pkix, TTlsLibTestCertificates.Field(AuthFile, 'leaf_cert'),
    TTlsLibTestCertificates.Field(AuthFile, 'leaf_key'));
end;

function TTestIssuerLookupConfig.ClientBuilder: ITlsClientConfigBuilder;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client;
end;

function TTestIssuerLookupConfig.ServerBuilder: ITlsServerConfigBuilder;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(AuthCredential);
end;

function TTestIssuerLookupConfig.ServerBuildRaises(const ABuilder: ITlsServerConfigBuilder): Boolean;
begin
  Result := False;
  try
    ABuilder.Build;
  except
    on EInvalidOperationTlsLibException do
      Result := True;
  end;
end;

function TTestIssuerLookupConfig.ResumingClient: ITlsClientConfigBuilder;
begin
  Result := ClientBuilder.WithResumption(True)
    .WithSessionCache(TInMemorySessionCache.Create as ISessionCache);
end;

function TTestIssuerLookupConfig.HandshakeAnchoredAtTheIssuer(ARule: TBundleAnchorRule): Boolean;
var
  LIssuer: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LIssuer := TTlsLibTestCertificates.Field(ChainFile, 'issuer_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LIssuer).SubjectName, TArray<TBytes>.Create(LIssuer), nil);
  LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(
    TTlsCredential.Load(Crypto, Pkix, TTlsLibTestCertificates.Field(ChainFile, 'leaf_cert'),
    TTlsLibTestCertificates.Field(ChainFile, 'leaf_key'))).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(
    ClientBuilder.WithServerVerification(TServerVerification.WebPki(FLookupRef, ARule).Build)
    .Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  Result := not (LClient.IsHandshaking or LClient.IsTerminal);
end;

function TTestIssuerLookupConfig.ServerHandshakeAnchoredAtTheIssuer(ARule: TBundleAnchorRule)
  : Boolean;
var
  LIssuer: TBytes;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LIssuer := TTlsLibTestCertificates.Field(RenewalFile, 'issuer_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LIssuer).SubjectName, TArray<TBytes>.Create(LIssuer), nil);
  LClientConfig := ClientBuilder.WithServerVerification(TServerVerification.WebPki(
    TTlsLibTestCertificates.Field(AuthFile, 'root_cert')).Build)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
    TTlsLibTestCertificates.Field(RenewalFile, 'leaf_cert'),
    TTlsLibTestCertificates.Field(RenewalFile, 'leaf_key'))).Build;
  LServerConfig := ServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(FLookupRef, ARule).Build).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  Result := not (LServer.IsHandshaking or LServer.IsTerminal);
end;

procedure TTestIssuerLookupConfig.TestServerFactoryPassesAnyCertificateToTheDecorator;
begin
  CheckTrue(ServerHandshakeAnchoredAtTheIssuer(TBundleAnchorRule.AnyCertificate),
    'the intermediate is an anchor of the client chain under AnyCertificate');
end;

procedure TTestIssuerLookupConfig.TestServerFactoryPassesSelfSignedOnlyToTheDecorator;
begin
  CheckFalse(ServerHandshakeAnchoredAtTheIssuer(TBundleAnchorRule.SelfSignedOnly),
    'the intermediate is chain material under SelfSignedOnly');
end;

procedure TTestIssuerLookupConfig.TestHardPostureRefusesTheDefaultReverifyAndNamesTheWayOut;
var
  LMessage: string;
begin
  LMessage := '';
  try
    ResumingClient.WithOcspStaplingRequest(True).WithServerVerification(
      TServerVerification.WebPki(FUnrelated).WithRevocation(TRevocationPosture.Hard)
      .WithIssuerLookup(FLookupRef).Build).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMessage := E.Message;
  end;
  CheckTrue(Pos('issuer lookup', LMessage) > 0, 'the refusal names the lookup: ' + LMessage);
  CheckTrue(Pos('WithResumeVerification(ReuseOriginal)', LMessage) > 0,
    'and the way out: ' + LMessage);
  CheckNotNull(ResumingClient.WithOcspStaplingRequest(True).WithServerVerification(
    TServerVerification.WebPki(FUnrelated).WithRevocation(TRevocationPosture.Hard).Build)
    .Build, 'control: the same client builds without the lookup');
end;

procedure TTestIssuerLookupConfig.TestEarlyDataBesideAnAsyncVerdictRefusesTheDefaultReverifyAndNamesTheWayOut;
var
  LMessage: string;
begin
  LMessage := '';
  try
    ResumingClient.WithAsyncCertificateVerdict(0)
      .WithServerVerification(TServerVerification.WebPki(FLookupRef).Build)
      .Tls13.WithEarlyData(True).Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMessage := E.Message;
  end;
  CheckTrue(Pos('issuer lookup', LMessage) > 0, 'the refusal names the lookup: ' + LMessage);
  CheckTrue(Pos('WithResumeVerification(ReuseOriginal)', LMessage) > 0,
    'and the way out: ' + LMessage);
  CheckNotNull(ResumingClient.WithAsyncCertificateVerdict(0)
    .WithServerVerification(TServerVerification.WebPki(FUnrelated).Build)
    .Tls13.WithEarlyData(True).Build, 'control: the same client builds without the lookup');
end;

procedure TTestIssuerLookupConfig.TestClientConfigCarriesTheLookupAndTheDefaultRule;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := ClientBuilder.WithServerVerification(TServerVerification.WebPki(FLookupRef).Build)
    .Build;
  CheckTrue(LConfig.IssuerLookup = FLookupRef, 'the lookup it was given');
  CheckEquals(Ord(TBundleAnchorRule.SelfSignedOnly), Ord(LConfig.IssuerAnchorRule),
    'only a self-signed certificate is an anchor by default');
end;

procedure TTestIssuerLookupConfig.TestServerConfigCarriesTheLookupAndTheDefaultRule;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(FLookupRef).Build).Build;
  CheckTrue(LConfig.IssuerLookup = FLookupRef, 'the lookup it was given');
  CheckEquals(Ord(TBundleAnchorRule.SelfSignedOnly), Ord(LConfig.IssuerAnchorRule),
    'only a self-signed certificate is an anchor by default');
end;

procedure TTestIssuerLookupConfig.TestClientConfigCarriesAnExplicitRule;
begin
  CheckEquals(Ord(TBundleAnchorRule.AnyCertificate),
    Ord(ClientBuilder.WithServerVerification(TServerVerification.WebPki(FUnrelated)
    .WithIssuerLookup(FLookupRef, TBundleAnchorRule.AnyCertificate).Build).Build
    .IssuerAnchorRule), 'the rule it was given');
end;

procedure TTestIssuerLookupConfig.TestServerConfigCarriesAnExplicitRule;
begin
  CheckEquals(Ord(TBundleAnchorRule.AnyCertificate),
    Ord(ServerBuilder.WithPeerAuth(TClientAuthMode.Required).WithClientVerification(
    TClientVerification.WebPki(FUnrelated)
    .WithIssuerLookup(FLookupRef, TBundleAnchorRule.AnyCertificate).Build).Build
    .IssuerAnchorRule), 'the rule it was given');
end;

procedure TTestIssuerLookupConfig.TestClientConfigWithoutALookupCarriesNone;
begin
  CheckTrue(ClientBuilder.WithServerVerification(TServerVerification.WebPki(FUnrelated).Build)
    .Build.IssuerLookup = nil, 'none unless set');
end;

procedure TTestIssuerLookupConfig.TestVerificationBuildersDefaultTheRuleToSelfSignedOnly;
begin
  CheckEquals(Ord(TBundleAnchorRule.SelfSignedOnly),
    Ord(TServerVerification.WebPki(FUnrelated).WithIssuerLookup(FLookupRef).Build
    .IssuerAnchorRule), 'server policy');
  CheckEquals(Ord(TBundleAnchorRule.SelfSignedOnly),
    Ord(TClientVerification.WebPki(FUnrelated).WithIssuerLookup(FLookupRef).Build
    .IssuerAnchorRule), 'client policy');
end;

procedure TTestIssuerLookupConfig.TestServerVerificationBuilderRefusesANilLookup;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TServerVerification.WebPki(FUnrelated).WithIssuerLookup(nil);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil lookup is refused');
end;

procedure TTestIssuerLookupConfig.TestClientVerificationBuilderRefusesANilLookup;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TClientVerification.WebPki(FUnrelated).WithIssuerLookup(nil);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil lookup is refused');
end;

procedure TTestIssuerLookupConfig.TestServerVerificationFactoryRefusesANilLookup;
var
  LRaised: Boolean;
  LNone: IIssuerLookup;
begin
  LRaised := False;
  LNone := nil;
  try
    TServerVerification.WebPki(LNone);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil lookup is refused');
end;

procedure TTestIssuerLookupConfig.TestClientVerificationFactoryRefusesANilLookup;
var
  LRaised: Boolean;
  LNone: IIssuerLookup;
begin
  LRaised := False;
  LNone := nil;
  try
    TClientVerification.WebPki(LNone, TBundleAnchorRule.AnyCertificate);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil lookup is refused');
end;

procedure TTestIssuerLookupConfig.TestWebPkiWithNeitherRootsNorLookupIsRefusedAtBuild;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TClientVerification.WebPki(TArray<ITrustAnchorStore>(nil), TArray<TBytes>(nil)).Build;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'no roots and no lookup is no trust source');
end;

procedure TTestIssuerLookupConfig.TestALookupAloneSatisfiesTheWebPkiTrustSource;
var
  LServer: IServerVerification;
  LClient: IClientVerification;
begin
  LServer := TServerVerification.WebPki(FLookupRef).Build;
  LClient := TClientVerification.WebPki(FLookupRef).Build;
  CheckEquals(0, System.Length(LServer.AnchorStores), 'no stores on the server policy');
  CheckEquals(0, System.Length(LClient.AnchorData), 'no root blobs on the client policy');
  CheckTrue(LServer.IssuerLookup = FLookupRef, 'the server policy carries the lookup');
  CheckTrue(LClient.IssuerLookup = FLookupRef, 'the client policy carries the lookup');
  CheckEquals(Ord(TVerificationKind.WebPki), Ord(LServer.Kind), 'still a WebPki policy');
end;

procedure TTestIssuerLookupConfig.TestLookupOnlyServerVerificationCarriesPostureFloorsAndIntermediates;
var
  LFloors: TCertificateStrengthPolicy;
  LVerification: IServerVerification;
begin
  LFloors := TCertificateStrengthPolicy.Defaults;
  LFloors.MinRsaModulusBits := 3072;
  LVerification := TServerVerification.WebPki(FLookupRef, TBundleAnchorRule.AnyCertificate)
    .WithRevocation(TRevocationPosture.Hard).WithMinimumStrength(LFloors)
    .WithIntermediateCertificates(TTlsLibTestCertificates.Field(ChainFile, 'issuer_cert')).Build;
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LVerification.RevocationPosture), 'posture');
  CheckEquals(3072, LVerification.StrengthPolicy.MinRsaModulusBits, 'floors');
  CheckEquals(1, System.Length(LVerification.IntermediateData), 'intermediates');
  CheckEquals(Ord(TBundleAnchorRule.AnyCertificate), Ord(LVerification.IssuerAnchorRule),
    'the rule it was given');
end;

procedure TTestIssuerLookupConfig.TestLookupOnlyClientVerificationCarriesPostureFloorsAndIntermediates;
var
  LFloors: TCertificateStrengthPolicy;
  LVerification: IClientVerification;
begin
  LFloors := TCertificateStrengthPolicy.Defaults;
  LFloors.MinRsaModulusBits := 3072;
  LVerification := TClientVerification.WebPki(FLookupRef)
    .WithRevocation(TRevocationPosture.Hard).WithMinimumStrength(LFloors)
    .WithIntermediateCertificates(TTlsLibTestCertificates.Field(ChainFile, 'issuer_cert')).Build;
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LVerification.RevocationPosture), 'posture');
  CheckEquals(3072, LVerification.StrengthPolicy.MinRsaModulusBits, 'floors');
  CheckEquals(1, System.Length(LVerification.IntermediateData), 'intermediates');
  CheckEquals(Ord(TBundleAnchorRule.SelfSignedOnly), Ord(LVerification.IssuerAnchorRule),
    'the default rule');
end;

procedure TTestIssuerLookupConfig.TestLookupOnlyClientConfigCarriesPostureAndFloors;
var
  LFloors: TCertificateStrengthPolicy;
  LConfig: ITlsClientConfig;
begin
  LFloors := TCertificateStrengthPolicy.Defaults;
  LFloors.MinRsaModulusBits := 3072;
  LConfig := ClientBuilder.WithOcspStaplingRequest(True).WithServerVerification(
    TServerVerification.WebPki(FLookupRef).WithRevocation(TRevocationPosture.Hard)
    .WithMinimumStrength(LFloors)
    .WithIntermediateCertificates(TTlsLibTestCertificates.Field(ChainFile, 'issuer_cert'))
    .Build).Build;
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LConfig.RevocationPosture), 'posture');
  CheckEquals(3072, LConfig.CertificateStrengthPolicy.MinRsaModulusBits, 'floors');
  CheckEquals(1, System.Length(LConfig.IntermediateCertificates), 'intermediates');
  CheckTrue(LConfig.IssuerLookup = FLookupRef, 'and the lookup');
end;

procedure TTestIssuerLookupConfig.TestLookupAndRootsUnionOnAHandshake;
var
  LRoot: TBytes;
  LClient, LServer: ITlsEngine;
begin
  LRoot := TTlsLibTestCertificates.Field(AuthFile, 'root_cert');
  LClient := TTlsEngineFactory.CreateClientEngine(ClientBuilder.WithServerVerification(
    TServerVerification.WebPki(LRoot).WithIssuerLookup(FLookupRef).Build).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LClient.IsTerminal,
    'the root of the policy is trusted beside a lookup that knows nothing');
  FLookup.Offer(Pkix.Certificates.Parse(LRoot).SubjectName, TArray<TBytes>.Create(LRoot), nil);
  LClient := TTlsEngineFactory.CreateClientEngine(ClientBuilder.WithServerVerification(
    TServerVerification.WebPki(FUnrelated).WithIssuerLookup(FLookupRef).Build).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LClient.IsTerminal,
    'the root the lookup finds is trusted beside unrelated policy roots');
end;

procedure TTestIssuerLookupConfig.TestRootsAloneRefuseWhatTheLookupWouldTrust;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(ClientBuilder.WithServerVerification(
    TServerVerification.WebPki(FUnrelated).Build).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerBuilder.Build);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'control: without the lookup the unrelated roots refuse the server');
end;

procedure TTestIssuerLookupConfig.TestALaterVerificationReplacesTheLookup;
begin
  CheckTrue(ClientBuilder.WithServerVerification(TServerVerification.WebPki(FLookupRef).Build)
    .WithServerVerification(TServerVerification.WebPki(FUnrelated).Build).Build.IssuerLookup = nil,
    'the policy that replaced it carried none');
end;

procedure TTestIssuerLookupConfig.TestOneLookupServesBothRolesAndEachRoleAppliesItsOwnGuards;
var
  LClient: ITlsClientConfig;
  LServer: ITlsServerConfig;
begin
  LClient := ClientBuilder.WithServerVerification(TServerVerification.WebPki(FLookupRef).Build)
    .Build;
  LServer := ServerBuilder.WithPeerAuth(TClientAuthMode.Required).WithClientVerification(
    TClientVerification.WebPki(FLookupRef).Build).Build;
  CheckTrue(LClient.IssuerLookup = FLookupRef, 'the client role resolves the server chain');
  CheckTrue(LServer.IssuerLookup = FLookupRef, 'the server role resolves the client chain');
  CheckTrue(ServerBuildRaises(ServerBuilder.WithClientVerification(
    TClientVerification.WebPki(FLookupRef).Build)),
    'the server role alone would ignore it without a requested client certificate');
end;

procedure TTestIssuerLookupConfig.TestLookupAloneIsAClientTrustSourceAndVerifiesTheServer;
var
  LRoot: TBytes;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LRoot := TTlsLibTestCertificates.Field(AuthFile, 'root_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LRoot).SubjectName, TArray<TBytes>.Create(LRoot), nil);
  LClientConfig := ClientBuilder.WithServerVerification(
    TServerVerification.WebPki(FLookupRef).Build).Build;
  LServerConfig := ServerBuilder.Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LClient.IsTerminal,
    'the client verified the server through the lookup alone');
  FLookup.Forget;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'control: without the root the same config refuses the server');
end;

procedure TTestIssuerLookupConfig.TestLookupAloneIsAClientAuthTrustSourceAndVerifiesTheClient;
var
  LRoot: TBytes;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LRoot := TTlsLibTestCertificates.Field(AuthFile, 'root_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LRoot).SubjectName, TArray<TBytes>.Create(LRoot), nil);
  LClientConfig := ClientBuilder.WithServerVerification(TServerVerification.WebPki(LRoot).Build)
    .WithCredential(AuthCredential).Build;
  LServerConfig := ServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.WebPki(FLookupRef).Build).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking or LServer.IsTerminal,
    'the server verified the client through the lookup alone');
  FLookup.Forget;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'control: without the root the same config refuses the client');
end;

procedure TTestIssuerLookupConfig.TestLookupBesideAClientVerifierSourceBuildsAndKeepsTheSource;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := ClientBuilder.WithServerVerification(TServerVerification.VerifierSource(FCaptureRef)
    .WithIssuerLookup(FLookupRef).Build).Build;
  CheckTrue(LConfig.ServerVerifierSource = FCaptureRef, 'the source is the one given');
  CheckTrue(LConfig.IssuerLookup = FLookupRef, 'the lookup is carried beside it');
end;

procedure TTestIssuerLookupConfig.TestLookupBesideAServerVerifierSourceBuildsAndKeepsTheSource;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := ServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.VerifierSource(FCapture as
    IClientCertificateVerifierSource, FUnrelated).WithIssuerLookup(FLookupRef).Build).Build;
  CheckTrue(LConfig.ClientVerifierSource = (FCapture as IClientCertificateVerifierSource),
    'the source is the one given');
  CheckTrue(LConfig.IssuerLookup = FLookupRef, 'the lookup is carried beside it');
end;

procedure TTestIssuerLookupConfig.TestABuiltInSourceStaysBuiltInWithALookup;
var
  LConfig: ITlsClientConfig;
begin
  // a source is classified by its class, so the built-in one must not be seen as a wrapper
  LConfig := ClientBuilder.WithServerVerification(TServerVerification.WebPki(FUnrelated)
    .WithIssuerLookup(FLookupRef).Build).Build;
  CheckTrue(LConfig.ServerVerifierSource is TBuiltInServerVerifierSource, 'built in');
  CheckFalse(LConfig.ServerVerifierSource is TIssuerLookupServerVerifierSource, 'not the wrapper');
end;

procedure TTestIssuerLookupConfig.TestServerLookupWithoutPeerAuthIsRefused;
begin
  CheckTrue(ServerBuildRaises(ServerBuilder.WithClientVerification(
    TClientVerification.WebPki(FLookupRef).Build)),
    'a lookup on a server that requests no client certificate would be ignored');
end;

procedure TTestIssuerLookupConfig.TestServerPeerAuthWithAVerifierSourceAndNoRootsBuildsOnALookup;
begin
  CheckFalse(ServerBuildRaises(ServerBuilder.WithPeerAuth(TClientAuthMode.Required)
    .WithClientVerification(TClientVerification.VerifierSource(FCapture as
    IClientCertificateVerifierSource, TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
    .WithIssuerLookup(FLookupRef).Build)), 'the lookup is the roots the source consumes');
end;

procedure TTestIssuerLookupConfig.TestFactoryPassesAnyCertificateToTheDecorator;
begin
  CheckTrue(HandshakeAnchoredAtTheIssuer(TBundleAnchorRule.AnyCertificate),
    'the intermediate is an anchor under AnyCertificate');
end;

procedure TTestIssuerLookupConfig.TestFactoryPassesSelfSignedOnlyToTheDecorator;
begin
  CheckFalse(HandshakeAnchoredAtTheIssuer(TBundleAnchorRule.SelfSignedOnly),
    'the intermediate is chain material under SelfSignedOnly');
end;

procedure TTestIssuerLookupConfig.TestResumingClientWithALookupDefaultsToReverify;
begin
  CheckEquals(Ord(TResumeVerification.Reverify),
    Ord(ResumingClient.WithServerVerification(TServerVerification.WebPki(FLookupRef).Build)
    .Build.ResumeVerification), 'what a lookup trusts can change between connections');
end;

procedure TTestIssuerLookupConfig.TestAnExplicitReuseOriginalBesideALookupIsKept;
begin
  CheckEquals(Ord(TResumeVerification.ReuseOriginal),
    Ord(ResumingClient.WithResumeVerification(TResumeVerification.ReuseOriginal)
    .WithServerVerification(TServerVerification.WebPki(FLookupRef).Build).Build
    .ResumeVerification), 'the caller chose it');
end;

procedure TTestIssuerLookupConfig.TestResumingClientWithoutALookupKeepsReuseOriginal;
begin
  CheckEquals(Ord(TResumeVerification.ReuseOriginal),
    Ord(ResumingClient.WithServerVerification(TServerVerification.WebPki(FUnrelated).Build)
    .Build.ResumeVerification), 'the default is untouched without a lookup');
end;

procedure TTestIssuerLookupConfig.TestClientLookupWithoutACacheStillBuilds;
begin
  CheckEquals(Ord(TResumeVerification.ReuseOriginal),
    Ord(ClientBuilder.WithServerVerification(TServerVerification.WebPki(FLookupRef).Build)
    .Build.ResumeVerification), 'nothing to re-verify without a cache to resume from');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTrustComposition);
  RegisterTest(TTestIssuerLookup);
  RegisterTest(TTestIssuerLookupConfig);
{$ELSE}
  RegisterTest(TTestTrustComposition.Suite);
  RegisterTest(TTestIssuerLookup.Suite);
  RegisterTest(TTestIssuerLookupConfig.Suite);
{$ENDIF FPC}

end.
