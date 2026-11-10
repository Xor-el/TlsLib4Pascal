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
  TlpTrustPolicy,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpPkixDomainTypes,
  TlpNegotiationTypes,
  TlpIClock,
  TlpClock,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpTlsCredential,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  MockCertificateVerifiers,
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
    procedure TestLayeredStoreOverNoBaseIsAPlainStore;
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
    procedure TestServerDecoratorRefusesANilLookup;
    procedure TestServerDecoratorRefusesANilSource;
    procedure TestClientDecoratorRefusesANilLookup;
    procedure TestClientDecoratorRefusesANilSource;
    procedure TestServerVerificationCarriesTheLookup;
    procedure TestClientVerificationCarriesTheLookup;
    procedure TestServerVerificationBuilderRefusesANilLookup;
    procedure TestClientVerificationBuilderRefusesANilLookup;
    procedure TestFactoryAppliesTheLookupToTheServerCertificate;
    procedure TestFactoryAppliesTheLookupToTheClientCertificate;
    procedure TestTheLookupIsNotPartOfTheStoredVerifierSource;
    procedure TestABuiltInSourceStaysBuiltInWithALookup;
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

procedure TTestTrustComposition.TestLayeredStoreOverNoBaseIsAPlainStore;
var
  LStore: ITrustAnchorStore;
begin
  LStore := TTrustAnchorStore.Layered(nil, TArray<TBytes>.Create(Der('root_cert'),
    Der('leaf_cert'), Der('root_cert')));
  CheckEquals(2, LStore.AnchorCount, 'the extras are the anchors, once each');
  CheckTrue(LStore.IsAnchor(Der('leaf_cert')), 'an extra is an anchor');
  CheckFalse(Supports(LStore, ILayeredTrustAnchorStore), 'there is no base to layer on');
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
  LSource := TIssuerLookupServerVerifierSource.Create(AInner, FLookupRef)
    as IServerCertificateVerifierSource;
  Result := LSource.CreateServerVerifier(AContext);
end;

function TTestIssuerLookup.ClientVerifier(const AInner: IClientCertificateVerifierSource;
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LSource: IClientCertificateVerifierSource;
begin
  LSource := TIssuerLookupClientVerifierSource.Create(AInner, FLookupRef)
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
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, LContext), TArray<TBytes>.Create(LLeaf), LAlert),
    'the root is below the anchor floor');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'it is never an anchor');
end;

procedure TTestIssuerLookup.TestStaticDistrustBeatsALookedUpAnchor;
var
  LDistrusting: ITrustAnchorStore;
  LAlert: TTlsAlertDescription;
begin
  FLookup.Offer(FRootName, TArray<TBytes>.Create(FRoot), nil);
  CheckTrue(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(FUnrelated)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'control: the root is not distrusted');
  LDistrusting := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field(EcFile, 'root2_cert')), TArray<TBytes>.Create(FRoot));
  CheckFalse(ServerVerdict(ServerVerifier(TBuiltInServerVerifierSource.Create
    as IServerCertificateVerifierSource, ServerContext(LDistrusting)),
    TArray<TBytes>.Create(FLeaf, FIssuer), LAlert), 'the static distrust wins');
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

procedure TTestIssuerLookup.TestServerDecoratorRefusesANilLookup;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TIssuerLookupServerVerifierSource.Create(FCaptureRef, nil);
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
    TIssuerLookupServerVerifierSource.Create(nil, FLookupRef);
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
    TIssuerLookupClientVerifierSource.Create(FCapture as IClientCertificateVerifierSource, nil);
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
    TIssuerLookupClientVerifierSource.Create(nil, FLookupRef);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil source is refused');
end;

procedure TTestIssuerLookup.TestServerVerificationCarriesTheLookup;
begin
  CheckTrue(TServerVerification.WebPki(FUnrelated).Build.IssuerLookup = nil,
    'none by default');
  CheckTrue(TServerVerification.WebPki(FUnrelated).WithIssuerLookup(FLookupRef).Build.IssuerLookup
    = FLookupRef, 'the lookup it was given');
end;

procedure TTestIssuerLookup.TestClientVerificationCarriesTheLookup;
begin
  CheckTrue(TClientVerification.WebPki(FUnrelated).Build.IssuerLookup = nil,
    'none by default');
  CheckTrue(TClientVerification.WebPki(FUnrelated).WithIssuerLookup(FLookupRef).Build.IssuerLookup
    = FLookupRef, 'the lookup it was given');
end;

procedure TTestIssuerLookup.TestServerVerificationBuilderRefusesANilLookup;
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

procedure TTestIssuerLookup.TestClientVerificationBuilderRefusesANilLookup;
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

procedure TTestIssuerLookup.TestFactoryAppliesTheLookupToTheServerCertificate;
var
  LRoot: TBytes;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LRoot := TTlsLibTestCertificates.Field(AuthFile, 'root_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LRoot).SubjectName, TArray<TBytes>.Create(LRoot), nil);
  LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(FUnrelated)
    .WithIssuerLookup(FLookupRef).Build).Build;
  LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(AuthCredential).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LClient.IsTerminal,
    'the client verified the server through the lookup');
  FLookup.Forget;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'control: without the root the same config refuses the server');
end;

procedure TTestIssuerLookup.TestFactoryAppliesTheLookupToTheClientCertificate;
var
  LRoot: TBytes;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LRoot := TTlsLibTestCertificates.Field(AuthFile, 'root_cert');
  FLookup.Offer(Pkix.Certificates.Parse(LRoot).SubjectName, TArray<TBytes>.Create(LRoot), nil);
  LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(LRoot).Build)
    .WithCredential(AuthCredential).Build;
  LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(AuthCredential)
    .WithClientVerification(TClientVerification.WebPki(FUnrelated)
    .WithIssuerLookup(FLookupRef).Build)
    .WithPeerAuth(TClientAuthMode.Required).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking or LServer.IsTerminal,
    'the server verified the client through the lookup');
  FLookup.Forget;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'control: without the root the same config refuses the client');
end;

procedure TTestIssuerLookup.TestTheLookupIsNotPartOfTheStoredVerifierSource;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.VerifierSource(FCaptureRef)
    .WithIssuerLookup(FLookupRef).Build).Build;
  CheckTrue(LConfig.ServerVerifierSource = FCaptureRef, 'the source is the one given');
  CheckTrue(LConfig.IssuerLookup = FLookupRef, 'the lookup is carried beside it');
end;

procedure TTestIssuerLookup.TestABuiltInSourceStaysBuiltInWithALookup;
var
  LConfig: ITlsClientConfig;
begin
  // a source is classified by its class, so the built-in one must not be seen as a wrapper
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(FUnrelated)
    .WithIssuerLookup(FLookupRef).Build).Build;
  CheckTrue(LConfig.ServerVerifierSource is TBuiltInServerVerifierSource, 'built in');
  CheckFalse(LConfig.ServerVerifierSource is TIssuerLookupServerVerifierSource, 'not the wrapper');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTrustComposition);
  RegisterTest(TTestIssuerLookup);
{$ELSE}
  RegisterTest(TTestTrustComposition.Suite);
  RegisterTest(TTestIssuerLookup.Suite);
{$ENDIF FPC}

end.
