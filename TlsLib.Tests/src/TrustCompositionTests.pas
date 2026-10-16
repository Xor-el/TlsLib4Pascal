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
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpICertificateVerifierSource,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  MockCertificateVerifiers,
  TlsLibTestBase;

type
  TTestTrustComposition = class(TTlsLibAlgorithmTestCase)
  private
    FCerts: TStringList;
    function StoreOf(const AFieldName: string): ITrustAnchorStore;
    function UnionOverWatchedStore(AReleased: PBoolean): ITrustAnchorStore;
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
    procedure TestBuildRefusesAUnionWhoseDistrustRemovesEveryAnchor;
    procedure TestCertificateVerifierLandsInFrozenConfig;
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestTrustComposition);
{$ELSE}
  RegisterTest(TTestTrustComposition.Suite);
{$ENDIF FPC}

end.
