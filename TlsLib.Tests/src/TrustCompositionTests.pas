{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Exercises the trust-composition rules the config builder enforces: anchor sources
/// UNION (multiple WithTrustStore/WithTrustAnchors calls accumulate), while a whole
/// certificate verifier is EXCLUSIVE (it replaces the pipeline and cannot be combined with any
/// anchor source, nor set twice) - the invariant the OS system-trust sources rely on.</summary>
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
  TlpTlsAlert,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpICertificateVerifierSource,
  TlpTrustPolicy,
  TlpServerName,
  TlpCertificateVerifier,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlsLibTestBase;

type
  TTestTrustComposition = class(TTlsLibAlgorithmTestCase)
  private
    FCerts: TStringList;
    function StoreOf(const AFieldName: string): ITrustAnchorStore;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestTwoAnchorStoresUnionIntoComposedStore;
    procedure TestDistrustingStoreDropsDistrustedRootsAndIsImmutable;
    procedure TestUnionCarriesAndAppliesDistrustAcrossStores;
    procedure TestBuildFreezesDistrustWithTheComposedStore;
    procedure TestCertificateVerifierLandsInFrozenConfig;
    procedure TestVerifierCombinedWithAnchorSourceIsRejected;
    // an empty store is still an anchor *source* for the exclusivity count (that rule runs before
    // the roots-based trust gate), so verifier + empty store is the exclusivity conflict, not empty-store
    procedure TestVerifierWithEmptyStoreStillConflicts;
    procedure TestTwoVerifiersAreRejected;
    procedure TestClientVerifierInstanceAndSourceRejected;
  end;

implementation

type
  /// <summary>A whole-verifier stub: it accepts everything and carries no anchors, standing in
  /// for an OS delegate so the composition rules can be exercised without real PKIX.</summary>
  TStubCertificateVerifier = class(TInterfacedObject, IServerCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

function TStubCertificateVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified.Path := AChain;
  AVerified.Outcome := TVerificationOutcome.Trusted;
  AAlert := TTlsAlertDescription.CertificateUnknown;
  Result := True;
end;

type
  // a client-certificate verifier instance and a source that mints one, to exercise the
  // dual-verifier guard for the client role (SF-AN)
  TStubClientCertificateVerifier = class(TInterfacedObject, IClientCertificateVerifier)
  public
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  TStubClientCertificateVerifierSource = class(TInterfacedObject,
    IClientCertificateVerifierSource)
  public
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

function TStubClientCertificateVerifier.VerifyClientCertificate(
  const AChain: TArray<TBytes>; out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified.Path := AChain;
  AVerified.Outcome := TVerificationOutcome.Trusted;
  AAlert := TTlsAlertDescription.CertificateUnknown;
  Result := True;
end;

function TStubClientCertificateVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
begin
  Result := TStubClientCertificateVerifier.Create as IClientCertificateVerifier;
end;

{ TTestTrustComposition }

procedure TTestTrustComposition.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
end;

procedure TTestTrustComposition.TearDown;
begin
  FCerts.Free;
  inherited TearDown;
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
    .WithTrustStore(StoreOf('root_cert'))
    .WithTrustStore(StoreOf('leaf_cert'))
    .Build;
  CheckEquals(2, System.Length(LConfig.TrustStore.RootCertificates),
    'both anchor sources union into the composed trust store');
  CheckTrue(LConfig.ServerVerifierSource <> nil,
    'no whole-verifier was set, so the built-in verifier source is installed by default');
end;

procedure TTestTrustComposition.TestDistrustingStoreDropsDistrustedRootsAndIsImmutable;
var
  LRoots, LDistrusted: TArray<TBytes>;
  LStore: IDistrustingTrustAnchorStore;
begin
  LRoots := TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']),
    DecodeHex(FCerts.Values['leaf_cert']));
  LDistrusted := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  LStore := TDistrustingTrustAnchorStore.Create(LRoots, LDistrusted);
  CheckEquals(1, System.Length(LStore.RootCertificates), 'a distrusted root is not an anchor');
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
  LDistrust: IDistrustingTrustAnchorStore;
begin
  // one store distrusts the leaf; another contributes it as an anchor: distrust wins
  LUnion := TUnionTrustAnchorStore.Create(TArray<ITrustAnchorStore>.Create(
    StoreOf('root_cert'), StoreOf('leaf_cert'),
    TDistrustingTrustAnchorStore.Create(nil,
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']))) as ITrustAnchorStore));
  CheckEquals(1, System.Length(LUnion.RootCertificates),
    'a root distrusted by any store is not an anchor of the union');
  CheckTrue(Supports(LUnion, IDistrustingTrustAnchorStore, LDistrust),
    'the union exposes the distrust set');
  CheckTrue(LDistrust.IsDistrusted(DecodeHex(FCerts.Values['leaf_cert'])), 'it carries the child distrust');
  CheckEquals(1, System.Length(LDistrust.DistrustedCertificates), 'the union of the distrust sets');
end;

procedure TTestTrustComposition.TestBuildFreezesDistrustWithTheComposedStore;
var
  LConfig: ITlsClientConfig;
  LDistrust: IDistrustingTrustAnchorStore;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(TDistrustingTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert'])),
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']))) as ITrustAnchorStore)
    .WithTrustAnchors(DecodeHex(FCerts.Values['root_cert']))
    .Build;
  CheckTrue(Supports(LConfig.TrustStore, IDistrustingTrustAnchorStore, LDistrust),
    'the frozen config keeps the distrust set');
  CheckTrue(LDistrust.IsDistrusted(DecodeHex(FCerts.Values['leaf_cert'])),
    'the distrusted certificate is still distrusted after composition with plain anchors');
end;

procedure TTestTrustComposition.TestCertificateVerifierLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
  LStub: IServerCertificateVerifier;
  LContext: TServerTrustContext;
begin
  // a whole-verifier is a valid, self-sufficient trust source (no anchors needed); it is wrapped
  // as an instance source that returns it unchanged for every connection
  LStub := TStubCertificateVerifier.Create as IServerCertificateVerifier;
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithDangerousCertificateVerifier(LStub)
    .Build;
  LContext := Default(TServerTrustContext);
  CheckTrue(LConfig.ServerVerifierSource.CreateServerVerifier(LContext) = LStub,
    'the injected whole-verifier is returned unchanged by the instance source');
end;

procedure TTestTrustComposition.TestVerifierCombinedWithAnchorSourceIsRejected;
var
  LRaised: Boolean;
begin
  // verifier + anchor source is the exclusivity conflict: refused at Build, fail-closed
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithDangerousCertificateVerifier(TStubCertificateVerifier.Create as IServerCertificateVerifier)
      .WithTrustStore(StoreOf('root_cert'))
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised,
    'a whole-verifier combined with an anchor source is refused at Build');
end;

procedure TTestTrustComposition.TestVerifierWithEmptyStoreStillConflicts;
var
  LMsg: string;
begin
  // the exclusivity rule counts a store as a source (empty or not) and runs before the roots gate,
  // so this raises the verifier conflict, not the empty-store message
  LMsg := '';
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithDangerousCertificateVerifier(TStubCertificateVerifier.Create as IServerCertificateVerifier)
      .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('exclusive', LMsg) > 0,
    'a verifier plus an empty store is the exclusivity conflict; got: ' + LMsg);
end;

procedure TTestTrustComposition.TestTwoVerifiersAreRejected;
var
  LRaised: Boolean;
begin
  // two whole-verifiers is the dual-verifier conflict: refused at Build
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithDangerousCertificateVerifier(TStubCertificateVerifier.Create as IServerCertificateVerifier)
      .WithDangerousCertificateVerifier(TStubCertificateVerifier.Create as IServerCertificateVerifier)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'setting two whole-verifiers is refused at Build');
end;

procedure TTestTrustComposition.TestClientVerifierInstanceAndSourceRejected;
var
  LRaised: Boolean;
begin
  // a client-verifier instance plus a client-verifier source is the dual-verifier conflict for the
  // client role: the source must not silently override the instance, so Build refuses it (SF-AN)
  LRaised := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithDangerousCertificateVerifier(
        TStubClientCertificateVerifier.Create as IClientCertificateVerifier)
      .WithCertificateVerifierSource(
        TStubClientCertificateVerifierSource.Create as IClientCertificateVerifierSource)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised,
    'a client-verifier instance combined with a client-verifier source is refused at Build');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTrustComposition);
{$ELSE}
  RegisterTest(TTestTrustComposition.Suite);
{$ENDIF FPC}

end.
