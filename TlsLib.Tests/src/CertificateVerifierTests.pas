{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CertificateVerifierTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpPkixDomainTypes,
  TlpDateTimeUtilities,
  TlpSystemTimeUtilities,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTrustTypes,
  TlpServerName,
  TlpCertificateVerifier,
  TlpICertificateVerifierSource,
  TlpCertificateVerifierSource,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpNegotiationTypes,
  TlpTrustPolicy,
  TlsLibTestBase;

type
  /// <summary>Wraps a trust-anchor store and counts how many times its anchor set is copied out, to
  /// prove the verify pipeline never copies it per verification.</summary>
  TCountingTrustAnchorStore = class(TInterfacedObject, ITrustAnchorStore)
  strict private
    FInner: ITrustAnchorStore;
    FReads: Int32;
  public
    constructor Create(const AInner: ITrustAnchorStore);
    function AnchorCount: Int32;
    function RootCertificates: TArray<TBytes>;
    function IsAnchor(const ACertificate: TBytes): Boolean;
    function DistrustedCertificates: TArray<TBytes>;
    function IsDistrusted(const ACertificate: TBytes): Boolean;
    property Reads: Int32 read FReads;
  end;

  /// <summary>A whole-verifier instance that accepts or rejects every chain, standing in for a
  /// caller-supplied verifier behind an instance source.</summary>
  TFixedVerdictVerifier = class(TInterfacedObject, IServerCertificateVerifier,
    IClientCertificateVerifier)
  strict private
    FAccept: Boolean;
  public
    constructor Create(AAccept: Boolean);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>The verify callback an instance source composes over a caller-supplied verifier.</summary>
  TTestInstanceSourceVerifyCallback = class(TTlsLibAlgorithmTestCase)
  strict private
    FAccept: Boolean;
    FCalls: Int32;
    function Callback(const AChain: TArray<TBytes>; const AHostName: string): Boolean;
    function Chain: TArray<TBytes>;
    // the verifier an instance source yields over AInner, with the callback set or not
    function ServerVerifier(const AInner: IServerCertificateVerifier;
      AWithCallback: Boolean): IServerCertificateVerifier;
    function ClientVerifier(const AInner: IClientCertificateVerifier;
      AWithCallback: Boolean): IClientCertificateVerifier;
  published
    procedure TestServerCallbackRejectsOverAcceptingInstance;
    procedure TestServerCallbackAcceptKeepsInstanceVerdict;
    procedure TestServerCallbackNotRunWhenInstanceRejects;
    procedure TestServerWithoutCallbackReturnsTheInstance;
    procedure TestClientCallbackRejectsOverAcceptingInstance;
    procedure TestClientCallbackNotRunWhenInstanceRejects;
    procedure TestClientWithoutCallbackReturnsTheInstance;
  end;

  TTestCertificateVerifier = class(TTlsLibAlgorithmTestCase)
  private
    FCerts: TStringList;
    // a three-level hierarchy (leaf <- issuer <- root) so an incomplete chain can be exercised
    FChain3: TStringList;
    // a dedicated root with dual-EKU / clientAuth-only / no-EKU leaves for the EKU-role tests
    FEku: TStringList;
    // self-signed edge certs pinned as their own anchor, for end-entity EKU enforcement
    FEkuEdge: TStringList;
    // one root key re-issued under several self-signed certificates (same subject), plus a
    // same-subject different-key lookalike, for the anchor-identity tests
    FReissued: TStringList;
    // a leaf issued by name X plus self-issued fillers all named X, for the path-building bound
    FFlood: TStringList;
    function Flood(const AName: string): TBytes;
    // the alert the path validator raises for AChain against AAnchor, and how long it took;
    // CloseNotify when it raised none (the chain validated)
    function PathAlert(const AChain: TArray<TBytes>; const AAnchor: TBytes;
      out AElapsedMs: Int64): TTlsAlertDescription;
    function RingChain: TArray<TBytes>;
    // the flood leaf followed by the first ACount fillers
    function FloodChain(ACount: Int32): TArray<TBytes>;
    function Cert(const AName: string): TBytes;
    function Chain3(const AName: string): TBytes;
    function EkuCert(const AName: string): TBytes;
    function EkuEdgeCert(const AName: string): TBytes;
    function Reissued(const AName: string): TBytes;
    function CountedVerifies(const AStore: TCountingTrustAnchorStore;
      ACount: Int32): Boolean;
    function VerifierFor(const ARoot: TBytes; ACheckHostName: Boolean)
      : IServerCertificateVerifier;
    // a verifier trusting ARoot with the chain-algorithm policy switched on, as the engine
    // wires it: only AAdvertised signature schemes are acceptable on the path
    function PolicyVerifierFor(const ARoot: TBytes; const AAdvertised: TArray<UInt16>)
      : IServerCertificateVerifier; overload;
    function PolicyVerifierFor(const ARoot: TBytes; const AAdvertised: TArray<UInt16>;
      const APolicy: TCertificateStrengthPolicy): IServerCertificateVerifier; overload;
    // a verifier trusting ARoot and seeded with AIntermediates for path building; host-name
    // checking is off so these tests isolate PKIX path construction
    function IntermediateVerifierFor(const ARoot: TBytes;
      const AIntermediates: TArray<TBytes>): IServerCertificateVerifier;
    function ClientVerifierFor(const ARoot: TBytes): IClientCertificateVerifier;
    // a verifier trusting ARoot over a store that also distrusts ADistrusted, seeded with
    // AIntermediates for path building
    function DistrustVerifierFor(const ARoot: TBytes;
      const ADistrusted, AIntermediates: TArray<TBytes>): IServerCertificateVerifier;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestOptionsInitializeMatchesConvenienceDefaults;
    procedure TestValidChainTrusted;
    procedure TestExpiredRejectedAsCertificateExpired;
    procedure TestExpiredExtraneousCertificateIgnored;
    procedure TestUnrelatedExpiredCertificateDoesNotMaskUnknownCa;
    procedure TestNilCollaboratorsAreRefused;
    procedure TestUntrustedRootRejectedAsUnknownCa;
    procedure TestHostNameMismatchRejectedAsBadCertificate;
    procedure TestEmptyChainRejected;
    procedure TestHostNameCheckDisabledIgnoresName;
    procedure TestIncompleteChainWithoutIntermediatesRejected;
    procedure TestIncompleteChainCompletedByIntermediates;
    procedure TestCompleteChainStillTrustedWithIntermediates;
    // a trust anchor's own nameConstraints bound every path under it (RFC 5280 6.1.1 (d))
    procedure TestAnchorNameConstraintsAreEnforced;
    // extendedKeyUsage role enforcement (RFC 5280 4.2.1.12, required-if-present)
    procedure TestServerCertWithClientAuthOnlyEkuRejected;
    procedure TestServerCertWithNoEkuAccepted;
    procedure TestClientCertWithServerAuthOnlyEkuRejected;
    procedure TestClientCertWithClientAuthAccepted;
    // end-entity EKU is enforced even when the leaf is itself the pinned trust anchor
    procedure TestPinnedSelfSignedClientAuthOnlyLeafRejectedAsServer;
    // a present-but-unparsable EKU is a certificate fault, not an internal error
    procedure TestMalformedEkuRejectedAsBadCertificate;
    // the validated path is issuer-ordered (leaf, its issuer, ..., anchor) whatever order the
    // peer presented (RFC 8446 4.4.2 tolerates arbitrary ordering), so the staple check keys off
    // the real issuer at [1]
    procedure TestMisorderedChainValidatedPathIsIssuerOrdered;
    procedure TestMisorderedChainRevokedStapleAborts;
    procedure TestReorderedChainBuildsFromPresentedFirstCert;
    // the trust anchor is identified by subject + key, not exact encoding (RFC 5280 6.1.1(d); a
    // constrained anchor is RFC 5937):
    // a peer-sent re-issued copy of the configured root collapses onto the configured DER and
    // is exempt from path policy; a same-subject different-key root is not the anchor
    procedure TestDistrustedIntermediateIsRejectedAsBadCertificate;
    procedure TestDistrustedLeafIsRejectedAsBadCertificate;
    procedure TestDistrustedIntermediateIsBypassedByAnAlternatePath;
    procedure TestDistrustedConfiguredIntermediateIsNotUsedForCompletion;
    procedure TestUnrelatedDistrustKeepsUnknownCa;
    procedure TestDistrustMatchIsExactDer;
    procedure TestReencodedDistrustedIntermediateStillFails;
    procedure TestPeerReissuedRootAcceptedAndCollapsed;
    procedure TestPeerSha1ReissuedRootExemptFromChainPolicy;
    procedure TestSha1SelfSignedRootNotConfiguredRejected;
    procedure TestBareVerifierRefusesSha1SignedIntermediate;
    procedure TestSha1ChainSignatureAdmittedWhenNamedInThePolicy;
    procedure TestMd5ChainSignatureRefusedEvenWhenAdmitted;
    // a PKCS#1 v1.5 chain signature must carry the DigestInfo NULL parameters (RFC 8017 9.2)
    procedure TestChainSignatureWithoutDigestInfoNullIsRefused;
    procedure TestSameSubjectDifferentKeyRootIgnoredForConfiguredAnchor;
    // the anchor set is fetched once per verify and shared by path validation and the chain policy
    procedure TestAnchorSetCopiedOnceAcrossVerifies;
    procedure TestDistinctStoresNeverShareCachedAnchors;
    procedure TestRepeatedStoresOverOneContentDoNotEvictOthers;
    // path building is bounded against a peer-controlled flood of same-named certificates, and a
    // nil parse result gets the right alert
    procedure TestSelfIssuedFillerFloodFailsFast;
    procedure TestRingOfSameNamedCertificatesFailsFast;
    procedure TestPerSubjectPoolKeepsFirstPresented;
    procedure TestEmptyOrNonDerEntryIsBadCertificate;
    procedure TestChainOverEntryCapRefused;
    procedure TestChainLimitsAdmitsChainCapsEveryDimension;
  end;

implementation

{ TFixedVerdictVerifier }

constructor TFixedVerdictVerifier.Create(AAccept: Boolean);
begin
  inherited Create;
  FAccept := AAccept;
end;

function TFixedVerdictVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := FAccept;
  if Result then
    AVerified.Path := AChain;
end;

function TFixedVerdictVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := VerifyServerCertificate(AChain, Default(TServerName), nil, AVerified, AAlert);
end;

{ TTestInstanceSourceVerifyCallback }

function TTestInstanceSourceVerifyCallback.Callback(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  System.Inc(FCalls);
  Result := FAccept;
end;

function TTestInstanceSourceVerifyCallback.Chain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(TBytes.Create(1, 2, 3));
end;

function TTestInstanceSourceVerifyCallback.ServerVerifier(
  const AInner: IServerCertificateVerifier; AWithCallback: Boolean): IServerCertificateVerifier;
var
  LContext: TServerTrustContext;
  LSource: IServerCertificateVerifierSource;
begin
  LContext := Default(TServerTrustContext);
  if AWithCallback then
    LContext.Dangerous.VerifyCallback := Callback;
  LSource := TInstanceServerVerifierSource.Create(AInner) as IServerCertificateVerifierSource;
  Result := LSource.CreateServerVerifier(LContext);
end;

function TTestInstanceSourceVerifyCallback.ClientVerifier(
  const AInner: IClientCertificateVerifier; AWithCallback: Boolean): IClientCertificateVerifier;
var
  LContext: TClientTrustContext;
  LSource: IClientCertificateVerifierSource;
begin
  LContext := Default(TClientTrustContext);
  if AWithCallback then
    LContext.Dangerous.VerifyCallback := Callback;
  LSource := TInstanceClientVerifierSource.Create(AInner) as IClientCertificateVerifierSource;
  Result := LSource.CreateClientVerifier(LContext);
end;

procedure TTestInstanceSourceVerifyCallback.TestServerCallbackRejectsOverAcceptingInstance;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  FAccept := False;
  LVerifier := ServerVerifier(TFixedVerdictVerifier.Create(True) as IServerCertificateVerifier,
    True);
  CheckFalse(LVerifier.VerifyServerCertificate(Chain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert), 'the callback rejects what the instance accepted');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckEquals(0, System.Length(LVerified.Path), 'a rejection carries no validated path');
  CheckEquals(1, FCalls, 'the callback ran once');
end;

procedure TTestInstanceSourceVerifyCallback.TestServerCallbackAcceptKeepsInstanceVerdict;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  FAccept := True;
  LVerifier := ServerVerifier(TFixedVerdictVerifier.Create(True) as IServerCertificateVerifier,
    True);
  CheckTrue(LVerifier.VerifyServerCertificate(Chain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert), 'an accepting callback leaves the instance verdict');
  CheckEquals(1, System.Length(LVerified.Path), 'the instance path is kept');
end;

procedure TTestInstanceSourceVerifyCallback.TestServerCallbackNotRunWhenInstanceRejects;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  FAccept := True;
  LVerifier := ServerVerifier(TFixedVerdictVerifier.Create(False) as IServerCertificateVerifier,
    True);
  CheckFalse(LVerifier.VerifyServerCertificate(Chain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert), 'the callback cannot rescue a rejection');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the instance alert is kept');
  CheckEquals(0, FCalls, 'the callback is not consulted');
end;

procedure TTestInstanceSourceVerifyCallback.TestServerWithoutCallbackReturnsTheInstance;
var
  LInstance, LVerifier: IServerCertificateVerifier;
begin
  LInstance := TFixedVerdictVerifier.Create(True) as IServerCertificateVerifier;
  LVerifier := ServerVerifier(LInstance, False);
  CheckTrue(LVerifier = LInstance, 'no callback leaves the instance undecorated');
end;

procedure TTestInstanceSourceVerifyCallback.TestClientCallbackRejectsOverAcceptingInstance;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  FAccept := False;
  LVerifier := ClientVerifier(TFixedVerdictVerifier.Create(True) as IClientCertificateVerifier,
    True);
  CheckFalse(LVerifier.VerifyClientCertificate(Chain, LVerified, LAlert),
    'the callback rejects what the instance accepted');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckEquals(0, System.Length(LVerified.Path), 'a rejection carries no validated path');
end;

procedure TTestInstanceSourceVerifyCallback.TestClientCallbackNotRunWhenInstanceRejects;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  FAccept := True;
  LVerifier := ClientVerifier(TFixedVerdictVerifier.Create(False) as IClientCertificateVerifier,
    True);
  CheckFalse(LVerifier.VerifyClientCertificate(Chain, LVerified, LAlert),
    'the callback cannot rescue a rejection');
  CheckEquals(0, FCalls, 'the callback is not consulted');
end;

procedure TTestInstanceSourceVerifyCallback.TestClientWithoutCallbackReturnsTheInstance;
var
  LInstance, LVerifier: IClientCertificateVerifier;
begin
  LInstance := TFixedVerdictVerifier.Create(True) as IClientCertificateVerifier;
  LVerifier := ClientVerifier(LInstance, False);
  CheckTrue(LVerifier = LInstance, 'no callback leaves the instance undecorated');
end;

{ TCountingTrustAnchorStore }

constructor TCountingTrustAnchorStore.Create(const AInner: ITrustAnchorStore);
begin
  inherited Create;
  FInner := AInner;
end;

function TCountingTrustAnchorStore.AnchorCount: Int32;
begin
  Result := FInner.AnchorCount;
end;

function TCountingTrustAnchorStore.RootCertificates: TArray<TBytes>;
begin
  System.Inc(FReads);
  Result := FInner.RootCertificates;
end;

function TCountingTrustAnchorStore.IsAnchor(const ACertificate: TBytes): Boolean;
begin
  Result := FInner.IsAnchor(ACertificate);
end;

function TCountingTrustAnchorStore.DistrustedCertificates: TArray<TBytes>;
begin
  Result := FInner.DistrustedCertificates;
end;

function TCountingTrustAnchorStore.IsDistrusted(const ACertificate: TBytes): Boolean;
begin
  Result := FInner.IsDistrusted(ACertificate);
end;

{ TTestCertificateVerifier }

procedure TTestCertificateVerifier.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  FChain3 := LoadVectorFields('Certs/OcspStapling.txt');
  FEku := LoadVectorFields('Certs/ClientAuthChain.txt');
  FEkuEdge := LoadVectorFields('Certs/SelfSignedEkuEdge.txt');
  FReissued := LoadVectorFields('Certs/ReissuedRoot.txt');
  FFlood := LoadVectorFields('Certs/PathBuildFlood.txt');
end;

procedure TTestCertificateVerifier.TearDown;
begin
  FCerts.Free;
  FChain3.Free;
  FEku.Free;
  FEkuEdge.Free;
  FReissued.Free;
  FFlood.Free;
  inherited TearDown;
end;

function TTestCertificateVerifier.Reissued(const AName: string): TBytes;
begin
  Result := DecodeHex(FReissued.Values[AName]);
end;

function TTestCertificateVerifier.Flood(const AName: string): TBytes;
begin
  Result := DecodeHex(FFlood.Values[AName]);
end;

function TTestCertificateVerifier.FloodChain(ACount: Int32): TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ACount + 1);
  Result[0] := Flood('leaf');
  for LI := 0 to ACount - 1 do
    Result[LI + 1] := Flood(Format('filler_%.2d', [LI]));
end;

function TTestCertificateVerifier.PolicyVerifierFor(const ARoot: TBytes;
  const AAdvertised: TArray<UInt16>): IServerCertificateVerifier;
begin
  Result := PolicyVerifierFor(ARoot, AAdvertised, TCertificateStrengthPolicy.Defaults);
end;

function TTestCertificateVerifier.PolicyVerifierFor(const ARoot: TBytes;
  const AAdvertised: TArray<UInt16>;
  const APolicy: TCertificateStrengthPolicy): IServerCertificateVerifier;
var
  LVerifier: TCertificateVerifier;
begin
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore, False);
  Result := LVerifier;
  LVerifier.SetChainAlgorithmPolicy(APolicy, AAdvertised);
end;

function TTestCertificateVerifier.Cert(const AName: string): TBytes;
begin
  Result := DecodeHex(FCerts.Values[AName]);
end;

function TTestCertificateVerifier.EkuCert(const AName: string): TBytes;
begin
  Result := DecodeHex(FEku.Values[AName]);
end;

function TTestCertificateVerifier.EkuEdgeCert(const AName: string): TBytes;
begin
  Result := DecodeHex(FEkuEdge.Values[AName]);
end;

function TTestCertificateVerifier.Chain3(const AName: string): TBytes;
begin
  Result := DecodeHex(FChain3.Values[AName]);
end;

function TTestCertificateVerifier.VerifierFor(const ARoot: TBytes;
  ACheckHostName: Boolean): IServerCertificateVerifier;
begin
  Result := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    ACheckHostName) as IServerCertificateVerifier;
end;

function TTestCertificateVerifier.ClientVerifierFor(const ARoot: TBytes)
  : IClientCertificateVerifier;
begin
  Result := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    False) as IClientCertificateVerifier;
end;

function TTestCertificateVerifier.IntermediateVerifierFor(const ARoot: TBytes;
  const AIntermediates: TArray<TBytes>): IServerCertificateVerifier;
var
  LOptions: TCertificateVerifierOptions;
begin
  LOptions.Intermediates := AIntermediates;
  Result := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    False, LOptions) as IServerCertificateVerifier;
end;

function TTestCertificateVerifier.DistrustVerifierFor(const ARoot: TBytes;
  const ADistrusted, AIntermediates: TArray<TBytes>): IServerCertificateVerifier;
var
  LOptions: TCertificateVerifierOptions;
begin
  LOptions.Intermediates := AIntermediates;
  Result := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot), ADistrusted)
    as ITrustAnchorStore, False, LOptions) as IServerCertificateVerifier;
end;

procedure TTestCertificateVerifier.TestDistrustedIntermediateIsRejectedAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LChain: TArray<TBytes>;
begin
  LChain := TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'));
  CheckTrue(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(LChain,
    TServerName.DnsName(''), nil, LVerified, LAlert), 'control: the chain is trusted');
  CheckFalse(DistrustVerifierFor(Reissued('root_cert'),
    TArray<TBytes>.Create(Reissued('issuer_cert')), nil).VerifyServerCertificate(LChain,
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a path through a distrusted intermediate is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'it is an explicit distrust (bad_certificate), not an unknown CA');
end;

procedure TTestCertificateVerifier.TestDistrustedLeafIsRejectedAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  CheckFalse(DistrustVerifierFor(Reissued('root_cert'),
    TArray<TBytes>.Create(Reissued('leaf_cert')), nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert), 'a distrusted leaf is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'bad_certificate');
end;

procedure TTestCertificateVerifier.TestDistrustedIntermediateIsBypassedByAnAlternatePath;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the peer also sent a twin of the distrusted issuer (same key and subject, a different
  // certificate): the path is built through the twin, so a distrusted cert in the pool does not
  // sink a chain that has a valid alternative
  CheckTrue(DistrustVerifierFor(Reissued('root_cert'),
    TArray<TBytes>.Create(Reissued('issuer_cert')), nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('issuer_twin_cert')), TServerName.DnsName(''), nil, LVerified, LAlert),
    'an alternate path avoiding the distrusted certificate is accepted');
  CheckEqualBytes('the path runs through the twin', Reissued('issuer_twin_cert'),
    LVerified.Path[1]);
end;

procedure TTestCertificateVerifier.TestDistrustedConfiguredIntermediateIsNotUsedForCompletion;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LLeafOnly: TArray<TBytes>;
begin
  LLeafOnly := TArray<TBytes>.Create(Reissued('leaf_cert'));
  CheckTrue(DistrustVerifierFor(Reissued('root_cert'), nil,
    TArray<TBytes>.Create(Reissued('issuer_cert'))).VerifyServerCertificate(LLeafOnly,
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'control: a configured intermediate completes a leaf-only chain');
  CheckFalse(DistrustVerifierFor(Reissued('root_cert'),
    TArray<TBytes>.Create(Reissued('issuer_cert')),
    TArray<TBytes>.Create(Reissued('issuer_cert'))).VerifyServerCertificate(LLeafOnly,
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a distrusted configured intermediate is not used to complete the path');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'bad_certificate');
end;

procedure TTestCertificateVerifier.TestUnrelatedDistrustKeepsUnknownCa;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // a distrusted certificate is withheld from the chain, but the chain fails for an unrelated
  // reason (a foreign root): the alert stays unknown_ca, not bad_certificate
  CheckFalse(DistrustVerifierFor(Reissued('root2_cert'),
    TArray<TBytes>.Create(Reissued('issuer_twin_cert')), nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('issuer_twin_cert')), TServerName.DnsName(''), nil, LVerified, LAlert),
    'a chain to an untrusted root is refused');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'a genuine unknown CA keeps its alert when an unrelated certificate was withheld');
end;

procedure TTestCertificateVerifier.TestDistrustMatchIsExactDer;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // distrusting the twin says nothing about the issuer: the match is on the whole certificate
  CheckTrue(DistrustVerifierFor(Reissued('root_cert'),
    TArray<TBytes>.Create(Reissued('issuer_twin_cert')), nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'an unrelated distrusted certificate leaves the verdict unchanged');
end;

procedure TTestCertificateVerifier.TestReencodedDistrustedIntermediateStillFails;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LIssuer, LReencoded: TBytes;
  LLen: Int32;
begin
  // the same certificate with a non-minimal outer length (30 82 hh ll -> 30 83 00 hh ll): the
  // outer SEQUENCE is not covered by the signature, so a peer can re-encode a distrusted
  // certificate; it must not slip past the distrust check
  LIssuer := Reissued('issuer_cert');
  CheckEquals($30, LIssuer[0], 'the certificate is a SEQUENCE');
  CheckEquals($82, LIssuer[1], 'the outer length is the two-byte form');
  LLen := (LIssuer[2] shl 8) or LIssuer[3];
  LReencoded := ConcatBytes(DecodeHex('308300'), System.Copy(LIssuer, 2, System.Length(LIssuer) - 2));
  CheckEquals(System.Length(LIssuer) - 4, LLen, 'the length field covers the body');
  // control: without the distrust the re-encoded chain verifies, so the refusal below is the
  // post-check and not a parse failure
  CheckTrue(DistrustVerifierFor(Reissued('root_cert'), nil, nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), LReencoded), TServerName.DnsName(''), nil,
    LVerified, LAlert), 'the re-encoded chain verifies when nothing is distrusted');
  CheckFalse(DistrustVerifierFor(Reissued('root_cert'),
    TArray<TBytes>.Create(LIssuer), nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), LReencoded), TServerName.DnsName(''), nil,
    LVerified, LAlert), 'a re-encoded distrusted intermediate is still refused');
end;

procedure TTestCertificateVerifier.TestValidChainTrusted;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  CheckTrue(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('localhost'), nil,
    LVerified, LAlert),
    'a valid leaf chaining to the trusted root, matching the host, is trusted');
end;

procedure TTestCertificateVerifier.TestOptionsInitializeMatchesConvenienceDefaults;
var
  LOptions: TCertificateVerifierOptions;
  LStore: ITrustAnchorStore;
  LConvenience, LFromOptions: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // a freshly declared options value must carry exactly the defaults the four-arg convenience
  // constructor applies, so the four-arg and options construction paths are interchangeable
  CheckEquals(TCertificateChainLimits.Defaults.MaxCertificateLength,
    LOptions.ChainLimits.MaxCertificateLength, 'default per-certificate cap');
  CheckEquals(TCertificateChainLimits.Defaults.MaxTotalChainLength,
    LOptions.ChainLimits.MaxTotalChainLength, 'default total-chain cap');
  CheckEquals(Ord(TRevocationPosture.Soft), Ord(LOptions.RevocationPosture),
    'default revocation posture is Soft');
  CheckEquals(Ord(TVerdictDeferral.None), Ord(LOptions.Deferral),
    'default deferral is None');
  CheckEquals(Ord(TVerificationOccasion.InitialHandshake), Ord(LOptions.Occasion),
    'default occasion is the initial handshake');
  CheckEquals(0, System.Length(LOptions.Intermediates), 'no seeded intermediates by default');
  CheckFalse(LOptions.StatusRequestOffered, 'status_request not offered by default');
  CheckFalse(LOptions.Dangerous.InsecureSkipVerify, 'no insecure skip-verify by default');
  CheckFalse(Assigned(LOptions.Dangerous.VerifyCallback), 'no verify callback by default');

  LStore := TTrustAnchorStore.Create(TArray<TBytes>.Create(Cert('root_cert')))
    as ITrustAnchorStore;
  LConvenience := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    LStore, True) as IServerCertificateVerifier;
  LFromOptions := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    LStore, True, LOptions) as IServerCertificateVerifier;

  CheckTrue(LConvenience.VerifyServerCertificate(TArray<TBytes>.Create(Cert('leaf_cert')),
    TServerName.DnsName('localhost'), nil, LVerified, LAlert),
    'the convenience-built verifier accepts a valid chain');
  CheckTrue(LFromOptions.VerifyServerCertificate(TArray<TBytes>.Create(Cert('leaf_cert')),
    TServerName.DnsName('localhost'), nil, LVerified, LAlert),
    'the options-built verifier accepts the same valid chain');
  CheckFalse(LConvenience.VerifyServerCertificate(TArray<TBytes>.Create(Cert('expired_cert')),
    TServerName.DnsName('localhost'), nil, LVerified, LAlert),
    'the convenience-built verifier rejects an expired chain');
  CheckFalse(LFromOptions.VerifyServerCertificate(TArray<TBytes>.Create(Cert('expired_cert')),
    TServerName.DnsName('localhost'), nil, LVerified, LAlert),
    'the options-built verifier rejects the same expired chain');
end;

procedure TTestCertificateVerifier.TestExpiredRejectedAsCertificateExpired;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('expired_cert')), TServerName.DnsName('localhost'), nil,
    LVerified, LAlert),
    'an expired certificate is rejected');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'the alert is certificate_expired');
end;

procedure TTestCertificateVerifier.TestExpiredExtraneousCertificateIgnored;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // an expired certificate the peer includes but that is not on the built path to the anchor is
  // ignored as extraneous rather than failing the whole chain (RFC 8446 4.4.2); the leaf chains
  // to the trusted root on its own, so the extra expired certificate never enters the path
  CheckTrue(VerifierFor(Cert('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert'), Cert('expired_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'an expired extraneous certificate is ignored, not rejected as expired');
end;

procedure TTestCertificateVerifier.TestUnrelatedExpiredCertificateDoesNotMaskUnknownCa;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the valid leaf chains to a root this store does not trust, and the peer also sent an expired
  // certificate that is nowhere on the leaf's issuer line: the failure is the untrusted issuer,
  // not an expiry
  CheckFalse(VerifierFor(Cert('root2_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert'), Cert('expired_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a chain to an untrusted root is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'an unrelated expired extra does not turn the alert into certificate_expired');
end;

procedure TTestCertificateVerifier.TestNilCollaboratorsAreRefused;
var
  LRaised: Boolean;
  LVerifier: IServerCertificateVerifier;
  LClient: IClientCertificateVerifier;
  LStore: ITrustAnchorStore;
begin
  LStore := TTrustAnchorStore.Create(TArray<TBytes>.Create(Cert('root_cert')))
    as ITrustAnchorStore;
  LRaised := False;
  try
    LVerifier := TCertificateVerifier.Create(nil, TSystemClock.Create as ITlsClock, LStore,
      False) as IServerCertificateVerifier;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil PKIX provider is refused');
  LRaised := False;
  try
    LVerifier := TCertificateVerifier.Create(Pkix, nil, LStore, False)
      as IServerCertificateVerifier;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil clock is refused');
  LRaised := False;
  try
    LVerifier := TPinningVerifier.Create(nil, nil, Crypto, Pkix) as IServerCertificateVerifier;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a pinning decorator over no inner verifier is refused');
  LRaised := False;
  try
    LClient := TClientPinningVerifier.Create(nil, nil, Crypto, Pkix)
      as IClientCertificateVerifier;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client pinning decorator over no inner verifier is refused');
  // a nil trust store stays tolerated (it simply trusts nothing)
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock, nil, False)
    as IServerCertificateVerifier;
  CheckNotNull(LVerifier, 'a nil trust store is still accepted');
end;

procedure TTestCertificateVerifier.TestUntrustedRootRejectedAsUnknownCa;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the leaf is genuine but the store trusts only an unrelated root
  CheckFalse(VerifierFor(Cert('root2_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('localhost'), nil,
    LVerified, LAlert),
    'a chain that does not reach a trusted anchor is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is unknown_ca');
end;

procedure TTestCertificateVerifier.TestHostNameMismatchRejectedAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('other.example'), nil,
    LVerified, LAlert),
    'a leaf that is valid but for the wrong host is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestCertificateVerifier.TestEmptyChainRejected;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(nil, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert),
    'an empty certificate chain is rejected');
end;

procedure TTestCertificateVerifier.TestHostNameCheckDisabledIgnoresName;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  CheckTrue(VerifierFor(Cert('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('other.example'), nil,
    LVerified, LAlert),
    'with host-name checking off, a name mismatch does not reject a trusted chain');
end;

procedure TTestCertificateVerifier.TestIncompleteChainWithoutIntermediatesRejected;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the server sends only its leaf, omitting the issuing CA; with no configured
  // intermediates no path to the trusted root can be built - this is the failure a
  // leaf-only server produces
  CheckFalse(IntermediateVerifierFor(Chain3('root_cert'), nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert')), TServerName.DnsName(''), nil,
    LVerified, LAlert),
    'a leaf-only chain with no configured intermediates cannot reach the root');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is unknown_ca');
end;

procedure TTestCertificateVerifier.TestIncompleteChainCompletedByIntermediates;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the same leaf-only chain, but the missing intermediate is supplied via config: the
  // path builder now assembles leaf -> issuer -> root and the chain is trusted
  CheckTrue(IntermediateVerifierFor(Chain3('root_cert'),
    TArray<TBytes>.Create(Chain3('issuer_cert'))).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert')), TServerName.DnsName(''), nil,
    LVerified, LAlert),
    'a configured intermediate completes an otherwise incomplete chain');
end;

procedure TTestCertificateVerifier.TestAnchorNameConstraintsAreEnforced;
var
  LVec: TStringList;
  LRoot: TBytes;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  LVec := LoadVectorFields('Certs/NameConstrainedRoot.txt');
  try
    LRoot := DecodeHex(LVec.Values['root_cert']);
    // the root permits only corp.example: a leaf inside it chains, a validly signed leaf outside
    // it does not, so a mis-issued certificate under the root cannot name a foreign host
    CheckTrue(VerifierFor(LRoot, False).VerifyServerCertificate(
      TArray<TBytes>.Create(DecodeHex(LVec.Values['in_scope_leaf_cert'])),
      TServerName.DnsName(''), nil, LVerified, LAlert), 'a leaf within the anchor constraints');
    CheckFalse(VerifierFor(LRoot, False).VerifyServerCertificate(
      TArray<TBytes>.Create(DecodeHex(LVec.Values['out_of_scope_leaf_cert'])),
      TServerName.DnsName(''), nil, LVerified, LAlert), 'a leaf outside the anchor constraints');
  finally
    LVec.Free;
  end;
end;

procedure TTestCertificateVerifier.TestCompleteChainStillTrustedWithIntermediates;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // a server that sends its full chain still verifies when intermediates are also
  // configured - the extra copy is a redundant pool entry, never a second path
  CheckTrue(IntermediateVerifierFor(Chain3('root_cert'),
    TArray<TBytes>.Create(Chain3('issuer_cert'))).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert'), Chain3('issuer_cert')), TServerName.DnsName(''), nil,
    LVerified, LAlert),
    'a complete chain remains trusted when intermediates are configured too');
end;

procedure TTestCertificateVerifier.TestServerCertWithClientAuthOnlyEkuRejected;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // a leaf whose extendedKeyUsage is clientAuth-only is not a valid SERVER certificate,
  // even though it chains to the trusted root
  CheckFalse(VerifierFor(EkuCert('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(EkuCert('clientonly_leaf_cert')), TServerName.DnsName('localhost'),
    nil, LVerified, LAlert), 'a clientAuth-only leaf is rejected as a server certificate');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'the alert is unsupported_certificate');
end;

procedure TTestCertificateVerifier.TestServerCertWithNoEkuAccepted;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // no extendedKeyUsage extension means unrestricted (RFC 5280 4.2.1.12): accepted
  CheckTrue(VerifierFor(EkuCert('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(EkuCert('noeku_leaf_cert')), TServerName.DnsName('localhost'),
    nil, LVerified, LAlert), 'a leaf with no EKU is accepted as a server certificate');
end;

procedure TTestCertificateVerifier.TestClientCertWithServerAuthOnlyEkuRejected;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the EcP256 leaf carries serverAuth only; it is not a valid CLIENT certificate
  CheckFalse(ClientVerifierFor(Cert('root_cert')).VerifyClientCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), LVerified, LAlert),
    'a serverAuth-only leaf is rejected as a client certificate');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'the alert is unsupported_certificate');
end;

procedure TTestCertificateVerifier.TestClientCertWithClientAuthAccepted;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the dual-EKU leaf carries clientAuth; it is a valid client certificate
  CheckTrue(ClientVerifierFor(EkuCert('root_cert')).VerifyClientCertificate(
    TArray<TBytes>.Create(EkuCert('leaf_cert')), LVerified, LAlert),
    'a clientAuth-capable leaf is accepted as a client certificate');
end;

procedure TTestCertificateVerifier.TestPinnedSelfSignedClientAuthOnlyLeafRejectedAsServer;
var
  LAlert: TTlsAlertDescription;
  LCert: TBytes;
  LVerified: TVerifiedChain;
begin
  // the leaf is directly trusted (pinned as its own anchor) yet its extendedKeyUsage is
  // clientAuth-only: the end-entity's purpose is enforced even when it equals the anchor
  LCert := EkuEdgeCert('clientauth_selfsigned_cert');
  CheckFalse(VerifierFor(LCert, False).VerifyServerCertificate(
    TArray<TBytes>.Create(LCert), TServerName.DnsName('localhost'), nil, LVerified, LAlert),
    'a pinned self-signed clientAuth-only leaf is rejected as a server certificate');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'the alert is unsupported_certificate');
end;

procedure TTestCertificateVerifier.TestMalformedEkuRejectedAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
  LCert: TBytes;
  LVerified: TVerifiedChain;
begin
  // the extendedKeyUsage extension is present but its value is not a SEQUENCE OF OID; this is
  // a malformed certificate, reported as bad_certificate rather than an opaque internal_error
  LCert := EkuEdgeCert('malformed_eku_selfsigned_cert');
  CheckFalse(VerifierFor(LCert, False).VerifyServerCertificate(
    TArray<TBytes>.Create(LCert), TServerName.DnsName('localhost'), nil, LVerified, LAlert),
    'a certificate with a malformed EKU extension is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestCertificateVerifier.TestMisorderedChainValidatedPathIsIssuerOrdered;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the peer presents [leaf, root, issuer]; the validated path must come back issuer-ordered,
  // ending at the configured anchor exactly once - not in the peer's order with the anchor
  // appended behind it
  CheckTrue(VerifierFor(Chain3('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert'), Chain3('root_cert'), Chain3('issuer_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a misordered but complete chain validates');
  CheckEquals(3, System.Length(LVerified.Path), 'the validated path is leaf, issuer, anchor');
  CheckEqualBytes('path[0] is the leaf', Chain3('leaf_cert'), LVerified.Path[0]);
  CheckEqualBytes('path[1] is the leaf issuer', Chain3('issuer_cert'), LVerified.Path[1]);
  CheckEqualBytes('path[2] is the anchor', Chain3('root_cert'), LVerified.Path[2]);
end;

procedure TTestCertificateVerifier.TestMisorderedChainRevokedStapleAborts;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the staple is authenticated against the validated path's [1]; when that was the peer's
  // presented order, a reordered chain put the root there, the Revoked staple failed to match
  // and degraded to Indeterminate, which Soft accepted
  CheckFalse(VerifierFor(Chain3('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert'), Chain3('root_cert'), Chain3('issuer_cert')),
    TServerName.DnsName(''), Chain3('ocsp_revoked'), LVerified, LAlert),
    'a revoked staple aborts a misordered chain under Soft');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRevoked), Ord(LAlert),
    'the alert is certificate_revoked');
end;

procedure TTestCertificateVerifier.TestReorderedChainBuildsFromPresentedFirstCert;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the build targets the peer's first presented certificate (index 0), whatever order the rest
  // arrive in: given [issuer, leaf, root] the path is built from the issuer up to the anchor and
  // the extra leaf is ignored. Binding the handshake to that certificate's key is CertificateVerify's
  // job downstream, not the path builder's - so this validates and path[0] is the presented cert
  CheckTrue(VerifierFor(Chain3('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('issuer_cert'), Chain3('leaf_cert'), Chain3('root_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a chain builds from the first presented certificate to the anchor');
  CheckEqualBytes('path[0] is the presented first certificate', Chain3('issuer_cert'),
    LVerified.Path[0]);
end;

procedure TTestCertificateVerifier.TestPeerReissuedRootAcceptedAndCollapsed;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the peer ends its chain with a re-issued copy of the configured root (same key and subject,
  // new serial); the validated path ends at the CONFIGURED anchor, once
  CheckTrue(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('root_reissued_cert')), TServerName.DnsName(''), nil, LVerified, LAlert),
    'a chain ending in a re-issued copy of the configured root is trusted');
  CheckEquals(3, System.Length(LVerified.Path), 'the peer copy is collapsed onto the anchor');
  CheckEqualBytes('path[0] is the leaf', Reissued('leaf_cert'), LVerified.Path[0]);
  CheckEqualBytes('path[1] is the issuer', Reissued('issuer_cert'), LVerified.Path[1]);
  CheckEqualBytes('path[2] is the configured anchor DER', Reissued('root_cert'),
    LVerified.Path[2]);
end;

procedure TTestCertificateVerifier.TestPeerSha1ReissuedRootExemptFromChainPolicy;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LChain: TArray<TBytes>;
begin
  // the peer copy of the root is self-signed with SHA-1, which the chain-algorithm policy refuses
  // on any validated edge (RFC 8446 4.4.2.4) - but the anchor's self-signature is not one, so a
  // re-issued copy that resolves to the configured anchor is exempt exactly as the configured
  // DER itself would be
  LChain := TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('root_reissued_sha1_cert'));
  CheckTrue(PolicyVerifierFor(Reissued('root_cert'),
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256)).VerifyServerCertificate(
    LChain, TServerName.DnsName(''), nil, LVerified, LAlert),
    'a SHA-1 self-signed re-issue of the configured root is exempt from the chain policy');
  CheckEqualBytes('the path still ends at the configured anchor', Reissued('root_cert'),
    LVerified.Path[System.High(LVerified.Path)]);
  // control: the policy is live on this verifier - withdraw the scheme the leaf and issuer are
  // signed with and the same chain is refused
  CheckFalse(PolicyVerifierFor(Reissued('root_cert'),
    TArray<UInt16>.Create(TSignatureSchemes.RsaPssRsaeSha256)).VerifyServerCertificate(
    LChain, TServerName.DnsName(''), nil, LVerified, LAlert),
    'the chain policy rejects the path when its scheme is not advertised');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'the alert is unsupported_certificate');
end;

procedure TTestCertificateVerifier.TestBareVerifierRefusesSha1SignedIntermediate;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // a verifier built without an armed chain policy (the whole-verifier instance path) still
  // refuses a SHA-1-signed chain certificate (RFC 8446 4.4.2.4)
  CheckTrue(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'control: the SHA-256 chain is trusted');
  CheckFalse(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_sha1_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a SHA-1-signed intermediate is refused without an armed policy');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestCertificateVerifier.TestSha1ChainSignatureAdmittedWhenNamedInThePolicy;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LPolicy: TCertificateStrengthPolicy;
  LAdvertised: TArray<UInt16>;
  LChain: TArray<TBytes>;
begin
  // only ecdsa_secp256r1_sha256 is advertised: no scheme names a SHA-1 certificate signature, so
  // an admitted one must not be held to the advertised set
  LAdvertised := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LChain := TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_sha1_cert'));
  CheckFalse(PolicyVerifierFor(Reissued('root_cert'), LAdvertised).VerifyServerCertificate(
    LChain, TServerName.DnsName(''), nil, LVerified, LAlert),
    'the default floor refuses a SHA-1-signed intermediate');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'default alert');
  LPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
  CheckTrue(PolicyVerifierFor(Reissued('root_cert'), LAdvertised, LPolicy)
    .VerifyServerCertificate(LChain, TServerName.DnsName(''), nil, LVerified, LAlert),
    'admitting SHA-1 accepts the SHA-1-signed intermediate');
end;

procedure TTestCertificateVerifier.TestChainSignatureWithoutDigestInfoNullIsRefused;
var
  LVec: TStringList;
  LRoot: TBytes;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  LVec := LoadVectorFields('Certs/Pkcs1StrictDigestInfo.txt');
  try
    LRoot := DecodeHex(LVec.Values['ca_cert']);
    CheckTrue(VerifierFor(LRoot, False).VerifyServerCertificate(
      TArray<TBytes>.Create(DecodeHex(LVec.Values['leaf_cert'])), TServerName.DnsName(''), nil,
      LVerified, LAlert), 'control: the canonically signed leaf is trusted');
    CheckFalse(VerifierFor(LRoot, False).VerifyServerCertificate(
      TArray<TBytes>.Create(DecodeHex(LVec.Values['leaf_nonull_cert'])),
      TServerName.DnsName(''), nil, LVerified, LAlert),
      'a leaf signed over a DigestInfo without NULL does not chain to the root');
  finally
    LVec.Free;
  end;
end;

procedure TTestCertificateVerifier.TestMd5ChainSignatureRefusedEvenWhenAdmitted;
var
  LVec: TStringList;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LPolicy: TCertificateStrengthPolicy;
begin
  LVec := LoadVectorFields('Certs/LegacyHashChain.txt');
  try
    LPolicy := TCertificateStrengthPolicy.Defaults;
    LPolicy.AllowedDeprecatedHashes := [TCertSignatureHash.Md5, TCertSignatureHash.Sha1];
    CheckTrue(PolicyVerifierFor(DecodeHex(LVec.Values['root_cert']),
      TArray<UInt16>.Create(TSignatureSchemes.RsaPkcs1Sha256), LPolicy)
      .VerifyServerCertificate(TArray<TBytes>.Create(DecodeHex(LVec.Values['leaf_cert']),
      DecodeHex(LVec.Values['issuer_sha1_cert'])), TServerName.DnsName(''), nil, LVerified,
      LAlert), 'control: admitting SHA-1 accepts the SHA-1-signed RSA intermediate');
    CheckFalse(PolicyVerifierFor(DecodeHex(LVec.Values['root_cert']),
      TArray<UInt16>.Create(TSignatureSchemes.RsaPkcs1Sha256), LPolicy)
      .VerifyServerCertificate(TArray<TBytes>.Create(DecodeHex(LVec.Values['leaf_cert']),
      DecodeHex(LVec.Values['issuer_md5_cert'])), TServerName.DnsName(''), nil, LVerified,
      LAlert), 'an MD5-signed intermediate is refused even when named in the admitted set');
    CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'alert');
  finally
    LVec.Free;
  end;
end;

function TTestCertificateVerifier.RingChain: TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, 17);
  Result[0] := Flood('ring_leaf');
  for LI := 0 to 15 do
    Result[LI + 1] := Flood(Format('ring_%.2d', [LI]));
end;

function TTestCertificateVerifier.PathAlert(const AChain: TArray<TBytes>;
  const AAnchor: TBytes; out AElapsedMs: Int64): TTlsAlertDescription;
var
  LEffective: TArray<TBytes>;
  LStart: Int64;
begin
  Result := TTlsAlertDescription.CloseNotify; // stands for "no alert raised"
  LEffective := nil;
  LStart := TSystemTimeUtilities.UtcUnixMs;
  try
    Pkix.PathValidation.ValidateCertificatePath(AChain,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(AAnchor)) as ITrustAnchorStore, nil,
      TDateTimeUtilities.UnixMsToDateTime(LStart), TCertKeyPurpose.ServerAuth, LEffective);
  except
    on E: EFatalAlertTlsLibException do
      Result := E.AlertDescription;
  end;
  AElapsedMs := TSystemTimeUtilities.UtcUnixMs - LStart;
end;

procedure TTestCertificateVerifier.TestSelfIssuedFillerFloodFailsFast;
var
  LElapsed: Int64;
begin
  // the builder's depth cap ignores self-issued certificates, so a peer padding its chain with
  // same-named ones could drive a permutation search; the per-subject pool cap bounds it
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa),
    Ord(PathAlert(FloodChain(40), Flood('anchor'), LElapsed)),
    'a chain that reaches no trusted anchor is unknown_ca');
  CheckTrue(LElapsed < 5000, 'path building gives up promptly (' + IntToStr(LElapsed) + ' ms)');
end;

procedure TTestCertificateVerifier.TestRingOfSameNamedCertificatesFailsFast;
var
  LElapsed: Int64;
begin
  // four subjects cross-issuing each other, each with three self-issued twins: every subject is
  // within a small per-subject count, yet without a tight cap the ring multiplies the permutations
  // until the builder's whole node budget is spent
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa),
    Ord(PathAlert(RingChain, Flood('ring_anchor'), LElapsed)),
    'a ring that reaches no trusted anchor is unknown_ca');
  CheckTrue(LElapsed < 1500, 'path building gives up promptly (' + IntToStr(LElapsed) + ' ms)');
end;

procedure TTestCertificateVerifier.TestPerSubjectPoolKeepsFirstPresented;
var
  LElapsed: Int64;
  LLegit, LDecoyFirst: TArray<TBytes>;
begin
  // at most two presented certificates per subject name are pooled, first presented first: the real
  // issuer presented right after the leaf validates, but behind two same-named decoys it is dropped
  LLegit := TArray<TBytes>.Create(Flood('order_leaf'), Flood('order_real'),
    Flood('order_decoy_0'), Flood('order_decoy_1'));
  LDecoyFirst := TArray<TBytes>.Create(Flood('order_leaf'), Flood('order_decoy_0'),
    Flood('order_decoy_1'), Flood('order_real'));
  CheckEquals(Ord(TTlsAlertDescription.CloseNotify),
    Ord(PathAlert(LLegit, Flood('order_anchor'), LElapsed)),
    'the real issuer presented first builds a path to the anchor');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa),
    Ord(PathAlert(LDecoyFirst, Flood('order_anchor'), LElapsed)),
    'the real issuer behind two same-named decoys is not pooled');
end;

procedure TTestCertificateVerifier.TestEmptyOrNonDerEntryIsBadCertificate;
var
  LElapsed: Int64;
  LChain: TArray<TBytes>;
begin
  // the parser answers an empty or non-DER entry with nil rather than raising; that must surface
  // as bad_certificate, not a nil dereference reported as an internal error
  LChain := TArray<TBytes>.Create(Flood('leaf'), nil);
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(PathAlert(LChain, Flood('anchor'), LElapsed)), 'an empty entry is bad_certificate');
  LChain := TArray<TBytes>.Create(Flood('leaf'), TBytes.Create($00, $01, $02));
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(PathAlert(LChain, Flood('anchor'), LElapsed)), 'a non-DER entry is bad_certificate');
end;

procedure TTestCertificateVerifier.TestChainOverEntryCapRefused;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  // 16 is the default cap; the flood leaf plus 16 fillers is 17 entries and is refused before any
  // PKIX work, whatever the chain would have validated to
  LVerifier := VerifierFor(Flood('anchor'), False);
  CheckFalse(LVerifier.VerifyServerCertificate(FloodChain(16), TServerName.DnsName(''), nil,
    LVerified, LAlert), 'a chain over the entry cap is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestCertificateVerifier.TestChainLimitsAdmitsChainCapsEveryDimension;
var
  LLimits: TCertificateChainLimits;
  LOne: TBytes;
  LChain: TArray<TBytes>;
begin
  LLimits := TCertificateChainLimits.Defaults;
  CheckEquals(16, LLimits.MaxChainCertificates, 'the default entry cap');
  LOne := nil;
  SetLength(LOne, 100);
  LChain := TArray<TBytes>.Create(LOne, LOne, LOne);
  CheckTrue(LLimits.AdmitsChain(LChain), 'a small chain is admitted');
  LLimits.MaxChainCertificates := 2;
  CheckFalse(LLimits.AdmitsChain(LChain), 'one entry over the count cap is refused');
  LLimits.MaxChainCertificates := 3;
  LLimits.MaxCertificateLength := 99;
  CheckFalse(LLimits.AdmitsChain(LChain), 'a certificate over the length cap is refused');
  LLimits.MaxCertificateLength := 100;
  LLimits.MaxTotalChainLength := 299;
  CheckFalse(LLimits.AdmitsChain(LChain), 'a chain over the total cap is refused');
  LLimits.MaxTotalChainLength := 300;
  CheckTrue(LLimits.AdmitsChain(LChain), 'a chain exactly at every cap is admitted');
end;

function TTestCertificateVerifier.CountedVerifies(const AStore: TCountingTrustAnchorStore;
  ACount: Int32): Boolean;
var
  LStore: ITrustAnchorStore;
  LVerifier: TCertificateVerifier;
  LServer: IServerCertificateVerifier;
  LChain: TArray<TBytes>;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  Result := True;
  LStore := AStore;
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock, LStore, False);
  LServer := LVerifier;
  LVerifier.SetChainAlgorithmPolicy(TCertificateStrengthPolicy.Defaults,
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256));
  LChain := TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('root_reissued_sha1_cert'));
  for LI := 1 to ACount do
    // a valid chain passes both PKIX path validation and the chain-algorithm policy
    if not LServer.VerifyServerCertificate(LChain, TServerName.DnsName(''), nil, LVerified,
      LAlert) then
      Result := False;
end;

procedure TTestCertificateVerifier.TestAnchorSetCopiedOnceAcrossVerifies;
var
  LFirst, LSecond: TCountingTrustAnchorStore;
  LFirstRef, LSecondRef: ITrustAnchorStore;
begin
  // the store is immutable, so its anchors are copied out once for the provider's cache and never
  // again per verification, however many verifies share it
  LFirst := TCountingTrustAnchorStore.Create(
    TTrustAnchorStore.Create(TArray<TBytes>.Create(Reissued('root_cert')))
    as ITrustAnchorStore);
  LFirstRef := LFirst;
  CheckTrue(CountedVerifies(LFirst, 3), 'the valid chain is trusted on every verify');
  CheckEquals(1, LFirst.Reads, 'three verifies copy the anchor set once');
  // control: a fresh store object over the same content is copied once as well, not per verify
  LSecond := TCountingTrustAnchorStore.Create(
    TTrustAnchorStore.Create(TArray<TBytes>.Create(Reissued('root_cert')))
    as ITrustAnchorStore);
  LSecondRef := LSecond;
  CheckTrue(CountedVerifies(LSecond, 3), 'the same chain is trusted through the second store');
  CheckEquals(1, LSecond.Reads, 'a new store object over cached content is copied once');
end;

procedure TTestCertificateVerifier.TestRepeatedStoresOverOneContentDoNotEvictOthers;
var
  LKept: TCountingTrustAnchorStore;
  LKeptRef: ITrustAnchorStore;
  LI: Int32;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  LKept := TCountingTrustAnchorStore.Create(
    TTrustAnchorStore.Create(TArray<TBytes>.Create(Reissued('root_cert')))
    as ITrustAnchorStore);
  LKeptRef := LKept;
  CheckTrue(CountedVerifies(LKept, 1), 'the kept store verifies');
  CheckEquals(1, LKept.Reads, 'and is copied once');
  // a config rebuilt over and over: each new store object over one other content must reuse a single
  // cached slot, not take a slot per object and push the kept store's anchors out of the cache
  for LI := 1 to 12 do
    VerifierFor(Reissued('root2_cert'), False).VerifyServerCertificate(
      TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
      Reissued('root_reissued_sha1_cert')), TServerName.DnsName(''), nil, LVerified, LAlert);
  CheckTrue(CountedVerifies(LKept, 1), 'the kept store still verifies');
  CheckEquals(1, LKept.Reads, 'its anchors were not evicted, so it was not copied again');
end;

procedure TTestCertificateVerifier.TestSha1SelfSignedRootNotConfiguredRejected;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the exemption is for the RESOLVED anchor, not for anything self-signed: with an unrelated
  // root configured the same chain reaches no anchor
  CheckFalse(VerifierFor(Reissued('root2_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('root_reissued_sha1_cert')), TServerName.DnsName(''), nil, LVerified, LAlert),
    'a self-signed root that is not the configured anchor does not anchor the chain');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

procedure TTestCertificateVerifier.TestDistinctStoresNeverShareCachedAnchors;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LChain: TArray<TBytes>;
begin
  // the provider caches parsed anchors across stores: a store must only ever see its own anchors
  LChain := TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('root_reissued_sha1_cert'));
  CheckTrue(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(LChain,
    TServerName.DnsName(''), nil, LVerified, LAlert), 'control: the trusted root verifies');
  CheckFalse(VerifierFor(Reissued('root2_cert'), False).VerifyServerCertificate(LChain,
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'an unrelated store does not inherit the anchors a previous store cached');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
  CheckTrue(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(LChain,
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a new store object over the first content is trusted again');
end;

procedure TTestCertificateVerifier.TestSameSubjectDifferentKeyRootIgnoredForConfiguredAnchor;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the peer appends a root with the anchor's subject but a DIFFERENT key: it verifies under no
  // configured anchor key, so it can never be the trust anchor. The leaf still chains to the
  // CONFIGURED anchor through the issuer, the look-alike is ignored as extraneous, and the
  // validated path ends at the configured anchor - never at the look-alike
  CheckTrue(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('root_lookalike_cert')), TServerName.DnsName(''), nil, LVerified, LAlert),
    'the leaf chains to the configured anchor with a same-subject different-key root ignored');
  CheckEqualBytes('the validated path ends at the configured anchor, not the look-alike',
    Reissued('root_cert'), LVerified.Path[System.High(LVerified.Path)]);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateVerifier);
  RegisterTest(TTestInstanceSourceVerifyCallback);
{$ELSE}
  RegisterTest(TTestCertificateVerifier.Suite);
  RegisterTest(TTestInstanceSourceVerifyCallback.Suite);
{$ENDIF FPC}

end.
