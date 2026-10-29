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

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

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
  TlpIPkixProvider,
  MockVerifyHooks,
  MockPkixProvider,
  MockClock,
  MockCertificateVerifiers,
{$IFDEF TLSLIB_ANDROID}
  TlpSystemTrustBase,
  TlpIPlatformChainEngine,
  TlpAndroidSystemTrust,
  TlpOSDelegateVerifier,
{$ENDIF TLSLIB_ANDROID}
  TlsLibTestCertificates,
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

  /// <summary>The verify callback decorators the engine composes over a caller-supplied verifier,
  /// and the instance sources that leave the callback to them.</summary>
  TTestVerifyCallbackVerifier = class(TTlsLibAlgorithmTestCase)
  strict private
    function Chain: TArray<TBytes>;
    // the verifier the callback decorator yields over AInner
    function ServerVerifier(const AInner: IServerCertificateVerifier;
      const ACallback: TTlsCertificateVerifyCallback): IServerCertificateVerifier;
    function ClientVerifier(const AInner: IClientCertificateVerifier;
      const ACallback: TTlsCertificateVerifyCallback): IClientCertificateVerifier;
  published
    procedure TestServerCallbackRejectsOverAcceptingInstance;
    procedure TestServerCallbackAcceptKeepsInstanceVerdict;
    procedure TestServerCallbackNotRunWhenInstanceRejects;
    procedure TestServerSourceLeavesTheInstanceUndecorated;
    procedure TestClientCallbackRejectsOverAcceptingInstance;
    procedure TestClientCallbackNotRunWhenInstanceRejects;
    procedure TestClientSourceLeavesTheInstanceUndecorated;
    procedure TestServerCallbackSeesPresentedChainAndValidatedPath;
    procedure TestClientCallbackSeesPresentedChainAndValidatedPath;
    procedure TestCallbackSeesNoValidatedPathWhenNothingWasValidated;
    procedure TestNilServerInstanceSourceRaises;
    procedure TestNilClientInstanceSourceRaises;
  end;

  /// <summary>Critical extensions the TLS layer processes itself (extendedKeyUsage on an intermediate,
  /// TLS Feature on the leaf), the end-entity rule for CA certificates, and the constructor guards
  /// of the pinning decorators.</summary>
  TTestCriticalExtensionsAndEndEntity = class(TTlsLibAlgorithmTestCase)
  strict private
    // the issuer probes the last DistrustAlert made
    FIssuerProbes: Int32;
    // the length of the path the last ServerVerdict validated
    FValidatedPathLength: Int32;
    // the fixture certificates named, in order
    function Chain(const ANames: array of string): TArray<TBytes>;
    // the verdict of a verifier trusting ARoot for the named chain, with the alert on a refusal
    function ServerVerdict(const ARoot: string; const AChain: array of string;
      AStatusRequestOffered: Boolean; out AAlert: TTlsAlertDescription): Boolean;
    function ClientVerdict(const ARoot: string; const AChain: array of string;
      out AAlert: TTlsAlertDescription): Boolean;
    // the alert for a chain with no path once ADistrusted are withheld, and the path builds it took
    function DistrustAlert(const AChain, ADistrusted: array of string;
      out APathBuilds: Int32): TTlsAlertDescription;
  published
    procedure TestCriticalEkuIntermediateWithServerAuthIsAccepted;
    procedure TestCriticalEkuIntermediateWithoutServerAuthIsWrongPurpose;
    procedure TestCriticalStatusRequestFeatureLeafBuildsAPath;
    procedure TestCriticalStatusRequestFeatureLeafIsProcessedAsMustStaple;
    procedure TestCriticalStatusRequestWithAnotherFeatureIsRefused;
    procedure TestCriticalUnenforcedFeatureLeafIsRefused;
    procedure TestCriticalTlsFeatureOnAnIntermediateIsRefused;
    procedure TestDistrustedIssuerOfTheLeafIsBadCertificate;
    procedure TestDistrustedCertificateOffTheLeafLineKeepsUnknownCa;
    procedure TestTwoDistrustedCertificatesInARowAreBadCertificate;
    procedure TestDistrustClassificationCostIsBoundedOnASameKeyRing;
    procedure TestCaCertificateAsServerLeafIsRefused;
    procedure TestCaCertificateAsClientLeafIsRefused;
    procedure TestPinnedSelfSignedCaServerLeafIsAccepted;
    procedure TestPinnedSelfSignedCaClientLeafIsAccepted;
    procedure TestPinningVerifierWithNoPinsIsRefused;
    procedure TestClientPinningVerifierWithNoPinsIsRefused;
    procedure TestDistrustClassificationBuildsThePathOnce;
  end;

  /// <summary>The chain-failure alerts every verifier must send over the fixture chains
  /// anchored at chain_root.</summary>
  TChainFailureAlertTestBase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    // the fixture certificates named, in order
    function Chain(const ANames: array of string): TArray<TBytes>;
    // whether the verifier accepts the named server chain, with the alert when it refuses
    function Verdict(const AChain: array of string;
      out AAlert: TTlsAlertDescription): Boolean; virtual; abstract;
  published
    procedure TestValidChainIsAccepted;
    procedure TestBadSignatureUnderAPooledIntermediateIsDecryptError;
    procedure TestCriticalPrivateExtensionOnTheLeafIsCertificateUnknown;
    procedure TestCriticalPrivateExtensionOnAnIntermediateIsCertificateUnknown;
  end;

  /// <summary>The alert a refused chain maps to when the cause is a bad signature, an unhandled
  /// critical extension or a certificate outside its validity window.</summary>
  TTestChainFailureAlerts = class(TChainFailureAlertTestBase)
  strict private
    // the time the verifiers run at; every test starts inside all the fixture windows
    FUnixMillis: UInt64;
    // the verdict of a client-certificate verifier trusting chain_root for the named chain
    function ClientVerdict(const AChain: array of string;
      out AAlert: TTlsAlertDescription): Boolean;
  strict protected
    procedure SetUp; override;
    function Verdict(const AChain: array of string;
      out AAlert: TTlsAlertDescription): Boolean; override;
  published
    procedure TestBadSignatureAsClientCertificateIsDecryptError;
    procedure TestExpiryOutranksABadSignature;
    procedure TestNameConstraintViolationIsCertificateUnknown;
    procedure TestBadSignatureDirectlyUnderTheAnchorIsDecryptError;
    procedure TestNotYetValidChainIsCertificateExpired;
    procedure TestNotYetValidIntermediateIsCertificateExpired;
    procedure TestIntermediateInsideItsValidityWindowIsAccepted;
  end;

{$IFDEF TLSLIB_ANDROID}
  /// <summary>The chain-failure alerts of the real Android trust manager over an exclusive
  /// anchor; a bad signature directly under the anchor reads there as a missing anchor.</summary>
  TTestAndroidChainFailureAlerts = class(TChainFailureAlertTestBase)
  strict private
    FFailure: TPlatformChainFailure;
    // the first certificate as the chain, the rest as intermediates, under the one anchor
    function RequestFor(const ACerts: TArray<TBytes>; const AAnchor: TBytes): TPlatformChainRequest;
    // the name-constrained fixture certificates named, in order
    function NcChain(const ANames: array of string): TArray<TBytes>;
    // the policy of a delegate trusting only AAnchor: no host-name check, no revocation
    function PolicyFor(const AAnchor: TBytes): TOSDelegatePolicy;
    // the server delegate over the Android engine, trusting the name-constrained root
    function NcServerVerdict(const AChain: array of string;
      out AAlert: TTlsAlertDescription): Boolean;
    // the client delegate, with the named intermediates configured; the validated path length
    function NcClientVerdict(const ALeaf: string; const AIntermediates: array of string;
      out APathLength: Int32; out AAlert: TTlsAlertDescription): Boolean;
  strict protected
    function Verdict(const AChain: array of string;
      out AAlert: TTlsAlertDescription): Boolean; override;
  published
    procedure TestBadSignatureAsClientCertificateIsDecryptError;
    procedure TestBadSignatureUnderTheAnchorIsUnknownCa;
    procedure TestBadSignatureUnderAPooledIntermediateIsNotAMissingAnchor;
    procedure TestAnchorNameConstraintsAreEnforcedByTheServerDelegate;
    procedure TestAnchorNameConstraintsSurviveAnOpenIntermediateOnTheServerDelegate;
    procedure TestAnchorNameConstraintsAreEnforcedByTheClientDelegate;
    procedure TestAnchorNameConstraintsSurviveAnOpenIntermediateOnTheClientDelegate;
  end;
{$ENDIF TLSLIB_ANDROID}

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
    // a name-constrained root, two intermediates (one constrained) and leaves in and out of scope
    FNameConstrained: TStringList;
    // a root with a 2048-bit RSA key and an EC leaf it signed
    FWeakAnchor: TStringList;
    function NcPath(const ANames: array of string): TArray<TBytes>;
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
    // a trust anchor's own nameConstraints bound every path under it (applying an anchor's
    // constraints is RFC 5937, permitted by RFC 5280 6.2)
    procedure TestAnchorNameConstraintsAreEnforced;
    // name constraints over a built path (RFC 5280 6.1.1 (h)(i), 6.1.4 (g); RFC 5937 3)
    procedure TestNameConstraintsAdmitInScopePath;
    procedure TestNameConstraintsRefuseOutOfScopePath;
    procedure TestNameConstraintsIntersectIntermediate;
    procedure TestNameConstraintsSurviveAnOpenIntermediate;
    procedure TestNameConstraintsHonourExcludedSubtrees;
    procedure TestNameConstraintsAdmitDirectlyTrustedLeaf;
    procedure TestNameConstraintsRefuseUnusablePaths;
    procedure TestNameConstrainedChainIsValidatedByTheBuiltInVerifier;
    procedure TestWeakAnchorChainIsValidatedByTheBuiltInVerifier;
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
    // peer presented (RFC 9846 4.5.1 tolerates arbitrary ordering), so the staple check keys off
    // the real issuer at [1]
    procedure TestMisorderedChainValidatedPathIsIssuerOrdered;
    procedure TestMisorderedChainRevokedStapleAborts;
    procedure TestReorderedChainBuildsFromPresentedFirstCert;
    procedure TestChainWhoseFirstCertificateIsACaIsRefusedAsEndEntity;
    // the trust anchor is identified by subject + key, not exact encoding (RFC 5280 6.1.1(d)):
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
    procedure TestEmptyChainIsBadCertificate;
    procedure TestPerSubjectPoolKeepsFirstPresented;
    procedure TestEmptyOrNonDerEntryIsBadCertificate;
    procedure TestChainOverEntryCapRefused;
    procedure TestChainLimitsAdmitsChainCapsEveryDimension;
  end;

implementation

{ TTestVerifyCallbackVerifier }

function TTestVerifyCallbackVerifier.Chain: TArray<TBytes>;
begin
  Result := TArray<TBytes>.Create(TBytes.Create(1, 2, 3));
end;

function TTestVerifyCallbackVerifier.ServerVerifier(
  const AInner: IServerCertificateVerifier;
  const ACallback: TTlsCertificateVerifyCallback): IServerCertificateVerifier;
begin
  Result := TVerifyCallbackVerifier.Create(AInner, ACallback) as IServerCertificateVerifier;
end;

function TTestVerifyCallbackVerifier.ClientVerifier(
  const AInner: IClientCertificateVerifier;
  const ACallback: TTlsCertificateVerifyCallback): IClientCertificateVerifier;
begin
  Result := TClientVerifyCallbackVerifier.Create(AInner, ACallback)
    as IClientCertificateVerifier;
end;

procedure TTestVerifyCallbackVerifier.TestServerCallbackRejectsOverAcceptingInstance;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(False));
  LVerifier := ServerVerifier(TFixedVerdictVerifier.CreateAccepting(False)
    as IServerCertificateVerifier, LSpy.Callback);
  CheckFalse(LVerifier.VerifyServerCertificate(Chain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert), 'the callback rejects what the instance accepted');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckEquals(0, System.Length(LVerified.Path), 'a rejection carries no validated path');
  CheckEquals(1, LSpy.Calls, 'the callback ran once');
end;

procedure TTestVerifyCallbackVerifier.TestServerCallbackAcceptKeepsInstanceVerdict;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LVerifier := ServerVerifier(TFixedVerdictVerifier.CreateAccepting(False)
    as IServerCertificateVerifier, LSpy.Callback);
  CheckTrue(LVerifier.VerifyServerCertificate(Chain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert), 'an accepting callback leaves the instance verdict');
  CheckEquals(1, System.Length(LVerified.Path), 'the instance path is kept');
end;

procedure TTestVerifyCallbackVerifier.TestServerCallbackNotRunWhenInstanceRejects;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LVerifier := ServerVerifier(TFixedVerdictVerifier.CreateRejecting(
    TTlsAlertDescription.BadCertificate) as IServerCertificateVerifier, LSpy.Callback);
  CheckFalse(LVerifier.VerifyServerCertificate(Chain, TServerName.DnsName('host.example'), nil,
    LVerified, LAlert), 'the callback cannot rescue a rejection');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the instance alert is kept');
  CheckEquals(0, LSpy.Calls, 'the callback is not consulted');
end;

procedure TTestVerifyCallbackVerifier.TestServerSourceLeavesTheInstanceUndecorated;
var
  LInstance, LVerifier: IServerCertificateVerifier;
  LContext: TServerTrustContext;
  LSource: IServerCertificateVerifierSource;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(False));
  LInstance := TFixedVerdictVerifier.CreateAccepting(False) as IServerCertificateVerifier;
  LContext := Default(TServerTrustContext);
  LContext.Dangerous.VerifyCallback := LSpy.Callback;
  LSource := TInstanceServerVerifierSource.Create(LInstance) as IServerCertificateVerifierSource;
  LVerifier := LSource.CreateServerVerifier(LContext);
  CheckTrue(LVerifier = LInstance, 'the callback is applied once by the engine, not by the source');
end;

procedure TTestVerifyCallbackVerifier.TestClientCallbackRejectsOverAcceptingInstance;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(False));
  LVerifier := ClientVerifier(TFixedVerdictVerifier.CreateAccepting(False)
    as IClientCertificateVerifier, LSpy.Callback);
  CheckFalse(LVerifier.VerifyClientCertificate(Chain, LVerified, LAlert),
    'the callback rejects what the instance accepted');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckEquals(0, System.Length(LVerified.Path), 'a rejection carries no validated path');
end;

procedure TTestVerifyCallbackVerifier.TestClientCallbackNotRunWhenInstanceRejects;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LVerifier := ClientVerifier(TFixedVerdictVerifier.CreateRejecting(
    TTlsAlertDescription.BadCertificate) as IClientCertificateVerifier, LSpy.Callback);
  CheckFalse(LVerifier.VerifyClientCertificate(Chain, LVerified, LAlert),
    'the callback cannot rescue a rejection');
  CheckEquals(0, LSpy.Calls, 'the callback is not consulted');
end;

procedure TTestVerifyCallbackVerifier.TestClientSourceLeavesTheInstanceUndecorated;
var
  LInstance, LVerifier: IClientCertificateVerifier;
  LContext: TClientTrustContext;
  LSource: IClientCertificateVerifierSource;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(False));
  LInstance := TFixedVerdictVerifier.CreateAccepting(False) as IClientCertificateVerifier;
  LContext := Default(TClientTrustContext);
  LContext.Dangerous.VerifyCallback := LSpy.Callback;
  LSource := TInstanceClientVerifierSource.Create(LInstance) as IClientCertificateVerifierSource;
  LVerifier := LSource.CreateClientVerifier(LContext);
  CheckTrue(LVerifier = LInstance, 'the callback is applied once by the engine, not by the source');
end;

procedure TTestVerifyCallbackVerifier.TestServerCallbackSeesPresentedChainAndValidatedPath;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
  LPresented, LPath: TArray<TBytes>;
begin
  LPresented := TArray<TBytes>.Create(TBytes.Create(1), TBytes.Create(2), TBytes.Create(3));
  LPath := TArray<TBytes>.Create(TBytes.Create(1), TBytes.Create(9));
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LVerifier := ServerVerifier(TFixedVerdictVerifier.CreateReporting(LPath,
    TVerificationOutcome.Trusted) as IServerCertificateVerifier, LSpy.Callback);
  CheckTrue(LVerifier.VerifyServerCertificate(LPresented, TServerName.DnsName('host.example'),
    nil, LVerified, LAlert), 'accepted');
  CheckEquals(3, System.Length(LSpy.Presented), 'the callback sees every certificate the peer sent');
  CheckEquals(2, System.Length(LSpy.Validated), 'the callback sees the validated path');
  CheckEquals(9, LSpy.Validated[1][0], 'the validated path is the verifier''s, not the presented one');
end;

procedure TTestVerifyCallbackVerifier.TestClientCallbackSeesPresentedChainAndValidatedPath;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
  LPresented, LPath: TArray<TBytes>;
begin
  LPresented := TArray<TBytes>.Create(TBytes.Create(1), TBytes.Create(2), TBytes.Create(3));
  LPath := TArray<TBytes>.Create(TBytes.Create(1), TBytes.Create(9));
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LVerifier := ClientVerifier(TFixedVerdictVerifier.CreateReporting(LPath,
    TVerificationOutcome.Trusted) as IClientCertificateVerifier, LSpy.Callback);
  CheckTrue(LVerifier.VerifyClientCertificate(LPresented, LVerified, LAlert), 'accepted');
  CheckEquals(3, System.Length(LSpy.Presented), 'the callback sees every certificate the peer sent');
  CheckEquals(2, System.Length(LSpy.Validated), 'the callback sees the validated path');
  CheckEquals(9, LSpy.Validated[1][0], 'the validated path is the verifier''s, not the presented one');
end;

procedure TTestVerifyCallbackVerifier.TestCallbackSeesNoValidatedPathWhenNothingWasValidated;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
  LSpy: TVerifyCallbackSpy;
  LPresented: TArray<TBytes>;
begin
  LPresented := TArray<TBytes>.Create(TBytes.Create(1), TBytes.Create(2));
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LVerifier := ServerVerifier(TFixedVerdictVerifier.CreateReporting(
    TArray<TBytes>.Create(TBytes.Create(1)), TVerificationOutcome.Unvalidated)
    as IServerCertificateVerifier, LSpy.Callback);
  CheckTrue(LVerifier.VerifyServerCertificate(LPresented, TServerName.DnsName('host.example'),
    nil, LVerified, LAlert), 'accepted');
  CheckEquals(0, System.Length(LSpy.Validated), 'an unvalidated acceptance reports no validated path');
  CheckEquals(2, System.Length(LSpy.Presented), 'the presented chain is intact');
end;

procedure TTestVerifyCallbackVerifier.TestNilServerInstanceSourceRaises;
var
  LRaised: Boolean;
  LSource: IServerCertificateVerifierSource;
begin
  LRaised := False;
  try
    LSource := TInstanceServerVerifierSource.Create(nil) as IServerCertificateVerifierSource;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil server verifier raises at construction');
end;

procedure TTestVerifyCallbackVerifier.TestNilClientInstanceSourceRaises;
var
  LRaised: Boolean;
  LSource: IClientCertificateVerifierSource;
begin
  LRaised := False;
  try
    LSource := TInstanceClientVerifierSource.Create(nil) as IClientCertificateVerifierSource;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil client verifier raises at construction');
end;

{ TTestCriticalExtensionsAndEndEntity }

function TTestCriticalExtensionsAndEndEntity.Chain(
  const ANames: array of string): TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(ANames));
  for LI := 0 to System.High(ANames) do
    Result[LI] := TTlsLibTestCertificates.Field('Certs/CriticalExtensionsChain.txt', ANames[LI]);
end;

function TTestCriticalExtensionsAndEndEntity.ServerVerdict(const ARoot: string;
  const AChain: array of string; AStatusRequestOffered: Boolean;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LOptions: TCertificateVerifierOptions;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LOptions.StatusRequestOffered := AStatusRequestOffered;
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(Chain([ARoot])) as ITrustAnchorStore, True, LOptions)
    as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(Chain(AChain), TServerName.DnsName('localhost'),
    nil, LVerified, AAlert);
  FValidatedPathLength := System.Length(LVerified.ValidatedPath);
end;

function TTestCriticalExtensionsAndEndEntity.ClientVerdict(const ARoot: string;
  const AChain: array of string; out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(Chain([ARoot])) as ITrustAnchorStore, False)
    as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(Chain(AChain), LVerified, AAlert);
end;

function TTestCriticalExtensionsAndEndEntity.DistrustAlert(const AChain,
  ADistrusted: array of string; out APathBuilds: Int32): TTlsAlertDescription;
var
  LSpy: TMockPkixProvider;
  LSpyRef: IPkixProvider;
  LOptions: TCertificateVerifierOptions;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LSpy := TMockPkixProvider.Create(Pkix);
  LSpyRef := LSpy as IPkixProvider;
  LVerifier := TCertificateVerifier.Create(LSpyRef, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(Chain(['root_cert']), Chain(ADistrusted)) as ITrustAnchorStore,
    False, LOptions) as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(Chain(AChain), TServerName.DnsName(''), nil,
    LVerified, Result), 'the chain has no path');
  APathBuilds := LSpy.PathBuildCount;
  FIssuerProbes := LSpy.FindIssuerCount;
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCriticalEkuIntermediateWithServerAuthIsAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ServerVerdict('root_cert', ['leaf_cert', 'inter_serverauth_cert'], False, LAlert),
    'a critical EKU that includes serverAuth is accepted on an intermediate');
  CheckEquals(3, FValidatedPathLength, 'the path runs leaf, intermediate, anchor');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCriticalEkuIntermediateWithoutServerAuthIsWrongPurpose;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ServerVerdict('root_cert', ['leaf_cert', 'inter_clientauth_cert'], False, LAlert),
    'a critical EKU without serverAuth on an intermediate is refused');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'it is the wrong-purpose alert, not an unknown CA');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCriticalStatusRequestFeatureLeafBuildsAPath;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ServerVerdict('root_cert', ['mustaple_leaf_cert'], False, LAlert),
    'a leaf with a critical status_request feature is accepted when no staple was asked for');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCriticalStatusRequestFeatureLeafIsProcessedAsMustStaple;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ServerVerdict('root_cert', ['mustaple_leaf_cert'], True, LAlert),
    'a must-staple leaf without a staple is refused once a staple was asked for');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse), Ord(LAlert),
    'the alert is bad_certificate_status_response');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCriticalStatusRequestWithAnotherFeatureIsRefused;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ServerVerdict('root_cert', ['mustaple_v2_leaf_cert'], False, LAlert),
    'a critical feature list beyond status_request stays refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'as an unhandled critical extension');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCriticalUnenforcedFeatureLeafIsRefused;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ServerVerdict('root_cert', ['other_feature_leaf_cert'], False, LAlert),
    'a critical feature the library does not enforce is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'as an unhandled critical extension');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCriticalTlsFeatureOnAnIntermediateIsRefused;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ServerVerdict('root_cert', ['feature_inter_leaf_cert', 'feature_inter_cert'], True,
    LAlert), 'a critical TLS Feature on an intermediate is not handled');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'as an unhandled critical extension');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCaCertificateAsServerLeafIsRefused;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ServerVerdict('root_cert', ['caleaf_cert'], False, LAlert),
    'a CA certificate is refused as the end-entity');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestCaCertificateAsClientLeafIsRefused;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ClientVerdict('root_cert', ['inter_serverauth_cert'], LAlert),
    'a CA certificate is refused as a client identity');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestPinnedSelfSignedCaServerLeafIsAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ServerVerdict('selfca_cert', ['selfca_cert'], False, LAlert),
    'a directly trusted self-signed CA certificate is accepted');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestPinnedSelfSignedCaClientLeafIsAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(ClientVerdict('selfca_cert', ['selfca_cert'], LAlert),
    'a directly trusted self-signed CA certificate is accepted as a client identity');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestPinningVerifierWithNoPinsIsRefused;
var
  LRaised: Boolean;
  LVerifier: IServerCertificateVerifier;
begin
  LRaised := False;
  try
    LVerifier := TPinningVerifier.Create(TFixedVerdictVerifier.CreateAccepting(False)
      as IServerCertificateVerifier, nil, Crypto, Pkix) as IServerCertificateVerifier;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a pinning decorator with no pins raises instead of matching everything');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestClientPinningVerifierWithNoPinsIsRefused;
var
  LRaised: Boolean;
  LVerifier: IClientCertificateVerifier;
begin
  LRaised := False;
  try
    LVerifier := TClientPinningVerifier.Create(TFixedVerdictVerifier.CreateAccepting(False)
      as IClientCertificateVerifier, nil, Crypto, Pkix) as IClientCertificateVerifier;
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a client pinning decorator with no pins raises instead of matching everything');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestDistrustClassificationBuildsThePathOnce;
var
  LBuilds: Int32;
begin
  DistrustAlert(['leaf_cert', 'inter_serverauth_cert'], ['inter_serverauth_cert'], LBuilds);
  CheckEquals(1, LBuilds, 'one path build served the verdict and its classification');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestDistrustedIssuerOfTheLeafIsBadCertificate;
var
  LBuilds: Int32;
begin
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(DistrustAlert(['leaf_cert', 'inter_serverauth_cert'], ['inter_serverauth_cert'], LBuilds)),
    'a path through a distrusted issuer is an explicit distrust');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestDistrustedCertificateOffTheLeafLineKeepsUnknownCa;
var
  LBuilds: Int32;
begin
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa),
    Ord(DistrustAlert(['x_leaf_cert', 'i2_cert', 'inter_serverauth_cert'],
    ['inter_serverauth_cert'], LBuilds)), 'a withheld certificate off the leaf''s line is not the cause');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestTwoDistrustedCertificatesInARowAreBadCertificate;
var
  LBuilds: Int32;
begin
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(DistrustAlert(['w1_leaf_cert', 'w1_cert', 'inter_serverauth_cert'],
    ['w1_cert', 'inter_serverauth_cert'], LBuilds)),
    'a line through two withheld certificates still reaches the anchor');
end;

procedure TTestCriticalExtensionsAndEndEntity.TestDistrustClassificationCostIsBoundedOnASameKeyRing;
var
  LBuilds: Int32;
begin
  // eight same-name, same-key certificates issue each other; expanding each once stays quadratic
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa),
    Ord(DistrustAlert(['ring_leaf', 'ring_00', 'ring_01', 'ring_02', 'ring_03', 'ring_04',
    'ring_05', 'ring_06', 'ring_07', 'inter_serverauth_cert'], ['inter_serverauth_cert'],
    LBuilds)), 'a ring off the distrusted line keeps unknown_ca');
  CheckTrue(FIssuerProbes <= 200, 'issuer probes stay quadratic (' + IntToStr(FIssuerProbes) + ')');
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
  FCerts := Own<TStringList>(LoadVectorFields('Certs/EcP256Chain.txt'));
  FChain3 := Own<TStringList>(LoadVectorFields('Certs/OcspStapling.txt'));
  FEku := Own<TStringList>(LoadVectorFields('Certs/ClientAuthChain.txt'));
  FEkuEdge := Own<TStringList>(LoadVectorFields('Certs/SelfSignedEkuEdge.txt'));
  FReissued := Own<TStringList>(LoadVectorFields('Certs/ReissuedRoot.txt'));
  FFlood := Own<TStringList>(LoadVectorFields('Certs/PathBuildFlood.txt'));
  FNameConstrained := Own<TStringList>(LoadVectorFields('Certs/NameConstrainedChain.txt'));
  FWeakAnchor := Own<TStringList>(LoadVectorFields('Certs/WeakAnchorClientChain.txt'));
end;

function TTestCertificateVerifier.NcPath(const ANames: array of string): TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(ANames));
  for LI := 0 to High(ANames) do
    Result[LI] := DecodeHex(FNameConstrained.Values[ANames[LI] + '_cert']);
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
  // ignored as extraneous rather than failing the whole chain (RFC 9846 4.5.1); the leaf chains
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

procedure TTestCertificateVerifier.TestNameConstraintsAdmitInScopePath;
begin
  CheckTrue(Pkix.PathValidation.NameConstraintsAdmit(NcPath(['direct_in_scope_leaf', 'root'])),
    'a leaf inside the anchor permitted subtree');
  CheckTrue(Pkix.PathValidation.NameConstraintsAdmit(NcPath(['apple_in_scope_leaf', 'root'])),
    'a leaf inside the anchor permitted subtree, short validity');
end;

procedure TTestCertificateVerifier.TestNameConstraintsRefuseOutOfScopePath;
begin
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['direct_out_of_scope_leaf', 'root'])), 'a leaf outside the anchor permitted subtree');
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['apple_out_of_scope_leaf', 'root'])), 'a short-validity leaf outside the subtree');
end;

procedure TTestCertificateVerifier.TestNameConstraintsIntersectIntermediate;
begin
  CheckTrue(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['in_scope_leaf', 'issuer', 'root'])), 'inside the anchor and the intermediate');
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['root_scope_leaf', 'issuer', 'root'])), 'inside the anchor, outside the intermediate');
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['out_of_scope_leaf', 'issuer', 'root'])), 'outside both');
end;

procedure TTestCertificateVerifier.TestNameConstraintsSurviveAnOpenIntermediate;
begin
  CheckTrue(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['open_in_scope_leaf', 'issuer_open', 'root'])),
    'an unconstrained intermediate passes an in-scope leaf');
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['open_out_of_scope_leaf', 'issuer_open', 'root'])),
    'only the anchor refuses a leaf outside its permitted subtree');
end;

procedure TTestCertificateVerifier.TestNameConstraintsHonourExcludedSubtrees;
begin
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(
    NcPath(['excluded_leaf', 'issuer_open', 'root'])),
    'a leaf inside the permitted subtree and inside the excluded one');
end;

procedure TTestCertificateVerifier.TestNameConstraintsAdmitDirectlyTrustedLeaf;
begin
  CheckTrue(Pkix.PathValidation.NameConstraintsAdmit(NcPath(['direct_out_of_scope_leaf'])),
    'a one-certificate path has no constraint above it');
end;

procedure TTestCertificateVerifier.TestNameConstraintsRefuseUnusablePaths;
begin
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(nil), 'an empty path');
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(TArray<TBytes>.Create(
    TBytes.Create(1, 2, 3), NcPath(['root'])[0])), 'a certificate that is not DER');
  CheckFalse(Pkix.PathValidation.NameConstraintsAdmit(TArray<TBytes>.Create(
    TBytes.Create($30, $03, $02, $01), NcPath(['root'])[0])),
    'a certificate whose DER is truncated');
end;

procedure TTestCertificateVerifier.TestNameConstrainedChainIsValidatedByTheBuiltInVerifier;
var
  LVerifier: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LRefused: TArray<string>;
  LName: string;
begin
  LVerifier := IntermediateVerifierFor(NcPath(['root'])[0], NcPath(['issuer', 'issuer_open']));
  CheckTrue(LVerifier.VerifyServerCertificate(NcPath(['in_scope_leaf']),
    TServerName.DnsName(''), nil, LVerified, LAlert), 'inside the anchor and the intermediate');
  CheckTrue(LVerifier.VerifyServerCertificate(NcPath(['open_in_scope_leaf']),
    TServerName.DnsName(''), nil, LVerified, LAlert), 'through the unconstrained intermediate');
  LRefused := TArray<string>.Create('root_scope_leaf', 'open_out_of_scope_leaf',
    'excluded_leaf');
  for LName in LRefused do
  begin
    CheckFalse(LVerifier.VerifyServerCertificate(NcPath([LName]), TServerName.DnsName(''), nil,
      LVerified, LAlert), LName + ' is refused');
    CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
      LName + ' is certificate_unknown');
  end;
end;

procedure TTestCertificateVerifier.TestWeakAnchorChainIsValidatedByTheBuiltInVerifier;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  CheckTrue(VerifierFor(DecodeHex(FWeakAnchor.Values['root_cert']), False).VerifyServerCertificate(
    TArray<TBytes>.Create(DecodeHex(FWeakAnchor.Values['leaf_cert'])), TServerName.DnsName(''),
    nil, LVerified, LAlert), 'the EC leaf chains to the RSA-2048 root');
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

procedure TTestCertificateVerifier.TestChainWhoseFirstCertificateIsACaIsRefusedAsEndEntity;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the build targets index 0 (the issuer here), which the end-entity rule then refuses as a CA
  CheckFalse(VerifierFor(Chain3('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('issuer_cert'), Chain3('leaf_cert'), Chain3('root_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert), 'a CA presented first is refused');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert), 'the alert is bad_certificate');
end;

procedure TTestCertificateVerifier.TestReorderedChainBuildsFromPresentedFirstCert;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // the build targets index 0 whatever order the rest arrive in: the extra root is only an input
  CheckTrue(VerifierFor(Chain3('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert'), Chain3('root_cert'), Chain3('issuer_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a chain builds from the first presented certificate to the anchor');
  CheckEqualBytes('path[0] is the presented first certificate', Chain3('leaf_cert'),
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
  // on any validated edge (RFC 9846 4.5.1.3) - but the anchor's self-signature is not one, so a
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
  // refuses a SHA-1-signed chain certificate (RFC 9846 4.5.1.3)
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
  LClock: ITlsMonotonicClock;
  LStart: Int64;
begin
  Result := TTlsAlertDescription.CloseNotify; // stands for "no alert raised"
  LEffective := nil;
  LClock := TSystemMonotonicClock.Create as ITlsMonotonicClock;
  LStart := LClock.NowMonotonicMillis;
  try
    Pkix.PathValidation.ValidateCertificatePath(AChain,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(AAnchor)) as ITrustAnchorStore, nil,
      NowUtc, TCertKeyPurpose.ServerAuth, LEffective);
  except
    on E: EFatalAlertTlsLibException do
      Result := E.AlertDescription;
  end;
  AElapsedMs := LClock.NowMonotonicMillis - LStart;
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

procedure TTestCertificateVerifier.TestEmptyChainIsBadCertificate;
var
  LElapsed: Int64;
begin
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(PathAlert(nil, Flood('anchor'), LElapsed)),
    'a chain with no certificate has no leaf to build a path for');
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

{ TChainFailureAlertTestBase }

function TChainFailureAlertTestBase.Chain(const ANames: array of string): TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(ANames));
  for LI := 0 to System.High(ANames) do
    Result[LI] := TTlsLibTestCertificates.Field('Certs/ChainFailures.txt', ANames[LI]);
end;

procedure TChainFailureAlertTestBase.TestValidChainIsAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(Verdict(['chain_leaf', 'chain_inter'], LAlert),
    'the fixture chain the bad-signature cases imitate is valid');
end;

procedure TChainFailureAlertTestBase.TestBadSignatureUnderAPooledIntermediateIsDecryptError;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_badsig_leaf', 'chain_inter'], LAlert),
    'a leaf not signed by its named intermediate is refused');
  CheckEquals(Ord(TTlsAlertDescription.DecryptError), Ord(LAlert),
    'an invalid certificate signature is decrypt_error');
end;

procedure TChainFailureAlertTestBase.TestCriticalPrivateExtensionOnTheLeafIsCertificateUnknown;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_crit_leaf'], LAlert),
    'a leaf with an unrecognized critical extension is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'an unhandled critical extension is certificate_unknown');
end;

procedure TChainFailureAlertTestBase.TestCriticalPrivateExtensionOnAnIntermediateIsCertificateUnknown;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_crit_inter_leaf', 'chain_crit_inter'], LAlert),
    'an intermediate with an unrecognized critical extension is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'an unhandled critical extension is certificate_unknown');
end;

{ TTestChainFailureAlerts }

const
  // 2019-06-01, before every fixture certificate is valid
  UnixMillisBeforeValidity = UInt64(1559347200000);
  // 2030-01-01, inside the leaf and the root windows but before chain_future_inter begins
  UnixMillisBeforeFutureIssuer = UInt64(1893456000000);
  // 2045-01-01, inside every fixture window
  UnixMillisInsideAllWindows = UInt64(2366841600000);

procedure TTestChainFailureAlerts.SetUp;
begin
  inherited SetUp;
  FUnixMillis := UnixMillisInsideAllWindows;
end;

function TTestChainFailureAlerts.Verdict(const AChain: array of string;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TCertificateVerifier.Create(Pkix, TMockClock.Create(FUnixMillis) as ITlsClock,
    TTrustAnchorStore.Create(Chain(['chain_root'])) as ITrustAnchorStore, True)
    as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(Chain(AChain), TServerName.DnsName('localhost'),
    nil, LVerified, AAlert);
end;

function TTestChainFailureAlerts.ClientVerdict(const AChain: array of string;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TCertificateVerifier.Create(Pkix, TMockClock.Create(FUnixMillis) as ITlsClock,
    TTrustAnchorStore.Create(Chain(['chain_root'])) as ITrustAnchorStore, False)
    as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(Chain(AChain), LVerified, AAlert);
end;

procedure TTestChainFailureAlerts.TestBadSignatureAsClientCertificateIsDecryptError;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(ClientVerdict(['chain_badsig_leaf', 'chain_inter'], LAlert),
    'a client chain with an invalid signature is refused');
  CheckEquals(Ord(TTlsAlertDescription.DecryptError), Ord(LAlert),
    'an invalid certificate signature is decrypt_error');
end;

procedure TTestChainFailureAlerts.TestExpiryOutranksABadSignature;
var
  LAlert: TTlsAlertDescription;
begin
  FUnixMillis := UnixMillisBeforeValidity;
  CheckFalse(Verdict(['chain_badsig_leaf', 'chain_inter'], LAlert),
    'a not-yet-valid chain with an invalid signature is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'the validity window is reported before the signature');
end;

procedure TTestChainFailureAlerts.TestNameConstraintViolationIsCertificateUnknown;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  LVerifier := TCertificateVerifier.Create(Pkix,
    TMockClock.Create(UnixMillisInsideAllWindows) as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TTlsLibTestCertificates.Field(
    'Certs/NameConstrainedRoot.txt', 'root_cert'))) as ITrustAnchorStore, True)
    as IServerCertificateVerifier;
  CheckFalse(LVerifier.VerifyServerCertificate(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/NameConstrainedRoot.txt', 'out_of_scope_leaf_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a leaf outside the anchor name constraints is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'a name-constraint violation is certificate_unknown');
end;

procedure TTestChainFailureAlerts.TestBadSignatureDirectlyUnderTheAnchorIsDecryptError;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_anchor_badsig_leaf'], LAlert),
    'a leaf not signed by the anchor it names is refused');
  CheckEquals(Ord(TTlsAlertDescription.DecryptError), Ord(LAlert),
    'an invalid certificate signature is decrypt_error');
end;

procedure TTestChainFailureAlerts.TestNotYetValidChainIsCertificateExpired;
var
  LAlert: TTlsAlertDescription;
begin
  FUnixMillis := UnixMillisBeforeValidity;
  CheckFalse(Verdict(['chain_leaf', 'chain_inter'], LAlert), 'a chain not yet valid is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'a not-yet-valid certificate is certificate_expired');
end;

procedure TTestChainFailureAlerts.TestNotYetValidIntermediateIsCertificateExpired;
var
  LAlert: TTlsAlertDescription;
begin
  FUnixMillis := UnixMillisBeforeFutureIssuer;
  CheckFalse(Verdict(['chain_future_leaf', 'chain_future_inter'], LAlert),
    'a chain whose intermediate is not yet valid is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'a not-yet-valid intermediate is certificate_expired');
end;

procedure TTestChainFailureAlerts.TestIntermediateInsideItsValidityWindowIsAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(Verdict(['chain_future_leaf', 'chain_future_inter'], LAlert),
    'the same chain is accepted once the intermediate is valid');
end;

{$IFDEF TLSLIB_ANDROID}

{ TTestAndroidChainFailureAlerts }

function TTestAndroidChainFailureAlerts.RequestFor(const ACerts: TArray<TBytes>;
  const AAnchor: TBytes): TPlatformChainRequest;
begin
  Result := Default(TPlatformChainRequest);
  Result.Chain := TArray<TBytes>.Create(ACerts[0]);
  Result.Intermediates := System.Copy(ACerts, 1, System.Length(ACerts) - 1);
  Result.Anchors := TArray<TBytes>.Create(AAnchor);
  CheckTrue(TServerName.TryParse('localhost', Result.ServerName));
end;

function TTestAndroidChainFailureAlerts.Verdict(const AChain: array of string;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LEngine: IPlatformChainEngine;
  LResult: TPlatformChainResult;
begin
  LEngine := TAndroidChainEngine.Create as IPlatformChainEngine;
  Result := LEngine.EvaluateServer(RequestFor(Chain(AChain), Chain(['chain_root'])[0]), LResult,
    AAlert);
  FFailure := LResult.Failure;
end;

procedure TTestAndroidChainFailureAlerts.TestBadSignatureAsClientCertificateIsDecryptError;
var
  LEngine: IPlatformChainEngine;
  LResult: TPlatformChainResult;
  LAlert: TTlsAlertDescription;
begin
  LEngine := TAndroidChainEngine.Create as IPlatformChainEngine;
  CheckFalse(LEngine.EvaluateClient(RequestFor(Chain(['chain_badsig_leaf', 'chain_inter']),
    Chain(['chain_root'])[0]), LResult, LAlert), 'the client chain is refused');
  CheckEquals(Ord(TTlsAlertDescription.DecryptError), Ord(LAlert),
    'an invalid certificate signature is decrypt_error');
end;

procedure TTestAndroidChainFailureAlerts.TestBadSignatureUnderTheAnchorIsUnknownCa;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_anchor_badsig_leaf'], LAlert),
    'a leaf not signed by the anchor it names is refused');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the platform reads it as a missing anchor');
  CheckEquals(Ord(TPlatformChainFailure.NoTrustAnchor), Ord(FFailure), 'failure class');
end;

procedure TTestAndroidChainFailureAlerts.TestBadSignatureUnderAPooledIntermediateIsNotAMissingAnchor;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_badsig_leaf', 'chain_inter'], LAlert), 'the chain is refused');
  CheckEquals(Ord(TPlatformChainFailure.Other), Ord(FFailure), 'failure class');
end;

function TTestAndroidChainFailureAlerts.NcChain(const ANames: array of string): TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(ANames));
  for LI := 0 to System.High(ANames) do
    Result[LI] := TTlsLibTestCertificates.Field('Certs/NameConstrainedChain.txt',
      ANames[LI] + '_cert');
end;

function TTestAndroidChainFailureAlerts.PolicyFor(const AAnchor: TBytes): TOSDelegatePolicy;
begin
  Result := Default(TOSDelegatePolicy);
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.Pkix := Pkix;
  Result.Clock := TSystemClock.Create as ITlsClock;
  Result.Posture := TRevocationPosture.Off;
  Result.Fetch := TSystemTrustFetch.CacheOnly;
  Result.Deferral := TVerdictDeferral.None;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.AdvertisedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.Anchors := TArray<TBytes>.Create(AAnchor);
  Result.AnchorStore := TTrustAnchorStore.Create(Result.Anchors) as ITrustAnchorStore;
  Result.CheckHostName := False;
  Result.DeadlineMs := 2000;
end;

function TTestAndroidChainFailureAlerts.NcServerVerdict(const AChain: array of string;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LVerifier := TOSDelegateServerVerifier.Create(TAndroidChainEngine.Create as IPlatformChainEngine,
    PolicyFor(NcChain(['root'])[0])) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(NcChain(AChain), TServerName.DnsName('localhost'),
    nil, LVerified, AAlert);
end;

function TTestAndroidChainFailureAlerts.NcClientVerdict(const ALeaf: string;
  const AIntermediates: array of string; out APathLength: Int32;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LPolicy: TOSDelegatePolicy;
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LPolicy := PolicyFor(NcChain(['root'])[0]);
  LPolicy.Intermediates := NcChain(AIntermediates);
  LVerifier := TOSDelegateClientVerifier.Create(TAndroidChainEngine.Create as IPlatformChainEngine,
    LPolicy) as IClientCertificateVerifier;
  Result := LVerifier.VerifyClientCertificate(NcChain([ALeaf]), LVerified, AAlert);
  APathLength := System.Length(LVerified.Path);
end;

procedure TTestAndroidChainFailureAlerts.TestAnchorNameConstraintsAreEnforcedByTheServerDelegate;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(NcServerVerdict(['direct_out_of_scope_leaf'], LAlert),
    'a leaf outside the anchor name constraints is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckTrue(NcServerVerdict(['direct_in_scope_leaf'], LAlert),
    'a leaf inside the anchor name constraints is accepted');
end;

procedure TTestAndroidChainFailureAlerts.TestAnchorNameConstraintsSurviveAnOpenIntermediateOnTheServerDelegate;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(NcServerVerdict(['open_out_of_scope_leaf', 'issuer_open'], LAlert),
    'the open intermediate carries no constraint, so the library holds the leaf to the anchor');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckTrue(NcServerVerdict(['open_in_scope_leaf', 'issuer_open'], LAlert),
    'a leaf inside the anchor name constraints under the open intermediate is accepted');
end;

procedure TTestAndroidChainFailureAlerts.TestAnchorNameConstraintsAreEnforcedByTheClientDelegate;
var
  LAlert: TTlsAlertDescription;
  LPathLength: Int32;
begin
  CheckFalse(NcClientVerdict('direct_out_of_scope_leaf', [], LPathLength, LAlert),
    'a client leaf outside the anchor name constraints is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckTrue(NcClientVerdict('direct_in_scope_leaf', [], LPathLength, LAlert),
    'a client leaf inside the anchor name constraints is accepted');
  CheckEquals(2, LPathLength, 'the built path is the leaf and the anchor');
end;

procedure TTestAndroidChainFailureAlerts.TestAnchorNameConstraintsSurviveAnOpenIntermediateOnTheClientDelegate;
var
  LAlert: TTlsAlertDescription;
  LPathLength: Int32;
begin
  CheckFalse(NcClientVerdict('open_out_of_scope_leaf', ['issuer_open'], LPathLength, LAlert),
    'a client leaf under the open intermediate is held to the anchor constraints');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'the alert is certificate_unknown');
  CheckTrue(NcClientVerdict('open_in_scope_leaf', ['issuer_open'], LPathLength, LAlert),
    'a client leaf inside the anchor name constraints under the open intermediate is accepted');
  CheckEquals(3, LPathLength, 'the built path is the leaf, the intermediate and the anchor');
end;

{$ENDIF TLSLIB_ANDROID}

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateVerifier);
  RegisterTest(TTestVerifyCallbackVerifier);
  RegisterTest(TTestCriticalExtensionsAndEndEntity);
  RegisterTest(TTestChainFailureAlerts);
{$IFDEF TLSLIB_ANDROID}
  RegisterTest(TTestAndroidChainFailureAlerts);
{$ENDIF TLSLIB_ANDROID}
{$ELSE}
  RegisterTest(TTestCertificateVerifier.Suite);
  RegisterTest(TTestVerifyCallbackVerifier.Suite);
  RegisterTest(TTestCriticalExtensionsAndEndEntity.Suite);
  RegisterTest(TTestChainFailureAlerts.Suite);
{$IFDEF TLSLIB_ANDROID}
  RegisterTest(TTestAndroidChainFailureAlerts.Suite);
{$ENDIF TLSLIB_ANDROID}
{$ENDIF FPC}

end.
