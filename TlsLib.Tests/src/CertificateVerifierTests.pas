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
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpServerName,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpNegotiationTypes,
  TlpTrustPolicy,
  TlsLibTestBase;

type
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
    function Cert(const AName: string): TBytes;
    function Chain3(const AName: string): TBytes;
    function EkuCert(const AName: string): TBytes;
    function EkuEdgeCert(const AName: string): TBytes;
    function Reissued(const AName: string): TBytes;
    function VerifierFor(const ARoot: TBytes; ACheckHostName: Boolean)
      : IServerCertificateVerifier;
    // a verifier trusting ARoot with the chain-algorithm policy switched on, as the engine
    // wires it: only AAdvertised signature schemes are acceptable on the path
    function PolicyVerifierFor(const ARoot: TBytes; const AAdvertised: TArray<UInt16>)
      : IServerCertificateVerifier;
    // a verifier trusting ARoot and seeded with AIntermediates for path building; host-name
    // checking is off so these tests isolate PKIX path construction
    function IntermediateVerifierFor(const ARoot: TBytes;
      const AIntermediates: TArray<TBytes>): IServerCertificateVerifier;
    function ClientVerifierFor(const ARoot: TBytes): IClientCertificateVerifier;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestValidChainTrusted;
    procedure TestExpiredRejectedAsCertificateExpired;
    procedure TestUntrustedRootRejectedAsUnknownCa;
    procedure TestHostNameMismatchRejectedAsBadCertificate;
    procedure TestEmptyChainRejected;
    procedure TestHostNameCheckDisabledIgnoresName;
    procedure TestIncompleteChainWithoutIntermediatesRejected;
    procedure TestIncompleteChainCompletedByIntermediates;
    procedure TestCompleteChainStillTrustedWithIntermediates;
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
    procedure TestForeignEndEntityChainRejected;
    // the trust anchor is identified by subject + key, not exact encoding (RFC 5280 6.1.1(d)):
    // a peer-sent re-issued copy of the configured root collapses onto the configured DER and
    // is exempt from path policy; a same-subject different-key root is not the anchor
    procedure TestPeerReissuedRootAcceptedAndCollapsed;
    procedure TestPeerSha1ReissuedRootExemptFromChainPolicy;
    procedure TestSha1SelfSignedRootNotConfiguredRejected;
    procedure TestSameSubjectDifferentKeyRootRejected;
  end;

implementation

{ TTestCertificateVerifier }

procedure TTestCertificateVerifier.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  FChain3 := LoadVectorFields('Certs/OcspStapling.txt');
  FEku := LoadVectorFields('Certs/ClientAuthChain.txt');
  FEkuEdge := LoadVectorFields('Certs/SelfSignedEkuEdge.txt');
  FReissued := LoadVectorFields('Certs/ReissuedRoot.txt');
end;

procedure TTestCertificateVerifier.TearDown;
begin
  FCerts.Free;
  FChain3.Free;
  FEku.Free;
  FEkuEdge.Free;
  FReissued.Free;
  inherited TearDown;
end;

function TTestCertificateVerifier.Reissued(const AName: string): TBytes;
begin
  Result := DecodeHex(FReissued.Values[AName]);
end;

function TTestCertificateVerifier.PolicyVerifierFor(const ARoot: TBytes;
  const AAdvertised: TArray<UInt16>): IServerCertificateVerifier;
var
  LVerifier: TCertificateVerifier;
begin
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore, False);
  Result := LVerifier;
  LVerifier.SetChainAlgorithmPolicy(TCertificateStrengthPolicy.Defaults, AAdvertised);
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
  LNoDangerous: TDangerousTrust;
begin
  LNoDangerous := Default(TDangerousTrust);
  Result := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    False, TCertificateChainLimits.Defaults, TRevocationPosture.Soft,
    LNoDangerous, TVerdictDeferral.None, AIntermediates) as IServerCertificateVerifier;
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

procedure TTestCertificateVerifier.TestForeignEndEntityChainRejected;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // [issuer, leaf, root] sorts to a valid path whose end-entity is the leaf, but the peer's
  // presented certificate is the issuer: validating some other presented certificate is not a
  // validation of the peer's own
  CheckFalse(VerifierFor(Chain3('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('issuer_cert'), Chain3('leaf_cert'), Chain3('root_cert')),
    TServerName.DnsName(''), nil, LVerified, LAlert),
    'a chain whose validated end-entity is not the presented leaf is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
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
  // on any validated edge (RFC 8446 4.4.2) - but the anchor's self-signature is not one, so a
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

procedure TTestCertificateVerifier.TestSameSubjectDifferentKeyRootRejected;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // a root with the anchor's subject but another key: its signature does not verify under the
  // anchor key, so it is neither the anchor nor a path to it
  CheckFalse(VerifierFor(Reissued('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Reissued('leaf_cert'), Reissued('issuer_cert'),
    Reissued('root_lookalike_cert')), TServerName.DnsName(''), nil, LVerified, LAlert),
    'a same-subject different-key root is not the configured anchor');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert), 'the alert is unknown_ca');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateVerifier);
{$ELSE}
  RegisterTest(TTestCertificateVerifier.Suite);
{$ENDIF FPC}

end.
