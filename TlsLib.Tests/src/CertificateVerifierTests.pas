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
  TlpServerName,
  TlpCertificateVerifier,
  TlpCertificateLimits,
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
    function Cert(const AName: string): TBytes;
    function Chain3(const AName: string): TBytes;
    function EkuCert(const AName: string): TBytes;
    function EkuEdgeCert(const AName: string): TBytes;
    function VerifierFor(const ARoot: TBytes; ACheckHostName: Boolean)
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
end;

procedure TTestCertificateVerifier.TearDown;
begin
  FCerts.Free;
  FChain3.Free;
  FEku.Free;
  FEkuEdge.Free;
  inherited TearDown;
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
  Result := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    ACheckHostName) as IServerCertificateVerifier;
end;

function TTestCertificateVerifier.ClientVerifierFor(const ARoot: TBytes)
  : IClientCertificateVerifier;
begin
  Result := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    False) as IClientCertificateVerifier;
end;

function TTestCertificateVerifier.IntermediateVerifierFor(const ARoot: TBytes;
  const AIntermediates: TArray<TBytes>): IServerCertificateVerifier;
var
  LNoDangerous: TDangerousTrust;
begin
  LNoDangerous := Default(TDangerousTrust);
  Result := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    False, TCertificateChainLimits.Defaults, TRevocationPosture.Soft, nil,
    LNoDangerous, False, AIntermediates) as IServerCertificateVerifier;
end;

procedure TTestCertificateVerifier.TestValidChainTrusted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('localhost'), nil, LAlert),
    'a valid leaf chaining to the trusted root, matching the host, is trusted');
end;

procedure TTestCertificateVerifier.TestExpiredRejectedAsCertificateExpired;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('expired_cert')), TServerName.DnsName('localhost'), nil, LAlert),
    'an expired certificate is rejected');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'the alert is certificate_expired');
end;

procedure TTestCertificateVerifier.TestUntrustedRootRejectedAsUnknownCa;
var
  LAlert: TTlsAlertDescription;
begin
  // the leaf is genuine but the store trusts only an unrelated root
  CheckFalse(VerifierFor(Cert('root2_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('localhost'), nil, LAlert),
    'a chain that does not reach a trusted anchor is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is unknown_ca');
end;

procedure TTestCertificateVerifier.TestHostNameMismatchRejectedAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('other.example'), nil, LAlert),
    'a leaf that is valid but for the wrong host is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestCertificateVerifier.TestEmptyChainRejected;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).VerifyServerCertificate(nil, TServerName.DnsName('localhost'), nil, LAlert),
    'an empty certificate chain is rejected');
end;

procedure TTestCertificateVerifier.TestHostNameCheckDisabledIgnoresName;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifierFor(Cert('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), TServerName.DnsName('other.example'), nil, LAlert),
    'with host-name checking off, a name mismatch does not reject a trusted chain');
end;

procedure TTestCertificateVerifier.TestIncompleteChainWithoutIntermediatesRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // the server sends only its leaf, omitting the issuing CA; with no configured
  // intermediates no path to the trusted root can be built - this is the failure a
  // leaf-only server produces
  CheckFalse(IntermediateVerifierFor(Chain3('root_cert'), nil).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert')), TServerName.DnsName(''), nil, LAlert),
    'a leaf-only chain with no configured intermediates cannot reach the root');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is unknown_ca');
end;

procedure TTestCertificateVerifier.TestIncompleteChainCompletedByIntermediates;
var
  LAlert: TTlsAlertDescription;
begin
  // the same leaf-only chain, but the missing intermediate is supplied via config: the
  // path builder now assembles leaf -> issuer -> root and the chain is trusted
  CheckTrue(IntermediateVerifierFor(Chain3('root_cert'),
    TArray<TBytes>.Create(Chain3('issuer_cert'))).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert')), TServerName.DnsName(''), nil, LAlert),
    'a configured intermediate completes an otherwise incomplete chain');
end;

procedure TTestCertificateVerifier.TestCompleteChainStillTrustedWithIntermediates;
var
  LAlert: TTlsAlertDescription;
begin
  // a server that sends its full chain still verifies when intermediates are also
  // configured - the extra copy is a redundant pool entry, never a second path
  CheckTrue(IntermediateVerifierFor(Chain3('root_cert'),
    TArray<TBytes>.Create(Chain3('issuer_cert'))).VerifyServerCertificate(
    TArray<TBytes>.Create(Chain3('leaf_cert'), Chain3('issuer_cert')), TServerName.DnsName(''), nil, LAlert),
    'a complete chain remains trusted when intermediates are configured too');
end;

procedure TTestCertificateVerifier.TestServerCertWithClientAuthOnlyEkuRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // a leaf whose extendedKeyUsage is clientAuth-only is not a valid SERVER certificate,
  // even though it chains to the trusted root
  CheckFalse(VerifierFor(EkuCert('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(EkuCert('clientonly_leaf_cert')), TServerName.DnsName('localhost'),
    nil, LAlert), 'a clientAuth-only leaf is rejected as a server certificate');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'the alert is unsupported_certificate');
end;

procedure TTestCertificateVerifier.TestServerCertWithNoEkuAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  // no extendedKeyUsage extension means unrestricted (RFC 5280 4.2.1.12): accepted
  CheckTrue(VerifierFor(EkuCert('root_cert'), False).VerifyServerCertificate(
    TArray<TBytes>.Create(EkuCert('noeku_leaf_cert')), TServerName.DnsName('localhost'),
    nil, LAlert), 'a leaf with no EKU is accepted as a server certificate');
end;

procedure TTestCertificateVerifier.TestClientCertWithServerAuthOnlyEkuRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // the EcP256 leaf carries serverAuth only; it is not a valid CLIENT certificate
  CheckFalse(ClientVerifierFor(Cert('root_cert')).VerifyClientCertificate(
    TArray<TBytes>.Create(Cert('leaf_cert')), LAlert),
    'a serverAuth-only leaf is rejected as a client certificate');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'the alert is unsupported_certificate');
end;

procedure TTestCertificateVerifier.TestClientCertWithClientAuthAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  // the dual-EKU leaf carries clientAuth; it is a valid client certificate
  CheckTrue(ClientVerifierFor(EkuCert('root_cert')).VerifyClientCertificate(
    TArray<TBytes>.Create(EkuCert('leaf_cert')), LAlert),
    'a clientAuth-capable leaf is accepted as a client certificate');
end;

procedure TTestCertificateVerifier.TestPinnedSelfSignedClientAuthOnlyLeafRejectedAsServer;
var
  LAlert: TTlsAlertDescription;
  LCert: TBytes;
begin
  // the leaf is directly trusted (pinned as its own anchor) yet its extendedKeyUsage is
  // clientAuth-only: the end-entity's purpose is enforced even when it equals the anchor
  LCert := EkuEdgeCert('clientauth_selfsigned_cert');
  CheckFalse(VerifierFor(LCert, False).VerifyServerCertificate(
    TArray<TBytes>.Create(LCert), TServerName.DnsName('localhost'), nil, LAlert),
    'a pinned self-signed clientAuth-only leaf is rejected as a server certificate');
  CheckEquals(Ord(TTlsAlertDescription.UnsupportedCertificate), Ord(LAlert),
    'the alert is unsupported_certificate');
end;

procedure TTestCertificateVerifier.TestMalformedEkuRejectedAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
  LCert: TBytes;
begin
  // the extendedKeyUsage extension is present but its value is not a SEQUENCE OF OID; this is
  // a malformed certificate, reported as bad_certificate rather than an opaque internal_error
  LCert := EkuEdgeCert('malformed_eku_selfsigned_cert');
  CheckFalse(VerifierFor(LCert, False).VerifyServerCertificate(
    TArray<TBytes>.Create(LCert), TServerName.DnsName('localhost'), nil, LAlert),
    'a certificate with a malformed EKU extension is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateVerifier);
{$ELSE}
  RegisterTest(TTestCertificateVerifier.Suite);
{$ENDIF FPC}

end.
