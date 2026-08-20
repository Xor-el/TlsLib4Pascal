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
    function Cert(const AName: string): TBytes;
    function Chain3(const AName: string): TBytes;
    function VerifierFor(const ARoot: TBytes; ACheckHostName: Boolean)
      : ICertificateVerifier;
    // a verifier trusting ARoot and seeded with AIntermediates for path building; host-name
    // checking is off so these tests isolate PKIX path construction
    function IntermediateVerifierFor(const ARoot: TBytes;
      const AIntermediates: TArray<TBytes>): ICertificateVerifier;
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
  end;

implementation

{ TTestCertificateVerifier }

procedure TTestCertificateVerifier.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  FChain3 := LoadVectorFields('Certs/OcspStapling.txt');
end;

procedure TTestCertificateVerifier.TearDown;
begin
  FCerts.Free;
  FChain3.Free;
  inherited TearDown;
end;

function TTestCertificateVerifier.Cert(const AName: string): TBytes;
begin
  Result := DecodeHex(FCerts.Values[AName]);
end;

function TTestCertificateVerifier.Chain3(const AName: string): TBytes;
begin
  Result := DecodeHex(FChain3.Values[AName]);
end;

function TTestCertificateVerifier.VerifierFor(const ARoot: TBytes;
  ACheckHostName: Boolean): ICertificateVerifier;
begin
  Result := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    ACheckHostName) as ICertificateVerifier;
end;

function TTestCertificateVerifier.IntermediateVerifierFor(const ARoot: TBytes;
  const AIntermediates: TArray<TBytes>): ICertificateVerifier;
var
  LNoDangerous: TDangerousTrust;
begin
  LNoDangerous := Default(TDangerousTrust);
  Result := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(ARoot)) as ITrustAnchorStore,
    False, TCertificateChainLimits.Defaults, TRevocationPosture.Soft, nil,
    LNoDangerous, False, AIntermediates) as ICertificateVerifier;
end;

procedure TTestCertificateVerifier.TestValidChainTrusted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifierFor(Cert('root_cert'), True).Verify(
    TArray<TBytes>.Create(Cert('leaf_cert')), 'localhost', nil, LAlert),
    'a valid leaf chaining to the trusted root, matching the host, is trusted');
end;

procedure TTestCertificateVerifier.TestExpiredRejectedAsCertificateExpired;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).Verify(
    TArray<TBytes>.Create(Cert('expired_cert')), 'localhost', nil, LAlert),
    'an expired certificate is rejected');
  CheckEquals(Ord(TTlsAlertDescription.CertificateExpired), Ord(LAlert),
    'the alert is certificate_expired');
end;

procedure TTestCertificateVerifier.TestUntrustedRootRejectedAsUnknownCa;
var
  LAlert: TTlsAlertDescription;
begin
  // the leaf is genuine but the store trusts only an unrelated root
  CheckFalse(VerifierFor(Cert('root2_cert'), True).Verify(
    TArray<TBytes>.Create(Cert('leaf_cert')), 'localhost', nil, LAlert),
    'a chain that does not reach a trusted anchor is rejected');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LAlert),
    'the alert is unknown_ca');
end;

procedure TTestCertificateVerifier.TestHostNameMismatchRejectedAsBadCertificate;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).Verify(
    TArray<TBytes>.Create(Cert('leaf_cert')), 'other.example', nil, LAlert),
    'a leaf that is valid but for the wrong host is rejected');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate), Ord(LAlert),
    'the alert is bad_certificate');
end;

procedure TTestCertificateVerifier.TestEmptyChainRejected;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(VerifierFor(Cert('root_cert'), True).Verify(nil, 'localhost', nil, LAlert),
    'an empty certificate chain is rejected');
end;

procedure TTestCertificateVerifier.TestHostNameCheckDisabledIgnoresName;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(VerifierFor(Cert('root_cert'), False).Verify(
    TArray<TBytes>.Create(Cert('leaf_cert')), 'other.example', nil, LAlert),
    'with host-name checking off, a name mismatch does not reject a trusted chain');
end;

procedure TTestCertificateVerifier.TestIncompleteChainWithoutIntermediatesRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // the server sends only its leaf, omitting the issuing CA; with no configured
  // intermediates no path to the trusted root can be built - this is the failure a
  // leaf-only server produces
  CheckFalse(IntermediateVerifierFor(Chain3('root_cert'), nil).Verify(
    TArray<TBytes>.Create(Chain3('leaf_cert')), '', nil, LAlert),
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
    TArray<TBytes>.Create(Chain3('issuer_cert'))).Verify(
    TArray<TBytes>.Create(Chain3('leaf_cert')), '', nil, LAlert),
    'a configured intermediate completes an otherwise incomplete chain');
end;

procedure TTestCertificateVerifier.TestCompleteChainStillTrustedWithIntermediates;
var
  LAlert: TTlsAlertDescription;
begin
  // a server that sends its full chain still verifies when intermediates are also
  // configured - the extra copy is a redundant pool entry, never a second path
  CheckTrue(IntermediateVerifierFor(Chain3('root_cert'),
    TArray<TBytes>.Create(Chain3('issuer_cert'))).Verify(
    TArray<TBytes>.Create(Chain3('leaf_cert'), Chain3('issuer_cert')), '', nil, LAlert),
    'a complete chain remains trusted when intermediates are configured too');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateVerifier);
{$ELSE}
  RegisterTest(TTestCertificateVerifier.Suite);
{$ENDIF FPC}

end.
