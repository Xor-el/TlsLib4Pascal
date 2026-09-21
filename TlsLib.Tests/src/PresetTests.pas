{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit PresetTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsVersion,
  TlpNegotiationTypes,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlsLibTestBase;

type
  TTestPreset = class(TTlsLibAlgorithmTestCase)
  private
    function ClientOf(const ABuilder: ITlsConfigBuilder): ITlsClientConfig;
  published
    procedure TestHardenedPrefersPqHybridGroup;
    procedure TestCompatiblePrefersX25519;
    procedure TestStrictIsGroupAllowlist;
    procedure TestStrictTightensCertificateChainLimits;
    procedure TestHardenedAndStrictAreTls13Only;
    procedure TestCompatibleOffersTls13And12;
    procedure TestHardenedAndStrictRequestOcspStapling;
    procedure TestCompatibleDoesNotRequestStapling;
    procedure TestStrictWithHardRevocationBuilds;
  end;

implementation

{ TTestPreset }

function TTestPreset.ClientOf(
  const ABuilder: ITlsConfigBuilder): ITlsClientConfig;
begin
  // any non-nil trust source lets the client build so its invariants can be read
  Result := ABuilder.Client.WithTrustStore(
    TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build;
end;

procedure TTestPreset.TestHardenedPrefersPqHybridGroup;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := ClientOf(TTlsPresets.Hardened(Provider));
  CheckEquals(TNamedGroupCatalog.X25519MlKem768, LConfig.PreferredGroups[0],
    'Hardened prefers the post-quantum hybrid group');
end;

procedure TTestPreset.TestCompatiblePrefersX25519;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := ClientOf(TTlsPresets.Compatible(Provider));
  CheckEquals(TNamedGroupCatalog.X25519, LConfig.PreferredGroups[0],
    'Compatible prefers classical X25519');
end;

procedure TTestPreset.TestStrictIsGroupAllowlist;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := ClientOf(TTlsPresets.Strict(Provider));
  CheckEquals(2, System.Length(LConfig.PreferredGroups),
    'Strict allows exactly two groups');
  CheckEquals(TNamedGroupCatalog.X25519MlKem768, LConfig.PreferredGroups[0], 'hybrid');
  CheckEquals(TNamedGroupCatalog.X25519, LConfig.PreferredGroups[1], 'X25519');
end;

procedure TTestPreset.TestStrictTightensCertificateChainLimits;
var
  LStrict, LCompatible: TCertificateChainLimits;
begin
  // Strict expects a short chain of compact certificates, tighter than the default
  LStrict := ClientOf(TTlsPresets.Strict(Provider)).CertificateChainLimits;
  LCompatible := ClientOf(TTlsPresets.Compatible(Provider)).CertificateChainLimits;
  CheckEquals(5, LStrict.MaxChainLength, 'Strict caps the chain length tightly');
  CheckTrue(LStrict.MaxChainLength < LCompatible.MaxChainLength,
    'Strict is tighter than the default profile');
  CheckTrue(LStrict.MaxTotalChainLength < LCompatible.MaxTotalChainLength,
    'Strict caps the total chain bytes tighter');
end;

procedure TTestPreset.TestHardenedAndStrictAreTls13Only;
var
  LHardened, LStrict: ITlsClientConfig;
begin
  LHardened := ClientOf(TTlsPresets.Hardened(Provider));
  CheckEquals(1, System.Length(LHardened.SupportedVersions), 'Hardened is single-version');
  CheckEquals(TlsWireVersionTls13, LHardened.SupportedVersions[0], 'Hardened is TLS 1.3 only');
  LStrict := ClientOf(TTlsPresets.Strict(Provider));
  CheckEquals(1, System.Length(LStrict.SupportedVersions), 'Strict is single-version');
  CheckEquals(TlsWireVersionTls13, LStrict.SupportedVersions[0], 'Strict is TLS 1.3 only');
end;

procedure TTestPreset.TestCompatibleOffersTls13And12;
var
  LConfig: ITlsClientConfig;
begin
  // the broad default now offers TLS 1.3 and the hardened TLS 1.2 profile
  LConfig := ClientOf(TTlsPresets.Compatible(Provider));
  CheckEquals(2, System.Length(LConfig.SupportedVersions), 'two offered versions');
  CheckEquals(TlsWireVersionTls13, LConfig.SupportedVersions[0], '1.3 preferred first');
  CheckEquals(TlsWireVersionTls12, LConfig.SupportedVersions[1], '1.2 offered second');
  // a hardened 1.2 ECDHE-ECDSA suite is present in the offered registry
  CheckTrue(LConfig.CipherSuites.Contains(
    TCipherSuites12.EcdheEcdsaAes128GcmSha256), 'a hardened 1.2 suite is offered');
end;

procedure TTestPreset.TestHardenedAndStrictRequestOcspStapling;
begin
  // the stricter presets request an OCSP staple (connectivity-safe under the soft-fail default)
  CheckTrue(ClientOf(TTlsPresets.Hardened(Provider)).RequestOcspStapling,
    'Hardened requests an OCSP staple');
  CheckTrue(ClientOf(TTlsPresets.Strict(Provider)).RequestOcspStapling,
    'Strict requests an OCSP staple');
end;

procedure TTestPreset.TestCompatibleDoesNotRequestStapling;
begin
  // Compatible keeps the default (no staple requested) for maximum reach
  CheckFalse(ClientOf(TTlsPresets.Compatible(Provider)).RequestOcspStapling,
    'Compatible does not request a staple');
end;

procedure TTestPreset.TestStrictWithHardRevocationBuilds;
var
  LConfig: ITlsClientConfig;
begin
  // Strict already requests a staple, so raising the posture to Hard is satisfiable without a
  // staple request of the caller's own - Build does not fail fast as always-rejecting
  LConfig := TTlsPresets.Strict(Provider).Client
    .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
    .WithRevocation(TRevocationPosture.Hard)
    .Build;
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LConfig.RevocationPosture),
    'Strict builds with Hard revocation on the staple it already requests');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPreset);
{$ELSE}
  RegisterTest(TTestPreset.Suite);
{$ENDIF FPC}

end.
