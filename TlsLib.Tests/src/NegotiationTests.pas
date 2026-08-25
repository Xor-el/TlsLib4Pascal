{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit NegotiationTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpCryptoAlgorithms,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpNegotiationPolicy,
  MockCryptoProvider,
  TlsLibTestBase;

type
  TTestNegotiation = class(TTlsLibAlgorithmTestCase)
  private
    function PolicyWithAes(AHasHardwareAes: Boolean): INegotiationPolicy;
    function SelectSuiteRaises(const APolicy: INegotiationPolicy;
      const AClientSuites: TArray<UInt16>;
      ADescription: TTlsAlertDescription): Boolean;
  published
    procedure TestCipherSuiteServerPreferenceHonored;
    procedure TestCipherSuiteHonorClientOrderWhenEnabled;
    procedure TestClientOrderOverridesHardwareAesTiebreak;
    procedure TestCpuAdaptiveTiebreakPrefersAesWithHardware;
    procedure TestCpuAdaptiveTiebreakPrefersChaChaWithoutHardware;
    procedure TestSuitePreferenceOrderUnifiedAcrossProtocols;
    procedure TestGroupSelectionServerPreference;
    procedure TestSignatureSchemeServerPreference;
    procedure TestNoCommonVersionIsProtocolVersion;
    procedure TestNoCommonSuiteIsHandshakeFailure;
    procedure TestRegistryPruningRemovesOption;
    procedure TestDowngradeSentinelEmittedAndDetected;
    procedure TestDualVersionRegistryHoldsHardenedTls12Suites;
    procedure TestDualVersionRegistryKeepsTls13SuitesDecoupled;
    procedure TestTls12GroupSelectionExcludesHybrid;
    procedure TestTls12CipherSelectionExcludesTls13Suite;
  end;

implementation

{ TTestNegotiation }

function TTestNegotiation.PolicyWithAes(AHasHardwareAes: Boolean): INegotiationPolicy;
begin
  Result := TNegotiationPolicy.CreateDefault(
    TFixedAesProvider.Create(Provider, AHasHardwareAes) as ICryptoProvider);
end;

function TTestNegotiation.SelectSuiteRaises(const APolicy: INegotiationPolicy;
  const AClientSuites: TArray<UInt16>;
  ADescription: TTlsAlertDescription): Boolean;
begin
  Result := False;
  try
    APolicy.SelectCipherSuite(AClientSuites, TlsWireVersionTls13);
  except
    on E: EFatalAlertTlsLibException do
      Result := E.AlertDescription = ADescription;
  end;
end;

procedure TTestNegotiation.TestCipherSuiteServerPreferenceHonored;
var
  LPolicy: INegotiationPolicy;
begin
  // with hardware AES the server prefers AES-128 over AES-256 regardless of client order
  LPolicy := PolicyWithAes(True);
  CheckEquals(TCipherSuites13.Aes128GcmSha256,
    LPolicy.SelectCipherSuite(TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384,
    TCipherSuites13.Aes128GcmSha256), TlsWireVersionTls13), 'server prefers AES-128-GCM');
end;

procedure TTestNegotiation.TestCipherSuiteHonorClientOrderWhenEnabled;
var
  LProvider: ICryptoProvider;
  LPolicy: INegotiationPolicy;
begin
  // same hardware-AES setup as above (server order prefers AES-128), but with honor-client-order
  // on: the client's most-preferred suite (AES-256) wins instead of the server's AES-128
  LProvider := TFixedAesProvider.Create(Provider, True);
  LPolicy := TNegotiationPolicy.Create(LProvider,
    TCipherSuiteRegistry.CreateDefault(LProvider),
    TNamedGroups.CreateDefaultRegistry(LProvider),
    TSignatureSchemeRegistry.CreateDefault,
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1),
    TArray<UInt16>.Create(TlsWireVersionTls13),
    TServerCipherPreference.ClientOrder);
  CheckEquals(TCipherSuites13.Aes256GcmSha384,
    LPolicy.SelectCipherSuite(TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384,
    TCipherSuites13.Aes128GcmSha256), TlsWireVersionTls13),
    'honor-client-order: the client''s AES-256 preference wins over the server''s AES-128');
end;

procedure TTestNegotiation.TestClientOrderOverridesHardwareAesTiebreak;
var
  LProvider: ICryptoProvider;
  LPolicy: INegotiationPolicy;
begin
  // the hardware-AES tiebreak lives in the SERVER's order (AES-GCM ahead of ChaCha with hardware
  // AES). Under ClientOrder the client's order decides and that tiebreak is bypassed: a ChaCha-
  // first client gets ChaCha even from a hardware-AES server (the mobile-client case)
  LProvider := TFixedAesProvider.Create(Provider, True);
  LPolicy := TNegotiationPolicy.Create(LProvider,
    TCipherSuiteRegistry.CreateDefault(LProvider),
    TNamedGroups.CreateDefaultRegistry(LProvider),
    TSignatureSchemeRegistry.CreateDefault,
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1),
    TArray<UInt16>.Create(TlsWireVersionTls13),
    TServerCipherPreference.ClientOrder);
  CheckEquals(TCipherSuites13.ChaCha20Poly1305Sha256,
    LPolicy.SelectCipherSuite(TArray<UInt16>.Create(TCipherSuites13.ChaCha20Poly1305Sha256,
    TCipherSuites13.Aes128GcmSha256), TlsWireVersionTls13),
    'ClientOrder overrides the hardware-AES tiebreak: a ChaCha-first client gets ChaCha');
end;

procedure TTestNegotiation.TestCpuAdaptiveTiebreakPrefersAesWithHardware;
var
  LPolicy: INegotiationPolicy;
begin
  LPolicy := PolicyWithAes(True);
  CheckEquals(TCipherSuites13.Aes128GcmSha256,
    LPolicy.SelectCipherSuite(TArray<UInt16>.Create(TCipherSuites13.ChaCha20Poly1305Sha256,
    TCipherSuites13.Aes128GcmSha256), TlsWireVersionTls13),
    'hardware AES -> AES-GCM ahead of ChaCha');
end;

procedure TTestNegotiation.TestCpuAdaptiveTiebreakPrefersChaChaWithoutHardware;
var
  LPolicy: INegotiationPolicy;
begin
  LPolicy := PolicyWithAes(False);
  CheckEquals(TCipherSuites13.ChaCha20Poly1305Sha256,
    LPolicy.SelectCipherSuite(TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites13.ChaCha20Poly1305Sha256), TlsWireVersionTls13),
    'no hardware AES -> ChaCha ahead of AES-GCM');
end;

procedure TTestNegotiation.TestSuitePreferenceOrderUnifiedAcrossProtocols;
var
  LCiphers: ICipherSuiteRegistry;

  function FirstAead(AHasHardwareAes: Boolean;
    AProtocol: TSuiteProtocol): TAeadAlgorithm;
  var
    LOrder: TArray<UInt16>;
    LSuite: TTlsCipherSuite;
  begin
    LOrder := TNegotiationPolicy.SuitePreferenceOrder(
      TFixedAesProvider.Create(Provider, AHasHardwareAes) as ICryptoProvider,
      LCiphers, AProtocol);
    CheckTrue(System.Length(LOrder) > 0, 'the preference order is non-empty');
    CheckTrue(LCiphers.TryGet(LOrder[0], LSuite), 'the first code resolves to a suite');
    Result := LSuite.Common.Aead;
  end;

begin
  // the one order all three consumers iterate (1.3 fresh, 1.2 server, 1.3 PSK): without
  // hardware AES ChaCha20 leads for both protocols; with it AES-GCM leads for both
  LCiphers := TCipherSuiteRegistry.CreateDualVersion(Provider);
  CheckTrue(FirstAead(False, TSuiteProtocol.Tls13) = TAeadAlgorithm.CHACHA20_POLY1305,
    'no hardware AES: the 1.3 order leads with ChaCha20');
  CheckTrue(FirstAead(False, TSuiteProtocol.Tls12) = TAeadAlgorithm.CHACHA20_POLY1305,
    'no hardware AES: the 1.2 order leads with ChaCha20');
  CheckFalse(FirstAead(True, TSuiteProtocol.Tls13) = TAeadAlgorithm.CHACHA20_POLY1305,
    'hardware AES: the 1.3 order leads with AES-GCM');
  CheckFalse(FirstAead(True, TSuiteProtocol.Tls12) = TAeadAlgorithm.CHACHA20_POLY1305,
    'hardware AES: the 1.2 order leads with AES-GCM');
end;

procedure TTestNegotiation.TestGroupSelectionServerPreference;
var
  LPolicy: INegotiationPolicy;
begin
  LPolicy := PolicyWithAes(True);
  // server prefers X25519 (its hybrid is not offered) over secp256r1
  CheckEquals(TNamedGroupCatalog.X25519,
    LPolicy.SelectGroup(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519), TlsWireVersionTls13), 'server prefers X25519');
end;

procedure TTestNegotiation.TestSignatureSchemeServerPreference;
var
  LPolicy: INegotiationPolicy;
begin
  LPolicy := PolicyWithAes(True);
  // ECDSA is preferred ahead of RSA-PSS in the default order
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256,
    LPolicy.SelectSignatureScheme(TArray<UInt16>.Create(TSignatureSchemes.RsaPssRsaeSha256,
    TSignatureSchemes.EcdsaSecp256r1Sha256)), 'server prefers ECDSA over RSA-PSS');
end;

procedure TTestNegotiation.TestNoCommonVersionIsProtocolVersion;
var
  LPolicy: INegotiationPolicy;
  LRaised: Boolean;
begin
  LPolicy := PolicyWithAes(True);
  CheckEquals(TlsWireVersionTls13,
    LPolicy.SelectVersion(TArray<UInt16>.Create(TlsWireVersionTls12,
    TlsWireVersionTls13)), '1.3 selected when offered');
  LRaised := False;
  try
    LPolicy.SelectVersion(TArray<UInt16>.Create(TlsWireVersionTls12));
  except
    on E: EFatalAlertTlsLibException do
      LRaised := E.AlertDescription = TTlsAlertDescription.ProtocolVersion;
  end;
  CheckTrue(LRaised, 'no 1.3 offered -> protocol_version');
end;

procedure TTestNegotiation.TestNoCommonSuiteIsHandshakeFailure;
begin
  CheckTrue(SelectSuiteRaises(PolicyWithAes(True), TArray<UInt16>.Create($9999),
    TTlsAlertDescription.HandshakeFailure), 'no common suite -> handshake_failure');
end;

procedure TTestNegotiation.TestRegistryPruningRemovesOption;
var
  LCiphers: ICipherSuiteRegistry;
  LPolicy: INegotiationPolicy;
begin
  LCiphers := TCipherSuiteRegistry.CreateDefault(Provider);
  LCiphers.Prune(TCipherSuites13.Aes128GcmSha256);
  CheckFalse(LCiphers.Contains(TCipherSuites13.Aes128GcmSha256), 'AES-128 pruned from the registry');
  LPolicy := TNegotiationPolicy.Create(Provider, LCiphers,
    TNamedGroups.CreateDefaultRegistry(Provider),
    TSignatureSchemeRegistry.CreateDefault,
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519),
    TArray<UInt16>.Create(TlsWireVersionTls13), TServerCipherPreference.ServerOrder);
  CheckTrue(SelectSuiteRaises(LPolicy, TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256),
    TTlsAlertDescription.HandshakeFailure), 'a pruned suite is no longer negotiable');
end;

procedure TTestNegotiation.TestDowngradeSentinelEmittedAndDetected;
var
  LRandom: TBytes;
  LI: Int32;
begin
  CheckEquals(0, System.Length(TDowngradeProtection.SentinelFor(TlsWireVersionTls13)),
    'no sentinel when negotiating 1.3');
  CheckEqualBytes('the 1.2 downgrade sentinel', DecodeHex('444f574e47524401'),
    TDowngradeProtection.SentinelFor(TlsWireVersionTls12));

  // a 32-byte server random ending in the 1.2 sentinel
  LRandom := nil;
  SetLength(LRandom, 32);
  for LI := 0 to 23 do
    LRandom[LI] := Byte(LI);
  Move(TDowngradeProtection.SentinelFor(TlsWireVersionTls12)[0], LRandom[24], 8);

  CheckTrue(TDowngradeProtection.IsDowngradeAttack(LRandom, True, TlsWireVersionTls12),
    'a 1.3 client on a 1.2 connection with the stamp is a downgrade');
  LRandom[31] := $00; // corrupt the sentinel
  CheckFalse(TDowngradeProtection.IsDowngradeAttack(LRandom, True, TlsWireVersionTls12),
    'no stamp -> not flagged');
end;

procedure TTestNegotiation.TestDualVersionRegistryHoldsHardenedTls12Suites;
var
  LRegistry: ICipherSuiteRegistry;

  procedure CheckSuite(ACode: UInt16; AKeyExchange: TKeyExchangeMethod;
    AAuth: TAuthMethod; AAead: TAeadAlgorithm; AHash: THashAlgorithm;
    AKeyLength: Int32; const AName: string);
  var
    LSuite: TTlsCipherSuite;
  begin
    CheckTrue(LRegistry.TryGet(ACode, LSuite), AName + ' present');
    CheckTrue(LSuite.Protocol = TSuiteProtocol.Tls12, AName + ' is a 1.2 suite');
    CheckTrue(LSuite.KeyExchange = AKeyExchange, AName + ' key exchange');
    CheckTrue(LSuite.Auth = AAuth, AName + ' auth');
    CheckTrue(LSuite.Common.Aead = AAead, AName + ' aead');
    CheckTrue(LSuite.Common.Hash = AHash, AName + ' hash');
    CheckTrue(LSuite.Prf = AHash, AName + ' prf follows the suite hash');
    CheckEquals(AKeyLength, LSuite.Common.KeyLength, AName + ' key length');
  end;

begin
  LRegistry := TCipherSuiteRegistry.CreateDualVersion(Provider);
  CheckSuite(TCipherSuites12.EcdheEcdsaAes128GcmSha256, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Ecdsa, TAeadAlgorithm.AES_128_GCM, THashAlgorithm.SHA_256, 16,
    'ECDHE-ECDSA-AES128-GCM');
  CheckSuite(TCipherSuites12.EcdheEcdsaAes256GcmSha384, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Ecdsa, TAeadAlgorithm.AES_256_GCM, THashAlgorithm.SHA_384, 32,
    'ECDHE-ECDSA-AES256-GCM');
  CheckSuite(TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256,
    TKeyExchangeMethod.Ecdhe, TAuthMethod.Ecdsa, TAeadAlgorithm.CHACHA20_POLY1305,
    THashAlgorithm.SHA_256, 32, 'ECDHE-ECDSA-ChaCha20');
  CheckSuite(TCipherSuites12.EcdheRsaAes128GcmSha256, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Rsa, TAeadAlgorithm.AES_128_GCM, THashAlgorithm.SHA_256, 16,
    'ECDHE-RSA-AES128-GCM');
  CheckSuite(TCipherSuites12.EcdheRsaAes256GcmSha384, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Rsa, TAeadAlgorithm.AES_256_GCM, THashAlgorithm.SHA_384, 32,
    'ECDHE-RSA-AES256-GCM');
  CheckSuite(TCipherSuites12.EcdheRsaChaCha20Poly1305Sha256,
    TKeyExchangeMethod.Ecdhe, TAuthMethod.Rsa, TAeadAlgorithm.CHACHA20_POLY1305,
    THashAlgorithm.SHA_256, 32, 'ECDHE-RSA-ChaCha20');
end;

procedure TTestNegotiation.TestDualVersionRegistryKeepsTls13SuitesDecoupled;
var
  LRegistry: ICipherSuiteRegistry;
  LSuite: TTlsCipherSuite;
begin
  // the 1.3 mandatory suite stays present and stays decoupled from KX/auth
  LRegistry := TCipherSuiteRegistry.CreateDualVersion(Provider);
  CheckTrue(LRegistry.TryGet(TCipherSuites13.Aes128GcmSha256, LSuite),
    'the 1.3 mandatory suite is still present');
  CheckTrue(LSuite.Protocol = TSuiteProtocol.Tls13, 'it is a 1.3 suite');
  CheckTrue(LSuite.KeyExchange = TKeyExchangeMethod.Decoupled,
    '1.3 decouples key exchange from the cipher');
  CheckTrue(LSuite.Auth = TAuthMethod.Decoupled,
    '1.3 decouples authentication from the cipher');
end;

procedure TTestNegotiation.TestTls12GroupSelectionExcludesHybrid;
var
  LPolicy: INegotiationPolicy;
  LGroups: INamedGroupRegistry;
  LGroup: INamedGroup;
  LSelected: UInt16;
begin
  // the server prefers the post-quantum hybrid first, but a 1.2 negotiation must skip
  // every KEM/hybrid group and fall through to a classical ECDHE group
  LGroups := TNamedGroups.CreateDefaultRegistry(Provider);
  LPolicy := TNegotiationPolicy.Create(Provider,
    TCipherSuiteRegistry.CreateDualVersion(Provider), LGroups,
    TSignatureSchemeRegistry.CreateDefault,
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.Secp256r1),
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12), TServerCipherPreference.ServerOrder);
  LSelected := LPolicy.SelectGroup(TArray<UInt16>.Create(
    TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.Secp256r1), TlsWireVersionTls12);
  CheckTrue(LSelected <> TNamedGroupCatalog.X25519MlKem768,
    'a 1.2 handshake never selects the post-quantum hybrid group');
  CheckTrue(LGroups.TryGet(LSelected, LGroup) and (LGroup.Kind = TNamedGroupKind.Ecdhe),
    'a 1.2 handshake selects a classical ECDHE group');
end;

procedure TTestNegotiation.TestTls12CipherSelectionExcludesTls13Suite;
var
  LPolicy: INegotiationPolicy;
  LCiphers: ICipherSuiteRegistry;
  LSuite: TTlsCipherSuite;
  LSelected: UInt16;
begin
  // the client offers a TLS 1.3 suite and a hardened TLS 1.2 suite; a 1.2 negotiation
  // must only ever land on the 1.2 suite
  LCiphers := TCipherSuiteRegistry.CreateDualVersion(Provider);
  LPolicy := TNegotiationPolicy.Create(Provider, LCiphers,
    TNamedGroups.CreateDefaultRegistry(Provider),
    TSignatureSchemeRegistry.CreateDefault,
    TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1),
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12), TServerCipherPreference.ServerOrder);
  LSelected := LPolicy.SelectCipherSuite(TArray<UInt16>.Create(
    TCipherSuites13.Aes128GcmSha256, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    TlsWireVersionTls12);
  CheckTrue(LSelected <> TCipherSuites13.Aes128GcmSha256,
    'a 1.2 handshake never selects a TLS 1.3 cipher suite');
  CheckTrue(LCiphers.TryGet(LSelected, LSuite) and
    (LSuite.Protocol = TSuiteProtocol.Tls12),
    'a 1.2 handshake selects a hardened TLS 1.2 suite');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestNegotiation);
{$ELSE}
  RegisterTest(TTestNegotiation.Suite);
{$ENDIF FPC}

end.
