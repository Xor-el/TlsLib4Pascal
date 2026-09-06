{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HpkeProviderTests;

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
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpTlsLibExceptions,
  TlsLibTestBase;

type
  /// <summary>
  /// The HPKE provider facet (RFC 9180 base mode) reached only through
  /// ICryptoProvider.Hpke - the seam Encrypted Client Hello builds on. Drives the
  /// RFC 9180 Appendix A.1 opener KAT (including the seq=1 advance the HRR path
  /// relies on), the seal/open and sealer/opener round-trips, the PKCS#8 import path,
  /// and the suite-support / error contracts.
  /// </summary>
  TTestHpkeProvider = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function V(const AName: string): TBytes;
    function X25519Suite: THpkeSuite;
    function P256Suite: THpkeSuite;
    function OpenRaised(const AOpener: IHpkeOpener;
      const AAad, ACiphertext: TBytes): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBaseModeKatOpenSeq0;
    procedure TestBaseModeKatOpenSeq1AdvancesSequence;
    procedure TestFreshOpenerCannotOpenSeq1Ciphertext;
    procedure TestFailedOpenDoesNotAdvanceSequence;
    procedure TestSealOpenRoundTrip;
    procedure TestAsymmetricSuiteRoundTrip;
    procedure TestSealerOpenerAdvanceInLockstep;
    procedure TestImportedX25519KeyRoundTrips;
    procedure TestImportedP256KeyRoundTrips;
    procedure TestSuiteSupported;
    procedure TestUnsupportedSuiteSetupRaises;
    procedure TestGenerateKeyPairUnsupportedKemRaises;
    procedure TestImportMismatchedAlgorithmRaises;
  end;

implementation

{ TTestHpkeProvider }

procedure TTestHpkeProvider.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Crypto/Hpke.txt');
end;

procedure TTestHpkeProvider.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestHpkeProvider.V(const AName: string): TBytes;
begin
  Result := DecodeHex(FVec.Values[AName]);
end;

function TTestHpkeProvider.X25519Suite: THpkeSuite;
begin
  Result := THpkeSuite.Create(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM);
end;

function TTestHpkeProvider.P256Suite: THpkeSuite;
begin
  Result := THpkeSuite.Create(THpkeKem.DHKEM_P256_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM);
end;

function TTestHpkeProvider.OpenRaised(const AOpener: IHpkeOpener;
  const AAad, ACiphertext: TBytes): Boolean;
begin
  Result := False;
  try
    AOpener.Open(AAad, ACiphertext);
  except
    on E: EHpkeOpenTlsLibException do
      Result := True;
  end;
end;

procedure TTestHpkeProvider.TestBaseModeKatOpenSeq0;
var
  LSkR: ISecretBuffer;
  LOpener: IHpkeOpener;
begin
  // RFC 9180 A.1: opening the seq=0 ciphertext yields the known plaintext
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LOpener := Provider.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
    .SetupOpener(X25519Suite, V('base_enc'), V('base_info'));
  CheckEqualBytes('seq 0 plaintext', V('base_pt'),
    LOpener.Open(V('base_aad0'), V('base_ct0')));
end;

procedure TTestHpkeProvider.TestBaseModeKatOpenSeq1AdvancesSequence;
var
  LSkR: ISecretBuffer;
  LOpener: IHpkeOpener;
begin
  // one opener, two messages in order: opening seq=0 advances the sequence number so
  // the second Open runs at seq=1 (the state the HRR second ClientHello reuses)
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LOpener := Provider.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
    .SetupOpener(X25519Suite, V('base_enc'), V('base_info'));
  CheckEqualBytes('seq 0 plaintext', V('base_pt'),
    LOpener.Open(V('base_aad0'), V('base_ct0')));
  CheckEqualBytes('seq 1 plaintext', V('base_pt'),
    LOpener.Open(V('base_aad1'), V('base_ct1')));
end;

procedure TTestHpkeProvider.TestFreshOpenerCannotOpenSeq1Ciphertext;
var
  LSkR: ISecretBuffer;
  LOpener: IHpkeOpener;
begin
  // a fresh opener is at seq=0; the seq=1 ciphertext must not open against it,
  // confirming the sequence number really participates in the nonce
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LOpener := Provider.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
    .SetupOpener(X25519Suite, V('base_enc'), V('base_info'));
  CheckTrue(OpenRaised(LOpener, V('base_aad1'), V('base_ct1')),
    'a seq=0 opener must fail on a seq=1 ciphertext');
end;

procedure TTestHpkeProvider.TestFailedOpenDoesNotAdvanceSequence;
var
  LSkR: ISecretBuffer;
  LOpener: IHpkeOpener;
  LTampered: TBytes;
begin
  // RFC 9180 sec. 5.2: a failed Open must not advance the sequence, so a rejected
  // ciphertext cannot desynchronise the receiver from the sender
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LOpener := Provider.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
    .SetupOpener(X25519Suite, V('base_enc'), V('base_info'));
  LTampered := V('base_ct0');
  LTampered[0] := LTampered[0] xor $FF;
  CheckTrue(OpenRaised(LOpener, V('base_aad0'), LTampered),
    'a tampered ciphertext must fail authentication');
  // still at seq=0: the genuine seq=0 ciphertext opens
  CheckEqualBytes('seq 0 plaintext after a failed open', V('base_pt'),
    LOpener.Open(V('base_aad0'), V('base_ct0')));
end;

procedure TTestHpkeProvider.TestSealOpenRoundTrip;
var
  LPk: TBytes;
  LSk: ISecretBuffer;
  LEnc, LAad, LPt, LCt: TBytes;
  LSealer: IHpkeSealer;
  LOpener: IHpkeOpener;
begin
  Provider.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPk, LSk);
  LAad := TBytes.Create(1, 2, 3, 4);
  LPt := TBytes.Create(10, 20, 30, 40, 50);
  Provider.Hpke.SetupSealer(X25519Suite, LPk, V('base_info'), LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Provider.Hpke.ImportRecipientKey(X25519Suite.Kem, LSk).SetupOpener(X25519Suite, LEnc, V('base_info'));
  CheckEqualBytes('round-trip plaintext', LPt, LOpener.Open(LAad, LCt));
end;

procedure TTestHpkeProvider.TestAsymmetricSuiteRoundTrip;
var
  LSuite: THpkeSuite;
  LPk: TBytes;
  LSk: ISecretBuffer;
  LEnc, LAad, LPt, LCt: TBytes;
  LSealer: IHpkeSealer;
  LOpener: IHpkeOpener;
begin
  // KDF and AEAD codepoints overlap numerically (both 1/2/3), so the default suite
  // (kdf=aead=1) cannot catch a kdf<->aead transposition. Use HKDF-SHA384 (2) with
  // ChaCha20-Poly1305 (3): a swap would pick a different, wrong suite and fail here.
  LSuite := THpkeSuite.Create(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA384, THpkeAead.CHACHA20_POLY1305);
  CheckTrue(Provider.Hpke.SuiteSupported(LSuite), 'the asymmetric suite is supported');
  Provider.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPk, LSk);
  LAad := TBytes.Create(7, 7, 7);
  LPt := TBytes.Create(70, 71, 72, 73, 74);
  Provider.Hpke.SetupSealer(LSuite, LPk, V('base_info'), LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Provider.Hpke.ImportRecipientKey(LSuite.Kem, LSk).SetupOpener(LSuite, LEnc, V('base_info'));
  CheckEqualBytes('asymmetric-suite round-trip', LPt, LOpener.Open(LAad, LCt));
end;

procedure TTestHpkeProvider.TestSealerOpenerAdvanceInLockstep;
var
  LPk: TBytes;
  LSk: ISecretBuffer;
  LEnc, LM0, LM1, LCt0, LCt1: TBytes;
  LSealer: IHpkeSealer;
  LOpener: IHpkeOpener;
begin
  // two sealed messages open in order: sealer and opener each advance one step
  Provider.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPk, LSk);
  LM0 := TBytes.Create(1, 1, 1);
  LM1 := TBytes.Create(2, 2, 2, 2);
  Provider.Hpke.SetupSealer(X25519Suite, LPk, V('base_info'), LEnc, LSealer);
  LCt0 := LSealer.Seal(nil, LM0);
  LCt1 := LSealer.Seal(nil, LM1);
  LOpener := Provider.Hpke.ImportRecipientKey(X25519Suite.Kem, LSk).SetupOpener(X25519Suite, LEnc, V('base_info'));
  CheckEqualBytes('message 0', LM0, LOpener.Open(nil, LCt0));
  CheckEqualBytes('message 1', LM1, LOpener.Open(nil, LCt1));
end;

procedure TTestHpkeProvider.TestImportedX25519KeyRoundTrips;
var
  LSk: ISecretBuffer;
  LEnc, LAad, LPt, LCt: TBytes;
  LSealer: IHpkeSealer;
  LOpener: IHpkeOpener;
begin
  // the PKCS#8 import path (RFC 8410 X25519): the imported scalar must be the pair of
  // the published public key, so the round-trip only closes if the decode is correct
  LSk := Provider.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    V('import_x25519_pkcs8'));
  LAad := TBytes.Create(9, 8, 7);
  LPt := TBytes.Create(11, 22, 33, 44);
  Provider.Hpke.SetupSealer(X25519Suite, V('import_x25519_pub'), V('base_info'),
    LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Provider.Hpke.ImportRecipientKey(X25519Suite.Kem, LSk).SetupOpener(X25519Suite, LEnc, V('base_info'));
  CheckEqualBytes('imported X25519 round-trip', LPt, LOpener.Open(LAad, LCt));
end;

procedure TTestHpkeProvider.TestImportedP256KeyRoundTrips;
var
  LSk: ISecretBuffer;
  LEnc, LAad, LPt, LCt: TBytes;
  LSealer: IHpkeSealer;
  LOpener: IHpkeOpener;
begin
  // the PKCS#8 import path (RFC 5915 EC) for the P-256 KEM
  LSk := Provider.Hpke.ImportPrivateKey(THpkeKem.DHKEM_P256_HKDF_SHA256,
    V('import_p256_pkcs8'));
  LAad := TBytes.Create(5, 5);
  LPt := TBytes.Create(60, 61, 62, 63, 64, 65);
  Provider.Hpke.SetupSealer(P256Suite, V('import_p256_pub'), V('base_info'),
    LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Provider.Hpke.ImportRecipientKey(P256Suite.Kem, LSk).SetupOpener(P256Suite, LEnc, V('base_info'));
  CheckEqualBytes('imported P-256 round-trip', LPt, LOpener.Open(LAad, LCt));
end;

procedure TTestHpkeProvider.TestSuiteSupported;
begin
  CheckTrue(Provider.Hpke.SuiteSupported(X25519Suite),
    'X25519/HKDF-SHA256/AES-128-GCM is supported');
  CheckTrue(Provider.Hpke.SuiteSupported(P256Suite),
    'P-256/HKDF-SHA256/AES-128-GCM is supported');
  CheckTrue(Provider.Hpke.SuiteSupported(THpkeSuite.Create(
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.CHACHA20_POLY1305)),
    'ChaCha20-Poly1305 is a supported AEAD');
  CheckFalse(Provider.Hpke.SuiteSupported(THpkeSuite.Create(
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.EXPORT_ONLY)),
    'export-only cannot seal/open');
  CheckFalse(Provider.Hpke.SuiteSupported(THpkeSuite.Create(UInt16($0009),
    THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM)),
    'an unknown KEM is unsupported');
  CheckFalse(Provider.Hpke.SuiteSupported(THpkeSuite.Create(
    THpkeKem.DHKEM_X25519_HKDF_SHA256, UInt16($00FF), THpkeAead.AES_128_GCM)),
    'an unknown KDF is unsupported');
end;

procedure TTestHpkeProvider.TestUnsupportedSuiteSetupRaises;
var
  LPk: TBytes;
  LSk: ISecretBuffer;
  LEnc: TBytes;
  LSealer: IHpkeSealer;
  LRaised: Boolean;
begin
  Provider.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPk, LSk);
  LRaised := False;
  try
    Provider.Hpke.SetupSealer(THpkeSuite.Create(
      THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
      THpkeAead.EXPORT_ONLY), LPk, V('base_info'), LEnc, LSealer);
  except
    on E: ENotSupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'setting up an export-only suite must be rejected');
end;

procedure TTestHpkeProvider.TestGenerateKeyPairUnsupportedKemRaises;
var
  LPk: TBytes;
  LSk: ISecretBuffer;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Provider.Hpke.GenerateKeyPair(UInt16($0009), LPk, LSk);
  except
    on E: ENotSupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an unknown KEM must be rejected');
end;

procedure TTestHpkeProvider.TestImportMismatchedAlgorithmRaises;
var
  LRaised: Boolean;
begin
  // an X25519 PKCS#8 imported as a P-256 key must be rejected, not silently reshaped
  LRaised := False;
  try
    Provider.Hpke.ImportPrivateKey(THpkeKem.DHKEM_P256_HKDF_SHA256,
      V('import_x25519_pkcs8'));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a key whose algorithm does not match the KEM must be rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHpkeProvider);
{$ELSE}
  RegisterTest(TTestHpkeProvider.Suite);
{$ENDIF FPC}

end.
