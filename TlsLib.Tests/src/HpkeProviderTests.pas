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
  MockCryptoProvider,
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
    function X25519Suite: IHpkeSuite;
    function P256Suite: IHpkeSuite;
    function OpenRaised(const AOpener: IHpkeOpener;
      const AAad, ACiphertext: TBytes): Boolean;
    // ADer with ADeleteLen bytes at AIndex replaced by AInsert
    function Spliced(const ADer: TBytes; AIndex, ADeleteLen: Int32;
      const AInsert: TBytes): TBytes;
    function ImportRaises(AKem: UInt16; const APkcs8: TBytes): Boolean;
    function P256Pkcs8: TBytes;
    function X25519Pkcs8: TBytes;
    procedure CheckKat(const ASuite: IHpkeSuite; const APrefix: string);
  protected
    procedure SetUp; override;
  published
    procedure TestBaseModeKatOpenSeq0;
    procedure TestBaseModeKatOpenSeq1AdvancesSequence;
    // RFC 9180 Appendix A.3/A.4/A.5/A.6 opener KATs: P-256 and P-521 KEMs across HKDF-SHA256/512
    // and AES-128/256-GCM / ChaCha20-Poly1305, so a wrong curve/hash/AEAD constant fails locally
    procedure TestBaseModeKatA3P256Sha256Aes128;
    procedure TestBaseModeKatA4P256Sha512Aes128;
    procedure TestBaseModeKatA5P256Sha256ChaCha20;
    procedure TestBaseModeKatA6P521Sha512Aes256;
    procedure TestFreshOpenerCannotOpenSeq1Ciphertext;
    procedure TestFailedOpenDoesNotAdvanceSequence;
    procedure TestSealOpenRoundTrip;
    procedure TestAsymmetricSuiteRoundTrip;
    procedure TestSealerOpenerAdvanceInLockstep;
    procedure TestImportedX25519KeyRoundTrips;
    procedure TestImportedP256KeyRoundTrips;
    procedure TestSuiteSupported;
    procedure TestGenerateKeyPairUnsupportedKemRaises;
    procedure TestImportMismatchedAlgorithmRaises;
    // every nested TLV of the PKCS#8 walker stays inside its parent, the outer ends at the buffer's
    // end, and the versions are checked
    procedure TestImportPrivateKeyRejectsTrailingBytes;
    procedure TestImportPrivateKeyRejectsTruncatedInput;
    procedure TestImportPrivateKeyRejectsPkcs8VersionAboveOne;
    procedure TestImportPrivateKeyAcceptsPkcs8VersionOne;
    procedure TestImportPrivateKeyRejectsEcPrivateKeyVersionTwo;
    procedure TestImportPrivateKeyRejectsEcPrivateKeyVersionZero;
    procedure TestImportPrivateKeyRejectsEcScalarOverrunningItsSequence;
    procedure TestImportPrivateKeyRejectsX25519ScalarOverrunningItsOctetString;
    procedure TestImportPrivateKeyRejectsX25519SlackInsideItsOctetString;
    procedure TestImportPrivateKeyRejectsEcSlackInsideItsOctetString;
    procedure TestImportPrivateKeyAcceptsEcParametersAndPublicKey;
    procedure TestImportPrivateKeyRejectsX25519AlgorithmParameters;
    procedure TestImportPrivateKeyRejectsEcAlgorithmTrailingElement;
    // an authentication failure and a malformed enc are told apart by their messages
    procedure TestOpenAuthFailureNamesAuthentication;
    procedure TestMalformedEncKeepsItsOwnMessage;
    // an out-of-range or wrong-length EC scalar is rejected at import
    procedure TestImportRecipientKeyRejectsZeroScalar;
    procedure TestImportRecipientKeyRejectsScalarAtOrAboveOrder;
    procedure TestImportRecipientKeyRejectsWrongLengthScalar;
    // a suite the provider's primitives cannot build is reported as nil, not a live suite
    procedure TestSuiteIsNilWhenAeadUnavailable;
    procedure TestOpenerRefusesUnknownKdfOrAead;
    procedure TestKemCodesNameTheirKeyAgreement;
    procedure TestKemCodesWithoutAKeyAgreementAreRefused;
    procedure TestAeadCodesNameTheirAlgorithm;
    procedure TestAeadCodesWithoutAnAlgorithmAreRefused;
  end;

implementation

type
  // a suite that reports the real suite's KEM but a caller-chosen KDF and AEAD
  TForeignIdsSuite = class(TInterfacedObject, IHpkeSuite)
  strict private
    FBase: IHpkeSuite;
    FKdf: UInt16;
    FAead: UInt16;
  public
    constructor Create(const ABase: IHpkeSuite; AKdf, AAead: UInt16);
    function Kem: UInt16;
    function Kdf: UInt16;
    function Aead: UInt16;
    function AeadTagLength: Int32;
    procedure SetupSealer(const ARecipientPublicKey, AInfo: TBytes;
      out AEnc: TBytes; out ASealer: IHpkeSealer);
  end;

constructor TForeignIdsSuite.Create(const ABase: IHpkeSuite; AKdf, AAead: UInt16);
begin
  inherited Create;
  FBase := ABase;
  FKdf := AKdf;
  FAead := AAead;
end;

function TForeignIdsSuite.Kem: UInt16;
begin
  Result := FBase.Kem;
end;

function TForeignIdsSuite.Kdf: UInt16;
begin
  Result := FKdf;
end;

function TForeignIdsSuite.Aead: UInt16;
begin
  Result := FAead;
end;

function TForeignIdsSuite.AeadTagLength: Int32;
begin
  Result := FBase.AeadTagLength;
end;

procedure TForeignIdsSuite.SetupSealer(const ARecipientPublicKey, AInfo: TBytes;
  out AEnc: TBytes; out ASealer: IHpkeSealer);
begin
  FBase.SetupSealer(ARecipientPublicKey, AInfo, AEnc, ASealer);
end;

{ TTestHpkeProvider }

procedure TTestHpkeProvider.SetUp;
begin
  inherited SetUp;
  FVec := Own<TStringList>(LoadVectorFields('Crypto/Hpke.txt'));
end;

function TTestHpkeProvider.V(const AName: string): TBytes;
begin
  Result := DecodeHex(FVec.Values[AName]);
end;

function TTestHpkeProvider.X25519Suite: IHpkeSuite;
begin
  Result := Crypto.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM);
end;

function TTestHpkeProvider.P256Suite: IHpkeSuite;
begin
  Result := Crypto.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256,
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

function TTestHpkeProvider.Spliced(const ADer: TBytes; AIndex, ADeleteLen: Int32;
  const AInsert: TBytes): TBytes;
begin
  Result := ConcatBytes(ConcatBytes(System.Copy(ADer, 0, AIndex), AInsert),
    System.Copy(ADer, AIndex + ADeleteLen, System.Length(ADer) - AIndex - ADeleteLen));
end;

function TTestHpkeProvider.ImportRaises(AKem: UInt16; const APkcs8: TBytes): Boolean;
begin
  Result := False;
  try
    Crypto.Hpke.ImportPrivateKey(AKem, APkcs8);
  except
    on E: EArgumentTlsLibException do
      Result := True;
  end;
end;

function TTestHpkeProvider.P256Pkcs8: TBytes;
begin
  Result := V('import_p256_pkcs8');
  // the layout the byte-level cases below rely on: PKCS#8 version at 5, AlgorithmIdentifier
  // SEQUENCE at 6 (content to 26), ECPrivateKey SEQUENCE at 29, its version at 33
  CheckEquals(Int64($30), Int64(Result[6]), 'fixture: AlgorithmIdentifier SEQUENCE at 6');
  CheckEquals(Int64($13), Int64(Result[7]), 'fixture: AlgorithmIdentifier length');
  CheckEquals(Int64($30), Int64(Result[29]), 'fixture: ECPrivateKey SEQUENCE at 29');
  CheckEquals(Int64(1), Int64(Result[33]), 'fixture: ECPrivateKey version at 33');
end;

function TTestHpkeProvider.X25519Pkcs8: TBytes;
begin
  Result := V('import_x25519_pkcs8');
  // PKCS#8 version at 4, AlgorithmIdentifier SEQUENCE at 5 (content to 11), privateKey OCTET
  // STRING at 12 holding the CurvePrivateKey OCTET STRING at 14
  CheckEquals(Int64($30), Int64(Result[5]), 'fixture: AlgorithmIdentifier SEQUENCE at 5');
  CheckEquals(Int64($22), Int64(Result[13]), 'fixture: privateKey OCTET STRING length');
  CheckEquals(Int64($04), Int64(Result[14]), 'fixture: CurvePrivateKey OCTET STRING at 14');
end;

procedure TTestHpkeProvider.TestBaseModeKatOpenSeq0;
var
  LSkR: ISecretBuffer;
  LOpener: IHpkeOpener;
begin
  // RFC 9180 A.1: opening the seq=0 ciphertext yields the known plaintext
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
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
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
    .SetupOpener(X25519Suite, V('base_enc'), V('base_info'));
  CheckEqualBytes('seq 0 plaintext', V('base_pt'),
    LOpener.Open(V('base_aad0'), V('base_ct0')));
  CheckEqualBytes('seq 1 plaintext', V('base_pt'),
    LOpener.Open(V('base_aad1'), V('base_ct1')));
end;

procedure TTestHpkeProvider.CheckKat(const ASuite: IHpkeSuite;
  const APrefix: string);
var
  LOpener: IHpkeOpener;
begin
  // open the seq=0 KAT ciphertext and check it yields the RFC 9180 plaintext (shared across the
  // appendix vectors); a wrong KEM/KDF/AEAD constant derives a different key and fails here
  CheckTrue(ASuite <> nil, APrefix + ': suite is supported');
  LOpener := Crypto.Hpke.ImportRecipientKey(ASuite.Kem,
    TSecretBuffer.From(V(APrefix + '_skRm')))
    .SetupOpener(ASuite, V(APrefix + '_enc'), V(APrefix + '_info'));
  CheckEqualBytes(APrefix + ': seq 0 plaintext', V('base_pt'),
    LOpener.Open(V(APrefix + '_aad0'), V(APrefix + '_ct0')));
end;

procedure TTestHpkeProvider.TestBaseModeKatA3P256Sha256Aes128;
begin
  CheckKat(Crypto.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'a3');
end;

procedure TTestHpkeProvider.TestBaseModeKatA4P256Sha512Aes128;
begin
  CheckKat(Crypto.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256,
    THpkeKdf.HKDF_SHA512, THpkeAead.AES_128_GCM), 'a4');
end;

procedure TTestHpkeProvider.TestBaseModeKatA5P256Sha256ChaCha20;
begin
  CheckKat(Crypto.Hpke.Suite(THpkeKem.DHKEM_P256_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.CHACHA20_POLY1305), 'a5');
end;

procedure TTestHpkeProvider.TestBaseModeKatA6P521Sha512Aes256;
begin
  CheckKat(Crypto.Hpke.Suite(THpkeKem.DHKEM_P521_HKDF_SHA512,
    THpkeKdf.HKDF_SHA512, THpkeAead.AES_256_GCM), 'a6');
end;

procedure TTestHpkeProvider.TestFreshOpenerCannotOpenSeq1Ciphertext;
var
  LSkR: ISecretBuffer;
  LOpener: IHpkeOpener;
begin
  // a fresh opener is at seq=0; the seq=1 ciphertext must not open against it,
  // confirming the sequence number really participates in the nonce
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
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
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
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
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPk, LSk);
  LAad := TBytes.Create(1, 2, 3, 4);
  LPt := TBytes.Create(10, 20, 30, 40, 50);
  X25519Suite.SetupSealer(LPk, V('base_info'), LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSk)
    .SetupOpener(X25519Suite, LEnc, V('base_info'));
  CheckEqualBytes('round-trip plaintext', LPt, LOpener.Open(LAad, LCt));
end;

procedure TTestHpkeProvider.TestAsymmetricSuiteRoundTrip;
var
  LSuite: IHpkeSuite;
  LPk: TBytes;
  LSk: ISecretBuffer;
  LEnc, LAad, LPt, LCt: TBytes;
  LSealer: IHpkeSealer;
  LOpener: IHpkeOpener;
begin
  // KDF and AEAD codepoints overlap numerically (both 1/2/3), so the default suite
  // (kdf=aead=1) cannot catch a kdf<->aead transposition. Use HKDF-SHA384 (2) with
  // ChaCha20-Poly1305 (3): a swap would pick a different, wrong suite and fail here.
  LSuite := Crypto.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA384, THpkeAead.CHACHA20_POLY1305);
  CheckTrue(LSuite <> nil, 'the asymmetric suite is supported');
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPk, LSk);
  LAad := TBytes.Create(7, 7, 7);
  LPt := TBytes.Create(70, 71, 72, 73, 74);
  LSuite.SetupSealer(LPk, V('base_info'), LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Crypto.Hpke.ImportRecipientKey(LSuite.Kem, LSk)
    .SetupOpener(LSuite, LEnc, V('base_info'));
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
  Crypto.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256, LPk, LSk);
  LM0 := TBytes.Create(1, 1, 1);
  LM1 := TBytes.Create(2, 2, 2, 2);
  X25519Suite.SetupSealer(LPk, V('base_info'), LEnc, LSealer);
  LCt0 := LSealer.Seal(nil, LM0);
  LCt1 := LSealer.Seal(nil, LM1);
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSk)
    .SetupOpener(X25519Suite, LEnc, V('base_info'));
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
  LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    V('import_x25519_pkcs8'));
  LAad := TBytes.Create(9, 8, 7);
  LPt := TBytes.Create(11, 22, 33, 44);
  X25519Suite.SetupSealer(V('import_x25519_pub'), V('base_info'), LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSk)
    .SetupOpener(X25519Suite, LEnc, V('base_info'));
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
  LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_P256_HKDF_SHA256,
    V('import_p256_pkcs8'));
  LAad := TBytes.Create(5, 5);
  LPt := TBytes.Create(60, 61, 62, 63, 64, 65);
  P256Suite.SetupSealer(V('import_p256_pub'), V('base_info'), LEnc, LSealer);
  LCt := LSealer.Seal(LAad, LPt);
  LOpener := Crypto.Hpke.ImportRecipientKey(P256Suite.Kem, LSk)
    .SetupOpener(P256Suite, LEnc, V('base_info'));
  CheckEqualBytes('imported P-256 round-trip', LPt, LOpener.Open(LAad, LCt));
end;

procedure TTestHpkeProvider.TestSuiteSupported;
begin
  // Suite returns a handle for a suite the provider can instantiate, nil otherwise -
  // so a nil is how an unusable suite (export-only, unknown KEM/KDF) is rejected: the
  // caller never obtains a handle to seal or open with
  CheckTrue(X25519Suite <> nil, 'X25519/HKDF-SHA256/AES-128-GCM is supported');
  CheckTrue(P256Suite <> nil, 'P-256/HKDF-SHA256/AES-128-GCM is supported');
  CheckTrue(Crypto.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.CHACHA20_POLY1305) <> nil,
    'ChaCha20-Poly1305 is a supported AEAD');
  CheckTrue(Crypto.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.EXPORT_ONLY) = nil,
    'export-only cannot seal/open');
  CheckTrue(Crypto.Hpke.Suite(UInt16($0009), THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM) = nil, 'an unknown KEM is unsupported');
  CheckTrue(Crypto.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256, UInt16($00FF),
    THpkeAead.AES_128_GCM) = nil, 'an unknown KDF is unsupported');
end;

procedure TTestHpkeProvider.TestGenerateKeyPairUnsupportedKemRaises;
var
  LPk: TBytes;
  LSk: ISecretBuffer;
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Crypto.Hpke.GenerateKeyPair(UInt16($0009), LPk, LSk);
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
    Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_P256_HKDF_SHA256,
      V('import_x25519_pkcs8'));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a key whose algorithm does not match the KEM must be rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsTrailingBytes;
var
  LDer: TBytes;
begin
  LDer := P256Pkcs8;
  CheckFalse(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256, LDer), 'control: the key imports');
  CheckTrue(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256,
    Spliced(LDer, System.Length(LDer), 0, TBytes.Create(0))),
    'a byte after the outer SEQUENCE is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsTruncatedInput;
var
  LDer: TBytes;
begin
  LDer := P256Pkcs8;
  CheckTrue(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256,
    Spliced(LDer, System.Length(LDer) - 1, 1, nil)), 'a key one byte short is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsPkcs8VersionAboveOne;
var
  LDer: TBytes;
begin
  LDer := X25519Pkcs8;
  CheckEquals(Int64(0), Int64(LDer[4]), 'fixture: PKCS#8 version 0');
  CheckTrue(ImportRaises(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    Spliced(LDer, 4, 1, TBytes.Create(2))), 'PKCS#8 version 2 is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyAcceptsPkcs8VersionOne;
var
  LDer: TBytes;
begin
  // RFC 5958 2: version 1 is a OneAsymmetricKey, still a valid PrivateKeyInfo
  LDer := X25519Pkcs8;
  CheckFalse(ImportRaises(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    Spliced(LDer, 4, 1, TBytes.Create(1))), 'PKCS#8 version 1 is accepted');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsEcPrivateKeyVersionTwo;
begin
  CheckTrue(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256,
    Spliced(P256Pkcs8, 33, 1, TBytes.Create(2))), 'ECPrivateKey version 2 is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsEcPrivateKeyVersionZero;
begin
  CheckTrue(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256,
    Spliced(P256Pkcs8, 33, 1, TBytes.Create(0))), 'ECPrivateKey version 0 is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsEcScalarOverrunningItsSequence;
var
  LDer: TBytes;
begin
  // the ECPrivateKey SEQUENCE (length at 30) is shortened by one so its privateKey OCTET STRING,
  // 3 + 34 bytes in, ends a byte past it while still inside the enclosing OCTET STRING
  LDer := P256Pkcs8;
  CheckEquals(Int64($6B), Int64(LDer[30]), 'fixture: ECPrivateKey length');
  CheckTrue(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256,
    Spliced(LDer, 30, 1, TBytes.Create(36))), 'a scalar that overruns its SEQUENCE is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsX25519ScalarOverrunningItsOctetString;
var
  LDer: TBytes;
begin
  // the privateKey OCTET STRING (length at 13) is shortened by one so the CurvePrivateKey inside
  // it ends a byte past it while still inside the outer SEQUENCE
  LDer := X25519Pkcs8;
  CheckTrue(ImportRaises(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    Spliced(LDer, 13, 1, TBytes.Create($21))), 'a scalar that overruns its OCTET STRING is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsX25519SlackInsideItsOctetString;
var
  LDer: TBytes;
begin
  // one extra byte inside the privateKey OCTET STRING after the CurvePrivateKey (outer SEQUENCE
  // and OCTET STRING lengths grown to cover it)
  LDer := Spliced(Spliced(Spliced(X25519Pkcs8, 13, 1, TBytes.Create($23)), 1, 1,
    TBytes.Create($2F)), 48, 0, TBytes.Create(0));
  CheckTrue(ImportRaises(THpkeKem.DHKEM_X25519_HKDF_SHA256, LDer),
    'a byte after the CurvePrivateKey inside its OCTET STRING is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsEcSlackInsideItsOctetString;
var
  LDer: TBytes;
begin
  // one extra byte after the ECPrivateKey inside the privateKey OCTET STRING (outer SEQUENCE and
  // OCTET STRING lengths grown to cover it)
  LDer := Spliced(Spliced(Spliced(P256Pkcs8, 28, 1, TBytes.Create($6E)), 2, 1,
    TBytes.Create($88)), System.Length(P256Pkcs8), 0, TBytes.Create(0));
  CheckTrue(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256, LDer),
    'a byte after the ECPrivateKey inside its OCTET STRING is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyAcceptsEcParametersAndPublicKey;
var
  LDer: TBytes;
begin
  // the fixture already carries the [1] publicKey; add the optional [0] parameters inside the
  // ECPrivateKey (RFC 5915 3), growing its three enclosing lengths by 12
  LDer := Spliced(Spliced(Spliced(Spliced(P256Pkcs8, 68, 0,
    TBytes.Create($A0, $0A, $06, $08, $2A, $86, $48, $CE, $3D, $03, $01, $07)),
    30, 1, TBytes.Create($77)), 28, 1, TBytes.Create($79)), 2, 1, TBytes.Create($93));
  CheckFalse(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256, LDer),
    'optional [0] parameters and [1] publicKey inside the ECPrivateKey are accepted');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsX25519AlgorithmParameters;
var
  LDer: TBytes;
begin
  // RFC 8410 3: the X25519 AlgorithmIdentifier carries no parameters; a NULL is added after the
  // OID (AlgorithmIdentifier length 5 -> 7, outer 0x2E -> 0x30)
  LDer := Spliced(Spliced(Spliced(X25519Pkcs8, 12, 0, TBytes.Create(5, 0)), 6, 1,
    TBytes.Create(7)), 1, 1, TBytes.Create($30));
  CheckTrue(ImportRaises(THpkeKem.DHKEM_X25519_HKDF_SHA256, LDer),
    'a parameter inside the X25519 AlgorithmIdentifier is rejected');
end;

procedure TTestHpkeProvider.TestImportPrivateKeyRejectsEcAlgorithmTrailingElement;
var
  LDer: TBytes;
begin
  // a NULL after the namedCurve OID (AlgorithmIdentifier length 0x13 -> 0x15, outer 0x87 -> 0x89)
  LDer := Spliced(Spliced(Spliced(P256Pkcs8, 27, 0, TBytes.Create(5, 0)), 7, 1,
    TBytes.Create($15)), 2, 1, TBytes.Create($89));
  CheckTrue(ImportRaises(THpkeKem.DHKEM_P256_HKDF_SHA256, LDer),
    'an element after the namedCurve inside the AlgorithmIdentifier is rejected');
end;

procedure TTestHpkeProvider.TestOpenAuthFailureNamesAuthentication;
var
  LSkR: ISecretBuffer;
  LOpener: IHpkeOpener;
  LTampered: TBytes;
  LMsg: string;
begin
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LOpener := Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
    .SetupOpener(X25519Suite, V('base_enc'), V('base_info'));
  LTampered := V('base_ct0');
  LTampered[0] := LTampered[0] xor $FF;
  LMsg := '';
  try
    LOpener.Open(V('base_aad0'), LTampered);
  except
    on E: EHpkeOpenTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('authentication', LMsg) > 0,
    'a tag failure is reported as an authentication failure; got: ' + LMsg);
end;

procedure TTestHpkeProvider.TestMalformedEncKeepsItsOwnMessage;
var
  LSkR: ISecretBuffer;
  LMsg: string;
begin
  LSkR := TSecretBuffer.From(V('base_skRm'));
  LMsg := '';
  try
    Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, LSkR)
      .SetupOpener(X25519Suite, TBytes.Create(1, 2, 3), V('base_info'));
  except
    on E: EHpkeOpenTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('encapsulated key', LMsg) > 0,
    'a malformed enc is still reported as one; got: ' + LMsg);
end;

procedure TTestHpkeProvider.TestImportRecipientKeyRejectsZeroScalar;
var
  LRaised: Boolean;
  LZero: TBytes;
begin
  // a P-256 scalar of 0 is outside [1, n-1]; import must reject it, not reduce it mod n
  LZero := nil;
  SetLength(LZero, 32); // all-zero
  LRaised := False;
  try
    Crypto.Hpke.ImportRecipientKey(THpkeKem.DHKEM_P256_HKDF_SHA256,
      TSecretBuffer.From(LZero));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a zero EC scalar is rejected');
end;

procedure TTestHpkeProvider.TestImportRecipientKeyRejectsScalarAtOrAboveOrder;
var
  LRaised: Boolean;
  LHigh: TBytes;
  LI: Int32;
begin
  // 32 bytes of 0xFF exceeds the P-256 group order n, so it is outside [1, n-1]
  LHigh := nil;
  SetLength(LHigh, 32);
  for LI := 0 to 31 do
    LHigh[LI] := $FF;
  LRaised := False;
  try
    Crypto.Hpke.ImportRecipientKey(THpkeKem.DHKEM_P256_HKDF_SHA256,
      TSecretBuffer.From(LHigh));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an EC scalar at or above the group order is rejected');
end;

procedure TTestHpkeProvider.TestImportRecipientKeyRejectsWrongLengthScalar;
var
  LRaised: Boolean;
  LShort: TBytes;
begin
  // a P-256 scalar must be exactly the 32-byte field width
  LShort := nil;
  SetLength(LShort, 31);
  LShort[30] := 1;
  LRaised := False;
  try
    Crypto.Hpke.ImportRecipientKey(THpkeKem.DHKEM_P256_HKDF_SHA256,
      TSecretBuffer.From(LShort));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a wrong-length EC scalar is rejected');
end;

procedure TTestHpkeProvider.TestOpenerRefusesUnknownKdfOrAead;

  function Refused(AKdf, AAead: UInt16): Boolean;
  begin
    Result := False;
    try
      Crypto.Hpke.ImportRecipientKey(X25519Suite.Kem, TSecretBuffer.From(V('base_skRm')))
        .SetupOpener(TForeignIdsSuite.Create(X25519Suite, AKdf, AAead) as IHpkeSuite,
        V('base_enc'), V('base_info'));
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  // an id the composition does not implement is refused up front, not mapped to a default algorithm
  CheckTrue(Refused($FFF0, THpkeAead.AES_128_GCM), 'an unknown KDF');
  CheckTrue(Refused(THpkeKdf.HKDF_SHA256, $FFF0), 'an unknown AEAD');
  CheckFalse(Refused(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'control: the real ids open');
end;

procedure TTestHpkeProvider.TestSuiteIsNilWhenAeadUnavailable;
var
  LCrypto: ICryptoProvider;
begin
  // a provider whose primitives cannot build ChaCha20-Poly1305 must report a ChaCha suite as nil
  // (so an ECH offer for it becomes a clean reject), while an AES-GCM suite stays usable
  LCrypto := TMissingAeadProvider.Create(Crypto,
    TAeadAlgorithm.CHACHA20_POLY1305) as ICryptoProvider;
  CheckTrue(LCrypto.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.CHACHA20_POLY1305) = nil,
    'a suite needing the unavailable AEAD is nil');
  CheckTrue(LCrypto.Hpke.Suite(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM) <> nil,
    'a suite whose primitives are all available stays usable');
end;

procedure TTestHpkeProvider.TestKemCodesNameTheirKeyAgreement;
var
  LAlgorithm: TKeyAgreementAlgorithm;
begin
  CheckTrue(THpkeKem.TryKeyAgreement(THpkeKem.DHKEM_P256_HKDF_SHA256, LAlgorithm), 'P-256');
  CheckTrue(LAlgorithm = TKeyAgreementAlgorithm.SECP256R1, 'P-256 agreement');
  CheckTrue(THpkeKem.TryKeyAgreement(THpkeKem.DHKEM_P384_HKDF_SHA384, LAlgorithm), 'P-384');
  CheckTrue(LAlgorithm = TKeyAgreementAlgorithm.SECP384R1, 'P-384 agreement');
  CheckTrue(THpkeKem.TryKeyAgreement(THpkeKem.DHKEM_P521_HKDF_SHA512, LAlgorithm), 'P-521');
  CheckTrue(LAlgorithm = TKeyAgreementAlgorithm.SECP521R1, 'P-521 agreement');
  CheckTrue(THpkeKem.TryKeyAgreement(THpkeKem.DHKEM_X25519_HKDF_SHA256, LAlgorithm), 'X25519');
  CheckTrue(LAlgorithm = TKeyAgreementAlgorithm.X25519, 'X25519 agreement');
end;

procedure TTestHpkeProvider.TestKemCodesWithoutAKeyAgreementAreRefused;
var
  LAlgorithm: TKeyAgreementAlgorithm;
begin
  CheckFalse(THpkeKem.TryKeyAgreement(THpkeKem.DHKEM_X448_HKDF_SHA512, LAlgorithm),
    'X448 has no agreement here');
  CheckFalse(THpkeKem.TryKeyAgreement(0, LAlgorithm), 'code zero');
  CheckFalse(THpkeKem.TryKeyAgreement($FFFF, LAlgorithm), 'a code outside the registry');
end;

procedure TTestHpkeProvider.TestAeadCodesNameTheirAlgorithm;
var
  LAlgorithm: TAeadAlgorithm;
begin
  CheckTrue(THpkeAead.TryAlgorithm(THpkeAead.AES_128_GCM, LAlgorithm), 'AES-128-GCM');
  CheckTrue(LAlgorithm = TAeadAlgorithm.AES_128_GCM, 'AES-128-GCM algorithm');
  CheckTrue(THpkeAead.TryAlgorithm(THpkeAead.AES_256_GCM, LAlgorithm), 'AES-256-GCM');
  CheckTrue(LAlgorithm = TAeadAlgorithm.AES_256_GCM, 'AES-256-GCM algorithm');
  CheckTrue(THpkeAead.TryAlgorithm(THpkeAead.CHACHA20_POLY1305, LAlgorithm), 'ChaCha20');
  CheckTrue(LAlgorithm = TAeadAlgorithm.CHACHA20_POLY1305, 'ChaCha20 algorithm');
end;

procedure TTestHpkeProvider.TestAeadCodesWithoutAnAlgorithmAreRefused;
var
  LAlgorithm: TAeadAlgorithm;
begin
  CheckFalse(THpkeAead.TryAlgorithm(THpkeAead.EXPORT_ONLY, LAlgorithm),
    'export-only seals nothing');
  CheckFalse(THpkeAead.TryAlgorithm(0, LAlgorithm), 'code zero');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHpkeProvider);
{$ELSE}
  RegisterTest(TTestHpkeProvider.Suite);
{$ENDIF FPC}

end.
