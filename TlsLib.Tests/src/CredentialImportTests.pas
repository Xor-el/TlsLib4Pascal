{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CredentialImportTests;

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
  TlpICryptoProvider,
  TlpSecretBuffer,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes,
  TlpISigningKey,
  TlpTlsCredential,
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  MockRandom,
  MockCryptoProvider,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>Covers the credential import seam: multi-format signing keys import to a
  /// key whose CapableSchemes are correct and whose signatures verify, and PEM/DER
  /// certificate chains load to the right DER; bad input raises typed exceptions.</summary>
  TTestCredentialImport = class(TTlsLibAlgorithmTestCase)
  private
    FV: TStringList;
    // A signing key imported from the named unencrypted vector field.
    function Import(const AField: string): ISigningKey;
    // Imports AKeyField, signs a fixed message with AScheme, and verifies it against
    // the SubjectPublicKeyInfo in APubField. True when the round-trip verifies.
    function RoundTrips(AScheme: TSignatureScheme; const AKey: ISigningKey;
      const APubField: string): Boolean;
    procedure CheckSchemes(const AName: string; const AKey: ISigningKey;
      const AExpected: array of TSignatureScheme);
    // Imports every listed unencrypted field, asserting the same CapableSchemes and a
    // verifying round-trip for each; proves format-independence.
    procedure CheckFormats(AScheme: TSignatureScheme; const APubField: string;
      const AExpected: array of TSignatureScheme; const AFields: array of string);
    // Asserts the public key derived from the private vector APrivField equals the known-good
    // public vector APubField by value (via the inspector's SamePublicKey).
    procedure CheckDerivedPublicKey(const APrivField, APubField: string);
    // The RSA credential of the 2048-bit test chain: its leaf and the key that owns it.
    function RsaLeafCredential: TTlsCredential;
  protected
    procedure SetUp; override;
  published
    procedure TestRsaImportsEveryFormat;
    procedure TestEcP256ImportsEveryFormat;
    procedure TestPkcs8FixturesAreWrappedKeys;
    procedure TestEcP384AndP521Import;
    procedure TestEd25519Imports;
    procedure TestEd448Imports;
    procedure TestEncryptedKeysImportWithPassword;
    procedure TestEncryptedKeyImportsWithUtf8Passphrase;
    // a zero-length passphrase decrypts every armour but the legacy Proc-Type PEM, which says so
    procedure TestEncryptedPkcs8DerImportsWithEmptyPassphrase;
    procedure TestEncryptedPkcs8PemImportsWithEmptyPassphrase;
    procedure TestLegacyEncryptedPemImportsWithItsPassphrase;
    procedure TestLegacyEncryptedPemRefusesEmptyPassphraseWithTypedError;
    procedure TestLegacyEncryptedPemRefusesNilPasswordWithTypedError;
    // nil and a zero-length buffer are the same empty passphrase
    procedure TestEncryptedPkcs8PemWithNilPasswordImportsEmptyPassphraseKey;
    procedure TestEncryptedPkcs8DerWithNilPasswordImportsEmptyPassphraseKey;
    procedure TestEncryptedKeyWithEmptyPasswordReportsPasswordRequired;
    // the ENCRYPTED PRIVATE KEY label binds the content to an EncryptedPrivateKeyInfo
    procedure TestPlaintextKeyUnderEncryptedLabelIsRefused;
    // an id-RSASSA-PSS SubjectPublicKeyInfo verifies no RSA scheme (RFC 4055 1.2)
    procedure TestPssSpkiVerifiesNoRsaPkcs1Signature;
    procedure TestPssSpkiVerifiesNoRsaPssRsaeSignature;
    procedure TestPemKeyAfterOtherObjectsImports;
    procedure TestShortReadFromInjectedRandomIsRefused;
    procedure TestPkcs1VerifierRejectsDigestInfoWithoutNullParameters;
    procedure TestLoadCertificateChainFromPemBundle;
    procedure TestLoadSingleDerCertificate;
    procedure TestConcatenatedDerRejected;
    procedure TestLoadCertificateChainFromPkcs7;
    procedure TestMalformedKeyRaisesTypedException;
    procedure TestEmptyKeyRaisesTypedException;
    procedure TestUnsupportedAlgorithmRaisesTypedException;
    procedure TestWrongPasswordRaisesTypedException;
    procedure TestEncryptedKeyWithoutPasswordReportsPasswordRequired;
    procedure TestCertificateAsKeyIsNotReportedAsPasswordRequired;
    procedure TestSmallRsaKeyOmitsPssSchemeItCannotSign;
    procedure TestFitRsaModulusBoundaries;
    procedure TestWithPreferredSchemesNarrowsReordersAndFilters;
    // TTlsCredential.Load builds a fresh staple-free credential: the chain matches LoadChain's,
    // the key imports, and nothing is stapled
    procedure TestLoadCredentialFromChainAndKey;
    // the password overload decrypts an encrypted key (it signs), and a wrong password fails typed
    procedure TestLoadCredentialWithEncryptedKey;
    // the imported key exposes its public half as a SubjectPublicKeyInfo, and it is the public
    // key of that private key (matches the known-good public vector by value)
    procedure TestPublicKeyInfoMatchesPublicVector;
    // the inspector's value-based public-key comparison: equal keys match, different keys and
    // families do not, malformed input is Undetermined
    procedure TestSamePublicKeyDistinguishesKeys;
    // the comparison is by key value, not encoding: one EC key written with explicit curve
    // parameters vs a namedCurve OID still matches (a byte/canonical compare would wrongly reject)
    procedure TestSamePublicKeyIsEncodingAgnostic;
    // the canonical-DER tail for families without a value comparator (X25519): equal keys match,
    // a different family does not
    procedure TestSamePublicKeyTailFamily;
    // TTlsCredential.Clone: its own chain and staple bytes, the same key
    procedure TestCloneOwnsTheChainAndStapleAndSharesTheKey;
    // TTlsCredential.Consistency: one test per outcome
    procedure TestConsistencyOfAKeyThatOwnsItsLeafIsConsistent;
    procedure TestConsistencyOfAnEmptyChainIsChainEmpty;
    procedure TestConsistencyChecksTheChainBeforeTheKey;
    procedure TestConsistencyOfAMissingKeyIsKeyMissing;
    procedure TestConsistencyOfALeafBarringDigitalSignatureIsLeafCannotSign;
    procedure TestConsistencyOfAnRsaKeyOverAnRsaPssLeafIsLeafKeyRsaPss;
    procedure TestConsistencyOfAKeyThatCannotExportIsKeyNotExportable;
    procedure TestConsistencyOfAMalformedLeafIsLeafMalformed;
    procedure TestConsistencyOfAnotherKeyIsKeyLeafMismatch;
    procedure TestConsistencyComparesKeysByValue;
  end;

implementation

const
  // "The quick brown fox"
  SMessageHex = '54686520717569636b2062726f776e20666f78';
  SPassword = 'tlslib';

{ TTestCredentialImport }

procedure TTestCredentialImport.SetUp;
begin
  inherited SetUp;
  FV := Own<TStringList>(LoadVectorFields('Certs/ImportKeys.txt'));
end;

function TTestCredentialImport.Import(const AField: string): ISigningKey;
begin
  Result := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values[AField]), nil);
end;

function TTestCredentialImport.RoundTrips(AScheme: TSignatureScheme;
  const AKey: ISigningKey; const APubField: string): Boolean;
var
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature: TBytes;
begin
  LMessage := DecodeHex(SMessageHex);
  LSigner := Crypto.Signing.CreateSignatureSigner(AScheme, AKey);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;

  LVerifier := Crypto.Signing.CreateSignatureVerifier(AScheme,
    DecodeHex(FV.Values[APubField]));
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  Result := LVerifier.Verify(LSignature);
end;

procedure TTestCredentialImport.CheckSchemes(const AName: string;
  const AKey: ISigningKey; const AExpected: array of TSignatureScheme);
var
  LActual: TArray<TSignatureScheme>;
  LI: Int32;
begin
  LActual := AKey.CapableSchemes;
  CheckEquals(System.Length(AExpected), System.Length(LActual),
    AName + ': CapableSchemes count');
  for LI := 0 to System.Length(AExpected) - 1 do
    CheckTrue(AExpected[LI] = LActual[LI],
      AName + ': CapableSchemes element ' + IntToStr(LI));
end;

procedure TTestCredentialImport.CheckFormats(AScheme: TSignatureScheme;
  const APubField: string; const AExpected: array of TSignatureScheme;
  const AFields: array of string);
var
  LI: Int32;
  LKey: ISigningKey;
begin
  for LI := 0 to System.Length(AFields) - 1 do
  begin
    LKey := Import(AFields[LI]);
    CheckSchemes(AFields[LI], LKey, AExpected);
    CheckTrue(RoundTrips(AScheme, LKey, APubField),
      AFields[LI] + ': imported key signs a verifying signature');
  end;
end;

procedure TTestCredentialImport.TestRsaImportsEveryFormat;
begin
  // PKCS#8 and PKCS#1, DER and PEM, all normalize to the same RSA key. An rsaEncryption key
  // advertises RSA-PSS (preferred) and the legacy RSA-PKCS1 schemes (RFC 9846 4.3.3).
  CheckFormats(TSignatureScheme.RSA_PSS_RSAE_SHA256, 'rsa_pub',
    [TSignatureScheme.RSA_PSS_RSAE_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA384,
     TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PKCS1_SHA256,
     TSignatureScheme.RSA_PKCS1_SHA384, TSignatureScheme.RSA_PKCS1_SHA512],
    ['rsa_pkcs8_der', 'rsa_pkcs8_pem', 'rsa_pkcs1_der', 'rsa_pkcs1_pem']);
end;

procedure TTestCredentialImport.TestEcP256ImportsEveryFormat;
begin
  // PKCS#8 and SEC1, DER and PEM
  CheckFormats(TSignatureScheme.ECDSA_SECP256R1_SHA256, 'ec256_pub',
    [TSignatureScheme.ECDSA_SECP256R1_SHA256],
    ['ec256_pkcs8_der', 'ec256_pkcs8_pem', 'ec256_sec1_der', 'ec256_sec1_pem']);
end;

procedure TTestCredentialImport.TestPkcs8FixturesAreWrappedKeys;
const
  Pairs: array [0 .. 3, 0 .. 1] of string = (
    ('rsa_pkcs8_der', 'rsa_pkcs1_der'), ('ec256_pkcs8_der', 'ec256_sec1_der'),
    ('ec384_pkcs8_der', 'ec384_sec1_der'), ('ec521_pkcs8_der', 'ec521_sec1_der'));
var
  LI, LBody: Int32;
  LKey: TBytes;
begin
  // a PKCS#8 PrivateKeyInfo wraps the traditional key with a version and an algorithm identifier,
  // so it is longer than it; a fixture equal to the traditional bytes tests nothing about PKCS#8
  for LI := Low(Pairs) to High(Pairs) do
  begin
    LKey := DecodeHex(FV.Values[Pairs[LI, 0]]);
    CheckTrue(System.Length(LKey) > System.Length(DecodeHex(FV.Values[Pairs[LI, 1]])),
      Pairs[LI, 0] + ' is a PKCS#8 wrapping of ' + Pairs[LI, 1]);
    // SEQUENCE { INTEGER 0, SEQUENCE (the algorithm identifier) ...
    LBody := 2;
    if LKey[1] >= $80 then
      Inc(LBody, LKey[1] and $7F);
    CheckTrue((LKey[0] = $30) and (LKey[LBody] = $02) and (LKey[LBody + 1] = $01) and
      (LKey[LBody + 2] = $00) and (LKey[LBody + 3] = $30),
      Pairs[LI, 0] + ' opens with a version 0 and an algorithm identifier');
  end;
end;

procedure TTestCredentialImport.TestPemKeyAfterOtherObjectsImports;
var
  LKey: ISigningKey;
begin
  LKey := Import('ec256_params_key_pem');
  CheckSchemes('ec256 after EC PARAMETERS', LKey,
    [TSignatureScheme.ECDSA_SECP256R1_SHA256]);
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_params_key_pub'),
    'the key behind EC PARAMETERS signs a verifying signature');

  LKey := Import('ec256_dh_params_key_pem');
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'an object the reader cannot parse ahead of the key does not fail the import');

  LKey := Crypto.Signing.ImportSigningKey(ConcatBytes(
    DecodeHex(FV.Values['chain_pem']), DecodeHex(FV.Values['ec256_pkcs8_pem'])), nil);
  CheckSchemes('ec256 after certificates', LKey, [TSignatureScheme.ECDSA_SECP256R1_SHA256]);
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'the key behind a certificate chain signs a verifying signature');
end;

procedure TTestCredentialImport.TestShortReadFromInjectedRandomIsRefused;
var
  LProvider: ICryptoProvider;
  LKey: ISigningKey;
  LSigner: ISignatureSigner;
  LMessage: TBytes;
  LRaised: Boolean;
begin
  // an RSA-PSS signature draws its salt from the injected source; one that returns fewer bytes
  // than asked must fail the signing, not hand back whatever lay beyond the short buffer
  LProvider := TMockCryptoProvider.Create(TShortRandom.Create as IRandom) as ICryptoProvider;
  LKey := LProvider.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_pkcs8_der']), nil);
  LSigner := LProvider.Signing.CreateSignatureSigner(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey);
  LMessage := DecodeHex(SMessageHex);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LRaised := False;
  try
    LSigner.Sign;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a short read from the random source fails the signature');
end;

procedure TTestCredentialImport.TestPkcs1VerifierRejectsDigestInfoWithoutNullParameters;
var
  LVerifier: ISignatureVerifier;
  LMessage: TBytes;
begin
  // the signature is genuine RSASSA-PKCS1-v1_5 by rsa_pkcs8_der, over a DigestInfo that omits the
  // NULL parameters RFC 8017 9.2 requires; no verifier may take it for a valid signature
  LMessage := DecodeHex(SMessageHex);
  LVerifier := Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.RSA_PKCS1_SHA256,
    DecodeHex(FV.Values['rsa_pub']));
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  CheckFalse(LVerifier.Verify(DecodeHex(FV.Values['rsa_pkcs1_sha256_no_null_sig'])),
    'a DigestInfo without NULL parameters does not verify');
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PKCS1_SHA256, Import('rsa_pkcs8_der'), 'rsa_pub'),
    'control: a canonical signature by the same key verifies');
end;

procedure TTestCredentialImport.TestEcP384AndP521Import;
begin
  CheckFormats(TSignatureScheme.ECDSA_SECP384R1_SHA384, 'ec384_pub',
    [TSignatureScheme.ECDSA_SECP384R1_SHA384],
    ['ec384_pkcs8_der', 'ec384_sec1_der']);
  CheckFormats(TSignatureScheme.ECDSA_SECP521R1_SHA512, 'ec521_pub',
    [TSignatureScheme.ECDSA_SECP521R1_SHA512],
    ['ec521_pkcs8_der', 'ec521_sec1_der']);
end;

procedure TTestCredentialImport.TestEd25519Imports;
begin
  // Ed25519 exists only as PKCS#8 (no PKCS#1/SEC1)
  CheckFormats(TSignatureScheme.ED25519, 'ed25519_pub',
    [TSignatureScheme.ED25519],
    ['ed25519_pkcs8_der', 'ed25519_pkcs8_pem']);
end;

procedure TTestCredentialImport.TestEd448Imports;
begin
  // Ed448 exists only as PKCS#8; the imported key must advertise exactly ed448
  CheckFormats(TSignatureScheme.ED448, 'ed448_pub',
    [TSignatureScheme.ED448],
    ['ed448_pkcs8_der', 'ed448_pkcs8_pem']);
end;

procedure TTestCredentialImport.TestEncryptedKeysImportWithPassword;
var
  LKey: ISigningKey;
begin
  // encrypted PKCS#8 in DER and PEM, decrypted with the password
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_enc_der']), TSecretBuffer.FromString(SPassword));
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey, 'rsa_pub'),
    'encrypted RSA PKCS#8 (DER) imports and signs');
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_enc_pem']), TSecretBuffer.FromString(SPassword));
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey, 'rsa_pub'),
    'encrypted RSA PKCS#8 (PEM) imports and signs');
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_enc_der']), TSecretBuffer.FromString(SPassword));
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'encrypted EC P-256 PKCS#8 (DER) imports and signs');
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ed25519_enc_der']), TSecretBuffer.FromString(SPassword));
  CheckTrue(RoundTrips(TSignatureScheme.ED25519, LKey, 'ed25519_pub'),
    'encrypted Ed25519 PKCS#8 (DER) imports and signs');
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ed448_enc_der']), TSecretBuffer.FromString(SPassword));
  CheckTrue(RoundTrips(TSignatureScheme.ED448, LKey, 'ed448_pub'),
    'encrypted Ed448 PKCS#8 (DER) imports and signs');
end;

procedure TTestCredentialImport.TestEncryptedKeyImportsWithUtf8Passphrase;
var
  LKey: ISigningKey;
begin
  // a PBES2 (PBKDF2/AES-256-CBC) key encrypted under a non-ASCII passphrase must decrypt from the
  // passphrase's UTF-8 octets (RFC 8018 3); a wrong ANSI/code-page derivation would raise on bad
  // padding. The passphrase buffer holds the UTF-8 octets of 'passwoerd-euro' with accents (never a
  // raw non-ASCII source literal - Delphi would read it as ANSI).
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_enc_utf8_der']),
    TSecretBuffer.From(DecodeHex('70C3A4737377C3B67264E282AC')));
  CheckTrue(LKey <> nil,
    'an encrypted PKCS#8 key with a non-ASCII UTF-8 passphrase imports (decrypts)');
end;

procedure TTestCredentialImport.TestEncryptedPkcs8DerImportsWithEmptyPassphrase;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_enc_empty_der']),
    TSecretBuffer.FromString(''));
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'an encrypted PKCS#8 (DER) under an empty passphrase imports and signs');
end;

procedure TTestCredentialImport.TestEncryptedPkcs8PemImportsWithEmptyPassphrase;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_enc_empty_pem']),
    TSecretBuffer.FromString(''));
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'an ENCRYPTED PRIVATE KEY PEM under an empty passphrase imports and signs');
end;

procedure TTestCredentialImport.TestLegacyEncryptedPemImportsWithItsPassphrase;
var
  LKey: ISigningKey;
begin
  // the control for the refusal below: this fixture is a valid legacy-encrypted key
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_legacy_enc_pem']),
    TSecretBuffer.FromString(SPassword));
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'a Proc-Type encrypted PEM imports under its passphrase');
end;

procedure TTestCredentialImport.TestLegacyEncryptedPemRefusesEmptyPassphraseWithTypedError;
var
  LMsg: string;
begin
  LMsg := '';
  try
    Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_legacy_enc_pem']),
      TSecretBuffer.FromString(''));
  except
    on E: EArgumentTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('non-empty', LMsg) > 0,
    'an empty passphrase on a legacy-encrypted PEM names the need for a non-empty one; got: ' + LMsg);
end;

procedure TTestCredentialImport.TestLegacyEncryptedPemRefusesNilPasswordWithTypedError;
var
  LMsg: string;
begin
  LMsg := '';
  try
    Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_legacy_enc_pem']), nil);
  except
    on E: EArgumentTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('non-empty', LMsg) > 0,
    'a nil password on a legacy-encrypted PEM names the need for a non-empty one; got: ' + LMsg);
end;

procedure TTestCredentialImport.TestEncryptedPkcs8PemWithNilPasswordImportsEmptyPassphraseKey;
var
  LKey: ISigningKey;
begin
  // rewritten to the nil == empty contract (it asserted password-required for nil before)
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_enc_empty_pem']), nil);
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'nil is the empty passphrase: an ENCRYPTED PRIVATE KEY PEM under it imports and signs');
end;

procedure TTestCredentialImport.TestEncryptedPkcs8DerWithNilPasswordImportsEmptyPassphraseKey;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_enc_empty_der']), nil);
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'nil is the empty passphrase: an encrypted PKCS#8 (DER) under it imports and signs');
end;

procedure TTestCredentialImport.TestEncryptedKeyWithEmptyPasswordReportsPasswordRequired;

  procedure CheckReportsPasswordRequired(const AField: string);
  var
    LMsg: string;
  begin
    LMsg := '';
    try
      Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values[AField]), TSecretBuffer.FromString(''));
    except
      on E: EArgumentTlsLibException do
        LMsg := E.Message;
    end;
    CheckTrue(Pos('password', LMsg) > 0,
      AField + ': a zero-length buffer that fails to decrypt names the missing password; got: ' + LMsg);
  end;

begin
  CheckReportsPasswordRequired('rsa_enc_der');
  CheckReportsPasswordRequired('rsa_enc_pem');
end;

procedure TTestCredentialImport.TestPlaintextKeyUnderEncryptedLabelIsRefused;
var
  LMsg: string;
begin
  LMsg := 'imported';
  try
    Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_mislabelled_pem']),
      TSecretBuffer.FromString(SPassword));
  except
    on E: EArgumentTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('could not be parsed', LMsg) > 0,
    'a plaintext key under an ENCRYPTED PRIVATE KEY label is malformed; got: ' + LMsg);
end;

procedure TTestCredentialImport.TestPssSpkiVerifiesNoRsaPkcs1Signature;
begin
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PKCS1_SHA256, Import('rsa_pkcs8_der'), 'rsa_pub'),
    'control: the signature verifies under the rsaEncryption SPKI');
  CheckFalse(RoundTrips(TSignatureScheme.RSA_PKCS1_SHA256, Import('rsa_pkcs8_der'), 'rsa_pub_pss'),
    'the same signature does not verify under the id-RSASSA-PSS SPKI of the same key');
end;

procedure TTestCredentialImport.TestPssSpkiVerifiesNoRsaPssRsaeSignature;
begin
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PSS_RSAE_SHA256, Import('rsa_pkcs8_der'), 'rsa_pub'),
    'control: the signature verifies under the rsaEncryption SPKI');
  CheckFalse(RoundTrips(TSignatureScheme.RSA_PSS_RSAE_SHA256, Import('rsa_pkcs8_der'), 'rsa_pub_pss'),
    'the same signature does not verify under the id-RSASSA-PSS SPKI of the same key');
end;

procedure TTestCredentialImport.TestLoadCertificateChainFromPemBundle;
var
  LChain: TArray<TBytes>;
begin
  // a fullchain PEM (leaf then root) splits into the two ordered DER certificates
  LChain := Pkix.Certificates.LoadChain(DecodeHex(FV.Values['chain_pem']));
  CheckEquals(2, System.Length(LChain), 'the PEM bundle yields two certificates');
  CheckEqualBytes('leaf DER', DecodeHex(FV.Values['chain_leaf_der']), LChain[0]);
  CheckEqualBytes('root DER', DecodeHex(FV.Values['chain_root_der']), LChain[1]);
end;

procedure TTestCredentialImport.TestLoadSingleDerCertificate;
var
  LChain: TArray<TBytes>;
begin
  // a lone DER certificate still loads (as a single-element chain)
  LChain := Pkix.Certificates.LoadChain(DecodeHex(FV.Values['single_leaf_der']));
  CheckEquals(1, System.Length(LChain), 'a lone DER certificate is a one-element chain');
  CheckEqualBytes('single DER', DecodeHex(FV.Values['single_leaf_der']), LChain[0]);
end;

procedure TTestCredentialImport.TestConcatenatedDerRejected;
var
  LRaised: Boolean;
  LMsg: string;
begin
  // two DER certificates back-to-back are not a standard chain container: LoadChain rejects the
  // trailing bytes rather than silently dropping all but the first (use PEM for a chain)
  LRaised := False;
  LMsg := '';
  try
    Pkix.Certificates.LoadChain(
      DecodeHex(FV.Values['chain_leaf_der'] + FV.Values['chain_root_der']));
  except
    on E: EArgumentTlsLibException do
    begin
      LRaised := True;
      LMsg := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'concatenated DER certificates are rejected, not silently truncated');
  CheckTrue(Pos('after the certificate', LMsg) > 0,
    'the rejection is the trailing-bytes check, not an unrelated parse failure');
  // even a single trailing byte after a lone DER certificate is rejected
  LRaised := False;
  try
    Pkix.Certificates.LoadChain(DecodeHex(FV.Values['single_leaf_der'] + '00'));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a single trailing byte after a DER certificate is rejected');
end;

procedure TTestCredentialImport.TestLoadCertificateChainFromPkcs7;
var
  LChain: TArray<TBytes>;
  LLeafHex, LRootHex: string;
  LHasLeaf, LHasRoot: Boolean;
  LI: Int32;
begin
  // a PKCS#7 / CMS DER bundle (RFC 5652) yields every certificate it carries; the order follows
  // the container's SET, so assert membership rather than position
  LChain := Pkix.Certificates.LoadChain(DecodeHex(FV.Values['chain_p7b_der']));
  CheckEquals(2, System.Length(LChain), 'the PKCS#7 bundle yields two certificates');
  LLeafHex := EncodeHex(DecodeHex(FV.Values['chain_leaf_der']));
  LRootHex := EncodeHex(DecodeHex(FV.Values['chain_root_der']));
  LHasLeaf := False;
  LHasRoot := False;
  for LI := 0 to System.High(LChain) do
  begin
    if EncodeHex(LChain[LI]) = LLeafHex then
      LHasLeaf := True;
    if EncodeHex(LChain[LI]) = LRootHex then
      LHasRoot := True;
  end;
  CheckTrue(LHasLeaf, 'the PKCS#7 bundle includes the leaf certificate');
  CheckTrue(LHasRoot, 'the PKCS#7 bundle includes the root certificate');
end;

procedure TTestCredentialImport.TestMalformedKeyRaisesTypedException;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Crypto.Signing.ImportSigningKey(DecodeHex('deadbeefdeadbeef'), nil);
  except
    // a typed library exception, never a raw backend/ASN.1 exception
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'malformed key bytes raise EArgumentTlsLibException');
end;

procedure TTestCredentialImport.TestEmptyKeyRaisesTypedException;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Crypto.Signing.ImportSigningKey(nil, nil);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty key raises EArgumentTlsLibException');
end;

procedure TTestCredentialImport.TestUnsupportedAlgorithmRaisesTypedException;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    // a valid PKCS#8 X25519 key: parseable, but not a signing algorithm
    Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['x25519_pkcs8_der']), nil);
  except
    on E: ENotSupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an unsupported key algorithm raises ENotSupportedTlsLibException');
end;

procedure TTestCredentialImport.TestWrongPasswordRaisesTypedException;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_enc_der']), TSecretBuffer.FromString('not-the-password'));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a wrong decryption password raises EArgumentTlsLibException');
end;

procedure TTestCredentialImport.TestEncryptedKeyWithoutPasswordReportsPasswordRequired;

  procedure CheckReportsPasswordRequired(const AField: string);
  var
    LMsg: string;
  begin
    LMsg := '';
    try
      Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values[AField]), nil);
    except
      on E: EArgumentTlsLibException do
        LMsg := E.Message;
    end;
    CheckTrue(Pos('password', LMsg) > 0,
      AField + ': an encrypted key without a password names the missing password; got: ' + LMsg);
  end;

begin
  // an encrypted key imported with no password is a distinct, actionable error, not "malformed"
  CheckReportsPasswordRequired('rsa_enc_der');
  CheckReportsPasswordRequired('rsa_enc_pem');
end;

procedure TTestCredentialImport.TestCertificateAsKeyIsNotReportedAsPasswordRequired;
var
  LMsg: string;
begin
  // a certificate is a SEQUENCE of a SEQUENCE, but not an EncryptedPrivateKeyInfo (RFC 5958 3)
  LMsg := '';
  try
    Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['chain_leaf_der']), nil);
  except
    on E: EArgumentTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(LMsg <> '', 'a certificate given as a key is refused');
  CheckTrue(Pos('password', LMsg) = 0, 'the refusal does not blame a missing password; got: ' + LMsg);
end;

procedure TTestCredentialImport.TestSmallRsaKeyOmitsPssSchemeItCannotSign;
begin
  // a 1024-bit modulus (emLen 128) fits rsa_pss_rsae_sha256/384 (needs 66/98) but not sha512
  // (needs 130), so that scheme is not offered
  CheckSchemes('rsa 1024', Import('rsa1024_pkcs8_der'),
    [TSignatureScheme.RSA_PSS_RSAE_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA384,
     TSignatureScheme.RSA_PKCS1_SHA256, TSignatureScheme.RSA_PKCS1_SHA384,
     TSignatureScheme.RSA_PKCS1_SHA512]);
end;

procedure TTestCredentialImport.TestFitRsaModulusBoundaries;
var
  LAll: TArray<TSignatureScheme>;
  function Has(const ASchemes: TArray<TSignatureScheme>; AScheme: TSignatureScheme): Boolean;
  var
    LS: TSignatureScheme;
  begin
    Result := False;
    for LS in ASchemes do
      if LS = AScheme then
        Exit(True);
  end;
begin
  LAll := TArray<TSignatureScheme>.Create(TSignatureScheme.RSA_PSS_RSAE_SHA256,
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512,
    TSignatureScheme.RSA_PKCS1_SHA256, TSignatureScheme.RSA_PKCS1_SHA384,
    TSignatureScheme.RSA_PKCS1_SHA512, TSignatureScheme.ED25519);
  // emLen = ceil((bits-1)/8) must reach 2*hLen+2: 66 / 98 / 130 bytes
  CheckFalse(Has(TSignatureScheme.FitRsaModulus(LAll, 521), TSignatureScheme.RSA_PSS_RSAE_SHA256),
    'sha256 needs 522 bits');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 522), TSignatureScheme.RSA_PSS_RSAE_SHA256),
    'sha256 fits 522 bits');
  CheckFalse(Has(TSignatureScheme.FitRsaModulus(LAll, 777), TSignatureScheme.RSA_PSS_RSAE_SHA384),
    'sha384 needs 778 bits');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 778), TSignatureScheme.RSA_PSS_RSAE_SHA384),
    'sha384 fits 778 bits');
  CheckFalse(Has(TSignatureScheme.FitRsaModulus(LAll, 1033), TSignatureScheme.RSA_PSS_RSAE_SHA512),
    'sha512 needs 1034 bits');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 1034), TSignatureScheme.RSA_PSS_RSAE_SHA512),
    'sha512 fits 1034 bits');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 512), TSignatureScheme.RSA_PKCS1_SHA256),
    'pkcs1 sha256 fits 512 bits');
  // PKCS#1 v1.5 needs the modulus to hold the DigestInfo plus 11 bytes of padding: 62 / 78 / 94 bytes
  CheckFalse(Has(TSignatureScheme.FitRsaModulus(LAll, 488), TSignatureScheme.RSA_PKCS1_SHA256),
    'pkcs1 sha256 does not fit 61 bytes');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 489), TSignatureScheme.RSA_PKCS1_SHA256),
    'pkcs1 sha256 fits 62 bytes');
  CheckFalse(Has(TSignatureScheme.FitRsaModulus(LAll, 616), TSignatureScheme.RSA_PKCS1_SHA384),
    'pkcs1 sha384 does not fit 77 bytes');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 617), TSignatureScheme.RSA_PKCS1_SHA384),
    'pkcs1 sha384 fits 78 bytes');
  CheckFalse(Has(TSignatureScheme.FitRsaModulus(LAll, 744), TSignatureScheme.RSA_PKCS1_SHA512),
    'pkcs1 sha512 does not fit 93 bytes');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 745), TSignatureScheme.RSA_PKCS1_SHA512),
    'pkcs1 sha512 fits 94 bytes');
  CheckTrue(Has(TSignatureScheme.FitRsaModulus(LAll, 512), TSignatureScheme.ED25519),
    'other families are kept');
end;

procedure TTestCredentialImport.TestWithPreferredSchemesNarrowsReordersAndFilters;
var
  LKey: ISigningKey;
begin
  // RSA key: CapableSchemes = [pss_sha256/384/512, pkcs1_sha256/384/512]
  LKey := Import('rsa_pkcs8_der');
  // narrow to a single scheme
  CheckSchemes('pin sha384',
    LKey.WithPreferredSchemes(
    TArray<TSignatureScheme>.Create(TSignatureScheme.RSA_PSS_RSAE_SHA384)),
    [TSignatureScheme.RSA_PSS_RSAE_SHA384]);
  // reorder within the key's capabilities
  CheckSchemes('reorder 512,256',
    LKey.WithPreferredSchemes(TArray<TSignatureScheme>.Create(
    TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PSS_RSAE_SHA256)),
    [TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PSS_RSAE_SHA256]);
  // schemes the key cannot sign are dropped (ECDSA on an RSA key)
  CheckSchemes('filter unsupported',
    LKey.WithPreferredSchemes(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA256)),
    [TSignatureScheme.RSA_PSS_RSAE_SHA256]);
  // empty preference is a no-op, and the original handle is unchanged
  CheckSchemes('empty is no-op', LKey.WithPreferredSchemes(nil),
    [TSignatureScheme.RSA_PSS_RSAE_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA384,
     TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PKCS1_SHA256,
     TSignatureScheme.RSA_PKCS1_SHA384, TSignatureScheme.RSA_PKCS1_SHA512]);
  CheckSchemes('original intact', LKey,
    [TSignatureScheme.RSA_PSS_RSAE_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA384,
     TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PKCS1_SHA256,
     TSignatureScheme.RSA_PKCS1_SHA384, TSignatureScheme.RSA_PKCS1_SHA512]);
end;

procedure TTestCredentialImport.TestLoadCredentialFromChainAndKey;
var
  LCred: TTlsCredential;
begin
  LCred := TTlsCredential.Load(Crypto, Pkix, DecodeHex(FV.Values['chain_pem']),
    DecodeHex(FV.Values['ec256_pkcs8_der']));
  CheckEquals(2, System.Length(LCred.CertificateChain),
    'the loaded chain matches the PEM bundle LoadChain yields');
  CheckEqualBytes('leaf DER', DecodeHex(FV.Values['chain_leaf_der']),
    LCred.CertificateChain[0]);
  CheckNotNull(LCred.PrivateKey, 'the private key imported');
  CheckEquals(0, System.Length(LCred.OcspStaple), 'a loaded credential carries no staple');
  CheckFalse(Assigned(LCred.OcspStapleCallback), 'a loaded credential carries no staple callback');
end;

procedure TTestCredentialImport.TestLoadCredentialWithEncryptedKey;
var
  LCred: TTlsCredential;
  LRaised: Boolean;
begin
  LCred := TTlsCredential.Load(Crypto, Pkix, DecodeHex(FV.Values['chain_pem']),
    DecodeHex(FV.Values['rsa_enc_pem']), SPassword);
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PSS_RSAE_SHA256, LCred.PrivateKey, 'rsa_pub'),
    'the decrypted key signs a verifying signature');
  LRaised := False;
  try
    TTlsCredential.Load(Crypto, Pkix, DecodeHex(FV.Values['chain_pem']),
      DecodeHex(FV.Values['rsa_enc_pem']), 'not-the-password');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a wrong key password raises EArgumentTlsLibException');
end;

procedure TTestCredentialImport.CheckDerivedPublicKey(
  const APrivField, APubField: string);
var
  LKey: ISigningKey;
begin
  LKey := Import(APrivField);
  CheckTrue(System.Length(LKey.PublicKeyInfo) > 0,
    APrivField + ': PublicKeyInfo is exported');
  CheckTrue(Pkix.Certificates.SamePublicKey(LKey.PublicKeyInfo,
    DecodeHex(FV.Values[APubField])) = TCertAnswer.Yes,
    APrivField + ': derived public key matches its public vector');
end;

procedure TTestCredentialImport.TestPublicKeyInfoMatchesPublicVector;
begin
  CheckDerivedPublicKey('rsa_pkcs8_der', 'rsa_pub');
  CheckDerivedPublicKey('ec256_pkcs8_der', 'ec256_pub');
  CheckDerivedPublicKey('ec384_pkcs8_der', 'ec384_pub');
  CheckDerivedPublicKey('ec521_pkcs8_der', 'ec521_pub');
  CheckDerivedPublicKey('ed25519_pkcs8_der', 'ed25519_pub');
  CheckDerivedPublicKey('ed448_pkcs8_der', 'ed448_pub');
end;

procedure TTestCredentialImport.TestSamePublicKeyDistinguishesKeys;
var
  LRsa, LEc256, LEc384: TBytes;
begin
  LRsa := DecodeHex(FV.Values['rsa_pub']);
  LEc256 := DecodeHex(FV.Values['ec256_pub']);
  LEc384 := DecodeHex(FV.Values['ec384_pub']);
  CheckTrue(Pkix.Certificates.SamePublicKey(LRsa, LRsa) = TCertAnswer.Yes,
    'an identical key value matches');
  CheckTrue(Pkix.Certificates.SamePublicKey(LRsa, LEc256) = TCertAnswer.No,
    'different key families do not match');
  CheckTrue(Pkix.Certificates.SamePublicKey(LEc256, LEc384) = TCertAnswer.No,
    'the same family with different keys does not match');
  CheckTrue(Pkix.Certificates.SamePublicKey(TBytes.Create($00, $01, $02), LRsa)
    = TCertAnswer.Undetermined, 'a malformed SubjectPublicKeyInfo is Undetermined');
end;

procedure TTestCredentialImport.TestSamePublicKeyTailFamily;
var
  LX25519, LEd25519: TBytes;
begin
  // X25519 has no value comparator, so it exercises the canonical-DER tail: equal keys match,
  // and a different family (Ed25519) does not
  LX25519 := DecodeHex(FV.Values['x25519_pub']);
  LEd25519 := DecodeHex(FV.Values['ed25519_pub']);
  CheckTrue(Pkix.Certificates.SamePublicKey(LX25519, LX25519) = TCertAnswer.Yes,
    'an identical tail-family key matches');
  CheckTrue(Pkix.Certificates.SamePublicKey(LX25519, LEd25519) = TCertAnswer.No,
    'a tail-family key does not match a different family');
end;

procedure TTestCredentialImport.TestSamePublicKeyIsEncodingAgnostic;
begin
  CheckTrue(Pkix.Certificates.SamePublicKey(DecodeHex(FV.Values['ec256_pub_explicit']),
    DecodeHex(FV.Values['ec256_pub'])) = TCertAnswer.Yes,
    'explicit-parameter and namedCurve encodings of one EC key match');
end;

function TTestCredentialImport.RsaLeafCredential: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_cert'));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/Rsa2048Chain.txt', 'leaf_key'), nil);
end;

procedure TTestCredentialImport.TestCloneOwnsTheChainAndStapleAndSharesTheKey;
var
  LOriginal, LClone: TTlsCredential;
begin
  LOriginal.CertificateChain := TArray<TBytes>.Create(DecodeHex('010203'));
  LOriginal.OcspStaple := DecodeHex('0a0b');
  LOriginal.PrivateKey := TFakeSigningKey.Create(nil, nil) as ISigningKey;
  LClone := LOriginal.Clone;
  LClone.CertificateChain[0][0] := $FF;
  LClone.OcspStaple[0] := $FF;
  CheckEquals(1, LOriginal.CertificateChain[0][0], 'the chain is copied');
  CheckEquals($0A, LOriginal.OcspStaple[0], 'the staple is copied');
  CheckTrue(LClone.PrivateKey = LOriginal.PrivateKey, 'the key is shared');
end;

procedure TTestCredentialImport.TestConsistencyOfAKeyThatOwnsItsLeafIsConsistent;
begin
  CheckEquals(Ord(TCredentialConsistency.Consistent),
    Ord(RsaLeafCredential.Consistency(Pkix.Certificates)), 'a key that owns its leaf');
end;

procedure TTestCredentialImport.TestConsistencyOfAnEmptyChainIsChainEmpty;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.CertificateChain := nil;
  CheckEquals(Ord(TCredentialConsistency.ChainEmpty),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'no certificate');
end;

procedure TTestCredentialImport.TestConsistencyChecksTheChainBeforeTheKey;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.CertificateChain := nil;
  LCredential.PrivateKey := nil;
  CheckEquals(Ord(TCredentialConsistency.ChainEmpty),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'no certificate and no key');
end;

procedure TTestCredentialImport.TestConsistencyOfAMissingKeyIsKeyMissing;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.PrivateKey := nil;
  CheckEquals(Ord(TCredentialConsistency.KeyMissing),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'a chain with no key');
end;

procedure TTestCredentialImport.TestConsistencyOfALeafBarringDigitalSignatureIsLeafCannotSign;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'ku_keyenc_cert'));
  CheckEquals(Ord(TCredentialConsistency.LeafCannotSign),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'a keyUsage without digitalSignature');
end;

procedure TTestCredentialImport.TestConsistencyOfAnRsaKeyOverAnRsaPssLeafIsLeafKeyRsaPss;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'rsapss_cert'));
  CheckEquals(Ord(TCredentialConsistency.LeafKeyRsaPss),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'an RSA key over an id-RSASSA-PSS leaf');
end;

procedure TTestCredentialImport.TestConsistencyOfAKeyThatCannotExportIsKeyNotExportable;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.PrivateKey := TFakeSigningKey.Create(
    LCredential.PrivateKey.CapableSchemes, nil) as ISigningKey;
  CheckEquals(Ord(TCredentialConsistency.KeyNotExportable),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'a key with no public half');
end;

procedure TTestCredentialImport.TestConsistencyOfAMalformedLeafIsLeafMalformed;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.CertificateChain := TArray<TBytes>.Create(TBytes.Create(1, 2, 3));
  CheckEquals(Ord(TCredentialConsistency.LeafMalformed),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'a leaf that is not a certificate');
end;

procedure TTestCredentialImport.TestConsistencyOfAnotherKeyIsKeyLeafMismatch;
var
  LCredential: TTlsCredential;
begin
  LCredential := RsaLeafCredential;
  LCredential.PrivateKey := Import('ec256_pkcs8_der');
  CheckEquals(Ord(TCredentialConsistency.KeyLeafMismatch),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'a key of another family');
  LCredential.PrivateKey := Import('rsa_pkcs8_der');
  CheckEquals(Ord(TCredentialConsistency.KeyLeafMismatch),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'another RSA key');
end;

procedure TTestCredentialImport.TestConsistencyComparesKeysByValue;
var
  LCredential: TTlsCredential;
  LReencoded: TBytes;
begin
  LCredential := RsaLeafCredential;
  LReencoded := TTlsLibTestCertificates.RsaSpkiWithoutNullParameters(
    LCredential.PrivateKey.PublicKeyInfo);
  CheckFalse(TArrayUtilities.AreEqual(LReencoded, LCredential.PrivateKey.PublicKeyInfo),
    'the two encodings differ in bytes');
  LCredential.PrivateKey := TFakeSigningKey.Create(
    LCredential.PrivateKey.CapableSchemes, LReencoded) as ISigningKey;
  CheckEquals(Ord(TCredentialConsistency.Consistent),
    Ord(LCredential.Consistency(Pkix.Certificates)), 'the same key in another encoding');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCredentialImport);
{$ELSE}
  RegisterTest(TTestCredentialImport.Suite);
{$ENDIF FPC}

end.
