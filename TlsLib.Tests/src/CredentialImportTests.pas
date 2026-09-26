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
  TlpTlsLibExceptions,
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
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRsaImportsEveryFormat;
    procedure TestEcP256ImportsEveryFormat;
    procedure TestEcP384AndP521Import;
    procedure TestEd25519Imports;
    procedure TestEd448Imports;
    procedure TestEncryptedKeysImportWithPassword;
    procedure TestLoadCertificateChainFromPemBundle;
    procedure TestLoadSingleDerCertificate;
    procedure TestConcatenatedDerRejected;
    procedure TestLoadCertificateChainFromPkcs7;
    procedure TestMalformedKeyRaisesTypedException;
    procedure TestUnsupportedAlgorithmRaisesTypedException;
    procedure TestWrongPasswordRaisesTypedException;
    procedure TestWithPreferredSchemesNarrowsReordersAndFilters;
    // the imported key exposes its public half as a SubjectPublicKeyInfo, and it is the public
    // key of that private key (matches the known-good public vector by value)
    procedure TestPublicKeyInfoMatchesPublicVector;
    // the inspector's value-based public-key comparison: equal keys match, different keys and
    // families do not, malformed input is Undetermined
    procedure TestSamePublicKeyDistinguishesKeys;
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
  FV := LoadVectorFields('Certs/ImportKeys.txt');
end;

procedure TTestCredentialImport.TearDown;
begin
  FV.Free;
  inherited TearDown;
end;

function TTestCredentialImport.Import(const AField: string): ISigningKey;
begin
  Result := Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values[AField]));
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
  // advertises RSA-PSS (preferred) and the legacy RSA-PKCS1 schemes (RFC 8446 4.2.3).
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
    Crypto.Signing.ImportSigningKey(DecodeHex('deadbeefdeadbeef'));
  except
    // a typed library exception, never a raw backend/ASN.1 exception
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'malformed key bytes raise EArgumentTlsLibException');
end;

procedure TTestCredentialImport.TestUnsupportedAlgorithmRaisesTypedException;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    // a valid PKCS#8 X25519 key: parseable, but not a signing algorithm
    Crypto.Signing.ImportSigningKey(DecodeHex(FV.Values['x25519_pkcs8_der']));
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestCredentialImport);
{$ELSE}
  RegisterTest(TTestCredentialImport.Suite);
{$ENDIF FPC}

end.
