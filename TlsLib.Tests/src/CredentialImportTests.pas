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
  TlpCryptoAlgorithms,
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
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRsaImportsEveryFormat;
    procedure TestEcP256ImportsEveryFormat;
    procedure TestEcP384AndP521Import;
    procedure TestEd25519Imports;
    procedure TestEncryptedKeysImportWithPassword;
    procedure TestLoadCertificateChainFromPemBundle;
    procedure TestLoadSingleDerCertificate;
    procedure TestMalformedKeyRaisesTypedException;
    procedure TestUnsupportedAlgorithmRaisesTypedException;
    procedure TestWrongPasswordRaisesTypedException;
    procedure TestWithPreferredSchemesNarrowsReordersAndFilters;
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
  Result := Provider.Signing.ImportSigningKey(DecodeHex(FV.Values[AField]));
end;

function TTestCredentialImport.RoundTrips(AScheme: TSignatureScheme;
  const AKey: ISigningKey; const APubField: string): Boolean;
var
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature: TBytes;
begin
  LMessage := DecodeHex(SMessageHex);
  LSigner := Provider.Signing.CreateSignatureSigner(AScheme, AKey);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;

  LVerifier := Provider.Signing.CreateSignatureVerifier(AScheme,
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

procedure TTestCredentialImport.TestEncryptedKeysImportWithPassword;
var
  LKey: ISigningKey;
begin
  // encrypted PKCS#8 in DER and PEM, decrypted with the password
  LKey := Provider.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_enc_der']), SPassword);
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey, 'rsa_pub'),
    'encrypted RSA PKCS#8 (DER) imports and signs');
  LKey := Provider.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_enc_pem']), SPassword);
  CheckTrue(RoundTrips(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey, 'rsa_pub'),
    'encrypted RSA PKCS#8 (PEM) imports and signs');
  LKey := Provider.Signing.ImportSigningKey(DecodeHex(FV.Values['ec256_enc_der']), SPassword);
  CheckTrue(RoundTrips(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey, 'ec256_pub'),
    'encrypted EC P-256 PKCS#8 (DER) imports and signs');
  LKey := Provider.Signing.ImportSigningKey(DecodeHex(FV.Values['ed25519_enc_der']), SPassword);
  CheckTrue(RoundTrips(TSignatureScheme.ED25519, LKey, 'ed25519_pub'),
    'encrypted Ed25519 PKCS#8 (DER) imports and signs');
end;

procedure TTestCredentialImport.TestLoadCertificateChainFromPemBundle;
var
  LChain: TArray<TBytes>;
begin
  // a fullchain PEM (leaf then root) splits into the two ordered DER certificates
  LChain := Provider.Certificates.LoadChain(DecodeHex(FV.Values['chain_pem']));
  CheckEquals(2, System.Length(LChain), 'the PEM bundle yields two certificates');
  CheckEqualBytes('leaf DER', DecodeHex(FV.Values['chain_leaf_der']), LChain[0]);
  CheckEqualBytes('root DER', DecodeHex(FV.Values['chain_root_der']), LChain[1]);
end;

procedure TTestCredentialImport.TestLoadSingleDerCertificate;
var
  LChain: TArray<TBytes>;
begin
  // a lone DER certificate still loads (as a single-element chain)
  LChain := Provider.Certificates.LoadChain(DecodeHex(FV.Values['single_leaf_der']));
  CheckEquals(1, System.Length(LChain), 'a lone DER certificate is a one-element chain');
  CheckEqualBytes('single DER', DecodeHex(FV.Values['single_leaf_der']), LChain[0]);
end;

procedure TTestCredentialImport.TestMalformedKeyRaisesTypedException;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Provider.Signing.ImportSigningKey(DecodeHex('deadbeefdeadbeef'));
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
    Provider.Signing.ImportSigningKey(DecodeHex(FV.Values['x25519_pkcs8_der']));
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
    Provider.Signing.ImportSigningKey(DecodeHex(FV.Values['rsa_enc_der']), 'not-the-password');
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestCredentialImport);
{$ELSE}
  RegisterTest(TTestCredentialImport.Suite);
{$ENDIF FPC}

end.
