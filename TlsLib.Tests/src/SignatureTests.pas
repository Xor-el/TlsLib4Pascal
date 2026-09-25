{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SignatureTests;

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
  TlpIPkixProvider,
  TlpISigningKey,
  TlpDefaultCryptoProvider,
  TlpOSCryptoProvider,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpHandshakeMessages,
  TlpCertificateVerify,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlsLibTestBase;

type
  TTestSignature = class(TTlsLibAlgorithmTestCase)
  private
    FHs, FKeys: TStringList;
    function SignThenVerify(AScheme: TSignatureScheme; const APrivDer, APubDer: TBytes)
      : Boolean;
    function TamperedVerifyFails(AScheme: TSignatureScheme;
      const APrivDer, APubDer: TBytes): Boolean;
    function Rfc8448LeafSpki: TBytes;
    function VerifyEcdsa(const ACryptoProvider: ICryptoProvider;
      const ASig, AMsg: TBytes): Boolean;
    function HashOf(const ANames: array of string): TBytes;
    function ServerCertVerifyContent(const ATranscriptHash: TBytes): TBytes;
    function CertVerifySignature: TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEd25519SignVerifyRoundTrip;
    procedure TestEd25519TamperedSignatureFails;
    procedure TestEd448SignVerifyRoundTrip;
    procedure TestEd448TamperedSignatureFails;
    procedure TestEcdsaP256SignVerifyRoundTrip;
    procedure TestEcdsaP256TamperedSignatureFails;
    procedure TestEcdsaP256DeterministicNoncesRfc6979;
    procedure TestRsaPssVerifiesRfc8448CertificateVerify;
    procedure TestRsaPssRejectsWrongTranscript;
    procedure TestSignatureSchemeCodesMatchCatalog;
    // the provider seam binds the scheme's key family and never leaks a backend exception
    procedure TestVerifierRejectsSchemeKeyFamilyMismatch;
    procedure TestVerifierAllowsEcdsaCurveHashDecoupling;
    procedure TestVerifierRejectsMalformedSpki;
    procedure TestVerifierRejectsUnclassifiableKey;
    procedure TestSignerRejectsSchemeOutsideCapableSchemes;
    procedure TestLeafPolicyRejectsSchemeFamilyMismatch;
    // the overlay ECDSA verifier accepts a valid signature and rejects a non-DER encoding
    procedure TestSystemEcdsaVerifiesValidAndRejectsTrailingBytes;
    procedure TestSystemSignerRejectsSchemeOutsideCapableSchemes;
  end;

implementation

{ TTestSignature }

procedure TTestSignature.SetUp;
begin
  inherited SetUp;
  FHs := LoadVectorFields('Rfc8448/HandshakeMessages.txt');
  FKeys := LoadVectorFields('Certs/SignatureKeys.txt');
end;

procedure TTestSignature.TearDown;
begin
  FHs.Free;
  FKeys.Free;
  inherited TearDown;
end;

function TTestSignature.SignThenVerify(AScheme: TSignatureScheme;
  const APrivDer, APubDer: TBytes): Boolean;
var
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature: TBytes;
begin
  LMessage := DecodeHex('54686520717569636b2062726f776e20666f78'); // "The quick brown fox"
  LSigner := Crypto.Signing.CreateSignatureSigner(AScheme, Crypto.Signing.ImportSigningKey(APrivDer));
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;

  LVerifier := Crypto.Signing.CreateSignatureVerifier(AScheme, APubDer);
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  Result := LVerifier.Verify(LSignature);
end;

function TTestSignature.TamperedVerifyFails(AScheme: TSignatureScheme;
  const APrivDer, APubDer: TBytes): Boolean;
var
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature: TBytes;
begin
  LMessage := DecodeHex('54686520717569636b2062726f776e20666f78');
  LSigner := Crypto.Signing.CreateSignatureSigner(AScheme, Crypto.Signing.ImportSigningKey(APrivDer));
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;
  // flip a signature byte
  LSignature[System.Length(LSignature) - 1] :=
    Byte(LSignature[System.Length(LSignature) - 1] xor $01);

  LVerifier := Crypto.Signing.CreateSignatureVerifier(AScheme, APubDer);
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  Result := not LVerifier.Verify(LSignature);
end;

function TTestSignature.HashOf(const ANames: array of string): TBytes;
var
  LHash: IHash;
  LMsg: TBytes;
  LI: Int32;
begin
  LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  for LI := 0 to High(ANames) do
  begin
    LMsg := DecodeHex(FHs.Values[ANames[LI]]);
    LHash.Update(LMsg, 0, System.Length(LMsg));
  end;
  Result := LHash.DoFinal;
end;

function TTestSignature.Rfc8448LeafSpki: TBytes;
var
  LFramed, LBody: TBytes;
  LCert: TTlsCertificate;
begin
  // strip the handshake header (type + uint24 length) to reach the message body,
  // then ask the provider for the leaf's SubjectPublicKeyInfo
  LFramed := DecodeHex(FHs.Values['certificate']);
  LBody := System.Copy(LFramed, 4, System.Length(LFramed) - 4);
  LCert := THandshakeMessages.DecodeCertificate(LBody);
  Result := Pkix.Certificates.PublicKeyInfo(LCert.Entries[0].CertData);
end;

function TTestSignature.CertVerifySignature: TBytes;
var
  LFramed, LBody: TBytes;
begin
  LFramed := DecodeHex(FHs.Values['cert_verify']);
  LBody := System.Copy(LFramed, 4, System.Length(LFramed) - 4);
  Result := THandshakeMessages.DecodeCertificateVerify(LBody).Signature;
end;

function TTestSignature.ServerCertVerifyContent(
  const ATranscriptHash: TBytes): TBytes;
var
  LContext: TBytes;
begin
  // RFC 8446 4.4.3: 64 spaces, the context string, a 0x00 separator, the transcript hash
  SetLength(Result, 64);
  FillChar(Result[0], 64, $20);
  LContext := TEncoding.ASCII.GetBytes('TLS 1.3, server CertificateVerify');
  Result := ConcatBytes(Result, LContext);
  Result := ConcatBytes(Result, TBytes.Create($00));
  Result := ConcatBytes(Result, ATranscriptHash);
end;

procedure TTestSignature.TestEd25519SignVerifyRoundTrip;
begin
  CheckTrue(SignThenVerify(TSignatureScheme.ED25519, DecodeHex(FKeys.Values['ed25519_key']),
    DecodeHex(FKeys.Values['ed25519_pub'])),
    'an Ed25519 signature verifies against its public key');
end;

procedure TTestSignature.TestEd25519TamperedSignatureFails;
begin
  CheckTrue(TamperedVerifyFails(TSignatureScheme.ED25519, DecodeHex(FKeys.Values['ed25519_key']),
    DecodeHex(FKeys.Values['ed25519_pub'])),
    'a tampered Ed25519 signature fails to verify');
end;

procedure TTestSignature.TestEd448SignVerifyRoundTrip;
begin
  CheckTrue(SignThenVerify(TSignatureScheme.ED448, DecodeHex(FKeys.Values['ed448_key']),
    DecodeHex(FKeys.Values['ed448_pub'])),
    'an Ed448 signature verifies against its public key');
end;

procedure TTestSignature.TestEd448TamperedSignatureFails;
begin
  CheckTrue(TamperedVerifyFails(TSignatureScheme.ED448, DecodeHex(FKeys.Values['ed448_key']),
    DecodeHex(FKeys.Values['ed448_pub'])),
    'a tampered Ed448 signature fails to verify');
end;

procedure TTestSignature.TestEcdsaP256SignVerifyRoundTrip;
begin
  CheckTrue(SignThenVerify(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    DecodeHex(FKeys.Values['ecdsa_key']), DecodeHex(FKeys.Values['ecdsa_pub'])),
    'an ECDSA P-256 signature verifies against its public key');
end;

procedure TTestSignature.TestEcdsaP256TamperedSignatureFails;
begin
  CheckTrue(TamperedVerifyFails(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    DecodeHex(FKeys.Values['ecdsa_key']), DecodeHex(FKeys.Values['ecdsa_pub'])),
    'a tampered ECDSA P-256 signature fails to verify');
end;

procedure TTestSignature.TestEcdsaP256DeterministicNoncesRfc6979;
const
  // RFC 6979 A.2.5: the P-256 private key x and public point U as PKCS#8 / SPKI
  Rfc6979P256Pkcs8 = '3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420' +
    'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';
  Rfc6979P256Spki = '3059301306072a8648ce3d020106082a8648ce3d030107034200' +
    '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6' +
    '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299';
  // the SHA-256 (r, s) pairs for the messages "sample" and "test", DER-encoded
  SampleSignature = '3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716' +
    '022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8';
  TestSignature = '3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367' +
    '0220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083';

  function SignWith(const AKey: ISigningKey; const AMessage: TBytes): TBytes;
  var
    LSigner: ISignatureSigner;
  begin
    LSigner := Crypto.Signing.CreateSignatureSigner(TSignatureScheme.ECDSA_SECP256R1_SHA256,
      AKey);
    LSigner.Update(AMessage, 0, System.Length(AMessage));
    Result := LSigner.Sign;
  end;

var
  LKey: ISigningKey;
  LSample, LTest, LSignature: TBytes;
  LVerifier: ISignatureVerifier;
begin
  // a random nonce would make each signature differ; matching the RFC's answers proves the
  // portable signer derives k from the key and message
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(Rfc6979P256Pkcs8));
  LSample := DecodeHex('73616d706c65'); // "sample"
  LTest := DecodeHex('74657374'); // "test"
  LSignature := SignWith(LKey, LSample);
  CheckEqualBytes('RFC 6979 A.2.5 P-256/SHA-256 "sample"', DecodeHex(SampleSignature),
    LSignature);
  CheckEqualBytes('RFC 6979 A.2.5 P-256/SHA-256 "test"', DecodeHex(TestSignature),
    SignWith(LKey, LTest));
  CheckEqualBytes('signing the same message again is byte-identical', LSignature,
    SignWith(LKey, LSample));
  LVerifier := Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    DecodeHex(Rfc6979P256Spki));
  LVerifier.Update(LSample, 0, System.Length(LSample));
  CheckTrue(LVerifier.Verify(LSignature), 'the deterministic signature is an ordinary ECDSA signature');
end;

procedure TTestSignature.TestRsaPssVerifiesRfc8448CertificateVerify;
var
  LVerifier: ISignatureVerifier;
  LContent: TBytes;
begin
  // the genuine RFC 8448 server CertificateVerify over the real transcript
  LContent := ServerCertVerifyContent(HashOf(['client_hello', 'server_hello',
    'encrypted_ext', 'certificate']));
  LVerifier := Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.RSA_PSS_RSAE_SHA256, Rfc8448LeafSpki);
  LVerifier.Update(LContent, 0, System.Length(LContent));
  CheckTrue(LVerifier.Verify(CertVerifySignature),
    'the genuine RFC 8448 server CertificateVerify verifies against the leaf key');
end;

procedure TTestSignature.TestRsaPssRejectsWrongTranscript;
var
  LVerifier: ISignatureVerifier;
  LHash, LContent: TBytes;
begin
  // the same signature over a transcript hash with one byte flipped must not verify
  LHash := HashOf(['client_hello', 'server_hello', 'encrypted_ext', 'certificate']);
  LHash[0] := Byte(LHash[0] xor $01);
  LContent := ServerCertVerifyContent(LHash);
  LVerifier := Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.RSA_PSS_RSAE_SHA256, Rfc8448LeafSpki);
  LVerifier.Update(LContent, 0, System.Length(LContent));
  CheckFalse(LVerifier.Verify(CertVerifySignature),
    'the signature does not verify over a different transcript');
end;

procedure TTestSignature.TestSignatureSchemeCodesMatchCatalog;
begin
  // the enum's ToCode and the wire-code catalog are two hand-kept mappings of the same
  // RFC 8446 4.2.3 codepoints; assert every scheme agrees so an edit to one that misses the
  // other cannot drift silently
  CheckEquals(TSignatureSchemes.EcdsaSecp256r1Sha256,
    TSignatureScheme.ECDSA_SECP256R1_SHA256.ToCode, 'ecdsa_secp256r1_sha256');
  CheckEquals(TSignatureSchemes.EcdsaSecp384r1Sha384,
    TSignatureScheme.ECDSA_SECP384R1_SHA384.ToCode, 'ecdsa_secp384r1_sha384');
  CheckEquals(TSignatureSchemes.EcdsaSecp521r1Sha512,
    TSignatureScheme.ECDSA_SECP521R1_SHA512.ToCode, 'ecdsa_secp521r1_sha512');
  CheckEquals(TSignatureSchemes.Ed25519, TSignatureScheme.ED25519.ToCode, 'ed25519');
  CheckEquals(TSignatureSchemes.Ed448, TSignatureScheme.ED448.ToCode, 'ed448');
  CheckEquals(TSignatureSchemes.RsaPssRsaeSha256,
    TSignatureScheme.RSA_PSS_RSAE_SHA256.ToCode, 'rsa_pss_rsae_sha256');
  CheckEquals(TSignatureSchemes.RsaPssRsaeSha384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384.ToCode, 'rsa_pss_rsae_sha384');
  CheckEquals(TSignatureSchemes.RsaPssRsaeSha512,
    TSignatureScheme.RSA_PSS_RSAE_SHA512.ToCode, 'rsa_pss_rsae_sha512');
  CheckEquals(TSignatureSchemes.RsaPkcs1Sha256,
    TSignatureScheme.RSA_PKCS1_SHA256.ToCode, 'rsa_pkcs1_sha256');
  CheckEquals(TSignatureSchemes.RsaPkcs1Sha384,
    TSignatureScheme.RSA_PKCS1_SHA384.ToCode, 'rsa_pkcs1_sha384');
  CheckEquals(TSignatureSchemes.RsaPkcs1Sha512,
    TSignatureScheme.RSA_PKCS1_SHA512.ToCode, 'rsa_pkcs1_sha512');
end;

procedure TTestSignature.TestVerifierRejectsSchemeKeyFamilyMismatch;

  procedure CheckMismatchRaises(AScheme: TSignatureScheme; const APubDer: TBytes;
    const AWhat: string);
  var
    LRaised: Boolean;
  begin
    LRaised := False;
    try
      Crypto.Signing.CreateSignatureVerifier(AScheme, APubDer);
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, AWhat);
  end;

begin
  // a scheme whose key family does not match the SPKI must be refused with a typed exception at
  // the seam, never a raw backend exception
  CheckMismatchRaises(TSignatureScheme.RSA_PSS_RSAE_SHA256,
    DecodeHex(FKeys.Values['ecdsa_pub']), 'an EC key under rsa_pss_rsae_* is rejected');
  CheckMismatchRaises(TSignatureScheme.ECDSA_SECP256R1_SHA256, Rfc8448LeafSpki,
    'an RSA key under ecdsa_* is rejected');
  CheckMismatchRaises(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    DecodeHex(FKeys.Values['ed25519_pub']), 'an Ed25519 key under ecdsa_* is rejected');
end;

procedure TTestSignature.TestVerifierAllowsEcdsaCurveHashDecoupling;
var
  LVerifier: ISignatureVerifier;
begin
  // the seam binds the key FAMILY, not the curve: a P-256 key under ecdsa_secp384r1_sha384 is a
  // legitimate TLS 1.2 pairing (the curve bind is a TLS 1.3 handshake concern), so it constructs
  LVerifier := Crypto.Signing.CreateSignatureVerifier(
    TSignatureScheme.ECDSA_SECP384R1_SHA384, DecodeHex(FKeys.Values['ecdsa_pub']));
  CheckTrue(LVerifier <> nil, 'an EC key under a different-curve ecdsa_* scheme still constructs');
end;

procedure TTestSignature.TestVerifierRejectsMalformedSpki;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.ECDSA_SECP256R1_SHA256,
      DecodeHex('deadbeefdeadbeef'));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a malformed SubjectPublicKeyInfo raises a typed exception, not a backend one');
end;

procedure TTestSignature.TestVerifierRejectsUnclassifiableKey;
var
  LX25519Spki: TBytes;
  LRaised: Boolean;
begin
  // an X25519 SubjectPublicKeyInfo parses to a valid key that cannot sign ANY TLS scheme; the seam
  // must reject it with a typed exception, never let a raw backend cast exception cross (a scheme
  // whose family the provider cannot classify has no usable pairing)
  LX25519Spki := DecodeHex('302a300506032b656e032100' +
    '0000000000000000000000000000000000000000000000000000000000000000');
  LRaised := False;
  try
    Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.ED25519, LX25519Spki);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an X25519 key (unclassifiable for signing) is rejected at the seam');
end;

procedure TTestSignature.TestSignerRejectsSchemeOutsideCapableSchemes;
var
  LKey: ISigningKey;
  LRaised: Boolean;
begin
  // an EC key cannot sign an rsa_pss_rsae_* scheme; the seam refuses it before the backend
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ecdsa_key']));
  LRaised := False;
  try
    Crypto.Signing.CreateSignatureSigner(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a scheme outside the key''s CapableSchemes is refused');
end;

procedure TTestSignature.TestLeafPolicyRejectsSchemeFamilyMismatch;
var
  LLeaf: IInspectedCertificate;
  LRaised: Boolean;
  LAlert: TTlsAlertDescription;
begin
  // the handshake leaf-policy gate rejects a scheme/leaf family mismatch with illegal_parameter
  // before signature verification (an RSA leaf presented for an ecdsa_* signature)
  LLeaf := Pkix.Certificates.Parse(DecodeHex(FKeys.Values['rsa_cert']));
  LRaised := False;
  LAlert := TTlsAlertDescription.BadCertificate;
  try
    TCertificateVerify.EnforceSigningLeafPolicy(LLeaf,
      TSignatureScheme.ECDSA_SECP256R1_SHA256, True);
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      LAlert := E.AlertDescription;
    end;
  end;
  CheckTrue(LRaised, 'an RSA leaf presented for an ecdsa_* signature is rejected');
  CheckEquals(Ord(TTlsAlertDescription.IllegalParameter), Ord(LAlert),
    'the alert is illegal_parameter');
end;

function TTestSignature.VerifyEcdsa(const ACryptoProvider: ICryptoProvider;
  const ASig, AMsg: TBytes): Boolean;
var
  LVerifier: ISignatureVerifier;
begin
  LVerifier := ACryptoProvider.Signing.CreateSignatureVerifier(
    TSignatureScheme.ECDSA_SECP256R1_SHA256, DecodeHex(FKeys.Values['ecdsa_pub']));
  LVerifier.Update(AMsg, 0, System.Length(AMsg));
  Result := LVerifier.Verify(ASig);
end;

procedure TTestSignature.TestSystemEcdsaVerifiesValidAndRejectsTrailingBytes;
var
  LCrypto: ICryptoProvider;
  LMessage, LSig, LTampered: TBytes;
  LSigner: ISignatureSigner;
  LRejected: Boolean;
begin
  // the OS-native overlay (native where present, portable fallback otherwise): a valid ECDSA
  // signature verifies (no regression from the stricter DER check), and a signature with a
  // trailing byte after the SEQUENCE is rejected - either as a False verdict (the native decoder)
  // or by the strict DER decoder raising, so the check tolerates both
  LCrypto := TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider);
  LMessage := DecodeHex('54686520717569636b2062726f776e20666f78'); // "The quick brown fox"
  LSigner := LCrypto.Signing.CreateSignatureSigner(
    TSignatureScheme.ECDSA_SECP256R1_SHA256,
    LCrypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ecdsa_key'])));
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSig := LSigner.Sign;

  CheckTrue(VerifyEcdsa(LCrypto, LSig, LMessage), 'a valid ECDSA signature verifies');

  LTampered := System.Copy(LSig);
  SetLength(LTampered, System.Length(LTampered) + 1); // a trailing byte after the DER SEQUENCE
  try
    LRejected := not VerifyEcdsa(LCrypto, LTampered, LMessage);
  except
    on E: Exception do
      LRejected := True;
  end;
  CheckTrue(LRejected, 'a signature with a trailing byte is rejected');
end;

procedure TTestSignature.TestSystemSignerRejectsSchemeOutsideCapableSchemes;
var
  LCrypto: ICryptoProvider;
  LKey: ISigningKey;
  LRaised: Boolean;
begin
  // the overlay signer enforces the same CapableSchemes gate as the portable one (native where
  // present, portable fallback otherwise), so this holds on every host
  LCrypto := TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider);
  LKey := LCrypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ecdsa_key']));
  LRaised := False;
  try
    LCrypto.Signing.CreateSignatureSigner(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the overlay signer refuses a scheme outside the key''s CapableSchemes');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSignature);
{$ELSE}
  RegisterTest(TTestSignature.Suite);
{$ENDIF FPC}

end.
