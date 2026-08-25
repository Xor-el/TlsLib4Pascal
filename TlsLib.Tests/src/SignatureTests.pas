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
  TlpCryptoAlgorithms,
  TlpHandshakeMessages,
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
    function HashOf(const ANames: array of string): TBytes;
    function ServerCertVerifyContent(const ATranscriptHash: TBytes): TBytes;
    function CertVerifySignature: TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEd25519SignVerifyRoundTrip;
    procedure TestEd25519TamperedSignatureFails;
    procedure TestEcdsaP256SignVerifyRoundTrip;
    procedure TestEcdsaP256TamperedSignatureFails;
    procedure TestRsaPssVerifiesRfc8448CertificateVerify;
    procedure TestRsaPssRejectsWrongTranscript;
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
  LSigner := Provider.Signing.CreateSignatureSigner(AScheme, Provider.Signing.ImportSigningKey(APrivDer));
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;

  LVerifier := Provider.Signing.CreateSignatureVerifier(AScheme, APubDer);
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
  LSigner := Provider.Signing.CreateSignatureSigner(AScheme, Provider.Signing.ImportSigningKey(APrivDer));
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;
  // flip a signature byte
  LSignature[System.Length(LSignature) - 1] :=
    Byte(LSignature[System.Length(LSignature) - 1] xor $01);

  LVerifier := Provider.Signing.CreateSignatureVerifier(AScheme, APubDer);
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  Result := not LVerifier.Verify(LSignature);
end;

function TTestSignature.HashOf(const ANames: array of string): TBytes;
var
  LHash: IHash;
  LMsg: TBytes;
  LI: Int32;
begin
  LHash := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256);
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
  Result := Provider.Certificates.PublicKeyInfo(LCert.Entries[0].CertData);
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

procedure TTestSignature.TestRsaPssVerifiesRfc8448CertificateVerify;
var
  LVerifier: ISignatureVerifier;
  LContent: TBytes;
begin
  // the genuine RFC 8448 server CertificateVerify over the real transcript
  LContent := ServerCertVerifyContent(HashOf(['client_hello', 'server_hello',
    'encrypted_ext', 'certificate']));
  LVerifier := Provider.Signing.CreateSignatureVerifier(TSignatureScheme.RSA_PSS_RSAE_SHA256, Rfc8448LeafSpki);
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
  LVerifier := Provider.Signing.CreateSignatureVerifier(TSignatureScheme.RSA_PSS_RSAE_SHA256, Rfc8448LeafSpki);
  LVerifier.Update(LContent, 0, System.Length(LContent));
  CheckFalse(LVerifier.Verify(CertVerifySignature),
    'the signature does not verify over a different transcript');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSignature);
{$ELSE}
  RegisterTest(TTestSignature.Suite);
{$ENDIF FPC}

end.
