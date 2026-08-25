{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Pkcs12ImportTests;

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
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpISigningKey,
  TlpTlsCredential,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlsLibTestBase;

type
  /// <summary>Covers ImportPkcs12: a .pfx round-trips into a complete TTlsCredential (chain
  /// + a usable ISigningKey) independent of the store's PBE profile, the chain is leaf-first
  /// with any CA present and validates through the certificate-verifier path, and a wrong
  /// password or malformed blob fails closed with a typed TlsLib exception - never a raw
  /// CryptoLib exception or a partial credential.</summary>
  TTestPkcs12Import = class(TTlsLibAlgorithmTestCase)
  private
    FV: TStringList;
    // The bytes of the named .pfx vector field.
    function Blob(const AField: string): TBytes;
    // Signs a fixed probe with the credential's key (its first capable scheme) and verifies
    // it against the leaf certificate's SubjectPublicKeyInfo. True when the key pairs the leaf.
    function KeyPairsLeaf(const ACredential: TTlsCredential): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRsaPfxImportsToCredential;
    procedure TestEcPfxImportsToCredential;
    procedure TestChainPfxIsLeafFirstAndVerifies;
    procedure TestAlternateAlgorithmProfileImports;
    procedure TestMultiKeyPfxFailsClosed;
    procedure TestWrongPasswordFailsClosed;
    procedure TestMalformedBlobFailsClosed;
  end;

implementation

const
  // "The quick brown fox"
  SMessageHex = '54686520717569636b2062726f776e20666f78';
  SPassword = 'tlslib';

{ TTestPkcs12Import }

procedure TTestPkcs12Import.SetUp;
begin
  inherited SetUp;
  FV := LoadVectorFields('Certs/Pkcs12.txt');
end;

procedure TTestPkcs12Import.TearDown;
begin
  FV.Free;
  inherited TearDown;
end;

function TTestPkcs12Import.Blob(const AField: string): TBytes;
begin
  Result := DecodeHex(FV.Values[AField]);
end;

function TTestPkcs12Import.KeyPairsLeaf(const ACredential: TTlsCredential): Boolean;
var
  LScheme: TSignatureScheme;
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature, LSpki: TBytes;
begin
  LScheme := ACredential.PrivateKey.CapableSchemes[0];
  LMessage := DecodeHex(SMessageHex);
  LSigner := Provider.Signing.CreateSignatureSigner(LScheme, ACredential.PrivateKey);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;

  LSpki := Provider.Certificates.PublicKeyInfo(ACredential.CertificateChain[0]);
  LVerifier := Provider.Signing.CreateSignatureVerifier(LScheme, LSpki);
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  Result := LVerifier.Verify(LSignature);
end;

procedure TTestPkcs12Import.TestRsaPfxImportsToCredential;
var
  LCredential: TTlsCredential;
begin
  LCredential := Provider.Signing.ImportPkcs12(Blob('rsa_pfx'), SPassword);
  CheckEquals(1, System.Length(LCredential.CertificateChain),
    'a single-leaf .pfx yields a one-certificate chain');
  CheckTrue(TSignatureScheme.RSA_PSS_RSAE_SHA256 =
    LCredential.PrivateKey.CapableSchemes[0], 'the RSA key reports an RSA-PSS scheme');
  CheckTrue(KeyPairsLeaf(LCredential),
    'the imported RSA key signs a signature the leaf public key verifies');
end;

procedure TTestPkcs12Import.TestEcPfxImportsToCredential;
var
  LCredential: TTlsCredential;
begin
  LCredential := Provider.Signing.ImportPkcs12(Blob('ec_pfx'), SPassword);
  CheckEquals(1, System.Length(LCredential.CertificateChain),
    'a single-leaf EC .pfx yields a one-certificate chain');
  CheckTrue(TSignatureScheme.ECDSA_SECP256R1_SHA256 =
    LCredential.PrivateKey.CapableSchemes[0], 'the P-256 key reports its ECDSA scheme');
  CheckTrue(KeyPairsLeaf(LCredential),
    'the imported EC key signs a signature the leaf public key verifies');
end;

procedure TTestPkcs12Import.TestChainPfxIsLeafFirstAndVerifies;
var
  LCredential: TTlsCredential;
  LVerifier: ICertificateVerifier;
  LAlert: TTlsAlertDescription;
begin
  // the store holds a leaf signed by a test CA plus that CA certificate
  LCredential := Provider.Signing.ImportPkcs12(Blob('chain_pfx'), SPassword);
  CheckEquals(2, System.Length(LCredential.CertificateChain),
    'the chain .pfx yields leaf + CA');
  CheckTrue(KeyPairsLeaf(LCredential),
    'the imported key pairs the leaf certificate (entry 0 is the leaf)');

  // feed the imported chain through the real certificate-verifier path: it must validate
  // to the test CA (leaf-first ordering + the CA present prove the chain wired through)
  LVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(Blob('ca_cert_der'))), False);
  LAlert := TTlsAlertDescription.InternalError;
  CheckTrue(LVerifier.Verify(LCredential.CertificateChain, '', nil, LAlert),
    'the imported chain validates against the test CA anchor');
end;

procedure TTestPkcs12Import.TestAlternateAlgorithmProfileImports;
var
  LCredential: TTlsCredential;
begin
  // the same RSA leaf stored under a different PBE profile (PBES2 AES-128-CBC bags + a
  // SHA-1 integrity MAC, versus rsa_pfx's AES-256-CBC + SHA-256) imports the same way:
  // import is driven by the store's declared algorithms, not pinned to one profile
  LCredential := Provider.Signing.ImportPkcs12(Blob('rsa_altalg_pfx'), SPassword);
  CheckEquals(1, System.Length(LCredential.CertificateChain),
    'the alternate-profile .pfx yields the leaf');
  CheckTrue(KeyPairsLeaf(LCredential),
    'the key from the alternate-profile store imports and pairs the leaf');
end;

procedure TTestPkcs12Import.TestMultiKeyPfxFailsClosed;
var
  LRaised: Boolean;
  LCredential: TTlsCredential;
begin
  // a store with more than one private-key entry is ambiguous for a single credential;
  // alias order is not stable, so it must be rejected rather than binding an arbitrary one
  LRaised := False;
  try
    LCredential := Provider.Signing.ImportPkcs12(Blob('multikey_pfx'), SPassword);
    CheckEquals(0, System.Length(LCredential.CertificateChain),
      'unreachable: a multi-key store must not return a credential');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a multi-identity PKCS#12 store raises EArgumentTlsLibException');
end;

procedure TTestPkcs12Import.TestWrongPasswordFailsClosed;
var
  LRaised: Boolean;
  LCredential: TTlsCredential;
begin
  LRaised := False;
  try
    // a bad-MAC/wrong-password store must raise a typed TlsLib exception, not a Clp* one
    LCredential := Provider.Signing.ImportPkcs12(Blob('rsa_pfx'), 'not-the-password');
    CheckEquals(0, System.Length(LCredential.CertificateChain),
      'unreachable: a wrong password must not return a credential');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a wrong PKCS#12 password raises EArgumentTlsLibException');
end;

procedure TTestPkcs12Import.TestMalformedBlobFailsClosed;
var
  LRaised: Boolean;
  LCredential: TTlsCredential;
begin
  LRaised := False;
  try
    // a truncated/garbage blob must fail closed with a typed exception, never an AV
    LCredential := Provider.Signing.ImportPkcs12(
      DecodeHex('3082deadbeefdeadbeefdeadbeef'), SPassword);
    CheckEquals(0, System.Length(LCredential.CertificateChain),
      'unreachable: a malformed blob must not return a credential');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a malformed PKCS#12 blob raises EArgumentTlsLibException');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcs12Import);
{$ELSE}
  RegisterTest(TTestPkcs12Import.Suite);
{$ENDIF FPC}

end.
