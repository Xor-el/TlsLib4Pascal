{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit WindowsSystemCryptoTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IFDEF TLSLIB_MSWINDOWS}

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
  TlpDefaultCryptoProvider,
  TlpWindowsSystemCrypto,
  TlpICryptoBackendReport,
  TlpSystemCryptoTypes,
  TlpCryptoDomainTypes,
  TlpISigningKey,
  TlpImportedCredential,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpIPkixProvider,
  TlpPkixDomainTypes,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsConfigBuilder,
  TlpTlsVersion,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpTlsLibExceptions,
  TlsLibTestBase;

type
  /// <summary>Covers the Windows CNG signing overlay's native public-key export: a natively
  /// imported key's PublicKeyInfo comes from the signing handle itself (not the portable
  /// facet), it is the canonical SPKI of that key, and it drives the credential leaf guard.
  /// Runs only where CNG signing is served; skips otherwise.</summary>
  TTestWindowsSystemCrypto = class(TTlsLibAlgorithmTestCase)
  strict private
    FKeys: TStringList;
    FPfx: TStringList;
    // The overlay composed over the portable base (native where the KSP is present).
    function Composed(const ABase: ICryptoProvider): ICryptoProvider;
    // Whether the provider serves AScheme from the OS module.
    function IsNativeSigning(const AProvider: ICryptoProvider;
      AScheme: TSignatureScheme): Boolean;
    // Whether AKey was adopted by the OS module (carries the native marker).
    function IsNativeKey(const AProvider: ICryptoProvider;
      const AKey: ISigningKey): Boolean;
    // Gate for a native test: True when the composed provider serves AScheme natively (so the
    // test runs), False when it reports portable (the caller skips - a host without the OS module).
    function NativeSigningOrSkip(const AProvider: ICryptoProvider;
      AScheme: TSignatureScheme): Boolean;
    // A full, valid TLS 1.3 server config built over the composed overlay with ACredential.
    function BuildServerConfig(const ACredential: TTlsCredential): ITlsServerConfig;
  strict protected
    // the fixture drives the overlay, so the crypto provider under test is the composed one
    function CreateCrypto: ICryptoProvider; override;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    // the exported SubjectPublicKeyInfo does not come from the portable facet: over a base
    // whose ImportSigningKey raises, a natively imported key still exposes the correct SPKI
    procedure TestExportedPublicKeyIsIndependentOfPortable;
    // the exported SPKI is the public key of the handle that signs: a signature made by the
    // native key verifies under the exported SPKI
    procedure TestExportedPublicKeyVerifiesNativeSignature;
    procedure TestNativeVerifierRejectsCrossFamilyScheme;
    procedure TestEcdhImportRefusesScalarsOutsideTheGroupOrder;
    // both parsers agree on the key: the natively adopted PKCS#12 key's exported SPKI equals
    // the leaf certificate's SPKI (guards against crypt32 key<->cert association drift)
    procedure TestPkcs12ExportedKeyMatchesLeaf;
    // policy stays enforced through the overlay: a multi-key store is rejected on Windows too
    procedure TestPkcs12MultiKeyStillFailsClosed;
    // the credential leaf guard sees the native key's exported SPKI: a wrong leaf is refused
    procedure TestBuilderRejectsWrongLeafForNativeKey;
    // and the matching leaf builds: a native credential passes the leaf guard end to end
    procedure TestBuilderAcceptsNativeCredential;
    // a preference-narrowed copy of a native key keeps the same exported public key
    procedure TestPreferredSchemesCopySharesPublicKey;
  end;

{$ENDIF TLSLIB_MSWINDOWS}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

const
  // "The quick brown fox"
  SMessageHex = '54686520717569636b2062726f776e20666f78';
  SPassword = 'tlslib';

type
  // a signing facet whose key import always fails loudly, used to prove the overlay's native
  // export never delegates to the portable facet; every other operation forwards to a real one
  TThrowingInnerSigning = class(TInterfacedObject, ISigningCrypto)
  strict private
    FReal: ISigningCrypto;
  public
    constructor Create(const AReal: ISigningCrypto);
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TImportedCredential;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

resourcestring
  SPortableUsed = 'the native export path fell back to the portable facet';

{ TThrowingInnerSigning }

constructor TThrowingInnerSigning.Create(const AReal: ISigningCrypto);
begin
  inherited Create;
  FReal := AReal;
end;

function TThrowingInnerSigning.ImportSigningKey(const AData: TBytes;
  const APassword: ISecretBuffer): ISigningKey;
begin
  raise Exception.CreateRes(@SPortableUsed);
end;

function TThrowingInnerSigning.ImportPkcs12(const AData: TBytes;
  const APassword: ISecretBuffer): TImportedCredential;
begin
  Result := FReal.ImportPkcs12(AData, APassword);
end;

function TThrowingInnerSigning.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
begin
  Result := FReal.CreateSignatureSigner(AScheme, AKey);
end;

function TThrowingInnerSigning.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
begin
  Result := FReal.CreateSignatureVerifier(AScheme, APublicKeyDer);
end;

{ TTestWindowsSystemCrypto }

procedure TTestWindowsSystemCrypto.SetUp;
begin
  inherited SetUp;
  FKeys := LoadVectorFields('Certs/ImportKeys.txt');
  FPfx := LoadVectorFields('Certs/Pkcs12.txt');
end;

procedure TTestWindowsSystemCrypto.TearDown;
begin
  FKeys.Free;
  FPfx.Free;
  inherited TearDown;
end;

function TTestWindowsSystemCrypto.CreateCrypto: ICryptoProvider;
begin
  Result := Composed(TDefaultCryptoProvider.Create as ICryptoProvider);
end;

function TTestWindowsSystemCrypto.Composed(
  const ABase: ICryptoProvider): ICryptoProvider;
begin
  Result := TWindowsSystemCrypto.Compose(ABase);
end;

function TTestWindowsSystemCrypto.NativeSigningOrSkip(const AProvider: ICryptoProvider;
  AScheme: TSignatureScheme): Boolean;
begin
  Result := IsNativeSigning(AProvider, AScheme);
end;

function TTestWindowsSystemCrypto.BuildServerConfig(
  const ACredential: TTlsCredential): ITlsServerConfig;
var
  LBuilder: ITlsConfigBuilder;
begin
  LBuilder := TTlsConfigBuilder.CreateFromProfile(Crypto, Pkix,
    TTlsConfigProfile.Default);
  Result := LBuilder.Server
    .WithCipherSuites(TCipherSuiteRegistry.CreateDefault(Crypto))
    .WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault)
    .WithNamedGroups(TNamedGroups.CreateDefaultRegistry(Crypto))
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13))
    .WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519))
    .WithCredential(ACredential)
    .Build;
end;

function TTestWindowsSystemCrypto.IsNativeSigning(const AProvider: ICryptoProvider;
  AScheme: TSignatureScheme): Boolean;
var
  LReport: ICryptoBackendReport;
begin
  Result := Supports(AProvider, ICryptoBackendReport, LReport) and
    (LReport.SigningBackend(AScheme).Backend = TCryptoBackend.System);
end;

function TTestWindowsSystemCrypto.IsNativeKey(const AProvider: ICryptoProvider;
  const AKey: ISigningKey): Boolean;
var
  LReport: ICryptoBackendReport;
begin
  Result := Supports(AProvider, ICryptoBackendReport, LReport) and
    (LReport.SigningKeyBackend(AKey).Backend = TCryptoBackend.System);
end;

procedure TTestWindowsSystemCrypto.TestExportedPublicKeyIsIndependentOfPortable;
type
  TCase = record
    Priv, Pub: string;
    Enc: Boolean;
  end;
const
  // every rewritten import path: DER/PEM PKCS#8, raw PKCS#1/SEC1, and encrypted DER/PEM
  LCases: array [0 .. 9] of TCase = (
    (Priv: 'rsa_pkcs8_der'; Pub: 'rsa_pub'; Enc: False),
    (Priv: 'rsa_pkcs8_pem'; Pub: 'rsa_pub'; Enc: False),
    (Priv: 'rsa_pkcs1_der'; Pub: 'rsa_pub'; Enc: False),
    (Priv: 'rsa_enc_der'; Pub: 'rsa_pub'; Enc: True),
    (Priv: 'rsa_enc_pem'; Pub: 'rsa_pub'; Enc: True),
    (Priv: 'ec256_pkcs8_der'; Pub: 'ec256_pub'; Enc: False),
    (Priv: 'ec256_sec1_pem'; Pub: 'ec256_pub'; Enc: False),
    (Priv: 'ec256_enc_der'; Pub: 'ec256_pub'; Enc: True),
    (Priv: 'ec384_pkcs8_der'; Pub: 'ec384_pub'; Enc: False),
    (Priv: 'ec521_pkcs8_der'; Pub: 'ec521_pub'; Enc: False));
var
  LBase, LProvider: ICryptoProvider;
  LKey: ISigningKey;
  LI: Int32;
begin
  // the inner facet raises on any key import, so a correct SPKI can only have been exported
  // from the native handle
  LBase := TDefaultCryptoProvider.Create as ICryptoProvider;
  LProvider := Composed((TCryptoProviderBuilder.Create as ICryptoProviderBuilder)
    .WithSigning(TThrowingInnerSigning.Create(LBase.Signing) as ISigningCrypto)
    .Build);
  if not NativeSigningOrSkip(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  for LI := Low(LCases) to High(LCases) do
  begin
    if LCases[LI].Enc then
      LKey := LProvider.Signing.ImportSigningKey(DecodeHex(FKeys.Values[LCases[LI].Priv]),
        TSecretBuffer.FromString(SPassword))
    else
      LKey := LProvider.Signing.ImportSigningKey(DecodeHex(FKeys.Values[LCases[LI].Priv]), nil);
    CheckEqualBytes(LCases[LI].Priv + ': the native handle exports its canonical SPKI',
      DecodeHex(FKeys.Values[LCases[LI].Pub]), LKey.PublicKeyInfo);
  end;
end;

procedure TTestWindowsSystemCrypto.TestExportedPublicKeyVerifiesNativeSignature;
type
  TCase = record
    Priv: string;
    Scheme: TSignatureScheme;
  end;
const
  LCases: array [0 .. 2] of TCase = (
    (Priv: 'ec256_pkcs8_der'; Scheme: TSignatureScheme.ECDSA_SECP256R1_SHA256),
    (Priv: 'rsa_pkcs8_der'; Scheme: TSignatureScheme.RSA_PSS_RSAE_SHA256),
    (Priv: 'rsa_pkcs8_der'; Scheme: TSignatureScheme.RSA_PKCS1_SHA256));
var
  LKey: ISigningKey;
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature: TBytes;
  LI: Int32;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LMessage := DecodeHex(SMessageHex);
  for LI := Low(LCases) to High(LCases) do
  begin
    LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values[LCases[LI].Priv]), nil);
    LSigner := Crypto.Signing.CreateSignatureSigner(LCases[LI].Scheme, LKey);
    LSigner.Update(LMessage, 0, System.Length(LMessage));
    LSignature := LSigner.Sign;
    LVerifier := Crypto.Signing.CreateSignatureVerifier(LCases[LI].Scheme,
      LKey.PublicKeyInfo);
    LVerifier.Update(LMessage, 0, System.Length(LMessage));
    CheckTrue(LVerifier.Verify(LSignature),
      LCases[LI].Priv + ': a native signature verifies under the exported SPKI');
  end;
end;

procedure TTestWindowsSystemCrypto.TestNativeVerifierRejectsCrossFamilyScheme;
var
  LEcKey, LRsaKey: ISigningKey;
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LEcSignature, LRsaSignature: TBytes;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LMessage := DecodeHex(SMessageHex);
  LEcKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ec256_pkcs8_der']), nil);
  LRsaKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  LSigner := Crypto.Signing.CreateSignatureSigner(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    LEcKey);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LEcSignature := LSigner.Sign;
  LSigner := Crypto.Signing.CreateSignatureSigner(TSignatureScheme.RSA_PSS_RSAE_SHA256,
    LRsaKey);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LRsaSignature := LSigner.Sign;

  // an EC key under an RSA scheme and an RSA key under an ECDSA scheme must verify False, not
  // throw
  LVerifier := Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.RSA_PSS_RSAE_SHA256,
    LEcKey.PublicKeyInfo);
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  CheckFalse(LVerifier.Verify(LEcSignature), 'an EC key does not verify under an RSA scheme');
  LVerifier := Crypto.Signing.CreateSignatureVerifier(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    LRsaKey.PublicKeyInfo);
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  CheckFalse(LVerifier.Verify(LRsaSignature), 'an RSA key does not verify under an ECDSA scheme');
end;

procedure TTestWindowsSystemCrypto.TestEcdhImportRefusesScalarsOutsideTheGroupOrder;
const
  Orders: array [0 .. 2] of string = (
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409');
  Algorithms: array [0 .. 2] of TKeyAgreementAlgorithm = (
    TKeyAgreementAlgorithm.SECP256R1, TKeyAgreementAlgorithm.SECP384R1,
    TKeyAgreementAlgorithm.SECP521R1);
var
  LAgreement: IKeyAgreement;
  LN, LZero, LBelow: TBytes;
  LPublic: TBytes;
  LRaised: Boolean;
  LI: Int32;

  function Imports(const AScalar: TBytes): Boolean;
  begin
    Result := True;
    try
      LAgreement.ImportPrivateKey(TSecretBuffer.From(AScalar),
        TKeyAgreementUsage.Ephemeral, LPublic);
    except
      on E: EArgumentTlsLibException do
        Result := False;
    end;
  end;

begin
  for LI := Low(Orders) to High(Orders) do
  begin
    LAgreement := Crypto.Primitives.CreateKeyAgreement(Algorithms[LI]);
    LN := DecodeHex(Orders[LI]);
    LZero := nil;
    SetLength(LZero, System.Length(LN));
    LBelow := System.Copy(LN);
    LBelow[High(LBelow)] := Byte(LBelow[High(LBelow)] - 1);
    LRaised := not Imports(LZero);
    CheckTrue(LRaised, Format('the zero scalar is refused (curve %d)', [LI]));
    CheckFalse(Imports(LN), Format('a scalar equal to n is refused (curve %d)', [LI]));
    CheckTrue(Imports(LBelow), Format('n-1 is a valid private key (curve %d)', [LI]));
  end;
end;

procedure TTestWindowsSystemCrypto.TestPkcs12ExportedKeyMatchesLeaf;
const
  LVectors: array [0 .. 3] of string = ('rsa_pfx', 'ec_pfx', 'chain_pfx',
    'rsa_altalg_pfx');
var
  LCredential: TImportedCredential;
  LLeafSpki: TBytes;
  LI: Int32;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  for LI := Low(LVectors) to High(LVectors) do
  begin
    LCredential := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values[LVectors[LI]]),
      TSecretBuffer.FromString(SPassword));
    CheckTrue(IsNativeKey(Crypto, LCredential.PrivateKey),
      LVectors[LI] + ': the key was adopted by the OS module');
    LLeafSpki := Pkix.Certificates.PublicKeyInfo(LCredential.CertificateChain[0]);
    CheckEqualBytes(LVectors[LI] + ': exported key SPKI equals the leaf SPKI',
      LLeafSpki, LCredential.PrivateKey.PublicKeyInfo);
    CheckTrue(Pkix.Certificates.SamePublicKey(LLeafSpki,
      LCredential.PrivateKey.PublicKeyInfo) = TCertAnswer.Yes,
      LVectors[LI] + ': the exported key pairs the leaf by value');
  end;
end;

procedure TTestWindowsSystemCrypto.TestPkcs12MultiKeyStillFailsClosed;
var
  LRaised: Boolean;
  LCredential: TImportedCredential;
begin
  LRaised := False;
  try
    LCredential := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['multikey_pfx']),
      TSecretBuffer.FromString(SPassword));
    CheckEquals(0, System.Length(LCredential.CertificateChain),
      'unreachable: a multi-key store must not return a credential');
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a multi-identity store is rejected through the overlay');
end;

procedure TTestWindowsSystemCrypto.TestBuilderRejectsWrongLeafForNativeKey;
var
  LCredential: TImportedCredential;
  LWrong: TTlsCredential;
  LEcChain: TStringList;
  LMsg: string;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(SPassword));
  // pair the native RSA key with a valid EC signing leaf: it permits signing (so the guard
  // reaches the key compare) but its key is a different family, so it fails as a wrong leaf -
  // not on an earlier keyUsage/exportability check
  LEcChain := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    LWrong.CertificateChain := TArray<TBytes>.Create(DecodeHex(LEcChain.Values['leaf_cert']));
  finally
    LEcChain.Free;
  end;
  LWrong.PrivateKey := LCredential.PrivateKey;
  // an otherwise-valid config, so the leaf guard (not the version/cipher checks) is the failure
  LMsg := '';
  try
    BuildServerConfig(LWrong);
  except
    on E: EInvalidOperationTlsLibException do
      LMsg := E.Message;
  end;
  // match the leaf-mismatch message, not just the class: the same class also flags a
  // non-exportable key, which is the very failure this export path removes
  CheckTrue(Pos('does not match the public key', LMsg) > 0,
    'a native key paired with a foreign leaf is refused at Build with a leaf-mismatch; got: '
    + LMsg);
end;

procedure TTestWindowsSystemCrypto.TestBuilderAcceptsNativeCredential;
var
  LCredential: TImportedCredential;
  LGood: TTlsCredential;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(SPassword));
  LGood.CertificateChain := LCredential.CertificateChain;
  LGood.PrivateKey := LCredential.PrivateKey;
  // the native key's exported SPKI matches its own leaf, so the guard passes and Build succeeds
  CheckTrue(BuildServerConfig(LGood) <> nil,
    'a native credential whose key owns its leaf builds');
end;

procedure TTestWindowsSystemCrypto.TestPreferredSchemesCopySharesPublicKey;
var
  LKey, LNarrowed: ISigningKey;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  LNarrowed := LKey.WithPreferredSchemes(
    TArray<TSignatureScheme>.Create(TSignatureScheme.RSA_PSS_RSAE_SHA256));
  CheckEqualBytes('a narrowed copy keeps the exported public key',
    LKey.PublicKeyInfo, LNarrowed.PublicKeyInfo);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestWindowsSystemCrypto);
{$ELSE}
  RegisterTest(TTestWindowsSystemCrypto.Suite);
{$ENDIF FPC}

{$ENDIF TLSLIB_MSWINDOWS}

end.
