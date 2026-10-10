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
  TlpIKeyExchangePrivateKey,
  TlpDefaultCryptoProvider,
  TlsLibTestProviders,
  TlpWindowsSystemCrypto,
  TlpICryptoBackendReport,
  TlpSystemCryptoTypes,
  TlpCryptoDomainTypes,
  TlpISigningKey,
  TlpImportedCredential,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpPem,
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
    // The class and message of the exception AProvider raises importing AData, empty when it imports.
    function ImportFailure(const AProvider: ICryptoProvider; const AData: TBytes;
      const APassword: ISecretBuffer): string;
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
    // importing never wipes or alters the caller's own key bytes, whether the key is imported
    // as given, wrapped first, or handed on to the portable facet
    procedure TestImportLeavesCallerKeyBytesIntact;
    procedure TestNativeVerifierRejectsCrossFamilyScheme;
    procedure TestNativeRsaVerifierRejectsShortSignature;
    procedure TestNativeRsaPkcs1VerifierIsStrictAboutDigestInfo;
    procedure TestEcdhImportRefusesScalarsOutsideTheGroupOrder;
    // every key-exchange primitive refuses a key minted by another primitive, and accepts its own
    // family's key through a fresh instance
    procedure TestKeyExchangePrimitivesRefuseEachOthersKeys;
    // the overlay's X25519 returns the portable result for a u outside the prime-order subgroup,
    // or refuses it, never a different value
    procedure TestX25519NeverDisagreesWithPortable;
    // both parsers agree on the key: the natively adopted PKCS#12 key's exported SPKI equals
    // the leaf certificate's SPKI (guards against crypt32 key<->cert association drift)
    procedure TestPkcs12ExportedKeyMatchesLeaf;
    // policy stays enforced through the overlay: a multi-key store is rejected on Windows too
    procedure TestPkcs12MultiKeyStillFailsClosed;
    procedure TestPemFirstPrivateKeyBlockDecidesImport;
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
    FThrowOnVerify: Boolean;
  public
    constructor Create(const AReal: ISigningCrypto); overload;
    // imports and signs through the real facet but fails loudly on creating a verifier, so a
    // test can prove a verification ran natively and not through this facet
    constructor Create(const AReal: ISigningCrypto; AThrowOnVerify: Boolean); overload;
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
  FThrowOnVerify := False;
end;

constructor TThrowingInnerSigning.Create(const AReal: ISigningCrypto; AThrowOnVerify: Boolean);
begin
  Create(AReal);
  FThrowOnVerify := AThrowOnVerify;
end;

function TThrowingInnerSigning.ImportSigningKey(const AData: TBytes;
  const APassword: ISecretBuffer): ISigningKey;
begin
  if FThrowOnVerify then
    Exit(FReal.ImportSigningKey(AData, APassword));
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
  if FThrowOnVerify then
    raise Exception.CreateRes(@SPortableUsed);
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
  Result := Composed(TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable));
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
  LBase := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
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

procedure TTestWindowsSystemCrypto.TestNativeRsaVerifierRejectsShortSignature;

  procedure CheckScheme(const AProvider: ICryptoProvider; AScheme: TSignatureScheme);
  var
    LKey: ISigningKey;
    LSigner: ISignatureSigner;
    LVerifier: ISignatureVerifier;
    LMessage, LSignature, LStripped: TBytes;
    LCounter: Int32;
  begin
    LKey := AProvider.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
    // vary the message until the signature starts with a zero octet (about 1 in 256)
    LSignature := nil;
    LMessage := nil;
    for LCounter := 0 to 4095 do
    begin
      LMessage := TBytes.Create(Byte(LCounter shr 8), Byte(LCounter and $FF));
      LSigner := AProvider.Signing.CreateSignatureSigner(AScheme, LKey);
      LSigner.Update(LMessage, 0, System.Length(LMessage));
      LSignature := LSigner.Sign;
      if LSignature[0] = 0 then
        Break;
    end;
    CheckTrue(LSignature[0] = 0, 'a signature with a leading zero octet was found');
    LVerifier := AProvider.Signing.CreateSignatureVerifier(AScheme, LKey.PublicKeyInfo);
    LVerifier.Update(LMessage, 0, System.Length(LMessage));
    CheckTrue(LVerifier.Verify(LSignature), 'the full-length signature verifies');
    LStripped := System.Copy(LSignature, 1, System.Length(LSignature) - 1);
    LVerifier := AProvider.Signing.CreateSignatureVerifier(AScheme, LKey.PublicKeyInfo);
    LVerifier.Update(LMessage, 0, System.Length(LMessage));
    CheckFalse(LVerifier.Verify(LStripped),
      'the signature without its leading zero octet is rejected (RFC 8017 8.1.2 / 8.2.2)');
  end;

var
  LBase, LProvider: ICryptoProvider;
begin
  // the inner facet raises on creating a verifier, so every verification here ran natively
  LBase := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
  LProvider := Composed((TCryptoProviderBuilder.Create as ICryptoProviderBuilder)
    .WithSigning(TThrowingInnerSigning.Create(LBase.Signing, True) as ISigningCrypto)
    .Build);
  if not NativeSigningOrSkip(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  CheckScheme(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA256);
  CheckScheme(LProvider, TSignatureScheme.RSA_PKCS1_SHA256);
  CheckScheme(LProvider, TSignatureScheme.RSA_PKCS1_SHA384);
  CheckScheme(LProvider, TSignatureScheme.RSA_PKCS1_SHA512);
end;

procedure TTestWindowsSystemCrypto.TestNativeRsaPkcs1VerifierIsStrictAboutDigestInfo;

  function Verifies(const AProvider: ICryptoProvider; const ASignatureName: string): Boolean;
  var
    LVerifier: ISignatureVerifier;
    LMessage: TBytes;
  begin
    LMessage := DecodeHex(SMessageHex);
    LVerifier := AProvider.Signing.CreateSignatureVerifier(TSignatureScheme.RSA_PKCS1_SHA256,
      DecodeHex(FKeys.Values['rsa_pub']));
    LVerifier.Update(LMessage, 0, System.Length(LMessage));
    Result := LVerifier.Verify(DecodeHex(FKeys.Values[ASignatureName]));
  end;

var
  LBase, LProvider: ICryptoProvider;
begin
  // the inner facet raises on creating a verifier, so every verification here ran natively. RFC 8017
  // 8.2.2 verifies by re-encoding with EMSA-PKCS1-v1_5 and comparing the whole block, so only the
  // DigestInfo of 9.2 Note 1 (with its NULL parameters) is a valid signature
  LBase := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
  LProvider := Composed((TCryptoProviderBuilder.Create as ICryptoProviderBuilder)
    .WithSigning(TThrowingInnerSigning.Create(LBase.Signing, True) as ISigningCrypto)
    .Build);
  if not NativeSigningOrSkip(LProvider, TSignatureScheme.RSA_PKCS1_SHA256) then
    Exit;
  CheckTrue(Verifies(LProvider, 'rsa_pkcs1_sha256_raw_canonical_sig'),
    'control: the canonical block verifies');
  CheckFalse(Verifies(LProvider, 'rsa_pkcs1_sha256_no_null_sig'),
    'a DigestInfo without the NULL parameters is not the encoding 8.2.2 compares against');
  CheckFalse(Verifies(LProvider, 'rsa_pkcs1_sha256_ps_flipped_sig'),
    'a padding octet that is not FF');
  CheckFalse(Verifies(LProvider, 'rsa_pkcs1_sha256_wrong_oid_sig'),
    'another hash''s DigestInfo prefix over a SHA-256 digest');
  CheckFalse(Verifies(LProvider, 'rsa_pkcs1_sha256_trailing_sig'),
    'an octet after the DigestInfo');
end;

procedure TTestWindowsSystemCrypto.TestX25519NeverDisagreesWithPortable;
const
  Names: array [0 .. 1] of string = ('u', 'u_twist');
var
  LVec: TStringList;
  LPortable, LOs: IKeyAgreement;
  LPortableKey, LOsKey: IKeyExchangePrivateKey;
  LPublic, LPeer, LExpected: TBytes;
  LI: Int32;
begin
  // a u outside the prime-order subgroup may be refused by the OS module (RFC 7748 7), but when
  // it is accepted the result must be the portable one
  LVec := LoadVectorFields('Crypto/Ecdh/X25519Rfc7748.txt');
  try
    LPortable := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable).Primitives
      .CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
    LOs := Crypto.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
    LPortableKey := LPortable.ImportPrivateKey(TSecretBuffer.From(DecodeHex(LVec.Values['scalar'])),
      TKeyAgreementUsage.Ephemeral, LPublic);
    LOsKey := LOs.ImportPrivateKey(TSecretBuffer.From(DecodeHex(LVec.Values['scalar'])),
      TKeyAgreementUsage.Ephemeral, LPublic);
    for LI := Low(Names) to High(Names) do
    begin
      LPeer := DecodeHex(LVec.Values[Names[LI]]);
      LExpected := LPortable.Agree(LPortableKey, LPeer).ToBytes;
      try
        CheckEqualBytes(Format('the overlay agrees with portable on %s', [Names[LI]]),
          LExpected, LOs.Agree(LOsKey, LPeer).ToBytes);
      except
        on EPeerInputTlsLibException do
          ; // refused, which is permitted
      end;
    end;
  finally
    LVec.Free;
  end;
end;

procedure TTestWindowsSystemCrypto.TestKeyExchangePrimitivesRefuseEachOthersKeys;
const
  Algorithms: array [0 .. 3] of TKeyAgreementAlgorithm = (
    TKeyAgreementAlgorithm.X25519, TKeyAgreementAlgorithm.SECP256R1,
    TKeyAgreementAlgorithm.SECP384R1, TKeyAgreementAlgorithm.SECP521R1);
  KemFamily = 4;
var
  LPrivates: array [0 .. KemFamily] of IKeyExchangePrivateKey;
  LPublics: array [0 .. KemFamily] of TBytes;
  LMinter: ICryptoProvider;
  LConsumer: IKeyAgreement;
  LKem: IKem;
  LCiphertext: TBytes;
  LShared, LOut: ISecretBuffer;
  LI, LJ: Int32;

  // exactly EArgument: a peer-input error (a subclass) or a raw backend error is not the refusal
  function AgreeRefused(const AKey: IKeyExchangePrivateKey; const APeer: TBytes): Boolean;
  begin
    Result := False;
    try
      LConsumer.Agree(AKey, APeer);
    except
      on E: Exception do
        Result := E.ClassType = EArgumentTlsLibException;
    end;
  end;

  function DecapsulateRefused(const AKey: IKeyExchangePrivateKey): Boolean;
  begin
    Result := False;
    try
      LKem.Decapsulate(AKey, LCiphertext, LOut);
    except
      on E: Exception do
        Result := E.ClassType = EArgumentTlsLibException;
    end;
  end;

begin
  // keys come from a second overlay, so a key is accepted by family and not by which instance
  // or algorithm handle minted it
  LMinter := Composed(TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable));
  for LI := Low(Algorithms) to High(Algorithms) do
    LMinter.Primitives.CreateKeyAgreement(Algorithms[LI]).GenerateKeyPair(LPrivates[LI],
      LPublics[LI]);
  LMinter.Primitives.CreateKem(TKemAlgorithm.ML_KEM_768).GenerateKeyPair(LPrivates[KemFamily],
    LPublics[KemFamily]);
  LKem := Crypto.Primitives.CreateKem(TKemAlgorithm.ML_KEM_768);

  for LJ := Low(Algorithms) to High(Algorithms) do
  begin
    LConsumer := Crypto.Primitives.CreateKeyAgreement(Algorithms[LJ]);
    for LI := 0 to KemFamily do
      if LI = LJ then
        CheckTrue(LConsumer.Agree(LPrivates[LI], LPublics[LJ]) <> nil,
          Format('family %d key is accepted by its own primitive', [LI]))
      else
        CheckTrue(AgreeRefused(LPrivates[LI], LPublics[LJ]),
          Format('family %d key at family %d primitive is refused', [LI, LJ]));
  end;

  LKem.Encapsulate(LPublics[KemFamily], LCiphertext, LShared);
  for LI := 0 to KemFamily do
    if LI = KemFamily then
    begin
      LKem.Decapsulate(LPrivates[LI], LCiphertext, LOut);
      CheckTrue(LOut <> nil, 'the KEM key is accepted by its own primitive');
    end
    else
      CheckTrue(DecapsulateRefused(LPrivates[LI]),
        Format('family %d key at the KEM primitive is refused', [LI]));
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

function TTestWindowsSystemCrypto.ImportFailure(const AProvider: ICryptoProvider;
  const AData: TBytes; const APassword: ISecretBuffer): string;
begin
  Result := '';
  try
    AProvider.Signing.ImportSigningKey(AData, APassword);
  except
    on E: Exception do
      Result := E.ClassName + ': ' + E.Message;
  end;
end;

procedure TTestWindowsSystemCrypto.TestPemFirstPrivateKeyBlockDecidesImport;
var
  LPortable: ICryptoProvider;
  LData: TBytes;
  LNativeKey, LPortableKey: ISigningKey;
  LFailure: string;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.ECDSA_SECP256R1_SHA256) then
    Exit;
  LPortable := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
  // the first private-key block decides, as in the portable provider: an encrypted block with no
  // password fails closed, naming the password, even when a plain key follows it
  LData := ConcatBytes(DecodeHex(FKeys.Values['rsa_enc_pem']),
    DecodeHex(FKeys.Values['ec256_pkcs8_pem']));
  LFailure := ImportFailure(LPortable, LData, nil);
  CheckTrue(Pos('password', LFailure) > 0,
    'the portable provider reports the missing password; got: ' + LFailure);
  CheckEquals(LFailure, ImportFailure(Crypto, LData, nil),
    'the overlay fails the same way instead of importing the second key');
  // a first key the native side cannot import must not let a later key win: the portable provider
  // owns the choice and takes the first
  LData := ConcatBytes(DecodeHex(FKeys.Values['ed25519_pkcs8_pem']),
    DecodeHex(FKeys.Values['rsa_pkcs8_pem']));
  LNativeKey := Crypto.Signing.ImportSigningKey(LData, nil);
  LPortableKey := LPortable.Signing.ImportSigningKey(LData, nil);
  CheckEqualBytes('the overlay picks the first block', DecodeHex(FKeys.Values['ed25519_pub']),
    LNativeKey.PublicKeyInfo);
  CheckEqualBytes('and it is the key the portable provider picks', LPortableKey.PublicKeyInfo,
    LNativeKey.PublicKeyInfo);
  // a boundary after text on its line is framed by the portable reader but not by ours: the overlay
  // defers to the portable choice rather than import a different key
  LData := ConcatBytes(TEncoding.ASCII.GetBytes('note '), ConcatBytes(
    DecodeHex(FKeys.Values['ed25519_pkcs8_pem']), DecodeHex(FKeys.Values['rsa_pkcs8_pem'])));
  LNativeKey := Crypto.Signing.ImportSigningKey(LData, nil);
  LPortableKey := LPortable.Signing.ImportSigningKey(LData, nil);
  CheckEqualBytes('the same key as the portable provider with a mid-line boundary',
    LPortableKey.PublicKeyInfo, LNativeKey.PublicKeyInfo);
  CheckEqualBytes('which is the first key', DecodeHex(FKeys.Values['ed25519_pub']),
    LNativeKey.PublicKeyInfo);
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

procedure TTestWindowsSystemCrypto.TestImportLeavesCallerKeyBytesIntact;
const
  // native as given (a PKCS#8 decoded from the PEM fixture; the *_pkcs8_der fixtures hold the
  // PKCS#1 / SEC1 bytes), native after wrapping (PKCS#1, SEC1), and the portable fallback,
  // which re-reads the very same input bytes
  Fields: array [0 .. 3] of string = ('rsa_pkcs8_pem', 'rsa_pkcs1_der', 'ec256_sec1_der',
    'ed25519_pkcs8_der');
  // Ed25519 has no CNG path, so it must take the portable fallback
  ExpectNative: array [0 .. 3] of Boolean = (True, True, True, False);
var
  LI: Int32;
  LData, LCopy: TBytes;
  LBlocks: TArray<TPemBlock>;
  LKey: ISigningKey;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  for LI := Low(Fields) to High(Fields) do
  begin
    LData := DecodeHex(FKeys.Values[Fields[LI]]);
    // a *_pem field is armored: import the DER of its first block
    if TPem.IsArmored(LData) then
    begin
      LBlocks := TPem.ReadBlocks(LData);
      LData := LBlocks[0].Content;
    end;
    LCopy := System.Copy(LData);
    LKey := Crypto.Signing.ImportSigningKey(LData, nil);
    CheckTrue(LKey <> nil, Fields[LI] + ' imports');
    CheckEquals(ExpectNative[LI], IsNativeKey(Crypto, LKey),
      Fields[LI] + ' takes the expected backend');
    CheckEqualBytes(Fields[LI] + ' leaves the caller''s bytes untouched', LCopy, LData);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestWindowsSystemCrypto);
{$ELSE}
  RegisterTest(TTestWindowsSystemCrypto.Suite);
{$ENDIF FPC}

{$ENDIF TLSLIB_MSWINDOWS}

end.
