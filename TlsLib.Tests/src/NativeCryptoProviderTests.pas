{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit NativeCryptoProviderTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

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
  TlpOSCryptoProvider,
  TlpICryptoBackendReport,
  TlpISystemSigningKey,
  TlpSystemCryptoTypes,
  TlpCryptoDomainTypes,
  TlpISigningKey,
  TlpImportedCredential,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpPem,
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
  TlpHpkeComposition,
  TlpSystemCryptoBase,
  TlsLibTestBase;

type
  /// <summary>What the native crypto provider suites share: the provider under test (whatever
  /// TOSCryptoProvider composes for the platform), the fixtures and the gates that tell whether
  /// something ran natively. It has no tests of its own and is never registered.</summary>
  TNativeCryptoProviderTestBase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    FKeys: TStringList;
    FPfx: TStringList;
    // The native facets composed over the portable base (native where the platform serves them).
    function Composed(const ABase: ICryptoProvider): ICryptoProvider;
    // A full, valid TLS 1.3 server config built over the composed overlay with ACredential.
    function BuildServerConfig(const ACredential: TTlsCredential): ITlsServerConfig;
    // The class and message of the exception AProvider raises importing AData, empty when it imports.
    function ImportFailure(const AProvider: ICryptoProvider; const AData: TBytes;
      const APassword: ISecretBuffer): string;
    // Asserts the portable provider reports the AField key as an unsupported encryption under a
    // nil, a zero-length and a non-empty password.
    procedure CheckPortableNamesUnsupportedEncryption(const AField: string);
    // the fixture drives the native provider, so the crypto provider under test is the composed one
    function CreateCrypto: ICryptoProvider; override;
    // The portable provider the native one is composed over, for the cases that wrap it (a facet
    // that raises when the portable path is used) or compare against it. Crypto is the composed one.
    function Portable: ICryptoProvider;
    // Whether the provider serves AScheme from the platform's native module.
    function IsNativeSigning(const AProvider: ICryptoProvider;
      AScheme: TSignatureScheme): Boolean;
    // Whether AKey was adopted by the platform's native module (carries the native marker).
    function IsNativeKey(const AProvider: ICryptoProvider;
      const AKey: ISigningKey): Boolean;
    // True when AScheme is served natively; otherwise skips the test and returns False (caller Exits).
    function NativeSigningOrSkip(const AProvider: ICryptoProvider;
      AScheme: TSignatureScheme): Boolean;
    // Whether a signature by AKey under AScheme verifies against the SubjectPublicKeyInfo ASpki.
    function SignedVerifies(AScheme: TSignatureScheme; const AKey: ISigningKey;
      const ASpki: TBytes): Boolean;
    // A portable provider holding AHpke as its HPKE facet (nil: the default composition).
    function BaseWithHpke(const AHpke: IHpkeCrypto): ICryptoProvider;
    // HPKE is reported Composed exactly when it composes over the provider's own primitives.
    procedure CheckHpkeFacetReport(const AProvider: ICryptoProvider);
    // AProvider's X25519 accepts a valid peer share, then refuses each small-order one as peer input.
    procedure CheckX25519RefusesSmallOrderShares(const AProvider: ICryptoProvider);
  protected
    procedure SetUp; override;
  end;

  /// <summary>The contract every native crypto provider must meet: a natively imported key's
  /// PublicKeyInfo comes from the signing handle itself (not the portable facet), signatures verify
  /// as strictly as the portable verifier, key exchange refuses foreign keys, and the credential
  /// leaf guard sees the native key. Each test runs only for what the backend report says is
  /// native, so a platform with no native provider runs none of them and a new one needs no edit
  /// here (the portable-path counterparts run everywhere).</summary>
  TTestNativeCryptoProvider = class(TNativeCryptoProviderTestBase)
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
    // a small-order peer share is refused as peer input (RFC 7748 6.1), natively and portably
    procedure TestNativeX25519RefusesSmallOrderPeerShares;
    procedure TestPortableX25519RefusesSmallOrderPeerShares;
    // policy stays enforced through the overlay: a multi-key store is rejected on every platform
    procedure TestPkcs12MultiKeyStillFailsClosed;
    procedure TestPemFirstPrivateKeyBlockDecidesImport;
    // the credential leaf guard sees the native key's exported SPKI: a wrong leaf is refused
    procedure TestBuilderRejectsWrongLeafForNativeKey;
    // and the matching leaf builds: a native credential passes the leaf guard end to end
    procedure TestBuilderAcceptsNativeCredential;
    // a preference-narrowed copy of a native key keeps the same exported public key
    procedure TestPreferredSchemesCopySharesPublicKey;
    // a zero-length passphrase is an empty passphrase on the composed provider too
    procedure TestEmptyPassphraseImportsEncryptedPkcs8Der;
    procedure TestEmptyPassphraseImportsEncryptedPkcs8Pem;
    procedure TestEmptyPassphraseOnLegacyPemRaisesTypedError;
    // nil is the empty passphrase on the composed provider too
    procedure TestNilPasswordImportsEncryptedPkcs8DerEmptyPassphraseKey;
    procedure TestNilPasswordImportsEncryptedPkcs8PemEmptyPassphraseKey;
    procedure TestNilPasswordOnRealPasswordKeyReportsPasswordRequired;
    // a PBE only the OS module decrypts: the portable provider names the encryption, the composed
    // one imports and signs
    procedure TestPortableNamesAPkcs12PbeAsUnsupported;
    procedure TestPortableNamesAnUnmappedPbes2CipherAsUnsupported;
    procedure TestPortableNamesAnUnmappedPbes2PrfAsUnsupported;
    procedure TestPortableNamesScryptAsUnsupported;
    procedure TestComposedImportsAnOsOnlyPbeKeyUnderEmptyPassphrase;
    // one native key handle signs from several threads at once and every signature verifies; a guard
    // only: it passes with or without the per-key signing lock
    procedure TestConcurrentSigningOnOneNativeKey;
    // an id-RSASSA-PSS SubjectPublicKeyInfo verifies no RSA scheme, natively or not
    procedure TestPssSpkiVerifiesNoRsaPkcs1Signature;
    procedure TestPssSpkiVerifiesNoRsaPssRsaeSignature;
  end;

  /// <summary>The overlay's HPKE contract, directly and through Compose, so every platform is covered.</summary>
  TTestOverlayCryptoProvider = class(TNativeCryptoProviderTestBase)
  published
    // a caller-supplied facet that is not the library's composition is returned as given
    procedure TestSuppliedHpkeFacetIsKept;
    // a composition over primitives other than the base's is caller-supplied too
    procedure TestHpkeCompositionOverOtherPrimitivesIsKept;
    // the default composition is rebuilt over the overlay's own primitives
    procedure TestDefaultHpkeIsRebuiltOverOverlayPrimitives;
    // through TOSCryptoProvider.Compose on any platform: a supplied facet comes back as given
    procedure TestComposeKeepsSuppliedHpkeFacet;
    procedure TestComposeKeepsHpkeCompositionOverOtherPrimitives;
    // and the default composition rides the result's own primitives
    procedure TestComposeDefaultHpkeRidesTheResultPrimitives;
    // the backend report agrees with the structure of the facet Compose returned
    procedure TestComposedReportMatchesSuppliedHpkeFacet;
    procedure TestComposedReportMatchesHpkeCompositionOverOtherPrimitives;
    procedure TestComposedReportMatchesDefaultHpkeComposition;
  end;

{$IF DEFINED(TLSLIB_MSWINDOWS)}
  /// <summary>The Windows CNG / crypt32 cases, beside the native provider contract.</summary>
  TTestWindowsNativeCryptoProvider = class(TNativeCryptoProviderTestBase)
  strict private
    // The import outcome as text: chain and key SPKI on success, exception class and message else.
    function Pkcs12Outcome(const AProvider: ICryptoProvider; const AField: string;
      const APassword: ISecretBuffer): string;
    // A composed provider whose portable facet fails every import, so only the OS can import.
    function ComposedOverRejectingImports: ICryptoProvider;
    // Imports AField and checks that the key signs what the leaf's public key verifies.
    function ImportPairingLeaf(const AProvider: ICryptoProvider; const AField: string;
      const APassword: ISecretBuffer): TImportedCredential;
  published
    // the native key's exported SPKI equals the leaf certificate's SPKI
    procedure TestPkcs12ExportedKeyMatchesLeaf;
    // with every portable import failing, the OS still unwraps the store and its key signs
    procedure TestPkcs12NativeUnwrapNeedsNoPortableImport;
    // a policy verdict over an OS-unwrapped store is final: it never reaches the portable facet
    procedure TestPkcs12NativeVerdictIsFinal;
    // the composed provider gives the portable outcome, errors included
    procedure TestPkcs12NativeAgreesWithPortable;
    // an Ed25519 store is beyond the OS key store, so the portable facet imports it
    procedure TestPkcs12NativeFailureFallsBackToPortable;
    // a key linked to the wrong certificate: the OS refuses the store, the portable facet loads it
    procedure TestPkcs12WrongLinkFallsBackToPortable;
    // the legacy RC2 / 3DES profiles import only through the OS
    procedure TestPkcs12LegacyProfilesImport;
    // a NULL-password store opens with nil and with an empty buffer, and only the OS reads it
    procedure TestPkcs12NullPasswordStore;
    // the password is the UTF-8 octets, so a non-ASCII one opens the store only as spelled
    procedure TestPkcs12NonAsciiPassword;
    // neither the OS nor the portable facet reads a PBMAC1 store
    procedure TestPkcs12Pbmac1Store;
    // the OS drops a key that matches no certificate: it imports what the portable facet refuses
    procedure TestPkcs12NativeAcceptsStoresPortableRejects;
    // a key on two certificates: the leaf is the linked one even though the other has the lower DER
    procedure TestPkcs12KeyOnSeveralCertificates;
    // an id-RSASSA-PSS certificate store is not unwrapped natively; the portable facet loads it
    procedure TestPkcs12RsaPssCertificateStore;
    // the CNG overlay engages and reports the default HPKE composition as composed
    procedure TestComposeEngagesCngAndReportsDefaultHpkeAsComposed;
    // a natively imported key answers for the neutral system-key marker
    procedure TestNativeKeyAnswersSystemSigningKeyMarker;
    // a key the portable facet imported does not
    procedure TestPortableKeyDoesNotAnswerSystemSigningKeyMarker;
  end;
{$IFEND}

implementation

const
  // "The quick brown fox"
  SMessageHex = '54686520717569636b2062726f776e20666f78';
  SPassword = 'tlslib';
  // small-order or non-canonical encodings of low-order X25519 u, then the same with bit 255 set
  SmallOrderShares: array [0 .. 13] of string = (
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0100000000000000000000000000000000000000000000000000000000000000',
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '0000000000000000000000000000000000000000000000000000000000000080',
    '0100000000000000000000000000000000000000000000000000000000000080',
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

type
  // a signing facet whose key import always fails loudly, used to prove the overlay's native
  // export never delegates to the portable facet; every other operation forwards to a real one
  TThrowingInnerSigning = class(TInterfacedObject, ISigningCrypto)
  strict private
    FReal: ISigningCrypto;
    FThrowOnVerify: Boolean;
    FThrowOnPkcs12: Boolean;
  public
    constructor Create(const AReal: ISigningCrypto); overload;
    // imports and signs through the real facet but fails loudly on creating a verifier, so a
    // test can prove a verification ran natively and not through this facet
    constructor Create(const AReal: ISigningCrypto; AThrowOnVerify: Boolean); overload;
    // fails loudly on every import, PKCS#12 included, so a test can prove an import ran natively
    constructor CreateRejectingImports(const AReal: ISigningCrypto);
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TImportedCredential;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

  // an HPKE facet that is not the library's composition; none of its operations is ever reached
  TStubHpke = class(TInterfacedObject, IHpkeCrypto)
  public
    function Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
    function ImportRecipientKey(AKem: UInt16;
      const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
    procedure GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
      out APrivateKey: ISecretBuffer);
    function ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
    function SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
    function ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
    function RandomEncapsulation(AKem: UInt16): TBytes;
  end;

  // signs and verifies repeatedly with one shared key, recording how many signatures verified
  // and the first failure
  TSharedKeySignWorker = class(TThread)
  strict private
    FProvider: ICryptoProvider;
    FKey: ISigningKey;
    FScheme: TSignatureScheme;
    FIndex: Int32;
    FIterations: Int32;
    FVerified: Int32;
    FFailure: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const AProvider: ICryptoProvider; const AKey: ISigningKey;
      AScheme: TSignatureScheme; AIndex, AIterations: Int32);
    property Verified: Int32 read FVerified;
    property Failure: string read FFailure;
  end;

resourcestring
  SPortableUsed = 'a portable facet ran where the native one must';

{ TStubHpke }

function TStubHpke.Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
begin
  Result := nil;
end;

function TStubHpke.ImportRecipientKey(AKem: UInt16;
  const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
begin
  Result := nil;
end;

procedure TStubHpke.GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
  out APrivateKey: ISecretBuffer);
begin
  APublicKey := nil;
  APrivateKey := nil;
end;

function TStubHpke.ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
begin
  Result := nil;
end;

function TStubHpke.SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
begin
  Result := nil;
end;

function TStubHpke.ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
begin
  Result := False;
end;

function TStubHpke.RandomEncapsulation(AKem: UInt16): TBytes;
begin
  Result := nil;
end;

{ TSharedKeySignWorker }

constructor TSharedKeySignWorker.Create(const AProvider: ICryptoProvider;
  const AKey: ISigningKey; AScheme: TSignatureScheme; AIndex, AIterations: Int32);
begin
  inherited Create(True);
  FProvider := AProvider;
  FKey := AKey;
  FScheme := AScheme;
  FIndex := AIndex;
  FIterations := AIterations;
end;

procedure TSharedKeySignWorker.Execute;
var
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature: TBytes;
  LI: Int32;
begin
  FVerified := 0;
  FFailure := '';
  try
    for LI := 0 to FIterations - 1 do
    begin
      LMessage := TBytes.Create(Byte(LI), Byte(FIndex), 3, 4);
      LSigner := FProvider.Signing.CreateSignatureSigner(FScheme, FKey);
      LSigner.Update(LMessage, 0, System.Length(LMessage));
      LSignature := LSigner.Sign;
      LVerifier := FProvider.Signing.CreateSignatureVerifier(FScheme, FKey.PublicKeyInfo);
      LVerifier.Update(LMessage, 0, System.Length(LMessage));
      if LVerifier.Verify(LSignature) then
        Inc(FVerified)
      else
        FFailure := 'a signature made on a shared key did not verify';
    end;
  except
    on E: Exception do
      FFailure := E.ClassName + ': ' + E.Message;
  end;
end;

{ TThrowingInnerSigning }

constructor TThrowingInnerSigning.Create(const AReal: ISigningCrypto);
begin
  inherited Create;
  FReal := AReal;
  FThrowOnVerify := False;
  FThrowOnPkcs12 := False;
end;

constructor TThrowingInnerSigning.Create(const AReal: ISigningCrypto; AThrowOnVerify: Boolean);
begin
  Create(AReal);
  FThrowOnVerify := AThrowOnVerify;
end;

constructor TThrowingInnerSigning.CreateRejectingImports(const AReal: ISigningCrypto);
begin
  Create(AReal);
  FThrowOnPkcs12 := True;
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
  if FThrowOnPkcs12 then
    raise Exception.CreateRes(@SPortableUsed);
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

{ TNativeCryptoProviderTestBase }

procedure TNativeCryptoProviderTestBase.SetUp;
begin
  inherited SetUp;
  FKeys := Own<TStringList>(LoadVectorFields('Certs/ImportKeys.txt'));
  FPfx := Own<TStringList>(LoadVectorFields('Certs/Pkcs12.txt'));
end;

function TNativeCryptoProviderTestBase.CreateCrypto: ICryptoProvider;
begin
  Result := Composed(Portable);
end;

function TNativeCryptoProviderTestBase.Portable: ICryptoProvider;
begin
  Result := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
end;

function TNativeCryptoProviderTestBase.Composed(
  const ABase: ICryptoProvider): ICryptoProvider;
begin
  Result := TOSCryptoProvider.Compose(ABase);
end;

function TNativeCryptoProviderTestBase.NativeSigningOrSkip(const AProvider: ICryptoProvider;
  AScheme: TSignatureScheme): Boolean;
begin
  Result := IsNativeSigning(AProvider, AScheme);
  if not Result then
    SkipTest('the platform serves this scheme from no native module');
end;

function TNativeCryptoProviderTestBase.SignedVerifies(AScheme: TSignatureScheme;
  const AKey: ISigningKey; const ASpki: TBytes): Boolean;
var
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage: TBytes;
begin
  LMessage := DecodeHex(SMessageHex);
  LSigner := Crypto.Signing.CreateSignatureSigner(AScheme, AKey);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LVerifier := Crypto.Signing.CreateSignatureVerifier(AScheme, ASpki);
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  Result := LVerifier.Verify(LSigner.Sign);
end;

function TNativeCryptoProviderTestBase.BaseWithHpke(const AHpke: IHpkeCrypto): ICryptoProvider;
var
  LBuilder: ICryptoProviderBuilder;
begin
  LBuilder := TCryptoProviderBuilder.Create as ICryptoProviderBuilder;
  Result := LBuilder.WithHpke(AHpke).Build;
end;

procedure TNativeCryptoProviderTestBase.CheckHpkeFacetReport(const AProvider: ICryptoProvider);
var
  LReport: ICryptoBackendReport;
  LComposition: IHpkeComposition;
  LExpected: TCryptoBackend;
begin
  if not Supports(AProvider, ICryptoBackendReport, LReport) then
  begin
    SkipTest('no overlay engaged, so there is no backend report');
    Exit;
  end;
  if Supports(AProvider.Hpke, IHpkeComposition, LComposition) and
    (LComposition.ComposedOver = AProvider.Primitives) then
    LExpected := TCryptoBackend.Composed
  else
    LExpected := TCryptoBackend.Portable;
  CheckEquals(Ord(LExpected), Ord(LReport.FacetBackend(TCryptoFacet.Hpke).Backend),
    'the HPKE backend report follows the structure of the facet');
end;

procedure TNativeCryptoProviderTestBase.CheckX25519RefusesSmallOrderShares(
  const AProvider: ICryptoProvider);
var
  LAgreement: IKeyAgreement;
  LPrivate, LPeerPrivate: IKeyExchangePrivateKey;
  LPublic, LPeerPublic: TBytes;
  LI: Int32;

  // exactly the peer-input error: EArgument or a raw backend error is not the refusal
  function Refused(const APeer: TBytes): Boolean;
  begin
    Result := False;
    try
      LAgreement.Agree(LPrivate, APeer);
    except
      on E: Exception do
        Result := E.ClassType = EPeerInputTlsLibException;
    end;
  end;

begin
  LAgreement := AProvider.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
  LAgreement.GenerateKeyPair(LPrivate, LPublic);
  LAgreement.GenerateKeyPair(LPeerPrivate, LPeerPublic);
  CheckTrue(LAgreement.Agree(LPrivate, LPeerPublic) <> nil, 'a valid peer share is accepted');
  for LI := Low(SmallOrderShares) to High(SmallOrderShares) do
    CheckTrue(Refused(DecodeHex(SmallOrderShares[LI])),
      Format('the small-order share %s is refused as peer input',
        [System.Copy(SmallOrderShares[LI], 1, 8)]));
end;

function TNativeCryptoProviderTestBase.BuildServerConfig(
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

function TNativeCryptoProviderTestBase.IsNativeSigning(const AProvider: ICryptoProvider;
  AScheme: TSignatureScheme): Boolean;
var
  LReport: ICryptoBackendReport;
begin
  Result := Supports(AProvider, ICryptoBackendReport, LReport) and
    (LReport.SigningBackend(AScheme).Backend = TCryptoBackend.System);
end;

function TNativeCryptoProviderTestBase.IsNativeKey(const AProvider: ICryptoProvider;
  const AKey: ISigningKey): Boolean;
var
  LReport: ICryptoBackendReport;
begin
  Result := Supports(AProvider, ICryptoBackendReport, LReport) and
    (LReport.SigningKeyBackend(AKey).Backend = TCryptoBackend.System);
end;

procedure TTestNativeCryptoProvider.TestExportedPublicKeyIsIndependentOfPortable;
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
  LBase := Portable;
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

procedure TTestNativeCryptoProvider.TestExportedPublicKeyVerifiesNativeSignature;
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

procedure TTestNativeCryptoProvider.TestNativeVerifierRejectsCrossFamilyScheme;
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

procedure TTestNativeCryptoProvider.TestNativeRsaVerifierRejectsShortSignature;

  procedure CheckScheme(const AProvider: ICryptoProvider; AScheme: TSignatureScheme;
    const AKeyName: string);
  var
    LKey: ISigningKey;
    LSigner: ISignatureSigner;
    LVerifier: ISignatureVerifier;
    LMessage, LSignature, LStripped: TBytes;
    LCounter: Int32;
  begin
    LKey := AProvider.Signing.ImportSigningKey(DecodeHex(FKeys.Values[AKeyName]), nil);
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
  LBase := Portable;
  LProvider := Composed((TCryptoProviderBuilder.Create as ICryptoProviderBuilder)
    .WithSigning(TThrowingInnerSigning.Create(LBase.Signing, True) as ISigningCrypto)
    .Build);
  if not NativeSigningOrSkip(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  CheckScheme(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA256, 'rsa_pkcs8_der');
  CheckScheme(LProvider, TSignatureScheme.RSA_PKCS1_SHA256, 'rsa_pkcs8_der');
  CheckScheme(LProvider, TSignatureScheme.RSA_PKCS1_SHA384, 'rsa_pkcs8_der');
  CheckScheme(LProvider, TSignatureScheme.RSA_PKCS1_SHA512, 'rsa_pkcs8_der');
  // a second modulus size pins k to the key, not to a 2048-bit assumption
  CheckScheme(LProvider, TSignatureScheme.RSA_PKCS1_SHA256, 'rsa1024_pkcs8_der');
  CheckScheme(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA384, 'rsa1024_pkcs8_der');
end;

procedure TTestNativeCryptoProvider.TestNativeRsaPkcs1VerifierIsStrictAboutDigestInfo;

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
  LBase := Portable;
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

procedure TTestNativeCryptoProvider.TestX25519NeverDisagreesWithPortable;
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
    LPortable := Portable.Primitives
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

procedure TTestNativeCryptoProvider.TestNativeX25519RefusesSmallOrderPeerShares;
var
  LReport: ICryptoBackendReport;
begin
  if not Supports(Crypto, ICryptoBackendReport, LReport) or
    (LReport.KeyAgreementBackend(TKeyAgreementAlgorithm.X25519).Backend <>
      TCryptoBackend.System) then
  begin
    SkipTest('the platform serves X25519 from no native module');
    Exit;
  end;
  CheckX25519RefusesSmallOrderShares(Crypto);
end;

procedure TTestNativeCryptoProvider.TestPortableX25519RefusesSmallOrderPeerShares;
begin
  CheckX25519RefusesSmallOrderShares(Portable);
end;

procedure TTestNativeCryptoProvider.TestKeyExchangePrimitivesRefuseEachOthersKeys;
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
  LMinter := Composed(Portable);
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

procedure TTestNativeCryptoProvider.TestEcdhImportRefusesScalarsOutsideTheGroupOrder;
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

{$IF DEFINED(TLSLIB_MSWINDOWS)}
procedure TTestWindowsNativeCryptoProvider.TestComposeEngagesCngAndReportsDefaultHpkeAsComposed;
var
  LReport: ICryptoBackendReport;
  LProvider: ICryptoProvider;
begin
  LProvider := Composed(BaseWithHpke(nil));
  CheckTrue(Supports(LProvider, ICryptoBackendReport, LReport),
    'the overlay engaged and reports its backends');
  CheckTrue(LReport.FacetBackend(TCryptoFacet.Hpke).Backend = TCryptoBackend.Composed,
    'the default HPKE composition is reported as composed over the native primitives');
end;

procedure TTestWindowsNativeCryptoProvider.TestNativeKeyAnswersSystemSigningKeyMarker;
var
  LKey: ISigningKey;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  CheckTrue(Supports(LKey, ISystemSigningKey), 'a natively imported key carries the marker');
end;

procedure TTestWindowsNativeCryptoProvider.TestPortableKeyDoesNotAnswerSystemSigningKeyMarker;
var
  LKey: ISigningKey;
begin
  LKey := Portable.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  CheckFalse(Supports(LKey, ISystemSigningKey), 'a portable key does not carry the marker');
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12ExportedKeyMatchesLeaf;
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

function TTestWindowsNativeCryptoProvider.Pkcs12Outcome(const AProvider: ICryptoProvider;
  const AField: string; const APassword: ISecretBuffer): string;
var
  LCredential: TImportedCredential;
  LI: Int32;
begin
  try
    LCredential := AProvider.Signing.ImportPkcs12(DecodeHex(FPfx.Values[AField]), APassword);
    Result := 'imported';
    for LI := 0 to System.High(LCredential.CertificateChain) do
      Result := Result + ' ' + EncodeHex(LCredential.CertificateChain[LI]);
    Result := Result + ' key ' + EncodeHex(LCredential.PrivateKey.PublicKeyInfo);
  except
    on E: Exception do
      Result := E.ClassName + ': ' + E.Message;
  end;
end;

function TTestWindowsNativeCryptoProvider.ComposedOverRejectingImports: ICryptoProvider;
begin
  Result := Composed((TCryptoProviderBuilder.Create as ICryptoProviderBuilder)
    .WithSigning(TThrowingInnerSigning.CreateRejectingImports(Portable.Signing)
    as ISigningCrypto).Build);
end;

function TTestWindowsNativeCryptoProvider.ImportPairingLeaf(const AProvider: ICryptoProvider;
  const AField: string; const APassword: ISecretBuffer): TImportedCredential;
var
  LScheme: TSignatureScheme;
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LMessage, LSignature: TBytes;
begin
  Result := AProvider.Signing.ImportPkcs12(DecodeHex(FPfx.Values[AField]), APassword);
  LScheme := Result.PrivateKey.CapableSchemes[0];
  LMessage := DecodeHex(SMessageHex);
  LSigner := AProvider.Signing.CreateSignatureSigner(LScheme, Result.PrivateKey);
  LSigner.Update(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.Sign;
  LVerifier := AProvider.Signing.CreateSignatureVerifier(LScheme,
    Pkix.Certificates.PublicKeyInfo(Result.CertificateChain[0]));
  LVerifier.Update(LMessage, 0, System.Length(LMessage));
  CheckTrue(LVerifier.Verify(LSignature),
    AField + ': the imported key signs what the first chain certificate verifies');
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12NativeUnwrapNeedsNoPortableImport;
const
  LFields: array [0 .. 5] of string = ('rsa_pfx', 'ec_pfx', 'chain_pfx', 'rsa_altalg_pfx',
    'nolink_cafirst_pfx', 'orphanlink_pfx');
  LPasswords: array [0 .. 5] of string = (SPassword, SPassword, SPassword, SPassword, '', '');
  LChainLengths: array [0 .. 5] of Int32 = (1, 1, 2, 1, 2, 2);
var
  LProvider: ICryptoProvider;
  LCredential: TImportedCredential;
  LI: Int32;
begin
  LProvider := ComposedOverRejectingImports;
  if not NativeSigningOrSkip(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  for LI := Low(LFields) to High(LFields) do
  begin
    LCredential := ImportPairingLeaf(LProvider, LFields[LI],
      TSecretBuffer.FromString(LPasswords[LI]));
    CheckTrue(IsNativeKey(LProvider, LCredential.PrivateKey),
      LFields[LI] + ': the key was adopted by the OS module');
    CheckEquals(LChainLengths[LI], System.Length(LCredential.CertificateChain),
      LFields[LI] + ': the chain holds the store''s certificates');
    if LChainLengths[LI] = 2 then
      CheckEqualBytes(LFields[LI] + ': the CA follows the leaf',
        DecodeHex(FPfx.Values['ca_cert_der']), LCredential.CertificateChain[1]);
  end;
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12NativeVerdictIsFinal;
const
  SMultipleKeys = 'EArgumentTlsLibException: the PKCS#12 blob holds more than one private-key';
var
  LProvider: ICryptoProvider;
  LOutcome: string;
begin
  LProvider := ComposedOverRejectingImports;
  if not NativeSigningOrSkip(LProvider, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LOutcome := Pkcs12Outcome(LProvider, 'multikey_pfx', TSecretBuffer.FromString(SPassword));
  CheckEquals(1, Pos(SMultipleKeys, LOutcome),
    'the policy rejects the two-key store the OS unwrapped; got: ' + LOutcome);
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12NativeAgreesWithPortable;
const
  SUnreadable = 'EArgumentTlsLibException: the PKCS#12 blob could not be read';
  SMultipleKeys = 'EArgumentTlsLibException: the PKCS#12 blob holds more than one private-key';
  SNoCert = 'EArgumentTlsLibException: the PKCS#12 blob holds no certificate for its private key';
var
  LPortable: ICryptoProvider;
  LPassword, LUtf8Password: TBytes;

  // AExpectedStart is the portable outcome's expected beginning: 'imported ' or the error
  procedure CheckAgrees(const AField: string; const APasswordBytes: TBytes;
    const AExpectedStart: string);
  var
    LExpected: string;
  begin
    LExpected := Pkcs12Outcome(LPortable, AField, TSecretBuffer.From(APasswordBytes));
    CheckEquals(1, Pos(AExpectedStart, LExpected),
      AField + ': the portable outcome is the expected kind; got: ' + LExpected);
    CheckEquals(LExpected, Pkcs12Outcome(Crypto, AField, TSecretBuffer.From(APasswordBytes)),
      AField + ': the composed provider gives the portable outcome');
  end;

begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LPortable := Portable;
  LPassword := TEncoding.UTF8.GetBytes(SPassword);
  LUtf8Password := DecodeHex(FPfx.Values['utf8pw_password']);
  CheckAgrees('rsa_pfx', LPassword, 'imported ');
  CheckAgrees('rsa_altalg_pfx', LPassword, 'imported ');
  CheckAgrees('ec_pfx', LPassword, 'imported ');
  CheckAgrees('chain_pfx', LPassword, 'imported ');
  CheckAgrees('utf8pw_pfx', LUtf8Password, 'imported ');
  CheckAgrees('nolink_cafirst_pfx', nil, 'imported ');
  CheckAgrees('orphanlink_pfx', nil, 'imported ');
  CheckAgrees('multikey_pfx', LPassword, SMultipleKeys);
  CheckAgrees('nomatch_pfx', nil, SNoCert);
  CheckAgrees('rsa_pfx', TEncoding.UTF8.GetBytes('not-the-password'), SUnreadable);
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12NativeFailureFallsBackToPortable;
var
  LCredential: TImportedCredential;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := ImportPairingLeaf(Crypto, 'ed25519_pfx', TSecretBuffer.FromString(SPassword));
  CheckFalse(IsNativeKey(Crypto, LCredential.PrivateKey),
    'the Ed25519 key is the portable facet''s');
  CheckTrue(TSignatureScheme.ED25519 = LCredential.PrivateKey.CapableSchemes[0],
    'the key signs with Ed25519');
  CheckTrue(Pos(SPortableUsed, Pkcs12Outcome(ComposedOverRejectingImports, 'ed25519_pfx',
    TSecretBuffer.FromString(SPassword))) > 0, 'the store reached the portable facet');
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12WrongLinkFallsBackToPortable;
var
  LCredential: TImportedCredential;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := ImportPairingLeaf(Crypto, 'wronglink_pfx', nil);
  CheckFalse(IsNativeKey(Crypto, LCredential.PrivateKey),
    'the OS refuses a store whose key names the wrong certificate');
  CheckEquals(2, System.Length(LCredential.CertificateChain), 'the chain is the leaf and the CA');
  CheckEquals(Pkcs12Outcome(Portable, 'wronglink_pfx', nil),
    Pkcs12Outcome(Crypto, 'wronglink_pfx', nil), 'the composed import is the portable one');
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12LegacyProfilesImport;
const
  LFields: array [0 .. 1] of string = ('legacy_pfx', 'des3_pfx');
var
  LCredential: TImportedCredential;
  LPortableOutcome: string;
  LI: Int32;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  for LI := Low(LFields) to High(LFields) do
  begin
    LCredential := ImportPairingLeaf(Crypto, LFields[LI], TSecretBuffer.FromString(SPassword));
    CheckTrue(IsNativeKey(Crypto, LCredential.PrivateKey),
      LFields[LI] + ': the OS imported the store');
    LPortableOutcome := Pkcs12Outcome(Portable, LFields[LI],
      TSecretBuffer.FromString(SPassword));
    CheckEquals(1, Pos('EArgumentTlsLibException: the PKCS#12 blob could not be read',
      LPortableOutcome), LFields[LI] + ': the portable facet cannot read the profile; got: '
      + LPortableOutcome);
  end;
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12NullPasswordStore;
var
  LCredential: TImportedCredential;
  LPortableOutcome: string;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := ImportPairingLeaf(Crypto, 'nullpw_pfx', nil);
  CheckTrue(IsNativeKey(Crypto, LCredential.PrivateKey), 'the OS imported the store with nil');
  LCredential := ImportPairingLeaf(Crypto, 'nullpw_pfx', TSecretBuffer.FromString(''));
  CheckTrue(IsNativeKey(Crypto, LCredential.PrivateKey),
    'the OS imported the store with an empty buffer');
  LPortableOutcome := Pkcs12Outcome(Portable, 'nullpw_pfx', nil);
  CheckEquals(1, Pos('EArgumentTlsLibException: the PKCS#12 blob could not be read',
    LPortableOutcome), 'the portable facet cannot read the profile; got: ' + LPortableOutcome);
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12NonAsciiPassword;
var
  LCredential: TImportedCredential;
  LWrongOutcome: string;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := ImportPairingLeaf(Crypto, 'utf8pw_pfx',
    TSecretBuffer.From(DecodeHex(FPfx.Values['utf8pw_password'])));
  CheckTrue(IsNativeKey(Crypto, LCredential.PrivateKey),
    'the OS read the store under its UTF-8 password');
  LWrongOutcome := Pkcs12Outcome(Crypto, 'utf8pw_pfx', TSecretBuffer.FromString('cafe-'));
  CheckEquals(1, Pos('EArgumentTlsLibException: the PKCS#12 blob could not be read',
    LWrongOutcome), 'the ASCII spelling of the password does not open the store; got: '
    + LWrongOutcome);
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12Pbmac1Store;
const
  SUnreadable = 'EArgumentTlsLibException: the PKCS#12 blob could not be read';
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  CheckEquals(1, Pos(SUnreadable, Pkcs12Outcome(Portable, 'pbmac1_pfx',
    TSecretBuffer.FromString(SPassword))), 'the portable facet rejects the PBMAC1 store');
  CheckEquals(1, Pos(SUnreadable, Pkcs12Outcome(Crypto, 'pbmac1_pfx',
    TSecretBuffer.FromString(SPassword))), 'the composed provider rejects the PBMAC1 store');
  CheckTrue(Pos(SPortableUsed, Pkcs12Outcome(ComposedOverRejectingImports, 'pbmac1_pfx',
    TSecretBuffer.FromString(SPassword))) > 0, 'the OS refused it, so the portable facet ran');
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12KeyOnSeveralCertificates;
var
  LCredential: TImportedCredential;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := ImportPairingLeaf(Crypto, 'dupkey_pfx', TSecretBuffer.FromString(SPassword));
  CheckTrue(IsNativeKey(Crypto, LCredential.PrivateKey), 'the OS imported the store');
  CheckEquals(1, System.Length(LCredential.CertificateChain),
    'the self-issued leaf is the whole chain');
  CheckEqualBytes('the leaf is the certificate the store links, not the lower-DER one',
    DecodeHex(FPfx.Values['dupkey_linked_cert']), LCredential.CertificateChain[0]);
  CheckEquals(Pkcs12Outcome(Portable, 'dupkey_pfx', TSecretBuffer.FromString(SPassword)),
    Pkcs12Outcome(Crypto, 'dupkey_pfx', TSecretBuffer.FromString(SPassword)),
    'the composed provider gives the portable outcome');
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12RsaPssCertificateStore;
var
  LCredential: TImportedCredential;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['pss_pfx']),
    TSecretBuffer.FromString(SPassword));
  CheckEquals(1, System.Length(LCredential.CertificateChain), 'the chain is the leaf');
  CheckFalse(IsNativeKey(Crypto, LCredential.PrivateKey), 'the portable facet imported the store');
  CheckTrue(Pos(SPortableUsed, Pkcs12Outcome(ComposedOverRejectingImports, 'pss_pfx',
    TSecretBuffer.FromString(SPassword))) > 0, 'the OS handed the store over');
end;

procedure TTestWindowsNativeCryptoProvider.TestPkcs12NativeAcceptsStoresPortableRejects;
const
  SMultipleKeys = 'EArgumentTlsLibException: the PKCS#12 blob holds more than one private-key';
  SNoCert = 'EArgumentTlsLibException: the PKCS#12 blob holds no certificate for its private key';
  LFields: array [0 .. 2] of string = ('hid_nolink_pfx', 'hid_orphan_pfx', 'hid_sharedlink_pfx');
var
  LCredential: TImportedCredential;
  LPortableOutcome, LExpected: string;
  LI: Int32;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  for LI := Low(LFields) to High(LFields) do
  begin
    LCredential := ImportPairingLeaf(Crypto, LFields[LI], nil);
    CheckTrue(IsNativeKey(Crypto, LCredential.PrivateKey),
      LFields[LI] + ': the OS imported the store');
    CheckEquals(1, System.Length(LCredential.CertificateChain),
      LFields[LI] + ': the chain is the RSA leaf');
    if LI = High(LFields) then
      LExpected := SNoCert
    else
      LExpected := SMultipleKeys;
    LPortableOutcome := Pkcs12Outcome(Portable, LFields[LI], nil);
    CheckEquals(1, Pos(LExpected, LPortableOutcome),
      LFields[LI] + ': the portable facet refuses the store; got: ' + LPortableOutcome);
  end;
end;

{$IFEND}

procedure TTestNativeCryptoProvider.TestConcurrentSigningOnOneNativeKey;
const
  WorkerCount = 8;
  Iterations = 20;
var
  LKey: ISigningKey;
  LWorkers: array [0 .. WorkerCount - 1] of TSharedKeySignWorker;
  LI: Int32;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  CheckTrue(IsNativeKey(Crypto, LKey), 'the key under test is a native handle');
  for LI := 0 to WorkerCount - 1 do
    LWorkers[LI] := TSharedKeySignWorker.Create(Crypto, LKey,
      TSignatureScheme.RSA_PSS_RSAE_SHA256, LI, Iterations);
  try
    for LI := 0 to WorkerCount - 1 do
      LWorkers[LI].Start;
    for LI := 0 to WorkerCount - 1 do
      LWorkers[LI].WaitFor;
    for LI := 0 to WorkerCount - 1 do
    begin
      CheckEquals('', LWorkers[LI].Failure, 'worker ' + IntToStr(LI) + ' saw no failure');
      CheckEquals(Iterations, LWorkers[LI].Verified,
        'worker ' + IntToStr(LI) + ' verified every signature');
    end;
  finally
    for LI := 0 to WorkerCount - 1 do
      LWorkers[LI].Free;
  end;
end;

procedure TTestNativeCryptoProvider.TestEmptyPassphraseImportsEncryptedPkcs8Der;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ec256_enc_empty_der']),
    TSecretBuffer.FromString(''));
  CheckTrue(SignedVerifies(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey,
    DecodeHex(FKeys.Values['ec256_pub'])), 'an encrypted PKCS#8 (DER) under an empty passphrase signs');
end;

procedure TTestNativeCryptoProvider.TestEmptyPassphraseImportsEncryptedPkcs8Pem;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ec256_enc_empty_pem']),
    TSecretBuffer.FromString(''));
  CheckTrue(SignedVerifies(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey,
    DecodeHex(FKeys.Values['ec256_pub'])), 'an ENCRYPTED PRIVATE KEY PEM under an empty passphrase signs');
end;

procedure TTestNativeCryptoProvider.TestEmptyPassphraseOnLegacyPemRaisesTypedError;
var
  LMsg: string;
begin
  LMsg := '';
  try
    Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ec256_legacy_enc_pem']),
      TSecretBuffer.FromString(''));
  except
    on E: EArgumentTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('non-empty', LMsg) > 0,
    'an empty passphrase on a legacy-encrypted PEM names the need for a non-empty one; got: ' + LMsg);
end;

procedure TTestNativeCryptoProvider.TestNilPasswordImportsEncryptedPkcs8DerEmptyPassphraseKey;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ec256_enc_empty_der']), nil);
  CheckTrue(SignedVerifies(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey,
    DecodeHex(FKeys.Values['ec256_pub'])), 'nil is the empty passphrase (DER)');
end;

procedure TTestNativeCryptoProvider.TestNilPasswordImportsEncryptedPkcs8PemEmptyPassphraseKey;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ec256_enc_empty_pem']), nil);
  CheckTrue(SignedVerifies(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey,
    DecodeHex(FKeys.Values['ec256_pub'])), 'nil is the empty passphrase (PEM)');
end;

procedure TNativeCryptoProviderTestBase.CheckPortableNamesUnsupportedEncryption(
  const AField: string);

  procedure CheckFor(const APassword: ISecretBuffer; const AWhat: string);
  var
    LFailure: string;
  begin
    LFailure := ImportFailure(Portable, DecodeHex(FKeys.Values[AField]), APassword);
    CheckTrue(Pos('ENotSupportedTlsLibException: ', LFailure) = 1, AWhat + ': ' + LFailure);
    CheckTrue(Pos('unsupported encryption', LFailure) > 0, AWhat + ': ' + LFailure);
  end;

begin
  // no password is blamed for an encryption the portable provider cannot run
  CheckFor(nil, AField + ' nil');
  CheckFor(TSecretBuffer.FromString(''), AField + ' zero-length');
  CheckFor(TSecretBuffer.FromString('x'), AField + ' non-empty');
end;

procedure TTestNativeCryptoProvider.TestPortableNamesAPkcs12PbeAsUnsupported;
begin
  // pbeWithSHA1And3-KeyTripleDES-CBC: no engine for the algorithm
  CheckPortableNamesUnsupportedEncryption('ec256_enc_empty_p12pbe_der');
end;

procedure TTestNativeCryptoProvider.TestPortableNamesAnUnmappedPbes2CipherAsUnsupported;
begin
  // DES-EDE3-CBC: the portable provider raises while resolving the cipher
  CheckPortableNamesUnsupportedEncryption('ec256_enc_empty_des3_der');
end;

procedure TTestNativeCryptoProvider.TestPortableNamesAnUnmappedPbes2PrfAsUnsupported;
begin
  // hmacWithMD5: the portable provider raises while resolving the PRF during decryption
  CheckPortableNamesUnsupportedEncryption('ec256_enc_empty_prfmd5_der');
end;

procedure TTestNativeCryptoProvider.TestPortableNamesScryptAsUnsupported;
begin
  // id-scrypt as the PBES2 key-derivation function
  CheckPortableNamesUnsupportedEncryption('ec256_enc_empty_scrypt_der');
end;

procedure TTestNativeCryptoProvider.TestComposedImportsAnOsOnlyPbeKeyUnderEmptyPassphrase;
var
  LKey: ISigningKey;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.ECDSA_SECP256R1_SHA256) then
    Exit;
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['ec256_enc_empty_p12pbe_der']), nil);
  CheckTrue(SignedVerifies(TSignatureScheme.ECDSA_SECP256R1_SHA256, LKey,
    DecodeHex(FKeys.Values['ec256_pub'])), 'the OS module decrypts the PBE under the empty passphrase');
end;

procedure TTestNativeCryptoProvider.TestNilPasswordOnRealPasswordKeyReportsPasswordRequired;
var
  LMsg: string;
begin
  LMsg := 'imported';
  try
    Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_enc_der']), nil);
  except
    on E: EArgumentTlsLibException do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('password', LMsg) > 0, 'a key needing a password names it; got: ' + LMsg);
end;

procedure TTestNativeCryptoProvider.TestPssSpkiVerifiesNoRsaPkcs1Signature;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  CheckTrue(SignedVerifies(TSignatureScheme.RSA_PKCS1_SHA256, LKey,
    DecodeHex(FKeys.Values['rsa_pub'])), 'control: the signature verifies under the rsaEncryption SPKI');
  CheckFalse(SignedVerifies(TSignatureScheme.RSA_PKCS1_SHA256, LKey,
    DecodeHex(FKeys.Values['rsa_pub_pss'])), 'the same key as id-RSASSA-PSS verifies nothing');
end;

procedure TTestNativeCryptoProvider.TestPssSpkiVerifiesNoRsaPssRsaeSignature;
var
  LKey: ISigningKey;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_pkcs8_der']), nil);
  CheckTrue(SignedVerifies(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey,
    DecodeHex(FKeys.Values['rsa_pub'])), 'control: the signature verifies under the rsaEncryption SPKI');
  CheckFalse(SignedVerifies(TSignatureScheme.RSA_PSS_RSAE_SHA256, LKey,
    DecodeHex(FKeys.Values['rsa_pub_pss'])), 'the same key as id-RSASSA-PSS verifies nothing');
end;

procedure TTestNativeCryptoProvider.TestPkcs12MultiKeyStillFailsClosed;
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

function TNativeCryptoProviderTestBase.ImportFailure(const AProvider: ICryptoProvider;
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

procedure TTestNativeCryptoProvider.TestPemFirstPrivateKeyBlockDecidesImport;
var
  LPortable: ICryptoProvider;
  LData: TBytes;
  LNativeKey, LPortableKey: ISigningKey;
  LFailure: string;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.ECDSA_SECP256R1_SHA256) then
    Exit;
  LPortable := Portable;
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

procedure TTestNativeCryptoProvider.TestBuilderRejectsWrongLeafForNativeKey;
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
  // the guard under test is for a natively held key; a platform that adopts none skips
  if not IsNativeKey(Crypto, LCredential.PrivateKey) then
  begin
    SkipTest('the platform adopts no native PKCS#12 key');
    Exit;
  end;
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

procedure TTestNativeCryptoProvider.TestBuilderAcceptsNativeCredential;
var
  LCredential: TImportedCredential;
  LGood: TTlsCredential;
begin
  if not NativeSigningOrSkip(Crypto, TSignatureScheme.RSA_PSS_RSAE_SHA256) then
    Exit;
  LCredential := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(SPassword));
  if not IsNativeKey(Crypto, LCredential.PrivateKey) then
  begin
    SkipTest('the platform adopts no native PKCS#12 key');
    Exit;
  end;
  LGood.CertificateChain := LCredential.CertificateChain;
  LGood.PrivateKey := LCredential.PrivateKey;
  // the native key's exported SPKI matches its own leaf, so the guard passes and Build succeeds
  CheckTrue(BuildServerConfig(LGood) <> nil,
    'a native credential whose key owns its leaf builds');
end;

procedure TTestNativeCryptoProvider.TestPreferredSchemesCopySharesPublicKey;
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

procedure TTestNativeCryptoProvider.TestImportLeavesCallerKeyBytesIntact;
const
  // native as given (PKCS#8), native after wrapping (PKCS#1, SEC1), and the portable fallback,
  // which re-reads the very same input bytes
  Fields: array [0 .. 3] of string = ('rsa_pkcs8_der', 'rsa_pkcs1_der', 'ec256_sec1_der',
    'ed25519_pkcs8_der');
  // each key is native exactly when the backend report says its scheme is
  Schemes: array [0 .. 3] of TSignatureScheme = (TSignatureScheme.RSA_PSS_RSAE_SHA256,
    TSignatureScheme.RSA_PSS_RSAE_SHA256, TSignatureScheme.ECDSA_SECP256R1_SHA256,
    TSignatureScheme.ED25519);
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
    CheckEquals(IsNativeSigning(Crypto, Schemes[LI]), IsNativeKey(Crypto, LKey),
      Fields[LI] + ' takes the backend the report names for its scheme');
    CheckEqualBytes(Fields[LI] + ' leaves the caller''s bytes untouched', LCopy, LData);
  end;
end;

{ TTestOverlayCryptoProvider }

procedure TTestOverlayCryptoProvider.TestSuppliedHpkeFacetIsKept;
var
  LSupplied: IHpkeCrypto;
  LBase, LOverlay: ICryptoProvider;
begin
  LSupplied := TStubHpke.Create as IHpkeCrypto;
  LBase := BaseWithHpke(LSupplied);
  LOverlay := TOverlayCryptoProvider.Create(LBase, nil, nil, nil) as ICryptoProvider;
  CheckTrue(LOverlay.Hpke = LSupplied, 'the overlay returns the caller-supplied HPKE facet');
end;

procedure TTestOverlayCryptoProvider.TestHpkeCompositionOverOtherPrimitivesIsKept;
var
  LOtherProvider: ICryptoProvider;
  LSupplied: IHpkeCrypto;
  LBase, LOverlay: ICryptoProvider;
begin
  LOtherProvider := BaseWithHpke(nil);
  LSupplied := THpkeComposition.Create(LOtherProvider.Primitives) as IHpkeCrypto;
  LBase := BaseWithHpke(LSupplied);
  LOverlay := TOverlayCryptoProvider.Create(LBase, nil, nil, nil) as ICryptoProvider;
  CheckTrue(LOverlay.Hpke = LSupplied,
    'a composition over primitives other than the base''s is the caller''s facet');
end;

procedure TTestOverlayCryptoProvider.TestDefaultHpkeIsRebuiltOverOverlayPrimitives;
var
  LBase, LOverlay: ICryptoProvider;
  LPrimitives: ICryptoPrimitives;
  LComposition: IHpkeComposition;
begin
  LBase := BaseWithHpke(nil);
  LPrimitives := TForwardingCryptoPrimitives.Create(LBase.Primitives) as ICryptoPrimitives;
  LOverlay := TOverlayCryptoProvider.Create(LBase, LPrimitives, nil, nil) as ICryptoProvider;
  CheckTrue(Supports(LOverlay.Hpke, IHpkeComposition, LComposition),
    'the overlay''s HPKE is still the default composition');
  CheckTrue(LComposition.ComposedOver = LPrimitives,
    'the default composition is rebuilt over the overlay''s primitives');
end;

procedure TTestOverlayCryptoProvider.TestComposeKeepsSuppliedHpkeFacet;
var
  LSupplied: IHpkeCrypto;
begin
  LSupplied := TStubHpke.Create as IHpkeCrypto;
  CheckTrue(Composed(BaseWithHpke(LSupplied)).Hpke = LSupplied,
    'Compose keeps a supplied HPKE facet');
end;

procedure TTestOverlayCryptoProvider.TestComposeKeepsHpkeCompositionOverOtherPrimitives;
var
  LSupplied: IHpkeCrypto;
begin
  LSupplied := THpkeComposition.Create(BaseWithHpke(nil).Primitives) as IHpkeCrypto;
  CheckTrue(Composed(BaseWithHpke(LSupplied)).Hpke = LSupplied,
    'Compose keeps a composition over other primitives');
end;

procedure TTestOverlayCryptoProvider.TestComposeDefaultHpkeRidesTheResultPrimitives;
var
  LResult: ICryptoProvider;
  LComposition: IHpkeComposition;
begin
  LResult := Composed(BaseWithHpke(nil));
  CheckTrue(Supports(LResult.Hpke, IHpkeComposition, LComposition),
    'the default HPKE is a composition');
  CheckTrue(LComposition.ComposedOver = LResult.Primitives,
    'the default composition rides the result''s own primitives');
end;

procedure TTestOverlayCryptoProvider.TestComposedReportMatchesSuppliedHpkeFacet;
begin
  CheckHpkeFacetReport(Composed(BaseWithHpke(TStubHpke.Create as IHpkeCrypto)));
end;

procedure TTestOverlayCryptoProvider.TestComposedReportMatchesHpkeCompositionOverOtherPrimitives;
begin
  CheckHpkeFacetReport(Composed(BaseWithHpke(
    THpkeComposition.Create(BaseWithHpke(nil).Primitives) as IHpkeCrypto)));
end;

procedure TTestOverlayCryptoProvider.TestComposedReportMatchesDefaultHpkeComposition;
begin
  CheckHpkeFacetReport(Composed(BaseWithHpke(nil)));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestNativeCryptoProvider);
  RegisterTest(TTestOverlayCryptoProvider);
{$ELSE}
  RegisterTest(TTestNativeCryptoProvider.Suite);
  RegisterTest(TTestOverlayCryptoProvider.Suite);
{$ENDIF FPC}

{$IFDEF TLSLIB_MSWINDOWS}
{$IFDEF FPC}
  RegisterTest(TTestWindowsNativeCryptoProvider);
{$ELSE}
  RegisterTest(TTestWindowsNativeCryptoProvider.Suite);
{$ENDIF FPC}
{$ENDIF TLSLIB_MSWINDOWS}

end.
