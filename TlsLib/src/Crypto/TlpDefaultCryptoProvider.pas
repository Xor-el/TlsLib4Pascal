{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpDefaultCryptoProvider;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  Rtti,
  SyncObjs,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIDigest,
  ClpDigestUtilities,
  ClpIMac,
  ClpHMac,
  ClpIDerivationParameters,
  ClpIHkdfParameters,
  ClpHkdfParameters,
  ClpHkdfBytesGenerator,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIBlockCipher,
  ClpIAeadCipher,
  ClpIGcmMultiplier,
  ClpBasicGcmMultiplier,
  ClpGcmBlockCipher,
  ClpAesBitSlicedEngine,
  ClpAesUtilities,
  ClpChaCha20Poly1305,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpIAsymmetricCipherKeyPair,
  ClpIKeyGenerationParameters,
  ClpX25519Parameters,
  ClpIX25519Parameters,
  ClpCustomNamedCurves,
  ClpECParameters,
  ClpIECParameters,
  ClpIECCommon,
  ClpECGenerators,
  ClpIECGenerators,
  ClpECDHBasicAgreement,
  ClpIECDHBasicAgreement,
  ClpMlKemParameters,
  ClpIMlKemParameters,
  ClpMlKemGenerators,
  ClpIMlKemGenerators,
  ClpMlKemEncapsulator,
  ClpIKemEncapsulator,
  ClpMlKemDecapsulator,
  ClpIKemDecapsulator,
  ClpISigner,
  ClpSignerUtilities,
  ClpIAsymmetricKeyParameter,
  ClpPublicKeyFactory,
  ClpPrivateKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpIOpenSslPasswordFinder,
  ClpIOpenSslPemReader,
  ClpOpenSslPemReader,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpIPkcsRsaAsn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpISecECAsn1Objects,
  ClpSecECAsn1Objects,
  ClpX9ObjectIdentifiers,
  ClpSecObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpRsaParameters,
  ClpX509CertificateParser,
  ClpIX509CertificateParser,
  ClpIX509Certificate,
  ClpIX509CertificateEntry,
  ClpIAsymmetricKeyEntry,
  ClpIPkcs12Store,
  ClpIPkcs12StoreBuilder,
  ClpPkcs12StoreBuilder,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixCertPathValidator,
  ClpTrustAnchor,
  ClpIPkixTypes,
  ClpOcspProtocolObjects,
  ClpIOcspProtocolObjects,
  ClpOcspGenerators,
  ClpIOcspGenerators,
  ClpX509ObjectIdentifiers,
  ClpX509CrlParser,
  ClpIX509CrlParser,
  ClpIX509Crl,
  ClpCryptoLibTypes,
  ClpNullable,
  ClpValueHelper,
  ClpCryptoLibExceptions,
  TlpCryptoAlgorithms,
  TlpBinaryPrimitives,
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpICryptoProvider,
  TlpISigningKey,
  TlpTlsCredential,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlpTlsAlert,
  TlpDateTimeUtilities,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The default <see cref="ICryptoProvider" />, backed by CryptoLib4Pascal.
  /// </summary>
  TDefaultCryptoProvider = class(TInterfacedObject, ICryptoProvider)
  strict private
  const
    // RFC 7633 id-pe-tlsfeature
    TlsFeatureExtensionOid = '1.3.6.1.5.5.7.1.24';
    // PKCS#1 id-RSASSA-PSS: the restricted RSA-PSS key type (RFC 4055)
    RsaSsaPssKeyOid = '1.2.840.113549.1.1.10';
  type
    // parsed trust anchors keyed by a digest of the anchor set, so a reused
    // config does not re-parse its (possibly large) anchor store on every verify
    TTrustAnchorRing = record
    strict private
    const
      TrustAnchorCacheSize = Int32(8);
    strict private
      FKeys: TArray<TBytes>;
      FSets: TArray<TArray<ITrustAnchor>>;
      FCount: Int32;
      FNext: Int32;
    public
      class function Init: TTrustAnchorRing; static;
      function TryGet(const AKey: TBytes;
        out AAnchors: TArray<ITrustAnchor>): Boolean;
      procedure Remember(const AKey: TBytes;
        const AAnchors: TArray<ITrustAnchor>);
    end;
  class var
    FTrustAnchors: TTrustAnchorRing;
    FTrustAnchorLock: TCriticalSection;
    FShared: ICryptoProvider;
    FSharedLock: TCriticalSection;
  var
    FHasHardwareAes: Boolean;
    FRandom: ISecureRandom;
    function ResolveDigest(AAlgorithm: THashAlgorithm): IDigest;
    function TrustAnchorKey(const ATrustAnchors: TArray<TBytes>): TBytes;
    class function SignerMechanismForScheme(AScheme: TSignatureScheme): string; static;
    /// <summary>
    /// Whether AResponse is signed by the certificate issuer itself or by a
    /// responder the issuer delegated to (RFC 6960 sec. 4.2.2.2).
    /// </summary>
    class function OcspResponseAuthorised(const AResponse: IBasicOcspResp;
      const AIssuerCert: IX509Certificate;
      const AIssuerPublicKey: IAsymmetricKeyParameter;
      AValidityDate: TDateTime): Boolean; static;
    class function OcspDelegatedResponder(const AResponderCert,
      AIssuerCert: IX509Certificate;
      const AIssuerPublicKey: IAsymmetricKeyParameter;
      AValidityDate: TDateTime): Boolean; static;
  public
    constructor Create;
    class constructor Create;
    class destructor Destroy;
    /// <summary>A process-wide, lazily-created default provider: the fallback when no provider
    /// is injected, and the hasher for memo signatures. One CSPRNG seed for the process, shared
    /// (the provider is a stateless service factory), so no per-connection provider is stood up.</summary>
    class function Shared: ICryptoProvider; static;

    function GetRandom: IRandom;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
    function ImportSigningKey(const AData: TBytes): ISigningKey; overload;
    function ImportSigningKey(const AData: TBytes;
      const APassword: string): ISigningKey; overload;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
    function LoadCertificateChain(const AData: TBytes): TArray<TBytes>;
    function IsWellFormedCertificate(const ADer: TBytes): Boolean;
    function ImportPkcs12(const AData: TBytes;
      const APassword: string): TTlsCredential;
    function CertificatePublicKeyInfo(const ACertificateDer: TBytes): TBytes;
    function CertificateDnsNames(const ACertificateDer: TBytes): TArray<string>;
    function CertificateIpAddresses(const ACertificateDer: TBytes): TArray<TBytes>;
    procedure ValidateCertificatePath(const AChain, ATrustAnchors: TArray<TBytes>;
      const AValidationTimeUtc: TDateTime);
    function ValidateOcspStaple(const ALeafCert, AIssuerCert,
      AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
      out AStatus: TOcspStatus;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
      out ARequestDer: TBytes): Boolean;
    function TryGetOcspResponderUrl(const ACert: TBytes;
      out AUrl: string): Boolean;
    function TryGetCrlDistributionPoints(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      out ARevoked: Boolean): Boolean;
    function CertificatePeerInfo(const ACertificateDer: TBytes;
      out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
    function CertificateTlsFeatures(const ACert: TBytes;
      out AFeatures: TArray<UInt16>): Boolean;
    function CertificateKeyUsagePermits(const ACertificateDer: TBytes;
      AUsage: TCertKeyUsage; out APermitted: Boolean): Boolean;
    function CertificateHasRsaPssKey(const ACertificateDer: TBytes;
      out AIsRsaPss: Boolean): Boolean;
    function CertificateKeyKind(const ACertificateDer: TBytes;
      out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
    function CreateKeyAgreement(AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
    function CreateKem(AAlgorithm: TKemAlgorithm): IKem;

    function HasHardwareAes: Boolean;
  end;

implementation

resourcestring
  SUnhandledAlgorithm = 'the provider has no backend for algorithm enum value %d';
  SInvalidKeySize = 'AEAD key size %d does not match the required %d bytes';
  SInvalidNonceSize = 'AEAD nonce size %d does not match the required %d bytes';
  SAeadAuthFailed = 'AEAD authentication failed';
  SDegenerateSharedSecret = 'the peer key produced a degenerate all-zero shared secret';
  SInvalidPeerPoint = 'the peer public point is not a valid curve point';
  SInvalidCiphertext = 'the peer ciphertext could not be decapsulated';
  SBadCertificate = 'a certificate in the chain could not be parsed';
  SCertificateExpired = 'a certificate in the chain is outside its validity window';
  SUntrustedChain = 'the certificate chain does not reach a trusted anchor';
  SMalformedPrivateKey = 'the private key could not be parsed in any supported encoding';
  SUnsupportedKeyAlgorithm = 'the private key uses an algorithm this library cannot sign with';
  SForeignSigningKey = 'the signing key was not produced by this provider';
  SMalformedCertificate = 'a certificate could not be parsed as PEM or DER';
  SNoCertificatesFound = 'no certificates were found in the input';
  SMalformedPkcs12 = 'the PKCS#12 blob could not be read (wrong password, bad MAC, or malformed)';
  SPkcs12NoKeyEntry = 'the PKCS#12 blob holds no private-key entry';
  SPkcs12MultipleKeys =
    'the PKCS#12 blob holds more than one private-key entry; it is ambiguous for a ' +
    'single credential — split it or import the intended identity explicitly';
  SPkcs12NoChain = 'the PKCS#12 private-key entry has no certificate chain';

type
  TAeadKind = (AesGcm, ChaChaPoly);

  TRandomAdapter = class(TInterfacedObject, IRandom)
  strict private
  var
    FRandom: ISecureRandom;
  public
    constructor Create;
    procedure NextBytes(var ABuffer: TBytes);
    function GenerateBytes(ALength: Int32): TBytes;
  end;

  THashAdapter = class(TInterfacedObject, IHash)
  strict private
  var
    FDigest: IDigest;
  public
    constructor Create(const ADigest: IDigest);
    function AlgorithmName: string;
    function HashSize: Int32;
    function BlockSize: Int32;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function DoFinal: TBytes;
    procedure Reset;
    function Clone: IHash;
  end;

  THmacAdapter = class(TInterfacedObject, IHmac)
  strict private
  var
    FMac: IMac;
  public
    constructor Create(const ADigest: IDigest);
    function AlgorithmName: string;
    function MacSize: Int32;
    procedure Init(const AKey: ISecretBuffer);
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function DoFinal: TBytes;
    procedure Reset;
  end;

  THkdfAdapter = class(TInterfacedObject, IHkdf)
  strict private
  var
    FAlgorithm: THashAlgorithm;
    function NewDigest: IDigest;
  public
    constructor Create(AAlgorithm: THashAlgorithm);
    function Extract(const ASalt: TBytes; const AIkm: ISecretBuffer): ISecretBuffer;
    function Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
      ALength: Int32): ISecretBuffer;
  end;

  TAeadAdapter = class(TInterfacedObject, IAead)
  strict private
  var
    FKind: TAeadKind;
    FAlgorithmName: string;
    FKeySize, FNonceSize, FTagSize: Int32;
    FHasHardwareAes: Boolean;
    FKey: ISecretBuffer;
    FCipher: IAeadCipher;
    function NewCipher: IAeadCipher;
    function Process(AForEncryption: Boolean; const ANonce, AAad, AInput: TBytes): TBytes;
  public
    constructor Create(AKind: TAeadKind; const AAlgorithmName: string;
      AKeySize, ANonceSize, ATagSize: Int32; AHasHardwareAes: Boolean);
    destructor Destroy; override;
    function AlgorithmName: string;
    function UsageCategory: TAeadUsageCategory;
    function KeySize: Int32;
    function NonceSize: Int32;
    function TagSize: Int32;
    function Overhead: Int32;
    procedure Init(const AKey: ISecretBuffer);
    function Seal(const ANonce, AAad, APlaintext: TBytes): TBytes;
    function Open(const ANonce, AAad, ACiphertext: TBytes): TBytes;
  end;

  // X25519 key agreement wrapped as a group's IKeyAgreement.
  TX25519Agreement = class(TInterfacedObject, IKeyAgreement)
  strict private
  var
    FRandom: ISecureRandom;
  public
    constructor Create(const ARandom: ISecureRandom);
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    function Agree(const APrivateKey: ISecretBuffer;
      const APeerPublicKey: TBytes): ISecretBuffer;
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
  end;

  // A NIST prime-curve ECDH key agreement over the constant-time custom Nat curves.
  TNistEcAgreement = class(TInterfacedObject, IKeyAgreement)
  strict private
  var
    FName: string;
    FRandom: ISecureRandom;
    FDomain: IECDomainParameters;
    FFieldSize: Int32;
    procedure GeneratePair(out APriv: IECPrivateKeyParameters;
      out APub: IECPublicKeyParameters);
    function WrapPeer(const APeerPub: TBytes): IECPublicKeyParameters;
    function AgreeParams(const APriv: IECPrivateKeyParameters;
      const APeer: IECPublicKeyParameters): ISecretBuffer;
  public
    constructor Create(const AName: string; const ARandom: ISecureRandom);
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    function Agree(const APrivateKey: ISecretBuffer;
      const APeerPublicKey: TBytes): ISecretBuffer;
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
  end;

  TKemAdapter = class(TInterfacedObject, IKem)
  strict private
  var
    FName: string;
    FParams: IMlKemParameters;
    FRandom: ISecureRandom;
  public
    constructor Create(const AName: string; const AParams: IMlKemParameters;
      const ARandom: ISecureRandom);
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    procedure Encapsulate(const APeerPublicKey: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APrivateKey: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
  end;

  TSignatureSignerAdapter = class(TInterfacedObject, ISignatureSigner)
  strict private
  var
    FSigner: ISigner;
    FScheme: string;
  public
    constructor Create(const ASigner: ISigner; const AScheme: string);
    function AlgorithmName: string;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Sign: TBytes;
  end;

  TSignatureVerifierAdapter = class(TInterfacedObject, ISignatureVerifier)
  strict private
  var
    FSigner: ISigner;
    FScheme: string;
  public
    constructor Create(const ASigner: ISigner; const AScheme: string);
    function AlgorithmName: string;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Verify(const ASignature: TBytes): Boolean;
  end;

  // Supplies a stored password to the PEM reader for encrypted PEM keys.
  TStaticPasswordFinder = class(TInterfacedObject, IOpenSslPasswordFinder)
  strict private
  var
    FPassword: TArray<Char>;
  public
    constructor Create(const APassword: string);
    function GetPassword: TArray<Char>;
  end;

  // The provider-internal face of an imported signing key: it hands back the parsed
  // key parameter (parsed and validated once at import, reused for every sign) plus the
  // canonical PKCS#8 bytes. Kept off ISigningKey so no key material appears on the
  // public surface.
  IProviderSigningKey = interface(IInterface)
    ['{6A7F0E2C-1B94-4D8A-9F3C-2E5B7C8D1A64}']
    function PrivateKeyInfo: ISecretBuffer;
    function KeyParameter: IAsymmetricKeyParameter;
  end;

  TSigningKey = class(TInterfacedObject, ISigningKey, IProviderSigningKey)
  strict private
  var
    FPrivateKeyInfo: ISecretBuffer;
    FKeyParameter: IAsymmetricKeyParameter;
    FCapableSchemes: TArray<TSignatureScheme>;
  public
    constructor Create(const APrivateKeyInfo: ISecretBuffer;
      const AKeyParameter: IAsymmetricKeyParameter;
      const ACapableSchemes: TArray<TSignatureScheme>);
    function CapableSchemes: TArray<TSignatureScheme>;
    function WithPreferredSchemes(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
    function PrivateKeyInfo: ISecretBuffer;
    function KeyParameter: IAsymmetricKeyParameter;
  end;

  // The shape of a DER-encoded private key, distinguished by its first inner elements.
  TDerKeyShape = (Unknown, Pkcs8, EncryptedPkcs8, Pkcs1Rsa, Sec1Ec);

  // Parses and normalizes imported credential key material to canonical PKCS#8 and
  // derives the schemes a key can sign with. All backend parsing stays here, inside
  // the provider boundary.
  TCredentialImport = class sealed(TObject)
  strict private
    class function DetectDerKeyShape(const AData: TBytes): TDerKeyShape; static;
    class function SchemesForKeyInfo(const AInfo: IPrivateKeyInfo)
      : TArray<TSignatureScheme>; static;
    class function KeyParamFromPem(const AData: TBytes; const APassword: string;
      AHasPassword: Boolean): IAsymmetricKeyParameter; static;
    class function KeyParamFromDer(const AData: TBytes; const APassword: string;
      AHasPassword: Boolean): IAsymmetricKeyParameter; static;
  public
    /// <summary>The password as the character array the PEM/PKCS#12 backends expect;
    /// empty yields nil (no password). Wipe it with WipePasswordChars after use.</summary>
    class function PasswordChars(const APassword: string): TArray<Char>; static;
    /// <summary>Zeroes a password character array in place.</summary>
    class procedure WipePasswordChars(var APassword: TArray<Char>); static;
    class function IsPemArmored(const AData: TBytes): Boolean; static;
    class function ImportKey(const AData: TBytes; const APassword: string;
      AHasPassword: Boolean): ISigningKey; static;
    /// <summary>The one signing-key construction path: normalizes a parsed private-key
    /// parameter to canonical PKCS#8 (held wipeably), derives its schemes, and wraps it.
    /// Both raw-key and PKCS#12 import funnel through here. Raises ENotSupported for a key
    /// algorithm this library cannot sign with.</summary>
    class function SigningKeyFromParam(
      const AKeyParam: IAsymmetricKeyParameter): ISigningKey; static;
  end;

{ TRandomAdapter }

constructor TRandomAdapter.Create;
begin
  inherited Create;
  FRandom := TSecureRandom.Create;
end;

procedure TRandomAdapter.NextBytes(var ABuffer: TBytes);
begin
  FRandom.NextBytes(ABuffer);
end;

function TRandomAdapter.GenerateBytes(ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  if ALength > 0 then
    FRandom.NextBytes(Result);
end;

{ THashAdapter }

constructor THashAdapter.Create(const ADigest: IDigest);
begin
  inherited Create;
  FDigest := ADigest;
end;

function THashAdapter.AlgorithmName: string;
begin
  Result := FDigest.AlgorithmName;
end;

function THashAdapter.HashSize: Int32;
begin
  Result := FDigest.GetDigestSize;
end;

function THashAdapter.BlockSize: Int32;
begin
  Result := FDigest.GetByteLength;
end;

procedure THashAdapter.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  FDigest.BlockUpdate(AData, AOffset, ALength);
end;

function THashAdapter.DoFinal: TBytes;
begin
  Result := FDigest.DoFinal;
end;

procedure THashAdapter.Reset;
begin
  FDigest.Reset;
end;

function THashAdapter.Clone: IHash;
begin
  Result := THashAdapter.Create(FDigest.Clone);
end;

{ THmacAdapter }

constructor THmacAdapter.Create(const ADigest: IDigest);
begin
  inherited Create;
  FMac := THMac.Create(ADigest);
end;

function THmacAdapter.AlgorithmName: string;
begin
  Result := FMac.AlgorithmName;
end;

function THmacAdapter.MacSize: Int32;
begin
  Result := FMac.GetMacSize;
end;

procedure THmacAdapter.Init(const AKey: ISecretBuffer);
var
  LKeyBytes: TBytes;
begin
  LKeyBytes := AKey.ToBytes;
  try
    FMac.Init(TKeyParameter.Create(LKeyBytes) as IKeyParameter);
  finally
    TSecureMemory.WipeBytes(LKeyBytes);
  end;
end;

procedure THmacAdapter.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  FMac.BlockUpdate(AData, AOffset, ALength);
end;

function THmacAdapter.DoFinal: TBytes;
begin
  Result := FMac.DoFinal;
end;

procedure THmacAdapter.Reset;
begin
  FMac.Reset;
end;

{ THkdfAdapter }

constructor THkdfAdapter.Create(AAlgorithm: THashAlgorithm);
begin
  inherited Create;
  FAlgorithm := AAlgorithm;
end;

function THkdfAdapter.NewDigest: IDigest;
begin
  Result := TDigestUtilities.GetDigest(TEnumUtilities.GetName<THashAlgorithm>(FAlgorithm));
end;

function THkdfAdapter.Extract(const ASalt: TBytes;
  const AIkm: ISecretBuffer): ISecretBuffer;
var
  LMac: IMac;
  LSalt, LIkmBytes, LPrk: TBytes;
begin
  LMac := THMac.Create(NewDigest) as IMac;
  LSalt := ASalt;
  if System.Length(LSalt) = 0 then
    SetLength(LSalt, LMac.GetMacSize); // HashLen zero bytes
  LMac.Init(TKeyParameter.Create(LSalt) as IKeyParameter);
  LIkmBytes := AIkm.ToBytes;
  try
    LMac.BlockUpdate(LIkmBytes, 0, System.Length(LIkmBytes));
    LPrk := LMac.DoFinal;
    try
      Result := TSecretBuffer.From(LPrk);
    finally
      TSecureMemory.WipeBytes(LPrk);
    end;
  finally
    TSecureMemory.WipeBytes(LIkmBytes);
  end;
end;

function THkdfAdapter.Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
  ALength: Int32): ISecretBuffer;
var
  LGen: THkdfBytesGenerator;
  LParams: IHkdfParameters;
  LPrkBytes, LOkm: TBytes;
begin
  LGen := THkdfBytesGenerator.Create(NewDigest);
  LPrkBytes := APrk.ToBytes;
  try
    LParams := THkdfParameters.SkipExtractParameters(LPrkBytes, AInfo);
    LGen.Init(LParams as IDerivationParameters);
    LOkm := nil;
    SetLength(LOkm, ALength);
    if ALength > 0 then
      LGen.GenerateBytes(LOkm, 0, ALength);
    try
      Result := TSecretBuffer.From(LOkm);
    finally
      TSecureMemory.WipeBytes(LOkm);
    end;
  finally
    TSecureMemory.WipeBytes(LPrkBytes);
    LGen.Free;
  end;
end;

{ TAeadAdapter }

constructor TAeadAdapter.Create(AKind: TAeadKind; const AAlgorithmName: string;
  AKeySize, ANonceSize, ATagSize: Int32; AHasHardwareAes: Boolean);
begin
  inherited Create;
  FKind := AKind;
  FAlgorithmName := AAlgorithmName;
  FKeySize := AKeySize;
  FNonceSize := ANonceSize;
  FTagSize := ATagSize;
  FHasHardwareAes := AHasHardwareAes;
end;

destructor TAeadAdapter.Destroy;
begin
  // releasing the retained cipher lets its engine wipe round-key/subkey state
  FCipher := nil;
  inherited Destroy;
end;

function TAeadAdapter.AlgorithmName: string;
begin
  Result := FAlgorithmName;
end;

function TAeadAdapter.UsageCategory: TAeadUsageCategory;
begin
  if FKind = TAeadKind.AesGcm then
    Result := TAeadUsageCategory.AesGcm
  else
    Result := TAeadUsageCategory.ChaCha20;
end;

function TAeadAdapter.KeySize: Int32;
begin
  Result := FKeySize;
end;

function TAeadAdapter.NonceSize: Int32;
begin
  Result := FNonceSize;
end;

function TAeadAdapter.TagSize: Int32;
begin
  Result := FTagSize;
end;

function TAeadAdapter.Overhead: Int32;
begin
  Result := FTagSize;
end;

function TAeadAdapter.NewCipher: IAeadCipher;
begin
  case FKind of
    TAeadKind.AesGcm:
      if FHasHardwareAes then
        Result := TGcmBlockCipher.Create(TAesUtilities.CreateEngine(),
          TBasicGcmMultiplier.Create as IGcmMultiplier)
      else
        // no-hardware path: constant-time bitsliced AES + constant-time software GHASH
        Result := TGcmBlockCipher.Create(TAesBitSlicedEngine.Create as IBlockCipher,
          TBasicGcmMultiplier.Create as IGcmMultiplier);
    TAeadKind.ChaChaPoly:
      Result := TChaCha20Poly1305.Create;
  else
    Result := nil;
  end;
end;

procedure TAeadAdapter.Init(const AKey: ISecretBuffer);
begin
  if AKey.Len <> FKeySize then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidKeySize,
      [AKey.Len, FKeySize]);
  FKey := AKey;
end;

function TAeadAdapter.Process(AForEncryption: Boolean;
  const ANonce, AAad, AInput: TBytes): TBytes;
var
  LCipher: IAeadCipher;
  LParams: IAeadParameters;
  LKeyBytes, LOut: TBytes;
  LLen: Int32;
begin
  Result := nil;
  if System.Length(ANonce) <> FNonceSize then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidNonceSize,
      [System.Length(ANonce), FNonceSize]);
  // the driver installs this adapter for one direction only (read or write); the
  // connection is already single-threaded (unsynchronized FSeq), so reuse is safe
  if FCipher = nil then
    FCipher := NewCipher;
  LCipher := FCipher;
  LKeyBytes := FKey.ToBytes;
  try
    LParams := TAeadParameters.Create(TKeyParameter.Create(LKeyBytes) as IKeyParameter,
      FTagSize * 8, ANonce, AAad) as IAeadParameters;
    LCipher.Init(AForEncryption, LParams);
    LOut := nil;
    SetLength(LOut, LCipher.GetOutputSize(System.Length(AInput)));
    LLen := LCipher.ProcessBytes(AInput, 0, System.Length(AInput), LOut, 0);
    LLen := LLen + LCipher.DoFinal(LOut, LLen);
    SetLength(LOut, LLen);
    Result := LOut;
  finally
    TSecureMemory.WipeBytes(LKeyBytes);
  end;
end;

function TAeadAdapter.Seal(const ANonce, AAad, APlaintext: TBytes): TBytes;
begin
  Result := Process(True, ANonce, AAad, APlaintext);
end;

function TAeadAdapter.Open(const ANonce, AAad, ACiphertext: TBytes): TBytes;
begin
  try
    Result := Process(False, ANonce, AAad, ACiphertext);
  except
    on E: EInvalidCipherTextCryptoLibException do
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadRecordMac,
        @SAeadAuthFailed);
  end;
end;

{ TX25519Agreement }

constructor TX25519Agreement.Create(const ARandom: ISecureRandom);
begin
  inherited Create;
  FRandom := ARandom;
end;

function TX25519Agreement.Name: string;
begin
  Result := 'X25519';
end;

procedure TX25519Agreement.GenerateKeyPair(out APrivateKey: ISecretBuffer;
  out APublicKey: TBytes);
var
  LX25519: IX25519PrivateKeyParameters;
  LPrivBytes: TBytes;
begin
  LX25519 := TX25519PrivateKeyParameters.Create(FRandom);
  APublicKey := LX25519.GeneratePublicKey.GetEncoded;
  LPrivBytes := LX25519.GetEncoded;
  try
    APrivateKey := TSecretBuffer.From(LPrivBytes);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

function TX25519Agreement.Agree(const APrivateKey: ISecretBuffer;
  const APeerPublicKey: TBytes): ISecretBuffer;
var
  LPriv: IX25519PrivateKeyParameters;
  LPrivBytes, LSecret: TBytes;
begin
  LPrivBytes := APrivateKey.ToBytes;
  try
    LPriv := TX25519PrivateKeyParameters.Create(LPrivBytes);
    LSecret := nil;
    SetLength(LSecret, TX25519PublicKeyParameters.KeySize);
    try
      try
        LPriv.GenerateSecret(TX25519PublicKeyParameters.Create(APeerPublicKey)
          as IX25519PublicKeyParameters, LSecret, 0);
      except
        // a small-order peer key yields an all-zero shared secret; the backend
        // rejects it - surface it as our own error so no backend exception escapes
        on E: EInvalidOperationCryptoLibException do
          raise EPeerInputTlsLibException.CreateRes(@SDegenerateSharedSecret);
      end;
      // defense in depth: never hand back a degenerate (contributory) secret
      if TSecureMemory.ConstantTimeIsAllZero(LSecret) then
        raise EPeerInputTlsLibException.CreateRes(@SDegenerateSharedSecret);
      Result := TSecretBuffer.From(LSecret);
    finally
      TSecureMemory.WipeBytes(LSecret);
    end;
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

function TX25519Agreement.ValidatePublicKey(const APublicKey: TBytes): Boolean;
begin
  // every 32-byte string is a valid u-coordinate; a degenerate (all-zero)
  // agreement is rejected during Agree
  Result := System.Length(APublicKey) = TX25519PublicKeyParameters.KeySize;
end;

{ TNistEcAgreement }

constructor TNistEcAgreement.Create(const AName: string;
  const ARandom: ISecureRandom);
begin
  inherited Create;
  FName := AName;
  FRandom := ARandom;
  FDomain := TECDomainParameters.FromX9ECParameters(TCustomNamedCurves.GetByName(AName));
  FFieldSize := FDomain.Curve.FieldElementEncodingLength;
end;

function TNistEcAgreement.Name: string;
begin
  Result := FName;
end;

procedure TNistEcAgreement.GeneratePair(out APriv: IECPrivateKeyParameters;
  out APub: IECPublicKeyParameters);
var
  LGen: IECKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
begin
  LGen := TECKeyPairGenerator.Create('ECDH');
  LGen.Init(TECKeyGenerationParameters.Create(FDomain, FRandom) as IKeyGenerationParameters);
  LKp := LGen.GenerateKeyPair;
  APriv := LKp.Private as IECPrivateKeyParameters;
  APub := LKp.Public as IECPublicKeyParameters;
end;

function TNistEcAgreement.WrapPeer(const APeerPub: TBytes): IECPublicKeyParameters;
var
  LPoint: IECPoint;
begin
  try
    LPoint := FDomain.Curve.DecodePoint(APeerPub);
  except
    on E: ECryptoLibException do
      raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
  end;
  if LPoint.IsInfinity or (not LPoint.IsValid) then
    raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
  Result := TECPublicKeyParameters.Create(LPoint, FDomain);
end;

function TNistEcAgreement.AgreeParams(const APriv: IECPrivateKeyParameters;
  const APeer: IECPublicKeyParameters): ISecretBuffer;
var
  LAgreement: IECDHBasicAgreement;
  LZ: TBytes;
begin
  LAgreement := TECDHBasicAgreement.Create;
  LAgreement.Init(APriv);
  LZ := TBigIntegerUtilities.AsUnsignedByteArray(FFieldSize, LAgreement.CalculateAgreement(APeer));
  try
    Result := TSecretBuffer.From(LZ);
  finally
    TSecureMemory.WipeBytes(LZ);
  end;
end;

procedure TNistEcAgreement.GenerateKeyPair(out APrivateKey: ISecretBuffer;
  out APublicKey: TBytes);
var
  LPriv: IECPrivateKeyParameters;
  LPub: IECPublicKeyParameters;
  LPrivBytes: TBytes;
begin
  GeneratePair(LPriv, LPub);
  APublicKey := LPub.Q.GetEncoded(False);
  LPrivBytes := TBigIntegerUtilities.AsUnsignedByteArray(FFieldSize, LPriv.D);
  try
    APrivateKey := TSecretBuffer.From(LPrivBytes);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

function TNistEcAgreement.Agree(const APrivateKey: ISecretBuffer;
  const APeerPublicKey: TBytes): ISecretBuffer;
var
  LPrivBytes: TBytes;
  LPrivParams: IECPrivateKeyParameters;
begin
  LPrivBytes := APrivateKey.ToBytes;
  try
    LPrivParams := TECPrivateKeyParameters.Create(TBigInteger.Create(1, LPrivBytes),
      FDomain);
    Result := AgreeParams(LPrivParams, WrapPeer(APeerPublicKey));
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

function TNistEcAgreement.ValidatePublicKey(const APublicKey: TBytes): Boolean;
var
  LPoint: IECPoint;
begin
  Result := False;
  // an EC key share must use the uncompressed point form: RFC 8446 4.2.8.2 (TLS 1.3)
  // and RFC 8422 5.1.2 (TLS 1.2 and earlier) both mandate it and forbid compressed/
  // hybrid, so reject those up front - the caller then yields illegal_parameter
  if (System.Length(APublicKey) = 0) or (APublicKey[0] <> $04) then
    Exit;
  try
    LPoint := FDomain.Curve.DecodePoint(APublicKey);
    Result := (not LPoint.IsInfinity) and LPoint.IsValid;
  except
    Result := False;
  end;
end;

{ TKemAdapter }

constructor TKemAdapter.Create(const AName: string; const AParams: IMlKemParameters;
  const ARandom: ISecureRandom);
begin
  inherited Create;
  FName := AName;
  FParams := AParams;
  FRandom := ARandom;
end;

function TKemAdapter.Name: string;
begin
  Result := FName;
end;

procedure TKemAdapter.GenerateKeyPair(out APrivateKey: ISecretBuffer;
  out APublicKey: TBytes);
var
  LGen: IMlKemKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivBytes: TBytes;
begin
  LGen := TMlKemKeyPairGenerator.Create;
  LGen.Init(TMlKemKeyGenerationParameters.Create(FRandom, FParams) as IKeyGenerationParameters);
  LKp := LGen.GenerateKeyPair;
  APublicKey := (LKp.Public as IMlKemPublicKeyParameters).GetEncoded;
  LPrivBytes := (LKp.Private as IMlKemPrivateKeyParameters).GetEncoded;
  try
    APrivateKey := TSecretBuffer.From(LPrivBytes);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

procedure TKemAdapter.Encapsulate(const APeerPublicKey: TBytes;
  out ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LEnc: IKemEncapsulator;
  LSecret: TBytes;
begin
  LEnc := TMlKemEncapsulator.Create(FParams);
  LEnc.Init(TMlKemPublicKeyParameters.FromEncoding(FParams, APeerPublicKey));
  ACiphertext := nil;
  SetLength(ACiphertext, LEnc.GetEncapsulationLength);
  LSecret := nil;
  SetLength(LSecret, LEnc.GetSecretLength);
  try
    LEnc.Encapsulate(ACiphertext, 0, System.Length(ACiphertext), LSecret, 0,
      System.Length(LSecret));
    ASharedSecret := TSecretBuffer.From(LSecret);
  finally
    TSecureMemory.WipeBytes(LSecret);
  end;
end;

procedure TKemAdapter.Decapsulate(const APrivateKey: ISecretBuffer;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LDec: IKemDecapsulator;
  LPrivBytes, LSecret: TBytes;
begin
  LPrivBytes := APrivateKey.ToBytes;
  try
    try
      LDec := TMlKemDecapsulator.Create(FParams);
      LDec.Init(TMlKemPrivateKeyParameters.FromEncoding(FParams, LPrivBytes));
      LSecret := nil;
      SetLength(LSecret, LDec.GetSecretLength);
      try
        LDec.Decapsulate(ACiphertext, 0, System.Length(ACiphertext), LSecret, 0,
          System.Length(LSecret));
        ASharedSecret := TSecretBuffer.From(LSecret);
      finally
        TSecureMemory.WipeBytes(LSecret);
      end;
    except
      // a malformed peer ciphertext must not leak a backend exception
      on E: ECryptoLibException do
        raise EPeerInputTlsLibException.CreateRes(@SInvalidCiphertext);
    end;
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

function TKemAdapter.ValidatePublicKey(const APublicKey: TBytes): Boolean;
begin
  Result := False;
  if System.Length(APublicKey) = 0 then
    Exit;
  try
    // FromEncoding validates the length and modulus bound
    TMlKemPublicKeyParameters.FromEncoding(FParams, APublicKey);
    Result := True;
  except
    Result := False;
  end;
end;

{ TSignatureSignerAdapter }

constructor TSignatureSignerAdapter.Create(const ASigner: ISigner;
  const AScheme: string);
begin
  inherited Create;
  FSigner := ASigner;
  FScheme := AScheme;
end;

function TSignatureSignerAdapter.AlgorithmName: string;
begin
  Result := FScheme;
end;

procedure TSignatureSignerAdapter.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  FSigner.BlockUpdate(AData, AOffset, ALength);
end;

function TSignatureSignerAdapter.Sign: TBytes;
begin
  Result := FSigner.GenerateSignature;
end;

{ TSignatureVerifierAdapter }

constructor TSignatureVerifierAdapter.Create(const ASigner: ISigner;
  const AScheme: string);
begin
  inherited Create;
  FSigner := ASigner;
  FScheme := AScheme;
end;

function TSignatureVerifierAdapter.AlgorithmName: string;
begin
  Result := FScheme;
end;

procedure TSignatureVerifierAdapter.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  FSigner.BlockUpdate(AData, AOffset, ALength);
end;

function TSignatureVerifierAdapter.Verify(const ASignature: TBytes): Boolean;
begin
  // fail-closed: a structurally invalid signature is a failed verification, never
  // an escaping exception
  try
    Result := FSigner.VerifySignature(ASignature);
  except
    on E: ECryptoLibException do
      Result := False;
  end;
end;

{ TStaticPasswordFinder }

constructor TStaticPasswordFinder.Create(const APassword: string);
begin
  inherited Create;
  FPassword := TCredentialImport.PasswordChars(APassword);
end;

function TStaticPasswordFinder.GetPassword: TArray<Char>;
begin
  Result := FPassword;
end;

{ TSigningKey }

constructor TSigningKey.Create(const APrivateKeyInfo: ISecretBuffer;
  const AKeyParameter: IAsymmetricKeyParameter;
  const ACapableSchemes: TArray<TSignatureScheme>);
begin
  inherited Create;
  FPrivateKeyInfo := APrivateKeyInfo;
  FKeyParameter := AKeyParameter;
  FCapableSchemes := ACapableSchemes;
end;

function TSigningKey.CapableSchemes: TArray<TSignatureScheme>;
begin
  Result := FCapableSchemes;
end;

function TSigningKey.WithPreferredSchemes(
  const ASchemes: TArray<TSignatureScheme>): ISigningKey;
var
  LNarrowed: TArray<TSignatureScheme>;
  LPref, LCapable: TSignatureScheme;
  LN: Int32;
begin
  if System.Length(ASchemes) = 0 then
    Exit(Self);
  LNarrowed := nil;
  // keep the requested schemes this key can actually sign, in the requested order;
  // the new handle shares the same parsed key and canonical bytes
  for LPref in ASchemes do
    for LCapable in FCapableSchemes do
      if LPref = LCapable then
      begin
        LN := System.Length(LNarrowed);
        SetLength(LNarrowed, LN + 1);
        LNarrowed[LN] := LPref;
        Break;
      end;
  Result := TSigningKey.Create(FPrivateKeyInfo, FKeyParameter, LNarrowed);
end;

function TSigningKey.PrivateKeyInfo: ISecretBuffer;
begin
  Result := FPrivateKeyInfo;
end;

function TSigningKey.KeyParameter: IAsymmetricKeyParameter;
begin
  Result := FKeyParameter;
end;

{ TCredentialImport }

class function TCredentialImport.PasswordChars(
  const APassword: string): TArray<Char>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(APassword));
  for LI := 1 to System.Length(APassword) do
    Result[LI - 1] := APassword[LI];
end;

class procedure TCredentialImport.WipePasswordChars(
  var APassword: TArray<Char>);
begin
  if System.Length(APassword) > 0 then
    FillChar(APassword[0], System.Length(APassword) * SizeOf(Char), 0);
end;

// Classifies a DER private key by the types of the outer SEQUENCE's first elements:
// a leading SEQUENCE is EncryptedPrivateKeyInfo; a leading INTEGER (the version) is
// followed by a SEQUENCE (PKCS#8), an INTEGER (PKCS#1 RSAPrivateKey) or an OCTET
// STRING (SEC1 ECPrivateKey). The ASN.1 layer does the DER decoding and validation.
class function TCredentialImport.DetectDerKeyShape(const AData: TBytes): TDerKeyShape;
var
  LSeq: IAsn1Sequence;
  LFirst, LSecond: IAsn1Object;
  LSeqRef: IAsn1Sequence;
  LIntRef: IDerInteger;
  LOctRef: IAsn1OctetString;
begin
  Result := TDerKeyShape.Unknown;
  try
    LSeq := TAsn1Sequence.GetInstance(AData);
  except
    // not a DER SEQUENCE at all; leave it Unknown for the caller to reject
    on E: Exception do
      Exit;
  end;
  if LSeq.Count < 2 then
    Exit;
  LFirst := LSeq[0].ToAsn1Object;
  if Supports(LFirst, IAsn1Sequence, LSeqRef) then
    Exit(TDerKeyShape.EncryptedPkcs8);
  if not Supports(LFirst, IDerInteger, LIntRef) then
    Exit;
  LSecond := LSeq[1].ToAsn1Object;
  if Supports(LSecond, IAsn1Sequence, LSeqRef) then
    Result := TDerKeyShape.Pkcs8
  else if Supports(LSecond, IDerInteger, LIntRef) then
    Result := TDerKeyShape.Pkcs1Rsa
  else if Supports(LSecond, IAsn1OctetString, LOctRef) then
    Result := TDerKeyShape.Sec1Ec;
end;

// Derives the schemes a key can sign with from its PrivateKeyInfo AlgorithmIdentifier:
// RSA -> the three rsa_pss_rsae_* variants; a named EC curve -> its matching ECDSA
// scheme; Ed25519 -> ed25519. Raises on any unsupported algorithm.
class function TCredentialImport.SchemesForKeyInfo(
  const AInfo: IPrivateKeyInfo): TArray<TSignatureScheme>;
var
  LAlg: IAlgorithmIdentifier;
  LOid, LCurve: IDerObjectIdentifier;
begin
  Result := nil;
  LAlg := AInfo.PrivateKeyAlgorithm;
  LOid := LAlg.Algorithm;
  // an rsaEncryption key can sign both RSASSA-PSS and legacy RSASSA-PKCS1-v1_5; PSS is
  // listed first so it stays preferred (and is the only RSA option for a 1.3 handshake
  // signature - the pkcs1 schemes are gated out there, RFC 8446 4.2.3)
  if LOid.Equals(TPkcsObjectIdentifiers.RsaEncryption) then
    Exit(TArray<TSignatureScheme>.Create(TSignatureScheme.RSA_PSS_RSAE_SHA256,
      TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512,
      TSignatureScheme.RSA_PKCS1_SHA256, TSignatureScheme.RSA_PKCS1_SHA384,
      TSignatureScheme.RSA_PKCS1_SHA512));
  if LOid.Equals(TEdECObjectIdentifiers.IdEd25519) then
    Exit(TArray<TSignatureScheme>.Create(TSignatureScheme.ED25519));
  if LOid.Equals(TX9ObjectIdentifiers.IdECPublicKey) and (LAlg.Parameters <> nil) and
    Supports(LAlg.Parameters.ToAsn1Object, IDerObjectIdentifier, LCurve) then
  begin
    if LCurve.Equals(TX9ObjectIdentifiers.Prime256v1) then
      Exit(TArray<TSignatureScheme>.Create(TSignatureScheme.ECDSA_SECP256R1_SHA256));
    if LCurve.Equals(TSecObjectIdentifiers.SecP384r1) then
      Exit(TArray<TSignatureScheme>.Create(TSignatureScheme.ECDSA_SECP384R1_SHA384));
    if LCurve.Equals(TSecObjectIdentifiers.SecP521r1) then
      Exit(TArray<TSignatureScheme>.Create(TSignatureScheme.ECDSA_SECP521R1_SHA512));
  end;
  raise ENotSupportedTlsLibException.CreateRes(@SUnsupportedKeyAlgorithm);
end;

// True when the bytes carry a PEM encapsulation header. RFC 7468 6.2 permits explanatory text
// before the first "-----BEGIN " boundary, so the header is accepted wherever it begins a line
// (a leading comment or annotation no longer makes a PEM bundle look like DER). DER stays
// unmatched: its binary content does not carry that ASCII run at a line start.
class function TCredentialImport.IsPemArmored(const AData: TBytes): Boolean;
const
  CBegin: array [0 .. 10] of Byte =
    (Ord('-'), Ord('-'), Ord('-'), Ord('-'), Ord('-'), Ord('B'), Ord('E'),
    Ord('G'), Ord('I'), Ord('N'), Ord(' '));
var
  LI, LN, LLen: Int32;
  LAtLineStart: Boolean;
begin
  Result := False;
  LN := System.Length(AData);
  LLen := System.Length(CBegin);
  LI := 0;
  while (LI < LN) and (AData[LI] <= Ord(' ')) do
    Inc(LI);
  // the first non-blank byte begins a line; thereafter a line starts right after each newline
  LAtLineStart := True;
  while LI <= (LN - LLen) do
  begin
    if LAtLineStart and CompareMem(@AData[LI], @CBegin[0], LLen) then
      Exit(True);
    LAtLineStart := AData[LI] = Ord(#10);
    Inc(LI);
  end;
end;

// The private half of the key object the PEM reader returned (a bare key parameter,
// or the private key of a returned key pair).
class function TCredentialImport.KeyParamFromPem(const AData: TBytes;
  const APassword: string; AHasPassword: Boolean): IAsymmetricKeyParameter;
var
  LStream: TBytesStream;
  LReader: IOpenSslPemReader;
  LValue: TValue;
  LPair: IAsymmetricCipherKeyPair;
  LParam: IAsymmetricKeyParameter;
begin
  Result := nil;
  LStream := TBytesStream.Create(AData);
  try
    if AHasPassword then
      LReader := TOpenSslPemReader.Create(LStream,
        TStaticPasswordFinder.Create(APassword) as IOpenSslPasswordFinder)
    else
      LReader := TOpenSslPemReader.Create(LStream) as IOpenSslPemReader;
    try
      LValue := LReader.ReadObject;
      if LValue.IsEmpty then
        raise EArgumentTlsLibException.CreateRes(@SMalformedPrivateKey);
      if LValue.TryGetAsType<IAsymmetricCipherKeyPair>(LPair) then
        Result := LPair.Private
      else if LValue.TryGetAsType<IAsymmetricKeyParameter>(LParam) then
        Result := LParam;
    finally
      LReader := nil;
    end;
  finally
    LStream.Free;
  end;
end;

// The key parameter for a DER private key, dispatched on its ASN.1 shape. PKCS#1
// and SEC1 are wrapped into a PrivateKeyInfo exactly as the PEM reader does.
class function TCredentialImport.KeyParamFromDer(const AData: TBytes;
  const APassword: string; AHasPassword: Boolean): IAsymmetricKeyParameter;
var
  LRsa: IRsaPrivateKeyStructure;
  LEc: IECPrivateKeyStructure;
  LAlgId: IAlgorithmIdentifier;
  LInfo: IPrivateKeyInfo;
  LPass: TArray<Char>;
begin
  Result := nil;
  case DetectDerKeyShape(AData) of
    TDerKeyShape.Pkcs8:
      Result := TPrivateKeyFactory.CreateKey(AData);
    TDerKeyShape.EncryptedPkcs8:
      begin
        if not AHasPassword then
          raise EArgumentTlsLibException.CreateRes(@SMalformedPrivateKey);
        LPass := PasswordChars(APassword);
        try
          Result := TPrivateKeyFactory.DecryptKey(LPass, AData);
        finally
          WipePasswordChars(LPass);
        end;
      end;
    TDerKeyShape.Pkcs1Rsa:
      begin
        LRsa := TRsaPrivateKeyStructure.GetInstance(AData);
        Result := TRsaPrivateCrtKeyParameters.Create(LRsa.Modulus,
          LRsa.PublicExponent, LRsa.PrivateExponent, LRsa.Prime1, LRsa.Prime2,
          LRsa.Exponent1, LRsa.Exponent2, LRsa.Coefficient);
      end;
    TDerKeyShape.Sec1Ec:
      begin
        LEc := TECPrivateKeyStructure.GetInstance(AData);
        LAlgId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey,
          LEc.Parameters);
        LInfo := TPrivateKeyInfo.Create(LAlgId, LEc.ToAsn1Object);
        Result := TPrivateKeyFactory.CreateKey(LInfo);
      end;
  else
    raise EArgumentTlsLibException.CreateRes(@SMalformedPrivateKey);
  end;
end;

class function TCredentialImport.SigningKeyFromParam(
  const AKeyParam: IAsymmetricKeyParameter): ISigningKey;
var
  LInfo: IPrivateKeyInfo;
  LPkcs8: TBytes;
  LSchemes: TArray<TSignatureScheme>;
  LBuffer: ISecretBuffer;
begin
  if (AKeyParam = nil) or (not AKeyParam.IsPrivate) then
    raise EArgumentTlsLibException.CreateRes(@SMalformedPrivateKey);
  LInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(AKeyParam);
  // capability comes straight off the parsed key info; hold the parsed key (reused for
  // every sign) plus canonical PKCS#8 (the wipeable export form)
  LSchemes := SchemesForKeyInfo(LInfo);
  LPkcs8 := LInfo.GetDerEncoded;
  try
    LBuffer := TSecretBuffer.From(LPkcs8);
  finally
    TSecureMemory.WipeBytes(LPkcs8);
  end;
  Result := TSigningKey.Create(LBuffer, AKeyParam, LSchemes);
end;

// Imports a signing key in any supported encoding: normalizes it to canonical
// PKCS#8 (held wipeably) and derives the schemes it can sign with. Any backend
// parse failure is reclassified as a typed library exception, so no Clp*/ASN.1
// exception escapes the provider.
class function TCredentialImport.ImportKey(const AData: TBytes;
  const APassword: string; AHasPassword: Boolean): ISigningKey;
var
  LKeyParam: IAsymmetricKeyParameter;
begin
  try
    if IsPemArmored(AData) then
      LKeyParam := KeyParamFromPem(AData, APassword, AHasPassword)
    else
      LKeyParam := KeyParamFromDer(AData, APassword, AHasPassword);
    Result := SigningKeyFromParam(LKeyParam);
  except
    on E: EBaseTlsLibException do
      raise;
    on E: Exception do
      raise EArgumentTlsLibException.CreateRes(@SMalformedPrivateKey);
  end;
end;

{ TDefaultCryptoProvider }

constructor TDefaultCryptoProvider.Create;
begin
  inherited Create;
  FHasHardwareAes := TAesUtilities.IsHardwareAccelerated();
  FRandom := TSecureRandom.Create;
end;

function TDefaultCryptoProvider.ResolveDigest(AAlgorithm: THashAlgorithm): IDigest;
begin
  Result := TDigestUtilities.GetDigest(
    TEnumUtilities.GetName<THashAlgorithm>(AAlgorithm));
end;

class function TDefaultCryptoProvider.SignerMechanismForScheme(
  AScheme: TSignatureScheme): string;
begin
  // map a TLS 1.3 signature scheme to a CryptoLib signer mechanism. The named
  // RSA-PSS mechanisms carry the right hash, MGF1 digest, and salt length (= the
  // hash size), matching the rsa_pss_rsae_* profile; the bare "PSSwithRSA" would
  // wrongly default to SHA-1. ECDSA resolves to DER-encoded signatures.
  case AScheme of
    TSignatureScheme.ECDSA_SECP256R1_SHA256:
      Result := 'SHA-256withECDSA';
    TSignatureScheme.ECDSA_SECP384R1_SHA384:
      Result := 'SHA-384withECDSA';
    TSignatureScheme.ECDSA_SECP521R1_SHA512:
      Result := 'SHA-512withECDSA';
    TSignatureScheme.ED25519:
      Result := 'Ed25519';
    TSignatureScheme.ED448:
      Result := 'Ed448';
    TSignatureScheme.RSA_PSS_RSAE_SHA256:
      Result := 'SHA-256withRSAandMGF1';
    TSignatureScheme.RSA_PSS_RSAE_SHA384:
      Result := 'SHA-384withRSAandMGF1';
    TSignatureScheme.RSA_PSS_RSAE_SHA512:
      Result := 'SHA-512withRSAandMGF1';
    // the legacy rsa_pkcs1_* schemes are RSASSA-PKCS1-v1_5 with the named hash; valid for
    // a TLS 1.2 handshake signature and for certificate signatures (RFC 8446 4.2.3)
    TSignatureScheme.RSA_PKCS1_SHA256:
      Result := 'SHA-256withRSA';
    TSignatureScheme.RSA_PKCS1_SHA384:
      Result := 'SHA-384withRSA';
    TSignatureScheme.RSA_PKCS1_SHA512:
      Result := 'SHA-512withRSA';
  else
    raise ENotSupportedTlsLibException.CreateResFmt(@SUnhandledAlgorithm,
      [Ord(AScheme)]);
  end;
end;

function TDefaultCryptoProvider.GetRandom: IRandom;
begin
  Result := TRandomAdapter.Create;
end;

function TDefaultCryptoProvider.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := THashAdapter.Create(ResolveDigest(AAlgorithm));
end;

function TDefaultCryptoProvider.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := THmacAdapter.Create(ResolveDigest(AAlgorithm));
end;

function TDefaultCryptoProvider.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := THkdfAdapter.Create(AAlgorithm);
end;

function TDefaultCryptoProvider.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  case AAlgorithm of
    TAeadAlgorithm.AES_128_GCM:
      Result := TAeadAdapter.Create(TAeadKind.AesGcm,
        TEnumUtilities.GetName<TAeadAlgorithm>(AAlgorithm), 16, 12, 16, FHasHardwareAes);
    TAeadAlgorithm.AES_256_GCM:
      Result := TAeadAdapter.Create(TAeadKind.AesGcm,
        TEnumUtilities.GetName<TAeadAlgorithm>(AAlgorithm), 32, 12, 16, FHasHardwareAes);
    TAeadAlgorithm.CHACHA20_POLY1305:
      Result := TAeadAdapter.Create(TAeadKind.ChaChaPoly,
        TEnumUtilities.GetName<TAeadAlgorithm>(AAlgorithm), 32, 12, 16, FHasHardwareAes);
  else
    raise ENotSupportedTlsLibException.CreateResFmt(@SUnhandledAlgorithm,
      [Ord(AAlgorithm)]);
  end;
end;

function TDefaultCryptoProvider.ImportSigningKey(const AData: TBytes): ISigningKey;
begin
  Result := TCredentialImport.ImportKey(AData, '', False);
end;

function TDefaultCryptoProvider.ImportSigningKey(const AData: TBytes;
  const APassword: string): ISigningKey;
begin
  Result := TCredentialImport.ImportKey(AData, APassword, True);
end;

function TDefaultCryptoProvider.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
var
  LProviderKey: IProviderSigningKey;
  LKey: IAsymmetricKeyParameter;
begin
  if not Supports(AKey, IProviderSigningKey, LProviderKey) then
    raise EArgumentTlsLibException.CreateRes(@SForeignSigningKey);
  // the key was parsed and validated once at import; reuse it rather than re-parsing and
  // re-validating it on every sign - InitSigner still makes a fresh per-call signer for
  // the digest state, so concurrent handshakes stay independent
  LKey := LProviderKey.KeyParameter;
  Result := TSignatureSignerAdapter.Create(
    TSignerUtilities.InitSigner(SignerMechanismForScheme(AScheme), True, LKey, FRandom),
    TEnumUtilities.GetName<TSignatureScheme>(AScheme));
end;

function TDefaultCryptoProvider.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
var
  LKey: IAsymmetricKeyParameter;
  LSigner: ISigner;
begin
  LKey := TPublicKeyFactory.CreateKey(APublicKeyDer);
  LSigner := TSignerUtilities.GetSigner(SignerMechanismForScheme(AScheme));
  LSigner.Init(False, LKey);
  Result := TSignatureVerifierAdapter.Create(LSigner,
    TEnumUtilities.GetName<TSignatureScheme>(AScheme));
end;

function TDefaultCryptoProvider.LoadCertificateChain(
  const AData: TBytes): TArray<TBytes>;
var
  LStream: TBytesStream;
  LReader: IOpenSslPemReader;
  LValue: TValue;
  LCert: IX509Certificate;
  LParser: IX509CertificateParser;
  LN: Int32;
begin
  // PEM may carry a whole chain/bundle (leaf first); DER is a single certificate.
  // Either way the result is the ordered list of raw DER certificates.
  Result := nil;
  try
    if TCredentialImport.IsPemArmored(AData) then
    begin
      LStream := TBytesStream.Create(AData);
      try
        LReader := TOpenSslPemReader.Create(LStream);
        try
          while True do
          begin
            LValue := LReader.ReadObject;
            if LValue.IsEmpty then
              Break;
            if LValue.TryGetAsType<IX509Certificate>(LCert) then
            begin
              LN := System.Length(Result);
              SetLength(Result, LN + 1);
              Result[LN] := LCert.GetEncoded;
            end;
          end;
        finally
          LReader := nil;
        end;
      finally
        LStream.Free;
      end;
    end
    else
    begin
      LParser := TX509CertificateParser.Create;
      Result := TArray<TBytes>.Create(
        LParser.ReadCertificate(AData).GetEncoded);
    end;
  except
    on E: ECryptoLibException do
      raise EArgumentTlsLibException.CreateRes(@SMalformedCertificate);
  end;
  if System.Length(Result) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SNoCertificatesFound);
end;

function TDefaultCryptoProvider.IsWellFormedCertificate(
  const ADer: TBytes): Boolean;
var
  LParser: IX509CertificateParser;
begin
  Result := False;
  if System.Length(ADer) = 0 then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    Result := LParser.ReadCertificate(ADer) <> nil;
  except
    Result := False;
  end;
end;

function TDefaultCryptoProvider.ImportPkcs12(const AData: TBytes;
  const APassword: string): TTlsCredential;
var
  LStore: IPkcs12Store;
  LStoreBuilder: IPkcs12StoreBuilder;
  LStream: TBytesStream;
  LPass: TArray<Char>;
  LAliases: TArray<string>;
  LAlias, LKeyAlias: string;
  LChainEntries: TArray<IX509CertificateEntry>;
  LChain: TArray<TBytes>;
  LI, LKeyCount: Int32;
begin
  // PKCS#12 takes a character-array password (empty = none), wiped in the finally so no
  // key-derivation password lingers
  LPass := TCredentialImport.PasswordChars(APassword);
  try
    try
      LStoreBuilder := TPkcs12StoreBuilder.Create;
      LStore := LStoreBuilder.Build;
      LStream := TBytesStream.Create(AData);
      try
        LStore.Load(LStream, LPass);
      finally
        LStream.Free;
      end;

      // the credential requires exactly one private-key entry; alias order is not stable,
      // so a multi-identity store is rejected rather than binding an arbitrary one
      LKeyAlias := '';
      LKeyCount := 0;
      LAliases := LStore.GetAliases;
      for LI := 0 to System.High(LAliases) do
      begin
        LAlias := LAliases[LI];
        if LStore.IsKeyEntry(LAlias) then
        begin
          LKeyAlias := LAlias;
          Inc(LKeyCount);
        end;
      end;
      if LKeyCount = 0 then
        raise EArgumentTlsLibException.CreateRes(@SPkcs12NoKeyEntry);
      if LKeyCount > 1 then
        raise EArgumentTlsLibException.CreateRes(@SPkcs12MultipleKeys);

      // the store orders the chain leaf-first (end entity to root)
      LChainEntries := LStore.GetCertificateChain(LKeyAlias);
      if System.Length(LChainEntries) = 0 then
        raise EArgumentTlsLibException.CreateRes(@SPkcs12NoChain);
      SetLength(LChain, System.Length(LChainEntries));
      for LI := 0 to System.High(LChainEntries) do
        LChain[LI] := LChainEntries[LI].Certificate.GetEncoded;

      // the single signing-key path shared with ImportSigningKey; wipes the PKCS#8
      Result.PrivateKey := TCredentialImport.SigningKeyFromParam(
        LStore.GetKey(LKeyAlias).Key);
      Result.CertificateChain := LChain;
    except
      // fail closed: reclassify any backend failure as a typed library exception, leaving
      // an already-typed one (e.g. unsupported-algorithm) to propagate unchanged
      on E: EBaseTlsLibException do
        raise;
      on E: Exception do
        raise EArgumentTlsLibException.CreateRes(@SMalformedPkcs12);
    end;
  finally
    TCredentialImport.WipePasswordChars(LPass);
  end;
end;

function TDefaultCryptoProvider.CertificatePublicKeyInfo(
  const ACertificateDer: TBytes): TBytes;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertificateDer);
  Result := LCert.GetSubjectPublicKeyInfo.GetDerEncoded;
end;

function TDefaultCryptoProvider.CertificateDnsNames(
  const ACertificateDer: TBytes): TArray<string>;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LGeneralNames: IGeneralNames;
  LNames: TArray<IGeneralName>;
  LString: IAsn1String;
  LI, LCount: Int32;
begin
  Result := nil;
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertificateDer);
  LGeneralNames := LCert.GetSubjectAlternativeNameExtension;
  if LGeneralNames = nil then
    Exit;
  LNames := LGeneralNames.GetNames;
  LCount := 0;
  for LI := 0 to System.Length(LNames) - 1 do
    if (LNames[LI].TagNo = TGeneralName.DnsName) and
      Supports(LNames[LI].GetName, IAsn1String, LString) then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := LString.GetString;
      Inc(LCount);
    end;
end;

function TDefaultCryptoProvider.CertificateIpAddresses(
  const ACertificateDer: TBytes): TArray<TBytes>;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LGeneralNames: IGeneralNames;
  LNames: TArray<IGeneralName>;
  LOctets: IAsn1OctetString;
  LI, LCount: Int32;
begin
  Result := nil;
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertificateDer);
  LGeneralNames := LCert.GetSubjectAlternativeNameExtension;
  if LGeneralNames = nil then
    Exit;
  LNames := LGeneralNames.GetNames;
  LCount := 0;
  for LI := 0 to System.Length(LNames) - 1 do
    if (LNames[LI].TagNo = TGeneralName.IPAddress) and
      Supports(LNames[LI].GetName, IAsn1OctetString, LOctets) then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := LOctets.GetOctets;
      Inc(LCount);
    end;
end;

class function TDefaultCryptoProvider.TTrustAnchorRing.Init: TTrustAnchorRing;
begin
  SetLength(Result.FKeys, TrustAnchorCacheSize);
  SetLength(Result.FSets, TrustAnchorCacheSize);
  Result.FCount := 0;
  Result.FNext := 0;
end;

function TDefaultCryptoProvider.TTrustAnchorRing.TryGet(const AKey: TBytes;
  out AAnchors: TArray<ITrustAnchor>): Boolean;
var
  LI: Int32;
begin
  AAnchors := nil;
  for LI := 0 to FCount - 1 do
    if TArrayUtilities.AreEqual(FKeys[LI], AKey) then
    begin
      AAnchors := FSets[LI];
      Exit(True);
    end;
  Result := False;
end;

procedure TDefaultCryptoProvider.TTrustAnchorRing.Remember(const AKey: TBytes;
  const AAnchors: TArray<ITrustAnchor>);
begin
  FKeys[FNext] := AKey;
  FSets[FNext] := AAnchors;
  FNext := (FNext + 1) mod TrustAnchorCacheSize;
  if FCount < TrustAnchorCacheSize then
    Inc(FCount);
end;

class constructor TDefaultCryptoProvider.Create;
begin
  FTrustAnchors := TTrustAnchorRing.Init;
  FTrustAnchorLock := TCriticalSection.Create;
  FSharedLock := TCriticalSection.Create;
end;

class destructor TDefaultCryptoProvider.Destroy;
begin
  FShared := nil;
  FSharedLock.Free;
  FTrustAnchorLock.Free;
end;

class function TDefaultCryptoProvider.Shared: ICryptoProvider;
begin
  FSharedLock.Acquire;
  try
    if FShared = nil then
      FShared := TDefaultCryptoProvider.Create as ICryptoProvider;
    Result := FShared;
  finally
    FSharedLock.Release;
  end;
end;

function TDefaultCryptoProvider.TrustAnchorKey(
  const ATrustAnchors: TArray<TBytes>): TBytes;
var
  LDigest: IDigest;
  LI, LN: Int32;
  LLen: TBytes;
begin
  LDigest := ResolveDigest(THashAlgorithm.SHA_256);
  System.SetLength(LLen, 4);
  for LI := 0 to System.High(ATrustAnchors) do
  begin
    // length-prefix each anchor so distinct groupings cannot alias one another
    LN := System.Length(ATrustAnchors[LI]);
    TBinaryPrimitives.WriteUInt32LittleEndian(LLen, 0, UInt32(LN));
    LDigest.BlockUpdate(LLen, 0, 4);
    if LN > 0 then
      LDigest.BlockUpdate(ATrustAnchors[LI], 0, LN);
  end;
  Result := LDigest.DoFinal;
end;

procedure TDefaultCryptoProvider.ValidateCertificatePath(const AChain,
  ATrustAnchors: TArray<TBytes>; const AValidationTimeUtc: TDateTime);
var
  LParser: IX509CertificateParser;
  LCerts: TArray<IX509Certificate>;
  LAnchors: TArray<ITrustAnchor>;
  LAnchorKey: TBytes;
  LHit: Boolean;
  LParams: IPkixParameters;
  LPath: IPkixCertPath;
  LValidator: IPkixCertPathValidator;
  LI: Int32;
begin
  LParser := TX509CertificateParser.Create;
  try
    SetLength(LCerts, System.Length(AChain));
    for LI := 0 to High(AChain) do
      LCerts[LI] := LParser.ReadCertificate(AChain[LI]);
  except
    on E: ECryptoLibException do
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.BadCertificate, @SBadCertificate);
  end;

  // an out-of-window certificate is a distinct, well-known failure; the window is
  // judged at the injected validation time so a mock clock drives it
  for LI := 0 to High(LCerts) do
    if not LCerts[LI].IsValid(AValidationTimeUtc) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.CertificateExpired, @SCertificateExpired);

  if System.Length(ATrustAnchors) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnknownCa, @SUntrustedChain);

  // parsing the anchor store dominates a reused-config verify, so memoise the
  // parsed anchors keyed by a digest of the anchor set; the parse itself runs
  // outside the lock so concurrent cold verifies do not serialise on it
  LAnchorKey := TrustAnchorKey(ATrustAnchors);
  FTrustAnchorLock.Acquire;
  try
    LHit := FTrustAnchors.TryGet(LAnchorKey, LAnchors);
  finally
    FTrustAnchorLock.Release;
  end;

  if not LHit then
  begin
    try
      SetLength(LAnchors, System.Length(ATrustAnchors));
      for LI := 0 to High(ATrustAnchors) do
        LAnchors[LI] := TTrustAnchor.Create(
          LParser.ReadCertificate(ATrustAnchors[LI]), nil);
    except
      on E: ECryptoLibException do
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.UnknownCa, @SUntrustedChain);
    end;
    FTrustAnchorLock.Acquire;
    try
      FTrustAnchors.Remember(LAnchorKey, LAnchors);
    finally
      FTrustAnchorLock.Release;
    end;
  end;

  // build the PKIX path to a trusted anchor; anything else is unknown_ca
  try
    LParams := TPkixParameters.Create(LAnchors);
    LParams.SetIsRevocationEnabled(False);
    // pin the PKIX path date to the same source as the notBefore/notAfter check
    LParams.SetDate(AValidationTimeUtc);
    LPath := TPkixCertPath.Create(LCerts);
    LValidator := TPkixCertPathValidator.Create;
    LValidator.Validate(LPath, LParams);
  except
    on E: ECryptoLibException do
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnknownCa, @SUntrustedChain);
  end;
end;

class function TDefaultCryptoProvider.OcspDelegatedResponder(const AResponderCert,
  AIssuerCert: IX509Certificate; const AIssuerPublicKey: IAsymmetricKeyParameter;
  AValidityDate: TDateTime): Boolean;
var
  LKeyPurposes: TArray<IDerObjectIdentifier>;
  LI: Int32;
begin
  Result := False;
  // the delegation only holds if the issuer itself issued the responder certificate
  if not AResponderCert.IssuerDN.Equivalent(AIssuerCert.SubjectDN, True) then
    Exit;
  try
    AResponderCert.CheckValidity(AValidityDate);
    AResponderCert.Verify(AIssuerPublicKey);
    LKeyPurposes := AResponderCert.GetExtendedKeyUsage;
  except
    // a responder certificate that is out of date, does not verify against the
    // issuer, or exposes no extended key usage delegates nothing
    Exit;
  end;
  for LI := 0 to System.High(LKeyPurposes) do
    if TKeyPurposeId.IdKpOcspSigning.Equals(LKeyPurposes[LI]) then
    begin
      Result := True;
      Exit;
    end;
end;

class function TDefaultCryptoProvider.OcspResponseAuthorised(
  const AResponse: IBasicOcspResp; const AIssuerCert: IX509Certificate;
  const AIssuerPublicKey: IAsymmetricKeyParameter; AValidityDate: TDateTime): Boolean;
var
  LCerts: TArray<IX509Certificate>;
  LI: Int32;
begin
  Result := False;
  try
    if AResponse.Verify(AIssuerPublicKey) then
    begin
      Result := True;
      Exit;
    end;
  except
    // a signature this key cannot even be applied to is simply not the issuer's
  end;

  LCerts := AResponse.GetCerts;
  for LI := 0 to System.High(LCerts) do
  begin
    if not OcspDelegatedResponder(LCerts[LI], AIssuerCert, AIssuerPublicKey,
      AValidityDate) then
      Continue;
    try
      if AResponse.Verify(LCerts[LI].GetPublicKey) then
      begin
        Result := True;
        Exit;
      end;
    except
      // a delegated responder whose signature does not verify is not authoritative
    end;
  end;
end;

function TDefaultCryptoProvider.ValidateOcspStaple(const ALeafCert, AIssuerCert,
  AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
  out AStatus: TOcspStatus; out AThisUpdate, ANextUpdate: TDateTime): Boolean;
var
  LParser: IX509CertificateParser;
  LLeaf, LIssuer: IX509Certificate;
  LResp: IOcspResp;
  LBasic: IBasicOcspResp;
  LSingles: TArray<ISingleResp>;
  LSingle: ISingleResp;
  LCertId: ICertificateID;
  LStatus: ICertificateStatus;
  LValidity: TDateTime;
  LI: Int32;
begin
  Result := False;
  AStatus := TOcspStatus.Unknown;
  AThisUpdate := 0;
  ANextUpdate := 0;
  if (System.Length(ALeafCert) = 0) or (System.Length(AIssuerCert) = 0) or
    (System.Length(AOcspResponseDer) = 0) then
    Exit;

  try
    LParser := TX509CertificateParser.Create;
    LLeaf := LParser.ReadCertificate(ALeafCert);
    LIssuer := LParser.ReadCertificate(AIssuerCert);

    LResp := TOcspResp.Create(AOcspResponseDer) as IOcspResp;
    if LResp.Status <> TOcspRespStatus.Successful then
      Exit;
    LBasic := LResp.GetResponseObject;
    if LBasic = nil then
      Exit;

    LValidity := AValidationTimeUtc;
    LSingles := LBasic.GetResponses;
    for LI := 0 to System.High(LSingles) do
    begin
      LSingle := LSingles[LI];
      LCertId := LSingle.GetCertID;
      // the staple must be about this leaf: matching serial and issuer name/key hash
      if not LLeaf.SerialNumber.Equals(LCertId.SerialNumber) then
        Continue;
      if not LCertId.MatchesIssuer(LIssuer) then
        Continue;
      // and it must be authoritative for that leaf
      if not OcspResponseAuthorised(LBasic, LIssuer, LIssuer.GetPublicKey,
        LValidity) then
        Exit;

      AThisUpdate := LSingle.ThisUpdate;
      // an omitted nextUpdate leaves no upper bound; 0 signals that to the caller
      if LSingle.NextUpdate.HasValue then
        ANextUpdate := LSingle.NextUpdate.Value
      else
        ANextUpdate := 0;

      LStatus := LSingle.GetCertStatus;
      if LStatus = nil then
        AStatus := TOcspStatus.Good
      else if Supports(LStatus, IRevokedStatus) then
        AStatus := TOcspStatus.Revoked
      else
        AStatus := TOcspStatus.Unknown;
      Result := True;
      Exit;
    end;
  except
    // a response that cannot be parsed leaves the status indeterminate, never raises
    Result := False;
    AStatus := TOcspStatus.Unknown;
    AThisUpdate := 0;
    ANextUpdate := 0;
  end;
end;

function TDefaultCryptoProvider.BuildOcspRequest(const ALeafCert,
  AIssuerCert: TBytes; out ARequestDer: TBytes): Boolean;
var
  LParser: IX509CertificateParser;
  LLeaf, LIssuer: IX509Certificate;
  LCertId: ICertificateID;
  LGen: IOcspReqGenerator;
begin
  Result := False;
  ARequestDer := nil;
  if (System.Length(ALeafCert) = 0) or (System.Length(AIssuerCert) = 0) then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LLeaf := LParser.ReadCertificate(ALeafCert);
    LIssuer := LParser.ReadCertificate(AIssuerCert);
    // the CertID is the SHA-1 issuer name/key hash plus the leaf serial (RFC 6960 4.1.1)
    LCertId := TCertificateID.Create(TCertificateID.DigestSha1, LIssuer,
      LLeaf.SerialNumber) as ICertificateID;
    LGen := TOcspReqGenerator.Create as IOcspReqGenerator;
    LGen.AddRequest(LCertId);
    ARequestDer := LGen.Generate.GetEncoded;
    Result := System.Length(ARequestDer) > 0;
  except
    // a malformed input leaves no request; never raise a backend exception
    Result := False;
    ARequestDer := nil;
  end;
end;

function TDefaultCryptoProvider.TryGetOcspResponderUrl(const ACert: TBytes;
  out AUrl: string): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExt: IAsn1OctetString;
  LAia: IAuthorityInformationAccess;
  LDescs: TCryptoLibGenericArray<IAccessDescription>;
  LLoc: IGeneralName;
  LIa5: IDerIA5String;
  LI: Int32;
begin
  Result := False;
  AUrl := '';
  if System.Length(ACert) = 0 then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACert);
    LExt := LCert.GetExtensionValue(TX509Extensions.AuthorityInfoAccess);
    if LExt = nil then
      Exit;
    LAia := TAuthorityInformationAccess.GetInstance(LExt.GetOctets);
    if LAia = nil then
      Exit;
    LDescs := LAia.GetAccessDescriptions;
    for LI := 0 to System.High(LDescs) do
      if TX509ObjectIdentifiers.IdADOcsp.Equals(LDescs[LI].GetAccessMethod) then
      begin
        LLoc := LDescs[LI].GetAccessLocation;
        if (LLoc <> nil) and (LLoc.GetTagNo = TGeneralName.UniformResourceIdentifier) and
          Supports(LLoc.GetName, IDerIA5String, LIa5) then
        begin
          AUrl := LIa5.GetString;
          if AUrl <> '' then
            Exit(True);
        end;
      end;
  except
    Result := False;
    AUrl := '';
  end;
end;

function TDefaultCryptoProvider.TryGetCrlDistributionPoints(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExt: IAsn1OctetString;
  LCdp: ICrlDistPoint;
  LPoints: TCryptoLibGenericArray<IDistributionPoint>;
  LDpn: IDistributionPointName;
  LGns: IGeneralNames;
  LNames: TCryptoLibGenericArray<IGeneralName>;
  LIa5: IDerIA5String;
  LI, LJ: Int32;
begin
  Result := False;
  AUrls := nil;
  if System.Length(ACert) = 0 then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACert);
    LExt := LCert.GetExtensionValue(TX509Extensions.CrlDistributionPoints);
    if LExt = nil then
      Exit;
    LCdp := TCrlDistPoint.GetInstance(LExt.GetOctets);
    if LCdp = nil then
      Exit;
    LPoints := LCdp.GetDistributionPoints;
    for LI := 0 to System.High(LPoints) do
    begin
      LDpn := LPoints[LI].GetDistributionPointName;
      if (LDpn = nil) or (LDpn.GetType <> TDistributionPointName.FullName) then
        Continue;
      if not Supports(LDpn.GetName, IGeneralNames, LGns) then
        Continue;
      LNames := LGns.GetNames;
      for LJ := 0 to System.High(LNames) do
        if (LNames[LJ].GetTagNo = TGeneralName.UniformResourceIdentifier) and
          Supports(LNames[LJ].GetName, IDerIA5String, LIa5) and
          (LIa5.GetString <> '') then
        begin
          SetLength(AUrls, System.Length(AUrls) + 1);
          AUrls[System.High(AUrls)] := LIa5.GetString;
        end;
    end;
    Result := System.Length(AUrls) > 0;
  except
    Result := False;
    AUrls := nil;
  end;
end;

function TDefaultCryptoProvider.CheckCrlRevocation(const ALeafCert, AIssuerCert,
  ACrlDer: TBytes; out ARevoked: Boolean): Boolean;
var
  LParser: IX509CertificateParser;
  LLeaf, LIssuer: IX509Certificate;
  LCrlParser: IX509CrlParser;
  LCrl: IX509Crl;
  LNowMs: Int64;
begin
  Result := False;
  ARevoked := False;
  if (System.Length(ALeafCert) = 0) or (System.Length(AIssuerCert) = 0) or
    (System.Length(ACrlDer) = 0) then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LLeaf := LParser.ReadCertificate(ALeafCert);
    LIssuer := LParser.ReadCertificate(AIssuerCert);
    LCrlParser := TX509CrlParser.Create;
    LCrl := LCrlParser.ReadCrl(ACrlDer);
    if LCrl = nil then
      Exit;
    // the CRL must be signed by the leaf's issuer to be authoritative
    if not LCrl.IsSignatureValid(LIssuer.GetPublicKey) then
      Exit;
    // honor the CRL validity window (mirrors the OCSP thisUpdate/nextUpdate check): a validly
    // signed but not-yet-valid or expired CRL is never authoritative - a MITM could otherwise
    // replay an old, legitimately-signed CRL predating the revocation. Out of window -> False
    // (indeterminate), never a silent Good.
    LNowMs := TDateTimeUtilities.CurrentUnixMs;
    if LNowMs < TDateTimeUtilities.DateTimeToUnixMs(LCrl.ThisUpdate) then
      Exit;
    if LCrl.NextUpdate.HasValue and
      (LNowMs >= TDateTimeUtilities.DateTimeToUnixMs(LCrl.NextUpdate.Value)) then
      Exit;
    ARevoked := LCrl.GetRevokedCertificate(LLeaf.SerialNumber) <> nil;
    Result := True;
  except
    // an unparseable or unverifiable CRL is indeterminate, never a raise
    Result := False;
    ARevoked := False;
  end;
end;

function TDefaultCryptoProvider.CertificatePeerInfo(const ACertificateDer: TBytes;
  out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LCns: TCryptoLibStringArray;
begin
  Result := False;
  ASubject := '';
  AIssuer := '';
  ACommonName := '';
  ASerialHex := '';
  if System.Length(ACertificateDer) = 0 then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificateDer);
    ASubject := LCert.SubjectDN.ToString;
    AIssuer := LCert.IssuerDN.ToString;
    LCns := LCert.SubjectDN.GetValueList(TX509Name.CN);
    if System.Length(LCns) > 0 then
      ACommonName := LCns[0];
    ASerialHex := LCert.SerialNumber.ToString(16);
    Result := True;
  except
    Result := False;
    ASubject := '';
    AIssuer := '';
    ACommonName := '';
    ASerialHex := '';
  end;
end;

function TDefaultCryptoProvider.CertificateTlsFeatures(const ACert: TBytes;
  out AFeatures: TArray<UInt16>): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExtValue: IAsn1OctetString;
  LObj: IAsn1Object;
  LSeq: IAsn1Sequence;
  LInt: IDerInteger;
  LI, LValue: Int32;
begin
  Result := False;
  AFeatures := nil;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACert);
    LExtValue := LCert.GetExtensionValue(
      TDerObjectIdentifier.Create(TlsFeatureExtensionOid) as IDerObjectIdentifier);
    if LExtValue = nil then
    begin
      // an absent extension is well-formed with no features
      Result := True;
      Exit;
    end;

    LObj := TAsn1Object.FromByteArray(LExtValue.GetOctets);
    if not Supports(LObj, IAsn1Sequence, LSeq) then
      // present but not a SEQUENCE: malformed TLS Feature
      Exit;

    SetLength(AFeatures, LSeq.Count);
    for LI := 0 to LSeq.Count - 1 do
    begin
      if not Supports(LSeq.Items[LI], IDerInteger, LInt) then
      begin
        AFeatures := nil;
        Exit;
      end;
      if (not LInt.TryGetIntValueExact(LValue)) or (LValue < 0) or
        (LValue > $FFFF) then
      begin
        AFeatures := nil;
        Exit;
      end;
      AFeatures[LI] := UInt16(LValue);
    end;
    Result := True;
  except
    // a present-but-unparseable TLS Feature value is malformed
    AFeatures := nil;
    Result := False;
  end;
end;

function TDefaultCryptoProvider.CertificateKeyUsagePermits(
  const ACertificateDer: TBytes; AUsage: TCertKeyUsage;
  out APermitted: Boolean): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LBits: TArray<Boolean>;
  LIndex: Int32;
begin
  // absent extension or an undeterminable certificate imposes no restriction
  APermitted := True;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificateDer);
    LBits := LCert.GetKeyUsage; // nil when the keyUsage extension is absent
    Result := True;
  except
    // an unparseable certificate cannot be determined; APermitted stays True
    Exit(False);
  end;
  if LBits = nil then
    Exit;
  // RFC 5280 4.2.1.3 bit order: digitalSignature(0), keyEncipherment(2), keyAgreement(4)
  case AUsage of
    TCertKeyUsage.DigitalSignature:
      LIndex := 0;
    TCertKeyUsage.KeyEncipherment:
      LIndex := 2;
    TCertKeyUsage.KeyAgreement:
      LIndex := 4;
  else
    LIndex := -1;
  end;
  // the extension is present, so the bit must be asserted; a bit past the encoded
  // length is an omitted trailing zero, i.e. not asserted
  APermitted := (LIndex >= 0) and (LIndex <= High(LBits)) and LBits[LIndex];
end;

function TDefaultCryptoProvider.CertificateHasRsaPssKey(
  const ACertificateDer: TBytes; out AIsRsaPss: Boolean): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
begin
  AIsRsaPss := False;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificateDer);
    AIsRsaPss := LCert.GetSubjectPublicKeyInfo.GetAlgorithm.GetAlgorithm.GetID
      = RsaSsaPssKeyOid;
    Result := True;
  except
    // an unparseable certificate cannot be determined; AIsRsaPss stays False
    Result := False;
  end;
end;

function TDefaultCryptoProvider.CertificateKeyKind(const ACertificateDer: TBytes;
  out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LAlg: IAlgorithmIdentifier;
  LOid, LCurve: IDerObjectIdentifier;
begin
  AKind := TCertKeyKind.Rsa; // ignored unless Result is True
  AEcNamedGroup := 0;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificateDer);
    LAlg := LCert.GetSubjectPublicKeyInfo.GetAlgorithm;
    LOid := LAlg.Algorithm;
  except
    // an unparseable certificate cannot be classified
    Exit(False);
  end;
  Result := True;
  if LOid.Equals(TPkcsObjectIdentifiers.RsaEncryption) or
    (LOid.GetID = RsaSsaPssKeyOid) then
    AKind := TCertKeyKind.Rsa
  else if LOid.Equals(TEdECObjectIdentifiers.IdEd25519) then
    AKind := TCertKeyKind.Ed25519
  else if LOid.Equals(TEdECObjectIdentifiers.IdEd448) then
    AKind := TCertKeyKind.Ed448
  else if LOid.Equals(TX9ObjectIdentifiers.IdECPublicKey) and (LAlg.Parameters <> nil) and
    Supports(LAlg.Parameters.ToAsn1Object, IDerObjectIdentifier, LCurve) then
  begin
    AKind := TCertKeyKind.Ecdsa;
    // the leaf's named curve as an IANA supported_groups code; 0 when unrecognized
    if LCurve.Equals(TX9ObjectIdentifiers.Prime256v1) then
      AEcNamedGroup := $0017
    else if LCurve.Equals(TSecObjectIdentifiers.SecP384r1) then
      AEcNamedGroup := $0018
    else if LCurve.Equals(TSecObjectIdentifiers.SecP521r1) then
      AEcNamedGroup := $0019;
  end
  else
    // a parseable certificate whose key algorithm we do not model is not classified
    Result := False;
end;

function TDefaultCryptoProvider.CreateKeyAgreement(
  AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  case AAlgorithm of
    TKeyAgreementAlgorithm.X25519:
      Result := TX25519Agreement.Create(FRandom);
    TKeyAgreementAlgorithm.SECP256R1,
    TKeyAgreementAlgorithm.SECP384R1,
    TKeyAgreementAlgorithm.SECP521R1:
      // a NIST prime curve: the SEC curve name is the lowercased enum name
      // (SECP256R1 -> "secp256r1"), which the backend curve registry keys on
      Result := TNistEcAgreement.Create(
        LowerCase(TEnumUtilities.GetName<TKeyAgreementAlgorithm>(AAlgorithm)), FRandom);
  else
    raise ENotSupportedTlsLibException.CreateResFmt(@SUnhandledAlgorithm,
      [Ord(AAlgorithm)]);
  end;
end;

function TDefaultCryptoProvider.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
begin
  case AAlgorithm of
    TKemAlgorithm.ML_KEM_768:
      Result := TKemAdapter.Create(TEnumUtilities.GetName<TKemAlgorithm>(AAlgorithm),
        TMlKemParameters.MlKem768, FRandom);
  else
    raise ENotSupportedTlsLibException.CreateResFmt(@SUnhandledAlgorithm,
      [Ord(AAlgorithm)]);
  end;
end;

function TDefaultCryptoProvider.HasHardwareAes: Boolean;
begin
  Result := FHasHardwareAes;
end;

end.
