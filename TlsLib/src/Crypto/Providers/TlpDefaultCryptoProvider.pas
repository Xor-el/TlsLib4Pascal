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

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  Rtti,
  SyncObjs,
  Generics.Collections,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIRandomGenerator,
  ClpIDigest,
  ClpDigestUtilities,
  ClpIMac,
  ClpHMac,
  ClpIDerivationParameters,
  ClpIHkdfParameters,
  ClpHkdfParameters,
  ClpHkdfBytesGenerator,
  ClpIHkdfBytesGenerator,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIBlockCipher,
  ClpIGcmMultiplier,
  ClpBasicGcmMultiplier,
  ClpAesBitSlicedEngine,
  ClpAesUtilities,
  ClpIAeadPacketCipher,
  ClpAesGcmPacketCipher,
  ClpChaCha20Poly1305PacketCipher,
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
  ClpEphemeralECDHAgreement,
  ClpIEphemeralECDHAgreement,
  ClpECCurveConstants,
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
  ClpNistObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpIEd25519Parameters,
  ClpIEd448Parameters,
  ClpIX509CertificateEntry,
  ClpIAsymmetricKeyEntry,
  ClpIPkcs12Store,
  ClpIPkcs12StoreBuilder,
  ClpPkcs12StoreBuilder,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  ClpNullable,
  ClpValueHelper,
  ClpCryptoLibExceptions,
  TlpCryptoDomainTypes,
  TlpPem,
  TlpBinaryPrimitives,
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpICryptoProvider,
  TlpISigningKey,
  TlpIKeyExchangePrivateKey,
  TlpTlsCredential,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpTls12PrfComposition,
  TlpHpkeComposition,
  TlpSecureMemory,
  TlpTlsAlert,
  TlpDateTimeUtilities,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// A recipe for composing a provider: each nil field takes the default, each
  /// non-nil field replaces that one facet (and <c>Random</c> replaces the entropy
  /// source threaded into the default Primitives and Signing). Composing coherent
  /// facets is the composer's responsibility: any supplied facet or <c>IRandom</c>
  /// must be thread-safe (stateless or internally synchronized), since it slots into
  /// a provider whose accessors promise thread-safety and whose RNG is reached
  /// concurrently from Primitives and Signing.
  /// </summary>
  TCryptoProviderOverrides = record
    Random: IRandom;
    Primitives: ICryptoPrimitives;
    Signing: ISigningCrypto;
    Hpke: IHpkeCrypto;
  end;

  /// <summary>
  /// The default <see cref="ICryptoProvider" />. A thin composition root: it holds one
  /// instance of each facet and its accessors return them. <see cref="Create" /> is the
  /// single composition point; the five facet implementations are private to this unit.
  /// </summary>
  TDefaultCryptoProvider = class(TInterfacedObject, ICryptoProvider)
  strict private
  class var
    FShared: ICryptoProvider;
    FSharedLock: TCriticalSection;
  var
    FPrimitives: ICryptoPrimitives;
    FSigning: ISigningCrypto;
    FHpke: IHpkeCrypto;
  public
    /// <summary>The single composition point. Resolves the effective RNG first (a supplied
    /// AOverrides.Random bridged to the CSPRNG, else a fresh one) and threads that
    /// one instance into the default Primitives and Signing it builds; each nil facet override
    /// is defaulted, each supplied facet is held as-is. A Random override governs only the
    /// default facets, not a supplied Primitives.</summary>
    constructor Create(const AOverrides: TCryptoProviderOverrides); overload;
    /// <summary>An all-defaults provider (no overrides).</summary>
    constructor Create; overload;
    class constructor Create;
    class destructor Destroy;
    /// <summary>A process-wide, lazily-created all-defaults provider: the fallback when no
    /// provider is injected, and the hasher for memo signatures. One CSPRNG seed for the
    /// process, shared (the provider is a stateless service factory). It reflects no
    /// overrides.</summary>
    class function Shared: ICryptoProvider; static;

    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

  /// <summary>
  /// The fluent <see cref="ICryptoProviderBuilder" />: accumulates facet overrides
  /// and composes through <see cref="TDefaultCryptoProvider.Create" /> (zero
  /// duplication - all composition logic stays in that one constructor).
  /// </summary>
  TCryptoProviderBuilder = class(TInterfacedObject, ICryptoProviderBuilder)
  strict private
  var
    FOverrides: TCryptoProviderOverrides;
  public
    function WithRandom(const ARandom: IRandom): ICryptoProviderBuilder;
    function WithPrimitives(const APrimitives: ICryptoPrimitives): ICryptoProviderBuilder;
    function WithSigning(const ASigning: ISigningCrypto): ICryptoProviderBuilder;
    function WithHpke(const AHpke: IHpkeCrypto): ICryptoProviderBuilder;
    function Build: ICryptoProvider;
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
  SMalformedPrivateKey = 'the private key could not be parsed in any supported encoding';
  SUnsupportedKeyAlgorithm = 'the private key uses an algorithm this library cannot sign with';
  SForeignSigningKey = 'the signing key was not produced by this provider';
  SMalformedPublicKey = 'the public key could not be parsed as a SubjectPublicKeyInfo';
  SSchemeKeyFamilyMismatch = 'the signature scheme does not match the key algorithm family';
  SSchemeNotCapable = 'the signing key cannot sign with the requested signature scheme';
  SKeyUnusableForScheme = 'the key cannot be used with the requested signature scheme';
  SInvalidScalarSize =
    'the EC private scalar size (%d) does not match the curve field size (%d)';
  SScalarOutOfRange = 'the EC private scalar is outside the valid range [1, n-1]';
  SForeignKeyExchangeKey =
    'the key-exchange private key was not produced by this crypto provider';
  SKeyExchangeKeyNotExportable =
    'this key-exchange key has no raw scalar to export (a KEM or hybrid key)';
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
    constructor Create(const ARandom: ISecureRandom);
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
    FExtractMac: IMac;
    FExpandGen: IHkdfBytesGenerator;
    function NewDigest: IDigest;
  public
    constructor Create(AAlgorithm: THashAlgorithm);
    function Extract(const ASalt, AIkm: ISecretBuffer): ISecretBuffer;
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
    FPacket: IAeadPacketCipher;
    FKeyPending: Boolean;
    function NewPacketCipher: IAeadPacketCipher;
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

  // The provider-internal face of a minted key-exchange key: the raw scalar (nil for a KEM key,
  // whose ExportRaw is unsupported) and the parsed backend parameter (the EC private key, or the
  // ML-KEM decapsulation key), so an agreement reuses the one parse done at mint. Kept off
  // IKeyExchangePrivateKey so a foreign key handed to Agree/Decapsulate is rejected, not misused.
  IProviderKeyExchangeKey = interface(IInterface)
    ['{2F5A9C3D-8B14-4E6A-9F02-7C1D5B8E3A46}']
    function Scalar: ISecretBuffer;
    function KeyParameter: IAsymmetricKeyParameter;
  end;

  // One key-exchange key class for all three default-backend primitives: it carries the fixed
  // Usage, the raw scalar (for ExportRaw and the scalar-based X25519 agreement), and the parsed
  // parameter (NIST EC private key / ML-KEM decapsulation key). A KEM key is not exportable.
  TKeyExchangePrivateKey = class(TInterfacedObject, IKeyExchangePrivateKey,
    IProviderKeyExchangeKey)
  strict private
  var
    FUsage: TKeyAgreementUsage;
    FScalar: ISecretBuffer;
    FKeyParameter: IAsymmetricKeyParameter;
    FExportable: Boolean;
  public
    constructor Create(AUsage: TKeyAgreementUsage; const AScalar: ISecretBuffer;
      const AKeyParameter: IAsymmetricKeyParameter; AExportable: Boolean);
    destructor Destroy; override;
    function Usage: TKeyAgreementUsage;
    function ExportRaw: ISecretBuffer;
    function Scalar: ISecretBuffer;
    function KeyParameter: IAsymmetricKeyParameter;
  end;

  // X25519 key agreement wrapped as a group's IKeyAgreement.
  TX25519Agreement = class(TInterfacedObject, IKeyAgreement)
  strict private
  var
    FRandom: ISecureRandom;
  public
    constructor Create(const ARandom: ISecureRandom);
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
      out APublicKey: TBytes);
    function Agree(const APrivateKey: IKeyExchangePrivateKey;
      const APeerPublicKey: TBytes): ISecretBuffer;
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
    function ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
      AUsage: TKeyAgreementUsage; out APublicKey: TBytes): IKeyExchangePrivateKey;
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
      const APeer: IECPublicKeyParameters; AUsage: TKeyAgreementUsage): ISecretBuffer;
    /// <summary>Validates a raw EC private scalar and returns it: it must be exactly the curve
    /// field size and lie in [1, n-1] (RFC 5915 / SEC1). Raises EArgumentTlsLibException
    /// otherwise, rather than letting an out-of-range scalar reduce mod n inside the backend.</summary>
    function ScalarFromBytes(const ARaw: TBytes): TBigInteger;
  public
    constructor Create(const AName: string; const ARandom: ISecureRandom);
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
      out APublicKey: TBytes);
    function Agree(const APrivateKey: IKeyExchangePrivateKey;
      const APeerPublicKey: TBytes): ISecretBuffer;
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
    function ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
      AUsage: TKeyAgreementUsage; out APublicKey: TBytes): IKeyExchangePrivateKey;
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
    procedure GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
      out APublicKey: TBytes);
    procedure Encapsulate(const APeerPublicKey: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APrivateKey: IKeyExchangePrivateKey;
      const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
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
    constructor Create(const APassword: ISecretBuffer);
    destructor Destroy; override;
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
    class function KeyParamFromPem(const AData: TBytes;
      const APassword: ISecretBuffer): IAsymmetricKeyParameter; static;
    class function KeyParamFromDer(const AData: TBytes;
      const APassword: ISecretBuffer): IAsymmetricKeyParameter; static;
  public
    /// <summary>The passphrase's code units as the character array the PEM/PKCS#12 backends
    /// expect; nil or an empty buffer yields nil. Wipe it with WipePasswordChars after use.</summary>
    class function PasswordChars(const APassword: ISecretBuffer): TArray<Char>; static;
    /// <summary>Zeroes a password character array in place.</summary>
    class procedure WipePasswordChars(var APassword: TArray<Char>); static;
    class function ImportKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey; static;
    /// <summary>The one signing-key construction path: normalizes a parsed private-key
    /// parameter to canonical PKCS#8 (held wipeably), derives its schemes, and wraps it.
    /// Both raw-key and PKCS#12 import funnel through here. Raises ENotSupported for a key
    /// algorithm this library cannot sign with.</summary>
    class function SigningKeyFromParam(
      const AKeyParam: IAsymmetricKeyParameter): ISigningKey; static;
  end;

  // Resolves a hash algorithm to its digest. A stateless leaf shared by
  // the primitives and the path validator's anchor-key hash.
  TDigestResolver = class sealed(TObject)
  public
    class function Resolve(AAlgorithm: THashAlgorithm): IDigest; static;
  end;

  // Bridges a facet IRandom into the random generator a TSecureRandom
  // draws from, so a supplied entropy source governs the default facets' key
  // generation. Seed material is ignored - the source is already a CSPRNG.
  TRandomGeneratorBridge = class(TInterfacedObject, IRandomGenerator)
  strict private
  var
    FRandom: IRandom;
  public
    constructor Create(const ARandom: IRandom);
    procedure AddSeedMaterial(const ASeed: TCryptoLibByteArray); overload;
    procedure AddSeedMaterial(ASeed: Int64); overload;
    procedure NextBytes(const ABytes: TCryptoLibByteArray); overload;
    procedure NextBytes(const ABytes: TCryptoLibByteArray;
      AStart, ALen: Int32); overload;
  end;

  // ICryptoPrimitives - CSPRNG, hashes / HMAC / HKDF, AEAD, key agreement and KEM.
  TCryptoPrimitives = class(TInterfacedObject, ICryptoPrimitives)
  strict private
  var
    FRandom: ISecureRandom;
    FRandomFacet: IRandom;
    FHasHardwareAes: Boolean;
  public
    constructor Create(const ARandom: ISecureRandom; AHasHardwareAes: Boolean);
    function GetRandom: IRandom;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
    function CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
    function CreateKeyAgreement(AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
    function CreateKem(AAlgorithm: TKemAlgorithm): IKem;
    function HasHardwareAes: Boolean;
  end;

  // ISigningCrypto - imports signing keys / PKCS#12 identities and mints signers / verifiers.
  TSigningCrypto = class(TInterfacedObject, ISigningCrypto)
  strict private
  var
    FRandom: ISecureRandom;
    class function SignerMechanismForScheme(AScheme: TSignatureScheme): string; static;
    /// <summary>Classifies a parsed public key into its TLS key family; False for a key kind the
    /// provider does not model (e.g. X25519/DH/DSA), which the verifier factory then rejects since
    /// no catalogued signature scheme can be verified with such a key.</summary>
    class function KeyKindOf(const AKey: IAsymmetricKeyParameter;
      out AKind: TSignatureKeyKind): Boolean; static;
  public
    constructor Create(const ARandom: ISecureRandom);
    function ImportSigningKey(const AData: TBytes): ISigningKey; overload;
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey; overload;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TTlsCredential;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

{ TRandomAdapter }

constructor TRandomAdapter.Create(const ARandom: ISecureRandom);
begin
  inherited Create;
  FRandom := ARandom;
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
  FExtractMac := THMac.Create(NewDigest) as IMac;
  FExpandGen := THkdfBytesGenerator.Create(NewDigest) as IHkdfBytesGenerator;
end;

function THkdfAdapter.NewDigest: IDigest;
begin
  Result := TDigestUtilities.GetDigest(TEnumUtilities.GetName<THashAlgorithm>(FAlgorithm));
end;

function THkdfAdapter.Extract(const ASalt, AIkm: ISecretBuffer): ISecretBuffer;
var
  LMac: IMac;
  LSalt, LIkmBytes, LPrk: TBytes;
begin
  LMac := FExtractMac;
  // a nil or empty salt is HashLen zeros; otherwise the salt is secret material, so it is
  // materialised into a private copy here and wiped, not aliased from the caller
  if (ASalt = nil) or (ASalt.Len = 0) then
    SetLength(LSalt, LMac.GetMacSize)
  else
    LSalt := ASalt.ToBytes;
  try
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
  finally
    TSecureMemory.WipeBytes(LSalt);
  end;
end;

function THkdfAdapter.Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
  ALength: Int32): ISecretBuffer;
var
  LGen: IHkdfBytesGenerator;
  LParams: IHkdfParameters;
  LPrkBytes, LOkm: TBytes;
begin
  LGen := FExpandGen;
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
  // releasing the retained packet cipher lets its mode wipe round-key/subkey/GHASH state
  FPacket := nil;
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

function TAeadAdapter.NewPacketCipher: IAeadPacketCipher;
begin
  case FKind of
    TAeadKind.AesGcm:
      // keep the same engine/multiplier selection the per-record path used: hardware AES + a
      // basic multiplier when available, else a constant-time bitsliced AES + constant-time
      // software GHASH (the parameterless packet ctor would silently pick T-table AES here)
      if FHasHardwareAes then
        Result := TAesGcmPacketCipher.Create(TAesUtilities.CreateEngine(),
          TBasicGcmMultiplier.Create as IGcmMultiplier)
      else
        Result := TAesGcmPacketCipher.Create(TAesBitSlicedEngine.Create as IBlockCipher,
          TBasicGcmMultiplier.Create as IGcmMultiplier);
    TAeadKind.ChaChaPoly:
      Result := TChaCha20Poly1305PacketCipher.Create;
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
  FKeyPending := True;
end;

function TAeadAdapter.Process(AForEncryption: Boolean;
  const ANonce, AAad, AInput: TBytes): TBytes;
var
  LKey, LOut: TBytes;
  LUsedKey: Boolean;
  LLen: Int32;
begin
  if System.Length(ANonce) <> FNonceSize then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidNonceSize,
      [System.Length(ANonce), FNonceSize]);
  // one packet-cipher instance per adapter, and the driver installs an adapter for one
  // direction only (read or write); the connection is already single-threaded (unsynchronized
  // FSeq), so reusing the mode across records is safe (the mode is not thread-safe)
  if FPacket = nil then
    FPacket := NewPacketCipher;
  // key the mode on the first record after Init; later records pass nil to reuse the schedule
  LUsedKey := FKeyPending;
  if LUsedKey then
    LKey := FKey.ToBytes
  else
    LKey := nil;
  try
    LOut := nil;
    SetLength(LOut, FPacket.GetOutputSize(AForEncryption, System.Length(AInput), FTagSize * 8));
    LLen := FPacket.ProcessPacket(AForEncryption, LKey, ANonce, AAad, AInput, 0,
      System.Length(AInput), LOut, 0, FTagSize * 8);
    SetLength(LOut, LLen);
    // clear the pending flag only after the mode accepted and retained the key, so a throw
    // mid-init leaves the next record to re-supply it rather than pass nil to an unkeyed mode
    if LUsedKey then
      FKeyPending := False;
    Result := LOut;
  finally
    TSecureMemory.WipeBytes(LKey);
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

{ TKeyExchangePrivateKey }

constructor TKeyExchangePrivateKey.Create(AUsage: TKeyAgreementUsage;
  const AScalar: ISecretBuffer; const AKeyParameter: IAsymmetricKeyParameter;
  AExportable: Boolean);
begin
  inherited Create;
  FUsage := AUsage;
  FScalar := AScalar;
  FKeyParameter := AKeyParameter;
  FExportable := AExportable;
end;

destructor TKeyExchangePrivateKey.Destroy;
begin
  FScalar := nil;
  FKeyParameter := nil;
  inherited Destroy;
end;

function TKeyExchangePrivateKey.Usage: TKeyAgreementUsage;
begin
  Result := FUsage;
end;

function TKeyExchangePrivateKey.ExportRaw: ISecretBuffer;
begin
  if (not FExportable) or (FScalar = nil) then
    raise ENotSupportedTlsLibException.CreateRes(@SKeyExchangeKeyNotExportable);
  Result := FScalar;
end;

function TKeyExchangePrivateKey.Scalar: ISecretBuffer;
begin
  Result := FScalar;
end;

function TKeyExchangePrivateKey.KeyParameter: IAsymmetricKeyParameter;
begin
  Result := FKeyParameter;
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

procedure TX25519Agreement.GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
  out APublicKey: TBytes);
var
  LX25519: IX25519PrivateKeyParameters;
  LPrivBytes: TBytes;
begin
  LX25519 := TX25519PrivateKeyParameters.Create(FRandom);
  APublicKey := LX25519.GeneratePublicKey.GetEncoded;
  LPrivBytes := LX25519.GetEncoded;
  try
    APrivateKey := TKeyExchangePrivateKey.Create(TKeyAgreementUsage.Ephemeral,
      TSecretBuffer.From(LPrivBytes), nil, True);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

function TX25519Agreement.Agree(const APrivateKey: IKeyExchangePrivateKey;
  const APeerPublicKey: TBytes): ISecretBuffer;
var
  LKey: IProviderKeyExchangeKey;
  LPriv: IX25519PrivateKeyParameters;
  LPrivBytes, LSecret: TBytes;
begin
  // X25519's ladder is constant-time regardless of scalar reuse, so the key's Usage has no
  // effect here.
  if not Supports(APrivateKey, IProviderKeyExchangeKey, LKey) then
    raise EArgumentTlsLibException.CreateRes(@SForeignKeyExchangeKey);
  LPrivBytes := LKey.Scalar.ToBytes;
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

function TX25519Agreement.ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
  AUsage: TKeyAgreementUsage; out APublicKey: TBytes): IKeyExchangePrivateKey;
var
  LPriv: IX25519PrivateKeyParameters;
  LPrivBytes: TBytes;
begin
  LPrivBytes := ARawPrivateKey.ToBytes;
  try
    // X25519 clamps the scalar, so any 32 bytes are usable, but a wrong length is a caller
    // error (a truncated/overlong buffer) rather than something to silently accept
    if System.Length(LPrivBytes) <> TX25519PrivateKeyParameters.KeySize then
      raise EArgumentTlsLibException.CreateResFmt(@SInvalidScalarSize,
        [System.Length(LPrivBytes), Int32(TX25519PrivateKeyParameters.KeySize)]);
    LPriv := TX25519PrivateKeyParameters.Create(LPrivBytes);
    APublicKey := LPriv.GeneratePublicKey.GetEncoded;
    // the raw scalar is the neutral currency; keep it for ExportRaw and the agreement
    Result := TKeyExchangePrivateKey.Create(AUsage, TSecretBuffer.From(LPrivBytes),
      nil, True);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
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
  const APeer: IECPublicKeyParameters; AUsage: TKeyAgreementUsage): ISecretBuffer;
var
  LAgreement: IEphemeralECDHAgreement;
  LBlindBits: Int32;
  LZ: TBytes;
begin
  // A fresh single-use scalar has no cross-operation leakage to defeat, so the
  // deterministic fixed-length posture suffices. A long-lived scalar reused against
  // attacker-chosen points needs full per-operation random scalar blinding.
  if AUsage = TKeyAgreementUsage.Static then
    LBlindBits := TECCurveConstants.SCALAR_BLIND_FULL
  else
    LBlindBits := TECCurveConstants.SCALAR_BLIND_DETERMINISTIC;
  LAgreement := TEphemeralECDHAgreement.Create(APriv, LBlindBits);
  LZ := TBigIntegerUtilities.AsUnsignedByteArray(FFieldSize, LAgreement.CalculateAgreement(APeer));
  try
    Result := TSecretBuffer.From(LZ);
  finally
    TSecureMemory.WipeBytes(LZ);
  end;
end;

procedure TNistEcAgreement.GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
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
    // keep the parsed EC key parameter so Agree does not re-parse the scalar; the raw scalar
    // is retained for ExportRaw
    APrivateKey := TKeyExchangePrivateKey.Create(TKeyAgreementUsage.Ephemeral,
      TSecretBuffer.From(LPrivBytes), LPriv, True);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
  end;
end;

function TNistEcAgreement.ScalarFromBytes(const ARaw: TBytes): TBigInteger;
begin
  if System.Length(ARaw) <> FFieldSize then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidScalarSize,
      [System.Length(ARaw), FFieldSize]);
  // an unsigned scalar; reject 0 and anything >= n rather than let [d]G silently reduce d mod n
  Result := TBigInteger.Create(1, ARaw);
  if (Result.SignValue <= 0) or (Result.CompareTo(FDomain.N) >= 0) then
    raise EArgumentTlsLibException.CreateRes(@SScalarOutOfRange);
end;

function TNistEcAgreement.Agree(const APrivateKey: IKeyExchangePrivateKey;
  const APeerPublicKey: TBytes): ISecretBuffer;
var
  LKey: IProviderKeyExchangeKey;
  LPrivParams: IECPrivateKeyParameters;
begin
  if not Supports(APrivateKey, IProviderKeyExchangeKey, LKey) then
    raise EArgumentTlsLibException.CreateRes(@SForeignKeyExchangeKey);
  // a key from a different primitive (a KEM has no scalar; X25519 or a different curve has a
  // different scalar width) is rejected rather than agreed under the wrong domain - the length
  // gate the pre-handle Agree applied when it re-parsed the scalar
  if (LKey.Scalar = nil) or (LKey.Scalar.Len <> FFieldSize) then
    raise EArgumentTlsLibException.CreateRes(@SForeignKeyExchangeKey);
  // reuse the EC key parameter parsed at mint; the key's Usage drives the blinding posture
  LPrivParams := LKey.KeyParameter as IECPrivateKeyParameters;
  Result := AgreeParams(LPrivParams, WrapPeer(APeerPublicKey), APrivateKey.Usage);
end;

function TNistEcAgreement.ValidatePublicKey(const APublicKey: TBytes): Boolean;
const
  UncompressedPointPrefix = $04; // SEC1 uncompressed EC point form
var
  LPoint: IECPoint;
begin
  Result := False;
  // an EC key share must use the uncompressed point form: RFC 8446 4.2.8.2 (TLS 1.3)
  // and RFC 8422 5.1.2 (TLS 1.2 and earlier) both mandate it and forbid compressed/
  // hybrid, so reject those up front - the caller then yields illegal_parameter
  if (System.Length(APublicKey) = 0) or (APublicKey[0] <> UncompressedPointPrefix) then
    Exit;
  try
    LPoint := FDomain.Curve.DecodePoint(APublicKey);
    Result := (not LPoint.IsInfinity) and LPoint.IsValid;
  except
    Result := False;
  end;
end;

function TNistEcAgreement.ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
  AUsage: TKeyAgreementUsage; out APublicKey: TBytes): IKeyExchangePrivateKey;
var
  LScalar: TBytes;
  LD: TBigInteger;
begin
  LScalar := ARawPrivateKey.ToBytes;
  try
    // d validated in [1, n-1]; the public value is the SEC1 uncompressed encoding of [d]G
    LD := ScalarFromBytes(LScalar);
    APublicKey := FDomain.G.Multiply(LD).Normalize.GetEncoded(False);
    // parse the EC key parameter once here so a later Agree reuses it; keep the raw scalar
    Result := TKeyExchangePrivateKey.Create(AUsage, TSecretBuffer.From(LScalar),
      TECPrivateKeyParameters.Create(LD, FDomain), True);
  finally
    TSecureMemory.WipeBytes(LScalar);
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

procedure TKemAdapter.GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
  out APublicKey: TBytes);
var
  LGen: IMlKemKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
begin
  LGen := TMlKemKeyPairGenerator.Create;
  LGen.Init(TMlKemKeyGenerationParameters.Create(FRandom, FParams) as IKeyGenerationParameters);
  LKp := LGen.GenerateKeyPair;
  APublicKey := (LKp.Public as IMlKemPublicKeyParameters).GetEncoded;
  // hold the parsed decapsulation key so Decapsulate does not re-decode it; a KEM key has no
  // single raw scalar, so it is not exportable
  APrivateKey := TKeyExchangePrivateKey.Create(TKeyAgreementUsage.Ephemeral, nil,
    LKp.Private, False);
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

procedure TKemAdapter.Decapsulate(const APrivateKey: IKeyExchangePrivateKey;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LKey: IProviderKeyExchangeKey;
  LDec: IKemDecapsulator;
  LSecret: TBytes;
begin
  if not Supports(APrivateKey, IProviderKeyExchangeKey, LKey) then
    raise EArgumentTlsLibException.CreateRes(@SForeignKeyExchangeKey);
  try
    LDec := TMlKemDecapsulator.Create(FParams);
    // reuse the decapsulation key parsed at mint
    LDec.Init(LKey.KeyParameter as IMlKemPrivateKeyParameters);
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

constructor TStaticPasswordFinder.Create(const APassword: ISecretBuffer);
begin
  inherited Create;
  FPassword := TCredentialImport.PasswordChars(APassword);
end;

destructor TStaticPasswordFinder.Destroy;
begin
  TCredentialImport.WipePasswordChars(FPassword);
  inherited Destroy;
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
  const APassword: ISecretBuffer): TArray<Char>;

  function Utf8ToChars(const AUtf8: TBytes): TArray<Char>;
  begin
  {$IF SizeOf(Char) = 1}
    // a one-byte Char: the passphrase's UTF-8 octets are the char array, copied as-is
    SetLength(Result, System.Length(AUtf8));
    Move(AUtf8[0], Result[0], System.Length(AUtf8));
  {$ELSE}
    // a wide Char: decode the UTF-8 octets to characters
    Result := TEncoding.UTF8.GetChars(AUtf8);
  {$IFEND}
  end;

begin
  Result := nil;
  // nil and a zero-length buffer both yield no chars (an empty passphrase)
  if (APassword = nil) or (APassword.Len = 0) then
    Exit;
  Result := Utf8ToChars(APassword.ToBytes);
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

// The private half of the key object the PEM reader returned (a bare key parameter,
// or the private key of a returned key pair).
class function TCredentialImport.KeyParamFromPem(const AData: TBytes;
  const APassword: ISecretBuffer): IAsymmetricKeyParameter;
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
    if APassword <> nil then
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
  const APassword: ISecretBuffer): IAsymmetricKeyParameter;
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
        if APassword = nil then
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
  const APassword: ISecretBuffer): ISigningKey;
var
  LKeyParam: IAsymmetricKeyParameter;
begin
  try
    if TPem.IsArmored(AData) then
      LKeyParam := KeyParamFromPem(AData, APassword)
    else
      LKeyParam := KeyParamFromDer(AData, APassword);
    Result := SigningKeyFromParam(LKeyParam);
  except
    on E: EBaseTlsLibException do
      raise;
    on E: Exception do
      raise EArgumentTlsLibException.CreateRes(@SMalformedPrivateKey);
  end;
end;

{ TDefaultCryptoProvider }

constructor TDefaultCryptoProvider.Create(const AOverrides: TCryptoProviderOverrides);
var
  LRandom: ISecureRandom;
begin
  inherited Create;
  // resolve the effective entropy source first, then thread that ONE instance into the
  // default Primitives and Signing this ctor builds; a supplied Random governs only the
  // facets built here, never a supplied Primitives override
  if AOverrides.Random <> nil then
    LRandom := TSecureRandom.Create(TRandomGeneratorBridge.Create(AOverrides.Random)
      as IRandomGenerator)
  else
    LRandom := TSecureRandom.Create;

  if AOverrides.Primitives <> nil then
    FPrimitives := AOverrides.Primitives
  else
    FPrimitives := TCryptoPrimitives.Create(LRandom,
      TAesUtilities.IsHardwareAccelerated()) as ICryptoPrimitives;

  if AOverrides.Signing <> nil then
    FSigning := AOverrides.Signing
  else
    FSigning := TSigningCrypto.Create(LRandom) as ISigningCrypto;

  if AOverrides.Hpke <> nil then
    FHpke := AOverrides.Hpke
  else
    FHpke := THpkeComposition.Create(FPrimitives) as IHpkeCrypto;
end;

constructor TDefaultCryptoProvider.Create;
var
  LOverrides: TCryptoProviderOverrides;
begin
  LOverrides := Default(TCryptoProviderOverrides);
  Create(LOverrides);
end;

{ TDigestResolver }

class function TDigestResolver.Resolve(AAlgorithm: THashAlgorithm): IDigest;
begin
  Result := TDigestUtilities.GetDigest(
    TEnumUtilities.GetName<THashAlgorithm>(AAlgorithm));
end;

{ TRandomGeneratorBridge }

constructor TRandomGeneratorBridge.Create(const ARandom: IRandom);
begin
  inherited Create;
  FRandom := ARandom;
end;

procedure TRandomGeneratorBridge.AddSeedMaterial(const ASeed: TCryptoLibByteArray);
begin
  // the wrapped source is already a CSPRNG; reseeding is a no-op
end;

procedure TRandomGeneratorBridge.AddSeedMaterial(ASeed: Int64);
begin
  // the wrapped source is already a CSPRNG; reseeding is a no-op
end;

procedure TRandomGeneratorBridge.NextBytes(const ABytes: TCryptoLibByteArray);
begin
  NextBytes(ABytes, 0, System.Length(ABytes));
end;

procedure TRandomGeneratorBridge.NextBytes(const ABytes: TCryptoLibByteArray;
  AStart, ALen: Int32);
var
  LGen: TBytes;
begin
  if ALen <= 0 then
    Exit;
  // the generated bytes may seed key material downstream; wipe this copy once handed over
  LGen := FRandom.GenerateBytes(ALen);
  try
    System.Move(LGen[0], ABytes[AStart], ALen);
  finally
    TSecureMemory.WipeBytes(LGen);
  end;
end;

{ TCryptoPrimitives }

constructor TCryptoPrimitives.Create(const ARandom: ISecureRandom;
  AHasHardwareAes: Boolean);
begin
  inherited Create;
  FRandom := ARandom;
  FHasHardwareAes := AHasHardwareAes;
  // one stable IRandom bound to the provider's effective RNG, so GetRandom is a
  // connected view (not a fresh, disconnected stream on every call)
  FRandomFacet := TRandomAdapter.Create(ARandom);
end;

{ TSigningCrypto }

constructor TSigningCrypto.Create(const ARandom: ISecureRandom);
begin
  inherited Create;
  FRandom := ARandom;
end;

class function TSigningCrypto.SignerMechanismForScheme(
  AScheme: TSignatureScheme): string;
begin
  // map a TLS 1.3 signature scheme to a signer mechanism. The named
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

function TDefaultCryptoProvider.Primitives: ICryptoPrimitives;
begin
  Result := FPrimitives;
end;

function TDefaultCryptoProvider.Signing: ISigningCrypto;
begin
  Result := FSigning;
end;

function TDefaultCryptoProvider.Hpke: IHpkeCrypto;
begin
  Result := FHpke;
end;

function TCryptoPrimitives.GetRandom: IRandom;
begin
  Result := FRandomFacet;
end;

function TCryptoPrimitives.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := THashAdapter.Create(TDigestResolver.Resolve(AAlgorithm));
end;

function TCryptoPrimitives.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := THmacAdapter.Create(TDigestResolver.Resolve(AAlgorithm));
end;

function TCryptoPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := THkdfAdapter.Create(AAlgorithm);
end;

function TCryptoPrimitives.CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
begin
  Result := TTls12PrfComposition.Create(Self, AAlgorithm) as ITls12Prf;
end;

function TCryptoPrimitives.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
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

function TSigningCrypto.ImportSigningKey(const AData: TBytes): ISigningKey;
begin
  Result := TCredentialImport.ImportKey(AData, nil);
end;

function TSigningCrypto.ImportSigningKey(const AData: TBytes;
  const APassword: ISecretBuffer): ISigningKey;
begin
  Result := TCredentialImport.ImportKey(AData, APassword);
end;

class function TSigningCrypto.KeyKindOf(const AKey: IAsymmetricKeyParameter;
  out AKind: TSignatureKeyKind): Boolean;
begin
  Result := True;
  if Supports(AKey, IRsaKeyParameters) then
    AKind := TSignatureKeyKind.Rsa
  else if Supports(AKey, IECPublicKeyParameters) then
    AKind := TSignatureKeyKind.Ecdsa
  else if Supports(AKey, IEd25519PublicKeyParameters) then
    AKind := TSignatureKeyKind.Ed25519
  else if Supports(AKey, IEd448PublicKeyParameters) then
    AKind := TSignatureKeyKind.Ed448
  else
    Result := False;
end;

function TSigningCrypto.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
var
  LProviderKey: IProviderSigningKey;
  LKey: IAsymmetricKeyParameter;
begin
  if not Supports(AKey, IProviderSigningKey, LProviderKey) then
    raise EArgumentTlsLibException.CreateRes(@SForeignSigningKey);
  // the key may only sign with a scheme it declared capable of (the import narrows this, and
  // WithPreferredSchemes narrows it further); refuse anything else rather than let the backend
  // produce a signature the key was never meant to make
  if not (TArrayUtilities.Contains<TSignatureScheme>(AKey.CapableSchemes, AScheme)) then
    raise EArgumentTlsLibException.CreateRes(@SSchemeNotCapable);
  // the key was parsed and validated once at import; reuse it rather than re-parsing and
  // re-validating it on every sign - InitSigner still makes a fresh per-call signer for
  // the digest state, so concurrent handshakes stay independent
  LKey := LProviderKey.KeyParameter;
  try
    Result := TSignatureSignerAdapter.Create(
      TSignerUtilities.InitSigner(SignerMechanismForScheme(AScheme), True, LKey, FRandom),
      TEnumUtilities.GetName<TSignatureScheme>(AScheme));
  except
    // a backend rejection here is a key/scheme problem our own config produced; keep a typed
    // exception at the seam rather than letting a raw backend exception cross it
    on E: ECryptoLibException do
      raise EArgumentTlsLibException.CreateRes(@SKeyUnusableForScheme);
  end;
end;

function TSigningCrypto.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
var
  LKey: IAsymmetricKeyParameter;
  LKind: TSignatureKeyKind;
  LSigner: ISigner;
begin
  // parse the SubjectPublicKeyInfo behind a typed exception (a malformed SPKI is a caller/peer
  // input problem, never a raw backend exception crossing the seam)
  try
    LKey := TPublicKeyFactory.CreateKey(APublicKeyDer);
  except
    on E: ECryptoLibException do
      raise EArgumentTlsLibException.CreateRes(@SMalformedPublicKey);
  end;
  // bind the scheme's key family to the key: an EC key under rsa_pss_rsae_*, or an RSA key under
  // ecdsa_*, could otherwise reach a backend signer that raises an untyped exception (RFC 8446
  // 4.2.3). Fail closed on a key family we cannot classify too: every catalogued scheme signs with
  // one of the four known families, so an unclassifiable key can never verify any scheme, and
  // letting it reach the backend risks a raw cast exception crossing the seam. The curve-vs-scheme
  // bind stays a TLS 1.3 handshake concern (TCertificateVerify).
  if (not KeyKindOf(LKey, LKind)) or (LKind <> AScheme.KeyKind) then
    raise EArgumentTlsLibException.CreateRes(@SSchemeKeyFamilyMismatch);
  try
    LSigner := TSignerUtilities.GetSigner(SignerMechanismForScheme(AScheme));
    LSigner.Init(False, LKey);
  except
    on E: ECryptoLibException do
      raise EArgumentTlsLibException.CreateRes(@SKeyUnusableForScheme);
  end;
  Result := TSignatureVerifierAdapter.Create(LSigner,
    TEnumUtilities.GetName<TSignatureScheme>(AScheme));
end;

function TSigningCrypto.ImportPkcs12(const AData: TBytes;
  const APassword: ISecretBuffer): TTlsCredential;
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

class constructor TDefaultCryptoProvider.Create;
begin
  FSharedLock := TCriticalSection.Create;
end;

class destructor TDefaultCryptoProvider.Destroy;
begin
  FShared := nil;
  FSharedLock.Free;
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

function TCryptoPrimitives.CreateKeyAgreement(
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

function TCryptoPrimitives.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
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

function TCryptoPrimitives.HasHardwareAes: Boolean;
begin
  Result := FHasHardwareAes;
end;

{ TCryptoProviderBuilder }

function TCryptoProviderBuilder.WithRandom(
  const ARandom: IRandom): ICryptoProviderBuilder;
begin
  FOverrides.Random := ARandom;
  Result := Self;
end;

function TCryptoProviderBuilder.WithPrimitives(
  const APrimitives: ICryptoPrimitives): ICryptoProviderBuilder;
begin
  FOverrides.Primitives := APrimitives;
  Result := Self;
end;

function TCryptoProviderBuilder.WithSigning(
  const ASigning: ISigningCrypto): ICryptoProviderBuilder;
begin
  FOverrides.Signing := ASigning;
  Result := Self;
end;

function TCryptoProviderBuilder.WithHpke(
  const AHpke: IHpkeCrypto): ICryptoProviderBuilder;
begin
  FOverrides.Hpke := AHpke;
  Result := Self;
end;

function TCryptoProviderBuilder.Build: ICryptoProvider;
begin
  Result := TDefaultCryptoProvider.Create(FOverrides) as ICryptoProvider;
end;

end.
