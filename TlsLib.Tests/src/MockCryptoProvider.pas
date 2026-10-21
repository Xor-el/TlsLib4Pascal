{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockCryptoProvider;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpISigningKey,
  TlpImportedCredential,
  TlpIKeyExchangePrivateKey,
  TlpICryptoProvider,
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  TlpDefaultCryptoProvider;

type
  /// <summary>A signature verifier that rejects every signature.</summary>
  TRejectingSignatureVerifier = class(TInterfacedObject, ISignatureVerifier)
  public
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Verify(const ASignature: TBytes): Boolean;
  end;

  /// <summary>An opaque signing key that holds nothing and signs nothing, for tests that only
  /// route a key (compared by reference) through code that never uses it.</summary>
  TMockSigningKey = class(TInterfacedObject, ISigningKey)
  public
    function CapableSchemes: TArray<TSignatureScheme>;
    function PublicKeyInfo: TBytes;
    function WithPreferredSchemes(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
  end;

  /// <summary>A signing key that reports fixed schemes and a fixed public key and has no
  /// private key material; WithPreferredSchemes keeps the requested schemes the key can
  /// sign.</summary>
  TFakeSigningKey = class(TInterfacedObject, ISigningKey)
  strict private
  var
    FSchemes: TArray<TSignatureScheme>;
    FPublicKeyInfo: TBytes;
  strict protected
    function Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey; virtual;
  public
    constructor Create(const ASchemes: TArray<TSignatureScheme>); overload;
    constructor Create(const ASchemes: TArray<TSignatureScheme>;
      const APublicKeyInfo: TBytes); overload;
    function CapableSchemes: TArray<TSignatureScheme>;
    function PublicKeyInfo: TBytes;
    function WithPreferredSchemes(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
  end;

  /// <summary>An HPKE suite that seals nothing; a test only asks whether one was granted.</summary>
  TFakeHpkeSuite = class sealed(TInterfacedObject, IHpkeSuite)
  strict private
  var
    FKem, FKdf, FAead: UInt16;
  public
    constructor Create(AKem, AKdf, AAead: UInt16);
    function Kem: UInt16;
    function Kdf: UInt16;
    function Aead: UInt16;
    function AeadTagLength: Int32;
    procedure SetupSealer(const ARecipientPublicKey, AInfo: TBytes; out AEnc: TBytes;
      out ASealer: IHpkeSealer);
  end;

  /// <summary>A foreign HPKE facet, not composed over any primitives, that offers every KEM and
  /// the three AEADs and counts the key operations that reach it. Never for production
  /// use.</summary>
  TFakeHpke = class sealed(TInterfacedObject, IHpkeCrypto)
  strict private
  var
    FRecipientImports: Int32;
    FKeyPairs: Int32;
    FPrivateImports: Int32;
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
    property RecipientImports: Int32 read FRecipientImports;
    property KeyPairs: Int32 read FKeyPairs;
    property PrivateImports: Int32 read FPrivateImports;
  end;

  /// <summary>An <see cref="ISigningCrypto" /> that signs and imports through an inner facet but
  /// hands out verifiers that reject every signature, so a peer's handshake signature never
  /// verifies while its certificate chain (checked by the PKIX provider) still does.</summary>
  TRejectingVerifierSigning = class sealed(TInterfacedObject, ISigningCrypto)
  strict private
  var
    FInner: ISigningCrypto;
  public
    constructor Create(const AInner: ISigningCrypto);
    function ImportSigningKey(const AData: TBytes; const APassword: ISecretBuffer): ISigningKey;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TImportedCredential;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;


  /// <summary>
  /// A test provider that runs the default crypto with a caller-supplied
  /// (deterministic) <see cref="IRandom" />. It is a thin wrapper over the
  /// composition seam - a provider built with the random override - so
  /// <c>Primitives.GetRandom</c> hands back the injected stream while every crypto
  /// operation is the real default. This is the seam an engine leans on to run with
  /// a fixed randomness stream.
  /// </summary>
  TMockCryptoProvider = class sealed(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FComposed: ICryptoProvider;
  public
    constructor Create(const ARandom: IRandom);
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

  /// <summary>
  /// An <see cref="ICryptoPrimitives" /> decorator that forces a fixed
  /// <c>HasHardwareAes</c> answer and forwards every other primitive to an inner
  /// primitives facet.
  /// </summary>
  TFixedAesPrimitives = class sealed(TInterfacedObject, ICryptoPrimitives)
  strict private
  var
    FInner: ICryptoPrimitives;
    FHasHardwareAes: Boolean;
  public
    constructor Create(const AInner: ICryptoPrimitives; AHasHardwareAes: Boolean);
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

  /// <summary>
  /// A test provider that forces a fixed <c>HasHardwareAes</c> answer while running
  /// the real crypto. It is a thin wrapper over the composition seam - a provider
  /// built with a primitives override that decorates the inner's primitives - and
  /// makes the CPU-adaptive AEAD ordering deterministic in tests.
  /// </summary>
  TFixedAesProvider = class sealed(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FComposed: ICryptoProvider;
  public
    constructor Create(const AInner: ICryptoProvider; AHasHardwareAes: Boolean);
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

  /// <summary>
  /// An <see cref="ICryptoPrimitives" /> decorator that cannot build one configured AEAD - it
  /// raises ENotSupportedTlsLibException for that algorithm and forwards everything else - so a
  /// composed provider models an overlay that lacks a primitive (for the HPKE suite-probe check).
  /// </summary>
  TMissingAeadPrimitives = class sealed(TInterfacedObject, ICryptoPrimitives)
  strict private
  var
    FInner: ICryptoPrimitives;
    FMissing: TAeadAlgorithm;
    FHasMissingAead: Boolean;
    FMissingAgreement: TKeyAgreementAlgorithm;
    FHasMissingAgreement: Boolean;
    FLenientKem: Boolean;
    FFault: ExceptClass;
  public
    constructor Create(const AInner: ICryptoPrimitives; AMissing: TAeadAlgorithm); overload;
    /// <summary>From now on the missing AEAD fails with AFault, a plain Exception as a third
    /// party's might or a fatal one, instead of the library's not-supported error.</summary>
    procedure ArmFault(AFault: ExceptClass);
    /// <summary>Models a facet that cannot build one key agreement instead.</summary>
    constructor Create(const AInner: ICryptoPrimitives;
      AMissingAgreement: TKeyAgreementAlgorithm); overload;
    /// <summary>Models a facet whose KEM accepts any right-length encapsulation key, as a backend
    /// that leaves the coefficient check to a later step would.</summary>
    constructor CreateLenientKem(const AInner: ICryptoPrimitives);
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

  /// <summary>An <see cref="IKem" /> that forwards to an inner KEM but validates only the length
  /// of an ML-KEM-768 encapsulation key.</summary>
  TLenientKem = class sealed(TInterfacedObject, IKem)
  strict private
  var
    FInner: IKem;
  public
    constructor Create(const AInner: IKem);
    procedure GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey; out APublicKey: TBytes);
    procedure Encapsulate(const APeerPublicKey: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APrivateKey: IKeyExchangePrivateKey;
      const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
  end;

  /// <summary>A test provider whose primitives cannot build one configured AEAD (or one key
  /// agreement), or whose KEM validates only the key length.</summary>
  TMissingAeadProvider = class sealed(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FComposed: ICryptoProvider;
  public
    constructor Create(const AInner: ICryptoProvider; AMissing: TAeadAlgorithm); overload;
    constructor Create(const AInner: ICryptoProvider;
      AMissingAgreement: TKeyAgreementAlgorithm); overload;
    constructor CreateLenientKem(const AInner: ICryptoProvider);
    /// <summary>Once built, the missing AEAD fails with AFault, as a third party's might (the
    /// builder itself tolerates only the library's not-supported error).</summary>
    constructor CreateFault(const AInner: ICryptoProvider; AMissing: TAeadAlgorithm;
      AFault: ExceptClass);
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

  /// <summary>A switch a test arms to make every <see cref="TCappedAead" /> that shares it fail on
  /// Seal; Open is never affected.</summary>
  TAeadFaultSwitch = class sealed(TObject)
  strict private
  var
    FArmed: Boolean;
  public
    property Armed: Boolean read FArmed write FArmed;
  end;

  /// <summary>
  /// An <see cref="IAead" /> decorator that forwards every operation to an inner AEAD but reports a
  /// small <c>UsageLimit</c>, so a test drives the record layer's usage-limit rekey path by writing
  /// a few dozen records instead of 2^24. While its fault switch (nil means none) is armed, Seal
  /// raises.
  /// </summary>
  TCappedAead = class sealed(TInterfacedObject, IAead)
  strict private
  var
    FInner: IAead;
    FUsageLimit: UInt64;
    FSwitch: TAeadFaultSwitch;
  public
    constructor Create(const AInner: IAead; AUsageLimit: UInt64); overload;
    constructor Create(const AInner: IAead; AUsageLimit: UInt64;
      const ASwitch: TAeadFaultSwitch); overload;
    function UsageCategory: TAeadUsageCategory;
    function UsageLimit: UInt64;
    function KeySize: Int32;
    function NonceSize: Int32;
    function TagSize: Int32;
    procedure Init(const AKey: ISecretBuffer);
    function Seal(const ANonce, AAad, ASrc: TBytes; ASrcOff, ALen: Int32;
      const ADest: TBytes; ADestOff: Int32): Int32;
    function Open(const ANonce, AAad, ASrc: TBytes; ASrcOff, ALen: Int32;
      const ADest: TBytes; ADestOff: Int32): Int32;
  end;

  /// <summary>An <see cref="ICryptoPrimitives" /> decorator whose <c>CreateAead</c> wraps the inner
  /// AEAD with a small usage limit; every other primitive forwards.</summary>
  TCappedAeadPrimitives = class sealed(TInterfacedObject, ICryptoPrimitives)
  strict private
  var
    FInner: ICryptoPrimitives;
    FUsageLimit: UInt64;
    FSwitch: TAeadFaultSwitch;
  public
    constructor Create(const AInner: ICryptoPrimitives; AUsageLimit: UInt64;
      const ASwitch: TAeadFaultSwitch);
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

  /// <summary>A test provider whose AEADs carry a small usage limit, so the record-layer rekey /
  /// usage-limit path is reached by writing a few dozen records rather than 2^24.</summary>
  TCappedAeadProvider = class sealed(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FComposed: ICryptoProvider;
  public
    constructor Create(const AInner: ICryptoProvider; AUsageLimit: UInt64); overload;
    constructor Create(const AInner: ICryptoProvider; AUsageLimit: UInt64;
      const ASwitch: TAeadFaultSwitch); overload;
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

implementation

const
  MlKem768KeyBytes = Int32(1184); // FIPS 203 sec. 8 table 3

resourcestring
  SMissingAead = 'this primitives facet does not provide the requested AEAD';
  SInjectedSealFault = 'the AEAD seal was made to fail by the test';
  SMissingAgreement = 'this primitives facet does not provide the requested key agreement';
  SFakeHpkeSealer = 'the fake HPKE suite seals nothing';

{ TRejectingSignatureVerifier }

procedure TRejectingSignatureVerifier.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  // the content is irrelevant: nothing verifies
end;

function TRejectingSignatureVerifier.Verify(const ASignature: TBytes): Boolean;
begin
  Result := False;
end;

{ TFakeHpkeSuite }

constructor TFakeHpkeSuite.Create(AKem, AKdf, AAead: UInt16);
begin
  inherited Create;
  FKem := AKem;
  FKdf := AKdf;
  FAead := AAead;
end;

function TFakeHpkeSuite.Kem: UInt16;
begin
  Result := FKem;
end;

function TFakeHpkeSuite.Kdf: UInt16;
begin
  Result := FKdf;
end;

function TFakeHpkeSuite.Aead: UInt16;
begin
  Result := FAead;
end;

function TFakeHpkeSuite.AeadTagLength: Int32;
begin
  Result := 16;
end;

procedure TFakeHpkeSuite.SetupSealer(const ARecipientPublicKey, AInfo: TBytes;
  out AEnc: TBytes; out ASealer: IHpkeSealer);
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeHpkeSealer);
end;

{ TFakeHpke }

function TFakeHpke.Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
begin
  Result := TFakeHpkeSuite.Create(AKem, AKdf, AAead) as IHpkeSuite;
end;

function TFakeHpke.ImportRecipientKey(AKem: UInt16;
  const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
begin
  Inc(FRecipientImports);
  Result := nil;
end;

procedure TFakeHpke.GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
  out APrivateKey: ISecretBuffer);
begin
  Inc(FKeyPairs);
  APublicKey := nil;
  APrivateKey := nil;
end;

function TFakeHpke.ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
begin
  Inc(FPrivateImports);
  Result := nil;
end;

function TFakeHpke.SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
begin
  Result := TArray<THpkeSuiteId>.Create(
    THpkeSuiteId.Create(AKem, THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM),
    THpkeSuiteId.Create(AKem, THpkeKdf.HKDF_SHA256, THpkeAead.AES_256_GCM),
    THpkeSuiteId.Create(AKem, THpkeKdf.HKDF_SHA256, THpkeAead.CHACHA20_POLY1305));
end;

function TFakeHpke.ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
begin
  Result := True;
end;

function TFakeHpke.RandomEncapsulation(AKem: UInt16): TBytes;
begin
  Result := TBytes.Create(1);
end;

{ TMockSigningKey }

function TMockSigningKey.CapableSchemes: TArray<TSignatureScheme>;
begin
  Result := nil;
end;

function TMockSigningKey.PublicKeyInfo: TBytes;
begin
  Result := nil;
end;

function TMockSigningKey.WithPreferredSchemes(
  const ASchemes: TArray<TSignatureScheme>): ISigningKey;
begin
  Result := Self;
end;

{ TFakeSigningKey }

constructor TFakeSigningKey.Create(const ASchemes: TArray<TSignatureScheme>);
begin
  Create(ASchemes, nil);
end;

constructor TFakeSigningKey.Create(const ASchemes: TArray<TSignatureScheme>;
  const APublicKeyInfo: TBytes);
begin
  inherited Create;
  FSchemes := ASchemes;
  FPublicKeyInfo := APublicKeyInfo;
end;

function TFakeSigningKey.Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
begin
  Result := TFakeSigningKey.Create(ASchemes, FPublicKeyInfo) as ISigningKey;
end;

function TFakeSigningKey.CapableSchemes: TArray<TSignatureScheme>;
begin
  Result := FSchemes;
end;

function TFakeSigningKey.PublicKeyInfo: TBytes;
begin
  Result := FPublicKeyInfo;
end;

function TFakeSigningKey.WithPreferredSchemes(
  const ASchemes: TArray<TSignatureScheme>): ISigningKey;
var
  LKept: TArray<TSignatureScheme>;
  LI: Int32;
begin
  if System.Length(ASchemes) = 0 then
    Exit(Self as ISigningKey);
  LKept := nil;
  for LI := 0 to System.Length(ASchemes) - 1 do
    if TArrayUtilities.Contains<TSignatureScheme>(FSchemes, ASchemes[LI]) then
      TArrayUtilities.Append<TSignatureScheme>(LKept, ASchemes[LI]);
  Result := Narrowed(LKept);
end;

{ TRejectingVerifierSigning }

constructor TRejectingVerifierSigning.Create(const AInner: ISigningCrypto);
begin
  inherited Create;
  FInner := AInner;
end;

function TRejectingVerifierSigning.ImportSigningKey(const AData: TBytes;
  const APassword: ISecretBuffer): ISigningKey;
begin
  Result := FInner.ImportSigningKey(AData, APassword);
end;

function TRejectingVerifierSigning.ImportPkcs12(const AData: TBytes;
  const APassword: ISecretBuffer): TImportedCredential;
begin
  Result := FInner.ImportPkcs12(AData, APassword);
end;

function TRejectingVerifierSigning.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
begin
  Result := FInner.CreateSignatureSigner(AScheme, AKey);
end;

function TRejectingVerifierSigning.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
begin
  Result := TRejectingSignatureVerifier.Create as ISignatureVerifier;
end;

{ TMockCryptoProvider }

constructor TMockCryptoProvider.Create(const ARandom: IRandom);
var
  LBuilder: ICryptoProviderBuilder;
begin
  inherited Create;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder.WithRandom(ARandom).Build;
end;

function TMockCryptoProvider.Primitives: ICryptoPrimitives;
begin
  Result := FComposed.Primitives;
end;

function TMockCryptoProvider.Signing: ISigningCrypto;
begin
  Result := FComposed.Signing;
end;

function TMockCryptoProvider.Hpke: IHpkeCrypto;
begin
  Result := FComposed.Hpke;
end;

{ TFixedAesPrimitives }

constructor TFixedAesPrimitives.Create(const AInner: ICryptoPrimitives;
  AHasHardwareAes: Boolean);
begin
  inherited Create;
  FInner := AInner;
  FHasHardwareAes := AHasHardwareAes;
end;

function TFixedAesPrimitives.GetRandom: IRandom;
begin
  Result := FInner.GetRandom;
end;

function TFixedAesPrimitives.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := FInner.CreateHash(AAlgorithm);
end;

function TFixedAesPrimitives.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := FInner.CreateHmac(AAlgorithm);
end;

function TFixedAesPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := FInner.CreateHkdf(AAlgorithm);
end;

function TFixedAesPrimitives.CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
begin
  Result := FInner.CreateTls12Prf(AAlgorithm);
end;

function TFixedAesPrimitives.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  Result := FInner.CreateAead(AAlgorithm);
end;

function TFixedAesPrimitives.CreateKeyAgreement(
  AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  Result := FInner.CreateKeyAgreement(AAlgorithm);
end;

function TFixedAesPrimitives.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
begin
  Result := FInner.CreateKem(AAlgorithm);
end;

function TFixedAesPrimitives.HasHardwareAes: Boolean;
begin
  Result := FHasHardwareAes;
end;

{ TFixedAesProvider }

constructor TFixedAesProvider.Create(const AInner: ICryptoProvider;
  AHasHardwareAes: Boolean);
var
  LBuilder: ICryptoProviderBuilder;
begin
  inherited Create;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder
    .WithPrimitives(TFixedAesPrimitives.Create(AInner.Primitives, AHasHardwareAes)
      as ICryptoPrimitives)
    .WithSigning(AInner.Signing)
    .Build;
end;

function TFixedAesProvider.Primitives: ICryptoPrimitives;
begin
  Result := FComposed.Primitives;
end;

function TFixedAesProvider.Signing: ISigningCrypto;
begin
  Result := FComposed.Signing;
end;

function TFixedAesProvider.Hpke: IHpkeCrypto;
begin
  Result := FComposed.Hpke;
end;

{ TMissingAeadPrimitives }

constructor TMissingAeadPrimitives.Create(const AInner: ICryptoPrimitives;
  AMissing: TAeadAlgorithm);
begin
  inherited Create;
  FInner := AInner;
  FMissing := AMissing;
  FHasMissingAead := True;
end;

constructor TMissingAeadPrimitives.Create(const AInner: ICryptoPrimitives;
  AMissingAgreement: TKeyAgreementAlgorithm);
begin
  inherited Create;
  FInner := AInner;
  FMissingAgreement := AMissingAgreement;
  FHasMissingAgreement := True;
end;

procedure TMissingAeadPrimitives.ArmFault(AFault: ExceptClass);
begin
  FFault := AFault;
end;

function TMissingAeadPrimitives.GetRandom: IRandom;
begin
  Result := FInner.GetRandom;
end;

function TMissingAeadPrimitives.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := FInner.CreateHash(AAlgorithm);
end;

function TMissingAeadPrimitives.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := FInner.CreateHmac(AAlgorithm);
end;

function TMissingAeadPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := FInner.CreateHkdf(AAlgorithm);
end;

function TMissingAeadPrimitives.CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
begin
  Result := FInner.CreateTls12Prf(AAlgorithm);
end;

function TMissingAeadPrimitives.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  if FHasMissingAead and (AAlgorithm = FMissing) then
  begin
    if FFault <> nil then
      raise FFault.CreateRes(@SMissingAead);
    raise ENotSupportedTlsLibException.CreateRes(@SMissingAead);
  end;
  Result := FInner.CreateAead(AAlgorithm);
end;

function TMissingAeadPrimitives.CreateKeyAgreement(
  AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  if FHasMissingAgreement and (AAlgorithm = FMissingAgreement) then
    raise ENotSupportedTlsLibException.CreateRes(@SMissingAgreement);
  Result := FInner.CreateKeyAgreement(AAlgorithm);
end;

function TMissingAeadPrimitives.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
begin
  Result := FInner.CreateKem(AAlgorithm);
  if FLenientKem then
    Result := TLenientKem.Create(Result) as IKem;
end;

constructor TMissingAeadPrimitives.CreateLenientKem(const AInner: ICryptoPrimitives);
begin
  inherited Create;
  FInner := AInner;
  FLenientKem := True;
end;

{ TLenientKem }

constructor TLenientKem.Create(const AInner: IKem);
begin
  inherited Create;
  FInner := AInner;
end;

procedure TLenientKem.GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
  out APublicKey: TBytes);
begin
  FInner.GenerateKeyPair(APrivateKey, APublicKey);
end;

procedure TLenientKem.Encapsulate(const APeerPublicKey: TBytes; out ACiphertext: TBytes;
  out ASharedSecret: ISecretBuffer);
begin
  FInner.Encapsulate(APeerPublicKey, ACiphertext, ASharedSecret);
end;

procedure TLenientKem.Decapsulate(const APrivateKey: IKeyExchangePrivateKey;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
begin
  FInner.Decapsulate(APrivateKey, ACiphertext, ASharedSecret);
end;

function TLenientKem.ValidatePublicKey(const APublicKey: TBytes): Boolean;
begin
  Result := System.Length(APublicKey) = MlKem768KeyBytes;
end;

function TMissingAeadPrimitives.HasHardwareAes: Boolean;
begin
  Result := FInner.HasHardwareAes;
end;

{ TMissingAeadProvider }

constructor TMissingAeadProvider.Create(const AInner: ICryptoProvider;
  AMissing: TAeadAlgorithm);
var
  LBuilder: ICryptoProviderBuilder;
begin
  inherited Create;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder
    .WithPrimitives(TMissingAeadPrimitives.Create(AInner.Primitives, AMissing)
      as ICryptoPrimitives)
    .WithSigning(AInner.Signing)
    .Build;
end;

constructor TMissingAeadProvider.Create(const AInner: ICryptoProvider;
  AMissingAgreement: TKeyAgreementAlgorithm);
var
  LBuilder: ICryptoProviderBuilder;
begin
  inherited Create;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder
    .WithPrimitives(TMissingAeadPrimitives.Create(AInner.Primitives, AMissingAgreement)
      as ICryptoPrimitives)
    .WithSigning(AInner.Signing)
    .Build;
end;

constructor TMissingAeadProvider.CreateLenientKem(const AInner: ICryptoProvider);
var
  LBuilder: ICryptoProviderBuilder;
begin
  inherited Create;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder
    .WithPrimitives(TMissingAeadPrimitives.CreateLenientKem(AInner.Primitives)
      as ICryptoPrimitives)
    .WithSigning(AInner.Signing)
    .Build;
end;

constructor TMissingAeadProvider.CreateFault(const AInner: ICryptoProvider;
  AMissing: TAeadAlgorithm; AFault: ExceptClass);
var
  LBuilder: ICryptoProviderBuilder;
  LPrimitives: TMissingAeadPrimitives;
  LHeld: ICryptoPrimitives;
begin
  inherited Create;
  LPrimitives := TMissingAeadPrimitives.Create(AInner.Primitives, AMissing);
  LHeld := LPrimitives as ICryptoPrimitives;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder
    .WithPrimitives(LHeld)
    .WithSigning(AInner.Signing)
    .Build;
  LPrimitives.ArmFault(AFault);
end;

function TMissingAeadProvider.Primitives: ICryptoPrimitives;
begin
  Result := FComposed.Primitives;
end;

function TMissingAeadProvider.Signing: ISigningCrypto;
begin
  Result := FComposed.Signing;
end;

function TMissingAeadProvider.Hpke: IHpkeCrypto;
begin
  Result := FComposed.Hpke;
end;

{ TCappedAead }

constructor TCappedAead.Create(const AInner: IAead; AUsageLimit: UInt64);
begin
  Create(AInner, AUsageLimit, nil);
end;

constructor TCappedAead.Create(const AInner: IAead; AUsageLimit: UInt64;
  const ASwitch: TAeadFaultSwitch);
begin
  inherited Create;
  FInner := AInner;
  FUsageLimit := AUsageLimit;
  FSwitch := ASwitch;
end;

function TCappedAead.UsageCategory: TAeadUsageCategory;
begin
  Result := FInner.UsageCategory;
end;

function TCappedAead.UsageLimit: UInt64;
begin
  Result := FUsageLimit;
end;

function TCappedAead.KeySize: Int32;
begin
  Result := FInner.KeySize;
end;

function TCappedAead.NonceSize: Int32;
begin
  Result := FInner.NonceSize;
end;

function TCappedAead.TagSize: Int32;
begin
  Result := FInner.TagSize;
end;

procedure TCappedAead.Init(const AKey: ISecretBuffer);
begin
  FInner.Init(AKey);
end;

function TCappedAead.Seal(const ANonce, AAad, ASrc: TBytes; ASrcOff, ALen: Int32;
  const ADest: TBytes; ADestOff: Int32): Int32;
begin
  if (FSwitch <> nil) and FSwitch.Armed then
    raise EInvalidOperationTlsLibException.CreateRes(@SInjectedSealFault);
  Result := FInner.Seal(ANonce, AAad, ASrc, ASrcOff, ALen, ADest, ADestOff);
end;

function TCappedAead.Open(const ANonce, AAad, ASrc: TBytes; ASrcOff, ALen: Int32;
  const ADest: TBytes; ADestOff: Int32): Int32;
begin
  Result := FInner.Open(ANonce, AAad, ASrc, ASrcOff, ALen, ADest, ADestOff);
end;

{ TCappedAeadPrimitives }

constructor TCappedAeadPrimitives.Create(const AInner: ICryptoPrimitives;
  AUsageLimit: UInt64; const ASwitch: TAeadFaultSwitch);
begin
  inherited Create;
  FInner := AInner;
  FUsageLimit := AUsageLimit;
  FSwitch := ASwitch;
end;

function TCappedAeadPrimitives.GetRandom: IRandom;
begin
  Result := FInner.GetRandom;
end;

function TCappedAeadPrimitives.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := FInner.CreateHash(AAlgorithm);
end;

function TCappedAeadPrimitives.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := FInner.CreateHmac(AAlgorithm);
end;

function TCappedAeadPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := FInner.CreateHkdf(AAlgorithm);
end;

function TCappedAeadPrimitives.CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
begin
  Result := FInner.CreateTls12Prf(AAlgorithm);
end;

function TCappedAeadPrimitives.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  Result := TCappedAead.Create(FInner.CreateAead(AAlgorithm), FUsageLimit, FSwitch) as IAead;
end;

function TCappedAeadPrimitives.CreateKeyAgreement(
  AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  Result := FInner.CreateKeyAgreement(AAlgorithm);
end;

function TCappedAeadPrimitives.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
begin
  Result := FInner.CreateKem(AAlgorithm);
end;

function TCappedAeadPrimitives.HasHardwareAes: Boolean;
begin
  Result := FInner.HasHardwareAes;
end;

{ TCappedAeadProvider }

constructor TCappedAeadProvider.Create(const AInner: ICryptoProvider;
  AUsageLimit: UInt64);
begin
  Create(AInner, AUsageLimit, nil);
end;

constructor TCappedAeadProvider.Create(const AInner: ICryptoProvider;
  AUsageLimit: UInt64; const ASwitch: TAeadFaultSwitch);
var
  LBuilder: ICryptoProviderBuilder;
begin
  inherited Create;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder
    .WithPrimitives(TCappedAeadPrimitives.Create(AInner.Primitives, AUsageLimit, ASwitch)
      as ICryptoPrimitives)
    .WithSigning(AInner.Signing)
    .Build;
end;

function TCappedAeadProvider.Primitives: ICryptoPrimitives;
begin
  Result := FComposed.Primitives;
end;

function TCappedAeadProvider.Signing: ISigningCrypto;
begin
  Result := FComposed.Signing;
end;

function TCappedAeadProvider.Hpke: IHpkeCrypto;
begin
  Result := FComposed.Hpke;
end;

end.
