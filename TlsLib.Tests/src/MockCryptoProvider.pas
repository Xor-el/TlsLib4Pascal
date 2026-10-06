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
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpTlsLibExceptions,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider;

type
  /// <summary>
  /// A test provider that runs the default crypto with a caller-supplied
  /// (deterministic) <see cref="IRandom" />. It is a thin wrapper over the
  /// composition seam - a provider built with the random override - so
  /// <c>Primitives.GetRandom</c> hands back the injected stream while every crypto
  /// operation is the real default. This is the seam an engine leans on to run with
  /// a fixed randomness stream.
  /// </summary>
  TMockCryptoProvider = class(TInterfacedObject, ICryptoProvider)
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
  TFixedAesPrimitives = class(TInterfacedObject, ICryptoPrimitives)
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
  TFixedAesProvider = class(TInterfacedObject, ICryptoProvider)
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
  TMissingAeadPrimitives = class(TInterfacedObject, ICryptoPrimitives)
  strict private
  var
    FInner: ICryptoPrimitives;
    FMissing: TAeadAlgorithm;
    FMissingAgreement: TKeyAgreementAlgorithm;
    FHasMissingAgreement: Boolean;
  public
    constructor Create(const AInner: ICryptoPrimitives; AMissing: TAeadAlgorithm); overload;
    /// <summary>Models a facet that cannot build one key agreement instead.</summary>
    constructor Create(const AInner: ICryptoPrimitives;
      AMissingAgreement: TKeyAgreementAlgorithm); overload;
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

  /// <summary>A test provider whose primitives cannot build one configured AEAD (or one key
  /// agreement).</summary>
  TMissingAeadProvider = class(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FComposed: ICryptoProvider;
  public
    constructor Create(const AInner: ICryptoProvider; AMissing: TAeadAlgorithm); overload;
    constructor Create(const AInner: ICryptoProvider;
      AMissingAgreement: TKeyAgreementAlgorithm); overload;
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

  /// <summary>
  /// An <see cref="IAead" /> decorator that forwards every operation to an inner AEAD but reports a
  /// small <c>UsageLimit</c>, so a test drives the record layer's usage-limit rekey path by writing
  /// a few dozen records instead of 2^24.
  /// </summary>
  TCappedAead = class(TInterfacedObject, IAead)
  strict private
  var
    FInner: IAead;
    FUsageLimit: UInt64;
  public
    constructor Create(const AInner: IAead; AUsageLimit: UInt64);
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
  TCappedAeadPrimitives = class(TInterfacedObject, ICryptoPrimitives)
  strict private
  var
    FInner: ICryptoPrimitives;
    FUsageLimit: UInt64;
  public
    constructor Create(const AInner: ICryptoPrimitives; AUsageLimit: UInt64);
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
  TCappedAeadProvider = class(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FComposed: ICryptoProvider;
  public
    constructor Create(const AInner: ICryptoProvider; AUsageLimit: UInt64);
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

  /// <summary>
  /// A test PKIX provider that runs the default PKIX facets (certificate inspection,
  /// path validation, revocation). It is a thin wrapper over the composition seam so a
  /// fixture that wants an explicit mock PKIX provider has one; the default facets are
  /// the real defaults.
  /// </summary>
  TMockPkixProvider = class(TInterfacedObject, IPkixProvider)
  strict private
  var
    FComposed: IPkixProvider;
  public
    constructor Create;
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
  end;

implementation

resourcestring
  SMissingAead = 'this primitives facet does not provide the requested AEAD';
  SMissingAgreement = 'this primitives facet does not provide the requested key agreement';

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
  FHasMissingAgreement := False;
end;

constructor TMissingAeadPrimitives.Create(const AInner: ICryptoPrimitives;
  AMissingAgreement: TKeyAgreementAlgorithm);
begin
  inherited Create;
  FInner := AInner;
  FMissingAgreement := AMissingAgreement;
  FHasMissingAgreement := True;
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
  if (not FHasMissingAgreement) and (AAlgorithm = FMissing) then
    raise ENotSupportedTlsLibException.CreateRes(@SMissingAead);
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
    .Build;
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
  inherited Create;
  FInner := AInner;
  FUsageLimit := AUsageLimit;
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
  Result := FInner.Seal(ANonce, AAad, ASrc, ASrcOff, ALen, ADest, ADestOff);
end;

function TCappedAead.Open(const ANonce, AAad, ASrc: TBytes; ASrcOff, ALen: Int32;
  const ADest: TBytes; ADestOff: Int32): Int32;
begin
  Result := FInner.Open(ANonce, AAad, ASrc, ASrcOff, ALen, ADest, ADestOff);
end;

{ TCappedAeadPrimitives }

constructor TCappedAeadPrimitives.Create(const AInner: ICryptoPrimitives;
  AUsageLimit: UInt64);
begin
  inherited Create;
  FInner := AInner;
  FUsageLimit := AUsageLimit;
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
  Result := TCappedAead.Create(FInner.CreateAead(AAlgorithm), FUsageLimit) as IAead;
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
var
  LBuilder: ICryptoProviderBuilder;
begin
  inherited Create;
  LBuilder := TCryptoProviderBuilder.Create;
  FComposed := LBuilder
    .WithPrimitives(TCappedAeadPrimitives.Create(AInner.Primitives, AUsageLimit)
      as ICryptoPrimitives)
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

{ TMockPkixProvider }

constructor TMockPkixProvider.Create;
begin
  inherited Create;
  FComposed := TDefaultPkixProvider.Create as IPkixProvider;
end;

function TMockPkixProvider.Certificates: ICertificateInspector;
begin
  Result := FComposed.Certificates;
end;

function TMockPkixProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FComposed.PathValidation;
end;

function TMockPkixProvider.Revocation: IRevocationChecker;
begin
  Result := FComposed.Revocation;
end;

end.
