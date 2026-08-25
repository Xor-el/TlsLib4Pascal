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
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider;

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
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
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
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
  end;

implementation

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

function TMockCryptoProvider.Certificates: ICertificateInspector;
begin
  Result := FComposed.Certificates;
end;

function TMockCryptoProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FComposed.PathValidation;
end;

function TMockCryptoProvider.Revocation: IRevocationChecker;
begin
  Result := FComposed.Revocation;
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

function TFixedAesProvider.Certificates: ICertificateInspector;
begin
  Result := FComposed.Certificates;
end;

function TFixedAesProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FComposed.PathValidation;
end;

function TFixedAesProvider.Revocation: IRevocationChecker;
begin
  Result := FComposed.Revocation;
end;

end.
