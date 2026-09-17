{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemCryptoBase;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpICryptoBackendReport,
  TlpHpkeComposition,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// An <see cref="ICryptoPrimitives" /> decorator that forwards every call to an inner
  /// primitives facet. It is the base for a system-native primitives facet: a subclass
  /// overrides only the Create* it has an OS backend for, and the rest resolve to the
  /// inner (portable) implementation unchanged - so an unaccelerated algorithm always
  /// falls back rather than failing. Every accessor is virtual for that reason. The
  /// decorator adds no state beyond the immutable inner reference, so its thread-safety
  /// is exactly the inner facet's. Native forwarders for other facets (e.g. signing)
  /// join this unit as they are added.
  /// </summary>
  TForwardingCryptoPrimitives = class(TInterfacedObject, ICryptoPrimitives)
  strict private
  var
    FInner: ICryptoPrimitives;
  strict protected
    /// <summary>The wrapped facet a subclass delegates the primitives it does not
    /// accelerate to.</summary>
    property Inner: ICryptoPrimitives read FInner;
  public
    constructor Create(const AInner: ICryptoPrimitives);
    function GetRandom: IRandom; virtual;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash; virtual;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac; virtual;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf; virtual;
    function CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf; virtual;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead; virtual;
    function CreateKeyAgreement(AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement; virtual;
    function CreateKem(AAlgorithm: TKemAlgorithm): IKem; virtual;
    function HasHardwareAes: Boolean; virtual;
  end;

  /// <summary>
  /// An <see cref="ICryptoProvider" /> that overlays a substituted Primitives and/or
  /// Signing facet on a base provider and forwards the certificate, path-validation,
  /// revocation and PEM facets to the base unchanged - so a native overlay preserves the
  /// base's identity and its same-reference-every-call contract. HPKE is the exception:
  /// being a pure composition of primitives, it is rebuilt here over the overlay's own
  /// primitives so its KEM/KDF/AEAD ride the native seam. A nil override takes that facet
  /// from the base. A platform composer builds this; the OS factory only dispatches.
  /// </summary>
  TOverlayCryptoProvider = class(TInterfacedObject, ICryptoProvider, ICryptoBackendReport)
  strict private
  var
    FInner: ICryptoProvider;
    FPrimitives: ICryptoPrimitives;
    FSigning: ISigningCrypto;
    FReport: ICryptoBackendReport;
    // HPKE composed over this overlay's own primitives, so its KEM/KDF/AEAD run native where
    // the primitive seam serves them (built once at construction, like the other facets)
    FHpke: IHpkeCrypto;
    // delegates ICryptoBackendReport to the held report; a nil report is not claimed
    // (Supports returns False), so a provider with no backend map reads as wholly portable
    property BackendReport: ICryptoBackendReport read FReport
      implements ICryptoBackendReport;
  public
    constructor Create(const ABase: ICryptoProvider;
      const APrimitives: ICryptoPrimitives; const ASigning: ISigningCrypto;
      const AReport: ICryptoBackendReport);
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
    function Hpke: IHpkeCrypto;
  end;

implementation

resourcestring
  SNilInnerPrimitives = 'the inner primitives facet must not be nil';

{ TForwardingCryptoPrimitives }

constructor TForwardingCryptoPrimitives.Create(const AInner: ICryptoPrimitives);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilInnerPrimitives);
  FInner := AInner;
end;

function TForwardingCryptoPrimitives.GetRandom: IRandom;
begin
  Result := FInner.GetRandom;
end;

function TForwardingCryptoPrimitives.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := FInner.CreateHash(AAlgorithm);
end;

function TForwardingCryptoPrimitives.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := FInner.CreateHmac(AAlgorithm);
end;

function TForwardingCryptoPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := FInner.CreateHkdf(AAlgorithm);
end;

function TForwardingCryptoPrimitives.CreateTls12Prf(
  AAlgorithm: THashAlgorithm): ITls12Prf;
begin
  Result := FInner.CreateTls12Prf(AAlgorithm);
end;

function TForwardingCryptoPrimitives.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  Result := FInner.CreateAead(AAlgorithm);
end;

function TForwardingCryptoPrimitives.CreateKeyAgreement(
  AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  Result := FInner.CreateKeyAgreement(AAlgorithm);
end;

function TForwardingCryptoPrimitives.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
begin
  Result := FInner.CreateKem(AAlgorithm);
end;

function TForwardingCryptoPrimitives.HasHardwareAes: Boolean;
begin
  Result := FInner.HasHardwareAes;
end;

{ TOverlayCryptoProvider }

constructor TOverlayCryptoProvider.Create(const ABase: ICryptoProvider;
  const APrimitives: ICryptoPrimitives; const ASigning: ISigningCrypto;
  const AReport: ICryptoBackendReport);
begin
  inherited Create;
  FInner := ABase;
  FPrimitives := APrimitives;
  FSigning := ASigning;
  FReport := AReport;
  // compose HPKE over this overlay's effective primitives so the KEM/KDF/AEAD ride the
  // native seam (each with its own per-algorithm fallback), not the base's portable HPKE
  FHpke := THpkeComposition.Create(Primitives) as IHpkeCrypto;
end;

function TOverlayCryptoProvider.Primitives: ICryptoPrimitives;
begin
  if FPrimitives <> nil then
    Result := FPrimitives
  else
    Result := FInner.Primitives;
end;

function TOverlayCryptoProvider.Signing: ISigningCrypto;
begin
  if FSigning <> nil then
    Result := FSigning
  else
    Result := FInner.Signing;
end;

function TOverlayCryptoProvider.Certificates: ICertificateInspector;
begin
  Result := FInner.Certificates;
end;

function TOverlayCryptoProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FInner.PathValidation;
end;

function TOverlayCryptoProvider.Revocation: IRevocationChecker;
begin
  Result := FInner.Revocation;
end;

function TOverlayCryptoProvider.Hpke: IHpkeCrypto;
begin
  Result := FHpke;
end;

end.
