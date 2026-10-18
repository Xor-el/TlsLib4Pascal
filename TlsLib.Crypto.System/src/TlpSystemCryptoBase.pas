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
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpICryptoBackendReport,
  TlpISystemSigningKey,
  TlpSystemCryptoTypes,
  TlpISecretBuffer,
  TlpISigningKey,
  TlpImportedCredential,
  TlpHpkeComposition,
  TlpPem,
  TlpDer,
  TlpSecureMemory,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// An <see cref="ICryptoPrimitives" /> decorator that forwards every call to an inner
  /// primitives facet. It is the base for a system-native primitives facet: a subclass
  /// overrides only the Create* it has an OS backend for, and the rest resolve to the
  /// inner (portable) implementation unchanged - so an unaccelerated algorithm always
  /// falls back rather than failing. Every accessor is virtual for that reason. The
  /// decorator adds no state beyond the immutable inner reference, so its thread-safety
  /// is exactly the inner facet's.
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
  /// Signing facet on a base provider - so a native overlay preserves the
  /// base's identity and its same-reference-every-call contract. A nil override takes that
  /// facet from the base. The base's HPKE is kept unless it is the default composition over the
  /// base's own primitives, which is rebuilt over the overlay's. A platform composer builds this;
  /// the OS factory only dispatches.
  /// </summary>
  TOverlayCryptoProvider = class(TInterfacedObject, ICryptoProvider, ICryptoBackendReport)
  strict private
  var
    FInner: ICryptoProvider;
    FPrimitives: ICryptoPrimitives;
    FSigning: ISigningCrypto;
    FReport: ICryptoBackendReport;
    FHpke: IHpkeCrypto;
    // delegates ICryptoBackendReport to the held report; a nil report is not claimed
    // (Supports returns False), so a provider with no backend map reads as wholly portable
    property BackendReport: ICryptoBackendReport read FReport
      implements ICryptoBackendReport;
  public
    /// <summary>True only for the default HPKE composition over ABase's own primitives.</summary>
    class function RebuildsHpke(const ABase: ICryptoProvider): Boolean; static;
    constructor Create(const ABase: ICryptoProvider;
      const APrimitives: ICryptoPrimitives; const ASigning: ISigningCrypto;
      const AReport: ICryptoBackendReport);
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Hpke: IHpkeCrypto;
  end;

  /// <summary>The accumulate step a native signer and verifier share: Update appends the span to
  /// the bytes to be signed or verified.</summary>
  TSignatureInputBase = class abstract(TInterfacedObject)
  strict protected
  var
    FBuffer: TBytes;
  public
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>
  /// An <see cref="ISigningCrypto" /> decorator over an inner signing facet, the base for a
  /// system-native signing facet. Key import tries the subclass's <see cref="TryImportNative" />
  /// first (DER as given, PEM through the first private-key block the inner reader would pick)
  /// and hands anything it declines to the inner facet unchanged; every member is virtual and
  /// forwards to the inner facet otherwise.
  /// </summary>
  TForwardingSigningCrypto = class(TInterfacedObject, ISigningCrypto)
  strict private
  var
    FInner: ISigningCrypto;
    // whether ADer is an EncryptedPrivateKeyInfo: an outer SEQUENCE leading with a SEQUENCE
    class function IsEncryptedPkcs8(const ADer: TBytes): Boolean; static;
    function TryImportPem(const AData: TBytes; const APassword: ISecretBuffer;
      out AKey: ISigningKey): Boolean;
  strict protected
    property Inner: ISigningCrypto read FInner;
    /// <summary>Imports a DER private key (PKCS#8 plain or encrypted, PKCS#1 or SEC1) natively;
    /// False hands the input to the inner facet, which owns every error.</summary>
    function TryImportNative(const ADer: TBytes; const APassword: ISecretBuffer;
      out AKey: ISigningKey): Boolean; virtual;
  public
    constructor Create(const AInner: ISigningCrypto);
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey; virtual;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TImportedCredential; virtual;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner; virtual;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier; virtual;
  end;

  /// <summary>
  /// The platform-neutral part of an <see cref="ICryptoBackendReport" />. Every per-algorithm
  /// query defaults to portable, so a platform overrides only what it serves natively; HKDF
  /// and the TLS 1.2 PRF follow the OS HMAC, a signing key follows the <see
  /// cref="ISystemSigningKey" /> marker, and the HPKE facet follows the constructor flag. The
  /// platform supplies <see cref="Describe" />.
  /// </summary>
  TSystemBackendReportBase = class abstract(TInterfacedObject, ICryptoBackendReport)
  strict private
  var
    FHpkeComposed: Boolean;
    // HKDF and the 1.2 PRF are assembled in portable code over the OS HMAC, so they follow it
    function ComposedOverHmac(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
  strict protected
    class function Ent(ABackend: TCryptoBackend;
      AReason: TCryptoBackendReason): TCryptoBackendEntry; static;
    class function NotNative: TCryptoBackendEntry; static;
  public
    /// <param name="AHpkeComposed">True when the provider's HPKE composes over its own
    /// primitives.</param>
    constructor Create(AHpkeComposed: Boolean);
    function RandomBackend: TCryptoBackendEntry; virtual;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; virtual;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; virtual;
    function HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry; virtual;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry; virtual;
    function KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry; virtual;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; virtual;
    function SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
    function FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
    function Describe: string; virtual; abstract;
  end;

implementation

resourcestring
  SNilInnerPrimitives = 'the inner primitives facet must not be nil';
  SNilInnerSigning = 'the inner signing facet must not be nil';
  SUpdateSpanOutOfRange = 'the Update source span is out of range';

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
  if RebuildsHpke(ABase) then
    FHpke := THpkeComposition.Create(Primitives) as IHpkeCrypto
  else
    FHpke := ABase.Hpke;
end;

class function TOverlayCryptoProvider.RebuildsHpke(const ABase: ICryptoProvider): Boolean;
var
  LComposition: IHpkeComposition;
begin
  Result := Supports(ABase.Hpke, IHpkeComposition, LComposition) and
    (LComposition.ComposedOver = ABase.Primitives);
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

function TOverlayCryptoProvider.Hpke: IHpkeCrypto;
begin
  Result := FHpke;
end;

{ TSignatureInputBase }

procedure TSignatureInputBase.Update(const AData: TBytes; AOffset, ALength: Int32);
var
  LOld: Int32;
begin
  if (AOffset < 0) or (ALength < 0) or (Int64(AOffset) + ALength > System.Length(AData)) then
    raise EArgumentTlsLibException.CreateRes(@SUpdateSpanOutOfRange);
  if ALength <= 0 then
    Exit;
  LOld := System.Length(FBuffer);
  SetLength(FBuffer, LOld + ALength);
  Move(AData[AOffset], FBuffer[LOld], ALength);
end;

{ TForwardingSigningCrypto }

constructor TForwardingSigningCrypto.Create(const AInner: ISigningCrypto);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilInnerSigning);
  FInner := AInner;
end;

class function TForwardingSigningCrypto.IsEncryptedPkcs8(const ADer: TBytes): Boolean;
var
  LTag: Byte;
  LOfs, LLen, LNext: Int32;
begin
  Result := TDer.ReadTlv(ADer, 0, LTag, LOfs, LLen, LNext) and (LTag = $30) and
    TDer.ReadTlv(ADer, LOfs, LTag, LOfs, LLen, LNext) and (LTag = $30);
end;

function TForwardingSigningCrypto.TryImportNative(const ADer: TBytes;
  const APassword: ISecretBuffer; out AKey: ISigningKey): Boolean;
begin
  AKey := nil;
  Result := False;
end;

function TForwardingSigningCrypto.TryImportPem(const AData: TBytes;
  const APassword: ISecretBuffer; out AKey: ISigningKey): Boolean;
var
  LBlocks: TArray<TPemBlock>;
  LIdx, LI: Int32;
begin
  AKey := nil;
  Result := False;
  try
    LBlocks := TPem.ReadBlocks(AData);
  except
    // malformed PEM: let the inner facet re-parse and own the canonical error
    Exit(False);
  end;
  try
    // a boundary this framing did not see (one that follows text on its line) could be read as a
    // block by the inner facet, which then must pick the key
    if TPem.BeginTagCount(AData) <> System.Length(LBlocks) then
      Exit;
    // the first private-key block is the one the inner facet imports, and it fails closed on
    // it, so a later block is never tried here: an unsupported or failed first block hands the
    // whole input to the inner facet, which owns the selection and the errors
    LIdx := TPem.IndexOfPrivateKey(LBlocks);
    if LIdx < 0 then
      Exit;
    // encrypted PKCS#8 needs the password; plain PKCS#8 and the raw PKCS#1/SEC1 forms
    // ("RSA/EC PRIVATE KEY") import unkeyed
    if LBlocks[LIdx].PemType = 'ENCRYPTED PRIVATE KEY' then
      // the label means EncryptedPrivateKeyInfo (RFC 7468 11); a native hook may take plaintext
      Result := IsEncryptedPkcs8(LBlocks[LIdx].Content) and
        TryImportNative(LBlocks[LIdx].Content, APassword, AKey)
    else if (LBlocks[LIdx].PemType = 'PRIVATE KEY') or
      (LBlocks[LIdx].PemType = 'RSA PRIVATE KEY') or
      (LBlocks[LIdx].PemType = 'EC PRIVATE KEY') then
      Result := TryImportNative(LBlocks[LIdx].Content, nil, AKey);
  finally
    // a decoded block may hold plaintext private-key DER
    for LI := 0 to System.Length(LBlocks) - 1 do
      TSecureMemory.WipeBytes(LBlocks[LI].Content);
  end;
end;

function TForwardingSigningCrypto.ImportSigningKey(const AData: TBytes;
  const APassword: ISecretBuffer): ISigningKey;
begin
  // a declined key goes to the inner facet, which owns the full parse range and every error
  if TPem.IsArmored(AData) then
  begin
    if not TryImportPem(AData, APassword, Result) then
      Result := FInner.ImportSigningKey(AData, APassword);
  end
  else if not TryImportNative(AData, APassword, Result) then
    Result := FInner.ImportSigningKey(AData, APassword);
end;

function TForwardingSigningCrypto.ImportPkcs12(const AData: TBytes;
  const APassword: ISecretBuffer): TImportedCredential;
begin
  Result := FInner.ImportPkcs12(AData, APassword);
end;

function TForwardingSigningCrypto.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
begin
  Result := FInner.CreateSignatureSigner(AScheme, AKey);
end;

function TForwardingSigningCrypto.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
begin
  Result := FInner.CreateSignatureVerifier(AScheme, APublicKeyDer);
end;

{ TSystemBackendReportBase }

constructor TSystemBackendReportBase.Create(AHpkeComposed: Boolean);
begin
  inherited Create;
  FHpkeComposed := AHpkeComposed;
end;

class function TSystemBackendReportBase.Ent(ABackend: TCryptoBackend;
  AReason: TCryptoBackendReason): TCryptoBackendEntry;
begin
  Result.Backend := ABackend;
  Result.Reason := AReason;
end;

class function TSystemBackendReportBase.NotNative: TCryptoBackendEntry;
begin
  Result := Ent(TCryptoBackend.Portable, TCryptoBackendReason.NoNativeImpl);
end;

function TSystemBackendReportBase.RandomBackend: TCryptoBackendEntry;
begin
  Result := NotNative;
end;

function TSystemBackendReportBase.HashBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := NotNative;
end;

function TSystemBackendReportBase.HmacBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := NotNative;
end;

function TSystemBackendReportBase.ComposedOverHmac(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  if HmacBackend(AAlgorithm).Backend = TCryptoBackend.System then
    Result := Ent(TCryptoBackend.Composed, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TSystemBackendReportBase.HkdfBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := ComposedOverHmac(AAlgorithm);
end;

function TSystemBackendReportBase.Tls12PrfBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := ComposedOverHmac(AAlgorithm);
end;

function TSystemBackendReportBase.AeadBackend(
  AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
begin
  Result := NotNative;
end;

function TSystemBackendReportBase.KeyAgreementBackend(
  AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
begin
  Result := NotNative;
end;

function TSystemBackendReportBase.KemBackend(
  AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
begin
  Result := NotNative;
end;

function TSystemBackendReportBase.SigningBackend(
  AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := NotNative;
end;

function TSystemBackendReportBase.SigningKeyBackend(
  const AKey: ISigningKey): TCryptoBackendEntry;
begin
  // per key, not per scheme: only a key the OS module imported carries the marker; one that
  // fell back to the portable facet signs portable regardless of its scheme
  if Supports(AKey, ISystemSigningKey) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TSystemBackendReportBase.FacetBackend(
  AFacet: TCryptoFacet): TCryptoBackendEntry;
begin
  // Primitives and Signing are mixed per algorithm; only Hpke has a whole-facet answer
  if (AFacet = TCryptoFacet.Hpke) and FHpkeComposed then
    Result := Ent(TCryptoBackend.Composed, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

end.
