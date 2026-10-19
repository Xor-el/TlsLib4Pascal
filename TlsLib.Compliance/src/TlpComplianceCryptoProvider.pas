{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceCryptoProvider;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpISigningKey,
  TlpImportedCredential,
  TlpSystemCryptoTypes,
  TlpICryptoBackendReport,
  TlpISystemSignatureVerifier,
  TlpSystemCryptoBase,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpComplianceHpke,
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpTlsLibExceptions;

type
  /// <summary>The report of a provider with none: every operation answers portable, so a strict
  /// signing layer built on it admits no key and no verifier.</summary>
  TPortableOnlyReport = class sealed(TSystemBackendReportBase)
  public
    function Describe: string; override;
  end;

  /// <summary>
  /// A backend report that answers as its inner report except for the HPKE facet, which a
  /// supplied facet makes portable whatever the inner report says.
  /// </summary>
  THpkeSuppliedReport = class sealed(TInterfacedObject, ICryptoBackendReport)
  strict private
  var
    FInner: ICryptoBackendReport;
  public
    constructor Create(const AInner: ICryptoBackendReport);
    function RandomBackend: TCryptoBackendEntry;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
    function KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    function SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
    function VerificationBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    function VerifierBackend(const AVerifier: ISignatureVerifier): TCryptoBackendEntry;
    function FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
    function Describe: string;
  end;

  /// <summary>
  /// A primitives decorator that refuses every algorithm outside the rules (in both modes), every
  /// key encapsulation, and, in strict mode, every algorithm the backend report does not place
  /// in the OS module. A refusal raises <see cref="EComplianceRefusedTlsLibException" />, so an
  /// HPKE probe over these primitives treats a refused algorithm as unavailable. It holds only
  /// immutable state, so its thread-safety is the inner facet's.
  /// </summary>
  TComplianceCryptoPrimitives = class sealed(TForwardingCryptoPrimitives)
  strict private
  var
    FReport: ICryptoBackendReport;
    FStrict: Boolean;
    FAeads: TComplianceAeadSet;
    FKeyAgreements: TComplianceKeyAgreementSet;
    FKdf: TKdfRule;
    FRequireEms: Boolean;
    procedure RequireInModule(const AEntry: TCryptoBackendEntry; const ASubject: string);
    procedure RequireKdfInModule(const AEntry: TCryptoBackendEntry; const ASubject: string);
  public
    /// <param name="AReport">Never nil: the provider's backend report, or a report that
    /// answers portable everywhere.</param>
    constructor Create(const AInner: ICryptoPrimitives; const ARules: TComplianceRules;
      const AReport: ICryptoBackendReport; AEnforcement: TComplianceEnforcement);
    function GetRandom: IRandom; override;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash; override;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac; override;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf; override;
    function CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf; override;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead; override;
    function CreateKeyAgreement(AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement; override;
    function CreateKem(AAlgorithm: TKemAlgorithm): IKem; override;
  end;

  /// <summary>
  /// A signing decorator that refuses every scheme outside the rules and, in strict mode, every
  /// key or verifier the OS module does not serve. An admitted key is narrowed to the rule
  /// schemes, so a server signs only with an allowed scheme.
  /// </summary>
  TComplianceSigningCrypto = class sealed(TForwardingSigningCrypto)
  strict private
  var
    FReport: ICryptoBackendReport;
    FStrict: Boolean;
    FReportsNothing: Boolean;
    FSchemes: TComplianceSchemeSet;
    procedure RequireInModule(const AEntry: TCryptoBackendEntry; const ASubject: string);
    function Admitted(const AKey: ISigningKey): ISigningKey;
  public
    /// <param name="AReport">Never nil: the provider's backend report, or a report that
    /// answers portable everywhere.</param>
    constructor Create(const AInner: ISigningCrypto; const ARules: TComplianceRules;
      const AReport: ICryptoBackendReport; AEnforcement: TComplianceEnforcement);
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey; override;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TImportedCredential; override;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner; override;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier; override;
  end;

  /// <summary>Wraps a crypto provider so its primitives and signing refuse what the rules or
  /// the module do not allow.</summary>
  TComplianceCryptoProvider = class sealed(TObject)
  public
    /// <summary>A provider with ABase's identity, HPKE rebuilt over the refusing primitives when
    /// ABase composes its own and otherwise filtered by the rules, and the backend report ABase
    /// carries (none if it has none), answering the HPKE facet as portable whenever HPKE is
    /// filtered. That report describes ABase's backends, not what the rules let through. A base
    /// with no backend report is treated as wholly portable. Raises EArgumentTlsLibException for
    /// a nil ABase.</summary>
    class function Compose(const ABase: ICryptoProvider; const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement): ICryptoProvider; static;
  end;

implementation

resourcestring
  SAlgorithmRefused = 'the %s is not allowed by the compliance rules';
  SAlgorithmOutsideModule = 'the %s does not run in the OS crypto module';
  SPlainMasterSecretRefused =
    'the plain master secret derivation is refused; Extended Master Secret is required';
  SRandomSubject = 'random generator';
  SSigningKeySubject = 'signing key';
  SNilReport = 'the backend report must not be nil';
  SNilBase = 'the base crypto provider must not be nil';
  SPortableOnlyReport = 'no backend report: every operation is portable';

const
  PlainMasterSecretLabel = 'master secret';

type
  /// <summary>A TLS 1.2 PRF that refuses the plain master secret label (RFC 5246 8.1), so a
  /// session without Extended Master Secret (RFC 7627) can never be keyed.</summary>
  TComplianceTls12Prf = class sealed(TInterfacedObject, ITls12Prf)
  strict private
  var
    FInner: ITls12Prf;
  public
    constructor Create(const AInner: ITls12Prf);
    function Compute(const ASecret: ISecretBuffer; const ALabel: string;
      const ASeed: TBytes; ALength: Int32): ISecretBuffer;
  end;

{ TPortableOnlyReport }

function TPortableOnlyReport.Describe: string;
begin
  Result := SPortableOnlyReport;
end;

{ TComplianceTls12Prf }

constructor TComplianceTls12Prf.Create(const AInner: ITls12Prf);
begin
  inherited Create;
  FInner := AInner;
end;

function TComplianceTls12Prf.Compute(const ASecret: ISecretBuffer; const ALabel: string;
  const ASeed: TBytes; ALength: Int32): ISecretBuffer;
begin
  if ALabel = PlainMasterSecretLabel then
    raise EComplianceRefusedTlsLibException.CreateRes(@SPlainMasterSecretRefused);
  Result := FInner.Compute(ASecret, ALabel, ASeed, ALength);
end;

{ TComplianceCryptoPrimitives }

constructor TComplianceCryptoPrimitives.Create(const AInner: ICryptoPrimitives;
  const ARules: TComplianceRules; const AReport: ICryptoBackendReport;
  AEnforcement: TComplianceEnforcement);
begin
  inherited Create(AInner);
  if AReport = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilReport);
  FReport := AReport;
  FStrict := AEnforcement = TComplianceEnforcement.Strict;
  FAeads := ARules.Aeads;
  FKeyAgreements := TComplianceCatalog.KeyAgreements(ARules);
  FKdf := ARules.Kdf;
  FRequireEms := TComplianceRequirement.ExtendedMasterSecret in ARules.Requirements;
end;

procedure TComplianceCryptoPrimitives.RequireInModule(const AEntry: TCryptoBackendEntry;
  const ASubject: string);
begin
  if FStrict and (AEntry.Backend <> TCryptoBackend.System) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmOutsideModule, [ASubject]);
end;

procedure TComplianceCryptoPrimitives.RequireKdfInModule(const AEntry: TCryptoBackendEntry;
  const ASubject: string);
begin
  // a derivation assembled over the module's HMAC is allowed only when the rules accept that
  if FStrict and (AEntry.Backend <> TCryptoBackend.System) and
    not ((AEntry.Backend = TCryptoBackend.Composed) and (FKdf = TKdfRule.AllowComposed)) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmOutsideModule, [ASubject]);
end;

function TComplianceCryptoPrimitives.GetRandom: IRandom;
begin
  RequireInModule(FReport.RandomBackend, SRandomSubject);
  Result := inherited GetRandom;
end;

function TComplianceCryptoPrimitives.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  RequireInModule(FReport.HashBackend(AAlgorithm),
    TEnumUtilities.GetName<THashAlgorithm>(AAlgorithm));
  Result := inherited CreateHash(AAlgorithm);
end;

function TComplianceCryptoPrimitives.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  RequireInModule(FReport.HmacBackend(AAlgorithm),
    TEnumUtilities.GetName<THashAlgorithm>(AAlgorithm));
  Result := inherited CreateHmac(AAlgorithm);
end;

function TComplianceCryptoPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  RequireKdfInModule(FReport.HkdfBackend(AAlgorithm),
    TEnumUtilities.GetName<THashAlgorithm>(AAlgorithm));
  Result := inherited CreateHkdf(AAlgorithm);
end;

function TComplianceCryptoPrimitives.CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
var
  LPrf: ITls12Prf;
begin
  RequireKdfInModule(FReport.Tls12PrfBackend(AAlgorithm),
    TEnumUtilities.GetName<THashAlgorithm>(AAlgorithm));
  LPrf := inherited CreateTls12Prf(AAlgorithm);
  if FRequireEms then
    Result := TComplianceTls12Prf.Create(LPrf) as ITls12Prf
  else
    Result := LPrf;
end;

function TComplianceCryptoPrimitives.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
var
  LName: string;
begin
  LName := TEnumUtilities.GetName<TAeadAlgorithm>(AAlgorithm);
  if not (AAlgorithm in FAeads) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmRefused, [LName]);
  RequireInModule(FReport.AeadBackend(AAlgorithm), LName);
  Result := inherited CreateAead(AAlgorithm);
end;

function TComplianceCryptoPrimitives.CreateKeyAgreement(
  AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
var
  LName: string;
begin
  LName := TEnumUtilities.GetName<TKeyAgreementAlgorithm>(AAlgorithm);
  if not (AAlgorithm in FKeyAgreements) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmRefused, [LName]);
  RequireInModule(FReport.KeyAgreementBackend(AAlgorithm), LName);
  Result := inherited CreateKeyAgreement(AAlgorithm);
end;

function TComplianceCryptoPrimitives.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
begin
  // no key encapsulation is approved, so every rule set refuses it
  raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmRefused,
    [TEnumUtilities.GetName<TKemAlgorithm>(AAlgorithm)]);
end;

{ TComplianceSigningCrypto }

constructor TComplianceSigningCrypto.Create(const AInner: ISigningCrypto;
  const ARules: TComplianceRules; const AReport: ICryptoBackendReport;
  AEnforcement: TComplianceEnforcement);
begin
  inherited Create(AInner);
  if AReport = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilReport);
  FReport := AReport;
  FStrict := AEnforcement = TComplianceEnforcement.Strict;
  FReportsNothing := AReport is TPortableOnlyReport;
  FSchemes := ARules.SignatureSchemes;
end;

procedure TComplianceSigningCrypto.RequireInModule(const AEntry: TCryptoBackendEntry;
  const ASubject: string);
begin
  // a marker over a report that knows nothing of the base proves nothing
  if FStrict and (FReportsNothing or (AEntry.Backend <> TCryptoBackend.System)) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmOutsideModule, [ASubject]);
end;

function TComplianceSigningCrypto.Admitted(const AKey: ISigningKey): ISigningKey;
var
  LCapable, LKept: TArray<TSignatureScheme>;
  LI: Int32;
begin
  if AKey = nil then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmRefused,
      [SSigningKeySubject]);
  LCapable := AKey.CapableSchemes;
  LKept := nil;
  for LI := 0 to System.Length(LCapable) - 1 do
    if LCapable[LI] in FSchemes then
      TArrayUtilities.Append<TSignatureScheme>(LKept, LCapable[LI]);
  if System.Length(LKept) = 0 then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmRefused,
      [SSigningKeySubject]);
  RequireInModule(FReport.SigningKeyBackend(AKey), SSigningKeySubject);
  Result := AKey.WithPreferredSchemes(LKept);
end;

function TComplianceSigningCrypto.ImportSigningKey(const AData: TBytes;
  const APassword: ISecretBuffer): ISigningKey;
begin
  Result := Admitted(inherited ImportSigningKey(AData, APassword));
end;

function TComplianceSigningCrypto.ImportPkcs12(const AData: TBytes;
  const APassword: ISecretBuffer): TImportedCredential;
begin
  Result := inherited ImportPkcs12(AData, APassword);
  Result.PrivateKey := Admitted(Result.PrivateKey);
end;

function TComplianceSigningCrypto.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
var
  LName: string;
begin
  LName := TEnumUtilities.GetName<TSignatureScheme>(AScheme);
  if not (AScheme in FSchemes) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmRefused, [LName]);
  RequireInModule(FReport.SigningKeyBackend(AKey), LName);
  Result := inherited CreateSignatureSigner(AScheme, AKey);
end;

function TComplianceSigningCrypto.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
var
  LName: string;
begin
  LName := TEnumUtilities.GetName<TSignatureScheme>(AScheme);
  if not (AScheme in FSchemes) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SAlgorithmRefused, [LName]);
  Result := inherited CreateSignatureVerifier(AScheme, APublicKeyDer);
  // the native facet falls back to a portable verifier for a key the module cannot import
  RequireInModule(FReport.VerifierBackend(Result), LName);
end;

{ THpkeSuppliedReport }

constructor THpkeSuppliedReport.Create(const AInner: ICryptoBackendReport);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilReport);
  FInner := AInner;
end;

function THpkeSuppliedReport.RandomBackend: TCryptoBackendEntry;
begin
  Result := FInner.RandomBackend;
end;

function THpkeSuppliedReport.HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := FInner.HashBackend(AAlgorithm);
end;

function THpkeSuppliedReport.HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := FInner.HmacBackend(AAlgorithm);
end;

function THpkeSuppliedReport.HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := FInner.HkdfBackend(AAlgorithm);
end;

function THpkeSuppliedReport.Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := FInner.Tls12PrfBackend(AAlgorithm);
end;

function THpkeSuppliedReport.AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
begin
  Result := FInner.AeadBackend(AAlgorithm);
end;

function THpkeSuppliedReport.KeyAgreementBackend(
  AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
begin
  Result := FInner.KeyAgreementBackend(AAlgorithm);
end;

function THpkeSuppliedReport.KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
begin
  Result := FInner.KemBackend(AAlgorithm);
end;

function THpkeSuppliedReport.SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := FInner.SigningBackend(AScheme);
end;

function THpkeSuppliedReport.SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
begin
  Result := FInner.SigningKeyBackend(AKey);
end;

function THpkeSuppliedReport.VerificationBackend(
  AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := FInner.VerificationBackend(AScheme);
end;

function THpkeSuppliedReport.VerifierBackend(
  const AVerifier: ISignatureVerifier): TCryptoBackendEntry;
begin
  Result := FInner.VerifierBackend(AVerifier);
end;

function THpkeSuppliedReport.FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
begin
  if AFacet = TCryptoFacet.Hpke then
  begin
    Result.Backend := TCryptoBackend.Portable;
    Result.Reason := TCryptoBackendReason.NoNativeImpl;
  end
  else
    Result := FInner.FacetBackend(AFacet);
end;

function THpkeSuppliedReport.Describe: string;
begin
  Result := FInner.Describe;
end;

{ TComplianceCryptoProvider }

class function TComplianceCryptoProvider.Compose(const ABase: ICryptoProvider;
  const ARules: TComplianceRules; AEnforcement: TComplianceEnforcement): ICryptoProvider;
var
  LReport, LDecisionReport: ICryptoBackendReport;
  LPrimitives: ICryptoPrimitives;
  LSigning: ISigningCrypto;
  LHpke: IHpkeCrypto;
begin
  if ABase = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBase);
  LReport := nil;
  Supports(ABase, ICryptoBackendReport, LReport);
  if LReport <> nil then
    LDecisionReport := LReport
  else
    LDecisionReport := TPortableOnlyReport.Create(False) as ICryptoBackendReport;
  LPrimitives := TComplianceCryptoPrimitives.Create(ABase.Primitives, ARules,
    LDecisionReport, AEnforcement);
  LSigning := TComplianceSigningCrypto.Create(ABase.Signing, ARules, LDecisionReport,
    AEnforcement);
  LHpke := nil;
  if not TOverlayCryptoProvider.RebuildsHpke(ABase) then
  begin
    LHpke := TComplianceHpke.Create(ABase.Hpke, ARules, AEnforcement) as IHpkeCrypto;
    // the supplied facet wraps a foreign one, so the report cannot call it a composition
    if LReport <> nil then
      LReport := THpkeSuppliedReport.Create(LReport) as ICryptoBackendReport;
  end;
  Result := TOverlayCryptoProvider.Create(ABase, LPrimitives, LSigning, LReport, LHpke);
end;

end.
