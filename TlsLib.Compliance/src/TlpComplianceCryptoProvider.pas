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
  TlpSystemCryptoBase,
  TlpHkdfComposition,
  TlpTls12PrfComposition,
  TlpTls12PrfLabels,
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
  /// A primitives decorator that refuses every algorithm outside the rules (in both modes), every
  /// key encapsulation, and, in strict mode, every algorithm the backend report does not place
  /// in the OS module. A refusal raises <see cref="EComplianceRefusedTlsLibException" />, so an
  /// HPKE probe over these primitives treats a refused algorithm as unavailable. HKDF, and the
  /// TLS 1.2 PRF unless the module serves it, are assembled over this decorator's own HMAC, so
  /// they never reach a native Expand. It holds only immutable state, so its thread-safety is
  /// the inner facet's.
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
    /// carries (none if it has none), unchanged: it describes ABase's backends, including its
    /// HPKE facet, not what the rules let through. A base with no backend report is treated as
    /// wholly portable. Raises EArgumentTlsLibException for a nil ABase.</summary>
    class function Compose(const ABase: ICryptoProvider; const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement): ICryptoProvider; overload; static;
    /// <summary>As above, but the refusing layers decide by ADecisionReport instead of the report
    /// of ABase, which still describes ABase's backends. Raises EArgumentTlsLibException for a
    /// nil ABase or ADecisionReport.</summary>
    class function Compose(const ABase: ICryptoProvider; const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement;
      const ADecisionReport: ICryptoBackendReport): ICryptoProvider; overload; static;
  end;

implementation

resourcestring
  SAlgorithmRefused = 'the %s is not allowed by the compliance rules';
  SAlgorithmOutsideModule = 'the %s does not run in the OS crypto module';
  SPlainMasterSecretRefused =
    'the plain master secret derivation is refused; Extended Master Secret is required';
  SNotKeyScheduleLabelRefused = 'the TLS 1.2 derivation is refused: its label is not a ' +
    'key-schedule label and the rules require every derivation inside the module';
  SRandomSubject = 'random generator';
  SSigningKeySubject = 'signing key';
  SNilReport = 'the backend report must not be nil';
  SNilBase = 'the base crypto provider must not be nil';
  SPortableOnlyReport = 'no backend report: every operation is portable';

type
  /// <summary>A TLS 1.2 PRF that can refuse the plain master secret label (RFC 5246 8.1), so a
  /// session without Extended Master Secret (RFC 7627) can never be keyed, and any label that
  /// is not a key-schedule label, so no exporter derivation is composed outside the
  /// module.</summary>
  TComplianceTls12Prf = class sealed(TInterfacedObject, ITls12Prf)
  strict private
  var
    FInner: ITls12Prf;
    FRefusePlainMaster: Boolean;
    FKeyScheduleOnly: Boolean;
  public
    constructor Create(const AInner: ITls12Prf; ARefusePlainMaster, AKeyScheduleOnly: Boolean);
    function Compute(const ASecret: ISecretBuffer; const ALabel: string;
      const ASeed: TBytes; ALength: Int32): ISecretBuffer;
  end;

{ TPortableOnlyReport }

function TPortableOnlyReport.Describe: string;
begin
  Result := SPortableOnlyReport;
end;

{ TComplianceTls12Prf }

constructor TComplianceTls12Prf.Create(const AInner: ITls12Prf;
  ARefusePlainMaster, AKeyScheduleOnly: Boolean);
begin
  inherited Create;
  FInner := AInner;
  FRefusePlainMaster := ARefusePlainMaster;
  FKeyScheduleOnly := AKeyScheduleOnly;
end;

function TComplianceTls12Prf.Compute(const ASecret: ISecretBuffer; const ALabel: string;
  const ASeed: TBytes; ALength: Int32): ISecretBuffer;
begin
  if FRefusePlainMaster and (ALabel = TTls12PrfLabels.MasterSecret) then
    raise EComplianceRefusedTlsLibException.CreateRes(@SPlainMasterSecretRefused);
  if FKeyScheduleOnly and not TTls12PrfLabels.IsKeyScheduleLabel(ALabel) then
    raise EComplianceRefusedTlsLibException.CreateRes(@SNotKeyScheduleLabelRefused);
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
  // over Self, so every HMAC it makes passes the refusing layer and a native Expand never runs
  Result := THkdfComposition.Create(Self, AAlgorithm) as IHkdf;
end;

function TComplianceCryptoPrimitives.CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
var
  LPrf: ITls12Prf;
  LKeyScheduleOnly: Boolean;
begin
  RequireKdfInModule(FReport.Tls12PrfBackend(AAlgorithm),
    TEnumUtilities.GetName<THashAlgorithm>(AAlgorithm));
  // only the module's own PRF is forwarded; any other is assembled over the refusing HMAC
  if FReport.Tls12PrfBackend(AAlgorithm).Backend = TCryptoBackend.System then
    LPrf := inherited CreateTls12Prf(AAlgorithm)
  else
    LPrf := TTls12PrfComposition.Create(Self, AAlgorithm) as ITls12Prf;
  // an exporter label runs over the module HMAC, which the rules forbid for a derivation
  LKeyScheduleOnly := FStrict and (FKdf = TKdfRule.RequireModule);
  if FRequireEms or LKeyScheduleOnly then
    Result := TComplianceTls12Prf.Create(LPrf, FRequireEms, LKeyScheduleOnly) as ITls12Prf
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
  // the inherited path would decode the PEM and copy the plaintext key before the inner provider
  Result := Admitted(Inner.ImportSigningKey(AData, APassword));
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

{ TComplianceCryptoProvider }

class function TComplianceCryptoProvider.Compose(const ABase: ICryptoProvider;
  const ARules: TComplianceRules; AEnforcement: TComplianceEnforcement): ICryptoProvider;
var
  LReport, LDecisionReport: ICryptoBackendReport;
begin
  if ABase = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBase);
  LReport := nil;
  Supports(ABase, ICryptoBackendReport, LReport);
  if LReport <> nil then
    LDecisionReport := LReport
  else
    LDecisionReport := TPortableOnlyReport.Create(False) as ICryptoBackendReport;
  Result := Compose(ABase, ARules, AEnforcement, LDecisionReport);
end;

class function TComplianceCryptoProvider.Compose(const ABase: ICryptoProvider;
  const ARules: TComplianceRules; AEnforcement: TComplianceEnforcement;
  const ADecisionReport: ICryptoBackendReport): ICryptoProvider;
var
  LReport: ICryptoBackendReport;
  LPrimitives: ICryptoPrimitives;
  LSigning: ISigningCrypto;
  LHpke: IHpkeCrypto;
begin
  if ABase = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBase);
  if ADecisionReport = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilReport);
  LReport := nil;
  Supports(ABase, ICryptoBackendReport, LReport);
  LPrimitives := TComplianceCryptoPrimitives.Create(ABase.Primitives, ARules,
    ADecisionReport, AEnforcement);
  LSigning := TComplianceSigningCrypto.Create(ABase.Signing, ARules, ADecisionReport,
    AEnforcement);
  LHpke := nil;
  if not TOverlayCryptoProvider.RebuildsHpke(ABase) then
    LHpke := TComplianceHpke.Create(ABase.Hpke, ARules, AEnforcement) as IHpkeCrypto;
  Result := TOverlayCryptoProvider.Create(ABase, LPrimitives, LSigning, LReport, LHpke);
end;

end.
