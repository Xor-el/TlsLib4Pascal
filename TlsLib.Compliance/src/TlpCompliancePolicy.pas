{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCompliancePolicy;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpCipherSuiteCatalog,
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpPkixDomainTypes,
  TlpITlsConfig,
  TlpINegotiation,
  TlpINamedGroup,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpTrustTypes,
  TlpSystemCryptoTypes,
  TlpICryptoBackendReport,
  TlpSystemCryptoBase,
  TlpISystemVerifierSource,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpIComplianceReport,
  TlpIModuleAttestation,
  TlpICompliancePolicy,
  TlpComplianceReport,
  TlpCompliancePresets,
  TlpComplianceCryptoProvider,
  TlpCompliancePkixProvider;

type
  /// <summary>
  /// The compliance policy. Construction checks the rules, the backends and the module, then
  /// builds the refusing providers; everything is fixed afterwards, so the policy is safe to share
  /// between threads. Strict refuses at construction and at Admit for any finding; Relaxed
  /// reports platform and rule findings and still refuses a configuration finding at Admit.
  /// </summary>
  TCompliancePolicy = class sealed(TInterfacedObject, ICompliancePolicy)
  strict private
  var
    FRules: TComplianceRules;
    FEnforcement: TComplianceEnforcement;
    FReport: ICryptoBackendReport;
    FCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    FAttestation: IModuleAttestation;
    FPreset: string;
    FPlatformFindings: TArray<TComplianceFinding>;
    FDisclosures: TArray<string>;
    FPlatformReport: IComplianceReport;
    class procedure CheckUsable(const ARules: TComplianceRules); static;
    procedure CheckBackend(var AFindings: TArray<TComplianceFinding>;
      const AEntry: TCryptoBackendEntry; const ASubject: string);
    procedure CheckKdf(var AFindings: TArray<TComplianceFinding>;
      const AEntry: TCryptoBackendEntry; const ASubject: string);
    procedure CollectPlatform(const ABaseCrypto: ICryptoProvider;
      var AFindings: TArray<TComplianceFinding>);
    procedure CheckCommon(const AConfig: ITlsCommonConfig;
      var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
    procedure CheckCredential(const ACredential: TTlsCredential;
      var AFindings: TArray<TComplianceFinding>);
    // the floors apply to the peer certificate a config verifies
    procedure CheckStrength(const AConfig: ITlsCommonConfig;
      var AFindings: TArray<TComplianceFinding>);
    function Report(const AFindings: TArray<TComplianceFinding>;
      const ADisclosures: TArray<string>): IComplianceReport;
    procedure Enforce(const AReport: IComplianceReport);
  public
    /// <summary>A policy over ABaseCrypto and ABasePkix. Raises EArgumentTlsLibException for a nil
    /// argument or rules no config can run, and, in Strict, EComplianceUnmetTlsLibException for
    /// any platform or rule finding.</summary>
    constructor Create(const ARules: TComplianceRules; const ABaseCrypto: ICryptoProvider;
      const ABasePkix: IPkixProvider; const AAttestation: IModuleAttestation;
      AEnforcement: TComplianceEnforcement);
    function Rules: TComplianceRules;
    function Enforcement: TComplianceEnforcement;
    function Crypto: ICryptoProvider;
    function Pkix: IPkixProvider;
    function Attestation: IModuleAttestation;
    function PlatformReport: IComplianceReport;
    function Evaluate(const AConfig: ITlsClientConfig): IComplianceReport; overload;
    function Evaluate(const AConfig: ITlsServerConfig): IComplianceReport; overload;
    function Admit(const AConfig: ITlsClientConfig): IComplianceReport; overload;
    function Admit(const AConfig: ITlsServerConfig): IComplianceReport; overload;
  end;

implementation

resourcestring
  SNilBaseCrypto = 'the base crypto provider must not be nil';
  SNilBasePkix = 'the base PKIX provider must not be nil';
  SNilAttestation = 'the module attestation must not be nil';
  SNilConfig = 'the config must not be nil';
  SVersionsInvalid = 'the rules must offer TLS 1.2, TLS 1.3 or both';
  SSuitesInvalid =
    'the rules must list known cipher suites, each with an AEAD the rules allow';
  SVersionWithoutSuite = 'the rules offer a TLS version that has no cipher suite';
  SGroupsInvalid = 'the rules must list only the secp256r1, secp384r1 and secp521r1 groups';
  SSchemesEmpty = 'the rules must allow at least one signature scheme';
  SCurvesEmpty = 'the rules must list the certificate curves; an empty list would allow any';
  SRulesOutsidePresets = 'the rules fit no named preset';
  SNoBackendReport =
    'the crypto provider has no backend report, so every operation counts as outside the module';
  SBackendOutside = 'runs %s (%s), not in the OS module';
  SKdfRequiresModule =
    'the derivation is composed outside the module and the rules require it inside';
  SForeignCrypto = 'the config does not use the policy crypto provider';
  SForeignPkix = 'the config does not use the policy PKIX provider';
  SNotAllowed = 'is not allowed by the rules';
  SEmsNotRequired = 'TLS 1.2 is offered without requiring extended master secret (RFC 7627)';
  SEarlyData = 'early data is enabled';
  SEch = 'Encrypted Client Hello is configured';
  SExternalPsk = 'an external pre-shared key is configured';
  STls12Psk = 'a TLS 1.2 pre-shared key is configured';
  SKeyLog = 'a key log is configured';
  SDangerousTrust = 'certificate verification can be skipped';
  SStrengthBelow = 'the certificate strength policy is looser than the rules';
  SKeyUndetermined = 'the credential key could not be read from its certificate';
  SKeyBelow = 'the credential key is below the strength floors of the rules';
  SCredentialSchemes = 'the credential key signs with no scheme the rules allow';
  SKeyOutside = 'the credential key is not served by the OS module';
  SChainOutside = 'the peer chain is not verified by the OS verifier';
  SStapleOutside = 'a requested OCSP staple would be verified outside the module';
  SKdfComposed = 'the TLS key derivations are composed outside the module over its HMAC';
  SRevocationOff = 'revocation checking is off';
  SHostResolver = 'a live-revocation resolver is host-owned and cannot be inspected';
  SSniCredentials = 'credentials chosen by server name are not size-checked';
  SRandomSubject = 'random generator';
  SHashSubject = 'hash %s';
  SHmacSubject = 'HMAC %s';
  SAeadSubject = 'AEAD %s';
  SHkdfSubject = 'HKDF %s';
  SPrfSubject = 'TLS 1.2 PRF %s';
  SAgreementSubject = 'key agreement %s';
  SSigningSubject = 'signing %s';
  SVerificationSubject = 'verification %s';
  SHpkeSubject = 'HPKE';
  SHpkeOutside =
    'the base HPKE is not composed over its primitives, so Encrypted Client Hello runs outside ' +
    'the module';
  SRsaPeerChainRange =
    'a peer chain is held to the RSA size range, not to the exact sizes of the rules';

{ TCompliancePolicy }

class procedure TCompliancePolicy.CheckUsable(const ARules: TComplianceRules);
var
  LI: Int32;
  LSuite: TTlsCipherSuite;
  LAlgorithm: TKeyAgreementAlgorithm;
  LOffers13, LOffers12, LHas13, LHas12, LKnown: Boolean;
begin
  if System.Length(ARules.Versions) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SVersionsInvalid);
  LOffers13 := False;
  LOffers12 := False;
  for LI := 0 to System.Length(ARules.Versions) - 1 do
    if ARules.Versions[LI] = TlsWireVersionTls13 then
      LOffers13 := True
    else if ARules.Versions[LI] = TlsWireVersionTls12 then
      LOffers12 := True
    else
      raise EArgumentTlsLibException.CreateRes(@SVersionsInvalid);
  if System.Length(ARules.CipherSuites) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SSuitesInvalid);
  LHas13 := False;
  LHas12 := False;
  for LI := 0 to System.Length(ARules.CipherSuites) - 1 do
  begin
    LKnown := TCipherSuiteCatalog.TryGet(ARules.CipherSuites[LI], LSuite);
    if not LKnown then
      raise EArgumentTlsLibException.CreateRes(@SSuitesInvalid);
    if not (LSuite.Common.Aead in ARules.Aeads) then
      raise EArgumentTlsLibException.CreateRes(@SSuitesInvalid);
    if LSuite.Protocol = TSuiteProtocol.Tls13 then
      LHas13 := True
    else
      LHas12 := True;
  end;
  if (LOffers13 and not LHas13) or (LOffers12 and not LHas12) then
    raise EArgumentTlsLibException.CreateRes(@SVersionWithoutSuite);
  if System.Length(ARules.NamedGroups) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SGroupsInvalid);
  for LI := 0 to System.Length(ARules.NamedGroups) - 1 do
  begin
    LKnown := TComplianceCatalog.TryKeyAgreement(ARules.NamedGroups[LI], LAlgorithm);
    if not LKnown or (LAlgorithm = TKeyAgreementAlgorithm.X25519) then
      raise EArgumentTlsLibException.CreateRes(@SGroupsInvalid);
  end;
  if ARules.SignatureSchemes = [] then
    raise EArgumentTlsLibException.CreateRes(@SSchemesEmpty);
  if System.Length(ARules.Strength.AllowedEcCurves) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SCurvesEmpty);
end;

procedure TCompliancePolicy.CheckBackend(var AFindings: TArray<TComplianceFinding>;
  const AEntry: TCryptoBackendEntry; const ASubject: string);
begin
  if AEntry.Backend = TCryptoBackend.System then
    Exit;
  TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
    TComplianceFindingKind.AlgorithmOutsideModule, ASubject, Format(SBackendOutside,
    [TEnumUtilities.GetName<TCryptoBackend>(AEntry.Backend),
    TEnumUtilities.GetName<TCryptoBackendReason>(AEntry.Reason)])));
end;

procedure TCompliancePolicy.CheckKdf(var AFindings: TArray<TComplianceFinding>;
  const AEntry: TCryptoBackendEntry; const ASubject: string);
var
  LDisclosed: Boolean;
begin
  if AEntry.Backend = TCryptoBackend.System then
    Exit;
  if AEntry.Backend = TCryptoBackend.Portable then
    CheckBackend(AFindings, AEntry, ASubject)
  else if FRules.Kdf = TKdfRule.RequireModule then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.KdfOutsideModule, ASubject, SKdfRequiresModule))
  else
  begin
    LDisclosed := TArrayUtilities.Contains<string>(FDisclosures, SKdfComposed);
    if not LDisclosed then
      TArrayUtilities.Append<string>(FDisclosures, SKdfComposed);
  end;
end;

procedure TCompliancePolicy.CollectPlatform(const ABaseCrypto: ICryptoProvider;
  var AFindings: TArray<TComplianceFinding>);
var
  LI: Int32;
  LSuite: TTlsCipherSuite;
  LHashes, LHkdfHashes, LPrfHashes: set of THashAlgorithm;
  LHash: THashAlgorithm;
  LAead: TAeadAlgorithm;
  LScheme: TSignatureScheme;
  LAlgorithm: TKeyAgreementAlgorithm;
  LName: string;
  LKnown: Boolean;
begin
  LHashes := [];
  LHkdfHashes := [];
  LPrfHashes := [];
  CheckBackend(AFindings, FReport.RandomBackend, SRandomSubject);
  for LI := 0 to System.Length(FRules.CipherSuites) - 1 do
  begin
    LKnown := TCipherSuiteCatalog.TryGet(FRules.CipherSuites[LI], LSuite);
    if LKnown then
    begin
      Include(LHashes, LSuite.Common.Hash);
      if LSuite.Protocol = TSuiteProtocol.Tls13 then
        Include(LHkdfHashes, LSuite.Common.Hash)
      else
        Include(LPrfHashes, LSuite.Prf);
    end;
  end;
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    if LScheme in FRules.SignatureSchemes then
      Include(LHashes, TComplianceCatalog.SchemeHash(LScheme));
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
    if LHash in LHashes then
    begin
      LName := TEnumUtilities.GetName<THashAlgorithm>(LHash);
      CheckBackend(AFindings, FReport.HashBackend(LHash), Format(SHashSubject, [LName]));
      CheckBackend(AFindings, FReport.HmacBackend(LHash), Format(SHmacSubject, [LName]));
    end;
  for LAead := Low(TAeadAlgorithm) to High(TAeadAlgorithm) do
    if LAead in FRules.Aeads then
      CheckBackend(AFindings, FReport.AeadBackend(LAead),
        Format(SAeadSubject, [TEnumUtilities.GetName<TAeadAlgorithm>(LAead)]));
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
  begin
    LName := TEnumUtilities.GetName<THashAlgorithm>(LHash);
    if LHash in LHkdfHashes then
      CheckKdf(AFindings, FReport.HkdfBackend(LHash), Format(SHkdfSubject, [LName]));
    if LHash in LPrfHashes then
      CheckKdf(AFindings, FReport.Tls12PrfBackend(LHash), Format(SPrfSubject, [LName]));
  end;
  for LI := 0 to System.Length(FRules.NamedGroups) - 1 do
  begin
    LKnown := TComplianceCatalog.TryKeyAgreement(FRules.NamedGroups[LI], LAlgorithm);
    if LKnown then
      CheckBackend(AFindings, FReport.KeyAgreementBackend(LAlgorithm),
        Format(SAgreementSubject, [TEnumUtilities.GetName<TKeyAgreementAlgorithm>(LAlgorithm)]));
  end;
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    if LScheme in FRules.SignatureSchemes then
    begin
      LName := TEnumUtilities.GetName<TSignatureScheme>(LScheme);
      CheckBackend(AFindings, FReport.SigningBackend(LScheme), Format(SSigningSubject, [LName]));
      CheckBackend(AFindings, FReport.VerificationBackend(LScheme),
        Format(SVerificationSubject, [LName]));
    end;
  if not (TComplianceRequirement.NoEch in FRules.Requirements) and
    not TOverlayCryptoProvider.RebuildsHpke(ABaseCrypto) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.AlgorithmOutsideModule, SHpkeSubject, SHpkeOutside));
  if FAttestation.Status(FRules.ModuleStandard) <> TModuleStatus.Validated then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ModuleNotValidated, FAttestation.Identity.OsVersion,
      FAttestation.Describe));
end;

constructor TCompliancePolicy.Create(const ARules: TComplianceRules;
  const ABaseCrypto: ICryptoProvider; const ABasePkix: IPkixProvider;
  const AAttestation: IModuleAttestation; AEnforcement: TComplianceEnforcement);
var
  LFindings: TArray<TComplianceFinding>;
  LReport: ICryptoBackendReport;
  LMatched, LHasReport: Boolean;
begin
  inherited Create;
  if ABaseCrypto = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBaseCrypto);
  if ABasePkix = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBasePkix);
  if AAttestation = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilAttestation);
  CheckUsable(ARules);
  FRules := ARules.Clone;
  FEnforcement := AEnforcement;
  FAttestation := AAttestation;
  LFindings := nil;
  LMatched := TCompliancePresets.TryMatch(FRules, FPreset);
  if not LMatched then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.RulesOutsidePresets, '', SRulesOutsidePresets));
  LReport := nil;
  LHasReport := Supports(ABaseCrypto, ICryptoBackendReport, LReport);
  if LHasReport then
    FReport := LReport
  else
  begin
    FReport := TPortableOnlyReport.Create(False) as ICryptoBackendReport;
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.NoBackendReport, '', SNoBackendReport));
  end;
  CollectPlatform(ABaseCrypto, LFindings);
  if System.Length(FRules.RsaModulusBits) > 0 then
    TArrayUtilities.Append<string>(FDisclosures, SRsaPeerChainRange);
  if (AEnforcement = TComplianceEnforcement.Strict) and (System.Length(LFindings) > 0) then
    raise EComplianceUnmetTlsLibException.Create(LFindings);
  FPlatformFindings := LFindings;
  FCrypto := TComplianceCryptoProvider.Compose(ABaseCrypto, FRules, AEnforcement);
  FPkix := TCompliancePkixProvider.Create(ABasePkix, AEnforcement) as IPkixProvider;
  FPlatformReport := Report(FPlatformFindings, FDisclosures);
end;

procedure TCompliancePolicy.CheckCredential(const ACredential: TTlsCredential;
  var AFindings: TArray<TComplianceFinding>);
var
  LFacts: TCertKeyFacts;
  LCapable: TArray<TSignatureScheme>;
  LI: Int32;
  LKnown, LAnyAllowed, LMeets: Boolean;
begin
  if System.Length(ACredential.CertificateChain) = 0 then
    Exit;
  LKnown := FPkix.Certificates.Parse(ACredential.CertificateChain[0]).KeyFacts(LFacts);
  if not LKnown then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyUndetermined, '', SKeyUndetermined))
  else
  begin
    LMeets := TComplianceCatalog.KeyMeets(LFacts, FRules.Strength, FRules.RsaModulusBits);
    if not LMeets then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyBelowRules, '', SKeyBelow));
  end;
  if ACredential.PrivateKey = nil then
    Exit;
  LCapable := ACredential.PrivateKey.CapableSchemes;
  LAnyAllowed := False;
  for LI := 0 to System.Length(LCapable) - 1 do
    if LCapable[LI] in FRules.SignatureSchemes then
      LAnyAllowed := True;
  if not LAnyAllowed then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialSchemesNotAllowed, '', SCredentialSchemes));
  if FReport.SigningKeyBackend(ACredential.PrivateKey).Backend <> TCryptoBackend.System then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyOutsideModule, '', SKeyOutside));
end;

procedure TCompliancePolicy.CheckCommon(const AConfig: ITlsCommonConfig;
  var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
var
  LI: Int32;
  LCodes: TArray<UInt16>;
  LSuites: TArray<TTlsCipherSuite>;
  LGroups: TArray<INamedGroup>;
  LSchemes: TArray<TSignatureScheme>;
  LAllowed, LOffers12: Boolean;
begin
  if AConfig.Crypto <> FCrypto then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ForeignCryptoProvider, 'Crypto', SForeignCrypto));
  if AConfig.Pkix <> FPkix then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ForeignPkixProvider, 'Pkix', SForeignPkix));
  LCodes := AConfig.SupportedVersions;
  LOffers12 := False;
  for LI := 0 to System.Length(LCodes) - 1 do
  begin
    if LCodes[LI] = TlsWireVersionTls12 then
      LOffers12 := True;
    LAllowed := TArrayUtilities.Contains<UInt16>(FRules.Versions, LCodes[LI]);
    if not LAllowed then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.VersionNotAllowed, Format('0x%.4X', [LCodes[LI]]),
        SNotAllowed));
  end;
  LSuites := AConfig.CipherSuites.Items;
  for LI := 0 to System.Length(LSuites) - 1 do
  begin
    LAllowed := TArrayUtilities.Contains<UInt16>(FRules.CipherSuites, LSuites[LI].Common.Code);
    if not LAllowed then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CipherSuiteNotAllowed,
        TCipherSuiteCatalog.Name(LSuites[LI].Common.Code), SNotAllowed));
  end;
  LGroups := AConfig.NamedGroups.Items;
  for LI := 0 to System.Length(LGroups) - 1 do
  begin
    LAllowed := TArrayUtilities.Contains<UInt16>(FRules.NamedGroups, LGroups[LI].Code);
    if not LAllowed then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.NamedGroupNotAllowed, TNamedGroupCatalog.Name(LGroups[LI].Code),
        SNotAllowed));
  end;
  LCodes := AConfig.PreferredGroups;
  for LI := 0 to System.Length(LCodes) - 1 do
  begin
    LAllowed := TArrayUtilities.Contains<UInt16>(FRules.NamedGroups, LCodes[LI]);
    if not LAllowed then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.NamedGroupNotAllowed, TNamedGroupCatalog.Name(LCodes[LI]),
        SNotAllowed));
  end;
  LSchemes := AConfig.SignatureSchemes.Items;
  for LI := 0 to System.Length(LSchemes) - 1 do
    if not (LSchemes[LI] in FRules.SignatureSchemes) then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.SignatureSchemeNotAllowed,
        TEnumUtilities.GetName<TSignatureScheme>(LSchemes[LI]), SNotAllowed));
  if (TComplianceRequirement.ExtendedMasterSecret in FRules.Requirements) and LOffers12 and
    not AConfig.RequireExtendedMasterSecret then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ExtendedMasterSecretNotRequired, '', SEmsNotRequired));
  if (TComplianceRequirement.NoExternalPsk in FRules.Requirements) and
    (System.Length(AConfig.ExternalPsks) > 0) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ExternalPskConfigured, '', SExternalPsk));
  if (TComplianceRequirement.NoTls12Psk in FRules.Requirements) and
    (System.Length(AConfig.Tls12Psks) > 0) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.Tls12PskConfigured, '', STls12Psk));
  if (TComplianceRequirement.NoKeyLog in FRules.Requirements) and (AConfig.KeyLog <> nil) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.KeyLogConfigured, '', SKeyLog));
  if (TComplianceRequirement.NoDangerousTrust in FRules.Requirements) and
    AConfig.DangerousTrust.InsecureSkipVerify then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.DangerousTrustConfigured, '', SDangerousTrust));
  CheckCredential(AConfig.Credential, AFindings);
  if AConfig.RevocationPosture = TRevocationPosture.Off then
    TArrayUtilities.Append<string>(ADisclosures, SRevocationOff);
  if AConfig.AsyncCertificateVerdict.Deferral = TVerdictDeferral.LiveRevocation then
    TArrayUtilities.Append<string>(ADisclosures, SHostResolver);
end;

procedure TCompliancePolicy.CheckStrength(const AConfig: ITlsCommonConfig;
  var AFindings: TArray<TComplianceFinding>);
var
  LWithin: Boolean;
begin
  LWithin := TComplianceCatalog.StrengthWithin(AConfig.CertificateStrengthPolicy,
    FRules.Strength);
  if not LWithin then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.StrengthBelowRules, '', SStrengthBelow));
end;

function TCompliancePolicy.Report(const AFindings: TArray<TComplianceFinding>;
  const ADisclosures: TArray<string>): IComplianceReport;
begin
  Result := TComplianceReport.Create(FEnforcement, FPreset, FAttestation.Identity,
    FAttestation.Status(FRules.ModuleStandard), AFindings, ADisclosures) as IComplianceReport;
end;

procedure TCompliancePolicy.Enforce(const AReport: IComplianceReport);
var
  LFindings, LConfiguration: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LFindings := AReport.Findings;
  if FEnforcement = TComplianceEnforcement.Strict then
  begin
    if System.Length(LFindings) > 0 then
      raise EComplianceUnmetTlsLibException.Create(LFindings);
    Exit;
  end;
  LConfiguration := nil;
  for LI := 0 to System.Length(LFindings) - 1 do
    if LFindings[LI].Category = TComplianceFindingCategory.Configuration then
      TArrayUtilities.Append<TComplianceFinding>(LConfiguration, LFindings[LI]);
  if System.Length(LConfiguration) > 0 then
    raise EComplianceUnmetTlsLibException.Create(LConfiguration);
end;

function TCompliancePolicy.Rules: TComplianceRules;
begin
  Result := FRules.Clone;
end;

function TCompliancePolicy.Enforcement: TComplianceEnforcement;
begin
  Result := FEnforcement;
end;

function TCompliancePolicy.Crypto: ICryptoProvider;
begin
  Result := FCrypto;
end;

function TCompliancePolicy.Pkix: IPkixProvider;
begin
  Result := FPkix;
end;

function TCompliancePolicy.Attestation: IModuleAttestation;
begin
  Result := FAttestation;
end;

function TCompliancePolicy.PlatformReport: IComplianceReport;
begin
  Result := FPlatformReport;
end;

function TCompliancePolicy.Evaluate(const AConfig: ITlsClientConfig): IComplianceReport;
var
  LFindings: TArray<TComplianceFinding>;
  LDisclosures: TArray<string>;
  LOutside: Boolean;
begin
  if AConfig = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilConfig);
  LFindings := System.Copy(FPlatformFindings);
  LDisclosures := System.Copy(FDisclosures);
  CheckCommon(AConfig, LFindings, LDisclosures);
  CheckStrength(AConfig, LFindings);
  if TComplianceRequirement.InModuleChainVerification in FRules.Requirements then
  begin
    LOutside := not Supports(AConfig.ServerVerifierSource, ISystemVerifierSource);
    if LOutside then
      TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
        TComplianceFindingKind.ChainVerifiedOutsideModule, '', SChainOutside));
    if AConfig.RequestOcspStapling then
      TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
        TComplianceFindingKind.StapleVerifiedOutsideModule, '', SStapleOutside));
  end;
  if (TComplianceRequirement.NoEarlyData in FRules.Requirements) and AConfig.EarlyData then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.EarlyDataEnabled, '', SEarlyData));
  if (TComplianceRequirement.NoEch in FRules.Requirements) and
    (AConfig.EncryptedClientHello <> nil) then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.EchConfigured, '', SEch));
  Result := Report(LFindings, LDisclosures);
end;

function TCompliancePolicy.Evaluate(const AConfig: ITlsServerConfig): IComplianceReport;
var
  LFindings: TArray<TComplianceFinding>;
  LDisclosures: TArray<string>;
  LOutside: Boolean;
begin
  if AConfig = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilConfig);
  LFindings := System.Copy(FPlatformFindings);
  LDisclosures := System.Copy(FDisclosures);
  CheckCommon(AConfig, LFindings, LDisclosures);
  if AConfig.ClientAuth <> TClientAuthMode.None then
    CheckStrength(AConfig, LFindings);
  if (TComplianceRequirement.InModuleChainVerification in FRules.Requirements) and
    (AConfig.ClientAuth <> TClientAuthMode.None) then
  begin
    LOutside := not Supports(AConfig.ClientVerifierSource, ISystemVerifierSource);
    if LOutside then
      TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
        TComplianceFindingKind.ChainVerifiedOutsideModule, '', SChainOutside));
  end;
  if (TComplianceRequirement.NoEarlyData in FRules.Requirements) and
    (AConfig.MaxEarlyData > 0) then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.EarlyDataEnabled, '', SEarlyData));
  if (TComplianceRequirement.NoEch in FRules.Requirements) and
    (AConfig.EncryptedClientHello <> nil) then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.EchConfigured, '', SEch));
  if AConfig.CredentialResolver <> nil then
    TArrayUtilities.Append<string>(LDisclosures, SSniCredentials);
  Result := Report(LFindings, LDisclosures);
end;

function TCompliancePolicy.Admit(const AConfig: ITlsClientConfig): IComplianceReport;
begin
  Result := Evaluate(AConfig);
  Enforce(Result);
end;

function TCompliancePolicy.Admit(const AConfig: ITlsServerConfig): IComplianceReport;
begin
  Result := Evaluate(AConfig);
  Enforce(Result);
end;

end.
