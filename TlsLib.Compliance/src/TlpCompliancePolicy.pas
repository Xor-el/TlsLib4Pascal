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
  TlpNamedGroups,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpITlsServerCredentialSet,
  TlpISession,
  TlpIClock,
  TlpSessionTicketKeys,
  TlpTrustPolicy,
  TlpTrustTypes,
  TlpSystemCryptoTypes,
  TlpICryptoBackendReport,
  TlpSystemCryptoBase,
  TlpCredentialResolvers,
  TlpCertificateVerifierSource,
  TlpOSDelegateVerifier,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpIComplianceReport,
  TlpIModuleAttestation,
  TlpICompliancePolicy,
  TlpIComplianceCredentialResolver,
  TlpComplianceReport,
  TlpCompliancePresets,
  TlpComplianceCryptoProvider,
  TlpCompliancePkixProvider,
  TlpComplianceCredentialResolver,
  TlpIComplianceTicketKeys,
  TlpComplianceTicketKeys;

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
    FGroups: INamedGroupRegistry;
    FAttestation: IModuleAttestation;
    FPreset: string;
    FPlatformFindings: TArray<TComplianceFinding>;
    FDisclosures: TArray<string>;
    FPlatformReport: IComplianceReport;
    FScopePrefix: TBytes;
    class procedure CheckUsable(const ARules: TComplianceRules); static;
    procedure CheckBackend(var AFindings: TArray<TComplianceFinding>;
      const AEntry: TCryptoBackendEntry; const ASubject: string);
    procedure CheckKdf(var AFindings: TArray<TComplianceFinding>;
      const AEntry: TCryptoBackendEntry; const ASubject: string);
    procedure CollectPlatform(const ABaseCrypto: ICryptoProvider;
      var AFindings: TArray<TComplianceFinding>);
    procedure CheckCommon(const AConfig: ITlsCommonConfig;
      var AFindings: TArray<TComplianceFinding>);
    // every group a config can resolve must be one the policy built over its own crypto
    procedure CheckGroups(const AConfig: ITlsCommonConfig;
      var AFindings: TArray<TComplianceFinding>);
    function TryKeyFacts(const ACertificate: TBytes; out AFacts: TCertKeyFacts): Boolean;
    function CredentialSubject(AIndex: Int32; const ACredential: TTlsCredential): string;
    // whether some offered version can end in a certificate the client verifies
    function ClientHasCertificatePath(const AConfig: ITlsClientConfig): Boolean;
    procedure CheckCredential(const ACredential: TTlsCredential; const ASubject: string;
      var AFindings: TArray<TComplianceFinding>);
    procedure CheckCredentialResolver(const AConfig: ITlsServerConfig;
      var AFindings: TArray<TComplianceFinding>);
    procedure CheckTickets(const AConfig: ITlsServerConfig;
      var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
    // only the policy's own scope keeps sessions of a config it did not admit from resuming
    function HasOwnScope(const AScope: TBytes): Boolean;
    // judged by class, as any host class can list a marker interface
    procedure CheckTicketKeys(const AKeys: ISessionTicketKeyManager;
      const AConfig: ITlsServerConfig; var AFindings: TArray<TComplianceFinding>;
      var ADisclosures: TArray<string>);
    // the floors and the revocation posture apply to the peer certificate a config verifies
    procedure CheckPeerVerification(const AConfig: ITlsCommonConfig;
      var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
    // judged by class, as any host class can list a marker interface
    procedure CheckVerifierSource(const ASource: IInterface;
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
    function NamedGroups: INamedGroupRegistry;
    function PlatformReport: IComplianceReport;
    function Evaluate(const AConfig: ITlsClientConfig): IComplianceReport; overload;
    function Evaluate(const AConfig: ITlsServerConfig): IComplianceReport; overload;
    function Admit(const AConfig: ITlsClientConfig): IComplianceReport; overload;
    function Admit(const AConfig: ITlsServerConfig): IComplianceReport; overload;
    function EvaluateCredential(const ACredential: TTlsCredential): IComplianceReport;
    function CheckedCredentialResolver(
      const AInner: ITlsServerCredentialResolver): ITlsServerCredentialResolver;
    function SessionScope: TBytes;
    function TicketKeys(const AClock: ITlsClock;
      ALifetimeSeconds: UInt32): ISessionTicketKeyManager;
    function CheckedTicketKeys(const AFleet: IFleetTicketKeyManager): ISessionTicketKeyManager;
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
  SForeignNamedGroup =
    'the group was not built by the policy; use ICompliancePolicy.NamedGroups';
  SSuiteDiffers = 'differs from the catalog definition of its code';
  SNotAllowed = 'is not allowed by the rules';
  SEmsNotRequired = 'TLS 1.2 is offered without requiring extended master secret (RFC 7627)';
  SEarlyData = 'early data is enabled';
  SEch = 'Encrypted Client Hello is configured';
  SExternalPsk = 'an external pre-shared key is configured';
  STls12Psk = 'a TLS 1.2 pre-shared key is configured';
  SKeyLog = 'a key log is configured';
  SDangerousTrust = 'certificate verification can be skipped';
  SServerNameSubject = 'ServerName';
  SServerNameUnchecked = 'the server certificate is not matched to the host name';
  SStrengthBelow = 'the certificate strength policy is looser than the rules';
  SKeyUndetermined = 'the credential key could not be read from its certificate';
  SNoPrivateKey = 'the credential holds a certificate and no private key';
  SKeyBelow = 'the credential key is below the strength floors of the rules';
  SCredentialSchemes = 'the credential key signs with no scheme the rules allow';
  SCredentialExtraSchemes =
    'the credential key can sign with schemes the rules do not allow: %s';
  SCredentialSubject = 'credential %d';
  SCredentialNamedSubject = 'credential %d (CN=%s)';
  SResolverUnchecked =
    'the credential resolver is not checked by the policy; wrap it with CheckedCredentialResolver';
  STicketAead = 'session tickets are sealed with AES-256-GCM, which the rules do not allow';
  SFleetTicketKeys = 'session-ticket keys are entered by the host';
  STicketKeysUnchecked =
    'the session-ticket keys were not issued by the policy; use ICompliancePolicy.TicketKeys, ' +
    'or CheckedTicketKeys for keys the host enters';
  STicketLifetimeDiffers =
    'the session-ticket keys rotate on a lifetime other than the ticket lifetime';
  SResumptionStateUnchecked =
    'the resumption scope is not one of the policy, so state shared with a config the policy ' +
    'did not admit could resume here; use WithResumptionScope(policy.SessionScope), or turn ' +
    'resumption off';
  SNilClock = 'the clock must not be nil';
  SNilFleet = 'the fleet ticket keys must not be nil';
  SKeyOutside = 'the credential key is not served by the OS module';
  SChainOutside = 'the peer chain is not verified by the OS verifier';
  SCustomVerifier = 'the certificate verifier is host-supplied; use the OS verifier source';
  SStapleOutside = 'a requested OCSP staple would be verified outside the module';
  SKdfComposed = 'the TLS key derivations are composed outside the module over its HMAC';
  SModuleRevisionDiffers =
    'the module file version %s differs from the %s the certificate lists; only the build is ' +
    'checked';
  SRevocationOff = 'revocation checking is off';
  SHostResolver = 'a live-revocation resolver is host-owned and cannot be inspected';
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

const
  ScopePrefixLength = Int32(16);
  ScopeRandomLength = Int32(16);

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
  LIdentity: TModuleIdentity;
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
  LIdentity := FAttestation.Identity;
  if FAttestation.Status(FRules.ModuleStandard) <> TModuleStatus.Validated then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ModuleNotValidated, LIdentity.OsVersion,
      FAttestation.Describe))
  else if (LIdentity.ListedModuleVersion <> '') and
    (LIdentity.ModuleFileVersion <> LIdentity.ListedModuleVersion) then
    TArrayUtilities.Append<string>(FDisclosures, Format(SModuleRevisionDiffers,
      [LIdentity.ModuleFileVersion, LIdentity.ListedModuleVersion]));
end;

constructor TCompliancePolicy.Create(const ARules: TComplianceRules;
  const ABaseCrypto: ICryptoProvider; const ABasePkix: IPkixProvider;
  const AAttestation: IModuleAttestation; AEnforcement: TComplianceEnforcement);
var
  LFindings: TArray<TComplianceFinding>;
  LReport: ICryptoBackendReport;
  LGroups: TArray<INamedGroup>;
  LI: Int32;
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
  if (AEnforcement = TComplianceEnforcement.Strict) and (System.Length(LFindings) > 0) then
    raise EComplianceUnmetTlsLibException.Create(LFindings);
  FPlatformFindings := LFindings;
  FCrypto := TComplianceCryptoProvider.Compose(ABaseCrypto, FRules, AEnforcement);
  FScopePrefix := FCrypto.Primitives.GetRandom.GenerateBytes(ScopePrefixLength);
  System.SetLength(LGroups, System.Length(FRules.NamedGroups));
  for LI := 0 to System.Length(FRules.NamedGroups) - 1 do
    // over the policy crypto, so each group's agreement is the refusing one
    LGroups[LI] := TNamedGroups.CreateNistEcdh(FCrypto,
      TNamedGroupCatalog.Name(FRules.NamedGroups[LI]));
  FGroups := TNamedGroups.CreateRegistry(LGroups);
  FPkix := TCompliancePkixProvider.Create(ABasePkix, AEnforcement) as IPkixProvider;
  FPlatformReport := Report(FPlatformFindings, FDisclosures);
end;

function TCompliancePolicy.TryKeyFacts(const ACertificate: TBytes;
  out AFacts: TCertKeyFacts): Boolean;
begin
  // Parse raises on a malformed certificate, so screen it with the fail-closed query first
  Result := FPkix.Certificates.IsWellFormed(ACertificate);
  if Result then
    Result := FPkix.Certificates.Parse(ACertificate).KeyFacts(AFacts);
end;

function TCompliancePolicy.CredentialSubject(AIndex: Int32;
  const ACredential: TTlsCredential): string;
var
  LSubject, LIssuer, LCommonName, LSerial: string;
  LNamed: Boolean;
begin
  Result := Format(SCredentialSubject, [AIndex]);
  if System.Length(ACredential.CertificateChain) = 0 then
    Exit;
  LNamed := FPkix.Certificates.PeerInfo(ACredential.CertificateChain[0], LSubject, LIssuer,
    LCommonName, LSerial);
  if LNamed and (LCommonName <> '') then
    Result := Format(SCredentialNamedSubject, [AIndex, LCommonName]);
end;

function TCompliancePolicy.ClientHasCertificatePath(const AConfig: ITlsClientConfig): Boolean;
var
  LVersions: TArray<UInt16>;
  LOffers13, LOffers12, LExternalPath, LTls12Path: Boolean;
begin
  LVersions := AConfig.SupportedVersions;
  LOffers13 := TArrayUtilities.Contains<UInt16>(LVersions, TlsWireVersionTls13);
  LOffers12 := TArrayUtilities.Contains<UInt16>(LVersions, TlsWireVersionTls12);
  // a required PSK ends a version's handshake without a certificate
  LExternalPath := (System.Length(AConfig.ExternalPsks) = 0) or
    not AConfig.ExternalPskRequired;
  LTls12Path := (System.Length(AConfig.Tls12Psks) = 0) or
    not AConfig.Tls12PreSharedKeyRequired;
  Result := (LOffers13 and LExternalPath) or (LOffers12 and LTls12Path);
end;

procedure TCompliancePolicy.CheckCredential(const ACredential: TTlsCredential;
  const ASubject: string; var AFindings: TArray<TComplianceFinding>);
var
  LFacts: TCertKeyFacts;
  LCapable: TArray<TSignatureScheme>;
  LExtras, LName: string;
  LI: Int32;
  LKnown, LAnyAllowed, LMeets: Boolean;
begin
  LKnown := (System.Length(ACredential.CertificateChain) > 0) and
    TryKeyFacts(ACredential.CertificateChain[0], LFacts);
  if not LKnown then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyUndetermined, ASubject, SKeyUndetermined))
  else
  begin
    LMeets := TComplianceCatalog.KeyMeets(LFacts, FRules.Strength, FRules.RsaModulusBits);
    if not LMeets then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyBelowRules, ASubject, SKeyBelow));
  end;
  if ACredential.PrivateKey = nil then
  begin
    // an empty chain was reported above; a chain with no key can sign nothing
    if System.Length(ACredential.CertificateChain) > 0 then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyUndetermined, ASubject, SNoPrivateKey));
    Exit;
  end;
  LCapable := ACredential.PrivateKey.CapableSchemes;
  LAnyAllowed := False;
  LExtras := '';
  for LI := 0 to System.Length(LCapable) - 1 do
    if LCapable[LI] in FRules.SignatureSchemes then
      LAnyAllowed := True
    else
    begin
      LName := TEnumUtilities.GetName<TSignatureScheme>(LCapable[LI]);
      if LExtras <> '' then
        LExtras := LExtras + ', ';
      LExtras := LExtras + LName;
    end;
  if not LAnyAllowed then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialSchemesNotAllowed, ASubject, SCredentialSchemes))
  else if LExtras <> '' then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialSchemesNotAllowed, ASubject,
      Format(SCredentialExtraSchemes, [LExtras])));
  if FReport.SigningKeyBackend(ACredential.PrivateKey).Backend <> TCryptoBackend.System then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyOutsideModule, ASubject, SKeyOutside));
end;

procedure TCompliancePolicy.CheckCredentialResolver(const AConfig: ITlsServerConfig;
  var AFindings: TArray<TComplianceFinding>);
var
  LResolver: ITlsServerCredentialResolver;
  LSet: ITlsServerCredentialSet;
  LChecked: IComplianceCredentialResolver;
  LCredentials: TArray<TTlsCredential>;
  LCredential: TTlsCredential;
  LSchemes: TArray<TSignatureScheme>;
  LOwn: Boolean;
  LI: Int32;
begin
  LResolver := AConfig.CredentialResolver;
  // a PSK-only server presents no certificate, so it has no resolver
  if LResolver = nil then
    Exit;
  LOwn := False;
  // a marker interface is claimable by any host class, so only the sealed wrapper counts
  if LResolver is TComplianceCredentialResolver then
  begin
    LChecked := LResolver as IComplianceCredentialResolver;
    LOwn := LChecked.Policy = (Self as ICompliancePolicy);
    LResolver := LChecked.Inner;
  end;
  // a host set can list credentials it never serves, so only the library's resolver is read
  if (LResolver is TSniCredentialResolver) and
    Supports(LResolver, ITlsServerCredentialSet, LSet) then
  begin
    LCredentials := LSet.Credentials;
    LSchemes := TComplianceCatalog.Schemes(FRules.SignatureSchemes);
    for LI := 0 to System.Length(LCredentials) - 1 do
    begin
      LCredential := LCredentials[LI];
      // the wrapper narrows a key before it judges it, so the build check does too
      if LOwn then
        LCredential := TComplianceCatalog.NarrowedCredential(LCredential, LSchemes);
      CheckCredential(LCredential, CredentialSubject(LI + 1, LCredential), AFindings);
    end;
    Exit;
  end;
  if not LOwn then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialResolverUnchecked, '', SResolverUnchecked));
end;

procedure TCompliancePolicy.CheckTickets(const AConfig: ITlsServerConfig;
  var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
begin
  // a store-only server seals nothing, and a client never seals
  if AConfig.Resumption and (AConfig.SessionTicketKeys <> nil) and
    not (TAeadAlgorithm.AES_256_GCM in FRules.Aeads) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.TicketAeadNotAllowed, '', STicketAead));
  if AConfig.SessionTicketKeys <> nil then
    CheckTicketKeys(AConfig.SessionTicketKeys, AConfig, AFindings, ADisclosures);
  if AConfig.Resumption and ((AConfig.SessionStore <> nil) or
    (AConfig.SessionTicketKeys <> nil)) and not HasOwnScope(AConfig.ResumptionScope) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ResumptionStateUnchecked, '', SResumptionStateUnchecked));
end;

function TCompliancePolicy.HasOwnScope(const AScope: TBytes): Boolean;
begin
  Result := (System.Length(AScope) >= ScopePrefixLength) and
    TArrayUtilities.AreEqual(System.Copy(AScope, 0, ScopePrefixLength), FScopePrefix);
end;

procedure TCompliancePolicy.CheckTicketKeys(const AKeys: ISessionTicketKeyManager;
  const AConfig: ITlsServerConfig; var AFindings: TArray<TComplianceFinding>;
  var ADisclosures: TArray<string>);
var
  LChecked: IComplianceTicketKeys;
  LOwn: Boolean;
begin
  // a marker interface is claimable by any host class, so only the sealed wrappers count
  LChecked := nil;
  LOwn := (AKeys is TComplianceTicketKeys) or (AKeys is TComplianceFleetTicketKeys);
  if LOwn then
  begin
    LChecked := AKeys as IComplianceTicketKeys;
    LOwn := LChecked.Policy = (Self as ICompliancePolicy);
  end;
  if not LOwn then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.TicketKeysUnchecked, '', STicketKeysUnchecked))
  else if (AKeys is TComplianceTicketKeys) and
    (LChecked.LifetimeSeconds <> AConfig.TicketLifetimeSeconds) then
    TArrayUtilities.Append<string>(ADisclosures, STicketLifetimeDiffers);
  if Supports(AKeys, IFleetTicketKeyManager) then
    TArrayUtilities.Append<string>(ADisclosures, SFleetTicketKeys);
end;

procedure TCompliancePolicy.CheckGroups(const AConfig: ITlsCommonConfig;
  var AFindings: TArray<TComplianceFinding>);
var
  LI: Int32;
  LCode: UInt16;
  LGroups: TArray<INamedGroup>;
  LCodes: TArray<UInt16>;
  LOwn, LConfigured: INamedGroup;
  LAllowed: Boolean;
begin
  LGroups := AConfig.NamedGroups.Items;
  for LI := 0 to System.Length(LGroups) - 1 do
  begin
    LCode := LGroups[LI].Code;
    LAllowed := FGroups.TryGet(LCode, LOwn);
    if not LAllowed then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.NamedGroupNotAllowed, TNamedGroupCatalog.Name(LCode),
        SNotAllowed))
    else if LGroups[LI] <> LOwn then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.ForeignNamedGroup, TNamedGroupCatalog.Name(LCode),
        SForeignNamedGroup));
  end;
  // the engine resolves a preferred code through the config registry, whatever Items lists
  LCodes := AConfig.PreferredGroups;
  for LI := 0 to System.Length(LCodes) - 1 do
  begin
    LAllowed := FGroups.TryGet(LCodes[LI], LOwn);
    if not LAllowed then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.NamedGroupNotAllowed, TNamedGroupCatalog.Name(LCodes[LI]),
        SNotAllowed))
    else if AConfig.NamedGroups.TryGet(LCodes[LI], LConfigured) and (LConfigured <> LOwn) then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.ForeignNamedGroup, TNamedGroupCatalog.Name(LCodes[LI]),
        SForeignNamedGroup));
  end;
end;

procedure TCompliancePolicy.CheckCommon(const AConfig: ITlsCommonConfig;
  var AFindings: TArray<TComplianceFinding>);
var
  LI: Int32;
  LCodes: TArray<UInt16>;
  LSuites: TArray<TTlsCipherSuite>;
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
        TCipherSuiteCatalog.Name(LSuites[LI].Common.Code), SNotAllowed))
    else if not TComplianceCatalog.IsCatalogSuite(LSuites[LI]) then
      // the engine builds its hash, AEAD and PRF from the record, not from its code
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CipherSuiteNotAllowed,
        TCipherSuiteCatalog.Name(LSuites[LI].Common.Code), SSuiteDiffers));
  end;
  CheckGroups(AConfig, AFindings);
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
end;

procedure TCompliancePolicy.CheckPeerVerification(const AConfig: ITlsCommonConfig;
  var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
var
  LWithin: Boolean;
begin
  LWithin := TComplianceCatalog.StrengthWithin(AConfig.CertificateStrengthPolicy,
    FRules.Strength);
  if not LWithin then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.StrengthBelowRules, '', SStrengthBelow));
  if System.Length(FRules.RsaModulusBits) > 0 then
    TArrayUtilities.Append<string>(ADisclosures, SRsaPeerChainRange);
  if AConfig.RevocationPosture = TRevocationPosture.Off then
    TArrayUtilities.Append<string>(ADisclosures, SRevocationOff);
  if AConfig.AsyncCertificateVerdict.Deferral = TVerdictDeferral.LiveRevocation then
    TArrayUtilities.Append<string>(ADisclosures, SHostResolver);
end;

procedure TCompliancePolicy.CheckVerifierSource(const ASource: IInterface;
  var AFindings: TArray<TComplianceFinding>);
begin
  if ASource is TOSVerifierSource then
    Exit;
  if (ASource is TBuiltInServerVerifierSource) or (ASource is TBuiltInClientVerifierSource) then
  begin
    if TComplianceRequirement.InModuleChainVerification in FRules.Requirements then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.ChainVerifiedOutsideModule, '', SChainOutside));
    Exit;
  end;
  TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
    TComplianceFindingKind.CustomVerifierConfigured, '', SCustomVerifier));
end;

function TCompliancePolicy.Report(const AFindings: TArray<TComplianceFinding>;
  const ADisclosures: TArray<string>): IComplianceReport;
begin
  Result := TComplianceReport.Create(FEnforcement, FPreset, FAttestation.Identity,
    FAttestation.Status(FRules.ModuleStandard), AFindings, ADisclosures) as IComplianceReport;
end;

procedure TCompliancePolicy.Enforce(const AReport: IComplianceReport);
var
  LRefused: TArray<TComplianceFinding>;
begin
  LRefused := TComplianceCatalog.Refusals(FEnforcement, AReport.Findings);
  if System.Length(LRefused) > 0 then
    raise EComplianceUnmetTlsLibException.Create(LRefused);
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

function TCompliancePolicy.NamedGroups: INamedGroupRegistry;
begin
  Result := FGroups;
end;

function TCompliancePolicy.PlatformReport: IComplianceReport;
begin
  Result := FPlatformReport;
end;

function TCompliancePolicy.Evaluate(const AConfig: ITlsClientConfig): IComplianceReport;
var
  LFindings: TArray<TComplianceFinding>;
  LDisclosures: TArray<string>;
  LCertPath: Boolean;
begin
  if AConfig = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilConfig);
  LFindings := System.Copy(FPlatformFindings);
  LDisclosures := System.Copy(FDisclosures);
  LCertPath := ClientHasCertificatePath(AConfig);
  CheckCommon(AConfig, LFindings);
  // a client that can only end in a PSK verifies no chain, so the floors and postures are idle
  if LCertPath then
    CheckPeerVerification(AConfig, LFindings, LDisclosures);
  // a client without a certificate holds an empty credential
  if System.Length(AConfig.Credential.CertificateChain) > 0 then
    CheckCredential(AConfig.Credential, '', LFindings);
  if (TComplianceRequirement.NoDangerousTrust in FRules.Requirements) and
    not AConfig.CheckServerName and LCertPath then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.DangerousTrustConfigured, SServerNameSubject, SServerNameUnchecked));
  if LCertPath then
    CheckVerifierSource(AConfig.ServerVerifierSource, LFindings);
  if (TComplianceRequirement.InModuleChainVerification in FRules.Requirements) and
    AConfig.RequestOcspStapling then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.StapleVerifiedOutsideModule, '', SStapleOutside));
  if AConfig.Resumption and (AConfig.SessionCache <> nil) and
    not HasOwnScope(AConfig.SessionScope) then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ResumptionStateUnchecked, '', SResumptionStateUnchecked));
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
begin
  if AConfig = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilConfig);
  LFindings := System.Copy(FPlatformFindings);
  LDisclosures := System.Copy(FDisclosures);
  CheckCommon(AConfig, LFindings);
  CheckCredentialResolver(AConfig, LFindings);
  CheckTickets(AConfig, LFindings, LDisclosures);
  if AConfig.ClientAuth <> TClientAuthMode.None then
  begin
    CheckPeerVerification(AConfig, LFindings, LDisclosures);
    CheckVerifierSource(AConfig.ClientVerifierSource, LFindings);
  end;
  if (TComplianceRequirement.NoEarlyData in FRules.Requirements) and
    (AConfig.MaxEarlyData > 0) then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.EarlyDataEnabled, '', SEarlyData));
  if (TComplianceRequirement.NoEch in FRules.Requirements) and
    (AConfig.EncryptedClientHello <> nil) then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.EchConfigured, '', SEch));
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

function TCompliancePolicy.EvaluateCredential(
  const ACredential: TTlsCredential): IComplianceReport;
var
  LFindings: TArray<TComplianceFinding>;
begin
  LFindings := System.Copy(FPlatformFindings);
  CheckCredential(ACredential, '', LFindings);
  Result := Report(LFindings, FDisclosures);
end;

function TCompliancePolicy.CheckedCredentialResolver(
  const AInner: ITlsServerCredentialResolver): ITlsServerCredentialResolver;
begin
  Result := TComplianceCredentialResolver.Create(Self as ICompliancePolicy, AInner)
    as ITlsServerCredentialResolver;
end;

function TCompliancePolicy.SessionScope: TBytes;
begin
  Result := TArrayUtilities.Concat(FScopePrefix,
    FCrypto.Primitives.GetRandom.GenerateBytes(ScopeRandomLength));
end;

function TCompliancePolicy.TicketKeys(const AClock: ITlsClock;
  ALifetimeSeconds: UInt32): ISessionTicketKeyManager;
var
  LKeys: IRotatingTicketKeyManager;
begin
  if AClock = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilClock);
  LKeys := TStekTicketKeyManager.CreateDefault(FCrypto, AClock, ALifetimeSeconds)
    as IRotatingTicketKeyManager;
  Result := TComplianceTicketKeys.Create(Self as ICompliancePolicy, LKeys, ALifetimeSeconds)
    as ISessionTicketKeyManager;
end;

function TCompliancePolicy.CheckedTicketKeys(
  const AFleet: IFleetTicketKeyManager): ISessionTicketKeyManager;
begin
  if AFleet = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilFleet);
  Result := TComplianceFleetTicketKeys.Create(Self as ICompliancePolicy, AFleet)
    as ISessionTicketKeyManager;
end;

end.
