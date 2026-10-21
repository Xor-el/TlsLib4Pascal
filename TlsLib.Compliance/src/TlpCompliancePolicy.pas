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
  TlpSessionTicketStrategy,
  TlpTlsConfigBuilder,
  TlpClientPskPath,
  TlpIClock,
  TlpTrustPolicy,
  TlpTrustTypes,
  TlpSystemCryptoTypes,
  TlpICryptoBackendReport,
  TlpCredentialResolvers,
  TlpCertificateVerifierSource,
  TlpOSDelegateVerifier,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpIComplianceReport,
  TlpIModuleAttestation,
  TlpOSModuleAttestation,
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
  /// reports platform findings and still refuses a configuration finding at Admit. Rules outside
  /// every named preset raise EArgumentTlsLibException in both modes. The policy hands itself out
  /// as ICompliancePolicy, so hold it through that interface, never through a class reference.
  /// </summary>
  TCompliancePolicy = class sealed(TInterfacedObject, ICompliancePolicy)
  strict private
  var
    FRules: TComplianceRules;
    FEnforcement: TComplianceEnforcement;
    FReport: ICryptoBackendReport;
    FCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    // the base provider runs the issuer search; a strict facet refuses it
    FBasePkix: IPkixProvider;
    FGroups: INamedGroupRegistry;
    FAttestation: IModuleAttestation;
    FIdentity: TModuleIdentity;
    FStatus: TModuleStatus;
    FAttestationText: string;
    FPreset: string;
    FPlatformFindings: TArray<TComplianceFinding>;
    FDisclosures: TArray<string>;
    FPlatformReport: IComplianceReport;
    FScopePrefix: TBytes;
    FRuleSuites: TArray<TTlsCipherSuite>;
    // the suite hashes whose derivation runs outside the module
    FHkdfOutside: set of THashAlgorithm;
    FPrfOutside: set of THashAlgorithm;
    // rules must be runnable and inside a named preset; APreset labels the match
    class procedure CheckUsable(const ARules: TComplianceRules; out APreset: string); static;
    procedure CheckBackend(var AFindings: TArray<TComplianceFinding>;
      const AEntry: TCryptoBackendEntry; const ASubject: string);
    // whether the derivation runs outside the module, which the rules may refuse
    function CheckKdf(var AFindings: TArray<TComplianceFinding>;
      const AEntry: TCryptoBackendEntry; const ASubject: string): Boolean;
    // whether a derivation that ASuites run under the offered versions is outside the module,
    // split into the TLS 1.3 HKDF and the TLS 1.2 PRF
    function KdfOutsideFor(const AVersions: TArray<UInt16>;
      const ASuites: TArray<TTlsCipherSuite>; out AHkdf, APrf: Boolean): Boolean;
    procedure CollectPlatform(var AFindings: TArray<TComplianceFinding>);
    procedure CheckCommon(const AConfig: ITlsCommonConfig;
      var AFindings: TArray<TComplianceFinding>);
    // every group a config can resolve must be one the policy built over its own crypto
    procedure CheckGroups(const AConfig: ITlsCommonConfig;
      var AFindings: TArray<TComplianceFinding>);
    // the key and the signature of the certificate at APosition of a credential chain
    procedure CheckChainCertificate(const AChain: TArray<TBytes>; APosition: Int32;
      const ASubject: string; var AFindings: TArray<TComplianceFinding>);
    function CredentialSubject(AIndex: Int32; const ACredential: TTlsCredential): string;
    procedure CheckCredential(const ACredential: TTlsCredential; const ASubject: string;
      var AFindings: TArray<TComplianceFinding>);
    procedure CheckCredentialResolver(const AConfig: ITlsServerConfig;
      var AFindings: TArray<TComplianceFinding>);
    // whether an earlier entry of ACredentials is the credential at AIndex
    function ListedBefore(const ACredentials: TArray<TTlsCredential>; AIndex: Int32): Boolean;
    procedure CheckTickets(const AConfig: ITlsServerConfig;
      var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
    // only the policy's own scope keeps sessions of a config it did not admit from resuming
    function HasOwnScope(const AScope: TBytes): Boolean;
    // keys the policy wrapped for a fleet answer to the scope the host gave that fleet
    function ScopeFitsKeys(const AScope: TBytes; const AKeys: ISessionTicketKeyManager): Boolean;
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
    // AVersions and ASuites are what the evaluated rules or config can run
    function Report(const AFindings: TArray<TComplianceFinding>;
      const ADisclosures: TArray<string>; const AVersions: TArray<UInt16>;
      const ASuites: TArray<TTlsCipherSuite>): IComplianceReport;
    procedure Enforce(const AReport: IComplianceReport);
  public
    /// <summary>A policy over ABaseCrypto and ABasePkix. Raises EArgumentTlsLibException for a nil
    /// argument, rules no config can run or rules outside every named preset, and, in Strict,
    /// EComplianceUnmetTlsLibException for any platform finding.</summary>
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
      ALifetimeSeconds: UInt32): IRotatingTicketKeyManager;
    function CheckedTicketKeys(const AFleet: IFleetTicketKeyManager;
      const AFleetScope: TBytes): ISessionTicketKeyManager;
  end;

implementation

resourcestring
  SNilBaseCrypto = 'the base crypto provider must not be nil';
  SNilBasePkix = 'the base PKIX provider must not be nil';
  SNilAttestation = 'the module attestation must not be nil';
  SNilConfig = 'the config must not be nil';
  SVersionsInvalid = 'the rules must offer TLS 1.2, TLS 1.3 or both';
  SSuitesInvalid =
    'the rules must list known cipher suites once each, each with an AEAD the rules allow';
  SVersionWithoutSuite = 'the rules offer a TLS version that has no cipher suite';
  SGroupsInvalid = 'the rules must list only the secp256r1, secp384r1 and secp521r1 groups, ' +
    'once each';
  SSchemesEmpty = 'the rules must allow at least one signature scheme';
  SCurvesEmpty = 'the rules must list the certificate curves; an empty list would allow any';
  SRulesOutsidePresets = 'the rules allow or omit something no named preset does';
  SCryptoNotCovered =
    'the crypto provider is not the OS composition the attestation covers, so every operation ' +
    'counts as outside the module';
  SAttestationFromHost = 'the module attestation is supplied by the host';
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
  SNoCertificate = 'the credential holds no certificate';
  SKeyUndetermined = 'the key of certificate %d of the credential could not be read';
  SIssuerKeyUndetermined =
    'the key of the issuer of certificate %d of the credential could not be read';
  SSignatureUndetermined = 'the signature of certificate %d of the credential could not be read';
  SSignatureNotAllowed = 'certificate %d of the credential is signed with an algorithm the ' +
    'rules do not allow';
  SSignatureUnderPssKey = 'certificate %d of the credential is signed under an RSASSA-PSS key, ' +
    'which no scheme of the rules covers';
  SNoPrivateKey = 'the credential holds a certificate and no private key';
  SKeyMismatch = 'the credential key is not the key of its leaf certificate';
  SLeafCannotSign = 'the leaf certificate of the credential forbids digitalSignature';
  SLeafKeyRsaPss = 'the leaf certificate of the credential holds an RSASSA-PSS key, which the ' +
    'credential cannot sign with';
  SKeyNotExportable = 'the credential key cannot export its public key, so it cannot be ' +
    'matched to its leaf certificate';
  SKeyBelow = 'the key of certificate %d of the credential is below the strength floors of ' +
    'the rules';
  SCredentialSchemes = 'the credential key signs with no scheme the rules allow';
  SCredentialExtraSchemes =
    'the credential key can sign with schemes the rules do not allow: %s';
  SCredentialSubject = 'credential %d';
  SCredentialNamedSubject = 'credential %d (CN=%s)';
  SResolverUnchecked =
    'the credential resolver is not checked by the policy; wrap it with CheckedCredentialResolver';
  STicketAead = 'session tickets are sealed with %s, which the rules do not allow';
  SFleetTicketKeys = 'session-ticket keys are entered by the host';
  SFleetScopeEntered = 'the fleet scope is entered by the host';
  SSha256Internal =
    'SHA-256 runs in the module for non-negotiated integrity values: HelloRetryRequest cookie, ' +
    'certificate pins, certificate-compression cache, config fingerprint';
  STicketKeysUnchecked =
    'the session-ticket keys were not issued by the policy; use ICompliancePolicy.TicketKeys, ' +
    'or CheckedTicketKeys for keys the host enters';
  STicketLifetimeDiffers =
    'the session-ticket keys rotate on a lifetime other than the ticket lifetime';
  SResumptionStateUnchecked =
    'the resumption scope is not one of the policy, so state shared with a config the policy ' +
    'did not admit could resume here; use WithResumptionScope(policy.SessionScope), or turn ' +
    'resumption off';
  SKeyOutside = 'the credential key is not served by the OS module';
  SChainOutside = 'the peer chain is not verified by the OS verifier';
  SCustomVerifier = 'the certificate verifier is host-supplied; use the OS verifier source';
  SStapleOutside = 'a requested OCSP staple would be verified outside the module';
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
  SRsaPeerChainRange =
    'a peer chain is held to the RSA size range, not to the exact sizes of the rules';
  SRsaRangeInvalid = 'the rules must hold a non-empty RSA modulus range that contains at ' +
    'least one exact size they list';
  SVersionSubject = '0x%.4X';
  SRelaxedPortable = 'relaxed mode reports platform facts but does not refuse portable code; ' +
    'per-connection fallbacks to portable code are not reflected in the verdict';
  SGcmIvConstruction =
    'the GCM IV fixed field and counter (TLS 1.2 nonce_explicit = record sequence number; ' +
    'TLS 1.3 write_iv XOR sequence number) are built by the library outside the module ' +
    'boundary per RFC 5288 / RFC 8446 section 5.3 (IG C.H scenario 1(a), SP section 2.7.1); ' +
    'the module offers no interface to generate or check the counter; counter exhaustion ' +
    'forces a key update or close, and keys are ephemeral per session';
  SExporterComposed = 'TLS 1.2 exporter derivations (RFC 5705) are composed over the module ' +
    'HMAC; only the key-schedule derivations are module services';
  SExporterRefused = 'TLS 1.2 exporter derivations (RFC 5705) are refused: the rules require ' +
    'every key derivation to be a module service';
  SHkdfOutside = 'the TLS 1.3 key schedule (HKDF) does not run as a module service';
  SPrfOutside = 'the TLS 1.2 key schedule (PRF) does not run as a module service';

const
  ScopePrefixLength = Int32(16);
  ScopeRandomLength = TTlsConfigBuilder.MaxResumptionScopeLength - ScopePrefixLength;

{ TCompliancePolicy }

class procedure TCompliancePolicy.CheckUsable(const ARules: TComplianceRules;
  out APreset: string);
var
  LI: Int32;
  LSuite: TTlsCipherSuite;
  LAlgorithm: TKeyAgreementAlgorithm;
  LOffers13, LOffers12, LHas13, LHas12, LKnown, LSizeInRange: Boolean;
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
    if TArrayUtilities.Contains<UInt16>(System.Copy(ARules.CipherSuites, 0, LI),
      ARules.CipherSuites[LI]) then
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
    if TArrayUtilities.Contains<UInt16>(System.Copy(ARules.NamedGroups, 0, LI),
      ARules.NamedGroups[LI]) then
      raise EArgumentTlsLibException.CreateRes(@SGroupsInvalid);
  end;
  if ARules.SignatureSchemes = [] then
    raise EArgumentTlsLibException.CreateRes(@SSchemesEmpty);
  if System.Length(ARules.Strength.AllowedEcCurves) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SCurvesEmpty);
  // a range no key fits, or exact sizes none of which lies in it, leave no config that can run
  if (ARules.Strength.MaxRsaModulusBits <> 0) and
    (ARules.Strength.MinRsaModulusBits > ARules.Strength.MaxRsaModulusBits) then
    raise EArgumentTlsLibException.CreateRes(@SRsaRangeInvalid);
  if System.Length(ARules.RsaModulusBits) > 0 then
  begin
    LSizeInRange := False;
    for LI := 0 to System.Length(ARules.RsaModulusBits) - 1 do
      if (ARules.RsaModulusBits[LI] >= UInt32(ARules.Strength.MinRsaModulusBits)) and
        ((ARules.Strength.MaxRsaModulusBits = 0) or
        (ARules.RsaModulusBits[LI] <= UInt32(ARules.Strength.MaxRsaModulusBits))) then
        LSizeInRange := True;
    if not LSizeInRange then
      raise EArgumentTlsLibException.CreateRes(@SRsaRangeInvalid);
  end;
  // rules only ever narrow a preset, in both modes
  if not TCompliancePresets.TryMatch(ARules, APreset) then
    raise EArgumentTlsLibException.CreateRes(@SRulesOutsidePresets);
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

function TCompliancePolicy.CheckKdf(var AFindings: TArray<TComplianceFinding>;
  const AEntry: TCryptoBackendEntry; const ASubject: string): Boolean;
begin
  // only a module service counts as inside; a portable derivation is also a backend finding
  Result := AEntry.Backend <> TCryptoBackend.System;
  if not Result then
    Exit;
  if AEntry.Backend = TCryptoBackend.Portable then
    CheckBackend(AFindings, AEntry, ASubject)
  else if FRules.Kdf = TKdfRule.RequireModule then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.KdfOutsideModule, ASubject, SKdfRequiresModule));
end;

function TCompliancePolicy.KdfOutsideFor(const AVersions: TArray<UInt16>;
  const ASuites: TArray<TTlsCipherSuite>; out AHkdf, APrf: Boolean): Boolean;
var
  LOffers13, LOffers12: Boolean;
  LI: Int32;
begin
  LOffers13 := TArrayUtilities.Contains<UInt16>(AVersions, TlsWireVersionTls13);
  LOffers12 := TArrayUtilities.Contains<UInt16>(AVersions, TlsWireVersionTls12);
  AHkdf := False;
  APrf := False;
  for LI := 0 to System.Length(ASuites) - 1 do
    if ASuites[LI].Protocol = TSuiteProtocol.Tls13 then
      AHkdf := AHkdf or (LOffers13 and (ASuites[LI].Common.Hash in FHkdfOutside))
    else
      APrf := APrf or (LOffers12 and (ASuites[LI].Prf in FPrfOutside));
  Result := AHkdf or APrf;
end;

procedure TCompliancePolicy.CollectPlatform(var AFindings: TArray<TComplianceFinding>);
var
  LI: Int32;
  LSuite: TTlsCipherSuite;
  LHashes, LHkdfHashes, LPrfHashes: set of THashAlgorithm;
  LHash: THashAlgorithm;
  LAead: TAeadAlgorithm;
  LScheme: TSignatureScheme;
  LAlgorithm: TKeyAgreementAlgorithm;
  LName: string;
  LAttested: TArray<string>;
  LEntry: TCryptoBackendEntry;
  LKnown, LSha256Listed, LOffers13, LOffers12, LGcm: Boolean;
begin
  LHashes := [];
  LHkdfHashes := [];
  LPrfHashes := [];
  LGcm := False;
  FRuleSuites := nil;
  FHkdfOutside := [];
  FPrfOutside := [];
  LOffers13 := TArrayUtilities.Contains<UInt16>(FRules.Versions, TlsWireVersionTls13);
  LOffers12 := TArrayUtilities.Contains<UInt16>(FRules.Versions, TlsWireVersionTls12);
  CheckBackend(AFindings, FReport.RandomBackend, SRandomSubject);
  for LI := 0 to System.Length(FRules.CipherSuites) - 1 do
  begin
    LKnown := TCipherSuiteCatalog.TryGet(FRules.CipherSuites[LI], LSuite);
    if LKnown then
    begin
      TArrayUtilities.Append<TTlsCipherSuite>(FRuleSuites, LSuite);
      LGcm := LGcm or (LSuite.Common.Aead in [TAeadAlgorithm.AES_128_GCM,
        TAeadAlgorithm.AES_256_GCM]);
      Include(LHashes, LSuite.Common.Hash);
      // a derivation counts only when some offered version runs it
      if (LSuite.Protocol = TSuiteProtocol.Tls13) and LOffers13 then
        Include(LHkdfHashes, LSuite.Common.Hash)
      else if (LSuite.Protocol <> TSuiteProtocol.Tls13) and LOffers12 then
        Include(LPrfHashes, LSuite.Prf);
    end;
  end;
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    // no preset holds an EdDSA scheme, so every scheme in the rules names its hash
    if (LScheme in FRules.SignatureSchemes) and LScheme.TryHash(LHash) then
      Include(LHashes, LHash);
  // the engine hashes values nobody negotiates with SHA-256, so the module must serve it
  LSha256Listed := THashAlgorithm.SHA_256 in LHashes;
  Include(LHashes, THashAlgorithm.SHA_256);
  if not LSha256Listed then
    TArrayUtilities.Append<string>(FDisclosures, SSha256Internal);
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
    begin
      // the policy assembles HKDF over its own HMAC whatever backend the report names
      LEntry := FReport.HkdfBackend(LHash);
      if LEntry.Backend = TCryptoBackend.System then
        LEntry.Backend := TCryptoBackend.Composed;
      if CheckKdf(AFindings, LEntry, Format(SHkdfSubject, [LName])) then
        Include(FHkdfOutside, LHash);
    end;
    if LHash in LPrfHashes then
      if CheckKdf(AFindings, FReport.Tls12PrfBackend(LHash), Format(SPrfSubject, [LName])) then
        Include(FPrfOutside, LHash);
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
  if FStatus <> TModuleStatus.Validated then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ModuleNotValidated, FIdentity.OsVersion, FAttestationText))
  else if (FIdentity.ListedModuleVersion <> '') and
    (FIdentity.ModuleFileVersion <> FIdentity.ListedModuleVersion) then
    TArrayUtilities.Append<string>(FDisclosures, Format(SModuleRevisionDiffers,
      [FIdentity.ModuleFileVersion, FIdentity.ListedModuleVersion]));
  LAttested := FAttestation.Disclosures;
  for LI := 0 to System.Length(LAttested) - 1 do
    TArrayUtilities.Append<string>(FDisclosures, LAttested[LI]);
  if LGcm then
    TArrayUtilities.Append<string>(FDisclosures, SGcmIvConstruction);
  if FEnforcement = TComplianceEnforcement.Relaxed then
    TArrayUtilities.Append<string>(FDisclosures, SRelaxedPortable);
end;

constructor TCompliancePolicy.Create(const ARules: TComplianceRules;
  const ABaseCrypto: ICryptoProvider; const ABasePkix: IPkixProvider;
  const AAttestation: IModuleAttestation; AEnforcement: TComplianceEnforcement);
var
  LFindings: TArray<TComplianceFinding>;
  LReport: ICryptoBackendReport;
  LGroups: TArray<INamedGroup>;
  LI: Int32;
  LHasReport, LCovered: Boolean;
begin
  inherited Create;
  if ABaseCrypto = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBaseCrypto);
  if ABasePkix = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBasePkix);
  if AAttestation = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilAttestation);
  CheckUsable(ARules, FPreset);
  FRules := ARules.Clone;
  FEnforcement := AEnforcement;
  FBasePkix := ABasePkix;
  FAttestation := AAttestation;
  // read once: a host attestation may change its answer, and a report must not follow it
  FIdentity := AAttestation.Identity;
  FStatus := AAttestation.Status(FRules.ModuleStandard);
  FAttestationText := AAttestation.Describe;
  // a certificate number means something only while the module is validated
  if FStatus <> TModuleStatus.Validated then
    FIdentity.Certificate := '';
  if not TOSModuleAttestation.IsPlatform(AAttestation) then
  begin
    FIdentity.Attested := False;
    TArrayUtilities.Append<string>(FDisclosures, SAttestationFromHost);
  end;
  LCovered := AAttestation.Covers(ABaseCrypto);
  LFindings := nil;
  LReport := nil;
  LHasReport := Supports(ABaseCrypto, ICryptoBackendReport, LReport);
  // one report decides everything: a provider the attestation does not cover has none to trust
  if LHasReport and LCovered then
    FReport := LReport
  else
    FReport := TPortableOnlyReport.Create(False) as ICryptoBackendReport;
  if not LHasReport then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.NoBackendReport, '', SNoBackendReport));
  if not LCovered then
    TArrayUtilities.Append<TComplianceFinding>(LFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CryptoNotCovered, '', SCryptoNotCovered));
  CollectPlatform(LFindings);
  if (AEnforcement = TComplianceEnforcement.Strict) and (System.Length(LFindings) > 0) then
    raise EComplianceUnmetTlsLibException.Create(LFindings);
  FPlatformFindings := LFindings;
  FCrypto := TComplianceCryptoProvider.Compose(ABaseCrypto, FRules, AEnforcement, FReport);
  FScopePrefix := FCrypto.Primitives.GetRandom.GenerateBytes(ScopePrefixLength);
  System.SetLength(LGroups, System.Length(FRules.NamedGroups));
  for LI := 0 to System.Length(FRules.NamedGroups) - 1 do
    // over the policy crypto, so each group's agreement is the refusing one
    LGroups[LI] := TNamedGroups.CreateNistEcdh(FCrypto,
      TNamedGroupCatalog.Name(FRules.NamedGroups[LI]));
  FGroups := TNamedGroups.CreateRegistry(LGroups);
  FPkix := TCompliancePkixProvider.Create(ABasePkix, AEnforcement) as IPkixProvider;
  FPlatformReport := Report(FPlatformFindings, FDisclosures, FRules.Versions, FRuleSuites);
end;

procedure TCompliancePolicy.CheckChainCertificate(const AChain: TArray<TBytes>;
  APosition: Int32; const ASubject: string; var AFindings: TArray<TComplianceFinding>);
var
  LCert: IInspectedCertificate;
  LKey: TCertKeyFacts;
  LSignature: TCertSignatureFacts;
  LIssuerDer: TBytes;
  LIndex: Int32;
  LIssuerKey: TCertAnswer;
  LLast: Boolean;
begin
  LIndex := APosition + 1;
  LLast := APosition = System.Length(AChain) - 1;
  // Parse raises on a malformed certificate, so screen it with the fail-closed query first
  if not FPkix.Certificates.IsWellFormed(AChain[APosition]) then
  begin
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyUndetermined, ASubject,
      Format(SKeyUndetermined, [LIndex])));
    Exit;
  end;
  LCert := FPkix.Certificates.Parse(AChain[APosition]);
  if not LCert.KeyFacts(LKey) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyUndetermined, ASubject,
      Format(SKeyUndetermined, [LIndex])))
  else if not TComplianceCatalog.KeyMeets(LKey, FRules.Strength, FRules.RsaModulusBits) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyBelowRules, ASubject, Format(SKeyBelow, [LIndex])));
  // the last certificate is not judged when it verifies under its own key
  if LLast and (LCert.IsSelfSigned = TCertAnswer.Yes) then
    Exit;
  // the core covers an RSASSA-PSS issuer key only with the rsa_pss_pss schemes
  LIssuerKey := TCertAnswer.No;
  if FBasePkix.Revocation.TryFindIssuer(AChain[APosition], AChain, LIssuerDer) then
    if FPkix.Certificates.IsWellFormed(LIssuerDer) then
      LIssuerKey := FPkix.Certificates.KeyIsRsaPss(LIssuerDer)
    else
      LIssuerKey := TCertAnswer.Undetermined;
  if not LCert.SignatureFacts(LSignature) then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyUndetermined, ASubject,
      Format(SSignatureUndetermined, [LIndex])))
  else if not TComplianceCatalog.SignatureMeets(LSignature.Family, LSignature.Hash,
    LSignature.PssCanonical, LIssuerKey = TCertAnswer.Yes, FRules) then
  begin
    // the refusal is the issuer key's when the signature would meet the rules under another key
    if (LIssuerKey = TCertAnswer.Yes) and TComplianceCatalog.SignatureMeets(LSignature.Family,
      LSignature.Hash, LSignature.PssCanonical, False, FRules) then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialSchemesNotAllowed, ASubject,
        Format(SSignatureUnderPssKey, [LIndex])))
    else
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialSchemesNotAllowed, ASubject,
        Format(SSignatureNotAllowed, [LIndex])));
  end
  else if LIssuerKey = TCertAnswer.Undetermined then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyUndetermined, ASubject,
      Format(SIssuerKeyUndetermined, [LIndex])));
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

procedure TCompliancePolicy.CheckCredential(const ACredential: TTlsCredential;
  const ASubject: string; var AFindings: TArray<TComplianceFinding>);
var
  LCapable: TArray<TSignatureScheme>;
  LExtras, LName: string;
  LI: Int32;
  LAnyAllowed: Boolean;
begin
  if System.Length(ACredential.CertificateChain) = 0 then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.CredentialKeyUndetermined, ASubject, SNoCertificate));
  // every certificate the credential presents is judged, not only the leaf
  for LI := 0 to System.Length(ACredential.CertificateChain) - 1 do
    CheckChainCertificate(ACredential.CertificateChain, LI, ASubject, AFindings);
  // an empty chain was reported above; the credential must be one the builder would accept
  case ACredential.Consistency(FPkix.Certificates) of
    TCredentialConsistency.KeyMissing:
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyMissing, ASubject, SNoPrivateKey));
    TCredentialConsistency.LeafCannotSign:
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyUnusable, ASubject, SLeafCannotSign));
    TCredentialConsistency.LeafKeyRsaPss:
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyUnusable, ASubject, SLeafKeyRsaPss));
    TCredentialConsistency.KeyNotExportable:
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyUnusable, ASubject, SKeyNotExportable));
    TCredentialConsistency.KeyLeafMismatch:
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialKeyMismatch, ASubject, SKeyMismatch));
  end;
  if ACredential.PrivateKey = nil then
    Exit;
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
    // the wrapper of another policy judges by that policy's rules, not these
    if not LOwn then
    begin
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CredentialResolverUnchecked, '', SResolverUnchecked));
      Exit;
    end;
  end;
  // a host set can list credentials it never serves, so only the library's resolver is read
  if (LResolver is TSniCredentialResolver) and
    Supports(LResolver, ITlsServerCredentialSet, LSet) then
  begin
    LCredentials := LSet.Credentials;
    LSchemes := TComplianceCatalog.Schemes(FRules.SignatureSchemes);
    for LI := 0 to System.Length(LCredentials) - 1 do
    begin
      // the default may also be a server-name entry: one finding per distinct credential
      if ListedBefore(LCredentials, LI) then
        Continue;
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

function TCompliancePolicy.ListedBefore(const ACredentials: TArray<TTlsCredential>;
  AIndex: Int32): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to AIndex - 1 do
    if TComplianceCatalog.SameCredential(ACredentials[LI], ACredentials[AIndex]) then
      Exit(True);
end;

procedure TCompliancePolicy.CheckTickets(const AConfig: ITlsServerConfig;
  var AFindings: TArray<TComplianceFinding>; var ADisclosures: TArray<string>);
var
  LKeys: ISessionTicketKeyManager;
  LVersions: TArray<UInt16>;
  LAeadName: string;
  LI: Int32;
  LFits: Boolean;
begin
  // keys count only when some offered version seals tickets with them
  LKeys := nil;
  LVersions := AConfig.SupportedVersions;
  for LI := 0 to System.Length(LVersions) - 1 do
    if TSessionTicketStrategies.SealsWithKeys(LVersions[LI], AConfig.SessionTicketKeys,
      AConfig.SessionStore) then
    begin
      LKeys := AConfig.SessionTicketKeys;
      Break;
    end;
  // a store-only server seals nothing, and a client never seals
  if AConfig.Resumption and (LKeys <> nil) and
    not (TSessionTicketStrategies.TicketAead in FRules.Aeads) then
  begin
    LAeadName := TEnumUtilities.GetName<TAeadAlgorithm>(TSessionTicketStrategies.TicketAead);
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.TicketAeadNotAllowed, '', Format(STicketAead, [LAeadName])));
  end;
  if LKeys <> nil then
    CheckTicketKeys(LKeys, AConfig, AFindings, ADisclosures);
  LFits := ScopeFitsKeys(AConfig.ResumptionScope, LKeys);
  // keys left idle beside a store may be the policy's fleet, and then its scope names the store
  if not LFits and (LKeys = nil) then
    LFits := ScopeFitsKeys(AConfig.ResumptionScope, AConfig.SessionTicketKeys);
  if AConfig.Resumption and ((AConfig.SessionStore <> nil) or (LKeys <> nil)) and
    not LFits then
    TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
      TComplianceFindingKind.ResumptionStateUnchecked, '', SResumptionStateUnchecked));
end;

function TCompliancePolicy.HasOwnScope(const AScope: TBytes): Boolean;
begin
  Result := (System.Length(AScope) >= ScopePrefixLength) and
    TArrayUtilities.AreEqual(System.Copy(AScope, 0, ScopePrefixLength), FScopePrefix);
end;

function TCompliancePolicy.ScopeFitsKeys(const AScope: TBytes;
  const AKeys: ISessionTicketKeyManager): Boolean;
var
  LChecked: IComplianceTicketKeys;
begin
  if (AKeys is TComplianceFleetTicketKeys) and
    Supports(AKeys, IComplianceTicketKeys, LChecked) and
    (LChecked.Policy = (Self as ICompliancePolicy)) then
    Result := TArrayUtilities.AreEqual(AScope, LChecked.FleetScope)
  else
    Result := HasOwnScope(AScope);
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
    TArrayUtilities.Append<string>(ADisclosures, STicketLifetimeDiffers)
  else if AKeys is TComplianceFleetTicketKeys then
    TArrayUtilities.Append<string>(ADisclosures, SFleetScopeEntered);
  if Supports(AKeys, IFleetTicketKeyManager) then
    TArrayUtilities.Append<string>(ADisclosures, SFleetTicketKeys);
end;

procedure TCompliancePolicy.CheckGroups(const AConfig: ITlsCommonConfig;
  var AFindings: TArray<TComplianceFinding>);
var
  LGroup, LOwn: INamedGroup;
begin
  // the groups the engine would offer: the preferred codes the config registry holds
  for LGroup in TNamedGroups.ResolvedGroups(AConfig.NamedGroups, AConfig.PreferredGroups) do
    if not FGroups.TryGet(LGroup.Code, LOwn) then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.NamedGroupNotAllowed, TNamedGroupCatalog.Name(LGroup.Code),
        SNotAllowed))
    else if LGroup <> LOwn then
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.ForeignNamedGroup, TNamedGroupCatalog.Name(LGroup.Code),
        SForeignNamedGroup));
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
        TComplianceFindingKind.VersionNotAllowed, Format(SVersionSubject, [LCodes[LI]]),
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
    else if not TCipherSuiteCatalog.MatchesCatalog(LSuites[LI]) then
      // the engine builds its hash, AEAD and PRF from the record, not from its code
      TArrayUtilities.Append<TComplianceFinding>(AFindings, TComplianceFinding.Create(
        TComplianceFindingKind.CipherSuiteDiffersFromCatalog,
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
  LWithin := AConfig.CertificateStrengthPolicy.IsAtLeastAsStrictAs(FRules.Strength);
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
  const ADisclosures: TArray<string>; const AVersions: TArray<UInt16>;
  const ASuites: TArray<TTlsCipherSuite>): IComplianceReport;
var
  LDisclosures: TArray<string>;
  LKdfOutside, LHkdf, LPrf: Boolean;
begin
  LDisclosures := System.Copy(ADisclosures);
  LKdfOutside := KdfOutsideFor(AVersions, ASuites, LHkdf, LPrf);
  if LHkdf then
    TArrayUtilities.Append<string>(LDisclosures, SHkdfOutside);
  if LPrf then
    TArrayUtilities.Append<string>(LDisclosures, SPrfOutside);
  if TArrayUtilities.Contains<UInt16>(AVersions, TlsWireVersionTls12) then
    // the provider refuses an exporter label exactly when strict meets RequireModule
    if (FEnforcement = TComplianceEnforcement.Strict) and (FRules.Kdf = TKdfRule.RequireModule) then
      TArrayUtilities.Append<string>(LDisclosures, SExporterRefused)
    else
      TArrayUtilities.Append<string>(LDisclosures, SExporterComposed);
  Result := TComplianceReport.Create(FEnforcement, FPreset, FIdentity, FStatus, AFindings,
    LDisclosures, LKdfOutside) as IComplianceReport;
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
  LVersions: TArray<UInt16>;
begin
  if AConfig = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilConfig);
  LFindings := System.Copy(FPlatformFindings);
  LDisclosures := System.Copy(FDisclosures);
  LVersions := AConfig.SupportedVersions;
  LCertPath := TClientPskPath.HasCertificatePath(
    TArrayUtilities.Contains<UInt16>(LVersions, TlsWireVersionTls13),
    TArrayUtilities.Contains<UInt16>(LVersions, TlsWireVersionTls12),
    System.Length(AConfig.ExternalPsks), AConfig.ExternalPskRequired,
    System.Length(AConfig.Tls12Psks), AConfig.Tls12PreSharedKeyRequired);
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
  if LCertPath and (TComplianceRequirement.InModuleChainVerification in FRules.Requirements) and
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
  Result := Report(LFindings, LDisclosures, AConfig.SupportedVersions,
    AConfig.CipherSuites.Items);
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
  Result := Report(LFindings, LDisclosures, AConfig.SupportedVersions,
    AConfig.CipherSuites.Items);
end;

function TCompliancePolicy.Admit(const AConfig: ITlsClientConfig): IComplianceReport;
var
  LReport: IComplianceReport;
begin
  LReport := Evaluate(AConfig);
  Enforce(LReport);
  Result := LReport;
end;

function TCompliancePolicy.Admit(const AConfig: ITlsServerConfig): IComplianceReport;
var
  LReport: IComplianceReport;
begin
  LReport := Evaluate(AConfig);
  Enforce(LReport);
  Result := LReport;
end;

function TCompliancePolicy.EvaluateCredential(
  const ACredential: TTlsCredential): IComplianceReport;
var
  LFindings: TArray<TComplianceFinding>;
begin
  LFindings := System.Copy(FPlatformFindings);
  CheckCredential(ACredential, '', LFindings);
  Result := Report(LFindings, FDisclosures, FRules.Versions, FRuleSuites);
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
  ALifetimeSeconds: UInt32): IRotatingTicketKeyManager;
begin
  Result := TComplianceTicketKeys.Create(Self as ICompliancePolicy, AClock, ALifetimeSeconds)
    as IRotatingTicketKeyManager;
end;

function TCompliancePolicy.CheckedTicketKeys(const AFleet: IFleetTicketKeyManager;
  const AFleetScope: TBytes): ISessionTicketKeyManager;
begin
  Result := TComplianceFleetTicketKeys.Create(Self as ICompliancePolicy, AFleet, AFleetScope)
    as ISessionTicketKeyManager;
end;

end.
